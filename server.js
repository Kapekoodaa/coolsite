// ===== server.js =====
const express = require("express");
const session = require("express-session");
const bodyParser = require("body-parser");
const fs = require("fs");
const path = require("path");
const cookieParser = require("cookie-parser");
const WebSocket = require("ws");
const crypto = require("crypto-js");
const bcrypt = require("bcryptjs"); // add at the top with other requires

const app = express();
const PORT = 8080;

// ---------- Middlewares ----------
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
const sessionMiddleware = session({
  secret: "supersecret",        // change to your own random string
  resave: false,
  saveUninitialized: false,
});
app.use(sessionMiddleware);
app.use(express.json()); // Add this if not already present

// ---- Helpers ----
function redirectIfLoggedIn(req, res, next) {
  if (req.session.user) return res.redirect("/chat/chat.html");
  next();
}

function requireLogin(req, res, next) {
  if (req.session.user) return next();
  return res.redirect("/login");
}

// Protect everything except login/register/static user JSON
app.use((req, res, next) => {
  const publicPaths = [
    "/login",
    "/register",
    "/index.html",
    "/",
    "/styles.css",
    "/images"
  ];
  if (
    publicPaths.includes(req.path) ||
    req.path.startsWith("/images") ||
    req.path.startsWith("/users")
  ) {
    return next();
  }
  return requireLogin(req, res, next);
});

// Serve static files
app.use(express.static(path.join(__dirname)));

// ---------- Routes ----------

// Login page (block if logged in)
app.get("/login", redirectIfLoggedIn, (req, res) => {
  res.sendFile(path.join(__dirname, "login.html"));
});

// Register page (block if logged in)
app.get("/register", redirectIfLoggedIn, (req, res) => {
  res.sendFile(path.join(__dirname, "register.html"));
});

// Handle registration + auto-login
app.post("/register", (req, res) => {
  const { username, password, invite } = req.body;
  const usersPath = path.join(__dirname, "users", "accounts.json");
  const invitesPath = path.join(__dirname, "users", "invites.json");

  const users = JSON.parse(fs.readFileSync(usersPath));
  const invites = JSON.parse(fs.readFileSync(invitesPath));

  // Normalize invite code: trim and uppercase
  const inviteCode = invite.trim().toUpperCase();

  if (!invites[inviteCode] || invites[inviteCode] === false) {
    return res.redirect("/register?error=Invalid%20or%20used%20invite%20code");
  }
  if (users[username]) {
    return res.redirect("/register?error=Username%20taken");
  }

  // Hash the password before saving
  const hashedPassword = bcrypt.hashSync(password, 10);

  users[username] = { password: hashedPassword };
  invites[inviteCode] = false;

  fs.writeFileSync(usersPath, JSON.stringify(users, null, 2));
  fs.writeFileSync(invitesPath, JSON.stringify(invites, null, 2));

  // Auto-login
  req.session.user = username;
  console.log(`User "${username}" registered and logged in.`);
  res.redirect("/chat/chat.html");
});

// Handle login
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  const usersPath = path.join(__dirname, "users", "accounts.json");
  const users = JSON.parse(fs.readFileSync(usersPath));

  if (
    !users[username] ||
    !bcrypt.compareSync(password, users[username].password)
  ) {
    return res.redirect("/login?error=Wrong%20username%20or%20password");
  }
  req.session.user = username;
  res.redirect("/chat/chat.html");
});

// Logout
app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/login");
  });
});

// User profile (JSON)
app.get('/users/me', (req, res) => {
  if (!req.session.user) return res.status(401).json({ username: null });
  res.json({ username: req.session.user });
});

app.post('/users/change-password', (req, res) => {
  if (!req.session.user) return res.status(401).json({ success: false, error: "Not logged in" });
  const { old, new: newPwd } = req.body;
  const usersPath = path.join(__dirname, "users", "accounts.json");
  const users = JSON.parse(fs.readFileSync(usersPath));
  const username = req.session.user;

  if (!users[username] || !bcrypt.compareSync(old, users[username].password)) {
    return res.json({ success: false, error: "Old password incorrect" });
  }
  if (!newPwd || newPwd.length < 4) {
    return res.json({ success: false, error: "New password too short" });
  }
  users[username].password = bcrypt.hashSync(newPwd, 10);
  fs.writeFileSync(usersPath, JSON.stringify(users, null, 2));
  res.json({ success: true });
});

// ---------- WebSocket Chat ----------
const server = app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

const wss = new WebSocket.Server({ server, path: "/ws" });

const SECRET_KEY = "40mvLNx2xw7YtmwJP21CWSbNrjuvSdg8"; // keep same in frontend

// Helper to wrap middleware for ws
function wrap(middleware) {
  return (ws, req, next) => middleware(req, {}, next);
}

const messagesPath = path.join(__dirname, "messages.json");

// Load messages from file or start with empty array
let messages = [];
if (fs.existsSync(messagesPath)) {
  try {
    messages = JSON.parse(fs.readFileSync(messagesPath));
  } catch {
    messages = [];
  }
}

// Helper to save messages
function saveMessages() {
  fs.writeFileSync(messagesPath, JSON.stringify(messages, null, 2));
}

const lastMessageTime = {}; // username: timestamp

wss.on("connection", function connection(ws, req) {
  wrap(sessionMiddleware)(ws, req, () => {
    const ip = req.socket.remoteAddress;
    const username = req.session && req.session.user ? req.session.user : "Unknown";
    ws.username = username;
    console.log(`Client connected from ${ip} as ${username}`);

    // Send all previous messages to the new client
    messages.forEach((msg) => {
      ws.send(JSON.stringify(msg));
    });

    ws.on("message", (data) => {
      const now = Date.now();
      const userKey = username + "|" + ip;
      if (lastMessageTime[userKey] && now - lastMessageTime[userKey] < 500) {
        // Too fast, ignore message
        return;
      }
      lastMessageTime[userKey] = now;

      let msgObj;
      try {
        msgObj = JSON.parse(data.toString());
      } catch (e) {
        console.error("Invalid JSON from client:", e);
        return;
      }
      const encrypted = msgObj.encrypted;
      let decrypted = "[Could not decrypt]";
      try {
        decrypted = crypto.AES.decrypt(encrypted, SECRET_KEY).toString(crypto.enc.Utf8);
      } catch (e) {
        console.error("Decryption failed:", e);
      }

      const hash = crypto.SHA256(decrypted).toString();
      const timestamp = msgObj.timestamp || new Date().toISOString();

      const messageData = {
        username: username,
        encrypted: encrypted,
        hash,
        time: timestamp,
        ip,
      };

      // Log the message
      console.log(
        `[${timestamp}] Message from ${username} (${ip}): "${decrypted}" (${encrypted}) SHA256: ${hash}`
      );

      // Save message
      messages.push(messageData);
      saveMessages();

      // Broadcast including username
      wss.clients.forEach((client) => {
        if (client.readyState === WebSocket.OPEN) {
          client.send(JSON.stringify(messageData));
        }
      });
    });

    ws.on("close", () => console.log(`Client disconnected: ${username} (${ip})`));
  });
});

function clearMessagesAtMidnight() {
  const now = new Date();
  const nextMidnight = new Date(
    now.getFullYear(),
    now.getMonth(),
    now.getDate() + 1,
    0, 0, 0, 0
  );
  const msUntilMidnight = nextMidnight - now;

  setTimeout(() => {
    messages = [];
    saveMessages();
    console.log("Messages cleared at midnight.");
    clearMessagesAtMidnight(); // Schedule next clear
  }, msUntilMidnight);
}

clearMessagesAtMidnight();
