// ===== server.js =====
const express = require("express");
const session = require("express-session");
const bodyParser = require("body-parser");
const fs = require("fs");
const path = require("path");
const cookieParser = require("cookie-parser");
const WebSocket = require("ws");
const crypto = require("crypto-js");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const { randomUUID } = require("crypto");

const app = express();
const PORT = 8080;

// --- Middleware ---
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.json());
const sessionMiddleware = session({
  secret: "supersecret",
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax" }
});
app.use(sessionMiddleware);

// --- Auth helpers ---
function requireAdmin(req, res, next) {
  if (req.session && req.session.user === "kape") return next();
  return res.status(403).send("Forbidden");
}
function redirectIfLoggedIn(req, res, next) {
  if (req.session.user) return res.redirect("/chat/chat.html");
  next();
}
function requireLogin(req, res, next) {
  if (req.session.user) return next();
  return res.redirect("/login");
}

// ==================== FILE-SHARE ====================
const uploadsDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);

const fileIndexPath = path.join(uploadsDir, "files.json");
let fileIndex = {};
if (fs.existsSync(fileIndexPath)) {
  try { fileIndex = JSON.parse(fs.readFileSync(fileIndexPath)); } catch {}
}
function saveFileIndex() {
  fs.writeFileSync(fileIndexPath, JSON.stringify(fileIndex, null, 2));
}

const storage = multer.diskStorage({
  destination: uploadsDir,
  filename: (req, file, cb) => {
    const id = randomUUID();
    const ext = path.extname(file.originalname);
    cb(null, `${id}${ext}`);
  }
});
const upload = multer({ storage });

app.get("/upload", requireLogin, (req, res) =>
  res.sendFile(path.join(__dirname, "upload.html"))
);

app.post("/api/upload", requireLogin, upload.single("file"), (req, res) => {
  if (!req.file) return res.status(400).json({ success: false, error: "No file" });
  const id = path.parse(req.file.filename).name;
  fileIndex[id] = {
    original: req.file.originalname,
    stored: req.file.filename,
    uploadedBy: req.session.user,
    uploadedAt: new Date().toISOString(),
    size: req.file.size
  };
  saveFileIndex();
  res.json({
    success: true,
    url: `/file/${id}/${encodeURIComponent(req.file.originalname)}`,
    previewUrl: `/f/${id}`
  });
});

// === RAW FILE ROUTE (Discord-friendly) ===
app.get("/file/:id/:name", (req, res) => {
  const meta = fileIndex[req.params.id];
  if (!meta) return res.status(404).send("File not found");
  const filePath = path.join(uploadsDir, meta.stored);
  if (!fs.existsSync(filePath)) return res.status(404).send("File missing");

  // Force inline so Discord shows preview (no "attachment")
  res.setHeader("Content-Disposition", "inline");
  res.sendFile(filePath);
});

// === Friendly preview page with OG tags ===
app.get("/f/:id", (req, res) => {
  const meta = fileIndex[req.params.id];
  if (!meta) return res.status(404).send("File not found");
  const fileUrl = `${req.protocol}://${req.get("host")}/file/${req.params.id}/${encodeURIComponent(meta.original)}`;
  const ext = path.extname(meta.original).toLowerCase();
  let ogType = "website";
  let ogMedia = "";
  if ([".png", ".jpg", ".jpeg", ".gif", ".webp"].includes(ext)) {
    ogType = "image";
    ogMedia = `<meta property="og:image" content="${fileUrl}" />`;
  } else if ([".mp4", ".webm", ".mov"].includes(ext)) {
    ogType = "video";
    ogMedia = `
      <meta property="og:video" content="${fileUrl}" />
      <meta property="og:video:type" content="video/${ext.replace(".", "")}" />
      <meta property="og:video:width" content="1280" />
      <meta property="og:video:height" content="720" />`;
  } else if ([".mp3", ".wav", ".ogg"].includes(ext)) {
    ogType = "audio";
    ogMedia = `<meta property="og:audio" content="${fileUrl}" />`;
  }
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta property="og:title" content="${escapeHtml(meta.original)}" />
<meta property="og:type" content="${ogType}" />
<meta property="og:url" content="${fileUrl}" />
${ogMedia}
<meta name="twitter:card" content="${ogType === "image" ? "summary_large_image" : "player"}" />
<title>${escapeHtml(meta.original)}</title>
</head>
<body style="background:#0f0f1a;color:#fff;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;font-family:Arial">
  <div style="text-align:center;padding:24px;">
    <h2 style="color:#c46fad">${escapeHtml(meta.original)}</h2>
    <p style="color:#bbb">Uploaded by ${escapeHtml(meta.uploadedBy)} • ${new Date(meta.uploadedAt).toLocaleString()}</p>
    <p><a href="${fileUrl}" style="color:#9acaff">Open raw file</a></p>
  </div>
</body>
</html>`);
});
function escapeHtml(s) {
  return String(s || "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

// --- Admin file list & delete ---
app.get("/admin/api/files", requireAdmin, (req, res) => res.json(fileIndex));
app.post("/admin/api/delete-file", requireAdmin, (req, res) => {
  const { id } = req.body;
  if (!id || !fileIndex[id]) return res.json({ success: false, error: "Not found" });
  const fp = path.join(uploadsDir, fileIndex[id].stored);
  if (fs.existsSync(fp)) fs.unlinkSync(fp);
  delete fileIndex[id];
  saveFileIndex();
  res.json({ success: true });
});

// ======= Existing admin/user routes (unchanged) =======
app.post("/admin/api/generate-invite", requireAdmin, (req, res) => {
  function randomGroup() {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    return Array.from({ length: 5 }, () => chars[Math.floor(Math.random() * chars.length)]).join("");
  }
  const invitesPath = path.join(__dirname, "users", "invites.json");
  let invites = {};
  try { invites = JSON.parse(fs.readFileSync(invitesPath)); } catch {}
  let inviteKey;
  do {
    inviteKey = `${randomGroup()}-${randomGroup()}-${randomGroup()}-${randomGroup()}`;
  } while (invites[inviteKey]);
  invites[inviteKey] = true;
  fs.writeFileSync(invitesPath, JSON.stringify(invites, null, 2));
  res.json({ success: true, inviteKey });
});

app.get("/admin", requireAdmin, (req, res) =>
  res.sendFile(path.join(__dirname, "admin.html"))
);

app.get("/admin/api/users", requireAdmin, (req, res) => {
  const usersPath = path.join(__dirname, "users", "accounts.json");
  const invitesPath = path.join(__dirname, "users", "invites.json");
  let users = {}, invites = {};
  try { users = JSON.parse(fs.readFileSync(usersPath)); } catch {}
  try { invites = JSON.parse(fs.readFileSync(invitesPath)); } catch {}
  res.json({ users, invites });
});

app.post("/admin/api/change-password", requireAdmin, (req, res) => {
  const { username, newPassword } = req.body;
  if (!username || !newPassword || newPassword.length < 4)
    return res.json({ success: false, error: "Invalid input" });
  const usersPath = path.join(__dirname, "users", "accounts.json");
  const users = JSON.parse(fs.readFileSync(usersPath));
  if (!users[username]) return res.json({ success: false, error: "User not found" });
  users[username].password = bcrypt.hashSync(newPassword, 10);
  fs.writeFileSync(usersPath, JSON.stringify(users, null, 2));
  res.json({ success: true });
});

app.post("/admin/api/delete-user", requireAdmin, (req, res) => {
  const { username } = req.body;
  const usersPath = path.join(__dirname, "users", "accounts.json");
  const users = JSON.parse(fs.readFileSync(usersPath));
  if (!users[username]) return res.json({ success: false, error: "User not found" });
  delete users[username];
  fs.writeFileSync(usersPath, JSON.stringify(users, null, 2));
  res.json({ success: true });
});

// ======= Login/Register and static files (unchanged) =======
app.use((req, res, next) => {
  const publicPaths = ["/login","/register","/index.html","/","/styles.css","/images"];
  if (publicPaths.includes(req.path) || req.path.startsWith("/images") || req.path.startsWith("/users"))
    return next();
  return requireLogin(req, res, next);
});
app.use(express.static(path.join(__dirname)));
app.get("/login", redirectIfLoggedIn, (req, res) =>
  res.sendFile(path.join(__dirname, "login.html"))
);
app.get("/register", redirectIfLoggedIn, (req, res) =>
  res.sendFile(path.join(__dirname, "register.html"))
);

app.post("/register", (req, res) => {
  const { username, password, invite } = req.body;
  const usersPath = path.join(__dirname, "users", "accounts.json");
  const invitesPath = path.join(__dirname, "users", "invites.json");
  const users = JSON.parse(fs.readFileSync(usersPath));
  const invites = JSON.parse(fs.readFileSync(invitesPath));
  const code = invite.trim().toUpperCase();
  if (!invites[code]) return res.redirect("/register?error=Invalid invite");
  if (users[username]) return res.redirect("/register?error=Username%20taken");
  users[username] = { password: bcrypt.hashSync(password, 10) };
  invites[code] = false;
  fs.writeFileSync(usersPath, JSON.stringify(users, null, 2));
  fs.writeFileSync(invitesPath, JSON.stringify(invites, null, 2));
  req.session.user = username;
  res.redirect("/chat/chat.html");
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  const usersPath = path.join(__dirname, "users", "accounts.json");
  const users = JSON.parse(fs.readFileSync(usersPath));
  if (!users[username] || !bcrypt.compareSync(password, users[username].password))
    return res.redirect("/login?error=Wrong%20username%20or%20password");
  req.session.user = username;
  res.redirect("/chat/chat.html");
});

app.get("/logout", (req, res) => req.session.destroy(() => res.redirect("/login")));
app.get("/users/me", (req, res) => {
  if (!req.session.user) return res.status(401).json({ username: null });
  res.json({ username: req.session.user });
});
app.post("/users/change-password", (req, res) => {
  if (!req.session.user) return res.status(401).json({ success: false });
  const { old, new: newPwd } = req.body;
  const usersPath = path.join(__dirname, "users", "accounts.json");
  const users = JSON.parse(fs.readFileSync(usersPath));
  const username = req.session.user;
  if (!users[username] || !bcrypt.compareSync(old, users[username].password))
    return res.json({ success: false, error: "Old password incorrect" });
  if (!newPwd || newPwd.length < 4)
    return res.json({ success: false, error: "New password too short" });
  users[username].password = bcrypt.hashSync(newPwd, 10);
  fs.writeFileSync(usersPath, JSON.stringify(users, null, 2));
  res.json({ success: true });
});

// ======= WebSocket Chat (unchanged) =======
const server = app.listen(PORT, () =>
  console.log(`Server running on http://localhost:${PORT}`)
);
const wss = new WebSocket.Server({ server, path: "/ws" });
const SECRET_KEY = "40mvLNx2xw7YtmwJP21CWSbNrjuvSdg8";
function wrap(mw) { return (ws, req, next) => mw(req, {}, next); }
const messagesPath = path.join(__dirname, "messages.json");
let messages = [];
if (fs.existsSync(messagesPath)) {
  try { messages = JSON.parse(fs.readFileSync(messagesPath)); } catch {}
}
function saveMessages() {
  fs.writeFileSync(messagesPath, JSON.stringify(messages, null, 2));
}
const lastMessageTime = {};
wss.on("connection", (ws, req) => {
  wrap(sessionMiddleware)(ws, req, () => {
    const ip = req.socket.remoteAddress;
    const username = req.session && req.session.user ? req.session.user : "Unknown";
    ws.username = username;
    messages.forEach(m => ws.send(JSON.stringify(m)));
    ws.on("message", data => {
      const now = Date.now();
      const key = username + "|" + ip;
      if (lastMessageTime[key] && now - lastMessageTime[key] < 500) return;
      lastMessageTime[key] = now;
      let msgObj;
      try { msgObj = JSON.parse(data.toString()); } catch { return; }
      const encrypted = msgObj.encrypted;
      let decrypted = "[Could not decrypt]";
      try { decrypted = crypto.AES.decrypt(encrypted, SECRET_KEY).toString(crypto.enc.Utf8); } catch {}
      const hash = crypto.SHA256(decrypted).toString();
      const timestamp = msgObj.timestamp || new Date().toISOString();
      const messageData = { username, encrypted, hash, time: timestamp, ip };
      messages.push(messageData);
      saveMessages();
      wss.clients.forEach(c => { if (c.readyState === WebSocket.OPEN) c.send(JSON.stringify(messageData)); });
    });
  });
});
function clearMessagesAtMidnight() {
  const now = new Date();
  const next = new Date(now.getFullYear(), now.getMonth(), now.getDate() + 1);
  setTimeout(() => {
    messages = [];
    saveMessages();
    clearMessagesAtMidnight();
  }, next - now);
}
clearMessagesAtMidnight();
