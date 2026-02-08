// api/index.js
const jwt = require("jsonwebtoken");
const cookie = require("cookie");

let _admin = null;

/* ---------------- Firebase Lazy Init ---------------- */
function getAdmin() {
  if (_admin) return _admin;

  const raw = process.env.FIREBASE_CONFIG;
  if (!raw) throw new Error("Missing FIREBASE_CONFIG");

  let cfg;
  try {
    cfg = JSON.parse(raw);
  } catch {
    throw new Error("FIREBASE_CONFIG invalid JSON");
  }

  const projectId = cfg.projectId || cfg.project_id;
  const clientEmail = cfg.clientEmail || cfg.client_email;
  const privateKeyRaw = cfg.privateKey || cfg.private_key;

  if (!projectId || !clientEmail || !privateKeyRaw) {
    throw new Error("FIREBASE_CONFIG missing fields");
  }

  const admin = require("firebase-admin");

  if (!admin.apps.length) {
    admin.initializeApp({
      credential: admin.credential.cert({
        projectId,
        clientEmail,
        privateKey: String(privateKeyRaw).replace(/\\n/g, "\n"),
      }),
    });
  }

  _admin = admin;
  return _admin;
}

function getDb() {
  const admin = getAdmin();
  return admin.firestore();
}

/* ---------------- Helpers ---------------- */
function json(res, status, data) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(JSON.stringify(data));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let raw = "";
    req.on("data", c => raw += c);
    req.on("end", () => {
      try { resolve(raw ? JSON.parse(raw) : {}); }
      catch { reject(new Error("Invalid JSON")); }
    });
  });
}

function getToken(req) {
  const cookies = cookie.parse(req.headers.cookie || "");
  return cookies.token || null;
}

function requireAuth(req) {
  try {
    const token = getToken(req);
    if (!token) return false;
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    return decoded && decoded.role === "admin";
  } catch {
    return false;
  }
}

/* ---------------- Handlers ---------------- */

async function handleLogin(req, res) {
  const body = await readBody(req);
  const { user, password } = body;

  if (!user || !password)
    return json(res, 400, { error: "Missing credentials" });

  if (
    user !== process.env.ADMIN_USER ||
    password !== process.env.ADMIN_PASSWORD
  ) {
    return json(res, 401, { error: "Invalid credentials" });
  }

  const token = jwt.sign(
    { role: "admin", user },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );

  res.setHeader("Set-Cookie",
    cookie.serialize("token", token, {
      httpOnly: true,
      secure: true,
      sameSite: "Lax",
      path: "/",
      maxAge: 60 * 60 * 24 * 7
    })
  );

  return json(res, 200, { ok: true });
}

async function handleLogout(req, res) {
  res.setHeader("Set-Cookie",
    cookie.serialize("token", "", {
      httpOnly: true,
      secure: true,
      sameSite: "Lax",
      path: "/",
      maxAge: 0
    })
  );
  return json(res, 200, { ok: true });
}

async function handleRegister(req, res) {
  const body = await readBody(req);
  const { fullName, phone, gameId } = body;

  if (!fullName || !phone || !gameId)
    return json(res, 400, { error: "Missing fields" });

  const db = getDb();
  await db.collection("registrations").add({
    ...body,
    createdAt: Date.now()
  });

  return json(res, 200, { ok: true });
}

async function handleList(req, res) {
  if (!requireAuth(req))
    return json(res, 401, { error: "Unauthorized" });

  const db = getDb();
  const snap = await db.collection("registrations")
    .orderBy("createdAt", "desc")
    .limit(200)
    .get();

  const rows = snap.docs.map(d => ({ id: d.id, ...d.data() }));
  return json(res, 200, { rows });
}

/* ---------------- Router ---------------- */

module.exports = async (req, res) => {
  try {
    const path = req.url.split("?")[0];

    if (path === "/api/health")
      return json(res, 200, { ok: true });

    if (path === "/api/login" && req.method === "POST")
      return handleLogin(req, res);

    if (path === "/api/logout")
      return handleLogout(req, res);

    if (path === "/api/register" && req.method === "POST")
      return handleRegister(req, res);

    if (path === "/api/registrations")
      return handleList(req, res);

    return json(res, 404, { error: "Not found" });
  } catch (e) {
    return json(res, 500, { error: e.message || "Server error" });
  }
};
