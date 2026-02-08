// api/index.js

let _admin = null;

function json(res, status, data) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(JSON.stringify(data));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => {
      try {
        resolve(raw ? JSON.parse(raw) : {});
      } catch {
        reject(new Error("Invalid JSON"));
      }
    });
  });
}

function getPath(req) {
  return req.url.split("?")[0];
}

function getCookieToken(req) {
  const cookie = require("cookie");
  const cookies = cookie.parse(req.headers.cookie || "");
  return cookies.token || null;
}

function requireAuth(req) {
  try {
    const jwt = require("jsonwebtoken");
    const token = getCookieToken(req);
    if (!token) return false;
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    return decoded && decoded.role === "admin";
  } catch {
    return false;
  }
}

/* ---------- Firebase Lazy Init ---------- */
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

/* ---------- Handlers ---------- */
async function handleLogin(req, res) {
  const body = await readBody(req);
  const { user, password } = body;

  if (!user || !password) return json(res, 400, { error: "Missing credentials" });

  const adminUser = process.env.ADMIN_USER || "";
  const adminPassword = process.env.ADMIN_PASSWORD || "";
  const jwtSecret = process.env.JWT_SECRET || "";

  if (!adminUser || !adminPassword || !jwtSecret) {
    return json(res, 500, { error: "Missing ADMIN_USER / ADMIN_PASSWORD / JWT_SECRET" });
  }

  if (String(user) !== adminUser || String(password) !== adminPassword) {
    return json(res, 401, { error: "Invalid credentials" });
  }

  const jwt = require("jsonwebtoken");
  const token = jwt.sign({ role: "admin", user: adminUser }, jwtSecret, { expiresIn: "7d" });

  const cookie = require("cookie");
  res.setHeader(
    "Set-Cookie",
    cookie.serialize("token", token, {
      httpOnly: true,
      secure: true,
      sameSite: "Lax",
      path: "/",
      maxAge: 60 * 60 * 24 * 7,
    })
  );

  return json(res, 200, { ok: true });
}

async function handleLogout(req, res) {
  const cookie = require("cookie");
  res.setHeader(
    "Set-Cookie",
    cookie.serialize("token", "", {
      httpOnly: true,
      secure: true,
      sameSite: "Lax",
      path: "/",
      maxAge: 0,
    })
  );
  return json(res, 200, { ok: true });
}

async function handleRegister(req, res) {
  const body = await readBody(req);
  const { fullName, phone, gameId } = body;

  if (!fullName || !phone || !gameId) {
    return json(res, 400, { error: "Missing fields" });
  }

  const db = getDb();
  await db.collection("registrations").add({
    ...body,
    createdAtMs: Date.now(),
  });

  return json(res, 200, { ok: true });
}

async function handleRegistrations(req, res) {
  if (!requireAuth(req)) return json(res, 401, { error: "Unauthorized" });

  const db = getDb();
  const snap = await db
    .collection("registrations")
    .orderBy("createdAtMs", "desc")
    .limit(500)
    .get();

  const rows = snap.docs.map((d) => ({ id: d.id, ...d.data() }));
  return json(res, 200, { ok: true, rows });
}

/* ---------- Router ---------- */
module.exports = async (req, res) => {
  try {
    const path = getPath(req);

    // ✅ health لازم يرد دايمًا
    if (path === "/api/health") return json(res, 200, { ok: true });

    if (path === "/api/login" && req.method === "POST") return await handleLogin(req, res);
    if (path === "/api/logout") return await handleLogout(req, res);

    if (path === "/api/register" && req.method === "POST") return await handleRegister(req, res);
    if (path === "/api/registrations") return await handleRegistrations(req, res);

    return json(res, 404, { error: "Not found" });
  } catch (e) {
    // خليها JSON علشان login.html ما يتهزش
    return json(res, 500, { error: e.message || "Server error" });
  }
};
