// api/index.js
let _admin = null;

/* ---------------- Helpers ---------------- */

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
      if (!raw) return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch {
        reject(new Error("Invalid JSON body"));
      }
    });
  });
}

function getPath(req) {
  return (req.url || "").split("?")[0];
}

function getQuery(req) {
  const url = new URL(req.url || "", "http://localhost");
  return url.searchParams;
}

function getCookieToken(req) {
  const cookie = require("cookie");
  const cookies = cookie.parse(req.headers.cookie || "");
  return cookies.token || null;
}

function isAuth(req) {
  try {
    const jwt = require("jsonwebtoken");
    const token = getCookieToken(req);
    if (!token) return false;
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    return !!decoded && decoded.role === "admin";
  } catch {
    return false;
  }
}

/* ---------------- Firebase Admin (lazy) ---------------- */

function getAdmin() {
  if (_admin) return _admin;

  const raw = process.env.FIREBASE_CONFIG;
  if (!raw) throw new Error("Missing FIREBASE_CONFIG");

  let cfg;
  try {
    cfg = JSON.parse(raw);
  } catch {
    throw new Error("FIREBASE_CONFIG must be valid JSON");
  }

  const projectId = cfg.projectId || cfg.project_id;
  const clientEmail = cfg.clientEmail || cfg.client_email;
  const privateKeyRaw = cfg.privateKey || cfg.private_key;

  if (!projectId || !clientEmail || !privateKeyRaw) {
    throw new Error("FIREBASE_CONFIG missing projectId/clientEmail/privateKey");
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

/* ---------------- Handlers ---------------- */

async function handleHealth(req, res) {
  return json(res, 200, { ok: true });
}

async function handleLogin(req, res) {
  if (req.method !== "POST") return json(res, 405, { error: "Method not allowed" });

  const { user, password } = await readBody(req);

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
      sameSite: "Lax",
      path: "/",
      secure: process.env.NODE_ENV === "production",
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
      sameSite: "Lax",
      path: "/",
      secure: process.env.NODE_ENV === "production",
      maxAge: 0,
    })
  );
  return json(res, 200, { ok: true });
}

async function handleMe(req, res) {
  if (!isAuth(req)) return json(res, 401, { error: "Unauthorized" });
  return json(res, 200, { ok: true });
}

async function handleRegister(req, res) {
  if (req.method !== "POST") return json(res, 405, { error: "Method not allowed" });

  const body = await readBody(req);

  const fullName = String(body.fullName || "").trim();
  const phone = String(body.phone || "").trim();
  const gameId = String(body.gameId || "").trim();
  const notes = String(body.notes || "").trim(); // اسم اللاعب/أسماء اللاعبين

  if (fullName.length < 2) return json(res, 400, { error: "fullName is required" });
  if (phone.length < 6) return json(res, 400, { error: "phone is required" });
  if (gameId.length < 2) return json(res, 400, { error: "gameId is required" });
  if (notes.length < 2) return json(res, 400, { error: "player name(s) is required" });

  const db = getDb();

  await db.collection("registrations").add({
    fullName,
    phone,
    gameId,
    notes,
    createdAtMs: Date.now(),
  });

  return json(res, 200, { ok: true, message: "Registered successfully" });
}

async function handleRegistrations(req, res) {
  if (!isAuth(req)) return json(res, 401, { error: "Unauthorized" });

  const db = getDb();
  const snap = await db
    .collection("registrations")
    .orderBy("createdAtMs", "desc")
    .limit(1000)
    .get();

  const rows = snap.docs.map((d) => ({ id: d.id, ...d.data() }));
  return json(res, 200, { ok: true, rows });
}

// ✅ NEW: delete one registration by id
async function handleDeleteRegistration(req, res) {
  if (!isAuth(req)) return json(res, 401, { error: "Unauthorized" });
  if (req.method !== "DELETE") return json(res, 405, { error: "Method not allowed" });

  const q = getQuery(req);
  const id = (q.get("id") || "").trim();
  if (!id) return json(res, 400, { error: "Missing id" });

  const db = getDb();
  await db.collection("registrations").doc(id).delete();

  return json(res, 200, { ok: true });
}

/* ---------------- Router ---------------- */

module.exports = async (req, res) => {
  try {
    const path = getPath(req);

    if (path === "/api/health") return await handleHealth(req, res);

    if (path === "/api/login") return await handleLogin(req, res);
    if (path === "/api/logout") return await handleLogout(req, res);
    if (path === "/api/me") return await handleMe(req, res);

    if (path === "/api/register") return await handleRegister(req, res);
    if (path === "/api/registrations") return await handleRegistrations(req, res);

    // ✅ NEW endpoint
    if (path === "/api/registration") return await handleDeleteRegistration(req, res);

    return json(res, 404, { error: "Not found" });
  } catch (e) {
    return json(res, 500, { error: e.message || "Server error" });
  }
};
