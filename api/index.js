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

// timing-safe compare for reset key
function safeEqual(a, b) {
  try {
    const crypto = require("crypto");
    const A = Buffer.from(String(a ?? ""), "utf8");
    const B = Buffer.from(String(b ?? ""), "utf8");
    if (A.length !== B.length) return false;
    return crypto.timingSafeEqual(A, B);
  } catch {
    return false;
  }
}

function hasValidResetKey(body) {
  const key = process.env.RESET_KEY || "";
  if (!key) return false;
  return safeEqual(body?.resetKey, key);
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

/* ---------------- Admin Auth Config in Firestore ---------------- */

async function getAdminAuthRef(db) {
  return db.collection("admin").doc("auth");
}

/**
 * Reads admin auth from Firestore.
 * If missing, bootstraps once from ENV (ADMIN_USER/ADMIN_PASSWORD) and stores hashed password.
 */
async function readAdminAuth(db) {
  const ref = await getAdminAuthRef(db);
  const snap = await ref.get();
  if (snap.exists) return { ref, data: snap.data() };

  // Bootstrap from ENV once (if provided)
  const adminUser = process.env.ADMIN_USER || "";
  const adminPassword = process.env.ADMIN_PASSWORD || "";

  if (!adminUser || !adminPassword) {
    return { ref, data: null };
  }

  const bcrypt = require("bcryptjs");
  const passwordHash = await bcrypt.hash(String(adminPassword), 12);

  const data = {
    user: String(adminUser),
    passwordHash,
    updatedAtMs: Date.now(),
  };

  await ref.set(data, { merge: true });
  return { ref, data };
}

async function verifyCurrentPassword(db, currentPassword) {
  const { data } = await readAdminAuth(db);
  if (!data?.passwordHash) return false;
  const bcrypt = require("bcryptjs");
  return await bcrypt.compare(String(currentPassword || ""), String(data.passwordHash));
}

/* ---------------- Handlers ---------------- */

async function handleHealth(req, res) {
  return json(res, 200, { ok: true });
}

async function handleLogin(req, res) {
  if (req.method !== "POST") return json(res, 405, { error: "Method not allowed" });

  const { user, password } = await readBody(req);
  if (!user || !password) return json(res, 400, { error: "Missing credentials" });

  const jwtSecret = process.env.JWT_SECRET || "";
  if (!jwtSecret) return json(res, 500, { error: "Missing JWT_SECRET" });

  const db = getDb();
  const { data } = await readAdminAuth(db);

  if (!data?.user || !data?.passwordHash) {
    return json(res, 500, { error: "Admin auth config not set" });
  }

  const bcrypt = require("bcryptjs");
  const okUser = String(user) === String(data.user);
  const okPass = await bcrypt.compare(String(password), String(data.passwordHash));

  if (!okUser || !okPass) return json(res, 401, { error: "Invalid credentials" });

  const jwt = require("jsonwebtoken");
  const token = jwt.sign({ role: "admin", user: data.user }, jwtSecret, { expiresIn: "7d" });

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
  const notes = String(body.notes || "").trim();

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

/* ---------------- NEW: Reset endpoints (NO login) ----------------
   Require: resetKey + currentPassword
*/

async function handleAdminUsername(req, res) {
  if (req.method !== "PATCH") return json(res, 405, { error: "Method not allowed" });

  const body = await readBody(req);

  if (!hasValidResetKey(body)) return json(res, 401, { error: "Invalid reset key" });

  const currentPassword = body.currentPassword;
  const userTrim = String(body.newUser || "").trim();

  if (!currentPassword) return json(res, 400, { error: "currentPassword is required" });
  if (userTrim.length < 2) return json(res, 400, { error: "newUser is required" });

  const db = getDb();

  const ok = await verifyCurrentPassword(db, currentPassword);
  if (!ok) return json(res, 401, { error: "Current password is incorrect" });

  const { ref } = await readAdminAuth(db);
  await ref.set({ user: userTrim, updatedAtMs: Date.now() }, { merge: true });

  return json(res, 200, { ok: true });
}

async function handleAdminPassword(req, res) {
  if (req.method !== "PATCH") return json(res, 405, { error: "Method not allowed" });

  const body = await readBody(req);

  if (!hasValidResetKey(body)) return json(res, 401, { error: "Invalid reset key" });

  const currentPassword = body.currentPassword;
  const pass = String(body.newPassword || "");

  if (!currentPassword) return json(res, 400, { error: "currentPassword is required" });
  if (pass.length < 8) return json(res, 400, { error: "newPassword must be at least 8 chars" });

  const db = getDb();

  const ok = await verifyCurrentPassword(db, currentPassword);
  if (!ok) return json(res, 401, { error: "Current password is incorrect" });

  const bcrypt = require("bcryptjs");
  const passwordHash = await bcrypt.hash(pass, 12);

  const { ref } = await readAdminAuth(db);
  await ref.set({ passwordHash, updatedAtMs: Date.now() }, { merge: true });

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

    if (path === "/api/registration") return await handleDeleteRegistration(req, res);

    // ✅ reset without login (requires RESET_KEY)
    if (path === "/api/admin/username") return await handleAdminUsername(req, res);
    if (path === "/api/admin/password") return await handleAdminPassword(req, res);

    return json(res, 404, { error: "Not found" });
  } catch (e) {
    return json(res, 500, { error: e.message || "Server error" });
  }
};
