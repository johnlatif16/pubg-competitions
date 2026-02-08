// api/index.js
const admin = require("firebase-admin");
const jwt = require("jsonwebtoken");
const cookie = require("cookie");

/* ---------------- Helpers ---------------- */

function json(res, status, data) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(JSON.stringify(data));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let raw = "";
    req.on("data", (chunk) => (raw += chunk));
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
  const url = new URL(req.url, "http://localhost");
  return url.pathname;
}

function getToken(req) {
  const cookies = cookie.parse(req.headers.cookie || "");
  return cookies.token || null;
}

function requireAuth(req) {
  const token = getToken(req);
  if (!token) return { ok: false, error: "Unauthorized" };

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (!decoded || decoded.role !== "admin") return { ok: false, error: "Unauthorized" };
    return { ok: true, user: decoded };
  } catch {
    return { ok: false, error: "Unauthorized" };
  }
}

/* ---------------- Firebase Admin ---------------- */

function getAdmin() {
  if (admin.apps.length) return admin;

  const raw = process.env.FIREBASE_CONFIG;
  if (!raw) throw new Error("Missing FIREBASE_CONFIG");

  let cfg;
  try {
    cfg = JSON.parse(raw);
  } catch {
    throw new Error("FIREBASE_CONFIG must be valid JSON");
  }

  // support both camelCase and snake_case keys
  const projectId = cfg.projectId || cfg.project_id;
  const clientEmail = cfg.clientEmail || cfg.client_email;
  const privateKeyRaw = cfg.privateKey || cfg.private_key;

  if (!projectId || !clientEmail || !privateKeyRaw) {
    throw new Error("FIREBASE_CONFIG missing projectId/clientEmail/privateKey");
  }

  admin.initializeApp({
    credential: admin.credential.cert({
      projectId,
      clientEmail,
      privateKey: String(privateKeyRaw).replace(/\\n/g, "\n"),
    }),
  });

  return admin;
}

function getDb() {
  const a = getAdmin();
  return a.firestore();
}

/* ---------------- Handlers ---------------- */

async function handleRegister(req, res) {
  if (req.method !== "POST") return json(res, 405, { error: "Method not allowed" });

  let body;
  try {
    body = await readBody(req);
  } catch (e) {
    return json(res, 400, { error: e.message });
  }

  const {
    fullName,
    phone,
    email,
    gameId,
    teamMode,   // "solo" | "duo" | "squad"
    shaddaType, // "325" | "660" | ...
    notes,
  } = body;

  // basic validation
  if (!fullName || String(fullName).trim().length < 2) return json(res, 400, { error: "fullName is required" });
  if (!phone || String(phone).trim().length < 6) return json(res, 400, { error: "phone is required" });
  if (!gameId || String(gameId).trim().length < 2) return json(res, 400, { error: "gameId is required" });

  const db = getDb();

  const doc = {
    fullName: String(fullName).trim(),
    phone: String(phone).trim(),
    email: email ? String(email).trim().toLowerCase() : "",
    gameId: String(gameId).trim(),
    teamMode: teamMode ? String(teamMode) : "solo",
    shaddaType: shaddaType ? String(shaddaType) : "",
    notes: notes ? String(notes).trim() : "",
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
    createdAtMs: Date.now(),
    ip:
      (req.headers["x-forwarded-for"] || "").split(",")[0].trim() ||
      req.socket?.remoteAddress ||
      "",
    userAgent: req.headers["user-agent"] || "",
  };

  await db.collection("registrations").add(doc);

  return json(res, 200, { ok: true, message: "Registered successfully" });
}

async function handleAdminLogin(req, res) {
  if (req.method !== "POST") return json(res, 405, { error: "Method not allowed" });

  let body;
  try {
    body = await readBody(req);
  } catch (e) {
    return json(res, 400, { error: e.message });
  }

  const { user, password } = body;
  if (!user || !password) return json(res, 400, { error: "Missing user or password" });

  const adminUser = (process.env.ADMIN_USER || "").trim();
  const adminPassword = (process.env.ADMIN_PASSWORD || "");
  const jwtSecret = process.env.JWT_SECRET || "";

  if (!adminUser || !adminPassword || !jwtSecret) {
    return json(res, 500, { error: "Missing ADMIN_USER / ADMIN_PASSWORD / JWT_SECRET" });
  }

  // Plain-text compare (زي ما طلبت)
  if (String(user).trim() !== adminUser || String(password) !== adminPassword) {
    return json(res, 401, { error: "Invalid credentials" });
  }

  const token = jwt.sign(
    { role: "admin", user: adminUser },
    jwtSecret,
    { expiresIn: "7d" }
  );

  // JWT in httpOnly cookie
  res.setHeader(
    "Set-Cookie",
    cookie.serialize("token", token, {
      httpOnly: true,
      secure: true,      // Vercel https
      sameSite: "Lax",
      path: "/",
      maxAge: 60 * 60 * 24 * 7,
    })
  );

  return json(res, 200, { ok: true });
}

async function handleLogout(req, res) {
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

async function handleMe(req, res) {
  const auth = requireAuth(req);
  if (!auth.ok) return json(res, 401, { error: auth.error });

  return json(res, 200, {
    ok: true,
    user: { user: auth.user.user, role: auth.user.role },
  });
}

async function handleListRegistrations(req, res) {
  const auth = requireAuth(req);
  if (!auth.ok) return json(res, 401, { error: auth.error });

  const db = getDb();
  const url = new URL(req.url, "http://localhost");
  const limit = Math.min(Number(url.searchParams.get("limit") || "200"), 1000);

  const snap = await db
    .collection("registrations")
    .orderBy("createdAtMs", "desc")
    .limit(limit)
    .get();

  const rows = snap.docs.map((d) => ({ id: d.id, ...d.data() }));
  return json(res, 200, { ok: true, rows });
}

/* ---------------- Router ---------------- */

module.exports = async (req, res) => {
  try {
    const path = getPath(req);

    // Health
    if (path === "/api/health") return json(res, 200, { ok: true });

    // Public
    if (path === "/api/register") return await handleRegister(req, res);

    // Admin auth
    if (path === "/api/login") return await handleAdminLogin(req, res);
    if (path === "/api/logout") return await handleLogout(req, res);
    if (path === "/api/me") return await handleMe(req, res);

    // Admin data (JWT protected)
    if (path === "/api/registrations") return await handleListRegistrations(req, res);

    return json(res, 404, { error: "Not found" });
  } catch (e) {
    return json(res, 500, { error: e.message || "Server error" });
  }
};
