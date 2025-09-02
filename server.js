// server/server.js
require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

// models and middleware
const User = require("./models/User");
const Task = require("./models/Task");
const Log = require("./models/Log");
const Review = require("./models/Review");
const Admin = require("./models/Admin"); // <-- Admin model
const Announcement = require("./models/Announcement"); // <-- added
const auth = require("./middleware/auth");

const app = express();

/* ======================= base app setup ======================= */
app.use(express.json());

// CORS allow list based on env and common dev hosts
const devAllowed = ["http://localhost:5173", "http://localhost:3000"];
const envAllowed = (process.env.CORS_ALLOWED_ORIGINS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

function isAllowedOrigin(origin) {
  if (!origin) return true; // tools and curl
  try {
    const u = new URL(origin);
    if (devAllowed.includes(origin)) return true;
    if (envAllowed.includes(origin)) return true;
    // allow vercel previews and prod subdomains
    if (u.hostname.endsWith(".vercel.app")) return true;
  } catch {}
  return false;
}

app.use(
  cors({
    origin(origin, cb) {
      if (isAllowedOrigin(origin)) return cb(null, true);
      cb(new Error("CORS blocked"));
    },
    credentials: true,
  })
);

// trust proxy when behind render
app.set("trust proxy", 1);

// simple health
app.get("/api/health", (_req, res) => res.json({ ok: true }));

/* ======================= uploads setup ======================== */
const uploadsDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
app.use("/uploads", express.static(uploadsDir));

// hybrid upload
// use cloud when CLOUDINARY_URL is set, else use local disk
const useCloud = !!process.env.CLOUDINARY_URL;

let upload;
let saveProof; // async (file) => returns a string url or local path
let removeProofFileIfLocal; // (proofUrl) => void

if (useCloud) {
  // memory upload and stream to cloud
  const mem = multer({ storage: multer.memoryStorage() });
  upload = mem;

  const { v2: cloudinary } = require("cloudinary"); // uses CLOUDINARY_URL
  const streamifier = require("streamifier");

  saveProof = async function saveToCloud(file) {
    return new Promise((resolve, reject) => {
      const publicId = Date.now() + "-" + file.originalname;
      const uploadStream = cloudinary.uploader.upload_stream(
        { folder: "founder-app", public_id: publicId, resource_type: "auto" },
        (err, result) => (err ? reject(err) : resolve(result.secure_url))
      );
      streamifier.createReadStream(file.buffer).pipe(uploadStream);
    });
  };

  removeProofFileIfLocal = function noop() {};
} else {
  // disk upload
  const storage = multer.diskStorage({
    destination: uploadsDir,
    filename: (_req, file, cb) => cb(null, Date.now() + "-" + file.originalname),
  });
  upload = multer({ storage });

  saveProof = async function saveToDisk(file) {
    return `/uploads/${file.filename}`;
  };

  removeProofFileIfLocal = function removeLocal(proofUrl) {
    try {
      if (!proofUrl || !proofUrl.startsWith("/uploads/")) return;
      const abs = path.join(uploadsDir, proofUrl.replace("/uploads/", ""));
      fs.unlink(abs, () => {});
    } catch {}
  };
}

/* ======================= database connect ===================== */
(async function connectDB() {
  try {
    const uri = process.env.MONGODB_URI || process.env.MONGO_URI;
    if (!uri) throw new Error("MONGODB_URI or MONGO_URI missing in env");
    await mongoose.connect(uri, { serverSelectionTimeoutMS: 8000 });
    console.log("Mongo connected");

    try {
      await Review.syncIndexes();
    } catch {}
  } catch (err) {
    console.error("Mongo connect failed:", err.message);
    process.exit(1);
  }
})();

/* ======================= helpers and consts =================== */
const JWT_SECRET = process.env.JWT_SECRET || "devsecret";
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5173";

const REQUIRED_REVIEW_ROLES = {
  CEO: ["COO", "MARKETING"],
  COO: ["CEO", "MARKETING"],
  MARKETING: ["CEO", "COO"],
};
const requiredRolesFor = (submitterRole) =>
  REQUIRED_REVIEW_ROLES[submitterRole] || ["COO", "MARKETING"];

const oid = (id) => new mongoose.Types.ObjectId(id);

function toObjectIdSafe(v) {
  try {
    if (!v) return null;
    if (typeof v === "object" && v._id) v = v._id;
    const s = String(v);
    if (mongoose.Types.ObjectId.isValid(s)) return new mongoose.Types.ObjectId(s);
  } catch {}
  return null;
}
function normDateStr(d) {
  if (!d) return "";
  const s = String(d).trim();
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return s;
  const m = s.match(/^(\d{2})\/(\d{2})\/(\d{4})$/);
  if (m) return `${m[3]}-${m[1]}-${m[2]}`;
  return s;
}

function scoresColl() {
  return mongoose.connection.collection("scores");
}

/* ======================= auth routes ========================== */
app.get("/api/auth/me", auth, (req, res) =>
  res.json({ id: req.user.id, name: req.user.name, role: req.user.role })
);

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const user = await User.findOne({ email }).select("+passwordHash");
    if (!user) return res.status(401).json({ error: "no user" });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: "bad pass" });

    const token = jwt.sign(
      { id: user._id, name: user.name, role: user.role },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ token, user: { id: user._id, name: user.name, role: user.role } });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* =================== password reset flow (users) ============== */
async function sendResetEmail(to, link) {
  const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, EMAIL_FROM } = process.env;
  if (!SMTP_HOST || !SMTP_USER || !SMTP_PASS) {
    console.log("RESET LINK for", to, "=>", link);
    return;
  }
  const nodemailer = require("nodemailer");
  const transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: Number(SMTP_PORT || 587),
    secure: false,
    auth: { user: SMTP_USER, pass: SMTP_PASS },
  });
  await transporter.sendMail({
    from: EMAIL_FROM || "noreply@example.com",
    to,
    subject: "Reset your password",
    html: `<p>Click the link below to set a new password. This link expires in 15 minutes.</p>
           <p><a href="${link}">${link}</a></p>`,
  });
}

app.post("/api/auth/forgot", async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email) return res.status(400).send("Email required");

    const user = await User.findOne({ email: String(email) });
    const finish = async () =>
      res.json({ ok: true, message: "If that email exists we sent a reset link" });

    if (!user) return finish();

    const token = jwt.sign(
      { id: user._id, purpose: "reset" },
      JWT_SECRET,
      { expiresIn: "15m" }
    );
    const link = `${FRONTEND_URL}/reset-password?token=${encodeURIComponent(token)}`;

    await sendResetEmail(user.email, link);
    return finish();
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/auth/reset", async (req, res) => {
  try {
    const { token, newPassword } = req.body || {};
    if (!token || !newPassword) return res.status(400).send("Missing fields");

    let payload;
    try {
      payload = jwt.verify(token, JWT_SECRET);
    } catch {
      return res.status(400).send("Invalid or expired token");
    }
    if (payload.purpose !== "reset" || !payload.id) {
      return res.status(400).send("Invalid token");
    }

    const user = await User.findById(payload.id).select("+passwordHash");
    if (!user) return res.status(400).send("Invalid token");

    const salt = await bcrypt.genSalt(10);
    user.passwordHash = await bcrypt.hash(newPassword, salt);
    await user.save();

    res.json({ ok: true, message: "Password updated. Please login" });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* =========== admin forgot/reset (Admins collection + email) ==== */
app.post("/api/admin/auth/forgot", async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email) return res.status(400).send("Email required");

    const admin = await Admin.findOne({ email: String(email).toLowerCase() });
    const finish = () =>
      res.json({ ok: true, message: "If that email exists we sent a reset link" });

    if (!admin) return finish();

    const token = jwt.sign(
      { id: admin._id, purpose: "admin-reset" },
      JWT_SECRET,
      { expiresIn: "15m" }
    );
    const link = `${FRONTEND_URL}/admin/reset-password?token=${encodeURIComponent(
      token
    )}`;

    await sendResetEmail(admin.email, link);
    return finish();
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/admin/auth/reset", async (req, res) => {
  try {
    const { token, newPassword } = req.body || {};
    if (!token || !newPassword) return res.status(400).send("Missing fields");

    let payload;
    try {
      payload = jwt.verify(token, JWT_SECRET);
    } catch {
      return res.status(400).send("Invalid or expired token");
    }
    if (payload.purpose !== "admin-reset" || !payload.id) {
      return res.status(400).send("Invalid token");
    }

    const admin = await Admin.findById(payload.id).select("+passwordHash");
    if (!admin) return res.status(400).send("Invalid token");

    const salt = await bcrypt.genSalt(10);
    admin.passwordHash = await bcrypt.hash(newPassword, salt);
    await admin.save();

    res.json({ ok: true, message: "Password updated. Please login" });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* =================== admin auth for dashboard =================
   1) Try Admins collection (hashed password)
   2) Fallback to ADMIN_EMAIL / ADMIN_PASSWORD from .env
================================================================ */
app.post("/api/admin/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ error: "email and password required" });
    }

    // 1) DB admin
    const adminDoc = await Admin.findOne({
      email: String(email).toLowerCase(),
    }).select("+passwordHash");

    if (adminDoc) {
      const ok = await bcrypt.compare(password, adminDoc.passwordHash);
      if (!ok) return res.status(401).json({ error: "invalid admin credentials" });

      const token = jwt.sign(
        { id: adminDoc._id, name: adminDoc.name, role: "ADMIN" },
        JWT_SECRET,
        { expiresIn: "7d" }
      );
      return res.json({
        token,
        admin: { id: adminDoc._id, name: adminDoc.name, email: adminDoc.email },
      });
    }

    // 2) Env fallback
    const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
    const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
    if (
      ADMIN_EMAIL &&
      ADMIN_PASSWORD &&
      email === ADMIN_EMAIL &&
      password === ADMIN_PASSWORD
    ) {
      const token = jwt.sign(
        { id: "admin", name: "System Admin", role: "ADMIN" },
        JWT_SECRET,
        { expiresIn: "7d" }
      );
      return res.json({
        token,
        admin: { id: "admin", name: "System Admin", email: ADMIN_EMAIL },
      });
    }

    return res.status(401).json({ error: "invalid admin credentials" });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ========================== seed data ========================= */
app.post("/api/seed", runSeed);
app.get("/api/seed", runSeed);

async function runSeed(_req, res) {
  try {
    const count = await User.countDocuments();
    if (count > 0) return res.json({ ok: true, note: "already seeded" });

    // .env only (no fallbacks)
    const {
      SEED_USERS_CEO_EMAIL,
      SEED_USERS_CEO_PASS,
      SEED_USERS_COO_EMAIL,
      SEED_USERS_COO_PASS,
      SEED_USERS_MARKETING_EMAIL,
      SEED_USERS_MARKETING_PASS,
    } = process.env;

    if (
      !SEED_USERS_CEO_EMAIL ||
      !SEED_USERS_CEO_PASS ||
      !SEED_USERS_COO_EMAIL ||
      !SEED_USERS_COO_PASS ||
      !SEED_USERS_MARKETING_EMAIL ||
      !SEED_USERS_MARKETING_PASS
    ) {
      return res.status(500).json({ error: "Missing SEED_USERS_* env vars" });
    }

    const users = [
      {
        name: "Dayien Joseph",
        email: SEED_USERS_CEO_EMAIL,
        role: "CEO",
        passwordHash: await bcrypt.hash(SEED_USERS_CEO_PASS, 10),
      },
      {
        name: "Arjun",
        email: SEED_USERS_COO_EMAIL,
        role: "COO",
        passwordHash: await bcrypt.hash(SEED_USERS_COO_PASS, 10),
      },
      {
        name: "John Paul",
        email: SEED_USERS_MARKETING_EMAIL,
        role: "MARKETING",
        passwordHash: await bcrypt.hash(SEED_USERS_MARKETING_PASS, 10),
      },
    ];
    await User.insertMany(users);

    const tasks = [
      { title: "Set top three priorities", role: "CEO", points: 5 },
      { title: "Review project progress", role: "CEO", points: 5 },
      { title: "Work on one tech task", role: "CEO", points: 8 },

      { title: "Check timelines and tasks", role: "COO", points: 5 },
      { title: "Verify quality of work", role: "COO", points: 7 },
      { title: "Client status update", role: "COO", points: 6 },

      { title: "Run one marketing activity", role: "MARKETING", points: 7 },
      { title: "Contact one lead", role: "MARKETING", points: 6 },
      { title: "Record leads in CRM", role: "MARKETING", points: 5 },

      { title: "Peer verify one update", role: "ALL", points: 4 },
    ];
    await Task.insertMany(tasks);

    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: e.message });
  }
}

/* ============================ tasks =========================== */
app.get("/api/tasks", auth, async (req, res) => {
  try {
    const role = req.user.role;
    const tasks = await Task.find({
      $or: [{ role }, { role: "ALL" }],
      isActive: { $ne: false },
    }).sort({ role: 1 });
    res.json(tasks);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ======================= admin tasks crud ===================== */
app.get("/api/admin/tasks", auth, async (req, res) => {
  try {
    if (req.user.role !== "ADMIN" && req.user.role !== "CEO")
      return res.status(403).json({ error: "only admin or CEO" });
    const rows = await Task.find().sort({ role: 1, title: 1 });
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/admin/tasks", auth, async (req, res) => {
  try {
    if (req.user.role !== "ADMIN" && req.user.role !== "CEO")
      return res.status(403).json({ error: "only admin or CEO" });

    const { title, role, points, isActive = true } = req.body || {};
    if (!title || !role || points === undefined)
      return res.status(400).json({ error: "missing fields" });

    const t = await Task.create({
      title: String(title).trim(),
      role,
      points: Number(points),
      isActive: Boolean(isActive),
    });
    res.status(201).json(t);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.put("/api/admin/tasks/:id", auth, async (req, res) => {
  try {
    if (req.user.role !== "ADMIN" && req.user.role !== "CEO")
      return res.status(403).json({ error: "only admin or CEO" });

    const { title, role, points, isActive } = req.body || {};
    const t = await Task.findByIdAndUpdate(
      req.params.id,
      { title, role, points, isActive },
      { new: true, runValidators: true }
    );
    if (!t) return res.status(404).json({ error: "task not found" });
    res.json(t);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete("/api/admin/tasks/:id", auth, async (req, res) => {
  try {
    if (req.user.role !== "ADMIN" && req.user.role !== "CEO")
      return res.status(403).json({ error: "only admin/CEO" });

    const t = await Task.findByIdAndDelete(req.params.id);
    if (!t) return res.status(404).json({ error: "task not found" });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ====================== announcements ========================= */
// list announcements for everyone
app.get("/api/announcements", auth, async (req, res) => {
  try {
    const { limit = 50 } = req.query;
    const rows = await Announcement.find({})
      .sort({ pinned: -1, createdAt: -1 })
      .limit(Number(limit));
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// create announcement only ADMIN or CEO
app.post("/api/announcements", auth, async (req, res) => {
  try {
    if (req.user.role !== "ADMIN" && req.user.role !== "CEO") {
      return res.status(403).json({ error: "only admin or ceo can post" });
    }
    const { title, body, pinned = false } = req.body || {};
    if (!title || !body) return res.status(400).json({ error: "missing fields" });

    const doc = await Announcement.create({
      title: String(title).trim(),
      body: String(body).trim(),
      pinned: Boolean(pinned),
      createdBy: { _id: req.user.id, name: req.user.name, role: req.user.role },
    });
    res.json(doc);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// delete announcement only ADMIN or CEO
app.delete("/api/announcements/:id", auth, async (req, res) => {
  try {
    if (req.user.role !== "ADMIN" && req.user.role !== "CEO") {
      return res.status(403).json({ error: "only admin or ceo" });
    }
    await Announcement.findByIdAndDelete(req.params.id);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ============================ logs ============================ */
app.post("/api/logs", auth, upload.single("proof"), async (req, res) => {
  try {
    const { taskId, date, note } = req.body;
    if (!note || !req.file)
      return res.status(400).json({ error: "note and proof are required" });

    const proofPath = await saveProof(req.file);

    const log = await Log.create({
      userId: req.user.id,
      taskId,
      date,
      note: note.trim(),
      proofUrl: proofPath,
      status: "PENDING",
      reviewRound: 1,
    });
    res.json(log);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/logs/upsert", auth, upload.single("proof"), async (req, res) => {
  try {
    const { taskId, date, note } = req.body;
    if (!note || !req.file)
      return res.status(400).json({ error: "note and proof are required" });

    let log = await Log.findOne({ userId: req.user.id, taskId, date });
    const proofPath = await saveProof(req.file);

    if (log) {
      removeProofFileIfLocal(log.proofUrl);
      log.note = note.trim();
      log.proofUrl = proofPath;
      log.status = "PENDING";
      log.reviewRound = (log.reviewRound || 1) + 1;
      await log.save();
      log = await Log.findById(log._id).populate("taskId");
    } else {
      log = await Log.create({
        userId: req.user.id,
        taskId,
        date,
        note: note.trim(),
        proofUrl: proofPath,
        status: "PENDING",
        reviewRound: 1,
      });
      log = await Log.findById(log._id).populate("taskId");
    }

    res.json(log);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.put("/api/logs/:id", auth, upload.single("proof"), async (req, res) => {
  try {
    const { note } = req.body;
    if (!note || !req.file)
      return res.status(400).json({ error: "note and proof are required" });

    let log = await Log.findOne({ _id: req.params.id, userId: req.user.id });
    if (!log) return res.status(404).json({ error: "no log" });

    const proofPath = await saveProof(req.file);

    removeProofFileIfLocal(log.proofUrl);
    log.note = note.trim();
    log.proofUrl = proofPath;
    log.status = "PENDING";
    log.reviewRound = (log.reviewRound || 1) + 1;
    await log.save();

    log = await Log.findById(log._id).populate("taskId");
    res.json(log);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/api/logs", auth, async (req, res) => {
  try {
    const { date } = req.query;
    const logs = await Log.find({ userId: req.user.id, date })
      .populate("taskId")
      .lean();

    if (logs.length === 0) return res.json([]);

    const ids = logs.map((l) => l._id);
    const reviews = await Review.find({ logId: { $in: ids } })
      .populate("reviewerId", "name role")
      .lean();

    const byLogRound = new Map();
    for (const r of reviews) {
      const key = `${r.logId}:${r.round || 1}`;
      if (!byLogRound.has(key)) byLogRound.set(key, []);
      byLogRound.get(key).push(r);
    }

    const result = logs.map((l) => {
      const round = l.reviewRound || 1;
      const key = `${l._id}:${round}`;
      const rs = byLogRound.get(key) || [];
      const approved = rs.filter((x) => x.decision === "APPROVE").length;
      const rejected = rs.filter((x) => x.decision === "REJECT").length;
      const reviewsForUi = rs.map((x) => ({
        name: x.reviewerId?.name,
        role: x.reviewerId?.role,
        decision: x.decision,
        comment: x.comment || "",
      }));
      return {
        ...l,
        currentRound: round,
        reviews: reviewsForUi,
        approvedCount: approved,
        rejectedCount: rejected,
        reviewSummary: { approvals: approved, rejections: rejected, required: 2 },
      };
    });

    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete("/api/logs/:id", auth, async (req, res) => {
  try {
    const log = await Log.findOne({ _id: req.params.id, userId: req.user.id });
    if (!log) return res.status(404).json({ error: "no log" });

    removeProofFileIfLocal(log.proofUrl);
    await log.deleteOne();
    await recomputeScoreInternal(log.userId, log.date);

    res.status(204).end();
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* =========================== reviews ========================== */
app.get("/api/reviews/pending", auth, async (req, res) => {
  try {
    const { date } = req.query;

    const q = { status: "PENDING", userId: { $ne: oid(req.user.id) } };
    if (date) q.date = String(date);

    let logs = await Log.find(q)
      .populate("userId", "name role")
      .populate("taskId")
      .lean();

    if (logs.length === 0) return res.json([]);

    logs = logs.filter((l) => requiredRolesFor(l.userId?.role).includes(req.user.role));
    if (logs.length === 0) return res.json([]);

    const reviewerId = oid(req.user.id);
    const pending = [];
    for (const l of logs) {
      const round = l.reviewRound || 1;
      const already = await Review.exists({ logId: l._id, reviewerId, round });
      if (!already) pending.push(l);
    }

    res.json(pending);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/reviews", auth, async (req, res) => {
  try {
    const { logId, decision, comment } = req.body || {};
    if (!logId) return res.status(400).json({ error: "logId required" });

    let log = await Log.findById(logId).populate("userId", "role");
    if (!log) return res.status(404).json({ error: "no log" });
    if (String(log.userId) === req.user.id)
      return res.status(400).json({ error: "cannot review self" });
    if (log.status !== "PENDING")
      return res.status(400).json({ error: "log is not pending review" });

    const round = log.reviewRound || 1;
    const needed = requiredRolesFor(log.userId.role);
    if (!needed.includes(req.user.role))
      return res.status(403).json({ error: "not allowed reviewer" });

    const norm = String(decision || "").trim().toUpperCase();
    const finalDecision = norm.startsWith("APPROV")
      ? "APPROVE"
      : norm.startsWith("REJECT")
      ? "REJECT"
      : null;
    if (!finalDecision) return res.status(400).json({ error: "bad decision" });

    const exists = await Review.findOne({ logId, reviewerId: req.user.id, round });
    if (exists) return res.status(400).json({ error: "already reviewed this round" });

    await Review.create({
      logId,
      reviewerId: req.user.id,
      decision: finalDecision,
      comment: (comment || "").trim(),
      round,
    });

    const roundReviews = await Review.find({ logId, round }).populate(
      "reviewerId",
      "role"
    );
    if (roundReviews.some((r) => r.decision === "REJECT")) {
      log.status = "REJECTED";
      await log.save();
      await recomputeScoreInternal(log.userId, log.date);
      return res.json({ ok: true, status: "REJECTED" });
    }

    const approvedRoles = new Set(
      roundReviews.filter((r) => r.decision === "APPROVE").map((r) => r.reviewerId?.role)
    );
    const allApproved = needed.every((role) => approvedRoles.has(role));
    if (allApproved) {
      log.status = "VERIFIED";
      await log.save();
      await recomputeScoreInternal(log.userId, log.date);
      return res.json({ ok: true, status: "VERIFIED" });
    }

    res.json({ ok: true, status: "PENDING" });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ======================= admin log views ====================== */
app.get("/api/admin/logs", auth, async (req, res) => {
  try {
    if (req.user.role !== "ADMIN" && req.user.role !== "CEO")
      return res.status(403).json({ error: "only admin/CEO" });

    const { date } = req.query;
    const q = date ? { date } : {};
    const rows = await Log.find(q)
      .populate("userId", "name role")
      .populate("taskId", "title role points")
      .sort({ date: 1 });
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete("/api/admin/logs/:id", auth, async (req, res) => {
  try {
    if (req.user.role !== "ADMIN" && req.user.role !== "CEO")
      return res.status(403).json({ error: "only admin/CEO" });

    const log = await Log.findById(req.params.id);
    if (!log) return res.status(404).json({ error: "log not found for id " + req.params.id });

    removeProofFileIfLocal(log.proofUrl);
    await log.deleteOne();
    await recomputeScoreInternal(log.userId, log.date);

    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ======================== score and board ===================== */
async function recomputeScoreInternal(userId, date) {
  try {
    const uid = toObjectIdSafe(userId);
    if (!uid) {
      console.error("score recompute bad userId");
      return;
    }
    const dstr = normDateStr(date);

    const verifiedCount = await Log.countDocuments({
      userId: uid,
      date: String(dstr),
      status: "VERIFIED",
    });

    const total = verifiedCount * 5;

    await scoresColl().findOneAndUpdate(
      { userId: uid, date: String(dstr) },
      {
        $set: {
          userId: uid,
          date: String(dstr),
          tasksDone: verifiedCount,
          total,
          rawPoints: 0,
          proofBonus: 0,
          verifyBonus: 0,
        },
      },
      { upsert: true }
    );
  } catch (e) {
    console.error("score recompute failed:", e.message);
  }
}

app.post("/api/score/recompute", auth, async (req, res) => {
  try {
    const { date, userId } = req.body;
    const uid = userId ? toObjectIdSafe(userId) : toObjectIdSafe(req.user.id);
    const dstr = normDateStr(date);

    await recomputeScoreInternal(uid, dstr);
    const s = await scoresColl().findOne({
      userId: uid,
      date: String(dstr || ""),
    });
    res.json(
      s || { total: 0, tasksDone: 0, rawPoints: 0, proofBonus: 0, verifyBonus: 0 }
    );
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/api/score", auth, async (req, res) => {
  try {
    const { date } = req.query;
    const dstr = normDateStr(date);
    const s = await scoresColl().findOne({
      userId: toObjectIdSafe(req.user.id),
      date: String(dstr || ""),
    });
    res.json(
      s || { total: 0, tasksDone: 0, rawPoints: 0, proofBonus: 0, verifyBonus: 0 }
    );
  } catch (e) {
    console.error("score route error:", e);
    res.json({
      total: 0,
      tasksDone: 0,
      rawPoints: 0,
      proofBonus: 0,
      verifyBonus: 0,
    });
  }
});

app.get("/api/scoreboard", auth, async (_req, res) => {
  try {
    const cursor = scoresColl().aggregate([
      {
        $addFields: {
          userIdObj: {
            $cond: [
              { $eq: [{ $type: "$userId" }, "objectId"] },
              "$userId",
              {
                $convert: {
                  input: "$userId",
                  to: "objectId",
                  onError: null,
                  onNull: null,
                },
              },
            ],
          },
          tasksNum: {
            $convert: { input: "$tasksDone", to: "int", onError: 0, onNull: 0 },
          },
          totalNum: {
            $convert: { input: "$total", to: "double", onError: 0, onNull: 0 },
          },
        },
      },
      { $match: { userIdObj: { $ne: null } } },
      {
        $group: {
          _id: "$userIdObj",
          tasksDone: { $sum: "$tasksNum" },
          total: { $sum: "$totalNum" },
        },
      },
      {
        $lookup: {
          from: "users",
          localField: "_id",
          foreignField: "_id",
          as: "user",
        },
      },
      { $unwind: { path: "$user", preserveNullAndEmptyArrays: true } },
      {
        $project: {
          _id: 0,
          userId: "$user._id",
          name: { $ifNull: ["$user.name", "Unknown"] },
          role: { $ifNull: ["$user.role", "?"] },
          tasksApproved: "$tasksDone",
          total: 1,
        },
      },
      { $sort: { total: -1, name: 1 } },
    ]);

    const rows = await cursor.toArray();
    res.json(rows);
  } catch (e) {
    console.error("scoreboard error:", e);
    res.status(500).json({ error: "scoreboard failed" });
  }
});

app.post("/api/admin/score/reset", auth, async (req, res) => {
  try {
    if (req.user.role !== "ADMIN" && req.user.role !== "CEO") {
      return res.status(403).json({ error: "only admin/CEO" });
    }

    const logs = await Log.find({}, { _id: 1, proofUrl: 1 });
    let files = 0;
    for (const l of logs) {
      if (l.proofUrl) {
        removeProofFileIfLocal(l.proofUrl);
        files++;
      }
    }

    const rReviews = await Review.deleteMany({});
    const rLogs = await Log.deleteMany({});
    const rScores = await scoresColl().deleteMany({});

    res.json({
      ok: true,
      deletedReviews: rReviews.deletedCount || 0,
      deletedLogs: rLogs.deletedCount || 0,
      deletedFiles: files,
      deletedScores: rScores.deletedCount || 0,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/admin/score/rebuild", auth, async (req, res) => {
  try {
    if (req.user.role !== "ADMIN" && req.user.role !== "CEO")
      return res.status(403).json({ error: "only admin/CEO" });

    await scoresColl().deleteMany({
      $or: [
        { userId: { $exists: false } },
        { userId: null },
        { userId: { $type: "string" } },
        { userId: { $type: "object" } },
        { userId: { $type: "array" } },
      ],
    });

    const groups = await Log.aggregate([
      { $group: { _id: { userId: "$userId", date: "$date" } } },
    ]);
    let n = 0;
    for (const g of groups) {
      await recomputeScoreInternal(g._id.userId, g._id.date);
      n++;
    }
    res.json({ ok: true, recomputed: n });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ===================== data retention cleanup ================= */
function ymd(d) {
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, "0");
  const day = String(d.getDate()).padStart(2, "0");
  return `${y}-${m}-${day}`;
}

async function cleanupOldData() {
  const cutoff = new Date();
  cutoff.setDate(cutoff.getDate() - 2);
  const cutoffYMD = ymd(cutoff);

  const oldLogs = await Log.find({ date: { $lt: cutoffYMD } });
  if (oldLogs.length === 0)
    return { deletedLogs: 0, deletedReviews: 0, deletedFiles: 0 };

  const ids = [];
  let files = 0;
  for (const l of oldLogs) {
    if (l.proofUrl) {
      removeProofFileIfLocal(l.proofUrl);
      files++;
    }
    ids.push(l._id);
  }

  const r = await Review.deleteMany({ logId: { $in: ids } });
  const x = await Log.deleteMany({ _id: { $in: ids } });

  return {
    deletedLogs: x.deletedCount || 0,
    deletedReviews: r.deletedCount || 0,
    deletedFiles: files,
  };
}

app.post("/api/admin/cleanup-old", auth, async (req, res) => {
  try {
    if (req.user.role !== "ADMIN" && req.user.role !== "CEO") {
      return res.status(403).json({ error: "only admin/CEO" });
    }
    const result = await cleanupOldData();
    res.json({ ok: true, ...result });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

setInterval(() => {
  cleanupOldData().catch((e) => console.error("cleanup error:", e.message));
}, 6 * 60 * 60 * 1000);

/* ============================ process ========================= */
process.on("unhandledRejection", (err) =>
  console.error("Unhandled Rejection:", err)
);
process.on("uncaughtException", (err) => {
  console.error("Uncaught Exception:", err);
  process.exit(1);
});

/* ============================ start =========================== */
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log("server on " + PORT));
