import express from "express";
import crypto from "crypto";
import mongoose from "mongoose";
import zxcvbn from "zxcvbn";
import rateLimit from "express-rate-limit";
import react from "@vitejs/plugin-react";
import { createServer as createVite } from "vite";

const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/pwndpass";
const LABELS = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"];

// ---------- Database (optional: falls back to memory so the app never crashes) ----------
const Scan = mongoose.model(
  "Scan",
  new mongoose.Schema({
    pwnedCount: { type: Number, required: true },
    strengthScore: { type: Number, required: true },
    strengthLabel: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
  })
);
const memoryScans = [];
let dbReady = false;

mongoose
  .connect(MONGO_URI, { serverSelectionTimeoutMS: 3000 })
  .then(() => {
    dbReady = true;
    console.log("MongoDB connected: pwndpass");
  })
  .catch(() =>
    console.warn("MongoDB not reachable. Running with in-memory history (start MongoDB to persist).")
  );

async function saveScan(doc) {
  if (dbReady) {
    try {
      return await Scan.create(doc);
    } catch {
      /* fall through to memory */
    }
  }
  const entry = { ...doc, createdAt: new Date() };
  memoryScans.unshift(entry);
  if (memoryScans.length > 200) memoryScans.pop();
  return entry;
}

async function getScans(limit) {
  if (dbReady) {
    try {
      return await Scan.find().sort({ createdAt: -1 }).limit(limit).lean();
    } catch {}
  }
  return memoryScans.slice(0, limit);
}

async function getStats() {
  const all = dbReady ? await Scan.find().lean().catch(() => memoryScans) : memoryScans;
  const total = all.length;
  const breached = all.filter((s) => s.pwnedCount > 0).length;
  const avg = total ? all.reduce((a, s) => a + s.strengthScore, 0) / total : 0;
  return { total, breached, safe: total - breached, averageStrength: Number(avg.toFixed(1)) };
}

// ---------- HIBP k-anonymity lookup ----------
async function pwnedCountFor(password) {
  const hash = crypto.createHash("sha1").update(password, "utf8").digest("hex").toUpperCase();
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);

  const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
    headers: { "Add-Padding": "true", "User-Agent": "SecurePass-Checker/1.0" },
  });
  if (!res.ok) throw new Error("HIBP unavailable");

  const text = await res.text();
  for (const line of text.split("\n")) {
    const [s, c] = line.trim().split(":");
    if (s && s.toUpperCase() === suffix) return Number(c) || 0; // padding rows have count 0
  }
  return 0;
}

// ---------- App ----------
const app = express();
app.use(express.json({ limit: "10kb" }));

app.get("/api/health", (_req, res) =>
  res.json({ success: true, message: "SecurePass API is running.", database: dbReady ? "mongodb" : "memory" })
);

app.post(
  "/api/password/check",
  rateLimit({ windowMs: 60_000, max: 30, message: { success: false, message: "Too many requests. Try again soon." } }),
  async (req, res) => {
    try {
      const { password } = req.body || {};
      if (typeof password !== "string" || !password.length || password.length > 128) {
        return res.status(400).json({ success: false, message: "Please enter a valid password." });
      }
      const pwnedCount = await pwnedCountFor(password);
      const strength = zxcvbn(password);
      const strengthLabel = LABELS[strength.score];
      const saved = await saveScan({ pwnedCount, strengthScore: strength.score, strengthLabel });

      res.json({
        success: true,
        breached: pwnedCount > 0,
        pwnedCount,
        strengthScore: strength.score,
        strengthLabel,
        crackTime: strength.crack_times_display.offline_slow_hashing_1e4_per_second,
        warning: strength.feedback.warning,
        suggestions: strength.feedback.suggestions,
        createdAt: saved.createdAt,
      });
    } catch {
      res.status(500).json({ success: false, message: "Unable to check password. Check your internet connection." });
    }
  }
);

app.get("/api/scans/history", async (_req, res) => res.json({ success: true, scans: await getScans(10) }));
app.get("/api/scans/stats", async (_req, res) => res.json({ success: true, ...(await getStats()) }));

// ---------- Frontend (Vite runs inside this same process) ----------
const vite = await createVite({
  server: { middlewareMode: true },
  appType: "spa",
  plugins: [react()],
});
app.use(vite.middlewares);

app.listen(PORT, () => {
  console.log(`\nSecurePass is running -> http://localhost:${PORT}\n`);
});
