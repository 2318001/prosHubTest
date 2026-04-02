import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import { fileURLToPath } from "url";
import { createRequire } from "module";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import sgMail from "@sendgrid/mail";
import { WebSocketServer, WebSocket } from "ws";
import http from "http";
import fs from "fs";
import multer from "multer";
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";
import admin from "firebase-admin";
import { getFirestore } from "firebase-admin/firestore";
import { z } from "zod";

// --- VALIDATION SCHEMAS ---
const RegisterSchema = z.object({
  email: z.string().email(),
  password: z.string().min(6),
  name: z.string().min(2),
  role: z.enum(['client', 'pro']),
  skills: z.array(z.string()).optional(),
  location: z.string().optional(),
});
const LoginSchema = z.object({ email: z.string().email(), password: z.string() });
const VerifyCodeSchema = z.object({ email: z.string().email(), code: z.string().length(6) });
const ForgotPasswordSchema = z.object({ email: z.string().email() });
const ResetPasswordSchema = z.object({ email: z.string().email(), code: z.string().length(6), newPassword: z.string().min(6) });
const JobSchema = z.object({ title: z.string().min(5), description: z.string().min(10), price: z.coerce.number().positive(), location: z.string().min(2), category: z.string().min(2), image_url: z.string().optional() });
const OfferSchema = z.object({ amount: z.coerce.number().positive() });
const ProfileUpdateSchema = z.object({ name: z.string().min(2).optional(), bio: z.string().optional(), skills: z.array(z.string()).optional(), avatar: z.string().optional(), is_public_profile: z.boolean().optional(), is_public_docs: z.boolean().optional(), location: z.string().optional() });
const DocumentSchema = z.object({ title: z.string().min(2), file_url: z.string().url() });
const PortfolioSchema = z.object({ title: z.string().min(2), description: z.string().min(5), image_url: z.string().optional() });
const AvailabilitySchema = z.object({ is_available: z.boolean() });
const CompleteJobSchema = z.object({ rating: z.number().min(1).max(5).optional(), comment: z.string().optional() });
const MessageSchema = z.object({ content: z.string().min(1).max(5000) });

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const _require = createRequire(import.meta.url);

dotenv.config();

// --- FAIL FAST ON MISSING SECRETS ---
if (!process.env.JWT_SECRET) throw new Error("FATAL: JWT_SECRET is not set.");
if (!process.env.FIREBASE_PROJECT_ID) throw new Error("FATAL: FIREBASE_PROJECT_ID is not set.");

const JWT_SECRET = process.env.JWT_SECRET;

// --- FIREBASE INIT ---
// Method 1: FIREBASE_CLIENT_EMAIL + FIREBASE_PRIVATE_KEY in .env
// Method 2: serviceAccount.json in project root
// Method 3: GCP Application Default Credentials (Cloud Run etc.)
function initFirebase(): admin.app.App {
  if (process.env.FIREBASE_CLIENT_EMAIL && process.env.FIREBASE_PRIVATE_KEY) {
    console.log("[Firebase] Using credentials from .env");
    return admin.initializeApp({
      credential: admin.credential.cert({
        projectId: process.env.FIREBASE_PROJECT_ID!,
        clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
        privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"),
      }),
    });
  }
  const saPath = path.join(process.cwd(), "serviceAccount.json");
  if (fs.existsSync(saPath)) {
    console.log("[Firebase] Using serviceAccount.json");
    const sa = _require(saPath);
    return admin.initializeApp({
      credential: admin.credential.cert(sa),
      projectId: process.env.FIREBASE_PROJECT_ID || sa.project_id,
    });
  }
  console.log("[Firebase] Using Application Default Credentials");
  return admin.initializeApp({ projectId: process.env.FIREBASE_PROJECT_ID });
}

const adminApp = initFirebase();
const firestore = getFirestore(adminApp, process.env.FIREBASE_FIRESTORE_DATABASE_ID || undefined);

if (process.env.SENDGRID_API_KEY) sgMail.setApiKey(process.env.SENDGRID_API_KEY);

async function sendEmail(to: string, subject: string, text: string) {
  if (!process.env.SENDGRID_API_KEY) {
    console.log(`[EMAIL] To: ${to} | Subject: ${subject} | Body: ${text}`);
    return;
  }
  try {
    await sgMail.send({ to, from: process.env.FROM_EMAIL || "noreply@proshub.com", subject, text });
  } catch (error) {
    console.error("SendGrid Error:", error);
  }
}

function sanitizeUser(user: any) {
  const { password, login_code, login_code_expires, ...safe } = user;
  return safe;
}

const CATEGORY_MAP: Record<string, string[]> = {
  "plumb": ["Plumbing", "Home Maintenance"], "electr": ["Electrical", "Home Maintenance"],
  "web": ["Web Design", "Software", "IT"], "design": ["Graphic Design", "Creative"],
  "law": ["Legal", "Consulting"], "fit": ["Fitness", "Health"],
  "clean": ["Cleaning", "Home Maintenance"], "teach": ["Tutoring", "Education"],
  "photo": ["Photography", "Creative"], "write": ["Writing", "Content"],
  "app": ["Mobile App Development", "Software"], "logo": ["Graphic Design", "Branding"],
  "yoga": ["Fitness", "Health", "Wellness"], "paint": ["Painting", "Home Maintenance"],
  "garden": ["Gardening", "Home Maintenance"], "account": ["Accounting", "Finance"],
  "market": ["Marketing", "Business"]
};

function normalizeSkills(inputSkills: string[]): string[] {
  const normalized = new Set<string>();
  inputSkills.forEach(skill => {
    if (!skill) return;
    const s = skill.toLowerCase().trim();
    normalized.add(skill.trim());
    for (const [key, values] of Object.entries(CATEGORY_MAP)) {
      if (s.includes(key)) values.forEach(v => normalized.add(v));
    }
  });
  return Array.from(normalized);
}

async function bootstrapAdmin() {
  const adminEmail = process.env.ADMIN_EMAIL;
  if (!adminEmail) { console.warn("[bootstrapAdmin] ADMIN_EMAIL not set, skipping."); return; }
  const snap = await firestore.collection("users").where("email", "==", adminEmail).get();
  if (!snap.empty) await snap.docs[0].ref.update({ is_admin: 1 });
}
bootstrapAdmin();

const app = express();
export default app;

const clients = new Map<string, WebSocket>();

const uploadsDir = path.join(process.cwd(), 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = /jpeg|jpg|png|pdf/;
    if (allowed.test(path.extname(file.originalname).toLowerCase()) && allowed.test(file.mimetype)) {
      return cb(null, true);
    }
    cb(new Error("Only images and PDFs are allowed!"));
  }
});

async function startServer() {
  app.use(helmet({ contentSecurityPolicy: process.env.NODE_ENV === "production" ? undefined : false }));
  const allowedOrigin = process.env.ALLOWED_ORIGIN || "http://localhost:3000";
  app.use(cors({ origin: allowedOrigin, credentials: true }));
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, message: "Too many requests, try again later." });
  app.use("/api/auth/login", authLimiter);
  app.use("/api/auth/register", authLimiter);
  app.use("/api/auth/verify-code", authLimiter);
  app.use("/api/auth/forgot-password", authLimiter);
  app.use("/api/auth/reset-password", authLimiter);

  const createNotification = async (userId: string, content: string, type: string) => {
    await firestore.collection("notifications").add({ user_id: userId, content, type, is_read: 0, created_at: admin.firestore.FieldValue.serverTimestamp() });
    const clientWs = clients.get(userId);
    if (clientWs && clientWs.readyState === WebSocket.OPEN) {
      clientWs.send(JSON.stringify({ type: 'notification', content, notificationType: type, createdAt: new Date().toISOString() }));
    }
  };

  // ============================================================
  // AUTH ROUTES
  // ============================================================

  app.post("/api/auth/register", async (req, res) => {
    try {
      const { email, password, name, role, skills, location } = RegisterSchema.parse(req.body);
      const hashedPassword = await bcrypt.hash(password, 10);
      const finalSkills = role === 'pro' ? normalizeSkills(skills || []) : [];
      const userRef = firestore.collection("users").doc();
      const userData = { id: userRef.id, email, password: hashedPassword, name, role, skills: finalSkills, location: location || "", is_verified: 0, is_admin: 0, is_available: 1, subscription_status: 'none', trial_ends_at: null, subscription_ends_at: null, created_at: admin.firestore.FieldValue.serverTimestamp() };
      await userRef.set(userData);
      const token = jwt.sign({ id: userRef.id, role, is_admin: 0 }, JWT_SECRET, { expiresIn: '7d' });
      res.json({ token, user: sanitizeUser(userData) });
    } catch (e) {
      if (e instanceof z.ZodError) return res.status(400).json({ error: e.issues[0].message });
      console.error("Register Error:", e);
      res.status(400).json({ error: "Registration failed" });
    }
  });

  app.post("/api/auth/login", async (req, res) => {
    try {
      const { email, password } = LoginSchema.parse(req.body);
      const userSnap = await firestore.collection("users").where("email", "==", email).get();
      if (userSnap.empty) return res.status(401).json({ error: "Invalid credentials" });
      const user = userSnap.docs[0].data();
      if (!(await bcrypt.compare(password, user.password))) return res.status(401).json({ error: "Invalid credentials" });
      const code = Math.floor(100000 + Math.random() * 900000).toString();
      const expires = new Date(Date.now() + 10 * 60 * 1000).toISOString();
      await userSnap.docs[0].ref.update({ login_code: code, login_code_expires: expires });
      await sendEmail(email, "ProsHub Login Verification", `Your verification code is: ${code}. It expires in 10 minutes.`);
      res.json({ message: "Verification code sent", email });
    } catch (e) {
      if (e instanceof z.ZodError) return res.status(400).json({ error: e.issues[0].message });
      res.status(500).json({ error: "Login failed" });
    }
  });

  app.post("/api/auth/verify-code", async (req, res) => {
    try {
      const { email, code } = VerifyCodeSchema.parse(req.body);
      const userSnap = await firestore.collection("users").where("email", "==", email).get();
      if (userSnap.empty) return res.status(401).json({ error: "Invalid credentials" });
      const user = userSnap.docs[0].data();
      if (user.login_code !== code || new Date() > new Date(user.login_code_expires)) return res.status(401).json({ error: "Invalid or expired verification code" });
      await userSnap.docs[0].ref.update({ login_code: admin.firestore.FieldValue.delete(), login_code_expires: admin.firestore.FieldValue.delete() });
      const token = jwt.sign({ id: user.id, role: user.role, is_admin: user.is_admin }, JWT_SECRET, { expiresIn: '7d' });
      res.json({ token, user: sanitizeUser(user) });
    } catch (e) {
      if (e instanceof z.ZodError) return res.status(400).json({ error: e.issues[0].message });
      res.status(500).json({ error: "Verification failed" });
    }
  });

  app.post("/api/auth/forgot-password", async (req, res) => {
    try {
      const { email } = ForgotPasswordSchema.parse(req.body);
      const usersSnap = await firestore.collection("users").where("email", "==", email).get();
      if (usersSnap.empty) return res.json({ message: "If an account exists with this email, a reset code has been sent." });
      const code = Math.floor(100000 + Math.random() * 900000).toString();
      const expires = new Date(Date.now() + 15 * 60 * 1000).toISOString();
      await usersSnap.docs[0].ref.update({ login_code: code, login_code_expires: expires });
      await sendEmail(email, "ProsHub Password Reset", `Your password reset code is: ${code}. It expires in 15 minutes.`);
      res.json({ message: "If an account exists with this email, a reset code has been sent." });
    } catch (e) {
      if (e instanceof z.ZodError) return res.status(400).json({ error: e.issues[0].message });
      res.status(500).json({ error: "Request failed" });
    }
  });

  app.post("/api/auth/reset-password", async (req, res) => {
    try {
      const { email, code, newPassword } = ResetPasswordSchema.parse(req.body);
      const usersSnap = await firestore.collection("users").where("email", "==", email).get();
      if (usersSnap.empty) return res.status(401).json({ error: "Invalid or expired reset code" });
      const user = usersSnap.docs[0].data();
      if (user.login_code !== code || new Date() > new Date(user.login_code_expires)) return res.status(401).json({ error: "Invalid or expired reset code" });
      const hashedPassword = await bcrypt.hash(newPassword, 10);
      await usersSnap.docs[0].ref.update({ password: hashedPassword, login_code: admin.firestore.FieldValue.delete(), login_code_expires: admin.firestore.FieldValue.delete() });
      res.json({ success: true, message: "Password updated successfully" });
    } catch (e) {
      if (e instanceof z.ZodError) return res.status(400).json({ error: e.issues[0].message });
      res.status(500).json({ error: "Reset failed" });
    }
  });

  // ============================================================
  // AUTH MIDDLEWARE
  // ============================================================

  const authenticate = async (req: any, res: any, next: any) => {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ error: "Unauthorized" });
    try {
      const decoded = jwt.verify(token, JWT_SECRET) as any;
      const userSnap = await firestore.collection("users").doc(decoded.id).get();
      if (!userSnap.exists) return res.status(401).json({ error: "User not found" });
      req.user = { id: userSnap.id, ...userSnap.data() };
      next();
    } catch (e) {
      res.status(401).json({ error: "Invalid or expired token" });
    }
  };

  // ============================================================
  // USER PROFILE ROUTES
  // ============================================================

  app.get("/api/user/profile", authenticate, async (req: any, res) => {
    const userSnap = await firestore.collection("users").doc(req.user.id).get();
    if (!userSnap.exists) return res.status(404).json({ error: "User not found" });
    const user = { id: userSnap.id, ...userSnap.data() } as any;
    res.json({ ...sanitizeUser(user), skills: user.skills || [] });
  });

  app.put("/api/user/profile", authenticate, async (req: any, res) => {
    try {
      const { name, bio, skills, avatar, is_public_profile, is_public_docs, location } = ProfileUpdateSchema.parse(req.body);
      const finalSkills = req.user.role === 'pro' ? normalizeSkills(skills || []) : [];
      await firestore.collection("users").doc(req.user.id).update({
        ...(name && { name }), ...(bio !== undefined && { bio }), skills: finalSkills,
        ...(avatar !== undefined && { avatar }),
        ...(is_public_profile !== undefined && { is_public_profile: is_public_profile ? 1 : 0 }),
        ...(is_public_docs !== undefined && { is_public_docs: is_public_docs ? 1 : 0 }),
        ...(location !== undefined && { location: location || "" })
      });
      res.json({ success: true, skills: finalSkills });
    } catch (e) {
      if (e instanceof z.ZodError) return res.status(400).json({ error: e.issues[0].message });
      res.status(500).json({ error: "Update failed" });
    }
  });

  app.get("/api/user/documents", authenticate, async (req: any, res) => {
    const docsSnap = await firestore.collection("user_documents").where("user_id", "==", req.user.id).get();
    res.json(docsSnap.docs.map(doc => ({ id: doc.id, ...doc.data() })));
  });

  app.post("/api/user/documents", authenticate, async (req: any, res) => {
    try {
      const { title, file_url } = DocumentSchema.parse(req.body);
      const docRef = await firestore.collection("user_documents").add({ user_id: req.user.id, title, file_url, created_at: admin.firestore.FieldValue.serverTimestamp() });
      res.json({ id: docRef.id });
    } catch (e) {
      if (e instanceof z.ZodError) return res.status(400).json({ error: e.issues[0].message });
      res.status(500).json({ error: "Failed to add document" });
    }
  });

  app.delete("/api/user/documents/:id", authenticate, async (req: any, res) => {
    const docRef = firestore.collection("user_documents").doc(req.params.id);
    const docSnap = await docRef.get();
    if (docSnap.exists && docSnap.data()?.user_id === req.user.id) {
      await docRef.delete();
      res.json({ success: true });
    } else {
      res.status(403).json({ error: "Unauthorized" });
    }
  });

  app.get("/api/pro/:id/full-profile", authenticate, async (req: any, res) => {
    const proId = req.params.id;
    const proSnap = await firestore.collection("users").doc(proId).get();
    if (!proSnap.exists || proSnap.data()?.role !== 'pro') return res.status(404).json({ error: "Professional not found" });
    const pro = { id: proSnap.id, ...proSnap.data() } as any;
    const jobsSnap = await firestore.collection("jobs").where("client_id", "==", req.user.id).where("pro_id", "==", proId).get();
    const hasActiveJob = jobsSnap.docs.some(doc => ['accepted', 'finalized'].includes(doc.data().status));
    const canSeeDocs = pro.is_public_docs === 1 || hasActiveJob;
    const canSeeProfile = pro.is_public_profile === 1 || hasActiveJob;
    if (!canSeeProfile && !hasActiveJob) return res.status(403).json({ error: "Profile is private" });
    const docs = canSeeDocs ? (await firestore.collection("user_documents").where("user_id", "==", proId).get()).docs.map(d => d.data()) : [];
    const portfolio = (await firestore.collection("completed_works").where("pro_id", "==", proId).get()).docs.map(d => d.data());
    const reviews = (await firestore.collection("reviews").where("pro_id", "==", proId).get()).docs.map(d => d.data());
    const workHistory = (await firestore.collection("jobs").where("pro_id", "==", proId).where("status", "==", "finalized").get()).docs.map(d => d.data());
    res.json({ ...sanitizeUser(pro), skills: pro.skills || [], documents: docs, portfolio, reviews, work_history: workHistory });
  });

  app.post("/api/user/verify", authenticate, async (req: any, res) => {
    await firestore.collection("users").doc(req.user.id).update({ is_verified: 50 });
    res.json({ success: true });
  });

  app.post("/api/user/availability", authenticate, async (req: any, res) => {
    try {
      const { is_available } = AvailabilitySchema.parse(req.body);
      await firestore.collection("users").doc(req.user.id).update({ is_available: is_available ? 1 : 0 });
      res.json({ success: true });
    } catch (e) {
      if (e instanceof z.ZodError) return res.status(400).json({ error: e.issues[0].message });
      res.status(500).json({ error: "Failed to update availability" });
    }
  });

  app.post("/api/jobs/:id/video-call", authenticate, async (req: any, res) => {
    const jobSnap = await firestore.collection("jobs").doc(req.params.id).get();
    if (!jobSnap.exists) return res.status(404).json({ error: "Job not found" });
    const job = jobSnap.data()!;
    const recipientId = req.user.id === job.client_id ? job.pro_id : job.client_id;
    if (recipientId) await createNotification(recipientId, `${req.user.name} is starting a video call for: ${job.title}`, 'message');
    res.json({ success: true });
  });

  // ============================================================
  // COMPLETED WORKS / PORTFOLIO
  // ============================================================

  app.get("/api/user/completed-works", authenticate, async (req: any, res) => {
    const worksSnap = await firestore.collection("completed_works").where("pro_id", "==", req.user.id).orderBy("created_at", "desc").get();
    res.json(worksSnap.docs.map(doc => ({ id: doc.id, ...doc.data() })));
  });

  app.get("/api/pros/:id/completed-works", authenticate, async (req: any, res) => {
    const worksSnap = await firestore.collection("completed_works").where("pro_id", "==", req.params.id).orderBy("created_at", "desc").get();
    res.json(worksSnap.docs.map(doc => ({ id: doc.id, ...doc.data() })));
  });

  app.post("/api/user/completed-works", authenticate, async (req: any, res) => {
    try {
      const { title, description, image_url } = PortfolioSchema.parse(req.body);
      await firestore.collection("completed_works").add({ pro_id: req.user.id, title, description, image_url: image_url || "", created_at: admin.firestore.FieldValue.serverTimestamp() });
      res.json({ success: true });
    } catch (e) {
      if (e instanceof z.ZodError) return res.status(400).json({ error: e.issues[0].message });
      res.status(500).json({ error: "Failed to add completed work" });
    }
  });

  app.delete("/api/user/completed-works/:id", authenticate, async (req: any, res) => {
    const workRef = firestore.collection("completed_works").doc(req.params.id);
    const workSnap = await workRef.get();
    if (workSnap.exists && workSnap.data()?.pro_id === req.user.id) {
      await workRef.delete(); res.json({ success: true });
    } else { res.status(403).json({ error: "Unauthorized" }); }
  });

  // ============================================================
  // NOTIFICATIONS
  // ============================================================

  app.get("/api/notifications", authenticate, async (req: any, res) => {
    const snap = await firestore.collection("notifications").where("user_id", "==", req.user.id).orderBy("created_at", "desc").limit(50).get();
    res.json(snap.docs.map(doc => ({ id: doc.id, ...doc.data() })));
  });

  app.post("/api/notifications/read", authenticate, async (req: any, res) => {
    const batch = firestore.batch();
    const snap = await firestore.collection("notifications").where("user_id", "==", req.user.id).where("is_read", "==", 0).get();
    snap.docs.forEach(doc => batch.update(doc.ref, { is_read: 1 }));
    await batch.commit();
    res.json({ success: true });
  });

  app.post("/api/notifications/:id/read", authenticate, async (req: any, res) => {
    const notifRef = firestore.collection("notifications").doc(req.params.id);
    const notifSnap = await notifRef.get();
    if (notifSnap.exists && notifSnap.data()?.user_id === req.user.id) {
      await notifRef.update({ is_read: 1 }); res.json({ success: true });
    } else { res.status(403).json({ error: "Unauthorized" }); }
  });

  // ============================================================
  // DELETE ACCOUNT
  // ============================================================

  app.delete("/api/user/account", authenticate, async (req: any, res) => {
    const userId = req.user.id;
    const batch = firestore.batch();
    const collections = [
      firestore.collection("messages").where("sender_id", "==", userId),
      firestore.collection("offers").where("sender_id", "==", userId),
      firestore.collection("completed_works").where("pro_id", "==", userId),
      firestore.collection("notifications").where("user_id", "==", userId),
      firestore.collection("jobs").where("client_id", "==", userId),
      firestore.collection("jobs").where("pro_id", "==", userId),
    ];
    for (const q of collections) {
      const snap = await q.get();
      snap.docs.forEach(doc => batch.delete(doc.ref));
    }
    batch.delete(firestore.collection("users").doc(userId));
    await batch.commit();
    res.json({ success: true });
  });

  // ============================================================
  // STATS & SEARCH
  // ============================================================

  app.get("/api/stats/categories", async (req, res) => {
    const prosSnap = await firestore.collection("users").where("role", "==", "pro").get();
    const skillCounts: Record<string, number> = {};
    prosSnap.docs.forEach(doc => {
      const pro = doc.data();
      if (pro.skills && Array.isArray(pro.skills)) {
        pro.skills.forEach((skill: string) => { if (skill) { const n = skill.trim(); skillCounts[n] = (skillCounts[n] || 0) + 1; } });
      }
    });
    const stats = Object.entries(skillCounts).map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count).slice(0, 12);
    res.json(stats);
  });

  app.get("/api/pros/search", authenticate, async (req: any, res) => {
    const { query, localOnly } = req.query;
    if (!query) return res.json([]);
    const q = (query as string).toLowerCase().trim();
    const isLocalOnly = localOnly === 'true';
    const userSnap = await firestore.collection("users").doc(req.user.id).get();
    const userLocation = userSnap.data()?.location;
    const SKILL_MAPPINGS: Record<string, string[]> = {
      "Plumbing": ["leak","pipe","drain","toilet","faucet","sink","water heater","shower","bath","tap","blockage","clog","plumber","heating","radiator"],
      "Electrical": ["wiring","socket","light","switch","fuse","circuit","breaker","rewire","installation","electrician","electricity","alarm","cctv"],
      "Cleaning": ["house","office","carpet","window","deep clean","vacuum","mopping","dusting","laundry","cleaner","ironing","end of tenancy"],
      "Gardening": ["lawn","mowing","weeding","planting","trimming","hedge","garden","landscaping","grass","gardener","tree","fencing"],
      "Handyman": ["furniture","assembly","mounting","shelf","door","lock","fixing","repair","hanging","handyman","flatpack","curtain"],
      "Painting": ["wall","ceiling","decorating","wallpaper","exterior","interior","paint","varnish","painter","plastering"],
      "IT & Tech": ["computer","laptop","software","network","wifi","repair","coding","website","tech support","it","developer","programming","app"],
      "Tutoring": ["math","science","english","exam","lesson","teacher","study","homework","tutor","language","music"],
      "Moving": ["packing","delivery","van","transport","furniture moving","relocation","heavy lifting","mover","courier","removals"],
      "Marketing": ["seo","social media","ads","branding","content","strategy","copywriting","advertising","digital marketing"],
      "Legal": ["contract","advice","lawyer","solicitor","notary","dispute","litigation","property law"],
      "Fitness": ["yoga","personal trainer","gym","workout","nutrition","pilates","coach","training"]
    };
    let mappedProfessions: string[] = [];
    for (const [profession, microskills] of Object.entries(SKILL_MAPPINGS)) {
      if (profession.toLowerCase() === q || microskills.some(s => q.includes(s) || s.includes(q))) mappedProfessions.push(profession.toLowerCase());
    }
    let prosQuery: admin.firestore.Query = firestore.collection("users").where("role", "==", "pro");
    if (isLocalOnly && userLocation) prosQuery = prosQuery.where("location", "==", userLocation);
    const prosSnap = await prosQuery.get();
    const allPros = prosSnap.docs.map(doc => { const d = doc.data(); return { id: doc.id, ...sanitizeUser(d) }; });
    const clientLat = parseFloat(req.query.lat as string);
    const clientLng = parseFloat(req.query.lng as string);
    const results = allPros.map((p: any) => {
      const skills = p.skills || [];
      let distance = null;
      if (!isNaN(clientLat) && !isNaN(clientLng) && p.location_lat && p.location_lng) {
        const R = 6371; const dLat = (p.location_lat - clientLat) * Math.PI / 180; const dLon = (p.location_lng - clientLng) * Math.PI / 180;
        const a = Math.sin(dLat/2)**2 + Math.cos(clientLat*Math.PI/180)*Math.cos(p.location_lat*Math.PI/180)*Math.sin(dLon/2)**2;
        distance = R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
      }
      let score = 0;
      const lowerName = (p.name||"").toLowerCase(); const lowerBio = (p.bio||"").toLowerCase(); const lowerSkills = skills.map((s:string)=>s.toLowerCase());
      if (lowerSkills.includes(q)) score += 100;
      else if (mappedProfessions.some(mp => lowerSkills.includes(mp))) score += 80;
      else if (lowerSkills.some((s:string) => s.includes(q))) score += 50;
      if (lowerName.includes(q)) score += 30; if (lowerBio.includes(q)) score += 10; if (p.is_available) score += 5;
      if (distance !== null) { if (distance < 5) score += 20; else if (distance < 20) score += 10; }
      return { ...p, score, distance };
    }).filter(p => p.score > 0).sort((a, b) => b.score - a.score);
    res.json(results.length > 0 ? results : allPros.slice(0, 5));
  });

  app.get("/api/pros/:id", authenticate, async (req: any, res) => {
    const proSnap = await firestore.collection("users").doc(req.params.id).get();
    if (!proSnap.exists || proSnap.data()?.role !== 'pro') return res.status(404).json({ error: "Professional not found" });
    const pro = proSnap.data()!;
    const [portfolioSnap, reviewsSnap, historySnap, docsSnap] = await Promise.all([
      firestore.collection("completed_works").where("pro_id", "==", pro.id).orderBy("created_at", "desc").get(),
      firestore.collection("reviews").where("pro_id", "==", pro.id).orderBy("created_at", "desc").get(),
      firestore.collection("jobs").where("pro_id", "==", pro.id).where("status", "==", "finalized").orderBy("created_at", "desc").get(),
      firestore.collection("user_documents").where("user_id", "==", pro.id).get(),
    ]);
    pro.portfolio = portfolioSnap.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    pro.reviews = await Promise.all(reviewsSnap.docs.map(async doc => {
      const r = doc.data(); const clientSnap = await firestore.collection("users").doc(r.client_id).get();
      return { id: doc.id, ...r, client_name: clientSnap.exists ? clientSnap.data()?.name : "Unknown Client" };
    }));
    pro.work_history = historySnap.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    pro.documents = docsSnap.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    res.json(sanitizeUser(pro));
  });

  // ============================================================
  // JOB ROUTES
  // ============================================================

  app.post("/api/jobs", authenticate, upload.single('file'), async (req: any, res) => {
    try {
      const { title, description, price, location, category } = JobSchema.parse(req.body);
      let image_url = req.body.image_url || "";
      if (req.file) image_url = `/api/uploads/${req.file.filename}`;
      const jobRef = await firestore.collection("jobs").add({ client_id: req.user.id, title, description, initial_price: price, location, category, image_url, status: 'pending', created_at: admin.firestore.FieldValue.serverTimestamp() });
      const prosSnap = await firestore.collection("users").where("role", "==", "pro").where("is_available", "==", 1).limit(10).get();
      prosSnap.docs.forEach(async doc => await createNotification(doc.id, `New job request: ${title}`, 'job_update'));
      res.json({ id: jobRef.id, image_url });
    } catch (e) {
      if (e instanceof z.ZodError) return res.status(400).json({ error: e.issues[0].message });
      res.status(500).json({ error: "Failed to create job" });
    }
  });

  app.get("/api/jobs/pending", authenticate, async (req: any, res) => {
    const userSnap = await firestore.collection("users").doc(req.user.id).get();
    const user = userSnap.data();
    if (!user || user.is_available === 0) return res.json([]);
    const proSkills = (user.skills || []).map((s: string) => s.toLowerCase());
    const jobsSnap = await firestore.collection("jobs").where("status", "==", "pending").orderBy("created_at", "desc").get();
    const allPendingJobs = await Promise.all(jobsSnap.docs.filter(doc => doc.data().client_id !== req.user.id).map(async doc => {
      const job = doc.data(); const clientSnap = await firestore.collection("users").doc(job.client_id).get();
      return { id: doc.id, ...job, client_name: clientSnap.exists ? clientSnap.data()?.name : "Unknown Client", client_role: clientSnap.exists ? clientSnap.data()?.role : "client" };
    }));
    if (proSkills.length === 0) return res.json(allPendingJobs);
    const matched = allPendingJobs.filter((job: any) => proSkills.some(skill => (job.category||"").toLowerCase().includes(skill) || skill.includes((job.category||"").toLowerCase()) || (job.title||"").toLowerCase().includes(skill)));
    res.json(matched.length > 0 ? matched : allPendingJobs);
  });

  app.get("/api/jobs/:id", authenticate, async (req: any, res) => {
    const jobSnap = await firestore.collection("jobs").doc(req.params.id).get();
    if (!jobSnap.exists) return res.status(404).json({ error: "Job not found" });
    const job = { id: jobSnap.id, ...jobSnap.data() } as any;
    const clientSnap = await firestore.collection("users").doc(job.client_id).get();
    if (clientSnap.exists) { const c = clientSnap.data()!; job.client_name = c.name; job.client_lat = c.location_lat; job.client_lng = c.location_lng; }
    if (job.pro_id) {
      const proSnap = await firestore.collection("users").doc(job.pro_id).get();
      if (proSnap.exists) { const p = proSnap.data()!; job.pro_name = p.name; job.pro_lat = p.location_lat; job.pro_lng = p.location_lng; }
    }
    if (job.client_lat && job.client_lng && job.pro_lat && job.pro_lng) {
      const R = 6371; const dLat = (job.pro_lat-job.client_lat)*Math.PI/180; const dLon = (job.pro_lng-job.client_lng)*Math.PI/180;
      const a = Math.sin(dLat/2)**2 + Math.cos(job.client_lat*Math.PI/180)*Math.cos(job.pro_lat*Math.PI/180)*Math.sin(dLon/2)**2;
      job.pro_distance = R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
    }
    res.json(job);
  });

  app.post("/api/jobs/:id/offers", authenticate, async (req: any, res) => {
    try {
      const { amount } = OfferSchema.parse(req.body);
      const jobSnap = await firestore.collection("jobs").doc(req.params.id).get();
      if (!jobSnap.exists) return res.status(404).json({ error: "Job not found" });
      const job = jobSnap.data()!;
      const offerRef = await firestore.collection("offers").add({ job_id: req.params.id, sender_id: req.user.id, amount, created_at: admin.firestore.FieldValue.serverTimestamp() });
      if (!job.pro_id) { await jobSnap.ref.update({ pro_id: req.user.id, status: 'negotiating' }); }
      else { await jobSnap.ref.update({ status: 'negotiating' }); }
      const recipientId = req.user.id === job.client_id ? job.pro_id : job.client_id;
      if (recipientId) await createNotification(recipientId, `New offer received for: ${job.title}`, 'offer');
      res.json({ id: offerRef.id });
    } catch (e) {
      if (e instanceof z.ZodError) return res.status(400).json({ error: e.issues[0].message });
      res.status(500).json({ error: "Failed to send offer" });
    }
  });

  app.get("/api/jobs/:id/offers", authenticate, async (req: any, res) => {
    const jobSnap = await firestore.collection("jobs").doc(req.params.id).get();
    if (!jobSnap.exists) return res.status(404).json({ error: "Job not found" });
    const job = jobSnap.data()!;
    if (req.user.id !== job.client_id && req.user.id !== job.pro_id && !req.user.is_admin) return res.status(403).json({ error: "Unauthorized" });
    const offersSnap = await firestore.collection("offers").where("job_id", "==", req.params.id).orderBy("created_at", "asc").get();
    const offers = await Promise.all(offersSnap.docs.map(async doc => {
      const offer = doc.data(); const senderSnap = await firestore.collection("users").doc(offer.sender_id).get();
      return { id: doc.id, ...offer, sender_name: senderSnap.exists ? senderSnap.data()?.name : "Unknown User" };
    }));
    res.json(offers);
  });

  app.post("/api/jobs/:id/accept", authenticate, async (req: any, res) => {
    try {
      const expiresAt = new Date(Date.now() + 60 * 1000).toISOString();
      await firestore.runTransaction(async (transaction) => {
        const jobRef = firestore.collection("jobs").doc(req.params.id);
        const jobDoc = await transaction.get(jobRef);
        if (!jobDoc.exists) throw new Error("Job not found");
        const job = jobDoc.data()!;
        if (job.status !== 'pending') throw new Error("Job is no longer pending");
        transaction.update(jobRef, { pro_id: req.user.id, final_price: job.initial_price, status: 'matching', matching_expires_at: expiresAt });
        const notifRef = firestore.collection("notifications").doc();
        transaction.set(notifRef, { user_id: job.client_id, content: `A Pro has accepted your job: ${job.title}. Matching phase started!`, type: 'match', is_read: 0, created_at: admin.firestore.FieldValue.serverTimestamp() });
      });
      res.json({ success: true, expires_at: expiresAt });
    } catch (e: any) { res.status(400).json({ error: e.message }); }
  });

  app.post("/api/jobs/:id/confirm-match", authenticate, async (req: any, res) => {
    try {
      await firestore.runTransaction(async (transaction) => {
        const jobRef = firestore.collection("jobs").doc(req.params.id);
        const jobDoc = await transaction.get(jobRef);
        if (!jobDoc.exists) throw new Error("Job not found");
        const job = jobDoc.data()!;
        if (job.status !== 'matching') throw new Error("Job not in matching phase");
        if (req.user.id !== job.client_id && req.user.id !== job.pro_id) throw new Error("Unauthorized");
        if (job.matching_expires_at && new Date(job.matching_expires_at) < new Date()) throw new Error("Matching phase has expired");
        transaction.update(jobRef, { status: 'accepted', matching_expires_at: null });
        [job.client_id, job.pro_id].forEach(uid => {
          const notifRef = firestore.collection("notifications").doc();
          transaction.set(notifRef, { user_id: uid, content: `Match confirmed! Job "${job.title}" is now active.`, type: 'job_update', is_read: 0, created_at: admin.firestore.FieldValue.serverTimestamp() });
        });
      });
      res.json({ success: true });
    } catch (e: any) { res.status(400).json({ error: e.message }); }
  });

  app.post("/api/offers/:id/accept", authenticate, async (req: any, res) => {
    try {
      await firestore.runTransaction(async (transaction) => {
        const offerRef = firestore.collection("offers").doc(req.params.id);
        const offerDoc = await transaction.get(offerRef);
        if (!offerDoc.exists) throw new Error("Offer not found");
        const offer = offerDoc.data()!;
        const jobRef = firestore.collection("jobs").doc(offer.job_id);
        const jobDoc = await transaction.get(jobRef);
        if (!jobDoc.exists) throw new Error("Job not found");
        const job = jobDoc.data()!;
        if (req.user.id !== job.client_id && req.user.id !== offer.sender_id) throw new Error("Unauthorized");
        if (job.status === 'accepted' || job.status === 'finalized') throw new Error("Job is already in progress or finished");
        const pro_id = req.user.role === 'pro' ? req.user.id : offer.sender_id;
        transaction.update(jobRef, { pro_id, final_price: offer.amount, status: 'accepted' });
        transaction.update(offerRef, { status: 'accepted' });
        const notifRef = firestore.collection("notifications").doc();
        transaction.set(notifRef, { user_id: req.user.id === job.client_id ? pro_id : job.client_id, content: `Offer accepted! Job "${job.title}" is now active.`, type: 'job_update', is_read: 0, created_at: admin.firestore.FieldValue.serverTimestamp() });
      });
      res.json({ success: true });
    } catch (e: any) { res.status(400).json({ error: e.message }); }
  });

  app.post("/api/jobs/:id/complete", authenticate, async (req: any, res) => {
    try {
      const { rating, comment } = CompleteJobSchema.parse(req.body);
      await firestore.runTransaction(async (transaction) => {
        const jobRef = firestore.collection("jobs").doc(req.params.id);
        const jobDoc = await transaction.get(jobRef);
        if (!jobDoc.exists) throw new Error("Job not found");
        const job = jobDoc.data()!;
        if (job.pro_id !== req.user.id && job.client_id !== req.user.id) throw new Error("Unauthorized");
        if (job.status !== 'accepted') throw new Error("Job must be in 'accepted' status to mark as complete");
        transaction.update(jobRef, { status: 'finalized' });
        if (req.user.id === job.client_id && rating) {
          const reviewRef = firestore.collection("reviews").doc();
          transaction.set(reviewRef, { job_id: req.params.id, client_id: job.client_id, pro_id: job.pro_id, rating, comment: comment || "", created_at: admin.firestore.FieldValue.serverTimestamp() });
        }
        const notifRef = firestore.collection("notifications").doc();
        transaction.set(notifRef, { user_id: req.user.id === job.client_id ? job.pro_id : job.client_id, content: `Job "${job.title}" has been finalized.`, type: 'job_update', is_read: 0, created_at: admin.firestore.FieldValue.serverTimestamp() });
      });
      res.json({ success: true });
    } catch (e: any) {
      if (e instanceof z.ZodError) return res.status(400).json({ error: e.issues[0].message });
      res.status(500).json({ error: e.message || "Failed to complete job" });
    }
  });

  // ============================================================
  // MESSAGES
  // ============================================================

  app.get("/api/jobs/:id/messages", authenticate, async (req: any, res) => {
    const jobSnap = await firestore.collection("jobs").doc(req.params.id).get();
    if (!jobSnap.exists) return res.status(404).json({ error: "Job not found" });
    const job = jobSnap.data()!;
    if (req.user.id !== job.client_id && req.user.id !== job.pro_id && !req.user.is_admin) return res.status(403).json({ error: "Unauthorized" });
    const messagesSnap = await firestore.collection("messages").where("job_id", "==", req.params.id).orderBy("created_at", "asc").get();
    const messages = await Promise.all(messagesSnap.docs.map(async doc => {
      const msg = doc.data(); const senderSnap = await firestore.collection("users").doc(msg.sender_id).get();
      return { id: doc.id, ...msg, sender_name: senderSnap.exists ? senderSnap.data()?.name : "Unknown User" };
    }));
    res.json(messages);
  });

  app.post("/api/jobs/:id/messages", authenticate, async (req: any, res) => {
    try {
      const { content } = MessageSchema.parse(req.body);
      const jobRef = firestore.collection("jobs").doc(req.params.id);
      const jobSnap = await jobRef.get();
      if (!jobSnap.exists) return res.status(404).json({ error: "Job not found" });
      const job = jobSnap.data()!;
      const isJobClient = req.user.id === job.client_id;
      const isJobPro = req.user.id === job.pro_id;
      const isNewProEngaging = req.user.role === 'pro' && !job.pro_id && job.status === 'pending';
      if (!isJobClient && !isJobPro && !isNewProEngaging) return res.status(403).json({ error: "You are not a participant in this job" });
      if (isNewProEngaging) await jobRef.update({ pro_id: req.user.id, status: 'negotiating' });
      await firestore.collection("messages").add({ job_id: req.params.id, sender_id: req.user.id, content: content.trim(), created_at: admin.firestore.FieldValue.serverTimestamp() });
      const recipientId = req.user.id === job.client_id ? job.pro_id : job.client_id;
      if (recipientId) await createNotification(recipientId, `New message for job: ${job.title}`, 'message');
      res.json({ success: true });
    } catch (e) {
      if (e instanceof z.ZodError) return res.status(400).json({ error: e.issues[0].message });
      res.status(500).json({ error: "Failed to send message" });
    }
  });

  // ============================================================
  // PRO PUBLIC PORTFOLIO & REVIEWS
  // ============================================================

  app.get("/api/pro/:id/portfolio", async (req, res) => {
    const snap = await firestore.collection("completed_works").where("pro_id", "==", req.params.id).orderBy("created_at", "desc").get();
    res.json(snap.docs.map(doc => ({ id: doc.id, ...doc.data() })));
  });

  app.get("/api/pro/:id/reviews", async (req, res) => {
    const snap = await firestore.collection("reviews").where("pro_id", "==", req.params.id).orderBy("created_at", "desc").get();
    const reviews = await Promise.all(snap.docs.map(async doc => {
      const r = doc.data(); const clientSnap = await firestore.collection("users").doc(r.client_id).get();
      return { id: doc.id, ...r, client_name: clientSnap.exists ? clientSnap.data()?.name : "Unknown Client" };
    }));
    res.json(reviews);
  });

  app.post("/api/pro/portfolio", authenticate, async (req: any, res) => {
    try {
      const { title, description, image_url } = PortfolioSchema.parse(req.body);
      const workRef = await firestore.collection("completed_works").add({ pro_id: req.user.id, title, description, image_url: image_url || "", created_at: admin.firestore.FieldValue.serverTimestamp() });
      res.json({ id: workRef.id });
    } catch (e) {
      if (e instanceof z.ZodError) return res.status(400).json({ error: e.issues[0].message });
      res.status(500).json({ error: "Failed to add portfolio item" });
    }
  });

  // ============================================================
  // ADMIN ROUTES
  // ============================================================

  app.post("/api/admin/verify-user/:id", authenticate, async (req: any, res) => {
    if (!req.user.is_admin) return res.status(403).json({ error: "Admin only" });
    await firestore.collection("users").doc(req.params.id).update({ is_verified: 100 });
    res.json({ success: true });
  });

  app.get("/api/jobs/:id/sub-jobs", authenticate, async (req: any, res) => {
    const jobsSnap = await firestore.collection("jobs").where("parent_id", "==", req.params.id).get();
    const subJobs = await Promise.all(jobsSnap.docs.map(async doc => {
      const job = doc.data(); const proSnap = await firestore.collection("users").doc(job.pro_id).get();
      return { id: doc.id, ...job, pro_name: proSnap.exists ? proSnap.data()?.name : null };
    }));
    res.json(subJobs);
  });

  app.get("/api/my-jobs", authenticate, async (req: any, res) => {
    if (!req.user.is_admin) {
      const [clientJobsSnap, proJobsSnap, offersSnap] = await Promise.all([
        firestore.collection("jobs").where("client_id", "==", req.user.id).get(),
        firestore.collection("jobs").where("pro_id", "==", req.user.id).get(),
        firestore.collection("offers").where("sender_id", "==", req.user.id).get(),
      ]);
      const jobIdsFromOffers = [...new Set(offersSnap.docs.map(doc => doc.data().job_id))];
      const offerJobsSnaps = await Promise.all(jobIdsFromOffers.map(id => firestore.collection("jobs").doc(id).get()));
      const allDocs = [...clientJobsSnap.docs, ...proJobsSnap.docs, ...offerJobsSnaps.filter(s => s.exists && s.data()?.status === 'negotiating')];
      const uniqueDocs = Array.from(new Map(allDocs.map(doc => [doc.id, doc])).values());
      const jobs = await Promise.all(uniqueDocs.map(async doc => {
        const job = doc.data()!; const clientSnap = await firestore.collection("users").doc(job.client_id).get();
        const proSnap = job.pro_id ? await firestore.collection("users").doc(job.pro_id).get() : null;
        return { id: doc.id, ...job, client_name: clientSnap.exists ? clientSnap.data()?.name : null, client_verified: clientSnap.exists ? clientSnap.data()?.is_verified : null, pro_name: proSnap?.exists ? proSnap.data()?.name : null, pro_verified: proSnap?.exists ? proSnap.data()?.is_verified : null };
      }));
      return res.json(jobs.sort((a: any, b: any) => (b.created_at?.seconds||0) - (a.created_at?.seconds||0)));
    } else {
      const jobsSnap = await firestore.collection("jobs").orderBy("created_at", "desc").get();
      const jobs = await Promise.all(jobsSnap.docs.map(async doc => {
        const job = doc.data(); const clientSnap = await firestore.collection("users").doc(job.client_id).get();
        const proSnap = job.pro_id ? await firestore.collection("users").doc(job.pro_id).get() : null;
        return { id: doc.id, ...job, client_name: clientSnap.exists ? clientSnap.data()?.name : null, client_verified: clientSnap.exists ? clientSnap.data()?.is_verified : null, pro_name: proSnap?.exists ? proSnap.data()?.name : null, pro_verified: proSnap?.exists ? proSnap.data()?.is_verified : null };
      }));
      res.json(jobs);
    }
  });

  // ============================================================
  // LEGAL
  // ============================================================

  app.get("/api/legal/terms", (req, res) => res.json({ title: "Terms of Service", content: "By using ProsHub, you agree to our terms. Users are responsible for settling payments externally. ProsHub is not responsible for any financial disputes between users." }));
  app.get("/api/legal/privacy", (req, res) => res.json({ title: "Privacy Policy", content: "We value your privacy. We only share your data with professionals you choose to hire. We do not process or store any payment information." }));

  // ============================================================
  // AUTHENTICATED FILE SERVING
  // ============================================================

  app.get("/api/uploads/:filename", authenticate, async (req: any, res) => {
    const filename = path.basename(req.params.filename);
    const filePath = path.join(process.cwd(), 'uploads', filename);
    if (!fs.existsSync(filePath)) return res.status(404).json({ error: "File not found" });
    const [docsSnap, worksSnap] = await Promise.all([
      firestore.collection("user_documents").where("user_id", "==", req.user.id).where("file_url", "==", `/api/uploads/${filename}`).get(),
      firestore.collection("completed_works").where("pro_id", "==", req.user.id).where("image_url", "==", `/api/uploads/${filename}`).get(),
    ]);
    if (!req.user.is_admin && docsSnap.empty && worksSnap.empty) return res.status(403).json({ error: "Access denied" });
    res.sendFile(filePath);
  });

  // ============================================================
  // GLOBAL ERROR HANDLER
  // ============================================================

  app.use((err: any, req: any, res: any, next: any) => {
    console.error('[Unhandled Error]', err);
    if (res.headersSent) return next(err);
    res.status(err.status || 500).json({ error: err.message || 'Internal server error' });
  });

  // ============================================================
  // VITE / STATIC
  // ============================================================

  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({ server: { middlewareMode: true }, appType: "spa" });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.join(__dirname, "dist")));
    app.get("*", (req, res) => res.sendFile(path.join(__dirname, "dist", "index.html")));
  }

  // ============================================================
  // MATCHING CLEANUP
  // ============================================================

  setInterval(async () => {
    const now = new Date().toISOString();
    const jobsSnap = await firestore.collection("jobs").where("status", "==", "matching").where("matching_expires_at", "<", now).get();
    const batch = firestore.batch();
    jobsSnap.docs.forEach(doc => batch.update(doc.ref, { status: 'pending', pro_id: null, final_price: null, matching_expires_at: null }));
    await batch.commit();
  }, 30000);

  const PORT = process.env.PORT || 3000;
  const server = http.createServer(app);

  // ============================================================
  // WEBSOCKET
  // ============================================================

  const wss = new WebSocketServer({ server });
  wss.on("connection", (ws) => {
    let userId: string | null = null;
    ws.on("message", async (data) => {
      try {
        const message = JSON.parse(data.toString());
        if (message.type === "auth") {
          const decoded = jwt.verify(message.token, JWT_SECRET) as any;
          userId = decoded.id;
          if (userId) clients.set(userId, ws);
        }
        if (message.type === "chat" && userId) {
          const { jobId, content, recipientId } = message;
          const jobSnap = await firestore.collection("jobs").doc(jobId).get();
          if (!jobSnap.exists) return;
          const job = jobSnap.data()!;
          if ((job.client_id !== userId && job.pro_id !== userId) || (job.client_id !== recipientId && job.pro_id !== recipientId)) return;
          const recipientWs = clients.get(recipientId);
          if (recipientWs && recipientWs.readyState === WebSocket.OPEN) {
            recipientWs.send(JSON.stringify({ type: "chat", jobId, senderId: userId, content, createdAt: new Date().toISOString() }));
          }
        }
      } catch (err) { console.error("WS Error:", err); }
    });
    ws.on("close", () => { if (userId) clients.delete(userId); });
  });

  server.listen(Number(PORT), "0.0.0.0", () => console.log(`Server running on port ${PORT}`));
}

startServer();
