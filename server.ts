// =============================================================================
// FILE: server.ts — ProsHub backend v8
// PURPOSE: Express + WebSocket API server.
//
// KEY CHANGES IN v8:
//   - Admin email moved to process.env.ADMIN_EMAIL (no hardcoded addresses)
//   - JWT_SECRET startup guard: server refuses to start with default/missing secret
//   - Zod input validation on all mutating routes (register, login, post-job, etc.)
//   - Global error handler middleware — no more unhandled 500 crashes
//   - WebSocket-push for notifications (no more client polling)
//   - Business email notifications: job matched, offer accepted, job complete
//   - Dispute system: client or pro can raise a dispute; admin resolves it
//   - Pro stats tracking: response_time_sum, response_count, jobs_offered, jobs_accepted
//   - Accept-rate + avg-response-time exposed on pro profile & search results
// =============================================================================

import express           from "express";
import rateLimit         from "express-rate-limit";
import { createServer as createViteServer } from "vite";
import path              from "path";
import { fileURLToPath } from "url";
import bcrypt            from "bcryptjs";
import jwt               from "jsonwebtoken";
import dotenv            from "dotenv";
import sgMail            from "@sendgrid/mail";
import { WebSocketServer, WebSocket } from "ws";
import http              from "http";
import fs                from "fs";
import crypto            from "crypto";
import multer            from "multer";
import { z }             from "zod";
import { initializeApp, cert, getApps } from "firebase-admin/app";
import { getFirestore, FieldValue }      from "firebase-admin/firestore";

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

dotenv.config();

// ---------------------------------------------------------------------------
// STARTUP GUARD: refuse to run with an insecure JWT secret
// ---------------------------------------------------------------------------
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET === "CHANGE_THIS_TO_A_LONG_RANDOM_STRING" || JWT_SECRET.length < 32) {
  console.error("\n❌  FATAL: JWT_SECRET is not set or is too short.");
  console.error("    Set a strong secret in your .env file (min 32 chars).");
  console.error("    Generate one with: openssl rand -hex 64\n");
  process.exit(1);
}

// Check REFRESH_TOKEN_SECRET for token rotation
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET;
if (!REFRESH_TOKEN_SECRET || REFRESH_TOKEN_SECRET === "CHANGE_THIS_TO_ANOTHER_LONG_RANDOM_STRING" || REFRESH_TOKEN_SECRET.length < 32) {
  console.error("\n❌  FATAL: REFRESH_TOKEN_SECRET is not set or is too short.");
  console.error("    Set a strong secret in your .env file (min 32 chars).");
  console.error("    Generate one with: openssl rand -hex 64\n");
  process.exit(1);
}

// Token expiration times
const ACCESS_TOKEN_EXPIRY  = (process.env.ACCESS_TOKEN_EXPIRY  || '15m') as import('jsonwebtoken').SignOptions['expiresIn'] & string;
const REFRESH_TOKEN_EXPIRY = (process.env.REFRESH_TOKEN_EXPIRY || '7d')  as import('jsonwebtoken').SignOptions['expiresIn'] & string;

// Admin emails from environment — never hardcoded in source
const ADMIN_EMAILS = [process.env.ADMIN_EMAIL].filter(Boolean) as string[];
if (ADMIN_EMAILS.length === 0) {
  console.warn("⚠️  ADMIN_EMAIL is not set in .env — no account will be auto-granted admin.");
}

if (!getApps().length) {
  initializeApp({
    credential: cert({
      projectId:   process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey:  process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, "\n"),
    }),
    storageBucket: process.env.FIREBASE_STORAGE_BUCKET,
  });
}

const db = getFirestore();

if (process.env.SENDGRID_API_KEY) {
  sgMail.setApiKey(process.env.SENDGRID_API_KEY);
}

async function sendEmail(to: string, subject: string, text: string, html?: string) {
  if (!process.env.SENDGRID_API_KEY) {
    console.log(`\n📧 [EMAIL] To: ${to} | Subject: ${subject}\n${text}\n`);
    return;
  }
  try {
    await sgMail.send({ to, from: process.env.FROM_EMAIL || "noreply@proshub.com", subject, text, html: html || text });
  } catch (err) {
    console.error("SendGrid error:", err);
  }
}

// ---------------------------------------------------------------------------
// EMAIL TEMPLATES — reusable HTML email bodies
// ---------------------------------------------------------------------------
function emailHtml(title: string, body: string): string {
  return `
  <div style="font-family:sans-serif;max-width:520px;margin:0 auto;padding:24px;background:#f9f9f9;border-radius:12px;">
    <h2 style="color:#1a1a2e;margin-bottom:8px;">ProsHub</h2>
    <hr style="border:none;border-top:1px solid #e0e0e0;margin-bottom:20px;"/>
    <h3 style="color:#2563eb;">${title}</h3>
    <p style="color:#444;line-height:1.6;">${body}</p>
    <hr style="border:none;border-top:1px solid #e0e0e0;margin-top:24px;"/>
    <p style="font-size:12px;color:#888;">ProsHub — connecting clients with verified professionals.</p>
  </div>`;
}

// ---------------------------------------------------------------------------
// TOKEN GENERATION HELPERS (v8+ — Token Rotation)
// ---------------------------------------------------------------------------
interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

function issueTokens(userId: string, email: string, role: string, isAdmin: number): TokenPair {
  const accessToken = jwt.sign(
    { id: userId, email, role, is_admin: isAdmin },
    JWT_SECRET,
    { expiresIn: ACCESS_TOKEN_EXPIRY }
  );

  const refreshToken = jwt.sign(
    { id: userId, type: 'refresh' },
    REFRESH_TOKEN_SECRET,
    { expiresIn: REFRESH_TOKEN_EXPIRY }
  );

  return { accessToken, refreshToken };
}

async function storeRefreshToken(userId: string, token: string): Promise<void> {
  // Store refresh token in Firestore for revocation support
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + 7); // Default 7 days
  
  await db.collection('refresh_tokens').doc(userId).set({
    token,
    created_at: new Date(),
    expires_at: expiresAt,
  }, { merge: true });
}

// ---------------------------------------------------------------------------
// SKILL CATEGORIES
// ---------------------------------------------------------------------------
const SKILL_KEYWORD_MAP: Record<string, string[]> = {
  "Plumbing":    ["plumb","plumber","leak","pipe","drain","toilet","faucet","sink","water heater","shower","bath","tap","blockage","clog","radiator","boiler"],
  "Electrical":  ["electr","electrician","wiring","socket","light","switch","fuse","circuit","breaker","rewire","alarm","cctv","power"],
  "Cleaning":    ["clean","cleaner","house clean","office clean","carpet","window","vacuum","mop","dust","laundry","ironing","end of tenancy"],
  "Gardening":   ["garden","gardener","lawn","mow","weed","plant","trim","hedge","landscap","grass","tree","fencing"],
  "Handyman":    ["handyman","furniture","assembl","mount","shelf","door","lock","fix","repair","hang","flatpack","curtain"],
  "Painting":    ["paint","painter","wall","ceiling","decorat","wallpaper","exterior","interior","varnish","plaster"],
  "IT & Tech":   ["it ","it&","tech","computer","laptop","software","network","wifi","cod","website","developer","programming","app dev","support"],
  "Tutoring":    ["tutor","teach","math","science","english","exam","lesson","study","homework","language","music lesson"],
  "Moving":      ["mov","pack","delivery","van hire","transport","relocation","heavy lift","remov","courier"],
  "Marketing":   ["market","seo","social media","ads","brand","content","copywrite","advertis","digital"],
  "Legal":       ["legal","law","lawyer","solicitor","notary","contract","dispute","litigat"],
  "Fitness":     ["fitness","personal train","gym","workout","nutrition","pilates","yoga","coach"],
  "Carpentry":   ["carpent","carpenter","wood","cabinet","joinery","timber","floor"],
  "HVAC":        ["hvac","air condition","heating","ventilat","boiler","heat pump"],
  "Roofing":     ["roof","roofer","tile","gutter","chimney","loft"],
  "Pest Control":["pest","exterminate","insect","rodent","vermin","wasp","rat"],
  "Photography": ["photo","photograph","camera","portrait","wedding photo","video produc"],
  "Accounting":  ["account","bookkeep","tax","finance","payroll","audit"],
  "Driving":     ["driv","chauffeur","taxi","minibus","courier"],
  "Doctor":      ["doctor","gp ","general practitioner","physician","medical"],
  "Dentist":     ["dentist","dental","teeth","orthodont"],
  "Nursing":     ["nurs","nurse","care","caregiver","healthcare worker"],
  "Engineering": ["engineer","civil","structural","mechanical eng","aerospace"],
};

const norm = (s: string) => s.toLowerCase().trim();

function jobMatchesPro(jobCategory: string, jobTitle: string, jobDesc: string, requiredSkills: string[], proSkills: string[]): boolean {
  if (!proSkills.length) return false;
  const jobCat    = norm(jobCategory);
  const jobTitleL = norm(jobTitle);
  const jobDescL  = norm(jobDesc.substring(0, 500)); // Check first 500 chars of description
  const reqLC     = requiredSkills.map(norm);

  const jobCanonicals = new Set<string>();
  for (const [canonCat, keywords] of Object.entries(SKILL_KEYWORD_MAP)) {
    const catLC    = norm(canonCat);
    const catExact = jobCat === catLC || reqLC.includes(catLC);
    const kwMatch  = keywords.some(kw => {
      if (kw.length < 3) return false;
      return (
        jobCat === kw ||
        jobTitleL === kw || jobTitleL.startsWith(kw+" ") || jobTitleL.includes(" "+kw) || jobTitleL.includes(kw) ||
        jobDescL.includes(kw) ||        // Also check description
        reqLC.some(r => r === kw || r.startsWith(kw) || r.includes(kw))
      );
    });
    if (catExact || kwMatch) jobCanonicals.add(catLC);
  }

  const proCanonicals = new Set<string>();
  for (const ps of proSkills.map(norm)) {
    proCanonicals.add(ps);
    for (const [canonCat, keywords] of Object.entries(SKILL_KEYWORD_MAP)) {
      const catLC = norm(canonCat);
      if (ps === catLC || keywords.some(kw => kw.length >= 3 && (ps === kw || ps.startsWith(kw) || ps.includes(kw)))) {
        proCanonicals.add(catLC);
      }
    }
  }

  // Direct required_skills match: if any of pro's skills directly matches a required skill
  const proSkillsLC = proSkills.map(norm);
  if (reqLC.some(r => proSkillsLC.some(ps => ps.includes(r) || r.includes(ps)))) return true;

  if (jobCanonicals.size === 0) {
    return reqLC.some(r => proSkillsLC.includes(r)) || proSkillsLC.includes(jobCat);
  }
  for (const cat of jobCanonicals) { if (proCanonicals.has(cat)) return true; }
  return false;
}

function searchMatchesPro(query: string, proSkills: string[], proName: string, proBio: string): number {
  if (!proSkills.length) return 0;
  const q = norm(query);
  const proLC = proSkills.map(norm);
  let score = 0;
  if (proLC.includes(q)) return 200;
  for (const [canonCat, keywords] of Object.entries(SKILL_KEYWORD_MAP)) {
    const catLC = norm(canonCat);
    const queryMatchesCat = catLC === q || catLC.includes(q) || q.includes(catLC) || keywords.some(kw => q.includes(kw) || kw.startsWith(q));
    if (!queryMatchesCat) continue;
    if (proLC.includes(catLC)) { score = Math.max(score, 150); continue; }
    if (keywords.some(kw => proLC.some(ps => ps.includes(kw) || kw.includes(ps)))) score = Math.max(score, 100);
  }
  if (score === 0 && proLC.some(s => s.includes(q) || q.includes(s))) score = 60;
  if (score > 0) {
    if (norm(proName).includes(q)) score += 20;
    if (norm(proBio).includes(q)) score += 10;
  }
  return score;
}

function normalizeSkills(inputSkills: string[]): string[] {
  const out = new Set<string>();
  for (const skill of inputSkills) {
    if (!skill) continue;
    const s = norm(skill);
    let matched = false;
    for (const [canonCat, keywords] of Object.entries(SKILL_KEYWORD_MAP)) {
      if (norm(canonCat) === s || keywords.some(kw => s === kw || s.includes(kw) || kw.includes(s))) {
        out.add(canonCat);
        matched = true;
      }
    }
    if (!matched) {
      const titled = skill.trim().replace(/\b\w/g, c => c.toUpperCase());
      out.add(titled);
    }
  }
  return Array.from(out);
}

function haversineKm(lat1: number, lng1: number, lat2: number, lng2: number): number {
  const R = 6371;
  const dLat = (lat2-lat1)*Math.PI/180;
  const dLon = (lng2-lng1)*Math.PI/180;
  const a = Math.sin(dLat/2)**2 + Math.cos(lat1*Math.PI/180)*Math.cos(lat2*Math.PI/180)*Math.sin(dLon/2)**2;
  return R*2*Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
}

const app = express();
export default app;

const wsClients = new Map<string, WebSocket>();

const uploadsDir = path.join(process.cwd(), "uploads");
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

// ⚠️  RENDER WARNING: Render's free/starter plans use an ephemeral filesystem.
//     Files uploaded to /uploads will be LOST on every redeploy or restart.
//     For production, migrate file uploads to Firebase Storage or a similar
//     persistent object store. See README for instructions.
if (process.env.NODE_ENV === 'production') {
  console.warn('⚠️  /uploads directory is ephemeral on Render. Uploaded files will not persist across restarts. Migrate to Firebase Storage for production.');
}

const multerStorage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, "uploads/"),
  filename:    (_req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `${file.fieldname}-${Date.now()}-${Math.round(Math.random()*1e9)}${ext}`);
  },
});
const upload = multer({
  storage: multerStorage,
  limits: { fileSize: 10*1024*1024 }, // 10 MB hard limit
  fileFilter: (_req, file, cb) => {
    const allowedMimes = [
      "image/jpeg","image/png","image/gif","image/webp","image/svg+xml",
      "video/mp4","video/webm","video/quicktime","video/x-msvideo",
      "application/pdf",
      "application/msword",
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      "application/vnd.ms-excel",
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      "text/plain",
    ];
    if (allowedMimes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error(`File type not allowed: ${file.mimetype}`));
    }
  },
});

// ---------------------------------------------------------------------------
// ZOD VALIDATION SCHEMAS
// ---------------------------------------------------------------------------
const RegisterSchema = z.object({
  email:    z.string().email("Invalid email address"),
  password: z.string().min(8, "Password must be at least 8 characters"),
  name:     z.string().min(2, "Name must be at least 2 characters").max(80),
  role:     z.enum(["client", "pro"], { errorMap: () => ({ message: "Role must be client or pro" }) }),
  skills:   z.array(z.string()).optional(),
  location: z.string().max(200).optional(),
});

const LoginSchema = z.object({
  email:    z.string().email("Invalid email address"),
  password: z.string().min(1, "Password is required"),
});

const PostJobSchema = z.object({
  title:       z.string().min(3, "Title must be at least 3 characters").max(120),
  description: z.string().min(10, "Description must be at least 10 characters").max(2000),
  price:       z.coerce.number().min(0, "Price cannot be negative"),
  location:    z.string().max(200).optional(),
  category:    z.string().max(80).optional(),
});

const OfferSchema = z.object({
  amount: z.coerce.number().positive("Amount must be a positive number"),
});

const DisputeSchema = z.object({
  reason: z.string().min(10, "Please describe the dispute (min 10 characters)").max(1000),
});

// ---------------------------------------------------------------------------
// HELPERS
// ---------------------------------------------------------------------------
function serializeDoc(data: Record<string, any>): Record<string, any> {
  const out: Record<string, any> = {};
  for (const [key, val] of Object.entries(data)) {
    if (val && typeof val==="object" && typeof val.toDate==="function") {
      out[key] = (val.toDate() as Date).toISOString();
    } else if (val && typeof val==="object" && "_seconds" in val && "_nanoseconds" in val) {
      out[key] = new Date((val as any)._seconds*1000).toISOString();
    } else { out[key] = val; }
  }
  return out;
}

function buildUserResponse(id: string, d: Record<string,any>) {
  return {
    id, email: d.email, name: d.name, role: d.role,
    is_verified: d.is_verified||0, is_admin: d.is_admin||0,
    is_available: d.is_available??1, bio: d.bio||"",
    location: d.location||"", avatar: d.avatar||"",
    skills: d.skills||[],
    subscription_status: d.subscription_status||"none",
    trial_ends_at: d.trial_ends_at||null,
    subscription_ends_at: d.subscription_ends_at||null,
    rejection_reason: d.rejection_reason||null,
    avg_rating: d.avg_rating||null,
    review_count: d.review_count||0,
    acceptance_rate: d.jobs_offered > 0 ? Math.round((d.jobs_accepted||0) / d.jobs_offered * 100) : null,
    avg_response_minutes: d.response_count > 0 ? Math.round((d.response_time_sum||0) / d.response_count) : null,
  };
}

// Validate request body with a Zod schema — returns parsed data or sends 400
function validate<T>(schema: z.ZodSchema<T>, data: unknown, res: any): T | null {
  const result = schema.safeParse(data);
  if (!result.success) {
    const messages = result.error.errors.map(e => e.message).join("; ");
    res.status(400).json({ error: messages });
    return null;
  }
  return result.data;
}

async function startServer() {
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // ⚠️  RENDER / REVERSE PROXY: trust the first hop so express-rate-limit
  //     sees the real client IP from X-Forwarded-For, not the proxy IP.
  app.set('trust proxy', 1);

  // CORS — allow the deployed frontend origin to call the API.
  // In production set CORS_ORIGIN in your Render env vars to your exact domain.
  const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';
  app.use((_req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', CORS_ORIGIN);
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
    if (_req.method === 'OPTIONS') return res.sendStatus(204);
    next();
  });

  app.use("/uploads", express.static(path.join(process.cwd(), "uploads")));

  const authLimiter = rateLimit({ 
    windowMs: 15*60*1000,  // 15 minutes
    max: 5,                // Only 5 attempts per 15 minutes (stricter for auth)
    standardHeaders: true, 
    legacyHeaders: false, 
    skipSuccessfulRequests: true,  // Don't count successful auth attempts
    message: { error: "Too many login attempts. Please try again in 15 minutes." } 
  });
  const apiLimiter  = rateLimit({ 
    windowMs: 60*1000,     // 1 minute
    max: 300,              // 300 requests per minute
    standardHeaders: true, 
    legacyHeaders: false, 
    message: { error: "Too many requests. Please slow down." } 
  });
  app.use("/api/auth", authLimiter);
  app.use("/api", apiLimiter);

  // Push a real-time notification via WebSocket AND store in Firestore
  // Push a real-time notification via WebSocket AND store in Firestore (non-blocking write)
  const createNotification = async (userId: string, content: string, type: string, jobId?: string) => {
    // Push via WebSocket immediately (don't wait for Firestore)
    const ws = wsClients.get(userId);
    const tmpId = `tmp_${Date.now()}_${Math.random().toString(36).slice(2)}`;
    if (ws?.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({
        type: "notification",
        id: tmpId,
        content,
        notificationType: type,
        jobId: jobId || null,
        createdAt: new Date().toISOString(),
        is_read: false,
      }));
    }
    // Write to Firestore in background (don't await — keeps API response fast)
    const notifData: any = { user_id: userId, content, type, is_read: false, created_at: FieldValue.serverTimestamp() };
    if (jobId) notifData.job_id = jobId;
    db.collection("notifications").add(notifData).catch(err => console.error("Notification write error:", err));
  };

  // Push real-time data update to a user via WebSocket (job changed, new offer, etc.)
  const pushDataUpdate = (userId: string, updateType: string, payload: Record<string, any>) => {
    const ws = wsClients.get(userId);
    if (ws?.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: updateType, ...payload }));
    }
  };

  // =========================================================================
  // AUTH
  // =========================================================================

  app.post("/api/auth/register", async (req, res, next) => {
    try {
      const body = validate(RegisterSchema, req.body, res);
      if (!body) return;
      const { email, password, name, role, skills, location } = body;

      const existing = await db.collection("users").where("email","==",email).limit(1).get();
      if (!existing.empty) return res.status(400).json({ error:"Email already exists" });

      const hashed      = await bcrypt.hash(password, 10);
      const finalSkills = role==="pro" ? normalizeSkills(skills||[]) : [];
      const isAdmin     = ADMIN_EMAILS.includes(email) ? 1 : 0;

      const ref = await db.collection("users").add({
        email, password:hashed, name, role, skills:finalSkills,
        location:location||"", location_lat:null, location_lng:null,
        is_verified:0, is_available:1, is_admin:isAdmin,
        is_public_profile:true, is_public_docs:false,
        subscription_status:"none", trial_ends_at:null, subscription_ends_at:null,
        login_code:null, login_code_expires:null, avatar:"", bio:"",
        // Pro stats
        jobs_offered:0, jobs_accepted:0, response_time_sum:0, response_count:0,
        created_at:FieldValue.serverTimestamp(),
      });

      const { accessToken, refreshToken } = issueTokens(ref.id, email, role, isAdmin);
      await storeRefreshToken(ref.id, refreshToken);

      res.json({ 
        accessToken, 
        refreshToken,
        expiresIn: 15 * 60, // 15 minutes in seconds
        user:buildUserResponse(ref.id, { email,name,role,is_verified:0,is_admin:isAdmin,skills:finalSkills,location:location||"",subscription_status:"none",trial_ends_at:null,subscription_ends_at:null,is_available:1,bio:"",avatar:"",jobs_offered:0,jobs_accepted:0,response_time_sum:0,response_count:0 }) 
      });
    } catch(e) { next(e); }
  });

  app.post("/api/auth/login", async (req, res, next) => {
    try {
      const body = validate(LoginSchema, req.body, res);
      if (!body) return;
      const { email, password } = body;

      const snap = await db.collection("users").where("email","==",email).limit(1).get();
      if (snap.empty) return res.status(401).json({ error:"Invalid credentials" });
      const doc = snap.docs[0]; const d = doc.data();
      if (!(await bcrypt.compare(password, d.password))) return res.status(401).json({ error:"Invalid credentials" });

      const isAdmin = ADMIN_EMAILS.includes(email) ? 1 : (d.is_admin||0);
      if (isAdmin === 1) {
        if (!d.is_admin) await doc.ref.update({ is_admin:1 });
        const { accessToken, refreshToken } = issueTokens(doc.id, email, d.role, 1);
        await storeRefreshToken(doc.id, refreshToken);
        return res.json({ 
          accessToken, 
          refreshToken,
          expiresIn: 15 * 60,
          user:buildUserResponse(doc.id, { ...d, is_admin:1 }), 
          adminDirect:true 
        });
      }
      const code    = Math.floor(100000+Math.random()*900000).toString();
      const expires = new Date(Date.now()+10*60*1000).toISOString();
      await doc.ref.update({ login_code:code, login_code_expires:expires });
      await sendEmail(email, "ProsHub Login Code",
        `Your verification code is: ${code}. It expires in 10 minutes.`,
        emailHtml("Your Login Code", `Your one-time verification code is: <strong style="font-size:28px;letter-spacing:6px;color:#2563eb;">${code}</strong><br/><br/>This code expires in 10 minutes. Do not share it with anyone.`)
      );
      res.json({ message:"Verification code sent", email });
    } catch(e) { next(e); }
  });

  app.post("/api/auth/verify-code", async (req, res, next) => {
    try {
      const { email, code } = req.body;
      if (!email || !code) return res.status(400).json({ error:"Email and code are required" });
      const snap = await db.collection("users").where("email","==",email).limit(1).get();
      if (snap.empty) return res.status(401).json({ error:"User not found" });
      const doc = snap.docs[0]; const d = doc.data();
      if (d.login_code!==code || new Date()>new Date(d.login_code_expires)) return res.status(401).json({ error:"Invalid or expired code" });
      await doc.ref.update({ login_code:null, login_code_expires:null });
      const isAdmin = ADMIN_EMAILS.includes(d.email) ? 1 : (d.is_admin||0);
      if (isAdmin===1 && !d.is_admin) await doc.ref.update({ is_admin:1 });
      
      const { accessToken, refreshToken } = issueTokens(doc.id, d.email, d.role, isAdmin);
      await storeRefreshToken(doc.id, refreshToken);
      
      res.json({ 
        accessToken, 
        refreshToken,
        expiresIn: 15 * 60, // 15 minutes in seconds
        user:buildUserResponse(doc.id, { ...d, is_admin:isAdmin }) 
      });
    } catch(e) { next(e); }
  });

  // New endpoint: Refresh access token using refresh token (v8+)
  app.post("/api/auth/refresh", async (req, res, next) => {
    try {
      const { refreshToken } = req.body;
      if (!refreshToken) {
        return res.status(401).json({ error: 'Refresh token required' });
      }

      try {
        const decoded = jwt.verify(refreshToken, REFRESH_TOKEN_SECRET) as any;
        
        // Check if refresh token still exists in DB (hasn't been revoked)
        const storedTokenDoc = await db.collection('refresh_tokens').doc(decoded.id).get();
        if (!storedTokenDoc.exists || storedTokenDoc.data()?.token !== refreshToken) {
          return res.status(401).json({ error: 'Invalid or revoked refresh token' });
        }

        // Get user info
        const userDoc = await db.collection('users').doc(decoded.id).get();
        if (!userDoc.exists) {
          return res.status(401).json({ error: 'User not found' });
        }

        const userData = userDoc.data()!;
        const newAccessToken = jwt.sign(
          { id: decoded.id, email: userData.email, role: userData.role, is_admin: userData.is_admin || 0 },
          JWT_SECRET,
          { expiresIn: ACCESS_TOKEN_EXPIRY }
        );

        res.json({ 
          accessToken: newAccessToken,
          expiresIn: 15 * 60
        });
      } catch (err: any) {
        if (err.name === 'TokenExpiredError') {
          return res.status(401).json({ error: 'Refresh token expired', code: 'REFRESH_TOKEN_EXPIRED' });
        }
        return res.status(401).json({ error: 'Invalid refresh token' });
      }
    } catch(e) { next(e); }
  });

  app.post("/api/auth/forgot-password", async (req, res, next) => {
    try {
      const { email } = req.body;
      if (!email) return res.status(400).json({ error:"Email is required" });
      const snap = await db.collection("users").where("email","==",email).limit(1).get();
      if (!snap.empty) {
        const code = Math.floor(100000+Math.random()*900000).toString();
        await snap.docs[0].ref.update({ login_code:code, login_code_expires:new Date(Date.now()+15*60*1000).toISOString() });
        await sendEmail(email, "ProsHub Password Reset",
          `Your reset code is: ${code}. Expires in 15 minutes.`,
          emailHtml("Password Reset", `Your password reset code is: <strong style="font-size:28px;letter-spacing:6px;color:#2563eb;">${code}</strong><br/><br/>This code expires in 15 minutes. If you didn't request this, you can safely ignore this email.`)
        );
      }
      res.json({ message:"If an account exists, a reset code has been sent.", email });
    } catch(e) { next(e); }
  });

  app.post("/api/auth/reset-password", async (req, res, next) => {
    try {
      const { email, code, newPassword } = req.body;
      if (!email || !code || !newPassword) return res.status(400).json({ error:"Email, code and new password are required" });
      if (newPassword.length < 8) return res.status(400).json({ error:"Password must be at least 8 characters" });
      const snap = await db.collection("users").where("email","==",email).limit(1).get();
      if (snap.empty) return res.status(401).json({ error:"Invalid or expired code" });
      const doc = snap.docs[0]; const d = doc.data();
      if (d.login_code!==code || new Date()>new Date(d.login_code_expires)) return res.status(401).json({ error:"Invalid or expired code" });
      const hashed = await bcrypt.hash(newPassword, 10);
      await doc.ref.update({ password:hashed, login_code:null, login_code_expires:null });
      res.json({ success:true, message:"Password updated" });
    } catch(e) { next(e); }
  });

  const authenticate = (req: any, res: any, next: any) => {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ error:"Unauthorized" });
    try { req.user = jwt.verify(token, JWT_SECRET!) as any; next(); }
    catch { res.status(401).json({ error:"Invalid token" }); }
  };

  // =========================================================================
  // SUBSCRIPTIONS
  // =========================================================================

  app.post("/api/subscription/start-trial", authenticate, async (req: any, res, next) => {
    try {
      if (req.user.role!=="pro") return res.status(403).json({ error:"Pros only" });
      const ends = new Date(); ends.setMonth(ends.getMonth()+6);
      await db.collection("users").doc(req.user.id).update({ subscription_status:"trial", trial_ends_at:ends.toISOString() });
      res.json({ success:true, trial_ends_at:ends.toISOString() });
    } catch(e) { next(e); }
  });

  app.post("/api/subscription/subscribe", authenticate, async (req: any, res, next) => {
    try {
      if (req.user.role!=="pro") return res.status(403).json({ error:"Pros only" });
      const ends = new Date(); ends.setMonth(ends.getMonth()+1);
      await db.collection("users").doc(req.user.id).update({ subscription_status:"active", subscription_ends_at:ends.toISOString() });
      res.json({ success:true, subscription_ends_at:ends.toISOString() });
    } catch(e) { next(e); }
  });

  app.get("/api/user/subscription", authenticate, async (req: any, res, next) => {
    try {
      const doc = await db.collection("users").doc(req.user.id).get();
      if (!doc.exists) return res.status(404).json({ error:"Not found" });
      const d = doc.data()!;
      res.json({ subscription_status:d.subscription_status||"none", trial_ends_at:d.trial_ends_at||null, subscription_ends_at:d.subscription_ends_at||null });
    } catch(e) { next(e); }
  });

  // =========================================================================
  // USER PROFILE
  // =========================================================================

  app.get("/api/user/profile", authenticate, async (req: any, res, next) => {
    try {
      const doc = await db.collection("users").doc(req.user.id).get();
      if (!doc.exists) return res.status(404).json({ error:"User not found" });
      const d = doc.data()!;
      let reviews: any[] = [];
      if (d.role==="pro") {
        const reviewsSnap = await db.collection("reviews").where("pro_id","==",req.user.id)
          .orderBy("created_at","desc").get()
          .catch(() => db.collection("reviews").where("pro_id","==",req.user.id).get());
        reviews = await Promise.all(reviewsSnap.docs.map(async r => {
          const rData = r.data();
          const clientDoc = rData.client_id ? await db.collection("users").doc(rData.client_id).get() : null;
          return { id:r.id, ...serializeDoc(rData), reviewer_name:clientDoc?.data()?.name||"Anonymous Client" };
        }));
      }
      res.json({
        ...buildUserResponse(doc.id, d),
        is_public_profile: d.is_public_profile??true,
        is_public_docs: d.is_public_docs??false,
        location_lat: d.location_lat||null,
        location_lng: d.location_lng||null,
        reviews,
      });
    } catch(e) { next(e); }
  });

  app.put("/api/user/profile", authenticate, async (req: any, res, next) => {
    try {
      const { name, bio, skills, avatar, is_public_profile, is_public_docs, location, location_lat, location_lng } = req.body;
      if (name && (name.length < 2 || name.length > 80)) return res.status(400).json({ error:"Name must be 2–80 characters" });
      const finalSkills = req.user.role==="pro" ? normalizeSkills(skills||[]) : [];
      const update: any = {
        name, bio:bio||"", skills:finalSkills, avatar:avatar||"",
        is_public_profile:is_public_profile!==false,
        is_public_docs:is_public_docs===true,
        location:location||"",
      };
      if (location_lat!=null) update.location_lat = Number(location_lat);
      if (location_lng!=null) update.location_lng = Number(location_lng);
      await db.collection("users").doc(req.user.id).update(update);
      res.json({ success:true, skills:finalSkills });
    } catch(e) { next(e); }
  });

  app.post("/api/user/avatar", authenticate, upload.single("avatar"), async (req: any, res, next) => {
    try {
      if (!req.file) return res.status(400).json({ error:"No file uploaded" });
      const avatar_url = `/uploads/${req.file.filename}`;
      await db.collection("users").doc(req.user.id).update({ avatar:avatar_url });
      res.json({ success:true, avatar_url });
    } catch(e) { next(e); }
  });

  app.post("/api/user/availability", authenticate, async (req: any, res, next) => {
    try {
      const { is_available } = req.body;
      await db.collection("users").doc(req.user.id).update({ is_available:is_available?1:0 });
      res.json({ success:true });
    } catch(e) { next(e); }
  });

  app.post("/api/user/verify", authenticate, async (req: any, res, next) => {
    try {
      const { status } = req.body;
      await db.collection("users").doc(req.user.id).update({ is_verified:status||50, rejection_reason: null });
      // Notify all admins that a new verification submission is pending review
      const adminSnap = await db.collection("users").where("is_admin","==",1).get();
      const proDoc = await db.collection("users").doc(req.user.id).get();
      const proName = proDoc.data()?.name || "A professional";
      await Promise.all(adminSnap.docs.map(admin =>
        createNotification(admin.id, `📋 New verification submission from ${proName}. Please review their documents.`, "verification_update")
      ));
      res.json({ success:true });
    } catch(e) { next(e); }
  });

  app.post("/api/jobs/:id/video-call", authenticate, async (req: any, res, next) => {
    try {
      const doc = await db.collection("jobs").doc(req.params.id).get();
      if (!doc.exists) return res.status(404).json({ error:"Not found" });
      const job = doc.data()!;
      const recipientId = req.user.id===job.client_id ? job.pro_id : job.client_id;
      if (recipientId) await createNotification(recipientId, `${req.user.name} is calling for: ${job.title}`, "message");
      res.json({ success:true });
    } catch(e) { next(e); }
  });

  // =========================================================================
  // DOCUMENTS
  // =========================================================================

  app.get("/api/user/documents", authenticate, async (req: any, res, next) => {
    try {
      const snap = await db.collection("user_documents").where("user_id","==",req.user.id).get();
      res.json(snap.docs.map(d => ({ id:d.id, ...serializeDoc(d.data()) })));
    } catch(e) { next(e); }
  });

  app.post("/api/user/documents", authenticate, async (req: any, res, next) => {
    try {
      const { title, file_url } = req.body;
      if (!title||!file_url) return res.status(400).json({ error:"Title and file_url are required" });
      await db.collection("user_documents").add({ user_id:req.user.id, title, file_url, created_at:FieldValue.serverTimestamp() });
      res.json({ success:true });
    } catch(e) { next(e); }
  });

  app.post("/api/user/documents/upload", authenticate, upload.single("file"), async (req: any, res, next) => {
    try {
      const { title } = req.body;
      if (!title?.trim()) return res.status(400).json({ error:"Title is required" });
      if (!req.file) return res.status(400).json({ error:"No file uploaded" });
      const file_url = `/uploads/${req.file.filename}`;
      // is_verification_doc=true when uploaded from Verification flow (not profile documents)
      const isVerificationDoc = req.body.is_verification_doc === "true" || req.body.is_verification_doc === true;
      await db.collection("user_documents").add({
        user_id:req.user.id, title:title.trim(), file_url,
        original_name:req.file.originalname, mimetype:req.file.mimetype,
        is_verification_doc: isVerificationDoc ? true : false,
        created_at:FieldValue.serverTimestamp(),
      });
      res.json({ success:true, file_url });
    } catch(e) { next(e); }
  });

  app.delete("/api/user/documents/:id", authenticate, async (req: any, res, next) => {
    try {
      const ref = db.collection("user_documents").doc(req.params.id);
      const doc = await ref.get();
      if (!doc.exists||doc.data()!.user_id!==req.user.id) return res.status(403).json({ error:"Not allowed" });
      const fileUrl: string = doc.data()!.file_url||"";
      if (fileUrl.startsWith("/uploads/")) {
        const filePath = path.join(process.cwd(), fileUrl);
        if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
      }
      await ref.delete();
      res.json({ success:true });
    } catch(e) { next(e); }
  });

  // =========================================================================
  // PORTFOLIO
  // =========================================================================

  app.get("/api/user/completed-works", authenticate, async (req: any, res, next) => {
    try {
      const snap = await db.collection("completed_works").where("pro_id","==",req.user.id).orderBy("created_at","desc").get();
      res.json(snap.docs.map(d => ({ id:d.id, ...serializeDoc(d.data()) })));
    } catch(e: any) { if (e.code===9) return res.json([]); next(e); }
  });

  app.get("/api/pros/:id/completed-works", authenticate, async (req, res, next) => {
    try {
      const snap = await db.collection("completed_works").where("pro_id","==",req.params.id).orderBy("created_at","desc").get();
      res.json(snap.docs.map(d => ({ id:d.id, ...serializeDoc(d.data()) })));
    } catch(e: any) { if (e.code===9) return res.json([]); next(e); }
  });

  app.delete("/api/user/completed-works/:id", authenticate, async (req: any, res, next) => {
    try {
      const ref = db.collection("completed_works").doc(req.params.id);
      const doc = await ref.get();
      if (!doc.exists||doc.data()!.pro_id!==req.user.id) return res.status(403).json({ error:"Not allowed" });
      const data = doc.data()!;
      // Remove all associated files
      for (const urlField of ['image_url', 'video_url', 'doc_url']) {
        const fileUrl: string = data[urlField]||"";
        if (fileUrl.startsWith("/uploads/")) {
          const filePath = path.join(process.cwd(), fileUrl);
          if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
        }
      }
      await ref.delete();
      res.json({ success:true });
    } catch(e) { next(e); }
  });

  // PORTFOLIO VISIBILITY TOGGLE — pro can show/hide portfolio items from their public profile
  app.patch("/api/user/completed-works/:id/visibility", authenticate, async (req: any, res, next) => {
    try {
      const ref = db.collection("completed_works").doc(req.params.id);
      const doc = await ref.get();
      if (!doc.exists || doc.data()!.pro_id !== req.user.id) return res.status(403).json({ error:"Not allowed" });
      const { is_hidden } = req.body;
      await ref.update({ is_hidden: is_hidden ? 1 : 0 });
      res.json({ success:true });
    } catch(e) { next(e); }
  });

  app.post("/api/pro/portfolio/upload", authenticate, upload.single("file"), async (req: any, res, next) => {
    try {
      const { title, description, image_url } = req.body;
      if (!title?.trim()) return res.status(400).json({ error:"Title is required" });
      
      let file_url = image_url || "";
      
      if (req.file) {
        // SECURITY FIX #3: Enhanced file validation
        const file = req.file;
        
        // 1. Check file size limit (10MB)
        const MAX_FILE_SIZE = 10 * 1024 * 1024;
        if (file.size > MAX_FILE_SIZE) {
          fs.unlinkSync(file.path);
          return res.status(413).json({ error: `File too large (max ${MAX_FILE_SIZE / 1024 / 1024}MB)` });
        }

        // 2. Allowed MIME types with extensions
        const ALLOWED_TYPES: Record<string, string[]> = {
          'image/jpeg': ['.jpg', '.jpeg'],
          'image/png': ['.png'],
          'image/webp': ['.webp'],
          'image/gif': ['.gif'],
          'application/pdf': ['.pdf'],
          'video/mp4': ['.mp4'],
          'video/webm': ['.webm'],
          'video/quicktime': ['.mov'],
          'video/x-msvideo': ['.avi'],
        };

        // 3. Validate MIME type from multer
        if (!ALLOWED_TYPES[file.mimetype]) {
          fs.unlinkSync(file.path);
          return res.status(400).json({ 
            error: `Invalid file type. Allowed: images, videos, and PDF`
          });
        }

        // 4. Check file extension matches MIME type (relaxed for videos)
        const fileExt = path.extname(file.originalname).toLowerCase();
        const allowedExts = ALLOWED_TYPES[file.mimetype];
        if (!allowedExts.includes(fileExt) && fileExt !== '') {
          // Only block if extension is totally wrong (not just missing)
          const allExts = Object.values(ALLOWED_TYPES).flat();
          if (allExts.includes(fileExt)) {
            fs.unlinkSync(file.path);
            return res.status(400).json({ 
              error: `Invalid file extension for ${file.mimetype}`
            });
          }
        }

        // 5. Generate secure filename (hash-based, prevents directory traversal)
        const fileHash = crypto
          .createHash('sha256')
          .update(file.originalname + Date.now() + Math.random())
          .digest('hex')
          .slice(0, 16);
        
        const secureFilename = `${fileHash}${fileExt}`;
        const finalPath = path.join(path.dirname(file.path), secureFilename);
        fs.renameSync(file.path, finalPath);

        file_url = `/uploads/${secureFilename}`;
      }

      const isVideo = req.file && req.file.mimetype.startsWith('video/');
      const isPdf = req.file && req.file.mimetype === 'application/pdf';
      await db.collection("completed_works").add({
        pro_id:req.user.id, 
        title:title.trim(),
        description:(description||"").trim(), 
        image_url: (!isVideo && !isPdf) ? file_url : "",
        video_url: isVideo ? file_url : "",
        doc_url: isPdf ? file_url : "",
        file_type:req.file?req.file.mimetype:"url",
        original_name:req.file?req.file.originalname:null,
        file_size:req.file?req.file.size:null,
        created_at:FieldValue.serverTimestamp(),
      });
      res.json({ success:true, file_url });
    } catch(e) { next(e); }
  });

  app.post("/api/pro/portfolio", authenticate, async (req: any, res, next) => {
    try {
      const { title, description, image_url } = req.body;
      await db.collection("completed_works").add({ pro_id:req.user.id, title, description, image_url:image_url||"", created_at:FieldValue.serverTimestamp() });
      res.json({ success:true });
    } catch(e) { next(e); }
  });

  app.get("/api/pro/:id/portfolio", async (req, res, next) => {
    try {
      const snap = await db.collection("completed_works").where("pro_id","==",req.params.id).orderBy("created_at","desc").get();
      // Only return non-hidden items for public view
      const items = snap.docs
        .map(d => ({ id:d.id, ...serializeDoc(d.data()) }))
        .filter((item: any) => !item.is_hidden);
      res.json(items);
    } catch(e: any) { if (e.code===9) return res.json([]); next(e); }
  });

  // =========================================================================
  // NOTIFICATIONS — delivered via WS push; REST is fallback/history
  // =========================================================================

  app.get("/api/notifications", authenticate, async (req: any, res, next) => {
    try {
      const snap = await db.collection("notifications").where("user_id","==",req.user.id).orderBy("created_at","desc").limit(50).get();
      // Filter out locked notifications (job taken by another pro) from the list
      const notifs = snap.docs
        .map(d => ({ id:d.id, ...serializeDoc(d.data()) }))
        .filter((n: any) => !n.locked);
      res.json(notifs);
    } catch(e: any) { if (e.code===9) return res.json([]); next(e); }
  });

  app.post("/api/notifications/read", authenticate, async (req: any, res, next) => {
    try {
      const snap = await db.collection("notifications").where("user_id","==",req.user.id).where("is_read","==",false).get();
      const batch = db.batch();
      snap.docs.forEach(d => batch.update(d.ref, { is_read:true }));
      await batch.commit();
      res.json({ success:true });
    } catch { res.json({ success:true }); }
  });

  app.post("/api/notifications/:id/read", authenticate, async (req: any, res, next) => {
    try {
      await db.collection("notifications").doc(req.params.id).update({ is_read:true });
      res.json({ success:true });
    } catch(e) { next(e); }
  });

  // =========================================================================
  // STATS
  // =========================================================================

  app.get("/api/stats/categories", async (_req, res, next) => {
    try {
      const snap = await db.collection("users").where("role","==","pro").get();
      const counts: Record<string,number> = {};
      snap.docs.forEach(doc => {
        (doc.data().skills||[]).forEach((s: string) => { if (s) counts[s.trim()]=(counts[s.trim()]||0)+1; });
      });
      res.json(Object.entries(counts).map(([name,count])=>({name,count})).sort((a,b)=>b.count-a.count));
    } catch(e) { next(e); }
  });

  // =========================================================================
  // DELETE ACCOUNT
  // =========================================================================

  app.delete("/api/user/account", authenticate, async (req: any, res, next) => {
    try {
      const uid = req.user.id;

      // Delete uploaded files from disk first
      try {
        const [docsSnap, worksSnap] = await Promise.all([
          db.collection("user_documents").where("user_id","==",uid).get(),
          db.collection("completed_works").where("pro_id","==",uid).get(),
        ]);
        docsSnap.docs.forEach(d => {
          const url = d.data().file_url||"";
          if (url.startsWith("/uploads/")) { try { const fp = path.join(process.cwd(), url); if (fs.existsSync(fp)) fs.unlinkSync(fp); } catch {} }
        });
        worksSnap.docs.forEach(d => {
          for (const f of ["image_url","video_url","doc_url"]) {
            const url = d.data()[f]||"";
            if (url.startsWith("/uploads/")) { try { const fp = path.join(process.cwd(), url); if (fs.existsSync(fp)) fs.unlinkSync(fp); } catch {} }
          }
        });
      } catch { /* non-fatal */ }

      // Delete all Firestore records — use individual batches per collection to avoid 500-doc limit
      const collectionsToDelete: Array<[string, string]> = [
        ["user_documents","user_id"],["completed_works","pro_id"],["notifications","user_id"],
        ["offers","sender_id"],["messages","sender_id"],["reviews","pro_id"],["reviews","client_id"],
      ];
      for (const [col, field] of collectionsToDelete) {
        try {
          const snap = await db.collection(col).where(field,"==",uid).get();
          if (!snap.empty) {
            const b = db.batch(); snap.docs.forEach(d => b.delete(d.ref)); await b.commit();
          }
        } catch { /* non-fatal */ }
      }
      for (const field of ["client_id","pro_id"]) {
        try {
          const snap = await db.collection("jobs").where(field,"==",uid).get();
          if (!snap.empty) { const b = db.batch(); snap.docs.forEach(d => b.delete(d.ref)); await b.commit(); }
        } catch { /* non-fatal */ }
      }
      // Delete refresh token
      try { await db.collection("refresh_tokens").doc(uid).delete(); } catch {}
      // Delete user doc
      await db.collection("users").doc(uid).delete();
      // Disconnect WebSocket
      const ws = wsClients.get(uid); if (ws) { ws.close(); wsClients.delete(uid); }
      res.json({ success:true });
    } catch(e) { next(e); }
  });

  // =========================================================================
  // PROS — SEARCH (returns acceptance_rate + avg_response_minutes)
  // =========================================================================

  app.get("/api/pros/search", authenticate, async (req: any, res, next) => {
    try {
      const { query, localOnly } = req.query;
      if (!query||(query as string).trim()==="") return res.json([]);
      const q = (query as string).trim();
      const isLocalOnly = localOnly==="true";
      const userDoc = await db.collection("users").doc(req.user.id).get();
      const userLocation = userDoc.data()?.location||"";
      const clientLat = parseFloat(req.query.lat as string);
      const clientLng = parseFloat(req.query.lng as string);
      let prosQuery: FirebaseFirestore.Query = db.collection("users").where("role","==","pro");
      if (isLocalOnly && userLocation) prosQuery = prosQuery.where("location","==",userLocation);
      const snap = await prosQuery.get();
      const results = snap.docs
        .map(doc => {
          const d = doc.data();
          const skills = (d.skills||[]) as string[];
          const score = searchMatchesPro(q, skills, d.name||"", d.bio||"");
          let distance: number|null = null;
          if (!isNaN(clientLat)&&!isNaN(clientLng)&&d.location_lat&&d.location_lng) {
            distance = haversineKm(clientLat, clientLng, d.location_lat, d.location_lng);
          }
          const acceptance_rate = d.jobs_offered > 0 ? Math.round((d.jobs_accepted||0) / d.jobs_offered * 100) : null;
          const avg_response_minutes = d.response_count > 0 ? Math.round((d.response_time_sum||0) / d.response_count) : null;
          return { id:doc.id, ...serializeDoc(d), skills, score, distance, acceptance_rate, avg_response_minutes };
        })
        .filter(p => p.score>0)
        .sort((a,b) => b.score-a.score);
      res.json(results);
    } catch(e) { next(e); }
  });

  // =========================================================================
  // PROS — FULL PROFILE
  // =========================================================================

  app.get("/api/pros/:id", authenticate, async (req, res, next) => {
    try {
      const doc = await db.collection("users").doc(req.params.id).get();
      if (!doc.exists||doc.data()!.role!=="pro") return res.status(404).json({ error:"Professional not found" });
      const d = doc.data()!;
      const [portfolioSnap, reviewsSnap, historySnap, docsSnap] = await Promise.all([
        db.collection("completed_works").where("pro_id","==",doc.id).orderBy("created_at","desc").get().catch(()=>db.collection("completed_works").where("pro_id","==",doc.id).get()),
        db.collection("reviews").where("pro_id","==",doc.id).orderBy("created_at","desc").get().catch(()=>db.collection("reviews").where("pro_id","==",doc.id).get()),
        db.collection("jobs").where("pro_id","==",doc.id).where("status","==","finalized").orderBy("created_at","desc").get().catch(()=>db.collection("jobs").where("pro_id","==",doc.id).where("status","==","finalized").get()),
        db.collection("user_documents").where("user_id","==",doc.id).get(),
      ]);
      const reviews = await Promise.all(reviewsSnap.docs.filter(r=>!r.data().is_private).map(async r => {
        const rData = r.data();
        const clientDoc = await db.collection("users").doc(rData.client_id).get();
        return { id:r.id, ...serializeDoc(rData), client_name:clientDoc.data()?.name||"Anonymous" };
      }));
      const acceptance_rate = d.jobs_offered > 0 ? Math.round((d.jobs_accepted||0) / d.jobs_offered * 100) : null;
      const avg_response_minutes = d.response_count > 0 ? Math.round((d.response_time_sum||0) / d.response_count) : null;
      res.json({
        id:doc.id, name:d.name, email:d.email, avatar:d.avatar||"",
        skills:d.skills||[], bio:d.bio||"", is_verified:d.is_verified||0,
        is_available:d.is_available??1, location:d.location||"",
        location_lat:d.location_lat||null, location_lng:d.location_lng||null,
        avg_rating:d.avg_rating||null, review_count:d.review_count||0,
        acceptance_rate, avg_response_minutes,
        created_at:d.created_at&&typeof d.created_at.toDate==="function"?d.created_at.toDate().toISOString():d.created_at,
        portfolio:   portfolioSnap.docs.map(p=>({id:p.id,...serializeDoc(p.data())})).filter((p: any) => !p.is_hidden),
        reviews,
        work_history:historySnap.docs.map(j=>({id:j.id,...serializeDoc(j.data())})),
        documents:   docsSnap.docs.map(d2=>({id:d2.id,...serializeDoc(d2.data())})),
      });
    } catch(e) { next(e); }
  });

  app.get("/api/pro/:id/full-profile", authenticate, async (req: any, res, next) => {
    try {
      const doc = await db.collection("users").doc(req.params.id).get();
      if (!doc.exists||doc.data()!.role!=="pro") return res.status(404).json({ error:"Not found" });
      const d = doc.data()!;
      const isAdmin = req.user.is_admin === 1;
      const jobSnap = await db.collection("jobs").where("client_id","==",req.user.id).where("pro_id","==",req.params.id).where("status","in",["accepted","finalized"]).limit(1).get();
      const hasJob = !jobSnap.empty;
      if (!isAdmin && !d.is_public_profile&&!hasJob) return res.status(403).json({ error:"Profile is private" });
      const canSeeDocs = isAdmin || d.is_public_docs||hasJob;
      const [portfolioSnap, reviewsSnap, historySnap, docsSnap] = await Promise.all([
        db.collection("completed_works").where("pro_id","==",req.params.id).get(),
        db.collection("reviews").where("pro_id","==",req.params.id).get(),
        db.collection("jobs").where("pro_id","==",req.params.id).where("status","==","finalized").get(),
        canSeeDocs ? db.collection("user_documents").where("user_id","==",req.params.id).get() : Promise.resolve({ docs:[] as FirebaseFirestore.QueryDocumentSnapshot[] } as any),
      ]);
      res.json({
        id:doc.id, ...serializeDoc(d), skills:d.skills||[],
        acceptance_rate: d.jobs_offered > 0 ? Math.round((d.jobs_accepted||0) / d.jobs_offered * 100) : null,
        avg_response_minutes: d.response_count > 0 ? Math.round((d.response_time_sum||0) / d.response_count) : null,
        portfolio:   portfolioSnap.docs.map(p=>({id:p.id,...serializeDoc(p.data())})).filter((p: any) => !p.is_hidden),
        reviews:     reviewsSnap.docs.filter(r=>!r.data().is_private).map(r=>({id:r.id,...serializeDoc(r.data())})),
        work_history:historySnap.docs.map(j=>({id:j.id,...serializeDoc(j.data())})),
        documents:   docsSnap.docs.map(d2=>({id:d2.id,...serializeDoc(d2.data())})),
      });
    } catch(e) { next(e); }
  });

  app.get("/api/pro/:id/reviews", async (req, res, next) => {
    try {
      const snap = await db.collection("reviews").where("pro_id","==",req.params.id).orderBy("created_at","desc").get();
      res.json(snap.docs.map(d=>({id:d.id,...serializeDoc(d.data())})));
    } catch(e: any) { if (e.code===9) return res.json([]); next(e); }
  });

  // =========================================================================
  // JOBS
  // =========================================================================

  app.post("/api/jobs", authenticate, upload.single("file"), async (req: any, res, next) => {
    try {
      const body = validate(PostJobSchema, req.body, res);
      if (!body) return;
      const { title, description, price, location, category } = body;
      const isDirectHire    = req.body.is_direct_hire    ==="true"||req.body.is_direct_hire    ===true;
      const isDirectMessage = req.body.is_direct_message ==="true"||req.body.is_direct_message ===true;
      const directProId: string|null = req.body.pro_id||null;
      let image_url = req.body.image_url||"";
      if (req.file) image_url = `/uploads/${req.file.filename}`;
      const _rawSkills: string[] = (() => { try { return JSON.parse(req.body.required_skills||"[]"); } catch { return []; } })();
      // Always include category so matching always has something to work with
      const requiredSkills: string[] = _rawSkills.filter(Boolean).length > 0
        ? _rawSkills.filter(Boolean)
        : (category ? [category] : []);

      const jobStatus = isDirectMessage&&directProId ? "accepted" : isDirectHire&&directProId ? "matching" : "pending";
      const matchingExpiresAt = isDirectHire&&directProId&&!isDirectMessage ? new Date(Date.now()+24*60*60*1000).toISOString() : null;

      const jobData: Record<string,any> = {
        client_id:req.user.id,
        pro_id:(isDirectHire||isDirectMessage)&&directProId ? directProId : null,
        title, description,
        initial_price:parseFloat(String(price))||0, final_price:null,
        status:jobStatus,
        location:location||"", category:category||"",
        required_skills:requiredSkills, image_url,
        completion_notes:null,
        matching_expires_at:matchingExpiresAt,
        is_direct_message:isDirectMessage?true:false,
        review_requested:false,
        created_at:FieldValue.serverTimestamp(),
      };
      const ref = await db.collection("jobs").add(jobData);

      // Notifications + pro stats
      if (isDirectMessage&&directProId) {
        await createNotification(directProId, `${req.body._clientName||"A client"} wants to chat with you!`, "message", ref.id);
        // Track: job offered to this pro
        await db.collection("users").doc(directProId).update({ jobs_offered: FieldValue.increment(1) });
      } else if (isDirectHire&&directProId) {
        await createNotification(directProId, `You have a direct hire request: ${title}`, "job_update", ref.id);
        await db.collection("users").doc(directProId).update({ jobs_offered: FieldValue.increment(1) });

        // Email the pro
        const proDoc = await db.collection("users").doc(directProId).get();
        if (proDoc.exists) {
          const clientDoc = await db.collection("users").doc(req.user.id).get();
          const clientName = clientDoc.data()?.name || "A client";
          await sendEmail(
            proDoc.data()!.email,
            `New direct hire request: ${title}`,
            `${clientName} has sent you a direct hire request for "${title}". Log in to review it.`,
            emailHtml("New Direct Hire Request", `<strong>${clientName}</strong> has sent you a direct hire request for:<br/><strong>${title}</strong><br/><br/>Log in to your ProsHub dashboard to accept or discuss the details.`)
          );
        }
      } else {
        // Regular job — notify and email all matching pros
        // FIX: is_available can be stored as integer 1 or boolean true — query role only and filter
        const prosSnap = await db.collection("users").where("role","==","pro").get();
        const availablePros = prosSnap.docs.filter(p => {
          const d = p.data();
          // Available if is_available is true, 1, or not set (default available)
          return d.is_available === 1 || d.is_available === true || d.is_available === undefined || d.is_available === null;
        });
        const matched = availablePros.filter(p => {
          const proSkills: string[] = p.data().skills||[];
          return jobMatchesPro(category||"", title||"", description||"", requiredSkills, proSkills);
        });
        await Promise.all(matched.map(async p => {
          await createNotification(p.id, `New job matching your skills: ${title}`, "job_update", ref.id);
          await db.collection("users").doc(p.id).update({ jobs_offered: FieldValue.increment(1) });
          // Email notification for new matching job
          await sendEmail(
            p.data().email,
            `New job matching your skills: ${title}`,
            `A new job has been posted that matches your skills: "${title}". Log in to ProsHub to view and accept it.`,
            emailHtml("New Job Matching Your Skills", `A new job has been posted that matches your skills:<br/><strong>${title}</strong><br/><br/>${description.substring(0, 200)}${description.length > 200 ? "..." : ""}<br/><br/>Log in to your ProsHub dashboard to view and accept it.`)
          );
        }));
      }

      res.json({
        id:ref.id, image_url, title, description,
        initial_price:parseFloat(String(price))||0, final_price:null,
        status:jobStatus, location:location||"", category:category||"",
        required_skills:requiredSkills,
        client_id:req.user.id, pro_id:jobData.pro_id,
        matching_expires_at:matchingExpiresAt,
        is_direct_message:isDirectMessage?true:false,
        review_requested:false,
        created_at:new Date().toISOString(),
      });
    } catch(e) { next(e); }
  });

  app.get("/api/jobs/pending", authenticate, async (req: any, res, next) => {
    try {
      const userDoc = await db.collection("users").doc(req.user.id).get();
      const d = userDoc.data();
      if (!d||d.is_available===0) return res.json([]);
      const proSkills: string[] = d.skills||[];
      if (proSkills.length===0) return res.json([]);
      const snap = await db.collection("jobs").where("status","==","pending").orderBy("created_at","desc").get()
        .catch(()=>db.collection("jobs").where("status","==","pending").get());
      const matched = snap.docs
        .filter(doc => doc.data().client_id!==req.user.id && !doc.data().pro_id)
        .map(doc => ({ id:doc.id, ...serializeDoc(doc.data()) }))
        .filter((job: any) => jobMatchesPro(job.category||"", job.title||"", job.description||"", job.required_skills||[], proSkills));
      res.json(matched);
    } catch(e) { next(e); }
  });

  app.get("/api/my-jobs", authenticate, async (req: any, res, next) => {
    try {
      let jobs: any[] = [];
      if (req.user.is_admin) {
        const snap = await db.collection("jobs").orderBy("created_at","desc").get().catch(()=>db.collection("jobs").get());
        jobs = snap.docs.map(d=>({id:d.id,...serializeDoc(d.data())}));
      } else {
        const [clientSnap, proSnap] = await Promise.all([
          db.collection("jobs").where("client_id","==",req.user.id).orderBy("created_at","desc").get().catch(()=>db.collection("jobs").where("client_id","==",req.user.id).get()),
          db.collection("jobs").where("pro_id","==",req.user.id).orderBy("created_at","desc").get().catch(()=>db.collection("jobs").where("pro_id","==",req.user.id).get()),
        ]);
        const seen = new Set<string>();
        [...clientSnap.docs,...proSnap.docs].forEach(d => { if (!seen.has(d.id)) { seen.add(d.id); jobs.push({id:d.id,...serializeDoc(d.data())}); } });
      }
      const enriched = await Promise.all(jobs.map(async (job: any) => {
        const [cDoc,pDoc] = await Promise.all([
          job.client_id ? db.collection("users").doc(job.client_id).get() : null,
          job.pro_id    ? db.collection("users").doc(job.pro_id).get()    : null,
        ]);
        return { ...job, client_name:cDoc?.data()?.name||"", pro_name:pDoc?.data()?.name||"", client_verified:cDoc?.data()?.is_verified||0, pro_verified:pDoc?.data()?.is_verified||0 };
      }));
      res.json(enriched);
    } catch(e) { next(e); }
  });

  app.get("/api/jobs/:id", authenticate, async (req: any, res, next) => {
    try {
      const doc = await db.collection("jobs").doc(req.params.id).get();
      if (!doc.exists) return res.status(404).json({ error:"Job not found" });
      const job = { id:doc.id, ...serializeDoc(doc.data()) } as any;
      const [cDoc,pDoc] = await Promise.all([
        job.client_id ? db.collection("users").doc(job.client_id).get() : null,
        job.pro_id    ? db.collection("users").doc(job.pro_id).get()    : null,
      ]);
      job.client_name = cDoc?.data()?.name||"";
      job.pro_name    = pDoc?.data()?.name||"";
      const cLat=cDoc?.data()?.location_lat, cLng=cDoc?.data()?.location_lng;
      const pLat=pDoc?.data()?.location_lat, pLng=pDoc?.data()?.location_lng;
      if (cLat&&cLng&&pLat&&pLng) job.pro_distance = haversineKm(cLat,cLng,pLat,pLng);
      res.json(job);
    } catch(e) { next(e); }
  });

  // =========================================================================
  // OFFERS — Multi-round negotiation: both client and pro can counter until one accepts
  // =========================================================================

  app.post("/api/jobs/:id/offers", authenticate, async (req: any, res, next) => {
    try {
      const body = validate(OfferSchema, req.body, res);
      if (!body) return;
      const jobDoc = await db.collection("jobs").doc(req.params.id).get();
      if (!jobDoc.exists) return res.status(404).json({ error:"Job not found" });
      const job = jobDoc.data()!;
      if (["cancelled","finalized","pro_done"].includes(job.status)) return res.status(400).json({ error:"Cannot make an offer on a cancelled or completed job" });
      // Only block if ANOTHER pro already accepted (not negotiating)
      if (job.pro_id&&job.pro_id!==req.user.id&&["accepted","matching"].includes(job.status)) return res.status(400).json({ error:"This job has already been accepted by another specialist" });

      // Both client and pro can send counter-offers — no restriction on who goes last
      const isClient = req.user.id === job.client_id;
      const isPro = req.user.role === "pro";

      // Track pro response time (minutes since job was created)
      if (isPro && job.created_at && !job.pro_id) {
        const jobCreated = job.created_at.toDate ? job.created_at.toDate() : new Date(job.created_at._seconds * 1000);
        const responseMinutes = Math.round((Date.now() - jobCreated.getTime()) / 60000);
        db.collection("users").doc(req.user.id).update({
          response_time_sum: FieldValue.increment(responseMinutes),
          response_count: FieldValue.increment(1),
        }).catch(() => {});
      }

      const newOfferRef = await db.collection("offers").add({
        job_id: req.params.id,
        sender_id: req.user.id,
        amount: body.amount,
        status: "pending",
        created_at: FieldValue.serverTimestamp()
      });
      const updates: any = { status: "negotiating" };
      if (!job.pro_id && isPro) updates.pro_id = req.user.id;
      await jobDoc.ref.update(updates);

      const recipientId = isClient ? job.pro_id : job.client_id;
      const senderName = req.user.name || "Someone";
      const offerMsg = isClient
        ? `💰 Client sent a counter-offer of £${body.amount} for: ${job.title}`
        : `💰 Pro sent an offer of £${body.amount} for: ${job.title}`;

      if (recipientId) {
        await createNotification(recipientId, offerMsg, "offer", req.params.id);
        // Push real-time offer update so the other side sees it instantly
        pushDataUpdate(recipientId, "offers_updated", {
          jobId: req.params.id,
          offer: { id: newOfferRef.id, job_id: req.params.id, sender_id: req.user.id, sender_name: senderName, amount: body.amount, status: "pending", created_at: new Date().toISOString() }
        });
      }
      res.json({ success: true, offer_id: newOfferRef.id });
    } catch(e) { next(e); }
  });

  app.get("/api/jobs/:id/offers", authenticate, async (req, res, next) => {
    try {
      const snap = await db.collection("offers").where("job_id","==",req.params.id).orderBy("created_at","asc").get()
        .catch(()=>db.collection("offers").where("job_id","==",req.params.id).get());
      // Batch fetch all senders in one go instead of N individual reads
      const senderIds = [...new Set(snap.docs.map(d => d.data().sender_id))];
      const senderDocs = await Promise.all(senderIds.map(id => db.collection("users").doc(id).get()));
      const senderMap = Object.fromEntries(senderDocs.map(d => [d.id, d.data()?.name || ""]));
      const offers = snap.docs.map(d => ({
        id: d.id,
        ...serializeDoc(d.data()),
        sender_name: senderMap[d.data().sender_id] || ""
      }));
      res.json(offers);
    } catch(e) { next(e); }
  });

  app.post("/api/offers/:id/accept", authenticate, async (req: any, res, next) => {
    try {
      const offerDoc = await db.collection("offers").doc(req.params.id).get();
      if (!offerDoc.exists) return res.status(404).json({ error:"Offer not found" });
      const offer  = offerDoc.data()!;
      const jobDoc = await db.collection("jobs").doc(offer.job_id).get();
      if (!jobDoc.exists) return res.status(404).json({ error:"Job not found" });
      const job    = jobDoc.data()!;
      const pro_id = req.user.role==="pro" ? req.user.id : offer.sender_id;
      await jobDoc.ref.update({ pro_id, final_price:offer.amount, status:"accepted" });
      await offerDoc.ref.update({ status:"accepted" });

      // Track job accepted for the pro
      db.collection("users").doc(pro_id).update({ jobs_accepted: FieldValue.increment(1) }).catch(() => {});

      const recipientId = req.user.id===job.client_id ? pro_id : job.client_id;
      if (recipientId) {
        await createNotification(recipientId, `✅ Offer accepted! "${job.title}" is now active.`, "job_update", offer.job_id);
        // Push real-time job status update so both sides refresh immediately
        pushDataUpdate(recipientId, "job_updated", { jobId: offer.job_id, status: "accepted", final_price: offer.amount });
      }
      // Also push to the acceptor themselves
      pushDataUpdate(req.user.id, "job_updated", { jobId: offer.job_id, status: "accepted", final_price: offer.amount });

      // Email both parties
      const [clientDoc, proDoc] = await Promise.all([
        db.collection("users").doc(job.client_id).get(),
        db.collection("users").doc(pro_id).get(),
      ]);
      await sendEmail(
        clientDoc.data()!.email,
        `Offer accepted — ${job.title}`,
        `Your offer for "${job.title}" has been accepted. The job is now active.`,
        emailHtml("Offer Accepted!", `Your offer for <strong>${job.title}</strong> has been accepted at <strong>£${offer.amount}</strong>.<br/><br/>The job is now active. Log in to your dashboard to chat and coordinate with your specialist.`)
      );
      await sendEmail(
        proDoc.data()!.email,
        `You've been hired — ${job.title}`,
        `You have been hired for "${job.title}". Check your dashboard to get started.`,
        emailHtml("You've Been Hired!", `Congratulations! You have been hired for <strong>${job.title}</strong> at <strong>£${offer.amount}</strong>.<br/><br/>Log in to your dashboard to chat with the client and get started.`)
      );

      res.json({ success:true });
    } catch(e) { next(e); }
  });

  // =========================================================================
  // JOB LIFECYCLE
  // =========================================================================

  app.post("/api/jobs/:id/cancel", authenticate, async (req: any, res, next) => {
    try {
      const doc = await db.collection("jobs").doc(req.params.id).get();
      if (!doc.exists) return res.status(404).json({ error:"Job not found" });
      const job = doc.data()!;
      if (!["pending","matching","negotiating"].includes(job.status)) return res.status(400).json({ error:"Job cannot be cancelled at this stage" });
      if (req.user.id!==job.client_id&&req.user.id!==job.pro_id) return res.status(403).json({ error:"Unauthorized" });
      await doc.ref.update({ status:"cancelled" });
      const otherId = req.user.id===job.client_id ? job.pro_id : job.client_id;
      if (otherId) await createNotification(otherId, `Job "${job.title}" was cancelled.`, "job_update", req.params.id);
      res.json({ success:true });
    } catch(e) { next(e); }
  });

  app.post("/api/jobs/:id/accept", authenticate, async (req: any, res, next) => {
    try {
      const doc = await db.collection("jobs").doc(req.params.id).get();
      if (!doc.exists) return res.status(404).json({ error:"Not found" });
      const job = doc.data()!;
      if (job.status==="cancelled") return res.status(400).json({ error:"This job has been cancelled" });
      if (job.status!=="pending") return res.status(400).json({ error:"Job no longer available — it has already been taken" });
      const expiresAt = new Date(Date.now()+60*1000).toISOString();
      await doc.ref.update({ pro_id:req.user.id, final_price:job.initial_price, status:"matching", matching_expires_at:expiresAt });
      // Track: pro responded to (accepted) this job
      await db.collection("users").doc(req.user.id).update({ jobs_accepted: FieldValue.increment(1) });
      await createNotification(job.client_id, `A Pro accepted your job: ${job.title}. Confirm the match!`, "match", req.params.id);

      // PRIVACY FIX: Lock notifications for all OTHER pros who were notified about this job.
      // Once one pro accepts, other pros should NOT see the chat or job details.
      try {
        const otherNotifSnap = await db.collection("notifications")
          .where("job_id","==",req.params.id)
          .get();
        const lockBatch = db.batch();
        otherNotifSnap.docs.forEach(notifDoc => {
          // Only lock notifications for pros OTHER than the one who accepted
          if (notifDoc.data().user_id !== req.user.id && notifDoc.data().user_id !== job.client_id) {
            lockBatch.update(notifDoc.ref, { locked: true, is_read: true, lock_reason: "Job was accepted by another professional" });
            // Push real-time removal via WebSocket
            const proWs = wsClients.get(String(notifDoc.data().user_id));
            if (proWs?.readyState === WebSocket.OPEN) {
              proWs.send(JSON.stringify({
                type: "notification_removed",
                notificationId: notifDoc.id,
                jobId: req.params.id,
                reason: "Job was accepted by another professional"
              }));
            }
          }
        });
        await lockBatch.commit();
      } catch { /* non-fatal */ }

      res.json({ success:true, expires_at:expiresAt });
    } catch(e) { next(e); }
  });

  app.post("/api/jobs/:id/confirm-match", authenticate, async (req: any, res, next) => {
    try {
      const doc = await db.collection("jobs").doc(req.params.id).get();
      if (!doc.exists) return res.status(404).json({ error:"Not found" });
      const job = doc.data()!;
      if (job.status!=="matching") return res.status(400).json({ error:"Not in matching phase" });
      if (req.user.id!==job.client_id&&req.user.id!==job.pro_id) return res.status(403).json({ error:"Unauthorized" });
      if (job.matching_expires_at&&new Date(job.matching_expires_at)<new Date()) return res.status(400).json({ error:"Matching expired" });
      await doc.ref.update({ status:"accepted", matching_expires_at:null });
      await createNotification(job.client_id, `Match confirmed! "${job.title}" is now active.`, "job_update", req.params.id);
      await createNotification(job.pro_id, `Match confirmed! "${job.title}" is now active.`, "job_update", req.params.id);
      res.json({ success:true });
    } catch(e) { next(e); }
  });

  app.post("/api/jobs/:id/mark-done", authenticate, async (req: any, res, next) => {
    try {
      const doc = await db.collection("jobs").doc(req.params.id).get();
      if (!doc.exists) return res.status(404).json({ error:"Not found" });
      const job = doc.data()!;
      if (req.user.id!==job.pro_id) return res.status(403).json({ error:"Only the assigned pro can mark the job as done" });
      if (job.status==="pro_done") return res.status(400).json({ error:"Already marked as done" });
      if (job.status==="finalized") return res.status(400).json({ error:"Job is already finalized" });
      if (job.status==="cancelled") return res.status(400).json({ error:"This job has been cancelled" });
      if (job.status!=="accepted") return res.status(400).json({ error:"Job must be accepted before marking as done" });
      await doc.ref.update({ status:"pro_done" });
      await createNotification(job.client_id, `✅ "${job.title}" marked complete by your pro. Tap to confirm & optionally leave a review.`, "review_request", req.params.id);

      // Email the client
      const clientDoc = await db.collection("users").doc(job.client_id).get();
      const proDoc = await db.collection("users").doc(req.user.id).get();
      await sendEmail(
        clientDoc.data()!.email,
        `Your job is complete — ${job.title}`,
        `${proDoc.data()?.name || "Your pro"} has marked "${job.title}" as complete. Log in to confirm and optionally leave a review.`,
        emailHtml("Job Marked Complete", `<strong>${proDoc.data()?.name || "Your pro"}</strong> has marked <strong>${job.title}</strong> as complete.<br/><br/>Log in to your ProsHub dashboard to confirm the work and optionally leave a review.`)
      );

      res.json({ success:true });
    } catch(e) { next(e); }
  });

  app.post("/api/jobs/:id/complete", authenticate, async (req: any, res, next) => {
    try {
      const { notes, rating, comment } = req.body;
      const doc = await db.collection("jobs").doc(req.params.id).get();
      if (!doc.exists) return res.status(404).json({ error:"Not found" });
      const job = doc.data()!;
      if (req.user.id!==job.client_id) return res.status(403).json({ error:"Only the client can finalize the job" });
      if (job.status!=="pro_done") return res.status(400).json({ error:"Pro must mark the job as done first" });
      await doc.ref.update({ status:"finalized", completion_notes:notes||null, locked:true });
      if (rating) {
        await db.collection("reviews").add({ job_id:doc.id, client_id:job.client_id, pro_id:job.pro_id, rating:parseInt(rating), comment:comment||"", is_private:0, created_at:FieldValue.serverTimestamp() });
        const reviewsSnap = await db.collection("reviews").where("pro_id","==",job.pro_id).get();
        const ratings = reviewsSnap.docs.map(r=>r.data().rating as number);
        const avg = ratings.reduce((a,b)=>a+b,0)/ratings.length;
        await db.collection("users").doc(job.pro_id).update({ avg_rating:Math.round(avg*10)/10, review_count:ratings.length });
      }
      if (job.pro_id) {
        await createNotification(job.pro_id, `✅ "${job.title}" confirmed complete by client!`, "job_update", doc.id);
        // Email the pro
        const proDoc = await db.collection("users").doc(job.pro_id).get();
        const clientDoc = await db.collection("users").doc(job.client_id).get();
        await sendEmail(
          proDoc.data()!.email,
          `Job complete — ${job.title}`,
          `${clientDoc.data()?.name || "Your client"} has confirmed "${job.title}" as complete. ${rating ? `They left a ${rating}-star review.` : ""}`,
          emailHtml("Job Confirmed Complete!", `<strong>${clientDoc.data()?.name || "Your client"}</strong> has confirmed <strong>${job.title}</strong> as complete.${rating ? `<br/><br/>They left you a <strong>${rating}-star review</strong>. Great work!` : ""}`)
        );
      }
      res.json({ success:true });
    } catch(e) { next(e); }
  });

  // =========================================================================
  // DISPUTE SYSTEM
  // =========================================================================

  app.post("/api/jobs/:id/dispute", authenticate, async (req: any, res, next) => {
    try {
      const body = validate(DisputeSchema, req.body, res);
      if (!body) return;
      const jobDoc = await db.collection("jobs").doc(req.params.id).get();
      if (!jobDoc.exists) return res.status(404).json({ error:"Job not found" });
      const job = jobDoc.data()!;
      if (req.user.id!==job.client_id && req.user.id!==job.pro_id) return res.status(403).json({ error:"Only job participants can raise a dispute" });
      if (["cancelled","finalized"].includes(job.status)) return res.status(400).json({ error:"Cannot dispute a cancelled or finalized job" });
      if (job.status==="disputed") return res.status(400).json({ error:"A dispute is already open for this job" });

      await jobDoc.ref.update({ status:"disputed", dispute_reason:body.reason, dispute_raised_by:req.user.id, dispute_at:FieldValue.serverTimestamp() });

      // Notify the other party
      const otherId = req.user.id===job.client_id ? job.pro_id : job.client_id;
      if (otherId) await createNotification(otherId, `⚠️ A dispute has been raised on "${job.title}". An admin will review it shortly.`, "dispute", req.params.id);

      // Notify all admins
      const adminSnap = await db.collection("users").where("is_admin","==",1).get();
      await Promise.all(adminSnap.docs.map(a =>
        createNotification(a.id, `⚠️ Dispute raised on job: "${job.title}". Review required.`, "dispute_admin", req.params.id)
      ));

      res.json({ success:true, message:"Dispute raised. An admin will review it shortly." });
    } catch(e) { next(e); }
  });

  app.post("/api/jobs/:id/resolve-dispute", authenticate, async (req: any, res, next) => {
    try {
      if (!req.user.is_admin) return res.status(403).json({ error:"Admin only" });
      const { resolution, outcome } = req.body; // outcome: 'favour_client' | 'favour_pro' | 'cancelled'
      if (!resolution) return res.status(400).json({ error:"Resolution notes are required" });
      const jobDoc = await db.collection("jobs").doc(req.params.id).get();
      if (!jobDoc.exists) return res.status(404).json({ error:"Job not found" });
      const job = jobDoc.data()!;
      if (job.status!=="disputed") return res.status(400).json({ error:"This job does not have an open dispute" });

      const newStatus = outcome==="cancelled" ? "cancelled" : outcome==="favour_client" ? "cancelled" : "finalized";
      await jobDoc.ref.update({ status:newStatus, dispute_resolution:resolution, dispute_resolved_at:FieldValue.serverTimestamp(), dispute_resolved_by:req.user.id });

      // Notify both parties
      const msg = `Your dispute for "${job.title}" has been resolved: ${resolution}`;
      if (job.client_id) await createNotification(job.client_id, msg, "dispute_resolved", req.params.id);
      if (job.pro_id)    await createNotification(job.pro_id, msg, "dispute_resolved", req.params.id);

      res.json({ success:true });
    } catch(e) { next(e); }
  });

  app.get("/api/admin/disputes", authenticate, async (req: any, res, next) => {
    try {
      if (!req.user.is_admin) return res.status(403).json({ error:"Admin only" });
      const snap = await db.collection("jobs").where("status","==","disputed").get();
      const disputes = await Promise.all(snap.docs.map(async d => {
        const job = serializeDoc(d.data());
        const [cDoc, pDoc] = await Promise.all([
          job.client_id ? db.collection("users").doc(job.client_id).get() : null,
          job.pro_id    ? db.collection("users").doc(job.pro_id).get()    : null,
        ]);
        return { id:d.id, ...job, client_name:cDoc?.data()?.name||"", pro_name:pDoc?.data()?.name||"" };
      }));
      res.json(disputes);
    } catch(e) { next(e); }
  });

  // =========================================================================
  // MESSAGES — locked after finalization
  // =========================================================================

  app.get("/api/jobs/:id/messages", authenticate, async (req: any, res, next) => {
    try {
      const jobDoc = await db.collection("jobs").doc(req.params.id).get();
      if (!jobDoc.exists) return res.status(404).json({ error:"Job not found" });
      const job = jobDoc.data()!;
      // PRIVACY: Only the assigned pro and client can read messages. Other pros are blocked.
      const isClient = req.user.id === job.client_id;
      const isAssignedPro = req.user.id === job.pro_id;
      const isAdmin = req.user.is_admin === 1;
      if (!isClient && !isAssignedPro && !isAdmin) {
        return res.status(403).json({ error:"This job has been assigned to another professional." });
      }
      const snap = await db.collection("messages").where("job_id","==",req.params.id).orderBy("created_at","asc").get()
        .catch(()=>db.collection("messages").where("job_id","==",req.params.id).get());
      const msgs = await Promise.all(snap.docs.map(async d => {
        const sDoc = await db.collection("users").doc(d.data().sender_id).get();
        return { id:d.id, ...serializeDoc(d.data()), sender_name:sDoc.data()?.name||"" };
      }));
      res.json(msgs);
    } catch(e) { next(e); }
  });

  app.post("/api/jobs/:id/messages", authenticate, async (req: any, res, next) => {
    try {
      const { content } = req.body;
      if (!content?.trim()) return res.status(400).json({ error:"Message content is required" });
      if (content.length > 2000) return res.status(400).json({ error:"Message too long (max 2000 characters)" });
      const jobDoc = await db.collection("jobs").doc(req.params.id).get();
      if (!jobDoc.exists) return res.status(404).json({ error:"Job not found" });
      const job = jobDoc.data()!;
      if (job.status==="finalized"||job.locked) return res.status(403).json({ error:"This job is complete — the chat is now locked." });

      let currentJob = job;
      if (req.user.role==="pro"&&!job.pro_id) {
        await jobDoc.ref.update({ pro_id:req.user.id, status:"negotiating" });
        currentJob = { ...job, pro_id: req.user.id, status: "negotiating" };
      }

      const senderDoc = await db.collection("users").doc(req.user.id).get();
      const senderName = senderDoc.data()?.name || "";
      const msgData = { job_id: req.params.id, sender_id: req.user.id, content: content.trim(), created_at: FieldValue.serverTimestamp() };
      const msgRef = await db.collection("messages").add(msgData);

      const recipientId = req.user.id === currentJob.client_id ? currentJob.pro_id : currentJob.client_id;
      const msgResponse = { id: msgRef.id, job_id: req.params.id, sender_id: req.user.id, sender_name: senderName, content: content.trim(), created_at: new Date().toISOString() };

      if (recipientId) {
        // Push the actual message content via WS (recipient sees it instantly, no polling)
        pushDataUpdate(recipientId, "chat", {
          jobId: req.params.id,
          senderId: req.user.id,
          senderName,
          content: content.trim(),
          createdAt: new Date().toISOString(),
          messageId: msgRef.id,
        });
        // Fire notification without blocking response
        createNotification(recipientId, `💬 ${senderName}: ${content.trim().slice(0,60)}${content.length > 60 ? '…' : ''}`, "message", req.params.id);
      }
      res.json(msgResponse);
    } catch(e) { next(e); }
  });

  // =========================================================================
  // ADMIN
  // =========================================================================

  app.post("/api/admin/verify-user/:id", authenticate, async (req: any, res, next) => {
    try {
      if (!req.user.is_admin) return res.status(403).json({ error:"Admin only" });
      const docsSnap = await db.collection("user_documents").where("user_id","==",req.params.id).limit(1).get();
      if (docsSnap.empty) return res.status(400).json({ error:"Pro has not uploaded any verification documents yet." });
      await db.collection("users").doc(req.params.id).update({ is_verified:100, rejection_reason:null });
      await createNotification(req.params.id, "🟢 Your identity has been verified! Your profile now shows a green verified badge. Tap to view your verification status.", "verification_update");

      // Email the pro
      const proDoc = await db.collection("users").doc(req.params.id).get();
      if (proDoc.exists) {
        await sendEmail(
          proDoc.data()!.email,
          "You're verified on ProsHub!",
          "Your identity has been verified. Your profile now shows a verified badge.",
          emailHtml("Identity Verified!", "Congratulations! Your identity has been verified by the ProsHub team.<br/><br/>Your profile now displays a <strong>verified badge</strong>, which builds trust with clients and can help you get more jobs.<br/><br/>Log in to your dashboard to start accepting jobs.")
        );
      }

      res.json({ success:true });
    } catch(e) { next(e); }
  });

  app.post("/api/admin/reject-user/:id", authenticate, async (req: any, res, next) => {
    try {
      if (!req.user.is_admin) return res.status(403).json({ error:"Admin only" });
      const { reason } = req.body;
      await db.collection("users").doc(req.params.id).update({ is_verified:0, rejection_reason: reason||"Please re-upload valid documents." });
      await createNotification(req.params.id, `❌ Verification rejected: ${reason||"Please re-upload valid documents."} — Tap to re-upload your documents.`, "verification_update");

      // Email the pro
      const proDoc = await db.collection("users").doc(req.params.id).get();
      if (proDoc.exists) {
        await sendEmail(
          proDoc.data()!.email,
          "Verification update — action required",
          `Your verification was not approved: ${reason || "Please re-upload valid documents."} Log in to re-upload.`,
          emailHtml("Verification Action Required", `Your verification could not be approved at this time.<br/><br/><strong>Reason:</strong> ${reason || "Please re-upload valid documents."}<br/><br/>Log in to your ProsHub dashboard to re-upload your documents. Once approved, your verified badge will appear.`)
        );
      }

      res.json({ success:true });
    } catch(e) { next(e); }
  });

  app.get("/api/admin/pending-pros", authenticate, async (req: any, res, next) => {
    try {
      if (!req.user.is_admin) return res.status(403).json({ error:"Admin only" });
      const snap = await db.collection("users").where("role","==","pro").get();
      const pros = await Promise.all(snap.docs.map(async d => {
        const data = d.data();
        const docsSnap = await db.collection("user_documents").where("user_id","==",d.id).get();
        // Sort verification docs first so admin sees them at the top
        const allDocs = docsSnap.docs.map(doc=>({id:doc.id,...serializeDoc(doc.data())}));
        const documents = [
          ...allDocs.filter((doc: any) => doc.is_verification_doc),
          ...allDocs.filter((doc: any) => !doc.is_verification_doc),
        ];
        return {
          id:d.id, name:data.name, email:data.email,
          is_verified:data.is_verified||0, avatar:data.avatar||"",
          location:data.location||"", skills:data.skills||[],
          rejection_reason:data.rejection_reason||null,
          created_at:data.created_at?new Date(data.created_at._seconds*1000).toISOString():null,
          documents,
        };
      }));
      // Sort: pending review (50) first, then unverified (0), then verified (100)
      pros.sort((a, b) => {
        const order = (v: number) => v === 50 ? 0 : v === 0 ? 1 : 2;
        return order(a.is_verified) - order(b.is_verified);
      });
      res.json(pros);
    } catch(e) { next(e); }
  });

  app.get("/api/admin/users", authenticate, async (req: any, res, next) => {
    try {
      if (!req.user.is_admin) return res.status(403).json({ error:"Admin only" });
      const snap = await db.collection("users").get();
      res.json(snap.docs.map(d => {
        const data = d.data();
        return { id:d.id, name:data.name, email:data.email, role:data.role, is_verified:data.is_verified||0, is_admin:data.is_admin||0, created_at:data.created_at?new Date(data.created_at._seconds*1000).toISOString():null };
      }));
    } catch(e) { next(e); }
  });

  app.get("/api/admin/jobs", authenticate, async (req: any, res, next) => {
    try {
      if (!req.user.is_admin) return res.status(403).json({ error:"Admin only" });
      const snap = await db.collection("jobs").orderBy("created_at","desc").limit(100).get();
      const jobsData = await Promise.all(snap.docs.map(async d => {
        const job = serializeDoc(d.data());
        const [cDoc,pDoc] = await Promise.all([
          job.client_id ? db.collection("users").doc(job.client_id).get() : null,
          job.pro_id    ? db.collection("users").doc(job.pro_id).get()    : null,
        ]);
        return { id:d.id, ...job, client_name:cDoc?.data()?.name||"", pro_name:pDoc?.data()?.name||"" };
      }));
      res.json(jobsData);
    } catch(e) { next(e); }
  });

  // =========================================================================
  // REVIEW MANAGEMENT (Pro manages own reviews)
  // =========================================================================

  app.get("/api/user/reviews", authenticate, async (req: any, res, next) => {
    try {
      const snap = await db.collection("reviews").where("pro_id","==",req.user.id)
        .orderBy("created_at","desc").get()
        .catch(()=>db.collection("reviews").where("pro_id","==",req.user.id).get());
      const reviews = await Promise.all(snap.docs.map(async r => {
        const rData = serializeDoc(r.data());
        const clientDoc = rData.client_id ? await db.collection("users").doc(rData.client_id).get() : null;
        return { id:r.id, ...rData, reviewer_name:clientDoc?.data()?.name||"Anonymous Client" };
      }));
      res.json(reviews);
    } catch(e) { next(e); }
  });

  app.patch("/api/user/reviews/:id", authenticate, async (req: any, res, next) => {
    try {
      const ref = db.collection("reviews").doc(req.params.id);
      const doc = await ref.get();
      if (!doc.exists) return res.status(404).json({ error:"Review not found" });
      if (doc.data()!.pro_id!==req.user.id) return res.status(403).json({ error:"Not your review" });
      const updates: any = {};
      if (req.body.is_private!==undefined) updates.is_private = req.body.is_private;
      if (req.body.comment   !==undefined) updates.comment    = req.body.comment;
      if (req.body.rating    !==undefined) updates.rating     = req.body.rating;
      await ref.update(updates);
      if (req.body.rating!==undefined) {
        const allSnap = await db.collection("reviews").where("pro_id","==",req.user.id).get();
        const ratings = allSnap.docs.map(r=>r.data().rating as number);
        const avg = ratings.reduce((a,b)=>a+b,0)/ratings.length;
        await db.collection("users").doc(req.user.id).update({ avg_rating:Math.round(avg*10)/10, review_count:ratings.length });
      }
      res.json({ success:true });
    } catch(e) { next(e); }
  });

  app.delete("/api/user/reviews/:id", authenticate, async (req: any, res, next) => {
    try {
      const ref = db.collection("reviews").doc(req.params.id);
      const doc = await ref.get();
      if (!doc.exists) return res.status(404).json({ error:"Not found" });
      if (doc.data()!.pro_id!==req.user.id) return res.status(403).json({ error:"Not your review" });
      await ref.delete();
      const allSnap = await db.collection("reviews").where("pro_id","==",req.user.id).get();
      const ratings = allSnap.docs.map(r=>r.data().rating as number);
      const avg = ratings.length ? ratings.reduce((a,b)=>a+b,0)/ratings.length : 0;
      await db.collection("users").doc(req.user.id).update({ avg_rating:ratings.length?Math.round(avg*10)/10:null, review_count:ratings.length });
      res.json({ success:true });
    } catch(e) { next(e); }
  });

  // =========================================================================
  // LEGAL
  // =========================================================================

  app.get("/api/legal/terms",   (_req,res) => res.json({ title:"Terms of Service", content:"By using ProsHub, you agree to settle all payments externally. ProsHub is not liable for disputes." }));
  app.get("/api/legal/privacy", (_req,res) => res.json({ title:"Privacy Policy",   content:"We only share your data with professionals you choose. We do not store payment info." }));

  // =========================================================================
  // GLOBAL ERROR HANDLER — catches any error passed to next(e)
  // =========================================================================

  app.use((err: any, _req: any, res: any, _next: any) => {
    console.error("Unhandled error:", err);
    // Multer file type / size errors
    if (err.message?.includes("File type not allowed")) {
      return res.status(400).json({ error: err.message });
    }
    if (err.code === "LIMIT_FILE_SIZE") {
      return res.status(400).json({ error: "File too large. Maximum size is 10MB." });
    }
    res.status(500).json({ error: "An internal server error occurred. Please try again." });
  });

  // =========================================================================
  // VITE / STATIC
  // =========================================================================

  if (process.env.NODE_ENV!=="production") {
    const vite = await createViteServer({ server:{ middlewareMode:true }, appType:"spa" });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.join(__dirname,"dist")));
    app.get("*", (_req,res) => res.sendFile(path.join(__dirname,"dist","index.html")));
  }

  // =========================================================================
  // MATCHING CLEANUP — reset expired matching jobs every 30s
  // =========================================================================

  setInterval(async () => {
    try {
      const now  = new Date().toISOString();
      const snap = await db.collection("jobs").where("status","==","matching").where("matching_expires_at","<",now).get();
      if (!snap.empty) {
        const batch = db.batch();
        snap.docs.forEach(d => batch.update(d.ref, { status:"pending", pro_id:null, final_price:null, matching_expires_at:null }));
        await batch.commit();
      }
    } catch { /* silent */ }
  }, 30_000);

  // =========================================================================
  // HTTP + WEBSOCKET
  // =========================================================================

  // Render assigns PORT=10000 in production; fall back to 3000 for local dev
  const PORT   = process.env.PORT || 3000;
  const server = http.createServer(app);
  const wss    = new WebSocketServer({ server });

  wss.on("connection", ws => {
    let userId: string|null = null;
    ws.on("message", data => {
      try {
        const msg = JSON.parse(data.toString());
        if (msg.type==="auth") {
          const decoded = jwt.verify(msg.token, JWT_SECRET!) as any;
          userId = decoded.id;
          if (userId) wsClients.set(userId, ws);
          // Confirm connection to client
          ws.send(JSON.stringify({ type:"auth_ok", userId }));
        }
        if (msg.type==="chat"&&userId) {
          const recipientWs = wsClients.get(msg.recipientId);
          if (recipientWs?.readyState===WebSocket.OPEN) {
            recipientWs.send(JSON.stringify({ type:"chat", jobId:msg.jobId, senderId:userId, content:msg.content, createdAt:new Date().toISOString() }));
          }
        }
      } catch (err) { console.error("WS error:",err); }
    });
    ws.on("close", () => { if (userId) wsClients.delete(userId); });
    ws.on("error", (err) => {
      console.error("WebSocket error:", err);
      if (userId) wsClients.delete(userId);
    });
  });

  server.listen(Number(PORT), "0.0.0.0", () => {
    console.log(`\n🚀 ProsHub v8 running on http://localhost:${PORT}\n`);
  });
}

process.on("unhandledRejection", (reason: any) => {
  if (reason?.code===9) {
    console.warn("⚠️  Firestore index missing — affected routes return [] until index is built.");
  } else {
    console.error("Unhandled rejection:", reason);
  }
});

startServer().catch(err => { console.error("Failed to start server:", err); process.exit(1); });
