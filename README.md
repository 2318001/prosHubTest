# ProsHub — Professional Skills Marketplace

A full-stack web app connecting clients with verified professionals. Features real-time job matching, WebSocket chat, two-factor login, professional verification, and a scoring-based search algorithm — all backed by Firebase Firestore and served through a single Express + Vite server.

---

## Quick Start (Local Testing)

### 1. Install dependencies
```bash
npm install
```

### 2. Set up Firebase
- Go to [Firebase Console](https://console.firebase.google.com) → Create a project
- Enable **Firestore Database** (Native mode)
- Go to **Project Settings → Service Accounts → Generate new private key**
- Save the downloaded JSON file as `serviceAccount.json` in the project root

### 3. Configure environment
```bash
cp .env.example .env
```
Open `.env` and fill in:
- `JWT_SECRET` — run `openssl rand -hex 32` and paste the result
- `FIREBASE_PROJECT_ID` — your Firebase project ID (e.g. `my-project-123`)
- `FIREBASE_FIRESTORE_DATABASE_ID` — use `(default)` unless you created a named database
- `GOOGLE_APPLICATION_CREDENTIALS` — absolute path to your `serviceAccount.json`
- `ADMIN_EMAIL` — your email address (gets auto-promoted to admin)

**For local testing, SendGrid is optional.** Without it, OTP login codes print to your terminal — copy them from there.

### 4. Run locally
```bash
npm run dev
```
Open [http://localhost:3000](http://localhost:3000)

### 5. Register your first account
- Register with the email you set as `ADMIN_EMAIL`
- Check your terminal for the OTP code (if no SendGrid)
- You are now an admin and can verify professionals

---

## Production Deployment

### Build
```bash
npm run build   # compiles React → /dist
npm start       # runs Express + dist on PORT
```

### Required for production
| Thing | What to do |
|---|---|
| `ALLOWED_ORIGIN` | Set to your public domain, e.g. `https://proshub.com` |
| `NODE_ENV` | Set to `production` in your host's env config |
| HTTPS / TLS | Use Caddy, nginx, or your host's built-in HTTPS in front of the Node process |
| Firebase credentials | On GCP (Cloud Run etc.) ADC works automatically — no `GOOGLE_APPLICATION_CREDENTIALS` needed |
| File uploads | Stored locally in `/uploads/` — not persistent on containerised hosts. For production, migrate to Firebase Storage or S3 |
| SendGrid | Required for real users — OTP codes won't reach users without it |

### Deploy Firestore security rules
```bash
npm install -g firebase-tools
firebase login
firebase deploy --only firestore:rules
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React 19, TypeScript, Tailwind CSS v4, Vite 6 |
| Backend | Node.js, Express 4, TypeScript (tsx) |
| Database | Google Cloud Firestore (Firebase Admin SDK) |
| Auth | JWT + bcryptjs + 6-digit email OTP (2FA on every login) |
| Real-time | WebSockets (ws library) |
| Email | SendGrid (optional in dev — falls back to console log) |
| Validation | Zod |
| Security | Helmet, CORS, express-rate-limit |

---

## Environment Variables Reference

| Variable | Required | Description |
|---|---|---|
| `JWT_SECRET` | ✅ | Secret for signing JWTs. Generate: `openssl rand -hex 32` |
| `FIREBASE_PROJECT_ID` | ✅ | Your Firebase project ID |
| `FIREBASE_FIRESTORE_DATABASE_ID` | ✅ | Use `(default)` unless you have a named database |
| `GOOGLE_APPLICATION_CREDENTIALS` | Dev only | Path to service account JSON. Not needed on GCP. |
| `PORT` | — | Server port. Defaults to `3000` |
| `ALLOWED_ORIGIN` | — | CORS allowed origin. Defaults to `http://localhost:3000` |
| `SENDGRID_API_KEY` | Prod | Without this, OTP codes print to terminal only |
| `FROM_EMAIL` | Prod | Sender address for emails |
| `ADMIN_EMAIL` | — | Email of user to auto-promote to admin on startup |
| `VITE_FIREBASE_*` | — | Firebase client SDK config (needed only for direct client-SDK usage) |

---

## Security Model

| Mechanism | Detail |
|---|---|
| Password hashing | bcryptjs, 10 salt rounds |
| Session tokens | JWT, 7-day expiry |
| Two-factor auth | Every login requires a 6-digit OTP |
| Rate limiting | Auth routes: 20 req / 15 min / IP |
| CORS | Restricted to `ALLOWED_ORIGIN` |
| HTTP headers | Helmet (CSP, HSTS, X-Frame-Options) |
| File uploads | JPEG/PNG/PDF only, 5 MB max, served only to authenticated owners |
| Input validation | Zod on every request body |
| Response sanitisation | `sanitizeUser()` strips password, OTP, and expiry from every response |

---

## Known Limitations (Not Blockers)

- **File uploads are local disk** — not persistent on containerised hosts. Migrate to Firebase Storage for production scale.
- **Avatar stored as base64** in Firestore (200 KB UI limit). Replace with Storage URL at scale.
- **Subscription system** is scaffolded (fields exist) but has no payment routes yet — Stripe integration needed.
- **Video calls** send a notification but don't connect a real video SDK (Daily.co / Twilio Video needed).
- **Matching cleanup** uses `setInterval` — replace with Cloud Scheduler for multi-instance reliability.
