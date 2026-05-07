# ProsHub 🔧

**A full-stack marketplace connecting clients with verified local professionals.**  
Clients post jobs. Pros accept, negotiate, and complete them. Real-time chat. Live GPS distance matching.

> **Version:** v7 (April 2026) — Portfolio media management, live location for clients, subscription-free era, admin doc review, 5-step How It Works.

---

## What's New in v7

| # | Change | Details |
|---|--------|---------|
| 1 | **5th "Review" step in How It Works** | Landing page now shows: Search → Negotiate → Hire → Verified → Review |
| 2 | **Subscription is FREE** | All pro features are free. Future paid plans will be announced in advance. `SubscriptionModalInline` updated accordingly. |
| 3 | **Pros can manage their portfolio** | Portfolio grid now shows View + Delete buttons on hover. Deleting removes the file from disk too. |
| 4 | **Live location for clients** | Search page shows "Live location active — showing real distances" badge when GPS is granted. Distances displayed in green with a navigation icon. |
| 5 | **Admin can view uploaded pro documents** | Documents render inline (images) or in an iframe (PDFs) in the admin dashboard before verify/reject. |
| 6 | **Full comments & formatting pass** | Every file has file-level JSDoc, inline comments on state, routes, and UX decisions. |

---

## Tech Stack

| Layer      | Technology                                                    |
|------------|---------------------------------------------------------------|
| Frontend   | React 19, TypeScript, Tailwind CSS v4, Vite, React Router v7 |
| Backend    | Express.js (TypeScript), WebSockets (`ws`)                    |
| Database   | **Firebase Firestore** (via Firebase Admin SDK)               |
| Auth       | Custom JWT + 2FA email code (via SendGrid)                    |
| Storage    | Local disk (`/uploads`) — swap for Firebase Storage in prod   |
| Email      | SendGrid (console-only in dev if key not set)                 |
| Animation  | Motion (Framer Motion v12)                                    |

---

## Project Structure

```
ProsHub/
├── server.ts                          # Express backend (API + WebSocket + file uploads)
├── firestore.rules                    # Firestore security rules
├── firebase-blueprint.json            # Firestore data schema reference
├── .env.example                       # All required environment variable keys
├── vite.config.ts                     # Vite + Tailwind + dev proxy config
├── public/
│   ├── manifest.json                  # PWA manifest
│   └── sw.js                          # Service worker (offline support)
└── src/
    ├── main.tsx                       # React entry point
    ├── App.tsx                        # Router + ProtectedRoute
    ├── AuthContext.tsx                # Global auth state (Context API)
    ├── Dashboard.tsx                  # Main app shell (all logged-in views + handleDeleteWork)
    ├── Landing.tsx                    # Public marketing page (5-step How It Works)
    ├── Login.tsx                      # Auth page (login / register / 2FA / reset)
    ├── types.ts                       # Shared TypeScript interfaces
    ├── index.css                      # Tailwind + CSS custom properties (design tokens)
    ├── lib/
    │   └── firebase.ts                # Firebase client SDK initialisation
    ├── hooks/
    │   ├── usejobs.ts                 # Job CRUD hook
    │   ├── useMessages.ts             # Real-time chat messages hook
    │   ├── useNotifications.ts        # Notifications polling hook
    │   └── useProfiles.ts             # Profile / docs / portfolio hook
    └── components/
        ├── ErrorBoundary.tsx          # Catches React render errors gracefully
        ├── Auth/
        │   ├── LoginForm.tsx          # Email + password login
        │   ├── RegisterForm.tsx       # Role-select registration
        │   └── VerifyForm.tsx         # 2FA code entry
        └── Dashboard/
            ├── Sidebar.tsx            # Responsive nav sidebar (desktop + mobile sheet)
            ├── Overview.tsx           # Dashboard home cards
            ├── Jobs.tsx               # Job feed / my jobs
            ├── Search.tsx             # Pro search with live GPS distance badges ★
            ├── Profile.tsx            # Pro/client profile — portfolio with keep/delete ★
            ├── Verification.tsx       # Pro ID verification upload flow
            ├── ProProfileModal.tsx    # Full pro profile + distance display
            ├── AdminDashboard.tsx     # Admin verify/reject with inline doc preview ★
            ├── Modals.tsx             # Job chat + Post Job + Add Work + Delete account
            ├── SubscriptionModalInline.tsx  # FREE access modal + future plan notice ★
            └── WithdrawModal.tsx      # Earnings withdrawal flow
```

★ = changed in v7

---

## How It Works (5 Steps)

1. **Search** — Find any micro-skill using our smart search engine
2. **Negotiate** — Chat directly with verified pros, agree on a fair price
3. **Hire** — Both parties confirm before work begins
4. **Verified** — Every pro is identity-checked by an admin
5. **Review** *(NEW)* — After the job, leave a review to help the community

---

## Firestore Collections

| Collection         | Description                                              |
|--------------------|----------------------------------------------------------|
| `users`            | All accounts — clients and professionals (with `location_lat`, `location_lng`) |
| `jobs`             | Job requests (`pending → matching → accepted → finalized`) |
| `offers`           | Price negotiations between client and pro                |
| `messages`         | Chat messages per job                                    |
| `user_documents`   | Pro verification documents (admin reviews these)         |
| `completed_works`  | Portfolio items — images, videos, docs (pro can delete)  |
| `notifications`    | In-app alerts for both roles                             |
| `reviews`          | Client reviews of pros                                   |
| `job_history`      | Completed job archive                                    |

---

## Subscription Policy

**ProsHub is currently FREE for all pros.** No credit card required. All features — search visibility, messaging, portfolio, notifications — are available at no cost.

> A subscription model will be introduced in the future. Pros will receive **advance notice via email and in-app notification** before any charges apply.

The `SubscriptionModalInline` component reflects this: it shows "Activate Free Access" and a notice banner: *"Subscription plans coming soon. You will be notified before any charges apply."*

---

## Portfolio Media Management (Pros)

Pros can **upload images and videos** to their portfolio via the Profile page → "Add Work" button.

On the portfolio grid, hovering any item reveals two action buttons:
- **View** — opens a full-size lightbox (image, video, or PDF/document preview)
- **Delete** — removes the item from the portfolio *and* deletes the file from disk (via `DELETE /api/user/completed-works/:id`)

This gives pros full control over what clients see on their public profile.

---

## Live Location for Clients

When a client searches for pros:

1. The browser requests GPS permission automatically
2. Coordinates are sent to `GET /api/pros/search?lat=...&lng=...`
3. The server computes Haversine distance for every pro who has set `location_lat`/`location_lng`
4. Results show a **green "X km away"** badge with a navigation icon
5. A "Live location active" banner confirms GPS is working

Pros set their GPS location by updating their profile (the app reads `navigator.geolocation` on the profile page and sends `location_lat`/`location_lng` with the profile save request).

---

## Admin Verification Flow

1. Pro uploads ID/documents via Profile → Documents section
2. Admin opens **Admin Dashboard → Verification tab**
3. Each pro card shows all uploaded documents with a **View** button
4. Clicking **View** opens an inline preview:
   - **Images** — displayed full-size in a modal
   - **PDFs** — rendered in an `<iframe>`
   - **Other files** — download link provided
5. Admin must view at least one document before Verify/Reject buttons activate
6. On **Verify** → `is_verified` set to `100`, pro receives a push notification
7. On **Reject** → admin writes a reason, pro receives a notification with the reason and a link to re-upload

---

## API Reference

### Auth
| Method | Endpoint                    | Description                        |
|--------|-----------------------------|------------------------------------|
| POST   | `/api/auth/register`        | Create account, get JWT            |
| POST   | `/api/auth/login`           | Step 1: verify password, send 2FA code |
| POST   | `/api/auth/verify-code`     | Step 2: verify code, get JWT       |
| POST   | `/api/auth/forgot-password` | Send password reset code           |
| POST   | `/api/auth/reset-password`  | Set new password with code         |

### User
| Method | Endpoint                        | Description                                     |
|--------|---------------------------------|-------------------------------------------------|
| GET    | `/api/user/profile`             | Get logged-in user's full profile               |
| PUT    | `/api/user/profile`             | Update profile (name, bio, location, lat/lng)   |
| POST   | `/api/user/avatar`              | Upload avatar image (multipart)                 |
| POST   | `/api/user/availability`        | Toggle available/offline status                 |
| POST   | `/api/user/verify`              | Submit verification docs (legacy text fields)   |
| DELETE | `/api/user/account`             | Permanently delete account + all data           |
| GET    | `/api/user/documents`           | List pro's uploaded documents                   |
| POST   | `/api/user/documents`           | Add document (URL)                              |
| POST   | `/api/user/documents/upload`    | Upload document file (multipart)                |
| DELETE | `/api/user/documents/:id`       | Delete document + file from disk                |
| GET    | `/api/user/completed-works`     | List pro's portfolio items                      |
| POST   | `/api/user/completed-works`     | Add portfolio item (URL)                        |
| DELETE | `/api/user/completed-works/:id` | **Delete portfolio item + file from disk** ★    |
| GET    | `/api/user/reviews`             | Pro's own review list (with visibility control) |
| PATCH  | `/api/user/reviews/:id`         | Edit/toggle visibility of a review              |
| DELETE | `/api/user/reviews/:id`         | Delete a review                                 |
| GET    | `/api/user/subscription`        | Get subscription status                         |

### Search & Pros
| Method | Endpoint                | Description                                          |
|--------|-------------------------|------------------------------------------------------|
| GET    | `/api/pros/search`      | Search pros by keyword + optional `lat`/`lng` for live distance ★ |
| GET    | `/api/pros/:id`         | Get full pro profile (portfolio, reviews, docs)      |
| GET    | `/api/stats/categories` | Top 12 skill categories with pro counts              |

### Portfolio
| Method | Endpoint                     | Description                              |
|--------|------------------------------|------------------------------------------|
| POST   | `/api/pro/portfolio/upload`  | Upload portfolio item (multipart)        |
| POST   | `/api/pro/portfolio`         | Add portfolio item (URL)                 |
| GET    | `/api/pro/:id/portfolio`     | Get public portfolio for a pro           |

### Jobs
| Method | Endpoint                        | Description                               |
|--------|---------------------------------|-------------------------------------------|
| POST   | `/api/jobs`                     | Post a new job                            |
| GET    | `/api/jobs/pending`             | Open job feed for pros (skill-matched)    |
| GET    | `/api/my-jobs`                  | Jobs for the current user                 |
| GET    | `/api/jobs/:id`                 | Single job + distance info                |
| POST   | `/api/jobs/:id/accept`          | Pro accepts job (starts 60s match timer)  |
| POST   | `/api/jobs/:id/confirm-match`   | Confirm the match                         |
| POST   | `/api/jobs/:id/complete`        | Finalize job + leave review               |
| POST   | `/api/jobs/:id/offers`          | Send a price offer                        |
| GET    | `/api/jobs/:id/offers`          | List offers for a job                     |
| POST   | `/api/offers/:id/accept`        | Accept an offer                           |
| GET    | `/api/jobs/:id/messages`        | Get chat history                          |
| POST   | `/api/jobs/:id/messages`        | Send a message                            |

### Admin
| Method | Endpoint                       | Description                                        |
|--------|--------------------------------|----------------------------------------------------|
| GET    | `/api/admin/pending-pros`      | All pros + their uploaded documents ★              |
| POST   | `/api/admin/verify-user/:id`   | Verify a pro (requires at least 1 uploaded doc)    |
| POST   | `/api/admin/reject-user/:id`   | Reject with reason (notifies pro)                  |
| GET    | `/api/admin/users`             | All platform users                                 |
| GET    | `/api/admin/jobs`              | All jobs (last 100)                                |

### Subscriptions
| Method | Endpoint                          | Description                           |
|--------|-----------------------------------|---------------------------------------|
| POST   | `/api/subscription/start-trial`   | Activate free access (trial)          |
| POST   | `/api/subscription/subscribe`     | Activate monthly plan (future)        |
| GET    | `/api/user/subscription`          | Get current subscription status       |

---

## Environment Variables

Copy `.env.example` to `.env` and fill in all values:

```env
# Firebase Admin SDK (from Firebase Console → Service Accounts)
FIREBASE_PROJECT_ID=
FIREBASE_CLIENT_EMAIL=
FIREBASE_PRIVATE_KEY=
FIREBASE_STORAGE_BUCKET=

# Firebase Client SDK (from Firebase Console → Project Settings → Web App)
VITE_FIREBASE_API_KEY=
VITE_FIREBASE_AUTH_DOMAIN=
VITE_FIREBASE_PROJECT_ID=
VITE_FIREBASE_STORAGE_BUCKET=
VITE_FIREBASE_MESSAGING_SENDER_ID=
VITE_FIREBASE_APP_ID=

# Auth
JWT_SECRET=your-long-random-secret-here

# Email (SendGrid — optional in dev, required in prod)
SENDGRID_API_KEY=
FROM_EMAIL=noreply@proshub.com

# Server
PORT=3000
NODE_ENV=development

# Admin account email (auto-granted admin on first registration)
ADMIN_EMAIL=your-admin@email.com
```

---

## Quick Start

```bash
# 1. Install dependencies
npm install

# 2. Copy and fill in environment variables
cp .env.example .env

# 3. Start development server (frontend + backend together)
npm run dev
```

The Vite dev server runs on `http://localhost:5173` and proxies `/api` requests to the Express backend on port `3000`.

---

## Deployment

**Recommended platforms:** Railway, Render, Fly.io

1. Push to GitHub
2. Create a new service pointing to your repo
3. Set all environment variables from `.env.example`
4. Set `NODE_ENV=production`
5. Build command: `npm run build`
6. Start command: `npm run start`

> ⚠️ **Never commit your `.env` file.** It is already in `.gitignore`.

For production, replace local `/uploads` disk storage with **Firebase Storage** or an S3-compatible bucket for persistent file hosting across deployments.

---

## Admin Access

Set `ADMIN_EMAIL` in your `.env`. That email address is automatically granted admin privileges (`is_admin: 1`) on first registration.

Admins can:
- View and preview all pro verification documents
- Verify or reject pros with a custom message
- See all users and all jobs on the platform

---

## Known Limitations / Future Work

- **File storage:** Files are stored on local disk. In production, use Firebase Storage or S3 so uploads survive redeployments.
- **Subscription payments:** Stripe integration is prepared but not wired up yet. Currently all access is free.
- **Map view:** Distance is calculated and shown numerically. A future version could embed a map (Leaflet/Google Maps) for a visual view of nearby pros.
- **Push notifications:** Currently in-app only. Web Push (via service worker) is scaffolded in `public/sw.js`.

---

## Bugs Fixed Across All Versions

| # | Bug | Fix |
|---|-----|-----|
| 1 | Server used SQLite instead of Firebase | Full rewrite to Firebase Admin SDK |
| 2 | Missing npm dependencies | Added `bcryptjs`, `@types/bcryptjs` |
| 3 | `SubscriptionModalInline` not found | Created component |
| 4 | Distance never shown in ProProfileModal | Added Haversine distance badge |
| 5 | Search route shadowed by `:id` param | Moved `/pros/search` above `/pros/:id` |
| 6 | Profile update ignored lat/lng | `PUT /api/user/profile` saves lat/lng |
| 7 | `.env.example` missing Firebase keys | Fully documented |
| 8 | Portfolio items had no delete button | Added View + Delete hover overlay ★ |
| 9 | Subscription modal showed payment prompt | Updated to free-tier messaging ★ |
| 10 | How It Works had only 4 steps | Added 5th "Review" step ★ |
| 11 | Search distance badge had no GPS status | Added "Live location active" indicator ★ |
| 12 | Admin couldn't preview doc before deciding | Inline image/PDF preview added ★ |



---

## License

© 2025 Rajan KC — UCA
