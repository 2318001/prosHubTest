// FILE: src/lib/firebase.ts — Initialises Firebase client SDK (Auth, Firestore, Storage) for the browser. Config loaded from VITE_FIREBASE_* env vars.

// =============================================================================
// FILE: src/lib/firebase.ts
// WHAT: Initialises the Firebase client-side SDK for the browser/frontend.
// WHY:  The frontend needs Firebase Auth (for auth state) and Firestore
//       (for reading real-time data if needed in the future).
//       The actual database writes are done securely through our Express
//       server using the Firebase Admin SDK — not directly from the browser.
// HOW:  Config values come from Vite environment variables (VITE_FIREBASE_*).
//       These are safe to expose — they identify which Firebase project to use,
//       but access is controlled by Firestore Security Rules.
// =============================================================================

import { initializeApp } from 'firebase/app';
import { getAuth }       from 'firebase/auth';
import { getFirestore }  from 'firebase/firestore';
import { getStorage }    from 'firebase/storage';

// All values loaded from .env — copy .env.example to .env and fill in your values
const firebaseConfig = {
  apiKey:            import.meta.env.VITE_FIREBASE_API_KEY,
  authDomain:        import.meta.env.VITE_FIREBASE_AUTH_DOMAIN,
  projectId:         import.meta.env.VITE_FIREBASE_PROJECT_ID,
  storageBucket:     import.meta.env.VITE_FIREBASE_STORAGE_BUCKET,
  messagingSenderId: import.meta.env.VITE_FIREBASE_MESSAGING_SENDER_ID,
  appId:             import.meta.env.VITE_FIREBASE_APP_ID,
};

// Initialise the Firebase app — this is a singleton, safe to call at module load
const app = initializeApp(firebaseConfig);

// Export the services we need throughout the frontend
export const auth    = getAuth(app);       // Firebase Authentication
export const db      = getFirestore(app);  // Firestore database (for future real-time features)
export const storage = getStorage(app);    // Firebase Storage (for file uploads)
export default app;
