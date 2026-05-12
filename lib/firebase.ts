import { initializeApp, getApps, getApp } from 'firebase/app';
import { getFirestore } from 'firebase/firestore';

const firebaseConfig = {
    apiKey: process.env.FIREBASE_API_KEY,
    authDomain: process.env.FIREBASE_AUTH_DOMAIN,
    projectId: process.env.FIREBASE_PROJECT_ID,
    storageBucket: process.env.FIREBASE_STORAGE_BUCKET,
    messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID,
    appId: process.env.FIREBASE_APP_ID
};

// Singleton pattern to prevent multiple initializations
let app;
try {
    app = getApps().length > 0 ? getApp() : initializeApp(firebaseConfig);
} catch (error) {
    console.error("Firebase init error:", error);
    // Provide a dummy app or let it fail gracefully
    app = getApps().length > 0 ? getApp() : null;
}

const db = app ? getFirestore(app) : null;

export { db };
