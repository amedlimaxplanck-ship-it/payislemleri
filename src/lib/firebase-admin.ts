import * as admin from 'firebase-admin';

const serviceAccount = {
    projectId: process.env.FIREBASE_PROJECT_ID,
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    privateKey: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
};

// Sadece anahtarlar varsa başlat, yoksa build'i bozma
if (!admin.apps.length && serviceAccount.projectId && serviceAccount.privateKey) {
    try {
        admin.initializeApp({
            credential: admin.credential.cert(serviceAccount as any),
        });
        console.log("[FIREBASE-ADMIN] Başarıyla başlatıldı.");
    } catch (error) {
        console.error("[FIREBASE-ADMIN] Başlatma hatası:", error);
    }
}

export const adminDb = admin.apps.length ? admin.firestore() : null as any;
export const adminAuth = admin.apps.length ? admin.auth() : null as any;
