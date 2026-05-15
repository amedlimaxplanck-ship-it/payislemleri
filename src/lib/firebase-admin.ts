import * as admin from 'firebase-admin';

// Vercel'deki tırnak ve \n sorunlarını temizleyen temizlik fonksiyonu
const formatKey = (key: string | undefined) => {
    if (!key) return undefined;
    return key.replace(/^"|"$/g, '').replace(/\\n/g, '\n');
};

const serviceAccount = {
    projectId: process.env.FIREBASE_PROJECT_ID,
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    privateKey: formatKey(process.env.FIREBASE_PRIVATE_KEY),
};

// Sadece anahtarlar varsa başlat, yoksa build'i bozma
if (!admin.apps.length && serviceAccount.projectId && serviceAccount.privateKey && serviceAccount.clientEmail) {
    try {
        admin.initializeApp({
            credential: admin.credential.cert(serviceAccount as any),
        });
        console.log("[FIREBASE-ADMIN] Başarıyla başlatıldı.");
    } catch (error) {
        // Bu hata artık global bir değişkene yazılsın ki diag görebilsin
        (global as any).firebaseAdminError = (error as Error).message;
        console.error("[FIREBASE-ADMIN] Başlatma hatası:", error);
    }
}

export const adminDb = admin.apps.length ? admin.firestore() : null as any;
export const adminAuth = admin.apps.length ? admin.auth() : null as any;
