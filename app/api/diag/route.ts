import { NextResponse } from 'next/server';
import * as admin from 'firebase-admin';

export const dynamic = 'force-dynamic';

export async function GET() {
    return NextResponse.json({ 
        status: "check",
        env_check: {
            projectId: process.env.FIREBASE_PROJECT_ID ? "OK" : "MISSING",
            clientEmail: process.env.FIREBASE_CLIENT_EMAIL ? "OK" : "MISSING",
            privateKey: process.env.FIREBASE_PRIVATE_KEY ? `OK (${process.env.FIREBASE_PRIVATE_KEY.length} char)` : "MISSING",
        },
        admin_initialized: admin.apps.length > 0 ? "YES" : "NO",
        error_log: (global as any).firebaseAdminError || "No Error Logged",
        message: "Eğer NO yazıyorsa yukarıdaki error_log her şeyi açıklar."
    });
}
