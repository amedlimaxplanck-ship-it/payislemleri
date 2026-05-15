import { NextResponse } from 'next/server';
import * as admin from 'firebase-admin';

export const dynamic = 'force-dynamic';

export async function GET() {
    return NextResponse.json({ 
        status: "check",
        env_check: {
            projectId: process.env.FIREBASE_PROJECT_ID ? "Var" : "YOK",
            clientEmail: process.env.FIREBASE_CLIENT_EMAIL ? "Var" : "YOK",
            privateKey: process.env.FIREBASE_PRIVATE_KEY ? "Var" : "YOK",
        },
        admin_initialized: admin.apps.length > 0 ? "YES" : "NO",
        message: "Eğer 'YOK' yazan varsa Vercel'deki ismiyle koddaki isim uyuşmuyor demektir."
    });
}
