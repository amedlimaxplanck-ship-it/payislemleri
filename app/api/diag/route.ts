import { NextResponse } from 'next/server';
import { adminDb } from '@/lib/firebase-admin';

export async function GET() {
    try {
        const usersSnap = await adminDb.collection('users').limit(1).get();
        
        return NextResponse.json({ 
            status: "ok", 
            adminSDK: "Connected",
            usersCollection: usersSnap.empty ? "Empty" : "Found Data",
            firstUser: !usersSnap.empty ? { id: usersSnap.docs[0].id, data: usersSnap.docs[0].data() } : null,
            message: "Admin SDK başarıyla test edildi."
        });
    } catch (error) {
        return NextResponse.json({ 
            status: "error", 
            message: (error as Error).message,
            stack: (error as Error).stack
        });
    }
}
