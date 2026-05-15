import { NextResponse } from 'next/server';
import { adminDb } from '@/lib/firebase-admin';

export const dynamic = 'force-dynamic';

export async function GET() {
    try {
        const snapshot = await adminDb.collection('users').get();
        const users = snapshot.docs.map(doc => ({ docId: doc.id, ...doc.data() }));
        return NextResponse.json(users);
    } catch (error) {
        console.error("[USERS-ADMIN] GET Hata:", error);
        return NextResponse.json({ hata: "Müşteriler getirilemedi" }, { status: 500 });
    }
}

export async function POST(request: Request) {
    try {
        const body = await request.json();
        const docRef = await adminDb.collection('users').add({
            ...body,
            createdAt: new Date().getTime(),
            isActive: true,
            isBanned: false,
            isSoftBanned: false,
            recentIps: [],
            isSuspicious: false,
            currentSession: null,
            ilanKotasi: body.ilanKotasi || "sinirsiz"
        });
        return NextResponse.json({ success: true, id: docRef.id });
    } catch (error) {
        console.error("[USERS-ADMIN] POST Hata:", error);
        return NextResponse.json({ hata: "Ekleme başarısız" }, { status: 500 });
    }
}
