import { NextResponse } from 'next/server';
import { adminDb } from '@/lib/firebase-admin';
import { verifyToken } from '@/lib/auth';
import { cookies } from 'next/headers';

export const dynamic = 'force-dynamic';

export async function GET(request: Request) {
    try {
        const cookieStore = await cookies();
        const token = request.headers.get('Authorization')?.split('Bearer ')[1] || cookieStore.get('token')?.value;
        if (!token) return NextResponse.json({ status: 'error', message: 'No token' }, { status: 401 });

        const decodedToken = await verifyToken(token);
        if (!decodedToken || decodedToken.role !== 'god') {
            return NextResponse.json({ status: 'error', message: 'Unauthorized' }, { status: 403 });
        }

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
        const cookieStore = await cookies();
        const token = request.headers.get('Authorization')?.split('Bearer ')[1] || cookieStore.get('token')?.value;
        if (!token) return NextResponse.json({ status: 'error', message: 'No token' }, { status: 401 });

        const decodedToken = await verifyToken(token);
        if (!decodedToken || decodedToken.role !== 'god') {
            return NextResponse.json({ status: 'error', message: 'Unauthorized' }, { status: 403 });
        }

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
            ilanKotasi: body.ilanKotasi || "sinirsiz",
            role: 'customer'
        });
        return NextResponse.json({ success: true, id: docRef.id });
    } catch (error) {
        console.error("[USERS-ADMIN] POST Hata:", error);
        return NextResponse.json({ hata: "Ekleme başarısız" }, { status: 500 });
    }
}
