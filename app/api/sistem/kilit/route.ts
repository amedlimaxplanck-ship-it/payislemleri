import { NextResponse } from 'next/server';
import { adminAuth, adminDb } from '@/lib/firebase-admin';

async function verifyGod(request: Request) {
    const token = request.headers.get('Authorization')?.split('Bearer ')[1];
    if (!token) return null;
    try {
        const decodedToken = await adminAuth.verifyIdToken(token);
        return decodedToken.role === 'god' ? decodedToken : null;
    } catch { return null; }
}

export async function POST(request: Request) {
    const god = await verifyGod(request);
    if (!god) return NextResponse.json({ status: 'error', message: 'Unauthorized' }, { status: 403 });

    const { kilitDurumu } = await request.json();
    await adminDb.collection('ayarlar').doc('sistem').set({ kilitDurumu }, { merge: true });
    return NextResponse.json({ success: true });
}
