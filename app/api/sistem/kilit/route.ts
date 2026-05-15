import { NextResponse } from 'next/server';
import { adminAuth, adminFirestore } from '@/lib/firebase-admin';

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
    await adminFirestore.collection('ayarlar').doc('sistem').set({ kilitDurumu }, { merge: true });
    return NextResponse.json({ success: true });
}
