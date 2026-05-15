import { NextResponse } from 'next/server';
import { adminDb } from '@/lib/firebase-admin';
import { verifyToken } from '@/lib/auth';
import { cookies } from 'next/headers';

async function verifyGod(request: Request) {
    const cookieStore = await cookies();
    const token = request.headers.get('Authorization')?.split('Bearer ')[1] || cookieStore.get('token')?.value;
    if (!token) return null;
    try {
        const decodedToken = await verifyToken(token);
        return decodedToken?.role === 'god' ? decodedToken : null;
    } catch { return null; }
}

export async function POST(request: Request) {
    const god = await verifyGod(request);
    if (!god) return NextResponse.json({ status: 'error', message: 'Unauthorized' }, { status: 403 });

    const { kilitDurumu } = await request.json();
    await adminDb.collection('ayarlar').doc('sistem').set({ kilitDurumu }, { merge: true });
    return NextResponse.json({ success: true });
}
