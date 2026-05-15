import { NextResponse } from 'next/server';
import { adminAuth, adminDb } from '@/lib/firebase-admin';

export async function POST(request: Request) {
    try {
        const token = request.headers.get('Authorization')?.split('Bearer ')[1];
        if (!token) return NextResponse.json({ status: 'error', message: 'No token' }, { status: 401 });

        const decodedToken = await adminAuth.verifyIdToken(token);
        const ilanData = await request.json();

        // Add creator ID
        ilanData.olusturanMusteri = decodedToken.uid;
        ilanData.createdAt = Date.now();
        ilanData.durum = ilanData.durum || 'aktif';

        const docRef = await adminDb.collection('ilanlar').add(ilanData);

        return NextResponse.json({ success: true, docId: docRef.id });
    } catch (error: any) {
        return NextResponse.json({ status: 'error', message: error.message }, { status: 500 });
    }
}
