import { NextResponse } from 'next/server';
import { adminDb } from '@/lib/firebase-admin';
import { verifyToken } from '@/lib/auth';
import { cookies } from 'next/headers';

export async function POST(request: Request) {
    try {
        const cookieStore = await cookies();
        const token = request.headers.get('Authorization')?.split('Bearer ')[1] || cookieStore.get('token')?.value;
        if (!token) return NextResponse.json({ status: 'error', message: 'No token' }, { status: 401 });

        const decodedToken = await verifyToken(token);
        if (!decodedToken) return NextResponse.json({ status: 'error', message: 'Invalid token' }, { status: 401 });
        
        const ilanData = await request.json();

        // Add creator ID
        ilanData.olusturanMusteri = decodedToken.id;
        ilanData.createdAt = Date.now();
        ilanData.durum = ilanData.durum || 'aktif';

        const docRef = await adminDb.collection('ilanlar').add(ilanData);

        return NextResponse.json({ success: true, docId: docRef.id });
    } catch (error: any) {
        return NextResponse.json({ status: 'error', message: error.message }, { status: 500 });
    }
}
