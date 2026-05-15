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
        if (!decodedToken) return NextResponse.json({ status: 'error', message: 'Invalid token' }, { status: 401 });

        const { searchParams } = new URL(request.url);
        let userId = searchParams.get('userId');

        if (decodedToken.role !== 'god') {
            userId = decodedToken.id;
        }

        if (!userId) return NextResponse.json({ status: 'error', message: 'UserId gerekli' }, { status: 400 });

        const snap = await adminDb.collection('dekontlar').where('olusturanMusteri', '==', userId).get();
        return NextResponse.json(snap.docs.map(doc => ({ id: doc.id, ...doc.data() })));
    } catch (error: any) {
        return NextResponse.json({ status: 'error', message: error.message }, { status: 500 });
    }
}
