import { NextResponse } from 'next/server';
import { adminDb } from '@/lib/firebase-admin';
import { verifyToken } from '@/lib/auth';
import { cookies } from 'next/headers';

export async function PATCH(request: Request, { params }: { params: { id: string } }) {
    try {
        const cookieStore = await cookies();
        const token = request.headers.get('Authorization')?.split('Bearer ')[1] || cookieStore.get('token')?.value;
        if (!token) return NextResponse.json({ status: 'error', message: 'No token' }, { status: 401 });

        const decodedToken = await verifyToken(token);
        if (!decodedToken) return NextResponse.json({ status: 'error', message: 'Invalid token' }, { status: 401 });

        const ilanId = params.id;
        const body = await request.json();
        
        const ilanDoc = await adminDb.collection('ilanlar').doc(ilanId).get();
        if (!ilanDoc.exists) return NextResponse.json({ status: 'error', message: 'İlan bulunamadı' }, { status: 404 });
        
        const ilanData = ilanDoc.data();
        if (decodedToken.role !== 'god' && ilanData?.olusturanMusteri !== decodedToken.id) {
            return NextResponse.json({ status: 'error', message: 'Yetkisiz işlem' }, { status: 403 });
        }

        await adminDb.collection('ilanlar').doc(ilanId).set(body, { merge: true });
        return NextResponse.json({ success: true });
    } catch (error: any) {
        return NextResponse.json({ status: 'error', message: error.message }, { status: 500 });
    }
}
