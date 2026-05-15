import { NextResponse } from 'next/server';
import { adminDb } from '@/lib/firebase-admin';
import { verifyToken } from '@/lib/auth';
import { cookies } from 'next/headers';

export async function DELETE(request: Request, { params }: { params: { id: string } }) {
    try {
        const cookieStore = await cookies();
        const token = request.headers.get('Authorization')?.split('Bearer ')[1] || cookieStore.get('token')?.value;
        if (!token) return NextResponse.json({ status: 'error', message: 'No token' }, { status: 401 });

        const decodedToken = await verifyToken(token);
        if (!decodedToken) return NextResponse.json({ status: 'error', message: 'Invalid token' }, { status: 401 });

        const dekontId = params.id;
        const dekontDoc = await adminDb.collection('dekontlar').doc(dekontId).get();
        if (!dekontDoc.exists) return NextResponse.json({ status: 'error', message: 'Dekont bulunamadı' }, { status: 404 });
        
        const dekontData = dekontDoc.data();
        if (decodedToken.role !== 'god' && dekontData?.olusturanMusteri !== decodedToken.id) {
            return NextResponse.json({ status: 'error', message: 'Yetkisiz işlem' }, { status: 403 });
        }

        await adminDb.collection('dekontlar').doc(dekontId).delete();
        return NextResponse.json({ success: true });
    } catch (error: any) {
        return NextResponse.json({ status: 'error', message: error.message }, { status: 500 });
    }
}
