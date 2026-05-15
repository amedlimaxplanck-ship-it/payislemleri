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
        
        const [ilanlarSnap, logsSnap] = await Promise.all([
            adminDb.collection('ilanlar').where('olusturanMusteri', '==', decodedToken.id).get(),
            adminDb.collection('logs').where('saticiId', '==', decodedToken.id).get()
        ]);

        const stats = {
            ilan: ilanlarSnap.size,
            log: logsSnap.size,
            dekont: logsSnap.docs.filter(doc => doc.data().aksiyon?.includes('Dekont')).length
        };

        return NextResponse.json(stats);
    } catch (error: any) {
        return NextResponse.json({ status: 'error', message: error.message }, { status: 500 });
    }
}
