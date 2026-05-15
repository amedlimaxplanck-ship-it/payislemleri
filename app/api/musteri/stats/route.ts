import { NextResponse } from 'next/server';
import { adminAuth, adminDb } from '@/lib/firebase-admin';

export const dynamic = 'force-dynamic';

export async function GET(request: Request) {
    try {
        const token = request.headers.get('Authorization')?.split('Bearer ')[1];
        if (!token) return NextResponse.json({ status: 'error', message: 'No token' }, { status: 401 });

        const decodedToken = await adminAuth.verifyIdToken(token);
        
        const [ilanlarSnap, logsSnap] = await Promise.all([
            adminDb.collection('ilanlar').where('olusturanMusteri', '==', decodedToken.uid).get(),
            adminDb.collection('logs').where('saticiId', '==', decodedToken.uid).get()
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
