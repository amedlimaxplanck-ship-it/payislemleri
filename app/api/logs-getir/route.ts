import { NextResponse } from 'next/server';
import { adminAuth, adminDb } from '@/lib/firebase-admin';

export const dynamic = 'force-dynamic';

export async function GET(request: Request) {
    try {
        const token = request.headers.get('Authorization')?.split('Bearer ')[1];
        if (!token) return NextResponse.json({ status: 'error', message: 'No token' }, { status: 401 });

        const decodedToken = await adminAuth.verifyIdToken(token);
        const { searchParams } = new URL(request.url);
        const targetUserId = searchParams.get('userId');

        let query: any = adminDb.collection('logs');

        if (decodedToken.role === 'customer') {
            // Customers only see their own logs
            query = query.where('saticiId', '==', decodedToken.uid);
        } else if (decodedToken.role === 'god') {
            // God can filter by userId or see all
            if (targetUserId) {
                query = query.where('saticiId', '==', targetUserId);
            }
        } else {
            return NextResponse.json({ status: 'error', message: 'Unauthorized' }, { status: 403 });
        }

        const snap = await query.orderBy('createdAt', 'desc').limit(100).get();
        return NextResponse.json(snap.docs.map((doc: any) => ({ docId: doc.id, ...doc.data() })));
    } catch (error: any) {
        return NextResponse.json({ status: 'error', message: error.message }, { status: 500 });
    }
}
