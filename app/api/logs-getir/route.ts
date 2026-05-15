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
        const targetUserId = searchParams.get('userId');

        let query: any = adminDb.collection('logs');

        if (decodedToken.role === 'customer') {
            // Customers only see their own logs
            query = query.where('saticiId', '==', decodedToken.id);
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
