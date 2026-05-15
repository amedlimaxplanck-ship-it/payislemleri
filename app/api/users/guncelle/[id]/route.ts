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

        if (decodedToken.role !== 'god' && decodedToken.id !== params.id) {
            return NextResponse.json({ status: 'error', message: 'Unauthorized' }, { status: 403 });
        }

        const updates = await request.json();
        const userRef = adminDb.collection('users').doc(params.id);
        
        await userRef.set(updates, { merge: true });

        return NextResponse.json({ success: true });
    } catch (error: any) {
        return NextResponse.json({ status: 'error', message: error.message }, { status: 500 });
    }
}
