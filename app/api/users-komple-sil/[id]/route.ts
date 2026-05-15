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
        if (!decodedToken || decodedToken.role !== 'god') {
            return NextResponse.json({ status: 'error', message: 'Unauthorized' }, { status: 403 });
        }

        const userId = params.id;
        
        // Delete user
        await adminDb.collection('users').doc(userId).delete();
        
        // Optionally delete associated ilanlar and logs, but the old version might only delete the user
        // For "komple sil", we should probably delete everything.
        const ilanlarSnap = await adminDb.collection('ilanlar').where('olusturanMusteri', '==', userId).get();
        const logsSnap = await adminDb.collection('logs').where('saticiId', '==', userId).get();
        
        const batch = adminDb.batch();
        ilanlarSnap.docs.forEach(doc => batch.delete(doc.ref));
        logsSnap.docs.forEach(doc => batch.delete(doc.ref));
        await batch.commit();

        return NextResponse.json({ success: true });
    } catch (error: any) {
        return NextResponse.json({ status: 'error', message: error.message }, { status: 500 });
    }
}
