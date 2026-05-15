import { NextResponse } from 'next/server';
import { adminAuth, adminFirestore } from '@/lib/firebase-admin';

export async function PATCH(request: Request, { params }: { params: { id: string } }) {
    try {
        const token = request.headers.get('Authorization')?.split('Bearer ')[1];
        if (!token) return NextResponse.json({ status: 'error', message: 'No token' }, { status: 401 });

        const decodedToken = await adminAuth.verifyIdToken(token);
        if (decodedToken.role !== 'god' && decodedToken.uid !== params.id) {
            return NextResponse.json({ status: 'error', message: 'Unauthorized' }, { status: 403 });
        }

        const updates = await request.json();
        const userRef = adminFirestore.collection('users').doc(params.id);
        
        await userRef.set(updates, { merge: true });

        // If God updated the role or status, we might want to update custom claims, 
        // but for now simple firestore update is enough for UI logic.

        return NextResponse.json({ success: true });
    } catch (error: any) {
        return NextResponse.json({ status: 'error', message: error.message }, { status: 500 });
    }
}
