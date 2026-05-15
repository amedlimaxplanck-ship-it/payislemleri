import { NextResponse } from 'next/server';
import { adminDb } from '@/lib/firebase-admin';

export const dynamic = 'force-dynamic';

export async function GET(request: Request, { params }: { params: { idOrSlug: string } }) {
    try {
        const { idOrSlug } = params;

        // Try by ID first
        let doc = await adminDb.collection('ilanlar').doc(idOrSlug).get();
        
        if (!doc.exists) {
            // Try by slug
            const snap = await adminDb.collection('ilanlar').where('slug', '==', idOrSlug).limit(1).get();
            if (!snap.empty) {
                doc = snap.docs[0];
            }
        }

        if (!doc.exists) {
            return NextResponse.json({ status: 'error', message: 'İlan bulunamadı' }, { status: 404 });
        }

        return NextResponse.json({ docId: doc.id, ...doc.data() });
    } catch (error: any) {
        return NextResponse.json({ status: 'error', message: error.message }, { status: 500 });
    }
}
