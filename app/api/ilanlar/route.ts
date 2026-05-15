import { NextResponse } from 'next/server';
import { adminDb } from '@/lib/firebase-admin';

export const dynamic = 'force-dynamic';

export async function GET(request: Request) {
    try {
        const { searchParams } = new URL(request.url);
        const userId = searchParams.get('userId');

        if (!userId) return NextResponse.json({ hata: "UserId gerekli" }, { status: 400 });

        const snap = await adminDb.collection('ilanlar').where("olusturanMusteri", "==", userId).get();
        return NextResponse.json(snap.docs.map(doc => ({ docId: doc.id, ...doc.data() })));
    } catch (e) {
        console.error("[ILANLAR-ADMIN] Hata:", e);
        return NextResponse.json({ hata: "İlanlar çekilemedi" }, { status: 500 });
    }
}
