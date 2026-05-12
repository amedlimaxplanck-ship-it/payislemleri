import { NextResponse } from 'next/server';
import { db } from '@/lib/firebase';
import { collection, query, where, getDocs } from 'firebase/firestore';

export async function GET(request: Request) {
    try {
        const { searchParams } = new URL(request.url);
        const userId = searchParams.get('userId');

        if (!userId) return NextResponse.json({ hata: "UserId gerekli" }, { status: 400 });

        const q = query(collection(db, "ilanlar"), where("olusturanMusteri", "==", userId));
        const snap = await getDocs(q);
        return NextResponse.json(snap.docs.map(doc => ({ docId: doc.id, ...doc.data() })));
    } catch (e) {
        return NextResponse.json({ hata: "İlanlar çekilemedi" }, { status: 500 });
    }
}
