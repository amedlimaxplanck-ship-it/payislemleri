import { NextResponse } from 'next/server';
import { db } from '@/lib/firebase';
import { doc, setDoc } from 'firebase/firestore';

export async function POST(request: Request) {
    try {
        const { aktif } = await request.json();
        await setDoc(doc(db, "settings", "global"), { sorguAktif: aktif }, { merge: true });
        return NextResponse.json({ success: true });
    } catch (error) {
        return NextResponse.json({ hata: "Sorgu durumu ayarlanamadı" }, { status: 500 });
    }
}
