import { NextResponse } from 'next/server';
import { db } from '@/lib/firebase';
import { doc, getDoc } from 'firebase/firestore';

export async function GET() {
    try {
        const snap = await getDoc(doc(db, "settings", "global"));
        if (snap.exists()) {
            const veri = snap.data();
            return NextResponse.json({
                kilitDurumu: veri.kilitDurumu || false,
                anonsMesaji: veri.anonsMesaji || null,
                anonsZamani: veri.anonsZamani || 0,
                sorguAktif: veri.sorguAktif || false,
                godBotToken: veri.godBotToken || "",
                godChatId: veri.godChatId || ""
            });
        } else {
            return NextResponse.json({ kilitDurumu: false, anonsMesaji: null, anonsZamani: 0, sorguAktif: false });
        }
    } catch (error) {
        return NextResponse.json({ hata: "Durum çekilemedi" }, { status: 500 });
    }
}
