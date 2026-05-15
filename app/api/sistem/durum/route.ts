import { NextResponse } from 'next/server';
import { adminDb } from '@/lib/firebase-admin';

export const dynamic = 'force-dynamic';

export async function GET() {
    try {
        const snap = await adminDb.collection('settings').doc('global').get();
        if (snap.exists) {
            const veri = snap.data() || {};
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
        console.error("[SISTEM-ADMIN] Hata:", error);
        return NextResponse.json({ hata: "Durum çekilemedi" }, { status: 500 });
    }
}
