import { NextResponse } from 'next/server';
import { adminDb } from '@/lib/firebase-admin';

export async function POST(request: Request) {
    try {
        const data = await request.json();
        const { ilanId, saticiId, ilanBasligi, aliciAd, aliciTel, aliciAdres, dekontUrl } = data;

        if (!saticiId || !dekontUrl) {
            return NextResponse.json({ success: false, message: "Eksik veri" }, { status: 400 });
        }

        const dekontRef = adminDb.collection('dekontlar').doc();
        const timestamp = Date.now();
        
        await dekontRef.set({
            ilanId,
            olusturanMusteri: saticiId,
            ilanBasligi,
            aliciAd,
            aliciTel,
            aliciAdres,
            dekontUrl,
            tarih: new Date().toLocaleDateString('tr-TR'),
            saat: new Date().toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' }),
            createdAt: timestamp,
            status: 'beklemede',
            id: dekontRef.id
        });

        // Telegram Notification
        try {
            const userDoc = await adminDb.collection('users').doc(saticiId).get();
            if (userDoc.exists) {
                const userData = userDoc.data();
                if (userData?.tgBotToken && userData?.tgChatId) {
                    const message = `✅ *YENİ SİPARİŞ / DEKONT*\n\n` +
                                   `📦 *İlan:* ${ilanBasligi}\n` +
                                   `👤 *Alıcı:* ${aliciAd}\n` +
                                   `📞 *Tel:* ${aliciTel}\n` +
                                   `📍 *Adres:* ${aliciAdres}\n\n` +
                                   `🖼 *Dekont:* [Görüntüle](${dekontUrl})`;
                    
                    await fetch(`https://api.telegram.org/bot${userData.tgBotToken}/sendMessage`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            chat_id: userData.tgChatId,
                            text: message,
                            parse_mode: 'Markdown'
                        })
                    });
                }
            }
        } catch (tgErr) {
            console.error("Telegram error:", tgErr);
        }

        return NextResponse.json({ success: true, docId: dekontRef.id });
    } catch (error: any) {
        console.error("Sipariş tamamlama hatası:", error);
        return NextResponse.json({ success: false, message: error.message }, { status: 500 });
    }
}
