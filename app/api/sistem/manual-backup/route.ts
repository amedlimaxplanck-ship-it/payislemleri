import { NextResponse } from 'next/server';
import { db } from '@/lib/firebase';
import { collection, query, getDocs, doc, getDoc } from 'firebase/firestore';

export async function POST() {
    try {
        const snap = await getDoc(doc(db, "settings", "global"));
        const ayarlar = snap.exists() ? snap.data() : {};
        if (!ayarlar.godBotToken || !ayarlar.godChatId) {
            return NextResponse.json({ hata: "Önce Telegram ayarlarını kaydetmelisiniz." }, { status: 400 });
        }

        const usersSnap = await getDocs(query(collection(db, "users")));
        const ilanlarSnap = await getDocs(query(collection(db, "ilanlar")));
        const dekontlarSnap = await getDocs(query(collection(db, "dekontlar")));
        
        const backupData = {
            tarih: new Date().toISOString(),
            kullanicilar: usersSnap.docs.map(d => ({id: d.id, ...d.data()})),
            ilanlar: ilanlarSnap.docs.map(d => ({id: d.id, ...d.data()})),
            dekontlar: dekontlarSnap.docs.map(d => ({id: d.id, ...d.data()}))
        };

        const buffer = Buffer.from(JSON.stringify(backupData, null, 2), 'utf-8');
        const boundary = '----TelegramBoundary' + Date.now().toString(16);
        const body = Buffer.concat([
            Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="chat_id"\r\n\r\n${ayarlar.godChatId}\r\n`, 'utf-8'),
            Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="document"; filename="Supa_Yedek_${Date.now()}.json"\r\nContent-Type: application/json\r\n\r\n`, 'utf-8'),
            buffer,
            Buffer.from(`\r\n--${boundary}--\r\n`, 'utf-8')
        ]);

        const tgRes = await fetch(`https://api.telegram.org/bot${ayarlar.godBotToken}/sendDocument`, {
            method: 'POST',
            headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}` },
            body: body
        });

        if (tgRes.ok) {
            return NextResponse.json({ success: true, mesaj: "Yedek Telegram'a iletildi." });
        } else {
            return NextResponse.json({ hata: "Telegram'a gönderilirken hata oluştu." }, { status: 500 });
        }
    } catch (error) {
        return NextResponse.json({ hata: "Yedekleme motoru çöktü." }, { status: 500 });
    }
}
