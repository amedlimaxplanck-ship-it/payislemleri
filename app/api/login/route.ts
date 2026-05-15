import { NextResponse } from 'next/server';
import { db } from '@/lib/firebase';
import { collection, query, where, getDocs, doc, updateDoc, limit } from 'firebase/firestore';
import { createToken } from '@/lib/auth';

export async function POST(request: Request) {
    const startTime = Date.now();
    try {
        const { code } = await request.json();
        console.log(`[LOGIN] İşlem başladı. Gelen kod: ${code} (Tip: ${typeof code})`);
        
        if (!code) return NextResponse.json({ success: false, message: "Kod eksik" }, { status: 400 });

        const fields = ["passcode", "passCode", "code"];
        let userDoc: any = null;

        // Bütün varyasyonları paralel tara (Hız için)
        const promises = fields.flatMap(field => [
            getDocs(query(collection(db, "users"), where(field, "==", String(code)), limit(1))),
            getDocs(query(collection(db, "users"), where(field, "==", Number(code)), limit(1)))
        ]);

        console.log(`[LOGIN] ${promises.length} adet sorgu paralel başlatıldı...`);
        const snapshots = await Promise.all(promises);
        
        for (const snap of snapshots) {
            if (!snap.empty) {
                userDoc = snap.docs[0];
                break;
            }
        }

        if (!userDoc) {
            console.warn(`[LOGIN] Kullanıcı bulunamadı. Geçen süre: ${Date.now() - startTime}ms`);
            
            // DEBUG: Veritabanında ne var? (Sadece geliştirme aşamasında loglar için)
            const debugSnap = await getDocs(query(collection(db, "users"), limit(1)));
            if (!debugSnap.empty) {
                console.log("[LOGIN DEBUG] DB'deki bir kullanıcının alanları:", Object.keys(debugSnap.docs[0].data()));
            } else {
                console.log("[LOGIN DEBUG] DB'de hiç kullanıcı yok!");
            }

            return NextResponse.json({ success: false, message: "Geçersiz erişim kodu!" }, { status: 401 });
        }

        const userData = userDoc.data();
        const userId = userDoc.id;

        // Oturum güncelleme
        const sessionId = Date.now().toString();
        try {
            await updateDoc(doc(db, "users", userId), { 
                currentSession: sessionId,
                lastLogin: new Date().toISOString()
            });
        } catch (updateErr) {
            console.error("[LOGIN] Oturum güncellenemedi:", updateErr);
        }

        const token = await createToken({ id: userId, role: userData.role || 'user', sessionId });
        const response = NextResponse.json({ success: true, user: { id: userId, ...userData } });

        response.cookies.set('token', token, {
            httpOnly: true,
            secure: true,
            maxAge: 60 * 60 * 24,
            path: '/',
        });

        console.log(`[LOGIN] Başarılı! Süre: ${Date.now() - startTime}ms`);
        return response;

    } catch (error) {
        console.error("[LOGIN KRİTİK HATA]", error);
        return NextResponse.json({ success: false, message: "Sistem hatası: " + (error as Error).message }, { status: 500 });
    }
}
