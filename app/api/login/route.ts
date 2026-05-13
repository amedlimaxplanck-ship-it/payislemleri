import { NextResponse } from 'next/server';
import { db } from '@/lib/firebase';
import { collection, query, where, getDocs, doc, updateDoc } from 'firebase/firestore';
import { createToken } from '@/lib/auth';

export async function POST(request: Request) {
    try {
        const { code } = await request.json();
        console.log("--- GİRİŞ DENEMESİ BAŞLADI ---");
        console.log("Alınan Kod:", code);
        
        if (!code) {
            return NextResponse.json({ success: false, message: "Lütfen bir kod girin!" }, { status: 400 });
        }

        // 1. ADIM: Farklı alan adları ve tiplerle sorgu dene
        const fieldVariations = ["passcode", "passCode", "code"];
        let querySnapshot: any = null;

        for (const field of fieldVariations) {
            console.log(`${field} alanı kontrol ediliyor...`);
            
            // String kontrolü
            let q = query(collection(db, "users"), where(field, "==", String(code)));
            querySnapshot = await getDocs(q);
            
            // Bulunamazsa ve sayı ise Number kontrolü
            if (querySnapshot.empty && !isNaN(Number(code))) {
                q = query(collection(db, "users"), where(field, "==", Number(code)));
                querySnapshot = await getDocs(q);
            }

            if (!querySnapshot.empty) {
                console.log(`Eşleşme bulundu! Alan: ${field}`);
                break;
            }
        }
        
        if (!querySnapshot || querySnapshot.empty) {
            console.warn("DİKKAT: Veritabanında eşleşen kullanıcı bulunamadı.");
            return NextResponse.json({ success: false, message: "Geçersiz erişim kodu!" }, { status: 401 });
        }
        
        const userDoc = querySnapshot.docs[0];
        const userData = userDoc.data();
        const userId = userDoc.id;

        console.log("Kullanıcı Doğrulandı:", userId, "Rol:", userData.role);

        // 2. ADIM: Oturum güncelleme (Hata alsa da girişi engellemesin)
        const yeniOturumKodu = Date.now().toString(); 
        try {
            await updateDoc(doc(db, "users", userId), { 
                currentSession: yeniOturumKodu,
                lastLogin: new Date().toISOString()
            });
        } catch (updateErr) {
            console.error("Oturum güncellenemedi (Muhtemelen yetki kısıtı), devam ediliyor:", updateErr);
        }

        const token = await createToken({ id: userId, role: userData.role, sessionId: yeniOturumKodu });

        const response = NextResponse.json({ 
            success: true, 
            user: { id: userId, ...userData },
            token: token // Client-side için de gönderiyoruz
        });

        response.cookies.set('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            maxAge: 60 * 60 * 24, 
            path: '/',
        });

        console.log("--- GİRİŞ BAŞARILI ---");
        return response;

    } catch (error) {
        console.error("KRİTİK GİRİŞ HATASI:", error);
        return NextResponse.json({ success: false, message: "Sunucu hatası: " + (error as Error).message }, { status: 500 });
    }
}
