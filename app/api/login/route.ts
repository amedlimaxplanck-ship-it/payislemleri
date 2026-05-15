import { NextResponse } from 'next/server';
import { adminDb } from '@/lib/firebase-admin';
import { createToken } from '@/lib/auth';

export async function POST(request: Request) {
    const startTime = Date.now();
    try {
        const { code } = await request.json();
        console.log(`[LOGIN-ADMIN] İşlem başladı. Gelen kod: ${code}`);
        
        if (!code) return NextResponse.json({ success: false, message: "Kod eksik" }, { status: 400 });

        const fields = ["passcode", "passCode", "code"];
        let userDoc: any = null;

        // Bütün varyasyonları paralel tara (Admin SDK ile)
        const queries = fields.flatMap(field => [
            adminDb.collection('users').where(field, '==', String(code)).limit(1).get(),
            adminDb.collection('users').where(field, '==', Number(code)).limit(1).get()
        ]);

        const snapshots = await Promise.all(queries);
        
        for (const snap of snapshots) {
            if (!snap.empty) {
                userDoc = snap.docs[0];
                break;
            }
        }

        if (!userDoc) {
            console.warn(`[LOGIN-ADMIN] Kullanıcı bulunamadı. Süre: ${Date.now() - startTime}ms`);
            return NextResponse.json({ success: false, message: "Geçersiz erişim kodu!" }, { status: 401 });
        }

        const userData = userDoc.data();
        const userId = userDoc.id;

        // Oturum güncelleme
        const sessionId = Date.now().toString();
        try {
            await adminDb.collection('users').doc(userId).update({ 
                currentSession: sessionId,
                lastLogin: new Date().toISOString()
            });
        } catch (updateErr) {
            console.error("[LOGIN-ADMIN] Oturum güncellenemedi:", updateErr);
        }

        const token = await createToken({ id: userId, role: userData.role || 'user', sessionId });
        const response = NextResponse.json({ success: true, user: { id: userId, ...userData } });

        response.cookies.set('token', token, {
            httpOnly: true,
            secure: true,
            maxAge: 60 * 60 * 24,
            path: '/',
        });

        console.log(`[LOGIN-ADMIN] Başarılı! Süre: ${Date.now() - startTime}ms`);
        return response;

    } catch (error) {
        console.error("[LOGIN-ADMIN KRİTİK HATA]", error);
        return NextResponse.json({ success: false, message: "Sistem hatası: " + (error as Error).message }, { status: 500 });
    }
}
