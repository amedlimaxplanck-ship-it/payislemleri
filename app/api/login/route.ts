import { NextResponse } from 'next/server';
import { db } from '@/lib/firebase';
import { collection, query, where, getDocs, doc, updateDoc } from 'firebase/firestore';
import { createToken } from '@/lib/auth';

export async function POST(request: Request) {
    try {
        const { code } = await request.json();
        console.log("Giriş denemesi:", code);
        
        if (!code) {
            return NextResponse.json({ success: false, message: "Geçersiz erişim kodu!" }, { status: 400 });
        }

        // Try as string first
        let q = query(collection(db, "users"), where("passcode", "==", String(code)));
        let querySnapshot = await getDocs(q);
        
        // If not found, try as number
        if (querySnapshot.empty && !isNaN(Number(code))) {
            q = query(collection(db, "users"), where("passcode", "==", Number(code)));
            querySnapshot = await getDocs(q);
        }
        
        if (querySnapshot.empty) {
            console.warn("Kod bulunamadı:", code);
            return NextResponse.json({ success: false, message: "Geçersiz erişim kodu!" }, { status: 401 });
        }
        
        const userDoc = querySnapshot.docs[0];
        const userData = userDoc.data();
        const userId = userDoc.id;

        if (userData.isBanned) {
            return NextResponse.json({ 
                success: false, 
                isBanned: true, 
                message: `HESAP YASAKLANDI!\nSebep: ${userData.banReason || 'Kural İhlali'}` 
            }, { status: 403 });
        }

        // Expire check
        if (userData.expireDate && userData.role !== 'god') {
            const parts = userData.expireDate.split('.');
            if (parts.length === 3) {
                const expDate = new Date(parts[2], parts[1] - 1, parts[0], 23, 59, 59).getTime();
                if (Date.now() > expDate) {
                    return NextResponse.json({ 
                        success: false, 
                        message: userData.banMessage || "Abonelik süreniz dolmuştur. Lütfen ödemenizi yapın." 
                    }, { status: 403 });
                }
            }
        }

        // IP Tracking
        const forwarded = request.headers.get('x-forwarded-for');
        const currentIp = forwarded ? forwarded.split(',')[0] : 'Bilinmeyen IP';
        
        let recentIps = userData.recentIps || [];
        if (!recentIps.includes(currentIp)) {
            recentIps.push(currentIp);
            if (recentIps.length > 3) recentIps.shift(); 
        }
        
        const isSuspicious = recentIps.length >= 3;
        const suspicionReason = isSuspicious ? "Farklı konumlardan/cihazlardan giriş tespit edildi." : "";

        const yeniOturumKodu = Date.now().toString(); 
        
        await updateDoc(doc(db, "users", userId), { 
            currentSession: yeniOturumKodu,
            recentIps: recentIps,
            isSuspicious: isSuspicious,
            suspicionReason: suspicionReason
        });

        const token = await createToken({ id: userId, role: userData.role, sessionId: yeniOturumKodu });

        const response = NextResponse.json({ 
            success: true, 
            user: { id: userId, ...userData } 
        });

        // Set cookie for persistence
        response.cookies.set('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            maxAge: 60 * 60 * 24, // 24 hours
            path: '/',
        });

        return response;

    } catch (error) {
        console.error("Login error:", error);
        return NextResponse.json({ success: false, message: "Sunucu hatası" }, { status: 500 });
    }
}
