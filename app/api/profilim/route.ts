import { NextResponse } from 'next/server';
import { adminDb } from '@/lib/firebase-admin';
import { verifyToken } from '@/lib/auth';
import { cookies } from 'next/headers';

export const dynamic = 'force-dynamic';

export async function GET() {
    try {
        const cookieStore = await cookies();
        const token = cookieStore.get('token')?.value;
        const decoded = token ? await verifyToken(token) : null;
        
        if (!decoded) return NextResponse.json({ hata: "Yetkisiz" }, { status: 401 });

        const userSnap = await adminDb.collection('users').doc(decoded.id).get();
        if (userSnap.exists) {
            const data = userSnap.data();
            return NextResponse.json({ 
                success: true, 
                id: userSnap.id,
                ...data
            });
        } else {
            return NextResponse.json({ hata: "Kullanıcı bulunamadı" }, { status: 404 });
        }
    } catch (error) {
        console.error("[PROFILE-ADMIN] Hata:", error);
        return NextResponse.json({ hata: "Sunucu hatası" }, { status: 500 });
    }
}
