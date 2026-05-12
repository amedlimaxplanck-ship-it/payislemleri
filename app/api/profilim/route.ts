import { NextResponse } from 'next/server';
import { db } from '@/lib/firebase';
import { doc, getDoc } from 'firebase/firestore';
import { verifyToken } from '@/lib/auth';
import { cookies } from 'next/headers';

export async function GET() {
    try {
        const token = cookies().get('token')?.value;
        const decoded = token ? verifyToken(token) : null;
        
        if (!decoded) return NextResponse.json({ hata: "Yetkisiz" }, { status: 401 });

        const userSnap = await getDoc(doc(db, "users", decoded.id));
        if (userSnap.exists()) {
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
        return NextResponse.json({ hata: "Sunucu hatası" }, { status: 500 });
    }
}
