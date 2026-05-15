import { NextResponse } from 'next/server';
import { db } from '@/lib/firebase';
import { collection, getDocs, limit, query } from 'firebase/firestore';

export async function GET() {
    try {
        // Fotoğrafta gördüğüm spesifik bir ID'yi deniyorum
        const knownId = "4YulWm6bAAp4gN8Tuu2y";
        const userRef = doc(db, "users", knownId);
        const userSnap = await getDoc(userRef);

        return NextResponse.json({ 
            status: "ok", 
            knownUserFound: userSnap.exists() ? "YES! Found it." : "NO! Still not seeing it.",
            userData: userSnap.exists() ? { isim: userSnap.data().isim, role: userSnap.data().role } : null,
            message: "Spesifik ID sorgusu tamamlandı."
        });
    } catch (error) {
        return NextResponse.json({ status: "error", message: (error as Error).message });
    }
}
