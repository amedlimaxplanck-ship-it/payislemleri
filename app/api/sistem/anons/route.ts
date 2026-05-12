import { NextResponse } from 'next/server';
import { db } from '@/lib/firebase';
import { doc, setDoc } from 'firebase/firestore';

export async function POST(request: Request) {
    try {
        const { mesaj, zaman } = await request.json();
        await setDoc(doc(db, "settings", "global"), { 
            anonsMesaji: mesaj, 
            anonsZamani: zaman 
        }, { merge: true });
        return NextResponse.json({ success: true });
    } catch (error) {
        return NextResponse.json({ hata: "Anons ayarlanamadı" }, { status: 500 });
    }
}
