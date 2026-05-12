import { NextResponse } from 'next/server';
import { db } from '@/lib/firebase';
import { doc, setDoc } from 'firebase/firestore';

export async function POST(request: Request) {
    try {
        const body = await request.json();
        await setDoc(doc(db, "settings", "global"), { 
            godBotToken: body.godBotToken, 
            godChatId: body.godChatId 
        }, { merge: true });
        return NextResponse.json({ success: true });
    } catch (error) {
        return NextResponse.json({ hata: "Ayarlar kaydedilemedi" }, { status: 500 });
    }
}
