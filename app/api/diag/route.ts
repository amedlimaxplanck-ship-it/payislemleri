import { NextResponse } from 'next/server';
import { db } from '@/lib/firebase';
import { collection, getDocs, limit, query } from 'firebase/firestore';

export async function GET() {
    try {
        console.log("--- DİAGNOSTİK BAŞLADI ---");
        const q = query(collection(db, "users"), limit(1));
        const snap = await getDocs(q);
        
        if (snap.empty) {
            return NextResponse.json({ 
                status: "error", 
                message: "Users koleksiyonu boş veya erişilemiyor.",
                projectId: process.env.FIREBASE_PROJECT_ID 
            });
        }

        const firstUser = snap.docs[0].data();
        const fields = Object.keys(firstUser);

        return NextResponse.json({ 
            status: "ok", 
            message: "Veritabanına bağlanıldı.",
            userCount: snap.size,
            availableFields: fields,
            projectId: process.env.FIREBASE_PROJECT_ID
        });
    } catch (error) {
        return NextResponse.json({ 
            status: "error", 
            message: (error as Error).message,
            stack: (error as Error).stack 
        });
    }
}
