import { NextResponse } from 'next/server';
import { db } from '@/lib/firebase';
import { doc, updateDoc } from 'firebase/firestore';

export async function POST(
    request: Request,
    { params }: { params: { id: string } }
) {
    try {
        const id = params.id;
        const { action, sebep } = await request.json();
        
        if (action === 'ban') {
            await updateDoc(doc(db, "users", id), { 
                isBanned: true, 
                banReason: sebep, 
                isActive: false, 
                currentSession: null 
            });
        } else if (action === 'unban') {
            await updateDoc(doc(db, "users", id), { 
                isBanned: false, 
                banReason: "", 
                recentIps: [], 
                isSuspicious: false, 
                isActive: true 
            });
        }
        
        return NextResponse.json({ success: true });
    } catch (error) {
        return NextResponse.json({ hata: "İşlem başarısız" }, { status: 500 });
    }
}
