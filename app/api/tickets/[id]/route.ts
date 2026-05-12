import { NextResponse } from 'next/server';
import { db } from '@/lib/firebase';
import { doc, updateDoc, deleteDoc } from 'firebase/firestore';

export async function PATCH(
    request: Request,
    { params }: { params: { id: string } }
) {
    try {
        const body = await request.json();
        await updateDoc(doc(db, "tickets", params.id), { 
            yanit: body.yanit, 
            durum: body.durum 
        });
        return NextResponse.json({ success: true });
    } catch (e) {
        return NextResponse.json({ hata: "Talep yanıtlanamadı" }, { status: 500 });
    }
}

export async function DELETE(
    request: Request,
    { params }: { params: { id: string } }
) {
    try {
        await deleteDoc(doc(db, "tickets", params.id));
        return NextResponse.json({ success: true });
    } catch (e) {
        return NextResponse.json({ hata: "Talep silinemedi" }, { status: 500 });
    }
}
