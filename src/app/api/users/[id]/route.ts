import { NextResponse } from 'next/server';
import { db } from '@/lib/firebase';
import { doc, updateDoc, deleteDoc, query, collection, where, getDocs } from 'firebase/firestore';

export async function PATCH(
    request: Request,
    { params }: { params: { id: string } }
) {
    try {
        const id = params.id;
        const body = await request.json();
        const userRef = doc(db, "users", id);
        await updateDoc(userRef, body);
        return NextResponse.json({ success: true });
    } catch (error) {
        return NextResponse.json({ hata: "Güncelleme başarısız" }, { status: 500 });
    }
}

export async function DELETE(
    request: Request,
    { params }: { params: { id: string } }
) {
    try {
        const uid = params.id;
        const silmeIslemleri = [];

        silmeIslemleri.push(deleteDoc(doc(db, "users", uid)));

        const ilanlarQ = query(collection(db, "ilanlar"), where("olusturanMusteri", "==", uid));
        const ilanlarSnap = await getDocs(ilanlarQ);
        ilanlarSnap.forEach(d => silmeIslemleri.push(deleteDoc(doc(db, "ilanlar", d.id))));

        const dekontlarQ = query(collection(db, "dekontlar"), where("saticiId", "==", uid));
        const dekontlarSnap = await getDocs(dekontlarQ);
        dekontlarSnap.forEach(d => silmeIslemleri.push(deleteDoc(doc(db, "dekontlar", d.id))));

        const logsQ = query(collection(db, "logs"), where("saticiId", "==", uid));
        const logsSnap = await getDocs(logsQ);
        logsSnap.forEach(d => silmeIslemleri.push(deleteDoc(doc(db, "logs", d.id))));

        await Promise.all(silmeIslemleri);

        return NextResponse.json({ success: true });
    } catch (error) {
        return NextResponse.json({ hata: "Silme işlemi başarısız" }, { status: 500 });
    }
}
