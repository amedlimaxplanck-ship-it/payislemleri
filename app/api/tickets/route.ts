import { NextResponse } from 'next/server';
import { db } from '@/lib/firebase';
import { collection, query, where, getDocs, addDoc } from 'firebase/firestore';
import { verifyToken } from '@/lib/auth';
import { cookies } from 'next/headers';

export async function GET() {
    try {
        const cookieStore = await cookies();
        const token = cookieStore.get('token')?.value;
        const decoded = token ? await verifyToken(token) : null;
        
        if (!decoded) return NextResponse.json({ hata: "Yetkisiz" }, { status: 401 });

        let q = decoded.role === 'god' 
            ? query(collection(db, "tickets")) 
            : query(collection(db, "tickets"), where("musteriId", "==", decoded.id));
            
        const snap = await getDocs(q);
        return NextResponse.json(snap.docs.map(doc => ({ docId: doc.id, ...doc.data() })));
    } catch (e) {
        return NextResponse.json({ hata: "Biletler çekilemedi" }, { status: 500 });
    }
}

export async function POST(request: Request) {
    try {
        const cookieStore = await cookies();
        const token = cookieStore.get('token')?.value;
        const decoded = token ? await verifyToken(token) : null;
        if (!decoded) return NextResponse.json({ hata: "Yetkisiz" }, { status: 401 });

        const body = await request.json();
        await addDoc(collection(db, "tickets"), {
            musteriId: decoded.id,
            musteriKod: body.musteriKod,
            konu: body.konu,
            mesaj: body.mesaj,
            tarih: new Date().getTime(),
            durum: 'Acik',
            yanit: ''
        });
        return NextResponse.json({ success: true });
    } catch (e) {
        return NextResponse.json({ hata: "Talep açılamadı" }, { status: 500 });
    }
}
