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

        let collectionRef = adminDb.collection('tickets');
        let snap;

        if (decoded.role === 'god') {
            snap = await collectionRef.get();
        } else {
            snap = await collectionRef.where("musteriId", "==", decoded.id).get();
        }
            
        return NextResponse.json(snap.docs.map(doc => ({ docId: doc.id, ...doc.data() })));
    } catch (e) {
        console.error("[TICKETS-ADMIN] GET Hata:", e);
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
        await adminDb.collection('tickets').add({
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
        console.error("[TICKETS-ADMIN] POST Hata:", e);
        return NextResponse.json({ hata: "Talep açılamadı" }, { status: 500 });
    }
}
