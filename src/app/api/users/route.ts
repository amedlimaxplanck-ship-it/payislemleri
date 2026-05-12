import { NextResponse } from 'next/server';
import { db } from '@/lib/firebase';
import { collection, query, getDocs, addDoc } from 'firebase/firestore';

export async function GET() {
    try {
        const q = query(collection(db, "users"));
        const snapshot = await getDocs(q);
        const users = snapshot.docs.map(doc => ({ docId: doc.id, ...doc.data() }));
        return NextResponse.json(users);
    } catch (error) {
        return NextResponse.json({ hata: "Müşteriler getirilemedi" }, { status: 500 });
    }
}

export async function POST(request: Request) {
    try {
        const body = await request.json();
        const docRef = await addDoc(collection(db, "users"), {
            ...body,
            createdAt: new Date().getTime(),
            isActive: true,
            isBanned: false,
            isSoftBanned: false,
            recentIps: [],
            isSuspicious: false,
            currentSession: null,
            ilanKotasi: body.ilanKotasi || "sinirsiz"
        });
        return NextResponse.json({ success: true, id: docRef.id });
    } catch (error) {
        return NextResponse.json({ hata: "Ekleme başarısız" }, { status: 500 });
    }
}
