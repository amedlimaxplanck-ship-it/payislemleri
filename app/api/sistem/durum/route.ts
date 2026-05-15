import { NextResponse } from 'next/server';
import { adminDb } from '@/lib/firebase-admin';
import { verifyToken } from '@/lib/auth';
import { cookies } from 'next/headers';

export async function GET(request: Request) {
    try {
        const cookieStore = await cookies();
        const token = request.headers.get('Authorization')?.split('Bearer ')[1] || cookieStore.get('token')?.value;
        if (!token) return NextResponse.json({ status: 'error', message: 'No token' }, { status: 401 });

        const decodedToken = await verifyToken(token);
        if (!decodedToken) return NextResponse.json({ status: 'error', message: 'Invalid token' }, { status: 401 });
        if (decodedToken.role !== 'god') return NextResponse.json({ status: 'error', message: 'Unauthorized' }, { status: 403 });

        const systemDoc = await adminDb.collection('ayarlar').doc('sistem').get();
        if (!systemDoc.exists) {
            return NextResponse.json({
                kilitDurumu: false,
                sorguAktif: false,
                anonsMesaji: '',
                godBotToken: '',
                godChatId: ''
            });
        }

        return NextResponse.json(systemDoc.data());
    } catch (error: any) {
        return NextResponse.json({ status: 'error', message: error.message }, { status: 500 });
    }
}
