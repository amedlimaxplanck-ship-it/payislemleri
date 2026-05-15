import { NextResponse } from 'next/server';
import { adminAuth, adminDb } from '@/lib/firebase-admin';

export async function GET(request: Request) {
    try {
        const token = request.headers.get('Authorization')?.split('Bearer ')[1];
        if (!token) return NextResponse.json({ status: 'error', message: 'No token' }, { status: 401 });

        const decodedToken = await adminAuth.verifyIdToken(token);
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
