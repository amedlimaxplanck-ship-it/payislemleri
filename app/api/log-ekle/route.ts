import { NextResponse } from 'next/server';
import { adminFirestore } from '@/lib/firebase-admin';

export async function POST(request: Request) {
    try {
        const logData = await request.json();
        
        // Basic validation
        if (!logData.saticiId) {
            return NextResponse.json({ status: 'error', message: 'saticiId required' }, { status: 400 });
        }

        const logRef = adminFirestore.collection('logs').doc();
        await logRef.set({
            ...logData,
            createdAt: Date.now(),
            docId: logRef.id
        });

        return NextResponse.json({ success: true, docId: logRef.id });
    } catch (error: any) {
        return NextResponse.json({ status: 'error', message: error.message }, { status: 500 });
    }
}
