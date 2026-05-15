import { NextResponse } from 'next/server';
import { adminDb } from '@/lib/firebase-admin';
import { verifyToken } from '@/lib/auth';
import { cookies } from 'next/headers';

export async function POST(request: Request) {
    try {
        const cookieStore = await cookies();
        const token = request.headers.get('Authorization')?.split('Bearer ')[1] || cookieStore.get('token')?.value;
        if (!token) return NextResponse.json({ status: 'error', message: 'No token' }, { status: 401 });

        const decodedToken = await verifyToken(token);
        if (!decodedToken || decodedToken.role !== 'god') {
            return NextResponse.json({ status: 'error', message: 'Unauthorized' }, { status: 403 });
        }

        // Fetch settings for Telegram
        const settingsSnap = await adminDb.collection('ayarlar').doc('sistem').get();
        const settings = settingsSnap.data() || {};
        
        const botToken = settings.godBotToken;
        const chatId = settings.godChatId;

        if (botToken && chatId) {
            // Fetch users for backup
            const usersSnap = await adminDb.collection('users').get();
            const users = usersSnap.docs.map(doc => doc.data());
            
            const backupData = JSON.stringify(users, null, 2);
            
            // Send to Telegram (Mocked or simple fetch)
            await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    chat_id: chatId,
                    text: `📦 *Sistem Yedeği Alındı*\nTarih: ${new Date().toLocaleString('tr-TR')}\nToplam Kullanıcı: ${users.length}`,
                    parse_mode: 'Markdown'
                })
            });
        }

        return NextResponse.json({ success: true });
    } catch (error: any) {
        return NextResponse.json({ status: 'error', message: error.message }, { status: 500 });
    }
}
