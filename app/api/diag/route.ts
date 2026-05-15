import { NextResponse } from 'next/server';
import { db } from '@/lib/firebase';
import { collection, getDocs, limit, query } from 'firebase/firestore';

export async function GET() {
    try {
        const configTest = {
            apiKey: process.env.FIREBASE_API_KEY ? "OK (Set)" : "MISSING",
            projectId: process.env.FIREBASE_PROJECT_ID || "MISSING",
            appId: process.env.FIREBASE_APP_ID ? "OK (Set)" : "MISSING"
        };

        const collectionsTested = ["users", "settings", "ilanlar"];
        const results: any = {};

        for (const col of collectionsTested) {
            try {
                const testSnap = await getDocs(query(collection(db, col), limit(1)));
                results[col] = testSnap.empty ? "Empty" : "Found Data";
            } catch (e) {
                results[col] = "Error: " + (e as Error).message;
            }
        }

        return NextResponse.json({ 
            status: "ok", 
            config: configTest,
            collectionStatus: results,
            message: results["users"] === "Found Data" ? "Veritabanı erişimi tam yetkiyle sağlandı." : "Bağlantı sağlandı ama 'users' boş görünüyor."
        });
    } catch (error) {
        return NextResponse.json({ 
            status: "error", 
            message: (error as Error).message,
            configCheck: process.env.FIREBASE_PROJECT_ID ? "Env Var Var" : "Env Var Yok"
        });
    }
}
