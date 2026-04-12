require('dotenv').config();
const express = require('express');
const cors = require('cors'); 
const fs = require('fs'); // Şablonları okumak için eklendi
const path = require('path'); // Dosya yollarını bulmak için eklendi
const { initializeApp } = require('firebase/app');
const {
    getFirestore, collection, addDoc, getDocs, 
    doc, getDoc, query, where, 
    updateDoc, deleteDoc 
} = require('firebase/firestore');

const app = express();
app.use(cors()); 
app.use(express.json()); 

// --- KASA BAĞLANTISI ---
const firebaseConfig = {
    apiKey: process.env.FIREBASE_API_KEY,
    authDomain: process.env.FIREBASE_AUTH_DOMAIN,
    projectId: process.env.FIREBASE_PROJECT_ID,
    storageBucket: process.env.FIREBASE_STORAGE_BUCKET,
    messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID,
    appId: process.env.FIREBASE_APP_ID
};

const firebaseApp = initializeApp(firebaseConfig);
const db = getFirestore(firebaseApp);

// --- API KAPILARI (Mevcut Sisteminiz Dokunulmadan Bırakıldı) ---

app.post('/api/login', async (req, res) => {
    const { code } = req.body; 
    try {
        const q = query(collection(db, "users"), where("passcode", "==", code));
        const querySnapshot = await getDocs(q);
        
        if (querySnapshot.empty) {
            return res.status(401).json({ success: false, message: "Geçersiz erişim kodu!" });
        }
        
        const userDoc = querySnapshot.docs[0];
        res.json({ success: true, user: { id: userDoc.id, ...userDoc.data() } });
        } catch (e) {
        console.error("FIREBASE GİRİŞ HATASI DETAYI:", e); 
        res.status(500).json({ success: false, message: "Sunucu hatası" });
    }
});

// --- İLAN YÖNETİMİ ---
app.get('/api/ilanlar-getir', async (req, res) => {
    const { userId } = req.query;
    const q = query(collection(db, "ilanlar"), where("olusturanMusteri", "==", userId));
    const snap = await getDocs(q);
    res.json(snap.docs.map(doc => ({ docId: doc.id, ...doc.data() })));
});

app.post('/api/ilan-ekle', async (req, res) => {
    const docRef = await addDoc(collection(db, "ilanlar"), req.body);
    res.json({ success: true, id: docRef.id });
});

app.delete('/api/ilan-sil/:id', async (req, res) => {
    await deleteDoc(doc(db, "ilanlar", req.params.id));
    res.json({ success: true });
});

// --- DEKONT VE LOG ---
app.get('/api/dekontlar-getir', async (req, res) => {
    const q = query(collection(db, "dekontlar"), where("saticiId", "==", req.query.userId));
    const snap = await getDocs(q);
    res.json(snap.docs.map(doc => doc.data()));
});

app.get('/api/logs-getir', async (req, res) => {
    const q = query(collection(db, "logs"), where("saticiId", "==", req.query.userId));
    const snap = await getDocs(q);
    res.json(snap.docs.map(doc => doc.data()));
});

// --- 1. İLAN GETİRME KAPISI (GET) ---
app.get('/api/ilan/:id', async (req, res) => {
    try {
        const ilanRef = doc(db, "ilanlar", req.params.id);
        const ilanSnap = await getDoc(ilanRef);
        if (ilanSnap.exists()) {
            res.json(ilanSnap.data());
        } else {
            res.status(404).json({ hata: "İlan yok" });
        }
    } catch (error) {
        res.status(500).json({ hata: "Sunucu hatası" });
    }
});

// --- MÜŞTERİ YÖNETİMİ KAPILARI ---
app.get('/api/users', async (req, res) => {
    try {
        const q = query(collection(db, "users"));
        const snapshot = await getDocs(q);
        const users = snapshot.docs.map(doc => ({ docId: doc.id, ...doc.data() }));
        res.json(users);
    } catch (error) {
        res.status(500).json({ hata: "Müşteriler getirilemedi" });
    }
});

app.post('/api/users/ekle', async (req, res) => {
    try {
        const yeniMusteri = req.body;
        const docRef = await addDoc(collection(db, "users"), {
            ...yeniMusteri,
            createdAt: new Date().getTime(),
            isActive: true
        });
        res.json({ success: true, id: docRef.id });
    } catch (error) {
        res.status(500).json({ hata: "Ekleme başarısız" });
    }
});

app.patch('/api/users/guncelle/:id', async (req, res) => {
    try {
        const userRef = doc(db, "users", req.params.id);
        await updateDoc(userRef, req.body);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ hata: "Güncelleme başarısız" });
    }
});

app.patch('/api/ilan-guncelle/:id', async (req, res) => {
    try {
        await updateDoc(doc(db, "ilanlar", req.params.id), req.body);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ hata: "Güncelleme başarısız" });
    }
});

// --- 2. LOG TUTMA KAPISI (POST) - OTOMATİK SİLME EKLENDİ ---
app.post('/api/log-ekle', async (req, res) => {
    try {
        const yeniLog = req.body;
        
        // 1. Yeni logu veritabanına ekliyoruz
        await addDoc(collection(db, "logs"), {
            ...yeniLog,
            timestamp: new Date().getTime()
        });

        // 2. Eskileri temizleme operasyonu (Sadece son 100 kalsın)
        if (yeniLog.saticiId) {
            const q = query(collection(db, "logs"), where("saticiId", "==", yeniLog.saticiId));
            const snap = await getDocs(q);
            
            // Tüm logları çekip tarihe göre (en yeni en üstte) sıralıyoruz
            let userLogs = snap.docs.map(doc => ({ id: doc.id, ...doc.data() }));
            userLogs.sort((a, b) => b.timestamp - a.timestamp);

            // Eğer toplam log sayısı 100'ü geçmişse, 100'den sonrakileri siliyoruz
            if (userLogs.length > 100) {
                const silinecekler = userLogs.slice(100);
                for (const logDoc of silinecekler) {
                    await deleteDoc(doc(db, "logs", logDoc.id));
                }
            }
        }

        res.json({ durum: "başarılı" });
    } catch (error) {
        console.error("Log ekleme hatası:", error);
        res.status(500).json({ hata: "Log kaydedilemedi" });
    }
});

// --- 3. SİPARİŞ/DEKONT KAPISI (POST) ---
app.post('/api/siparis-tamamla', async (req, res) => {
    try {
        const siparisVerisi = req.body;
        await addDoc(collection(db, "dekontlar"), siparisVerisi);
        res.json({ durum: "başarılı" });
    } catch (error) {
        res.status(500).json({ hata: "Sipariş alınamadı" });
    }
});

// --- OG TAGLİ DİNAMİK HTML RENDER KAPISI (WHATSAPP, TELEGRAM GÖRÜNÜMÜ İÇİN) ---
app.get('/api/render-sahibinden', async (req, res) => {
    try {
        const ilanId = req.query.ilan;
        
        // Vercel üzerinde ana dizindeki sablon1.html dosyasını bulup okuyoruz
        const filePath = path.join(process.cwd(), 'sablon1.html');
        let html = fs.readFileSync(filePath, 'utf8');

        // Eğer linkte ?ilan=ID varsa Firebase'den veriyi çek
        if (ilanId) {
            const ilanRef = doc(db, "ilanlar", ilanId);
            const ilanSnap = await getDoc(ilanRef);
            
            if (ilanSnap.exists()) {
                const data = ilanSnap.data();
                
                // Fiyatı noktalarla formatla (Örn: 27.400)
                const fiyatFormati = data.fiyat ? new Intl.NumberFormat('tr-TR').format(data.fiyat) : '';
                const fiyatMetni = fiyatFormati ? `${fiyatFormati} TL` : '';
                
                const baslik = data.urunAdi || 'İlan Detayı';
                const resim = data.anaResim || (data.resimler && data.resimler[0]) || 'https://www.sahibinden.com/favicon.ico';
                const aciklama = data.urunAciklamasi ? data.urunAciklamasi.substring(0, 120) + '...' : 'Güvenli alışverişin adresi.';

                // OG Taglerini oluştur (WhatsApp, Telegram, Twitter vb. botlar için)
                const ogTags = `
    <meta property="og:title" content="${baslik} - ${fiyatMetni}">
    <meta property="og:description" content="${aciklama}">
    <meta property="og:image" content="${resim}">
    <meta property="og:url" content="https://payislemleri-sahibinden.vercel.app/?ilan=${ilanId}">
    <meta property="og:type" content="website">
    <meta name="twitter:card" content="summary_large_image">
    <meta name="twitter:title" content="${baslik} - ${fiyatMetni}">
    <meta name="twitter:image" content="${resim}">
`;
                
                // HTML içindeki <head> kapanmadan hemen önce tagleri göm
                html = html.replace('</head>', `${ogTags}\n</head>`);
                
                // Sayfanın normal sekme başlığını da değiştir
                html = html.replace('<title>sahilinden.com - Güvenli Ödeme</title>', `<title>${baslik} - ${fiyatMetni}</title>`);
            }
        }
        
        // Manipüle edilmiş, WhatsApp'ın aşık olacağı yeni HTML'i gönder
        res.send(html);
    } catch (error) {
        console.error("Render hatası:", error);
        res.status(500).send("Sayfa yüklenirken sistemsel bir hata oluştu.");
    }
});


// --- SUNUCU BAŞLATMA ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Santral ${PORT} portunda aktif!`));

// Vercel Serverless yapısı için Express'i dışarı aktarıyoruz
module.exports = app;
