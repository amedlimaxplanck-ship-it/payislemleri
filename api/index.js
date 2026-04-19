require('dotenv').config();
const express = require('express');
const cors = require('cors'); 
const fs = require('fs'); 
const path = require('path'); 
const { initializeApp } = require('firebase/app');
const {
    getFirestore, collection, addDoc, getDocs, 
    doc, getDoc, query, where, 
    updateDoc, deleteDoc, setDoc
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


// =================================================================
// 🔥 SİBER FEDAİ (GÜVENLİK DUVARI - MIDDLEWARE) 🔥
// Bu kod, kritik işlemlerde araya girer ve sistemin kilitli
// olup olmadığını kontrol eder. Kilitliyse işlemi anında reddeder!
// =================================================================
const kilitKontrol = async (req, res, next) => {
    try {
        const snap = await getDoc(doc(db, "settings", "global"));
        if (snap.exists() && snap.data().kilitDurumu === true) {
            console.warn(`[GÜVENLİK] Kilitli sisteme yetkisiz erişim denemesi reddedildi! IP/Rota: ${req.originalUrl}`);
            return res.status(403).json({ hata: "Sistem yönetici tarafından kilitlenmiştir. İşlem yapılamaz." });
        }
        // Şalter açık (sistem normal), o zaman işleme devam etmesine izin ver:
        next(); 
    } catch (error) {
        console.error("Kilit kontrol hatası:", error);
        res.status(500).json({ hata: "Güvenlik protokolü doğrulanamadı." });
    }
};


// --- API KAPILARI ---

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

// KORUMALI ROTA: İlan Ekleme
app.post('/api/ilan-ekle', kilitKontrol, async (req, res) => {
    const docRef = await addDoc(collection(db, "ilanlar"), req.body);
    res.json({ success: true, id: docRef.id });
});

// KORUMALI ROTA: İlan Silme
app.delete('/api/ilan-sil/:id', kilitKontrol, async (req, res) => {
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

app.get('/api/ilan/:id', async (req, res) => {
    try {
        const ilanRef = doc(db, "ilanlar", req.params.id);
        const ilanSnap = await getDoc(ilanRef);
        if (ilanSnap.exists()) {
            const ilanVerisi = ilanSnap.data();
            if (ilanVerisi.durum === 'pasif') {
                return res.status(404).json({ hata: "Bu ilan pasife alınmış." });
            }
            res.json(ilanVerisi);
        } else {
            res.status(404).json({ hata: "İlan yok" });
        }
    } catch (error) {
        res.status(500).json({ hata: "Sunucu hatası" });
    }
});

// --- MÜŞTERİ YÖNETİMİ KAPILARI (God Panel Kullanır, Kilite Takılmaz) ---
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

// KORUMALI ROTA: İlan Güncelleme (Müşteri pasife çekmek isterse vs.)
app.patch('/api/ilan-guncelle/:id', kilitKontrol, async (req, res) => {
    try {
        await updateDoc(doc(db, "ilanlar", req.params.id), req.body);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ hata: "Güncelleme başarısız" });
    }
});

// KORUMALI ROTA: Log Ekleme (Sistem kilitliyken log spam'ini önler)
app.post('/api/log-ekle', kilitKontrol, async (req, res) => {
    try {
        const yeniLog = req.body;
        await addDoc(collection(db, "logs"), {
            ...yeniLog,
            timestamp: new Date().getTime()
        });

        if (yeniLog.saticiId) {
            const q = query(collection(db, "logs"), where("saticiId", "==", yeniLog.saticiId));
            const snap = await getDocs(q);
            
            let userLogs = snap.docs.map(doc => ({ id: doc.id, ...doc.data() }));
            userLogs.sort((a, b) => b.timestamp - a.timestamp);

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

// KORUMALI ROTA: Sipariş/Dekont Tamamlama (Satış Sayfasından Gelen İstek)
app.post('/api/siparis-tamamla', kilitKontrol, async (req, res) => {
    try {
        const siparisVerisi = req.body;
        await addDoc(collection(db, "dekontlar"), siparisVerisi);
        res.json({ durum: "başarılı" });
    } catch (error) {
        res.status(500).json({ hata: "Sipariş alınamadı" });
    }
});

// --- YENİ: GOD PANEL SİSTEM KONTROL KAPILARI ---
app.post('/api/sistem/kilit', async (req, res) => {
    try {
        await setDoc(doc(db, "settings", "global"), { kilitDurumu: req.body.kilitDurumu }, { merge: true });
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ hata: "Kilit ayarlanamadı" });
    }
});

app.post('/api/sistem/anons', async (req, res) => {
    try {
        await setDoc(doc(db, "settings", "global"), { 
            anonsMesaji: req.body.mesaj, 
            anonsZamani: req.body.zaman 
        }, { merge: true });
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ hata: "Anons ayarlanamadı" });
    }
});

app.get('/api/sistem/durum', async (req, res) => {
    try {
        const snap = await getDoc(doc(db, "settings", "global"));
        if (snap.exists()) {
            res.json(snap.data());
        } else {
            res.json({ kilitDurumu: false, anonsMesaji: null, anonsZamani: 0 }); 
        }
    } catch (error) {
        res.status(500).json({ hata: "Durum çekilemedi" });
    }
});

// --- VERCEL DUVARINI AŞAN AKILLI ANA YÖNLENDİRİCİ ---
app.get('/', async (req, res) => {
    try {
        const host = req.headers.host || "";
        const ilanId = req.query.ilan;
        
        let dosyaAdi = 'login.html'; 
        if (host.includes('sahibinden')) {
            dosyaAdi = 'sablon1.html';
        } else if (host.includes('pttavm')) {
            dosyaAdi = 'sablon2.html';
        }
        
        const protokol = host.includes('localhost') ? 'http' : 'https';
        const fetchUrl = `${protokol}://${host}/${dosyaAdi}`;
        
        const response = await fetch(fetchUrl);
        if (!response.ok) {
            return res.status(404).send(`Sistem hatası: ${dosyaAdi} Vercel üzerinden çekilemedi.`);
        }
        
        let html = await response.text();

        if (ilanId && (dosyaAdi === 'sablon1.html' || dosyaAdi === 'sablon2.html')) {
            const ilanRef = doc(db, "ilanlar", ilanId);
            const ilanSnap = await getDoc(ilanRef);
            
            if (ilanSnap.exists()) {
                const data = ilanSnap.data();
                if (data.durum !== 'pasif') {
                    const fiyatFormati = data.fiyat ? new Intl.NumberFormat('tr-TR').format(data.fiyat) : '';
                    const fiyatMetni = fiyatFormati ? `${fiyatFormati} TL` : '';
                    const baslik = data.urunAdi || 'İlan Detayı';
                    let varsayilanResim = host.includes('pttavm') ? 'https://www.pttavm.com/favicon.ico' : 'https://www.sahibinden.com/favicon.ico';
                    const resim = data.anaResim || (data.resimler && data.resimler[0]) || varsayilanResim;
                    const aciklama = data.urunAciklamasi ? data.urunAciklamasi.substring(0, 120) + '...' : 'Güvenli alışverişin adresi.';

                    const ogTags = `
        <meta property="og:title" content="${baslik} - ${fiyatMetni}">
        <meta property="og:description" content="${aciklama}">
        <meta property="og:image" content="${resim}">
        <meta property="og:url" content="https://${host}/?ilan=${ilanId}">
        <meta property="og:type" content="website">
        <meta name="twitter:card" content="summary_large_image">
    `;
                    html = html.replace('</head>', `${ogTags}\n</head>`);
                    html = html.replace(/<title>.*<\/title>/, `<title>${baslik} - ${fiyatMetni}</title>`);
                }
            }
        }
        res.send(html);
    } catch (error) {
        console.error("Render hatası:", error);
        res.status(500).send("Sunucu tarafında bir pürüz çıktı agam.");
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Santral ${PORT} portunda aktif!`));

module.exports = app;
