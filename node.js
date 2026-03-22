require('dotenv').config();
const express = require('express');
const cors = require('cors'); // HTML'in bağlanabilmesi için şart!
const { initializeApp } = require('firebase/app');
const { getFirestore, collection, addDoc, getDocs, doc, getDoc, query, where } = require('firebase/firestore');

const app = express();
app.use(cors()); // Diğer sitelerden gelen isteklere izin ver
app.use(express.json()); // Gelen paketleri oku

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

// Sunucuyu Çalıştır
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Santral ${PORT} portunda aktif!`));
