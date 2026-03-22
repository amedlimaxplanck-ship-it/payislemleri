// Eğer bilgisayarında test ediyorsan .env dosyasını okuması için bu gerekir
// Vercel'e atınca Vercel bunu otomatik halleder.
require('dotenv').config(); 

const express = require('express');
const { initializeApp } = require('firebase/app');
const { getFirestore, collection, getDocs } = require('firebase/firestore');

// VURUCU NOKTA BURASI KANKA!
// Şifreler kodun içinde yok. process.env diyerek Vercel'in kasasına el uzatıyoruz.
const firebaseConfig = {
    apiKey: process.env.FIREBASE_API_KEY,
    authDomain: process.env.FIREBASE_AUTH_DOMAIN,
    projectId: process.env.FIREBASE_PROJECT_ID,
    storageBucket: process.env.FIREBASE_STORAGE_BUCKET,
    messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID,
    appId: process.env.FIREBASE_APP_ID
};

// Kasadan alınan şifrelerle Firebase'i başlatıyoruz
const firebaseApp = initializeApp(firebaseConfig);
const db = getFirestore(firebaseApp);

const app = express();

// Tarayıcıdan senin backend'ine gelindiğinde çalışacak basit bir API köprüsü
app.get('/api/test', async (req, res) => {
    try {
        res.json({
            mesaj: "Backend tıkır tıkır çalışıyor agam!",
            durum: "Şifreler Vercel kasasında güvende, kimse göremez."
        });
    } catch (error) {
        res.status(500).json({ hata: "Bir şeyler ters gitti." });
    }
});

// Sunucuyu ayağa kaldırıyoruz
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Namussuz sunucu ${PORT} portunda nöbette!`);
});
