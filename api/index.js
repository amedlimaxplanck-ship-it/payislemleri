require('dotenv').config();
/* 🔥 VERCEL .ENV (ENVIRONMENT VARIABLES) EKLENECEK GİZLİ ANAHTARLAR 🔥
Vercel paneline gidip Settings -> Environment Variables kısmına şunları ekleyeceksin:
- UCUNCU_PARTI_API_URL = (Satın aldığın API'nin adresi örn: https://api.sorgusistemi.com/v1)
- SORGU_API_KEY = (Satın aldığın servisin sana vereceği şifre)
*/

const express = require('express');
const cors = require('cors'); 
const fs = require('fs'); 
const path = require('path'); 
const jwt = require('jsonwebtoken'); // VIP BİLET BASICI
const rateLimit = require('express-rate-limit'); // ŞİFRE DENEME KALKANI
const { initializeApp } = require('firebase/app');
const {
    getFirestore, collection, addDoc, getDocs, 
    doc, getDoc, query, where, 
    updateDoc, deleteDoc, setDoc
} = require('firebase/firestore');

const app = express();
app.use(cors()); 
app.use(express.json()); 

// Mühür için gizli anahtar
const JWT_SECRET = process.env.JWT_SECRET || 'SuperGizliAnahtar2026';

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
// 🔥 GÜVENLİK DUVARI: RATE LIMIT (BRUTE FORCE ENGELLEYİCİ) 🔥
// =================================================================
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 10, 
    message: { success: false, message: "Çok fazla deneme yaptınız. Lütfen 15 dakika sonra tekrar deneyin." },
    standardHeaders: true,
    legacyHeaders: false,
});


// =================================================================
// 🔥 1. FEDAİ: VIP KART & TEK CİHAZ (KOLTUK KAPMACA) KONTROLÜ 🔥
// =================================================================
const authKontrol = async (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(401).json({ hata: "Erişim engellendi. Geçerli bir bilet bulunamadı." });
    }

    const token = authHeader.split(' ')[1]; 

    try {
        const dogrulama = jwt.verify(token, JWT_SECRET);
        
        const userSnap = await getDoc(doc(db, "users", dogrulama.id));
        
        if (!userSnap.exists()) {
            return res.status(401).json({ hata: "Kullanıcı bulunamadı." });
        }
        
        const userData = userSnap.data();

        // 🔥 BAN KONTROLÜ 🔥
        if (userData.isBanned) {
            return res.status(403).json({ hata: `HESAP YASAKLANDI! Sebep: ${userData.banReason || 'Sistem Kuralları İhlali'}` });
        }
        
        if (userData.currentSession && userData.currentSession !== dogrulama.sessionId) {
            console.warn(`[ÇOKLU GİRİŞ YAKALANDI] Kullanıcı ID: ${dogrulama.id}`);
            return res.status(401).json({ hata: "Hesabınıza başka bir cihazdan giriş yapıldı. Oturumunuz sonlandırıldı!" });
        }

        req.user = dogrulama; 
        next(); 
    } catch (error) {
        return res.status(403).json({ hata: "Geçersiz veya süresi dolmuş bilet." });
    }
};


// =================================================================
// 🔥 2. FEDAİ: SİSTEM KİLİT KONTROLÜ 🔥
// =================================================================
const kilitKontrol = async (req, res, next) => {
    try {
        const snap = await getDoc(doc(db, "settings", "global"));
        if (snap.exists() && snap.data().kilitDurumu === true) {
            return res.status(403).json({ hata: "Sistem yönetici tarafından kilitlenmiştir. İşlem yapılamaz." });
        }
        next(); 
    } catch (error) {
        res.status(500).json({ hata: "Güvenlik protokolü doğrulanamadı." });
    }
};


// --- API KAPILARI ---

// GİRİŞ VE BİLET BASIMI
app.post('/api/login', loginLimiter, async (req, res) => {
    const { code } = req.body; 
    try {
        const q = query(collection(db, "users"), where("passcode", "==", code));
        const querySnapshot = await getDocs(q);
        
        if (querySnapshot.empty) {
            return res.status(401).json({ success: false, message: "Geçersiz erişim kodu!" });
        }
        
        const userDoc = querySnapshot.docs[0];
        const userData = userDoc.data();
        const userId = userDoc.id;

        // 🔥 BAN EKRANI 🔥
        if (userData.isBanned) {
            return res.status(403).json({ success: false, isBanned: true, message: `HESAP YASAKLANDI!\nSebep: ${userData.banReason || 'Kural İhlali'}` });
        }

        // 🔥 IP CASUSU (ŞÜPHELİ HESAP ALGILAYICI) 🔥
        const currentIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || "Bilinmeyen IP";
        let recentIps = userData.recentIps || [];
        if (!recentIps.includes(currentIp)) {
            recentIps.push(currentIp);
            if (recentIps.length > 3) recentIps.shift(); // Sadece son 3 IP'yi tut
        }
        
        const isSuspicious = recentIps.length >= 3;
        const suspicionReason = isSuspicious ? "Farklı konumlardan/cihazlardan giriş tespit edildi." : "";

        const yeniOturumKodu = Date.now().toString(); 
        
        await updateDoc(doc(db, "users", userId), { 
            currentSession: yeniOturumKodu,
            recentIps: recentIps,
            isSuspicious: isSuspicious,
            suspicionReason: suspicionReason
        });

        const token = jwt.sign(
            { id: userId, role: userData.role, sessionId: yeniOturumKodu }, 
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({ 
            success: true, 
            token: token, 
            user: { id: userId, ...userData } 
        });

    } catch (e) {
        console.error("FIREBASE GİRİŞ HATASI DETAYI:", e); 
        res.status(500).json({ success: false, message: "Sunucu hatası" });
    }
});

app.get('/api/profilim', authKontrol, async (req, res) => {
    try {
        const userSnap = await getDoc(doc(db, "users", req.user.id));
        if (userSnap.exists()) {
            const data = userSnap.data();
            res.json({ 
                success: true, 
                ilanKotasi: data.ilanKotasi || "sinirsiz",
                telegramBotToken: data.telegramBotToken || "",
                telegramChatId: data.telegramChatId || ""
            });
        } else {
            res.status(404).json({ hata: "Kullanıcı bulunamadı" });
        }
    } catch (error) {
        res.status(500).json({ hata: "Sunucu hatası" });
    }
});

app.patch('/api/profilim/guncelle', authKontrol, async (req, res) => {
    try {
        const userId = req.user.id;
        const { telegramBotToken, telegramChatId } = req.body;
        
        await updateDoc(doc(db, "users", userId), { 
            telegramBotToken: telegramBotToken || "",
            telegramChatId: telegramChatId || ""
        });
        
        res.json({ success: true, mesaj: "Ayarlar güncellendi." });
    } catch (error) {
        res.status(500).json({ hata: "Ayarlar kaydedilemedi." });
    }
});

// =================================================================
// 🔥 BAN SİSTEMİ (GOD PANEL İÇİN) 🔥
// =================================================================
app.post('/api/users/:id/banla', authKontrol, async (req, res) => {
    if (req.user.role !== 'god') {
        return res.status(403).json({ hata: "Yetkisiz işlem." });
    }
    try {
        await updateDoc(doc(db, "users", req.params.id), { 
            isBanned: true, 
            banReason: req.body.sebep, 
            isActive: false, 
            currentSession: null 
        });
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ hata: "Kullanıcı banlanamadı." });
    }
});

app.post('/api/users/:id/bankaldir', authKontrol, async (req, res) => {
    if (req.user.role !== 'god') {
        return res.status(403).json({ hata: "Yetkisiz işlem." });
    }
    try {
        await updateDoc(doc(db, "users", req.params.id), { 
            isBanned: false, 
            banReason: "", 
            recentIps: [], 
            isSuspicious: false, 
            isActive: true 
        });
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ hata: "Ban kaldırılamadı." });
    }
});

// =================================================================
// 🔥 DESTEK (TICKET) SİSTEMİ 🔥
// =================================================================
app.get('/api/tickets', authKontrol, async (req, res) => {
    try {
        let q = req.user.role === 'god' 
            ? query(collection(db, "tickets")) 
            : query(collection(db, "tickets"), where("musteriId", "==", req.user.id));
        const snap = await getDocs(q);
        res.json(snap.docs.map(doc => ({ docId: doc.id, ...doc.data() })));
    } catch (e) {
        res.status(500).json({ hata: "Biletler çekilemedi." });
    }
});

app.post('/api/tickets/ekle', authKontrol, async (req, res) => {
    try {
        await addDoc(collection(db, "tickets"), {
            musteriId: req.user.id,
            musteriKod: req.body.musteriKod,
            konu: req.body.konu,
            mesaj: req.body.mesaj,
            tarih: new Date().getTime(),
            durum: 'Acik',
            yanit: ''
        });
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ hata: "Talep açılamadı." });
    }
});

app.patch('/api/tickets/:id/yanitla', authKontrol, async (req, res) => {
    if (req.user.role !== 'god') {
        return res.status(403).json({ hata: "Yetkisiz işlem." });
    }
    try {
        await updateDoc(doc(db, "tickets", req.params.id), { 
            yanit: req.body.yanit, 
            durum: req.body.durum 
        });
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ hata: "Talep yanıtlanamadı." });
    }
});

// =================================================================
// 🔥 3. PARTİ API SORGULAMA KÖPRÜSÜ (PROXY) 🔥
// =================================================================
app.post('/api/sorgu-yap', authKontrol, kilitKontrol, async (req, res) => {
    try {
        // 1. Şalter kontrolü: God Panel'den modül aktif edilmiş mi?
        const snap = await getDoc(doc(db, "settings", "global"));
        const ayarlar = snap.exists() ? snap.data() : {};
        
        if (ayarlar.sorguAktif === false) {
            return res.status(403).json({ hata: "Sorgu sistemi şu an bakımda veya pasif durumdadır." });
        }

        const { sorguTuru, sorguDegeri } = req.body;

        // 2. 3. Parti API'ye gizli istek (API'yi aldığında burayı açacaksın)
        /*
        const response = await fetch(`${process.env.UCUNCU_PARTI_API_URL}/arama-yap`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${process.env.SORGU_API_KEY}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ tur: sorguTuru, deger: sorguDegeri })
        });
        const data = await response.json();
        return res.json(data);
        */

        // Şimdilik API hazır olana kadar test amaçlı sahte veri dönüyoruz:
        res.json({
            success: true,
            mesaj: "Sorgu modülü backend'de çalışıyor, API bağlantısı bekleniyor."
        });

    } catch (error) {
        console.error("Sorgu hatası:", error);
        res.status(500).json({ hata: "Sorgu işlemi sırasında sunucu hatası oluştu." });
    }
});

// --- İLAN YÖNETİMİ ---

app.get('/api/ilanlar-getir', authKontrol, async (req, res) => {
    const { userId } = req.query;

    if (req.user.role !== 'god' && req.user.id !== userId) {
        return res.status(403).json({ hata: "Başkasının ilanlarına erişemezsiniz." });
    }

    const q = query(collection(db, "ilanlar"), where("olusturanMusteri", "==", userId));
    const snap = await getDocs(q);
    res.json(snap.docs.map(doc => ({ docId: doc.id, ...doc.data() })));
});

app.post('/api/ilan-ekle', authKontrol, kilitKontrol, async (req, res) => {
    try {
        const userId = req.user.id;
        
        const userSnap = await getDoc(doc(db, "users", userId));
        if (!userSnap.exists()) {
            return res.status(404).json({ hata: "Kullanıcı bulunamadı." });
        }
        const userData = userSnap.data();
        
        const kota = userData.ilanKotasi || "sinirsiz";
        
        if (kota !== "sinirsiz") {
            const q = query(collection(db, "ilanlar"), where("olusturanMusteri", "==", userId));
            const ilanlarSnap = await getDocs(q);
            const mevcutIlanSayisi = ilanlarSnap.size; 
            
            if (mevcutIlanSayisi >= parseInt(kota)) {
                return res.status(403).json({ 
                    hata: `Paket limitinize (${kota} İlan) ulaştınız! Yeni ilan girmek için eskileri tamamen silmeli veya paketinizi yükseltmelisiniz.` 
                });
            }
        }

        const docRef = await addDoc(collection(db, "ilanlar"), req.body);
        res.json({ success: true, id: docRef.id });
        
    } catch (error) {
        console.error("İlan ekleme hatası:", error);
        res.status(500).json({ hata: "İlan eklenemedi." });
    }
});

app.delete('/api/ilan-sil/:id', authKontrol, kilitKontrol, async (req, res) => {
    await deleteDoc(doc(db, "ilanlar", req.params.id));
    res.json({ success: true });
});

// --- DEKONT VE LOG ---

app.get('/api/dekontlar-getir', authKontrol, async (req, res) => {
    if (req.user.role !== 'god' && req.user.id !== req.query.userId) {
        return res.status(403).json({ hata: "Yetkisiz erişim." });
    }

    const q = query(collection(db, "dekontlar"), where("saticiId", "==", req.query.userId));
    const snap = await getDocs(q);
    res.json(snap.docs.map(doc => ({ id: doc.id, ...doc.data() })));
});

app.get('/api/logs-getir', authKontrol, async (req, res) => {
    if (req.user.role !== 'god' && req.user.id !== req.query.userId) {
        return res.status(403).json({ hata: "Yetkisiz erişim." });
    }

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

// --- MÜŞTERİ YÖNETİMİ KAPILARI (God Panel Kullanır) ---

app.get('/api/users', authKontrol, async (req, res) => {
    if (req.user.role !== 'god') {
        return res.status(403).json({ hata: "Yetkisiz işlem. Tanrı değilsin!" });
    }

    try {
        const q = query(collection(db, "users"));
        const snapshot = await getDocs(q);
        const users = snapshot.docs.map(doc => ({ docId: doc.id, ...doc.data() }));
        res.json(users);
    } catch (error) {
        res.status(500).json({ hata: "Müşteriler getirilemedi" });
    }
});

app.post('/api/users/ekle', authKontrol, async (req, res) => {
    if (req.user.role !== 'god') {
        return res.status(403).json({ hata: "Yetkisiz işlem." });
    }

    try {
        const yeniMusteri = req.body;
        const docRef = await addDoc(collection(db, "users"), {
            ...yeniMusteri,
            createdAt: new Date().getTime(),
            isActive: true,
            isBanned: false,
            recentIps: [],
            isSuspicious: false,
            currentSession: null, 
            ilanKotasi: req.body.ilanKotasi || "sinirsiz" 
        });
        res.json({ success: true, id: docRef.id });
    } catch (error) {
        res.status(500).json({ hata: "Ekleme başarısız" });
    }
});

app.patch('/api/users/guncelle/:id', authKontrol, async (req, res) => {
    if (req.user.role !== 'god') {
        return res.status(403).json({ hata: "Yetkisiz işlem." });
    }

    try {
        const userRef = doc(db, "users", req.params.id);
        await updateDoc(userRef, req.body);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ hata: "Güncelleme başarısız" });
    }
});

// 🔥 YENİ: KULLANICIYI HER YERDEN (KOMPLE) SİLME OPERASYONU 🔥
app.delete('/api/users-komple-sil/:id', authKontrol, async (req, res) => {
    if (req.user.role !== 'god') {
        return res.status(403).json({ hata: "Yetkisiz işlem." });
    }

    try {
        const uid = req.params.id;
        const silmeIslemleri = [];

        // 1. Ana kullanıcıyı sil
        silmeIslemleri.push(deleteDoc(doc(db, "users", uid)));

        // 2. Kullanıcıya ait İlanları sil
        const ilanlarQ = query(collection(db, "ilanlar"), where("olusturanMusteri", "==", uid));
        const ilanlarSnap = await getDocs(ilanlarQ);
        ilanlarSnap.forEach(d => silmeIslemleri.push(deleteDoc(doc(db, "ilanlar", d.id))));

        // 3. Kullanıcıya ait Dekontları sil
        const dekontlarQ = query(collection(db, "dekontlar"), where("saticiId", "==", uid));
        const dekontlarSnap = await getDocs(dekontlarQ);
        dekontlarSnap.forEach(d => silmeIslemleri.push(deleteDoc(doc(db, "dekontlar", d.id))));

        // 4. Kullanıcıya ait Logları sil
        const logsQ = query(collection(db, "logs"), where("saticiId", "==", uid));
        const logsSnap = await getDocs(logsQ);
        logsSnap.forEach(d => silmeIslemleri.push(deleteDoc(doc(db, "logs", d.id))));

        // Bütün silme emirlerini aynı anda ateşle (Hızlandırır)
        await Promise.all(silmeIslemleri);

        res.json({ success: true });
    } catch (error) {
        console.error("Komple silme hatası:", error);
        res.status(500).json({ hata: "Silme işlemi başarısız oldu." });
    }
});

app.patch('/api/ilan-guncelle/:id', authKontrol, kilitKontrol, async (req, res) => {
    try {
        await updateDoc(doc(db, "ilanlar", req.params.id), req.body);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ hata: "Güncelleme başarısız" });
    }
});

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

app.post('/api/siparis-tamamla', kilitKontrol, async (req, res) => {
    try {
        const siparisVerisi = req.body;
        await addDoc(collection(db, "dekontlar"), siparisVerisi);

        // 🔥 TELEGRAM BİLDİRİM ATEŞLEYİCİ 🔥
        if (siparisVerisi.saticiId) {
            const saticiRef = await getDoc(doc(db, "users", siparisVerisi.saticiId));
            if (saticiRef.exists()) {
                const satici = saticiRef.data();
                if (satici.telegramBotToken && satici.telegramChatId) {
                    const mesaj = `🔔 YENİ DEKONT GELDİ!\n\n📦 İlan: ${siparisVerisi.ilanBasligi || 'Bilinmeyen İlan'}\n👤 Alıcı: ${siparisVerisi.aliciAd || 'Belirtilmedi'}\n📞 Tel: ${siparisVerisi.aliciTel || 'Belirtilmedi'}\n\nPaneli kontrol et patron!`;
                    
                    const telegramUrl = `https://api.telegram.org/bot${satici.telegramBotToken}/sendMessage`;
                    fetch(telegramUrl, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ 
                            chat_id: satici.telegramChatId, 
                            text: mesaj 
                        })
                    }).catch(err => console.error("Telegram bildirim hatası:", err));
                }
            }
        }

        res.json({ durum: "başarılı" });
    } catch (error) {
        res.status(500).json({ hata: "Sipariş alınamadı" });
    }
});

// --- GOD PANEL SİSTEM KONTROL KAPILARI ---
app.post('/api/sistem/kilit', authKontrol, async (req, res) => {
    if (req.user.role !== 'god') {
        return res.status(403).json({ hata: "Yetkisiz işlem." });
    }

    try {
        await setDoc(doc(db, "settings", "global"), { kilitDurumu: req.body.kilitDurumu }, { merge: true });
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ hata: "Kilit ayarlanamadı" });
    }
});

// 🔥 YENİ: GOD PANEL SORGU ŞALTERİ 🔥
app.post('/api/sistem/sorgu-toggle', authKontrol, async (req, res) => {
    if (req.user.role !== 'god') {
        return res.status(403).json({ hata: "Yetkisiz işlem." });
    }

    try {
        await setDoc(doc(db, "settings", "global"), { sorguAktif: req.body.aktif }, { merge: true });
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ hata: "Sorgu durumu ayarlanamadı" });
    }
});

app.post('/api/sistem/anons', authKontrol, async (req, res) => {
    if (req.user.role !== 'god') {
        return res.status(403).json({ hata: "Yetkisiz işlem." });
    }

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

app.get('/api/sistem/durum', authKontrol, async (req, res) => {
    try {
        const snap = await getDoc(doc(db, "settings", "global"));
        if (snap.exists()) {
            const veri = snap.data();
            // Eğer sorguAktif daha önce hiç ayarlanmadıysa varsayılan olarak kapalı (false) gönder
            if(veri.sorguAktif === undefined) veri.sorguAktif = false;
            res.json(veri);
        } else {
            res.json({ kilitDurumu: false, anonsMesaji: null, anonsZamani: 0, sorguAktif: false }); 
        }
    } catch (error) {
        res.status(500).json({ hata: "Durum çekilemedi" });
    }
});

// --- VERCEL DUVARINI AŞAN AKILLI ANA YÖNLENDİRİCİ ---
app.get('/:slug?', async (req, res, next) => {
    const slug = req.params.slug;
    
    // Eğer istek bir API rotasıysa pas geç
    if (slug && (slug.startsWith('api') || slug.includes('.'))) {
        return next();
    }

    try {
        const host = req.headers.host || "";
        // Hem eski ?ilan= parametresini hem de yeni /slug formatını destekler
        const arananDeger = slug || req.query.ilan; 
        
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

        if (arananDeger && (dosyaAdi === 'sablon1.html' || dosyaAdi === 'sablon2.html')) {
            let ilanData = null;
            let ilanId = null;

            // 1. Yeni Sistem: Önce "linkUzantisi" (Slug) ile veritabanında arama yap
            const q = query(collection(db, "ilanlar"), where("linkUzantisi", "==", arananDeger));
            const snap = await getDocs(q);
            
            if (!snap.empty) {
                ilanData = snap.docs[0].data();
                ilanId = snap.docs[0].id;
            } else if (arananDeger.length >= 20) {
                // 2. Eski Sistem: Bulunamazsa doğrudan ID ile arama yap
                const ilanRef = doc(db, "ilanlar", arananDeger);
                const ilanSnap = await getDoc(ilanRef);
                if (ilanSnap.exists()) {
                    ilanData = ilanSnap.data();
                    ilanId = ilanSnap.id;
                }
            }
            
            if (ilanData && ilanData.durum !== 'pasif') {
                const fiyatFormati = ilanData.fiyat ? new Intl.NumberFormat('tr-TR').format(ilanData.fiyat) : '';
                const fiyatMetni = fiyatFormati ? `${fiyatFormati} TL` : '';
                const baslik = ilanData.urunAdi || 'İlan Detayı';
                let varsayilanResim = host.includes('pttavm') ? 'https://www.pttavm.com/favicon.ico' : 'https://www.sahibinden.com/favicon.ico';
                const resim = ilanData.anaResim || (ilanData.resimler && ilanData.resimler[0]) || varsayilanResim;
                const aciklama = ilanData.urunAciklamasi ? ilanData.urunAciklamasi.substring(0, 120) + '...' : 'Güvenli alışverişin adresi.';

                const ogTags = `
    <meta property="og:title" content="${baslik} - ${fiyatMetni}">
    <meta property="og:description" content="${aciklama}">
    <meta property="og:image" content="${resim}">
    <meta property="og:url" content="https://${host}/${ilanData.linkUzantisi || ilanId}">
    <meta property="og:type" content="website">
    <meta name="twitter:card" content="summary_large_image">
    <!-- Frontend'in ilanı tanıması için ID'yi JavaScript'e enjekte et -->
    <script>window.ILAN_ID = "${ilanId}";</script>
`;
                html = html.replace('</head>', `${ogTags}\n</head>`);
                html = html.replace(/<title>.*<\/title>/, `<title>${baslik} - ${fiyatMetni}</title>`);
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
