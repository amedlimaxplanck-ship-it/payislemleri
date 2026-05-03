require('dotenv').config();
/* 🔥 VERCEL .ENV (ENVIRONMENT VARIABLES) EKLENECEK GİZLİ ANAHTARLAR 🔥
Vercel paneline gidip Settings -> Environment Variables kısmına şunları ekleyeceksin:
- UCUNCU_PARTI_API_URL = (Satın aldığın API'nin adresi örn: https://api.sorgusistemi.com/v1)
- SORGU_API_KEY = (Satın aldığın servisin sana vereceği şifre)
- CRON_SECRET = (Vercel Cron için kendi belirleyeceğin bir şifre)
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

        // 🔥 SÜRE (EXPIRE) KONTROLÜ (YENİ EKLENDİ) 🔥
        if (userData.expireDate && userData.role !== 'god') {
            const parts = userData.expireDate.split('.');
            if (parts.length === 3) {
                // Adamın süresi o günün gece 23:59:59'unda bitmiş sayılır
                const expDate = new Date(parts[2], parts[1] - 1, parts[0], 23, 59, 59).getTime();
                if (Date.now() > expDate) {
                    return res.status(403).json({ hata: userData.banMessage || "Abonelik süreniz dolmuştur. Lütfen ödemenizi yapın." });
                }
            }
        }
        
        if (userData.currentSession && userData.currentSession !== dogrulama.sessionId) {
            console.warn(`[ÇOKLU GİRİŞ YAKALANDI] Kullanıcı ID: ${dogrulama.id}`);
            return res.status(401).json({ hata: "Hesabınıza başka bir cihazdan giriş yapıldı. Oturumunuz sonlandırıldı!" });
        }

        req.user = dogrulama; 
        
        // 🔥 SOFT BAN DURUMUNU VERİTABANINDAN OKU VE REQ'E EKLE 🔥
        req.user.isSoftBanned = userData.isSoftBanned || false; 

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

// =================================================================
// 🔥 3. FEDAİ: SOFT-BAN KONTROLÜ (SADECE OKUMA) 🔥
// =================================================================
const softBanKontrol = (req, res, next) => {
    if (req.user.role !== 'god' && req.user.isSoftBanned === true) {
        return res.status(403).json({ 
            hata: "İŞLEM KISITLANDI! Abonelik süreniz dolduğu için sadece okuma modundasınız.",
            isSoftBanned: true 
        });
    }
    next();
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

        // 🔥 SÜRE (EXPIRE) KONTROLÜ GİRİŞTE DE ÇALIŞIR (YENİ EKLENDİ) 🔥
        if (userData.expireDate && userData.role !== 'god') {
            const parts = userData.expireDate.split('.');
            if (parts.length === 3) {
                const expDate = new Date(parts[2], parts[1] - 1, parts[0], 23, 59, 59).getTime();
                if (Date.now() > expDate) {
                    return res.status(403).json({ success: false, message: userData.banMessage || "Abonelik süreniz dolmuştur. Lütfen ödemenizi yapın." });
                }
            }
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
                telegramChatId: data.telegramChatId || "",
                isSoftBanned: data.isSoftBanned || false
            });
        } else {
            res.status(404).json({ hata: "Kullanıcı bulunamadı" });
        }
    } catch (error) {
        res.status(500).json({ hata: "Sunucu hatası" });
    }
});

app.patch('/api/profilim/guncelle', authKontrol, softBanKontrol, async (req, res) => {
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

app.post('/api/tickets/ekle', authKontrol, softBanKontrol, async (req, res) => {
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

app.delete('/api/tickets/:id', authKontrol, async (req, res) => {
    if (req.user.role !== 'god') {
        return res.status(403).json({ hata: "Yetkisiz işlem." });
    }
    try {
        await deleteDoc(doc(db, "tickets", req.params.id));
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ hata: "Talep silinemedi." });
    }
});

// =================================================================
// 🔥 3. PARTİ API SORGULAMA KÖPRÜSÜ (PROXY) 🔥
// =================================================================
app.post('/api/sorgu-yap', authKontrol, kilitKontrol, async (req, res) => {
    try {
        const snap = await getDoc(doc(db, "settings", "global"));
        const ayarlar = snap.exists() ? snap.data() : {};
        
        if (ayarlar.sorguAktif === false) {
            return res.status(403).json({ hata: "Sorgu sistemi şu an bakımda veya pasif durumdadır." });
        }

        const { sorguTuru, sorguDegeri } = req.body;

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

app.post('/api/ilan-ekle', authKontrol, kilitKontrol, softBanKontrol, async (req, res) => {
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

app.delete('/api/ilan-sil/:id', authKontrol, kilitKontrol, softBanKontrol, async (req, res) => {
    await deleteDoc(doc(db, "ilanlar", req.params.id));
    res.json({ success: true });
});

app.patch('/api/ilan-guncelle/:id', authKontrol, kilitKontrol, softBanKontrol, async (req, res) => {
    try {
        await updateDoc(doc(db, "ilanlar", req.params.id), req.body);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ hata: "Güncelleme başarısız" });
    }
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

app.delete('/api/dekont-sil/:id', authKontrol, softBanKontrol, async (req, res) => {
    try {
        await deleteDoc(doc(db, "dekontlar", req.params.id));
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ hata: "Dekont silinemedi" });
    }
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
            isSoftBanned: false, 
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

        silmeIslemleri.push(deleteDoc(doc(db, "users", uid)));

        const ilanlarQ = query(collection(db, "ilanlar"), where("olusturanMusteri", "==", uid));
        const ilanlarSnap = await getDocs(ilanlarQ);
        ilanlarSnap.forEach(d => silmeIslemleri.push(deleteDoc(doc(db, "ilanlar", d.id))));

        const dekontlarQ = query(collection(db, "dekontlar"), where("saticiId", "==", uid));
        const dekontlarSnap = await getDocs(dekontlarQ);
        dekontlarSnap.forEach(d => silmeIslemleri.push(deleteDoc(doc(db, "dekontlar", d.id))));

        const logsQ = query(collection(db, "logs"), where("saticiId", "==", uid));
        const logsSnap = await getDocs(logsQ);
        logsSnap.forEach(d => silmeIslemleri.push(deleteDoc(doc(db, "logs", d.id))));

        await Promise.all(silmeIslemleri);

        res.json({ success: true });
    } catch (error) {
        console.error("Komple silme hatası:", error);
        res.status(500).json({ hata: "Silme işlemi başarısız oldu." });
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
            if(veri.sorguAktif === undefined) veri.sorguAktif = false;
            res.json(veri);
        } else {
            res.json({ kilitDurumu: false, anonsMesaji: null, anonsZamani: 0, sorguAktif: false }); 
        }
    } catch (error) {
        res.status(500).json({ hata: "Durum çekilemedi" });
    }
});

// =================================================================
// 🔥 YENİ: GOD PANEL TELEGRAM AYARLARI KAYIT 🔥
// =================================================================
app.post('/api/sistem/god-ayarlar', authKontrol, async (req, res) => {
    if (req.user.role !== 'god') {
        return res.status(403).json({ hata: "Yetkisiz işlem." });
    }
    try {
        await setDoc(doc(db, "settings", "global"), { 
            godBotToken: req.body.godBotToken, 
            godChatId: req.body.godChatId 
        }, { merge: true });
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ hata: "Ayarlar kaydedilemedi" });
    }
});

// =================================================================
// 🔥 YENİ: MANUEL YEDEK (BACKUP) SİSTEMİ (TELEGRAM'A DOSYA ATAR) 🔥
// =================================================================
app.post('/api/sistem/manual-backup', authKontrol, async (req, res) => {
    if (req.user.role !== 'god') {
        return res.status(403).json({ hata: "Yetkisiz işlem." });
    }
    try {
        const snap = await getDoc(doc(db, "settings", "global"));
        const ayarlar = snap.exists() ? snap.data() : {};
        if (!ayarlar.godBotToken || !ayarlar.godChatId) {
            return res.status(400).json({ hata: "Önce Telegram ayarlarını kaydetmelisiniz." });
        }

        const usersSnap = await getDocs(query(collection(db, "users")));
        const ilanlarSnap = await getDocs(query(collection(db, "ilanlar")));
        const dekontlarSnap = await getDocs(query(collection(db, "dekontlar")));
        
        const backupData = {
            tarih: new Date().toISOString(),
            kullanicilar: usersSnap.docs.map(d => ({id: d.id, ...d.data()})),
            ilanlar: ilanlarSnap.docs.map(d => ({id: d.id, ...d.data()})),
            dekontlar: dekontlarSnap.docs.map(d => ({id: d.id, ...d.data()}))
        };

        const buffer = Buffer.from(JSON.stringify(backupData, null, 2), 'utf-8');
        const boundary = '----TelegramBoundary' + Date.now().toString(16);
        const body = Buffer.concat([
            Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="chat_id"\r\n\r\n${ayarlar.godChatId}\r\n`, 'utf-8'),
            Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="document"; filename="Santral_Yedek_${Date.now()}.json"\r\nContent-Type: application/json\r\n\r\n`, 'utf-8'),
            buffer,
            Buffer.from(`\r\n--${boundary}--\r\n`, 'utf-8')
        ]);

        const tgRes = await fetch(`https://api.telegram.org/bot${ayarlar.godBotToken}/sendDocument`, {
            method: 'POST',
            headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}` },
            body: body
        });

        if (tgRes.ok) {
            res.json({ success: true, mesaj: "Yedek Telegram'a iletildi." });
        } else {
            res.status(500).json({ hata: "Telegram'a gönderilirken hata oluştu." });
        }
    } catch (error) {
        res.status(500).json({ hata: "Yedekleme motoru çöktü." });
    }
});

// =================================================================
// 🔥 YENİ: VERCEL CRON OTOMATİK YEDEK (HER GECE ÇALIŞIR) 🔥
// =================================================================
app.get('/api/cron/backup', async (req, res) => {
    const authHeader = req.headers.authorization;
    if (process.env.CRON_SECRET && authHeader !== `Bearer ${process.env.CRON_SECRET}`) {
        return res.status(401).json({ hata: "Cron yetkisiz." });
    }

    try {
        const snap = await getDoc(doc(db, "settings", "global"));
        const ayarlar = snap.exists() ? snap.data() : {};
        if (!ayarlar.godBotToken || !ayarlar.godChatId) {
            return res.status(400).json({ hata: "Telegram ayarları yok." });
        }

        const usersSnap = await getDocs(query(collection(db, "users")));
        const ilanlarSnap = await getDocs(query(collection(db, "ilanlar")));
        
        const backupData = {
            tarih: new Date().toISOString(),
            kullanicilar: usersSnap.docs.map(d => ({id: d.id, ...d.data()})),
            ilanlar: ilanlarSnap.docs.map(d => ({id: d.id, ...d.data()}))
        };

        const buffer = Buffer.from(JSON.stringify(backupData, null, 2), 'utf-8');
        const boundary = '----TelegramBoundary' + Date.now().toString(16);
        const body = Buffer.concat([
            Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="chat_id"\r\n\r\n${ayarlar.godChatId}\r\n`, 'utf-8'),
            Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="document"; filename="Otomatik_Yedek_${Date.now()}.json"\r\nContent-Type: application/json\r\n\r\n`, 'utf-8'),
            buffer,
            Buffer.from(`\r\n--${boundary}--\r\n`, 'utf-8')
        ]);

        await fetch(`https://api.telegram.org/bot${ayarlar.godBotToken}/sendDocument`, {
            method: 'POST',
            headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}` },
            body: body
        });

        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ hata: "Cron çöktü." });
    }
});

// =================================================================
// 🔥 TELEGRAM BOT KOMUT DİNLEYİCİSİ (WEBHOOK) - UYKU SORUNU ÇÖZÜLDÜ 🔥
// =================================================================
app.post('/api/telegram-webhook', async (req, res) => {
    try {
        const body = req.body;
        let chatId, text = "", isCallback = false, callbackQueryId = null;

        if (body.message && body.message.text) {
            chatId = body.message.chat.id.toString();
            text = body.message.text.trim();
        } else if (body.callback_query) {
            chatId = body.callback_query.message.chat.id.toString();
            text = body.callback_query.data; 
            isCallback = true;
            callbackQueryId = body.callback_query.id;
        } else {
            return res.status(200).send("OK");
        }

        const snap = await getDoc(doc(db, "settings", "global"));
        const ayarlar = snap.exists() ? snap.data() : {};
        
        if (!ayarlar.godChatId || ayarlar.godChatId !== chatId) return res.status(200).send("OK");
        
        const godBotToken = ayarlar.godBotToken;
        if(!godBotToken) return res.status(200).send("OK");

        const args = text.split(' ');
        const command = args[0].toLowerCase();
        
        let replyMsg = "";
        let replyMarkup = null;

        if (command === '/start' || command === '/menu') {
            replyMsg = "👑 *God Panel Komuta Merkezi*\nLütfen yapmak istediğiniz işlemi seçin:";
            replyMarkup = {
                inline_keyboard: [
                    [{ text: "📊 Sistem Durumu", callback_data: "/durum" }],
                    [{ text: "🔒 Kısıtla (Soft-Ban)", callback_data: "/help_softban" }, { text: "🔓 Kısıt Çöz", callback_data: "/help_coz" }],
                    [{ text: "⏳ Süre Uzat", callback_data: "/help_uzat" }],
                    [{ text: "🗄️ Hemen Yedek Al", callback_data: "/yedekal" }]
                ]
            };
        }
        else if (command === '/yedekal') {
            replyMsg = "⏳ Veritabanı paketleniyor, yedek dosyanız birazdan bu sohbete düşecek patron...";
            
            const usersSnap = await getDocs(query(collection(db, "users")));
            const ilanlarSnap = await getDocs(query(collection(db, "ilanlar")));
            const dekontlarSnap = await getDocs(query(collection(db, "dekontlar")));
            
            const backupData = {
                tarih: new Date().toISOString(),
                kullanicilar: usersSnap.docs.map(d => ({id: d.id, ...d.data()})),
                ilanlar: ilanlarSnap.docs.map(d => ({id: d.id, ...d.data()})),
                dekontlar: dekontlarSnap.docs.map(d => ({id: d.id, ...d.data()}))
            };

            const buffer = Buffer.from(JSON.stringify(backupData, null, 2), 'utf-8');
            const boundary = '----TelegramBoundary' + Date.now().toString(16);
            const bodyBuffer = Buffer.concat([
                Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="chat_id"\r\n\r\n${chatId}\r\n`, 'utf-8'),
                Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="document"; filename="Santral_Yedek_${Date.now()}.json"\r\nContent-Type: application/json\r\n\r\n`, 'utf-8'),
                buffer,
                Buffer.from(`\r\n--${boundary}--\r\n`, 'utf-8')
            ]);

            fetch(`https://api.telegram.org/bot${godBotToken}/sendDocument`, {
                method: 'POST',
                headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}` },
                body: bodyBuffer
            }).catch(e => console.log(e));
        }
        else if (command === '/help_softban') {
            replyMsg = "🔒 *Soft-Ban Atmak İçin:*\nLütfen sohbete koduyla birlikte şunu yazıp gönderin:\n\n`/softban MüşteriKodu`\n(Örnek: `/softban VIP-1234`)";
        }
        else if (command === '/help_coz') {
            replyMsg = "🔓 *Kısıtlama / Ban Kaldırmak İçin:*\nLütfen sohbete koduyla birlikte şunu yazıp gönderin:\n\n`/coz MüşteriKodu`\n(Örnek: `/coz VIP-1234`)";
        }
        else if (command === '/help_uzat') {
            replyMsg = "⏳ *Süre Uzatmak İçin:*\nLütfen sohbete kodu ve gün sayısını yazıp gönderin:\n\n`/uzat MüşteriKodu GünSayısı`\n(Örnek: `/uzat VIP-1234 30`)";
        }
        else if (command === '/uzat') {
            if(args.length < 3) {
                replyMsg = "⚠️ Hatalı kullanım.\nFormat: `/uzat <MüşteriKodu> <GünSayı>`\nÖrn: `/uzat VIP-1234 30`";
            } else {
                const targetKod = args[1];
                const gunEkle = parseInt(args[2]);
                
                const q = query(collection(db, "users"), where("passcode", "==", targetKod));
                const userSnap = await getDocs(q);
                
                if(userSnap.empty) {
                    replyMsg = `❌ Müşteri bulunamadı: ${targetKod}`;
                } else {
                    const uDoc = userSnap.docs[0];
                    const uData = uDoc.data();
                    
                    let expDate = new Date();
                    if(uData.expireDate) {
                        let p = uData.expireDate.split('.');
                        if(p.length === 3) expDate = new Date(p[2], p[1]-1, p[0]);
                    }
                    
                    expDate.setDate(expDate.getDate() + gunEkle);
                    
                    await updateDoc(doc(db, "users", uDoc.id), {
                        expireDate: expDate.toLocaleDateString('tr-TR')
                    });
                    
                    replyMsg = `✅ ${targetKod} kodlu müşterinin süresi ${gunEkle} gün uzatıldı.\nYeni Bitiş: ${expDate.toLocaleDateString('tr-TR')}`;
                }
            }
        } 
        else if (command === '/softban' || command === '/kısıtla') {
            if(args.length < 2) {
                replyMsg = "⚠️ Hatalı kullanım.\nFormat: `/softban <MüşteriKodu>`\nÖrn: `/softban VIP-1234`";
            } else {
                const targetKod = args[1];
                const q = query(collection(db, "users"), where("passcode", "==", targetKod));
                const userSnap = await getDocs(q);
                
                if(userSnap.empty) {
                    replyMsg = `❌ Müşteri bulunamadı: ${targetKod}`;
                } else {
                    const uDoc = userSnap.docs[0];
                    await updateDoc(doc(db, "users", uDoc.id), { isSoftBanned: true });
                    replyMsg = `🔒 ${targetKod} kodlu müşteri SADECE OKUMA (Soft-Ban) moduna alındı.`;
                }
            }
        }
        else if (command === '/coz' || command === '/unban') {
            if(args.length < 2) {
                replyMsg = "⚠️ Hatalı kullanım.\nFormat: `/coz <MüşteriKodu>`\nÖrn: `/coz VIP-1234`";
            } else {
                const targetKod = args[1];
                const q = query(collection(db, "users"), where("passcode", "==", targetKod));
                const userSnap = await getDocs(q);
                
                if(userSnap.empty) {
                    replyMsg = `❌ Müşteri bulunamadı: ${targetKod}`;
                } else {
                    const uDoc = userSnap.docs[0];
                    await updateDoc(doc(db, "users", uDoc.id), { isSoftBanned: false, isBanned: false });
                    replyMsg = `✅ ${targetKod} kodlu müşterinin tüm kısıtlamaları ve banları kaldırıldı.`;
                }
            }
        }
        else if (command === '/durum' || command === '/stat') {
            const uSnap = await getDocs(query(collection(db, "users")));
            const iSnap = await getDocs(query(collection(db, "ilanlar")));
            const tSnap = await getDocs(query(collection(db, "tickets"), where("durum", "==", "Acik")));
            
            let toplam = 0, aktif = 0, banli = 0, soft = 0;
            uSnap.forEach(d => {
                const dt = d.data();
                if(dt.role === 'customer') {
                    toplam++;
                    if(dt.isActive) aktif++;
                    if(dt.isBanned) banli++;
                    if(dt.isSoftBanned) soft++;
                }
            });

            replyMsg = `📊 *SİSTEM DURUM RAPORU*\n\n👥 Toplam Müşteri: ${toplam}\n✅ Aktif Müşteri: ${aktif}\n🚫 Banlı: ${banli} | 🔒 Kısıtlı: ${soft}\n📦 Toplam İlan: ${iSnap.size}\n🎫 Bekleyen Talep: ${tSnap.size}`;
        }

        if(replyMsg) {
            const payload = { chat_id: chatId, text: replyMsg, parse_mode: "Markdown" };
            if (replyMarkup) {
                payload.reply_markup = replyMarkup;
            }

            await fetch(`https://api.telegram.org/bot${godBotToken}/sendMessage`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
        }

        if (isCallback) {
            await fetch(`https://api.telegram.org/bot${godBotToken}/answerCallbackQuery`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ callback_query_id: callbackQueryId })
            });
        }
        
        // BÜTÜN İŞLER BİTTİKTEN SONRA VERCEL'E UYKU İZNİ VERİYORUZ
        return res.status(200).send("OK");
        
    } catch (error) {
        console.error("Webhook hatası:", error);
        // Hata olsa bile OK gönderiyoruz ki Telegram aynı hatalı mesajı tekrar tekrar atıp spamlamasın.
        return res.status(200).send("OK");
    }
});


// --- VERCEL DUVARINI AŞAN AKILLI ANA YÖNLENDİRİCİ ---
app.get('/:slug?', async (req, res, next) => {
    const slug = req.params.slug;
    
    if (slug && (slug.startsWith('api') || slug.includes('.'))) {
        return next();
    }

    try {
        const host = req.headers.host || "";
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

            const q = query(collection(db, "ilanlar"), where("linkUzantisi", "==", arananDeger));
            const snap = await getDocs(q);
            
            if (!snap.empty) {
                ilanData = snap.docs[0].data();
                ilanId = snap.docs[0].id;
            } else if (arananDeger.length >= 20) {
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
