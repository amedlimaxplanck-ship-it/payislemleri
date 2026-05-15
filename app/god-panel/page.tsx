'use client';

import { useState, useEffect, useRef } from 'react';
import { useRouter } from 'next/navigation';

export default function GodPanel() {
    const [stats, setStats] = useState({ total: 0, active: 0, tickets: 0 });
    const [customers, setCustomers] = useState<any[]>([]);
    const [tickets, setTickets] = useState<any[]>([]);
    const [system, setSystem] = useState({ 
        kilitDurumu: false, 
        sorguAktif: false, 
        anonsMesaji: '', 
        godBotToken: '', 
        godChatId: '' 
    });
    const [loading, setLoading] = useState(true);
    const [theme, setTheme] = useState('dark');
    const [selectedIds, setSelectedIds] = useState<string[]>([]);
    const [isKickActive, setIsKickActive] = useState(false);
    
    // Modals
    const [isEditModalOpen, setIsEditModalOpen] = useState(false);
    const [isBanModalOpen, setIsBanModalOpen] = useState(false);
    const [isTicketModalOpen, setIsTicketModalOpen] = useState(false);
    const [isConfirmModalOpen, setIsConfirmModalOpen] = useState(false);
    
    const [editingUser, setEditingUser] = useState<any>(null);
    const [banningUserId, setBanningUserId] = useState('');
    const [banReason, setBanReason] = useState('Hesap paylaşımı / Çoklu cihaz tespiti.');
    const [viewingTicket, setViewingTicket] = useState<any>(null);
    const [ticketReply, setTicketReply] = useState('');
    const [ticketStatus, setTicketStatus] = useState('Yanitlandi');
    const [confirmData, setConfirmData] = useState({ message: '', callback: () => {}, isDanger: false });
    
    // New Customer Form
    const [newCust, setNewCust] = useState({ name: '', passcode: '', duration: '1', kota: 'sinirsiz', ozelKota: '' });

    const router = useRouter();

    useEffect(() => {
        const savedTheme = localStorage.getItem('godTheme') || 'dark';
        setTheme(savedTheme);
        document.documentElement.setAttribute('data-theme', savedTheme);
        
        fetchInitialData();
        const interval = setInterval(loadTickets, 10000);
        return () => clearInterval(interval);
    }, []);

    const fetchInitialData = async () => {
        try {
            await Promise.all([loadSystemStatus(), loadCustomers(), loadTickets()]);
            setLoading(false);
        } catch (e) {
            console.error(e);
            setLoading(false);
        }
    };

    const checkTokenError = (res: any) => {
        if (res.status === 401 || res.status === 403) {
            setIsKickActive(true);
            return true;
        }
        return false;
    };

    const loadSystemStatus = async () => {
        const res = await fetch(`/api/sistem/durum?t=${Date.now()}`);
        if (checkTokenError(res)) return;
        if (res.ok) {
            const data = await res.json();
            setSystem(data);
        }
    };

    const loadCustomers = async () => {
        const res = await fetch(`/api/users`);
        if (checkTokenError(res)) return;
        if (res.ok) {
            const data = await res.json();
            const custs = data.filter((u: any) => u.role === 'customer');
            custs.sort((a: any, b: any) => (b.createdAt || 0) - (a.createdAt || 0));
            setCustomers(custs);
            
            setStats(prev => ({
                ...prev,
                total: custs.length,
                active: custs.filter((u: any) => u.isActive).length
            }));

            // Fetch individual stats (ilan counts etc) - mimicking old version's async load
            custs.forEach((c: any) => fetchExtraStats(c.docId, c.ilanKotasi));
        }
    };

    const [extraStats, setExtraStats] = useState<any>({});
    const fetchExtraStats = async (id: string, maxKota: string) => {
        try {
            const [resLogs, resIlan] = await Promise.all([
                fetch(`/api/logs-getir?userId=${id}`),
                fetch(`/api/ilanlar-getir?userId=${id}`)
            ]);
            
            let işlemCount = 0;
            if (resLogs.ok) {
                const logs = await resLogs.json();
                işlemCount = logs.filter((l: any) => l.aksiyon && (l.aksiyon.includes("BAŞARILI") || l.aksiyon.includes("Dekont") || l.aksiyon.includes("Bitiş"))).length;
            }

            let ilanCount = 0;
            if (resIlan.ok) {
                const ilanlar = await resIlan.json();
                ilanCount = ilanlar.length;
            }

            setExtraStats((prev: any) => ({
                ...prev,
                [id]: { ilanCount, işlemCount, maxKota: maxKota || 'sinirsiz' }
            }));
        } catch (e) {}
    };

    const loadTickets = async () => {
        const res = await fetch(`/api/tickets`);
        if (res.ok) {
            const data = await res.json();
            data.sort((a: any, b: any) => (b.tarih || 0) - (a.tarih || 0));
            setTickets(data);
            setStats(prev => ({ ...prev, tickets: data.filter((t: any) => t.durum === 'Acik').length }));
        }
    };

    const handleThemeToggle = () => {
        const newTheme = theme === 'light' ? 'dark' : 'light';
        setTheme(newTheme);
        localStorage.setItem('godTheme', newTheme);
        document.documentElement.setAttribute('data-theme', newTheme);
    };

    const handleLockdown = async (checked: boolean) => {
        const res = await fetch(`/api/sistem/kilit`, { 
            method: 'POST', 
            headers: { 'Content-Type': 'application/json' }, 
            body: JSON.stringify({ kilitDurumu: checked }) 
        });
        if (checkTokenError(res)) return;
        setSystem({ ...system, kilitDurumu: checked });
        alert(checked ? "Sistem Kilitlendi!" : "Kilit Açıldı.");
    };

    const handleSorguToggle = async (checked: boolean) => {
        const res = await fetch(`/api/sistem/sorgu-toggle`, { 
            method: 'POST', 
            headers: { 'Content-Type': 'application/json' }, 
            body: JSON.stringify({ aktif: checked }) 
        });
        if (checkTokenError(res)) return;
        setSystem({ ...system, sorguAktif: checked });
        alert(checked ? "Sorgu Paneli Aktif Edildi." : "Sorgu Paneli Bakıma Alındı.");
    };

    const handleSendAnons = async () => {
        const res = await fetch(`/api/sistem/anons`, { 
            method: 'POST', 
            headers: { 'Content-Type': 'application/json' }, 
            body: JSON.stringify({ mesaj: system.anonsMesaji, zaman: Date.now() }) 
        });
        if (checkTokenError(res)) return;
        alert("Sistem Anonsu Güncellendi.");
    };

    const handleSaveGodSettings = async () => {
        const res = await fetch(`/api/sistem/god-ayarlar`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ godBotToken: system.godBotToken, godChatId: system.godChatId })
        });
        if (checkTokenError(res)) return;
        alert("God Telegram ayarları kaydedildi!");
    };

    const handleManualBackup = async () => {
        alert("Yedek hazırlanıyor, Telegram'ı kontrol et...");
        const res = await fetch(`/api/sistem/manual-backup`, { method: 'POST' });
        if (checkTokenError(res)) return;
        alert("Yedek başarıyla cebine yollandı!");
    };

    const handleAddCustomer = async () => {
        if (!newCust.passcode) return alert("Şifre girin.");
        
        let finalKota = newCust.kota;
        if (newCust.kota === 'ozel') {
            if (!newCust.ozelKota) return alert("Özel kota girin.");
            finalKota = newCust.ozelKota;
        }

        const exp = new Date();
        exp.setMonth(exp.getMonth() + parseInt(newCust.duration));

        const res = await fetch(`/api/users/ekle`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                passcode: newCust.passcode,
                isim: newCust.name || "İsimsiz Müşteri",
                role: "customer",
                expireDate: exp.toLocaleDateString('tr-TR'),
                createdDateStr: new Date().toLocaleDateString('tr-TR'),
                banMessage: "Süreniz doldu.",
                ilanKotasi: finalKota,
                isSoftBanned: false
            })
        });
        if (checkTokenError(res)) return;
        if (res.ok) {
            alert("Müşteri eklendi.");
            setNewCust({ name: '', passcode: '', duration: '1', kota: 'sinirsiz', ozelKota: '' });
            loadCustomers();
        }
    };

    const handleBulkAction = async (action: string) => {
        if (selectedIds.length === 0) return alert("Önce müşteri seçin!");
        
        if (action === 'extend') {
            if (!confirm(`Seçili ${selectedIds.length} müşteriye +30 GÜN eklemek istiyor musunuz?`)) return;
            for (let id of selectedIds) {
                const user = customers.find(u => u.docId === id);
                if (!user) continue;
                let parts = user.expireDate.split(".");
                let d = new Date(parts[2], parts[1]-1, parts[0]);
                d.setDate(d.getDate() + 30);
                await fetch(`/api/users/guncelle/${id}`, {
                    method: 'PATCH',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ expireDate: d.toLocaleDateString('tr-TR') })
                });
            }
            alert("İşlem başarılı!");
        } else if (action === 'softban') {
            if (!confirm(`Seçili ${selectedIds.length} müşteriyi Soft-Ban moduna almak istiyor musunuz?`)) return;
            await Promise.all(selectedIds.map(id => fetch(`/api/users/guncelle/${id}`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ isSoftBanned: true })
            })));
            alert("Müşteriler kısıtlandı!");
        } else if (action === 'delete') {
            if (!confirm(`Seçili ${selectedIds.length} müşteriyi SİLMEK istiyor musunuz?`)) return;
            await Promise.all(selectedIds.map(id => fetch(`/api/users-komple-sil/${id}`, { method: 'DELETE' })));
            alert("Müşteriler silindi!");
        }
        
        setSelectedIds([]);
        loadCustomers();
    };

    const handleUpdateUser = async () => {
        if (!editingUser) return;
        const res = await fetch(`/api/users/guncelle/${editingUser.docId}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                isim: editingUser.isim,
                expireDate: new Date(editingUser.expireDateVal).toLocaleDateString('tr-TR'),
                banMessage: editingUser.banMessage,
                ilanKotasi: editingUser.ilanKotasi
            })
        });
        if (res.ok) {
            setIsEditModalOpen(false);
            alert("Güncellendi.");
            loadCustomers();
        }
    };

    const handleBanUser = async () => {
        const res = await fetch(`/api/users/${banningUserId}/banla`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ sebep: banReason })
        });
        if (res.ok) {
            setIsBanModalOpen(false);
            alert("Kullanıcı Yasaklandı!");
            loadCustomers();
        }
    };

    const handleUnbanUser = async (id: string) => {
        if (!confirm("Kullanıcının yasağını kaldırmak istediğinize emin misiniz?")) return;
        const res = await fetch(`/api/users/${id}/bankaldir`, { method: 'POST' });
        if (res.ok) {
            alert("Yasak Kaldırıldı.");
            loadCustomers();
        }
    };

    const handleDeleteUser = async (id: string) => {
        if (!confirm("Müşteriyi komple silmek istediğinize emin misiniz?")) return;
        const res = await fetch(`/api/users-komple-sil/${id}`, { method: 'DELETE' });
        if (res.ok) {
            alert("Müşteri kazındı!");
            loadCustomers();
        }
    };

    const handleToggleActive = async (id: string, active: boolean) => {
        await fetch(`/api/users/guncelle/${id}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ isActive: active })
        });
        loadCustomers();
    };

    const handleToggleSoftBan = async (id: string, status: boolean) => {
        await fetch(`/api/users/guncelle/${id}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ isSoftBanned: status })
        });
        alert(status ? "Soft-Ban atıldı." : "Kısıt kaldırıldı.");
        loadCustomers();
    };

    const handleSubmitTicket = async () => {
        const res = await fetch(`/api/tickets/${viewingTicket.docId}/yanitla`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ yanit: ticketReply, durum: ticketStatus })
        });
        if (res.ok) {
            setIsTicketModalOpen(false);
            alert("Yanıtlandı.");
            loadTickets();
        }
    };

    const parseDateForInput = (s: string) => {
        if (!s) return "";
        let p = s.split(".");
        return p.length === 3 ? `${p[2]}-${p[1].padStart(2, '0')}-${p[0].padStart(2, '0')}` : "";
    };

    if (loading) return <div className="loading">SİSTEM YÜKLENİYOR...</div>;

    return (
        <div className="god-body">
            {isKickActive && (
                <div id="kick-overlay" className="active">
                    <div className="kick-card">
                        <svg viewBox="0 0 24 24" fill="none" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <circle cx="12" cy="12" r="10"></circle>
                            <line x1="12" y1="8" x2="12" y2="12"></line>
                            <line x1="12" y1="16" x2="12.01" y2="16"></line>
                        </svg>
                        <h2>Oturum Yenilendi</h2>
                        <p>Güvenliğiniz için bağlantınız yenilendi. Başka bir cihazdan giriş yapmış veya sayfayı arka planda bekletmiş olabilirsiniz.</p>
                        <button className="kick-btn" onClick={() => router.push('/login')}>Tekrar Giriş Yap</button>
                    </div>
                </div>
            )}

            <div className="header animate-in">
                <h1>God<span>Panel</span></h1>
                <div className="header-controls">
                    <label className="theme-switch" title="Gece/Gündüz Modu">
                        <input type="checkbox" checked={theme === 'dark'} onChange={handleThemeToggle} />
                        <span className="theme-slider"></span>
                    </label>
                    <button className="logout-btn" onClick={() => {
                        document.cookie = "token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
                        router.push('/login');
                    }}>Çıkış Yap</button>
                </div>
            </div>

            <div className="stats-grid animate-in delay-1">
                <div className="stat-card">
                    <div className="stat-info">
                        <h3>{stats.total}</h3>
                        <p>Müşteri</p>
                    </div>
                </div>
                <div className="stat-card">
                    <div className="stat-info">
                        <h3>{stats.active}</h3>
                        <p>Aktif</p>
                    </div>
                </div>
                <div className="stat-card">
                    <div className="stat-info">
                        <h3 style={{ color: 'var(--warning-color)' }}>{stats.tickets}</h3>
                        <p>Destek Talebi</p>
                    </div>
                </div>
            </div>

            <div className="command-center animate-in delay-2">
                <div className="command-title">Sistem Komuta Merkezi</div>
                
                <div className="command-grid">
                    <div className="command-box">
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                            <h3>Sistem Kilidi (Lockdown)</h3>
                            <label className="switch lockdown-toggle">
                                <input type="checkbox" checked={system.kilitDurumu} onChange={(e) => handleLockdown(e.target.checked)} />
                                <span className="slider"></span>
                            </label>
                        </div>
                        <p>Tüm müşterilerin işlemlerini anında dondurur.</p>
                    </div>

                    <div className="command-box">
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                            <h3>Sorgu Modülü (API)</h3>
                            <label className="switch sorgu-toggle">
                                <input type="checkbox" checked={system.sorguAktif} onChange={(e) => handleSorguToggle(e.target.checked)} />
                                <span className="slider"></span>
                            </label>
                        </div>
                        <p>Müşterilerin TC/Adres vb. sorgu panelini Aktif/Pasif yapar.</p>
                    </div>
                    
                    <div className="command-box full-width">
                        <h3>Genel Duyuru (Anons)</h3>
                        <p>Paneli açık olan tüm müşterilere bildirim düşürür.</p>
                        <div style={{ display: 'flex', gap: '10px', marginTop: '15px' }}>
                            <input type="text" className="god-input" placeholder="Mesajı yazın..." value={system.anonsMesaji} onChange={(e) => setSystem({ ...system, anonsMesaji: e.target.value })} />
                            <button className="btn-primary" style={{ width: '120px' }} onClick={handleSendAnons}>Yayınla</button>
                        </div>
                    </div>

                    <div className="command-box full-width">
                        <h3>God Telegram & Güvenlik Ayarları</h3>
                        <p>Otomatik yedeklemeler ve uzaktan komutlar için kendi botunu bağla.</p>
                        <div className="form-grid-inner">
                            <div className="form-group-inner">
                                <label>Admin Bot Token</label>
                                <input type="text" placeholder="BotFather'dan aldığın token" value={system.godBotToken} onChange={(e) => setSystem({ ...system, godBotToken: e.target.value })} />
                            </div>
                            <div className="form-group-inner">
                                <label>Admin Chat ID</label>
                                <input type="text" placeholder="Senin chat ID'n" value={system.godChatId} onChange={(e) => setSystem({ ...system, godChatId: e.target.value })} />
                            </div>
                        </div>
                        <div style={{ display: 'flex', gap: '10px', marginTop: '20px' }}>
                            <button className="btn-primary" style={{ background: 'var(--success-color)', color: 'white' }} onClick={handleSaveGodSettings}>Ayarları Kaydet</button>
                            <button className="btn-primary" style={{ background: '#3b82f6', color: 'white' }} onClick={handleManualBackup}>Hemen Yedek Al (Cebine At)</button>
                        </div>
                    </div>
                </div>
            </div>

            <div className="grid-container animate-in delay-2">
                <div className="card" style={{ height: 'fit-content' }}>
                    <h2>Müşteri Oluştur</h2>
                    
                    <div className="form-group">
                        <label>Takma İsim / Müşteri Adı</label>
                        <input type="text" placeholder="Örn: Ahmet Abi (Adana)" value={newCust.name} onChange={(e) => setNewCust({ ...newCust, name: e.target.value })} />
                    </div>

                    <div className="form-group">
                        <label>Erişim Kodu (Şifre)</label>
                        <input type="text" placeholder="Örn: VIP-1234" value={newCust.passcode} onChange={(e) => setNewCust({ ...newCust, passcode: e.target.value })} />
                    </div>
                    
                    <div className="form-group">
                        <label>Abonelik Süresi</label>
                        <select value={newCust.duration} onChange={(e) => setNewCust({ ...newCust, duration: e.target.value })}>
                            <option value="1">1 Aylık</option>
                            <option value="3">3 Aylık</option>
                            <option value="6">6 Aylık</option>
                            <option value="12">1 Yıllık</option>
                        </select>
                    </div>

                    <div className="form-group">
                        <label>İlan Kotası (Paket Limiti)</label>
                        <select value={newCust.kota} onChange={(e) => setNewCust({ ...newCust, kota: e.target.value })}>
                            <option value="sinirsiz">Sınırsız İlan</option>
                            <option value="5">Maksimum 5 İlan</option>
                            <option value="10">Maksimum 10 İlan</option>
                            <option value="15">Maksimum 15 İlan</option>
                            <option value="ozel">Özel Sayı Gir...</option>
                        </select>
                    </div>

                    {newCust.kota === 'ozel' && (
                        <div className="form-group" style={{ marginTop: '-10px' }}>
                            <input type="number" placeholder="Örn: 20" value={newCust.ozelKota} onChange={(e) => setNewCust({ ...newCust, ozelKota: e.target.value })} />
                        </div>
                    )}
                    
                    <button className="btn-primary" onClick={handleAddCustomer}>Sisteme Kaydet</button>
                </div>

                <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
                    <div className="db-header">
                        <h2 style={{ margin: 0, padding: 0 }}>Müşteri Veritabanı</h2>
                        <div className="filo-buttons">
                            <button className="action-btn" onClick={() => handleBulkAction('extend')}>+30 Gün Uzat</button>
                            <button className="action-btn" style={{ color: '#8b5cf6', borderColor: 'rgba(139,92,246,0.3)' }} onClick={() => handleBulkAction('softban')}>Toplu Soft-Ban</button>
                            <button className="action-btn" style={{ color: 'var(--danger-color)', borderColor: 'var(--danger-color)' }} onClick={() => handleBulkAction('delete')}>Çöpleri Sil</button>
                        </div>
                    </div>

                    <div className="table-responsive" style={{ border: 'none', borderRadius: 0, minHeight: '400px', marginBottom: 0 }}>
                        <table className="db-table">
                            <colgroup>
                                <col style={{ width: '40px' }} />
                                <col style={{ width: '100px' }} />
                                <col style={{ width: '130px' }} />
                                <col style={{ width: '150px' }} />
                                <col style={{ width: '100px' }} />
                                <col style={{ width: '130px' }} />
                                <col style={{ width: '80px' }} />
                                <col style={{ width: '220px' }} />
                            </colgroup>
                            <thead>
                                <tr>
                                    <th><input type="checkbox" className="cust-checkbox" onChange={(e) => setSelectedIds(e.target.checked ? customers.map(c => c.docId) : [])} /></th>
                                    <th>Kayıt</th>
                                    <th>Müşteri Bilgisi</th>
                                    <th>Kota & İşlem</th>
                                    <th>Bitiş</th>
                                    <th>Risk Durumu</th>
                                    <th>Erişim</th>
                                    <th>Aksiyon</th>
                                </tr>
                            </thead>
                            <tbody>
                                {customers.map(c => {
                                    const extra = extraStats[c.docId] || { ilanCount: 0, işlemCount: 0, maxKota: 'sinirsiz' };
                                    const isBanned = c.isBanned;
                                    const isSoftBanned = c.isSoftBanned;
                                    const isSuspicious = c.isSuspicious;
                                    
                                    let kg = extra.maxKota === "sinirsiz" ? "Sınırsız" : extra.maxKota;
                                    let kotaColor = (extra.maxKota !== "sinirsiz" && extra.ilanCount >= parseInt(extra.maxKota)) ? "var(--danger-color)" : "var(--success-color)";

                                    return (
                                        <tr key={c.docId} style={{ opacity: isBanned ? 0.6 : 1 }}>
                                            <td><input type="checkbox" className="cust-checkbox" checked={selectedIds.includes(c.docId)} onChange={() => setSelectedIds(prev => prev.includes(c.docId) ? prev.filter(id => id !== c.docId) : [...prev, c.docId])} /></td>
                                            <td style={{ color: 'var(--text-secondary)', fontSize: '11px' }}>{c.createdDateStr || '-'}</td>
                                            <td>
                                                <div className="cust-name-text">{c.isim || 'İsimsiz Müşteri'}</div>
                                                <span className="passcode-badge">{c.passcode}</span>
                                            </td>
                                            <td>
                                                <div style={{ fontWeight: 800, fontSize: '16px', color: kotaColor }}>
                                                    {extra.ilanCount} <span style={{ color: 'var(--text-secondary)', fontSize: '13px', fontWeight: 400 }}>/ {kg}</span>
                                                </div>
                                                <div className="success-badge">{extra.işlemCount} İŞLEM</div>
                                            </td>
                                            <td style={{ fontWeight: 600 }}>{c.expireDate || '-'}</td>
                                            <td>
                                                {isBanned ? (
                                                    <span className="alert-badge" style={{ background: 'var(--danger-color)', color: 'white' }}>YASAKLI</span>
                                                ) : isSoftBanned ? (
                                                    <span className="alert-badge" style={{ background: 'rgba(139,92,246,0.1)', color: '#8b5cf6', borderColor: 'rgba(139,92,246,0.3)' }}>SADECE OKUMA</span>
                                                ) : isSuspicious ? (
                                                    <span className="alert-badge" title={c.suspicionReason}>⚠️ ŞÜPHELİ IP</span>
                                                ) : (
                                                    <span style={{ fontSize: '11px', color: 'var(--success-color)', fontWeight: 600 }}>Güvenli</span>
                                                )}
                                            </td>
                                            <td>
                                                <label className="switch user-toggle">
                                                    <input type="checkbox" checked={c.isActive} onChange={(e) => handleToggleActive(c.docId, e.target.checked)} />
                                                    <span className="slider"></span>
                                                </label>
                                            </td>
                                            <td>
                                                <div style={{ display: 'flex', gap: '5px' }}>
                                                    <button className="action-btn" onClick={() => {
                                                        setEditingUser({ ...c, expireDateVal: parseDateForInput(c.expireDate) });
                                                        setIsEditModalOpen(true);
                                                    }}>Ayar</button>
                                                    {isBanned ? (
                                                        <button className="action-btn" style={{ color: 'var(--success-color)', borderColor: 'var(--success-color)' }} onClick={() => handleUnbanUser(c.docId)}>Ban Kaldır</button>
                                                    ) : (
                                                        <button className="action-btn" style={{ color: 'var(--warning-color)', borderColor: 'var(--warning-color)' }} onClick={() => { setBanningUserId(c.docId); setIsBanModalOpen(true); }}>Banla</button>
                                                    )}
                                                    {isSoftBanned ? (
                                                        <button className="action-btn" style={{ color: 'var(--success-color)', borderColor: 'var(--success-color)' }} onClick={() => handleToggleSoftBan(c.docId, false)}>Kısıt Çöz</button>
                                                    ) : (
                                                        <button className="action-btn" style={{ color: '#8b5cf6', borderColor: 'rgba(139,92,246,0.3)' }} onClick={() => handleToggleSoftBan(c.docId, true)}>Soft-Ban</button>
                                                    )}
                                                    <button className="action-btn" style={{ color: 'var(--danger-color)', borderColor: 'var(--danger-color)' }} onClick={() => handleDeleteUser(c.docId)}>Sil</button>
                                                </div>
                                            </td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>

                    <h2 style={{ padding: '24px 24px 0 24px' }}>Destek Talepleri (Tickets)</h2>
                    <div className="table-responsive" style={{ border: 'none', borderTop: '1px solid var(--border-subtle)', borderRadius: 0, borderBottom: 0, minHeight: '250px' }}>
                        <table>
                            <colgroup>
                                <col style={{ width: '140px' }} />
                                <col style={{ width: 'auto' }} />
                                <col style={{ width: '120px' }} />
                                <col style={{ width: '150px' }} />
                            </colgroup>
                            <thead>
                                <tr>
                                    <th>Müşteri Bilgisi</th>
                                    <th>Konu</th>
                                    <th>Durum</th>
                                    <th>İşlem</th>
                                </tr>
                            </thead>
                            <tbody>
                                {tickets.map(t => {
                                    const cust = customers.find(u => u.docId === t.musteriId || u.passcode === t.musteriKod);
                                    return (
                                        <tr key={t.docId}>
                                            <td>
                                                <div>{cust ? (cust.isim || 'İsimsiz') : 'Bilinmiyor'}</div>
                                                <span className="passcode-badge">{cust ? cust.passcode : t.musteriKod}</span>
                                            </td>
                                            <td>{t.konu}</td>
                                            <td style={{ fontWeight: 800 }}>{t.durum === 'Acik' ? 'AÇIK YENİ' : t.durum}</td>
                                            <td><button className="action-btn" onClick={() => {
                                                setViewingTicket(t);
                                                setTicketReply(t.yanit || '');
                                                setTicketStatus(t.durum === 'Kapali' ? 'Kapali' : 'Yanitlandi');
                                                setIsTicketModalOpen(true);
                                            }}>Yanıtla</button></td>
                                        </tr>
                                    );
                                })}
                                {tickets.length === 0 && <tr><td colSpan={4} style={{ textAlign: 'center', padding: '20px' }}>Talep bulunamadı.</td></tr>}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            {/* MODALS */}
            {isEditModalOpen && editingUser && (
                <div className="modal" style={{ display: 'flex' }} onClick={(e) => e.target === e.currentTarget && setIsEditModalOpen(false)}>
                    <div className="modal-content">
                        <span className="close-modal" onClick={() => setIsEditModalOpen(false)}>&times;</span>
                        <h2 className="modal-title">Müşteri Ayarları</h2>
                        <div className="form-group">
                            <label>Takma İsim / Müşteri Adı</label>
                            <input type="text" value={editingUser.isim} onChange={(e) => setEditingUser({ ...editingUser, isim: e.target.value })} />
                        </div>
                        <div className="form-group">
                            <label>Erişim Kodu</label>
                            <input type="text" value={editingUser.passcode} readOnly style={{ opacity: 0.5 }} />
                        </div>
                        <div className="form-group">
                            <label>Bitiş Tarihi</label>
                            <input type="date" value={editingUser.expireDateVal} onChange={(e) => setEditingUser({ ...editingUser, expireDateVal: e.target.value })} />
                        </div>
                        <div className="form-group">
                            <label>İlan Kotası</label>
                            <input type="text" value={editingUser.ilanKotasi} onChange={(e) => setEditingUser({ ...editingUser, ilanKotasi: e.target.value })} />
                        </div>
                        <div className="form-group">
                            <label>Ban Mesajı</label>
                            <input type="text" value={editingUser.banMessage} onChange={(e) => setEditingUser({ ...editingUser, banMessage: e.target.value })} />
                        </div>
                        <button className="btn-primary" onClick={handleUpdateUser}>Güncelle</button>
                    </div>
                </div>
            )}

            {isBanModalOpen && (
                <div className="modal" style={{ display: 'flex' }} onClick={(e) => e.target === e.currentTarget && setIsBanModalOpen(false)}>
                    <div className="modal-content">
                        <span className="close-modal" onClick={() => setIsBanModalOpen(false)}>&times;</span>
                        <h2 className="modal-title" style={{ color: 'var(--danger-color)' }}>Hesabı Yasakla (Ban)</h2>
                        <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '20px' }}>Kullanıcı giriş yapmaya çalıştığında bu sebebi görecektir.</p>
                        <div className="form-group">
                            <label>Ban Sebebi</label>
                            <input type="text" value={banReason} onChange={(e) => setBanReason(e.target.value)} />
                        </div>
                        <button className="btn-primary btn-danger" onClick={handleBanUser}>Kullanıcıyı Banla</button>
                    </div>
                </div>
            )}

            {isTicketModalOpen && viewingTicket && (
                <div className="modal" style={{ display: 'flex' }} onClick={(e) => e.target === e.currentTarget && setIsTicketModalOpen(false)}>
                    <div className="modal-content" style={{ maxWidth: '500px' }}>
                        <span className="close-modal" onClick={() => setIsTicketModalOpen(false)}>&times;</span>
                        <h2 className="modal-title">Talep İnceleme</h2>
                        <div className="ticket-message-box">
                            <strong style={{ color: 'var(--text-secondary)', fontSize: '10px' }}>MÜŞTERİ MESAJI:</strong><br />
                            <span style={{ display: 'block', marginTop: '8px', lineHeight: '1.6' }}>{viewingTicket.mesaj}</span>
                        </div>
                        <div className="form-group">
                            <label>Yönetici Yanıtı (Sizin Cevabınız)</label>
                            <textarea rows={4} className="god-textarea" value={ticketReply} onChange={(e) => setTicketReply(e.target.value)} placeholder="Bu talebe vereceğiniz yanıtı buraya yazın..."></textarea>
                        </div>
                        <div className="form-group">
                            <label>Talep Durumu</label>
                            <select value={ticketStatus} onChange={(e) => setTicketStatus(e.target.value)}>
                                <option value="Yanitlandi">Yanıtlandı Olarak İşaretle</option>
                                <option value="Kapali">Talebi Kapat</option>
                            </select>
                        </div>
                        <button className="btn-primary btn-success" onClick={handleSubmitTicket}>Yanıtı Kaydet ve Gönder</button>
                    </div>
                </div>
            )}

            <style jsx global>{`
                :root {
                    --bg-base: #f4f4f5; 
                    --bg-surface: #ffffff; 
                    --bg-card: #fafafa; 
                    --border-subtle: rgba(0, 0, 0, 0.08);
                    --text-primary: #09090b; 
                    --text-secondary: #71717a; 
                    --danger-color: #ef4444;
                    --success-color: #10b981;
                    --warning-color: #f59e0b;
                    --switch-bg: #e4e4e7;
                    --switch-knob: #ffffff;
                    --modal-overlay: rgba(255, 255, 255, 0.85);
                }

                [data-theme="dark"] {
                    --bg-base: #000000;
                    --bg-surface: #0a0a0b;
                    --bg-card: #121214;
                    --border-subtle: rgba(255, 255, 255, 0.08);
                    --text-primary: #ffffff;
                    --text-secondary: #a1a1aa;
                    --switch-bg: #27272a;
                    --switch-knob: #a1a1aa;
                    --modal-overlay: rgba(0, 0, 0, 0.85);
                }

                .god-body {
                    background-color: var(--bg-base); 
                    color: var(--text-primary);
                    font-family: 'Plus Jakarta Sans', sans-serif;
                    min-height: 100vh;
                    padding: 25px;
                    transition: background-color 0.4s, color 0.4s;
                }

                .animate-in { animation: slideUpFade 0.6s cubic-bezier(0.16, 1, 0.3, 1) both; }
                .delay-1 { animation-delay: 0.1s; }
                .delay-2 { animation-delay: 0.2s; }
                @keyframes slideUpFade { 
                    from { opacity: 0; transform: translateY(20px); } 
                    to { opacity: 1; transform: translateY(0); } 
                }

                .header {
                    display: flex; justify-content: space-between; align-items: center;
                    background: var(--bg-surface); border: 1px solid var(--border-subtle);
                    padding: 16px 20px; border-radius: 16px; margin-bottom: 24px;
                }
                .header h1 { font-size: 20px; font-weight: 800; letter-spacing: -0.5px; margin: 0; }
                .header h1 span { color: var(--danger-color); }
                .header-controls { display: flex; align-items: center; gap: 15px; }

                .theme-switch { position: relative; display: inline-block; width: 44px; height: 24px; }
                .theme-switch input { opacity: 0; width: 0; height: 0; }
                .theme-slider { 
                    position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; 
                    background-color: var(--switch-bg); transition: .3s; border-radius: 24px; border: 1px solid var(--border-subtle);
                }
                .theme-slider:before { 
                    position: absolute; content: ""; height: 16px; width: 16px; left: 3px; bottom: 3px; 
                    background-color: var(--switch-knob); transition: .3s; border-radius: 50%; box-shadow: 0 2px 4px rgba(0,0,0,0.15);
                }
                .theme-switch input:checked + .theme-slider { background-color: var(--text-primary); border-color: var(--text-primary); }
                .theme-switch input:checked + .theme-slider:before { transform: translateX(20px); background-color: var(--bg-base); }

                .logout-btn {
                    background: transparent; color: var(--text-primary); border: 1px solid var(--border-subtle); 
                    padding: 8px 16px; border-radius: 10px; font-size: 11px; font-weight: 800; text-transform: uppercase; cursor: pointer;
                }

                .stats-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-bottom: 24px; }
                .stat-card { background: var(--bg-surface); padding: 20px 10px; border-radius: 16px; border: 1px solid var(--border-subtle); text-align: center; }
                .stat-info h3 { font-size: 28px; font-weight: 900; margin: 0; }
                .stat-info p { font-size: 10px; color: var(--text-secondary); font-weight: 800; text-transform: uppercase; margin: 0; }

                .command-center { background: var(--bg-surface); border: 1px solid var(--border-subtle); border-radius: 16px; padding: 24px; margin-bottom: 24px; }
                .command-title { font-size: 11px; font-weight: 800; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 1px; margin-bottom: 20px; }
                .command-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
                .command-box { background: var(--bg-card); border: 1px solid var(--border-subtle); padding: 20px; border-radius: 14px; }
                .command-box.full-width { grid-column: span 2; }
                .command-box h3 { font-size: 14px; font-weight: 800; margin: 0 0 5px 0; }
                .command-box p { font-size: 11px; color: var(--text-secondary); margin-bottom: 15px; }

                .switch { position: relative; display: inline-block; width: 50px; height: 28px; }
                .switch input { opacity: 0; width: 0; height: 0; }
                .slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: #27272a; transition: .3s; border-radius: 34px; }
                .slider:before { position: absolute; content: ""; height: 22px; width: 22px; left: 3px; bottom: 3px; background-color: white; transition: .3s; border-radius: 50%; box-shadow: 0 2px 4px rgba(0,0,0,0.3); }
                .lockdown-toggle input:checked + .slider { background-color: var(--danger-color); }
                .sorgu-toggle input:checked + .slider { background-color: #3b82f6; }
                .switch input:checked + .slider:before { transform: translateX(22px); }

                .god-input { width: 100%; padding: 12px 16px; border: 1px solid var(--border-subtle); border-radius: 12px; background: var(--bg-card); color: var(--text-primary); outline: none; }
                .form-grid-inner { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-top: 15px; }
                .form-group-inner label { display: block; font-size: 10px; font-weight: 800; color: var(--text-secondary); text-transform: uppercase; margin-bottom: 5px; }
                .form-group-inner input { width: 100%; padding: 12px 16px; border: 1px solid var(--border-subtle); border-radius: 12px; background: var(--bg-card); color: var(--text-primary); outline: none; }

                .grid-container { display: grid; grid-template-columns: 320px 1fr; gap: 24px; }
                .card { background: var(--bg-surface); border: 1px solid var(--border-subtle); border-radius: 16px; padding: 24px; }
                .card h2 { font-size: 16px; font-weight: 800; margin-bottom: 24px; margin-top: 0; }
                .form-group { margin-bottom: 20px; }
                .form-group label { display: block; margin-bottom: 8px; font-size: 10px; font-weight: 800; color: var(--text-secondary); text-transform: uppercase; }
                .form-group input, .form-group select, .form-group textarea {
                    width: 100%; padding: 16px; border: 1px solid var(--border-subtle); border-radius: 12px; background: var(--bg-card); color: var(--text-primary); outline: none; font-size: 14px;
                }
                .btn-primary { 
                    width: 100%; padding: 18px; background: var(--text-primary); color: var(--bg-base); border: none; border-radius: 14px; 
                    font-size: 13px; font-weight: 800; text-transform: uppercase; cursor: pointer; transition: 0.2s;
                }
                .btn-primary:active { transform: scale(0.96); opacity: 0.8; }
                .btn-danger { background: var(--danger-color) !important; color: white !important; }
                .btn-success { background: var(--success-color) !important; color: white !important; }

                .db-header { padding: 20px 24px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-subtle); flex-wrap: wrap; gap: 15px; }
                .filo-buttons { display: flex; gap: 10px; }
                .action-btn { background: transparent; color: var(--text-primary); border: 1px solid var(--border-subtle); padding: 8px 12px; border-radius: 8px; cursor: pointer; font-size: 11px; font-weight: 700; transition: 0.2s; white-space: nowrap; }
                .action-btn:active { background: var(--text-primary); color: var(--bg-base); transform: scale(0.95); }

                .table-responsive { overflow-x: auto; }
                table { width: 100%; border-collapse: collapse; min-width: 900px; }
                th, td { padding: 18px; text-align: left; border-bottom: 1px solid var(--border-subtle); font-size: 14px; }
                th { font-size: 10px; font-weight: 900; color: var(--text-secondary); text-transform: uppercase; background: rgba(125,125,125,0.05); }

                .cust-name-text { font-weight: 800; font-size: 12px; margin-bottom: 4px; color: var(--text-primary); }
                .passcode-badge { background: var(--bg-surface); padding: 4px 6px; border-radius: 8px; font-family: monospace; font-weight: bold; border: 1px solid var(--border-subtle); display: inline-block; font-size: 10px; }
                .success-badge { color: var(--success-color); font-weight: 800; font-size: 12px; margin-top: 4px; }
                .alert-badge { padding: 4px 8px; border-radius: 6px; font-size: 11px; font-weight: bold; white-space: nowrap; border: 1px solid transparent; }
                .cust-checkbox { width: 16px; height: 16px; cursor: pointer; accent-color: var(--text-primary); }

                .modal { 
                    display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; 
                    background: var(--modal-overlay); backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px); 
                    padding: 20px; align-items: center; justify-content: center; 
                }
                .modal-content { 
                    background: var(--bg-surface); border: 1px solid var(--border-subtle); border-radius: 20px; padding: 30px; 
                    width: 100%; max-width: 400px; position: relative; box-shadow: 0 25px 50px rgba(0,0,0,0.1); 
                    animation: modalPop 0.4s cubic-bezier(0.16, 1, 0.3, 1); 
                }
                @keyframes modalPop { 0% { opacity: 0; transform: scale(0.95) translateY(20px); } 100% { opacity: 1; transform: scale(1) translateY(0); } }
                .close-modal { position: absolute; right: 20px; top: 20px; color: var(--text-secondary); font-size: 24px; cursor: pointer; line-height: 1; }
                .modal-title { margin: 0 0 24px 0; font-size: 18px; font-weight: 800; }

                .ticket-message-box { background: var(--bg-card); padding: 15px; border-radius: 10px; font-size:13px; margin-bottom: 15px; border:1px solid var(--border-subtle); max-height: 200px; overflow-y: auto; word-break: break-word; }
                .god-textarea { width: 100%; padding: 16px; border: 1px solid var(--border-subtle); border-radius: 12px; background: var(--bg-card); color: var(--text-primary); outline: none; font-size: 14px; resize: vertical; }

                #kick-overlay {
                    display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: 999999; 
                    background: rgba(255, 255, 255, 0.7); backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px); 
                    align-items: center; justify-content: center; opacity: 0; transition: opacity 0.4s ease; 
                }
                #kick-overlay.active { display: flex; opacity: 1; }
                [data-theme="dark"] #kick-overlay { background: rgba(9, 9, 11, 0.85); }
                .kick-card { background: var(--bg-card); padding: 40px; border-radius: 20px; text-align: center; max-width: 420px; box-shadow: 0 30px 60px -12px rgba(59, 130, 246, 0.25); border: 1px solid rgba(59, 130, 246, 0.3); transform: scale(0.95); transition: transform 0.4s cubic-bezier(0.16, 1, 0.3, 1); }
                .kick-card svg { width: 60px; height: 60px; stroke: #3b82f6; margin-bottom: 20px; animation: pulseWarning 2s infinite; }
                @keyframes pulseWarning { 0% { transform: scale(1); opacity: 1; } 50% { transform: scale(1.1); opacity: 0.7; } 100% { transform: scale(1); opacity: 1; } }
                .kick-btn { background: #3b82f6; color: white; border: none; padding: 14px 30px; border-radius: 10px; font-weight: 700; font-size: 14px; cursor: pointer; width: 100%; }

                .loading { height: 100vh; background: #000; color: #fff; display: flex; align-items: center; justify-content: center; font-weight: 900; letter-spacing: 4px; font-size: 12px; }

                @media (max-width: 992px) {
                    .grid-container { grid-template-columns: 1fr; }
                    .command-grid { grid-template-columns: 1fr; }
                    .command-box.full-width { grid-column: span 1; }
                }
            `}</style>
        </div>
    );
}
