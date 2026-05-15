'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';

export default function GodPanel() {
    const [stats, setStats] = useState({ total: 0, active: 0, tickets: 0 });
    const [customers, setCustomers] = useState<any[]>([]);
    const [tickets, setTickets] = useState<any[]>([]);
    const [system, setSystem] = useState({ kilitDurumu: false, sorguAktif: false, anonsMesaji: '', godBotToken: '', godChatId: '' });
    const [activeTab, setActiveTab] = useState('dashboard');
    const [loading, setLoading] = useState(true);
    const [selectedIds, setSelectedIds] = useState<string[]>([]);
    const router = useRouter();

    useEffect(() => {
        // Force Dark Mode for God Panel
        document.documentElement.setAttribute('data-theme', 'dark');
        fetchInitialData();
        const interval = setInterval(refreshData, 30000);
        return () => clearInterval(interval);
    }, []);

    const fetchInitialData = async () => {
        try {
            const [usersRes, systemRes, ticketsRes] = await Promise.all([
                fetch('/api/users'),
                fetch('/api/sistem/durum'),
                fetch('/api/tickets')
            ]);

            if (usersRes.status === 401 || usersRes.status === 403) {
                return router.push('/login');
            }

            const users = await usersRes.json();
            const systemData = await systemRes.json();
            const ticketsData = await ticketsRes.json();

            setCustomers(Array.isArray(users) ? users.filter((u: any) => u.role === 'customer') : []);
            setSystem(systemData);
            setTickets(ticketsData);
            
            setStats({
                total: Array.isArray(users) ? users.length : 0,
                active: Array.isArray(users) ? users.filter((u: any) => u.isActive).length : 0,
                tickets: Array.isArray(ticketsData) ? ticketsData.filter((t: any) => t.durum === 'Acik').length : 0
            });

            setLoading(false);
        } catch (error) {
            console.error("Fetch error", error);
            setLoading(false);
        }
    };

    const refreshData = async () => {
        try {
            const res = await fetch('/api/users');
            if (res.ok) {
                const users = await res.json();
                setCustomers(Array.isArray(users) ? users.filter((u: any) => u.role === 'customer') : []);
            }
        } catch (e) {}
    };

    const handleLockdown = async (val: boolean) => {
        const res = await fetch('/api/sistem/kilit', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ kilitDurumu: val })
        });
        if (res.ok) {
            setSystem({ ...system, kilitDurumu: val });
        }
    };

    const handleAnonsKaydet = async () => {
        const res = await fetch('/api/sistem/anons', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ mesaj: system.anonsMesaji, zaman: new Date().toLocaleString() })
        });
        if (res.ok) alert("Anons yayınlandı!");
    };

    const handleBulkAction = async (action: string) => {
        if (selectedIds.length === 0) return alert("Seçim yapın!");
        
        if (action === 'delete') {
            if (!confirm("Seçili kullanıcıları SİLMEK istiyor musunuz?")) return;
            await Promise.all(selectedIds.map(id => fetch(`/api/users/${id}`, { method: 'DELETE' })));
        } else if (action === 'softban') {
            await Promise.all(selectedIds.map(id => fetch(`/api/users/guncelle/${id}`, { 
                method: 'PATCH', 
                headers: { 'Content-Type': 'application/json' }, 
                body: JSON.stringify({ isSoftBanned: true }) 
            })));
        }
        
        setSelectedIds([]);
        fetchInitialData();
    };

    if (loading) return <div className="loading">YÜKLENİYOR... SYSTEM_BOOT_SEQUENCE</div>;

    return (
        <div className="god-wrapper animate-slide-up">
            <header className="header">
                <div className="header-left">
                    <div className="hazard-logo">
                        <svg viewBox="0 0 24 24" width="24" height="24" fill="#fbbf24"><path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/></svg>
                    </div>
                    <h1>COMMAND<span>CENTER</span></h1>
                </div>
                <div className="header-right">
                    <button className="logout-btn" onClick={() => {
                        document.cookie = "token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
                        router.push('/login');
                    }}>GÜVENLİ ÇIKIŞ</button>
                </div>
            </header>

            <div className="stats-row">
                <div className="stat-box">
                    <span>TOPLAM FİLO</span>
                    <h2>{stats.total}</h2>
                </div>
                <div className="stat-box active-glow">
                    <span>AKTİF GÜÇ</span>
                    <h2>{stats.active}</h2>
                </div>
                <div className="stat-box warning">
                    <span>AÇIK TALEPLER</span>
                    <h2>{stats.tickets}</h2>
                </div>
            </div>

            <div className="main-grid">
                <aside className="sidebar">
                    {['dashboard', 'customers', 'tickets', 'settings'].map(tab => (
                        <button key={tab} className={`nav-item ${activeTab === tab ? 'active' : ''}`} onClick={() => setActiveTab(tab)}>
                            {tab.toUpperCase()}
                        </button>
                    ))}
                </aside>

                <main className="content">
                    {activeTab === 'dashboard' && (
                        <div className="dashboard-view">
                            <div className="system-switches">
                                <div className="switch-card">
                                    <div className="switch-info">
                                        <h3>GLOBAL LOCKDOWN</h3>
                                        <p>Tüm sistem erişimini anında dondurur.</p>
                                    </div>
                                    <label className="switch">
                                        <input type="checkbox" checked={system.kilitDurumu} onChange={(e) => handleLockdown(e.target.checked)} />
                                        <span className="slider danger"></span>
                                    </label>
                                </div>
                                
                                <div className="switch-card">
                                    <div className="switch-info">
                                        <h3>SORGU PANELİ</h3>
                                        <p>Müşteriler için sorgu servisini aç/kapat.</p>
                                    </div>
                                    <label className="switch">
                                        <input type="checkbox" checked={system.sorguAktif} />
                                        <span className="slider"></span>
                                    </label>
                                </div>
                            </div>

                            <div className="announcement-box">
                                <h3>SİSTEM ANONSU</h3>
                                <textarea 
                                    placeholder="Tüm müşterilere görünecek mesaj..." 
                                    value={system.anonsMesaji} 
                                    onChange={(e) => setSystem({...system, anonsMesaji: e.target.value})}
                                />
                                <button className="btn-save" onClick={handleAnonsKaydet}>ANONSU YAYINLA</button>
                            </div>
                        </div>
                    )}

                    {activeTab === 'customers' && (
                        <div className="customers-view">
                            <div className="bulk-actions">
                                <button className="btn-bulk" onClick={() => handleBulkAction('softban')}>SOFT-BAN AT</button>
                                <button className="btn-bulk danger" onClick={() => handleBulkAction('delete')}>SİL</button>
                            </div>
                            <div className="table-wrapper">
                                <table>
                                    <thead>
                                        <tr>
                                            <th><input type="checkbox" onChange={(e) => setSelectedIds(e.target.checked ? customers.map(c => c.docId) : [])} /></th>
                                            <th>MÜŞTERİ</th>
                                            <th>DURUM</th>
                                            <th>İŞLEM</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {customers.map(c => (
                                            <tr key={c.docId}>
                                                <td><input type="checkbox" checked={selectedIds.includes(c.docId)} onChange={() => setSelectedIds(prev => prev.includes(c.docId) ? prev.filter(id => id !== c.docId) : [...prev, c.docId])} /></td>
                                                <td>
                                                    <div className="cust-name">{c.isim || 'İsimsiz'}</div>
                                                    <div className="cust-code">{c.passcode}</div>
                                                </td>
                                                <td><span className={`badge ${c.isSoftBanned ? 'warning' : (c.isActive ? 'success' : 'muted')}`}>{c.isSoftBanned ? 'SOFTBAN' : (c.isActive ? 'AKTİF' : 'PASİF')}</span></td>
                                                <td><button className="btn-action">DÜZENLE</button></td>
                                            </tr>
                                        ))}
                                        {customers.length === 0 && <tr><td colSpan={4} style={{ textAlign: 'center', padding: '40px', color: '#444' }}>Veri bulunamadı.</td></tr>}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}
                </main>
            </div>

            <style jsx>{`
                .god-wrapper { background: #000; min-height: 100vh; color: #fff; font-family: 'Plus Jakarta Sans', sans-serif; }
                .header { padding: 30px 40px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #111; }
                .header-left { display: flex; align-items: center; gap: 15px; }
                .hazard-logo { background: rgba(251, 191, 36, 0.1); padding: 8px; border-radius: 12px; border: 1px solid rgba(251, 191, 36, 0.2); }
                h1 { font-size: 20px; font-weight: 900; letter-spacing: 2px; }
                h1 span { color: #fbbf24; }

                .logout-btn { background: #111; border: 1px solid #222; color: #f87171; padding: 10px 20px; border-radius: 10px; font-size: 11px; font-weight: 900; cursor: pointer; transition: 0.3s; }
                .logout-btn:hover { background: #f87171; color: #fff; }

                .stats-row { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; padding: 30px 40px; }
                .stat-box { background: #050505; border: 1px solid #111; padding: 25px; border-radius: 20px; }
                .stat-box span { font-size: 10px; color: #444; font-weight: 800; letter-spacing: 2px; }
                .stat-box h2 { font-size: 36px; font-weight: 900; margin-top: 10px; }
                .stat-box.warning h2 { color: #f87171; }
                .stat-box.active-glow { border-color: rgba(52, 211, 153, 0.3); box-shadow: 0 0 30px rgba(52, 211, 153, 0.05); }

                .main-grid { display: grid; grid-template-columns: 260px 1fr; gap: 40px; padding: 0 40px 40px 40px; }
                .sidebar { display: flex; flex-direction: column; gap: 10px; }
                .nav-item { background: transparent; border: 1px solid transparent; color: #444; text-align: left; padding: 15px 25px; border-radius: 16px; cursor: pointer; font-size: 12px; font-weight: 900; transition: 0.3s; }
                .nav-item.active { background: #111; color: #fff; border-color: #222; }
                .nav-item:hover:not(.active) { color: #888; }

                .content { background: #080808; border: 1px solid #111; border-radius: 32px; padding: 40px; }
                
                .system-switches { display: grid; grid-template-columns: 1fr 1fr; gap: 25px; margin-bottom: 40px; }
                .switch-card { background: #000; border: 1px solid #111; padding: 25px; border-radius: 24px; display: flex; justify-content: space-between; align-items: center; }
                .switch-info h3 { font-size: 15px; font-weight: 900; letter-spacing: 1px; }
                .switch-info p { font-size: 11px; color: #444; margin-top: 6px; }

                .announcement-box { background: #000; border: 1px solid #111; padding: 30px; border-radius: 24px; }
                .announcement-box h3 { font-size: 15px; font-weight: 900; margin-bottom: 20px; color: #fbbf24; }
                textarea { width: 100%; background: #050505; border: 1px solid #111; border-radius: 16px; padding: 20px; color: #fff; font-size: 14px; height: 120px; resize: none; margin-bottom: 20px; outline: none; }
                textarea:focus { border-color: #3b82f6; }
                .btn-save { background: #3b82f6; color: #fff; border: none; padding: 14px 28px; border-radius: 12px; font-weight: 900; font-size: 12px; cursor: pointer; transition: 0.3s; }
                .btn-save:hover { transform: translateY(-2px); box-shadow: 0 10px 20px rgba(59, 130, 246, 0.2); }

                .bulk-actions { display: flex; gap: 12px; margin-bottom: 25px; }
                .btn-bulk { background: #111; border: 1px solid #222; color: #fff; padding: 10px 20px; border-radius: 10px; font-size: 11px; font-weight: 900; cursor: pointer; transition: 0.3s; }
                .btn-bulk.danger { color: #f87171; border-color: rgba(248, 113, 113, 0.2); }
                .btn-bulk:hover { background: #222; }

                table { width: 100%; border-collapse: collapse; }
                th { text-align: left; padding: 20px; font-size: 11px; color: #444; border-bottom: 1px solid #111; letter-spacing: 1px; }
                td { padding: 20px; border-bottom: 1px solid #111; font-size: 13px; }
                .cust-name { font-weight: 900; color: #fff; }
                .cust-code { font-size: 11px; color: #444; margin-top: 4px; font-family: monospace; }
                .badge { padding: 6px 12px; border-radius: 8px; font-size: 10px; font-weight: 900; }
                .badge.success { background: rgba(52, 211, 153, 0.1); color: #34d399; }
                .badge.warning { background: rgba(251, 191, 36, 0.1); color: #fbbf24; }
                .badge.muted { background: #111; color: #444; }

                .switch { position: relative; display: inline-block; width: 50px; height: 26px; }
                .switch input { opacity: 0; width: 0; height: 0; }
                .slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: #111; transition: .4s; border-radius: 34px; border: 1px solid #222; }
                .slider:before { position: absolute; content: ""; height: 18px; width: 18px; left: 3px; bottom: 3px; background-color: #fff; transition: .4s; border-radius: 50%; }
                input:checked + .slider { background-color: #3b82f6; border-color: #3b82f6; }
                input:checked + .slider.danger { background-color: #ef4444; border-color: #ef4444; }
                input:checked + .slider:before { transform: translateX(24px); }

                .loading { height: 100vh; background: #000; color: #fff; display: flex; align-items: center; justify-content: center; font-weight: 900; letter-spacing: 4px; font-size: 12px; }
            `}</style>
        </div>
    );
}
