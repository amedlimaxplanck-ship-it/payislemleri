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
    const [theme, setTheme] = useState('dark');
    const [selectedIds, setSelectedIds] = useState<string[]>([]);
    const router = useRouter();

    useEffect(() => {
        fetchInitialData();
        const interval = setInterval(refreshData, 30000);
        return () => clearInterval(interval);
    }, []);

    const fetchInitialData = async () => {
        const token = document.cookie.split('; ').find(row => row.startsWith('token='))?.split('=')[1];
        if (!token) return router.push('/login');

        try {
            const [usersRes, systemRes, ticketsRes] = await Promise.all([
                fetch('/api/users', { headers: { 'Authorization': `Bearer ${token}` } }),
                fetch('/api/sistem/durum', { headers: { 'Authorization': `Bearer ${token}` } }),
                fetch('/api/tickets', { headers: { 'Authorization': `Bearer ${token}` } })
            ]);

            if (usersRes.status === 401 || usersRes.status === 403) return router.push('/login');

            const users = await usersRes.json();
            setCustomers(users.filter((u: any) => u.role === 'customer'));
            setSystem(await systemRes.json());
            setTickets(await ticketsRes.json());
            
            setStats({
                total: users.length,
                active: users.filter((u: any) => u.isActive).length,
                tickets: (await ticketsRes.json()).filter((t: any) => t.durum === 'Acik').length
            });

            setTheme(localStorage.getItem('god_theme') || 'dark');
            setLoading(false);
        } catch (error) {
            console.error("Fetch error", error);
        }
    };

    const refreshData = async () => {
        const token = document.cookie.split('; ').find(row => row.startsWith('token='))?.split('=')[1];
        if (!token) return;
        const res = await fetch('/api/users', { headers: { 'Authorization': `Bearer ${token}` } });
        if (res.ok) {
            const users = await res.json();
            setCustomers(users.filter((u: any) => u.role === 'customer'));
        }
    };

    const handleLockdown = async (val: boolean) => {
        const token = document.cookie.split('; ').find(row => row.startsWith('token='))?.split('=')[1];
        await fetch('/api/sistem/kilit', {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ kilitDurumu: val })
        });
        setSystem({ ...system, kilitDurumu: val });
    };

    const handleBulkAction = async (action: string) => {
        if (selectedIds.length === 0) return alert("Seçim yapın!");
        const token = document.cookie.split('; ').find(row => row.startsWith('token='))?.split('=')[1];
        
        if (action === 'delete') {
            if (!confirm("Seçili kullanıcıları SİLMEK istiyor musunuz?")) return;
            await Promise.all(selectedIds.map(id => fetch(`/api/users-komple-sil/${id}`, { method: 'DELETE', headers: { 'Authorization': `Bearer ${token}` } })));
        } else if (action === 'softban') {
            await Promise.all(selectedIds.map(id => fetch(`/api/users/guncelle/${id}`, { method: 'PATCH', headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ isSoftBanned: true }) })));
        }
        
        setSelectedIds([]);
        fetchInitialData();
    };

    if (loading) return <div className="loading">YÜKLENİYOR...</div>;

    return (
        <div className="god-wrapper">
            <header className="header">
                <div className="header-left">
                    <div className="hazard-logo">
                        <svg viewBox="0 0 24 24" width="24" height="24" fill="#fbbf24"><path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/></svg>
                    </div>
                    <h1>COMMAND<span>CENTER</span></h1>
                </div>
                <div className="header-right">
                    <button className="logout-btn" onClick={() => router.push('/login')}>GÜVENLİ ÇIKIŞ</button>
                </div>
            </header>

            <div className="stats-row">
                <div className="stat-box">
                    <span>TOPLAM FİLO</span>
                    <h2>{stats.total}</h2>
                </div>
                <div className="stat-box">
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
                    <button className={`nav-item ${activeTab === 'dashboard' ? 'active' : ''}`} onClick={() => setActiveTab('dashboard')}>DASHBOARD</button>
                    <button className={`nav-item ${activeTab === 'customers' ? 'active' : ''}`} onClick={() => setActiveTab('customers')}>MÜŞTERİ YÖNETİMİ</button>
                    <button className={`nav-item ${activeTab === 'tickets' ? 'active' : ''}`} onClick={() => setActiveTab('tickets')}>DESTEK MERKEZİ</button>
                    <button className={`nav-item ${activeTab['settings'] ? 'active' : ''}`} onClick={() => setActiveTab('settings')}>SİSTEM AYARLARI</button>
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
                                    <label className="switch danger">
                                        <input type="checkbox" checked={system.kilitDurumu} onChange={(e) => handleLockdown(e.target.checked)} />
                                        <span className="slider"></span>
                                    </label>
                                </div>
                                
                                <div className="switch-card">
                                    <div className="switch-info">
                                        <h3>SORGU PANELİ</h3>
                                        <p>Müşteriler için sorgu servisini aç/kapat.</p>
                                    </div>
                                    <label className="switch">
                                        <input type="checkbox" checked={system.sorguAktif} onChange={(e) => setSystem({...system, sorguAktif: e.target.checked})} />
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
                                <button className="btn-save">ANONSU YAYINLA</button>
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
                                            <th>GEÇERLİLİK</th>
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
                                                <td>{c.expireDate}</td>
                                                <td><span className={`badge ${c.isSoftBanned ? 'warning' : (c.isActive ? 'success' : 'muted')}`}>{c.isSoftBanned ? 'SOFTBAN' : (c.isActive ? 'AKTİF' : 'PASİF')}</span></td>
                                                <td><button className="btn-action">DÜZENLE</button></td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}
                </main>
            </div>

            <style jsx>{`
                .god-wrapper { background: #000; min-height: 100vh; color: #fff; font-family: 'Plus Jakarta Sans', sans-serif; }
                .header { padding: 20px 40px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #111; }
                .header-left { display: flex; align-items: center; gap: 15px; }
                .hazard-logo { background: rgba(251, 191, 36, 0.1); padding: 8px; border-radius: 10px; border: 1px solid rgba(251, 191, 36, 0.2); }
                h1 { font-size: 18px; font-weight: 900; letter-spacing: 1px; }
                h1 span { color: #fbbf24; }

                .logout-btn { background: #111; border: 1px solid #222; color: #666; padding: 8px 16px; border-radius: 8px; font-size: 10px; font-weight: 800; cursor: pointer; }

                .stats-row { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; padding: 20px 40px; }
                .stat-box { background: #050505; border: 1px solid #111; padding: 20px; border-radius: 16px; }
                .stat-box span { font-size: 10px; color: #666; font-weight: 800; letter-spacing: 1px; }
                .stat-box h2 { font-size: 32px; font-weight: 900; margin-top: 5px; }
                .stat-box.warning h2 { color: #f87171; }

                .main-grid { display: grid; grid-template-columns: 240px 1fr; gap: 40px; padding: 0 40px 40px 40px; }
                .sidebar { display: flex; flex-direction: column; gap: 8px; }
                .nav-item { background: transparent; border: 1px solid transparent; color: #666; text-align: left; padding: 12px 20px; border-radius: 12px; cursor: pointer; font-size: 11px; font-weight: 800; transition: 0.2s; }
                .nav-item.active { background: #111; color: #fff; border-color: #222; }

                .content { background: #050505; border: 1px solid #111; border-radius: 24px; padding: 30px; }
                
                .system-switches { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 30px; }
                .switch-card { background: #0a0a0a; border: 1px solid #111; padding: 20px; border-radius: 16px; display: flex; justify-content: space-between; align-items: center; }
                .switch-info h3 { font-size: 14px; font-weight: 900; }
                .switch-info p { font-size: 11px; color: #666; margin-top: 4px; }

                .announcement-box { background: #0a0a0a; border: 1px solid #111; padding: 20px; border-radius: 16px; }
                .announcement-box h3 { font-size: 14px; font-weight: 900; margin-bottom: 15px; }
                textarea { width: 100%; background: #000; border: 1px solid #111; border-radius: 12px; padding: 15px; color: #fff; font-size: 13px; height: 100px; resize: none; margin-bottom: 15px; }
                .btn-save { background: #fff; color: #000; border: none; padding: 10px 20px; border-radius: 10px; font-weight: 900; font-size: 11px; cursor: pointer; }

                .bulk-actions { display: flex; gap: 10px; margin-bottom: 20px; }
                .btn-bulk { background: #111; border: 1px solid #222; color: #fff; padding: 8px 16px; border-radius: 8px; font-size: 10px; font-weight: 800; cursor: pointer; }
                .btn-bulk.danger { color: #f87171; border-color: rgba(248, 113, 113, 0.2); }

                table { width: 100%; border-collapse: collapse; }
                th { text-align: left; padding: 15px; font-size: 10px; color: #666; border-bottom: 1px solid #111; }
                td { padding: 15px; border-bottom: 1px solid #111; font-size: 12px; }
                .cust-name { font-weight: 800; }
                .cust-code { font-size: 10px; color: #666; margin-top: 2px; }
                .badge { padding: 4px 8px; border-radius: 6px; font-size: 9px; font-weight: 900; }
                .badge.success { background: rgba(52, 211, 153, 0.1); color: #34d399; }
                .badge.warning { background: rgba(251, 191, 36, 0.1); color: #fbbf24; }
                .badge.muted { background: #111; color: #666; }

                .switch { position: relative; display: inline-block; width: 44px; height: 24px; }
                .switch input { opacity: 0; width: 0; height: 0; }
                .slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: #222; transition: .4s; border-radius: 24px; }
                .slider:before { position: absolute; content: ""; height: 18px; width: 18px; left: 3px; bottom: 3px; background-color: #fff; transition: .4s; border-radius: 50%; }
                input:checked + .slider { background-color: #3b82f6; }
                input:checked + .slider.danger { background-color: #ef4444; }
                input:checked + .slider:before { transform: translateX(20px); }

                .loading { height: 100vh; background: #000; color: #fff; display: flex; align-items: center; justify-content: center; font-weight: 900; letter-spacing: 2px; }
            `}</style>
        </div>
    );
}
