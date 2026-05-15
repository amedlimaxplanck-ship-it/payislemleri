'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';

export default function GodPanel() {
    const [stats, setStats] = useState({ total: 0, active: 0, tickets: 0 });
    const [system, setSystem] = useState({ kilitDurumu: false, sorguAktif: false, anonsMesaji: '' });
    const [users, setUsers] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [theme, setTheme] = useState('light');
    const [kick, setKick] = useState(false);
    const router = useRouter();

    useEffect(() => {
        fetchData();
        const savedTheme = localStorage.getItem('god_theme') || 'dark';
        setTheme(savedTheme);
        document.documentElement.setAttribute('data-theme', savedTheme);
        
        const interval = setInterval(fetchData, 10000);
        return () => clearInterval(interval);
    }, []);

    const fetchData = async () => {
        try {
            const [statusRes, usersRes] = await Promise.all([
                fetch('/api/sistem/durum'),
                fetch('/api/users')
            ]);

            if (statusRes.status === 401) return router.push('/login');

            const statusData = await statusRes.json();
            const usersData = await usersRes.json();

            setSystem(statusData);
            setUsers(usersData);

            const activeCount = usersData.filter((u: any) => u.isActive && !u.isBanned).length;
            setStats({ total: usersData.length, active: activeCount, tickets: 0 });
            
            setLoading(false);
        } catch (error) {
            console.error("Data fetch error", error);
        }
    };

    const toggleTheme = () => {
        const newTheme = theme === 'light' ? 'dark' : 'light';
        setTheme(newTheme);
        localStorage.setItem('god_theme', newTheme);
        document.documentElement.setAttribute('data-theme', newTheme);
    };

    const handleToggleLockdown = async (val: boolean) => {
        await fetch('/api/sistem/kilit', {
            method: 'POST',
            body: JSON.stringify({ kilitDurumu: val })
        });
        setSystem({ ...system, kilitDurumu: val });
    };

    const handleLogout = () => {
        document.cookie = "token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
        router.push('/login');
    };

    if (loading) return (
        <div className="loading-screen">
            <div className="spinner"></div>
            <p>ROOT_ERİŞİMİ_DOĞRULANIYOR...</p>
            <style jsx>{`
                .loading-screen { height: 100vh; display: flex; flex-direction: column; justify-content: center; align-items: center; background: #000; color: #ef4444; font-family: monospace; }
                .spinner { width: 30px; height: 30px; border: 2px solid #111; border-top: 2px solid #ef4444; border-radius: 50%; animation: spin 1s linear infinite; margin-bottom: 15px; }
                @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
            `}</style>
        </div>
    );

    return (
        <div className="god-wrapper animate-slide-up">
            {/* Header */}
            <header className="header">
                <h1>God<span>Panel</span></h1>
                <div className="header-controls">
                    <label className="theme-switch">
                        <input type="checkbox" checked={theme === 'dark'} onChange={toggleTheme} />
                        <span className="theme-slider"></span>
                    </label>
                    <button className="logout-btn" onClick={handleLogout}>GÜVENLİ ÇIKIŞ</button>
                </div>
            </header>

            {/* Stats Grid */}
            <div className="stats-grid">
                <div className="stat-card">
                    <h3>{stats.total}</h3>
                    <p>MÜŞTERİ</p>
                </div>
                <div className="stat-card">
                    <h3>{stats.active}</h3>
                    <p>AKTİF</p>
                </div>
                <div className="stat-card warning">
                    <h3>{stats.tickets}</h3>
                    <p>DESTEK TALEBİ</p>
                </div>
            </div>

            {/* Command Center */}
            <div className="command-center">
                <div className="command-title">SİSTEM KOMUTA MERKEZİ</div>
                <div className="command-grid">
                    <div className="command-box">
                        <div className="command-header">
                            <h3>Sistem Kilidi (Lockdown)</h3>
                            <label className="switch lockdown-toggle">
                                <input type="checkbox" checked={system.kilitDurumu} onChange={(e) => handleToggleLockdown(e.target.checked)} />
                                <span className="slider"></span>
                            </label>
                        </div>
                        <p>Tüm müşterilerin işlemlerini anında dondurur.</p>
                    </div>

                    <div className="command-box">
                        <div className="command-header">
                            <h3>Sorgu Modülü (API)</h3>
                            <label className="switch sorgu-toggle">
                                <input type="checkbox" checked={system.sorguAktif} disabled />
                                <span className="slider"></span>
                            </label>
                        </div>
                        <p>Müşteri sorgu panelini Aktif/Pasif yapar.</p>
                    </div>

                    <div className="command-box full-width">
                        <h3>Genel Duyuru (Anons)</h3>
                        <div className="announcement-input">
                            <input type="text" placeholder="Tüm müşterilere gidecek mesajı yazın..." value={system.anonsMesaji} readOnly />
                            <button className="btn-primary">GÖNDER</button>
                        </div>
                    </div>
                </div>
            </div>

            {/* User Management */}
            <div className="grid-container">
                <aside className="card user-form">
                    <h2>YENİ MÜŞTERİ EKLE</h2>
                    <div className="form-group">
                        <label>Müşteri İsmi</label>
                        <input type="text" placeholder="Örn: Ahmet Yılmaz" />
                    </div>
                    <div className="form-group">
                        <label>Giriş Anahtarı</label>
                        <input type="text" placeholder="Otomatik oluşturulur" />
                    </div>
                    <button className="btn-primary success">MÜŞTERİ TANIMLA</button>
                </aside>

                <div className="card table-card">
                    <h2>MÜŞTERİ VERİTABANI</h2>
                    <div className="table-responsive">
                        <table>
                            <thead>
                                <tr>
                                    <th>KOD</th>
                                    <th>KULLANICI</th>
                                    <th>BİTİŞ</th>
                                    <th>DURUM</th>
                                    <th>İŞLEMLER</th>
                                </tr>
                            </thead>
                            <tbody>
                                {users.map(u => (
                                    <tr key={u.docId}>
                                        <td><span className="passcode-badge">{u.passcode}</span></td>
                                        <td>{u.isim || 'Belirtilmemiş'}</td>
                                        <td>{u.expireDate || 'Süresiz'}</td>
                                        <td>
                                            <span className={u.isBanned ? 'alert-badge' : 'success-badge'}>
                                                {u.isBanned ? 'YASAKLI' : 'AKTİF'}
                                            </span>
                                        </td>
                                        <td>
                                            <button className="action-btn">DÜZENLE</button>
                                            <button className="action-btn danger">BANLA</button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <style jsx>{`
                .god-wrapper { max-width: 1400px; margin: 0 auto; padding: 25px; }
                
                .header { display: flex; justify-content: space-between; align-items: center; background: var(--bg-card); border: 1px solid var(--border-color); padding: 16px 20px; border-radius: 16px; margin-bottom: 24px; }
                .header h1 { font-size: 20px; font-weight: 800; }
                .header h1 span { color: var(--danger-color); }
                
                .header-controls { display: flex; align-items: center; gap: 15px; }
                .theme-switch { position: relative; display: inline-block; width: 44px; height: 24px; }
                .theme-switch input { opacity: 0; width: 0; height: 0; }
                .theme-slider { position: absolute; cursor: pointer; inset: 0; background-color: var(--border-color); transition: .3s; border-radius: 24px; border: 1px solid var(--border-color); }
                .theme-slider:before { position: absolute; content: ""; height: 16px; width: 16px; left: 3px; bottom: 3px; background-color: white; transition: .3s; border-radius: 50%; box-shadow: 0 2px 4px rgba(0,0,0,0.15); }
                input:checked + .theme-slider { background-color: var(--text-main); border-color: var(--text-main); }
                input:checked + .theme-slider:before { transform: translateX(20px); background-color: var(--bg-body); }
                
                .logout-btn { background: transparent; color: var(--text-main); border: 1px solid var(--border-color); padding: 8px 16px; border-radius: 10px; font-size: 11px; font-weight: 800; cursor: pointer; }

                .stats-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-bottom: 24px; }
                .stat-card { background: var(--bg-card); padding: 20px 10px; border-radius: 16px; border: 1px solid var(--border-color); text-align: center; }
                .stat-card h3 { font-size: 28px; font-weight: 900; margin-bottom: 2px; }
                .stat-card p { font-size: 10px; color: var(--text-muted); font-weight: 800; text-transform: uppercase; }
                .stat-card.warning h3 { color: var(--warning-color); }

                .command-center { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 16px; padding: 24px; margin-bottom: 24px; }
                .command-title { font-size: 11px; font-weight: 800; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px; margin-bottom: 20px; }
                .command-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
                .command-box { background: var(--bg-body); border: 1px solid var(--border-color); padding: 20px; border-radius: 14px; }
                .command-box.full-width { grid-column: span 2; }
                .command-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
                .command-box h3 { font-size: 14px; font-weight: 800; margin: 0; }
                .command-box p { font-size: 11px; color: var(--text-muted); }

                .switch { position: relative; display: inline-block; width: 50px; height: 28px; }
                .switch input { opacity: 0; width: 0; height: 0; }
                .slider { position: absolute; cursor: pointer; inset: 0; background-color: #27272a; transition: .3s; border-radius: 34px; }
                .slider:before { position: absolute; content: ""; height: 22px; width: 22px; left: 3px; bottom: 3px; background-color: white; transition: .3s; border-radius: 50%; }
                .lockdown-toggle input:checked + .slider { background-color: var(--danger-color); }
                .sorgu-toggle input:checked + .slider { background-color: #3b82f6; }
                .switch input:checked + .slider:before { transform: translateX(22px); }

                .grid-container { display: grid; grid-template-columns: 320px 1fr; gap: 24px; }
                .card { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 16px; padding: 24px; }
                .card h2 { font-size: 16px; font-weight: 800; margin-bottom: 24px; }

                .form-group { margin-bottom: 20px; }
                .form-group label { display: block; font-size: 10px; font-weight: 800; color: var(--text-muted); margin-bottom: 8px; text-transform: uppercase; }
                .form-group input { width: 100%; padding: 16px; border: 1px solid var(--border-color); border-radius: 12px; background: var(--bg-body); color: var(--text-main); font-size: 16px; outline: none; }
                
                .btn-primary { width: 100%; padding: 18px; background: var(--text-main); color: var(--bg-body); border: none; border-radius: 14px; font-size: 13px; font-weight: 800; text-transform: uppercase; cursor: pointer; }
                .btn-primary.success { background: var(--success-color); color: white; }

                .table-responsive { overflow-x: auto; border-radius: 14px; border: 1px solid var(--border-color); }
                table { width: 100%; border-collapse: collapse; min-width: 600px; }
                th { padding: 18px; text-align: left; background: rgba(125,125,125,0.05); color: var(--text-muted); font-size: 10px; font-weight: 900; text-transform: uppercase; }
                td { padding: 18px; border-bottom: 1px solid var(--border-color); font-size: 14px; }
                
                .passcode-badge { background: var(--bg-body); padding: 8px 12px; border-radius: 8px; font-family: monospace; font-weight: bold; border: 1px solid var(--border-color); }
                .success-badge { color: var(--success-color); font-weight: 800; font-size: 12px; }
                .alert-badge { color: var(--danger-color); font-weight: 800; font-size: 12px; background: rgba(239, 68, 68, 0.1); padding: 4px 8px; border-radius: 6px; }

                .action-btn { background: transparent; color: var(--text-main); border: 1px solid var(--border-color); padding: 8px 12px; border-radius: 8px; cursor: pointer; font-size: 11px; font-weight: 700; margin-right: 5px; }
                .action-btn.danger { color: var(--danger-color); }

                @media (max-width: 992px) {
                    .grid-container { grid-template-columns: 1fr; }
                    .command-grid { grid-template-columns: 1fr; }
                }
            `}</style>
        </div>
    );
}
