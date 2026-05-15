'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';

export default function GodPanel() {
    const [stats, setStats] = useState({ total: 0, active: 0, tickets: 0 });
    const [system, setSystem] = useState({ kilitDurumu: false, sorguAktif: false, anonsMesaji: '', godBotToken: '', godChatId: '' });
    const [users, setUsers] = useState<any[]>([]);
    const [tickets, setTickets] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const router = useRouter();

    useEffect(() => {
        fetchData();
        const interval = setInterval(fetchData, 30000);
        return () => clearInterval(interval);
    }, []);

    const fetchData = async () => {
        try {
            const [statusRes, usersRes, ticketsRes] = await Promise.all([
                fetch('/api/sistem/durum'),
                fetch('/api/users'),
                fetch('/api/tickets')
            ]);

            if (statusRes.status === 401) return router.push('/login');

            const statusData = await statusRes.json();
            const usersData = await usersRes.json();
            const ticketsData = await ticketsRes.json();

            setSystem(statusData);
            setUsers(usersData);
            setTickets(ticketsData);

            const activeCount = usersData.filter((u: any) => u.isActive && !u.isBanned).length;
            const openTickets = ticketsData.filter((t: any) => t.durum === 'Acik').length;
            setStats({ total: usersData.length, active: activeCount, tickets: openTickets });
            
            setLoading(false);
        } catch (error) {
            console.error("Data fetch error", error);
        }
    };

    const handleToggleLockdown = async (val: boolean) => {
        await fetch('/api/sistem/kilit', {
            method: 'POST',
            body: JSON.stringify({ kilitDurumu: val })
        });
        setSystem({ ...system, kilitDurumu: val });
    };

    const handleLogout = async () => {
        document.cookie = "token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
        router.push('/login');
    };

    if (loading) return (
        <div className="loading-screen">
            <div className="shimmer"></div>
            <p>ERİŞİM_YETKİSİ_DOĞRULANIYOR...</p>
            <style jsx>{`
                .loading-screen { height: 100vh; background: #000; display: flex; flex-direction: column; justify-content: center; align-items: center; color: #ef4444; font-family: monospace; }
                .shimmer { width: 100px; height: 2px; background: #111; position: relative; overflow: hidden; margin-bottom: 20px; }
                .shimmer::after { content: ''; position: absolute; inset: 0; background: #ef4444; animation: slide 1.5s infinite; }
                @keyframes slide { 0% { transform: translateX(-100%); } 100% { transform: translateX(100%); } }
            `}</style>
        </div>
    );

    return (
        <div className="god-interface">
            <div className="cyber-grid"></div>
            <div className="scanline-effect"></div>

            <main className="god-content">
                <header className="god-header">
                    <div className="logo-area">
                        <div className="hazard-box">!</div>
                        <div className="title-stack">
                            <h1>GOD_COMMAND_CENTER</h1>
                            <div className="system-path">ROOT://SECURE/ADMIN/PANEL</div>
                        </div>
                    </div>
                    <div className="global-actions">
                        <div className="clock">{new Date().toLocaleTimeString()}</div>
                        <button className="danger-btn" onClick={handleLogout}>SİSTEMİ_KAPAT</button>
                    </div>
                </header>

                <div className="top-stats">
                    <div className="stat-box blue">
                        <span className="label">TOPLAM_USER</span>
                        <div className="value">{stats.total}</div>
                    </div>
                    <div className="stat-box green">
                        <span className="label">AKTİF_OTURUM</span>
                        <div className="value">{stats.active}</div>
                    </div>
                    <div className="stat-box red">
                        <span className="label">AÇIK_TALEPLER</span>
                        <div className="value">{stats.tickets}</div>
                    </div>
                    <div className="stat-box amber">
                        <span className="label">SİSTEM_GÜVENLİĞİ</span>
                        <div className="value">{system.kilitDurumu ? 'KRİTİK' : 'STABİL'}</div>
                    </div>
                </div>

                <div className="main-layout">
                    {/* Control Section */}
                    <aside className="controls-side">
                        <div className="glass-panel control-card">
                            <h3>SİSTEM_KONTROLLERİ</h3>
                            <div className="control-item">
                                <div className="info">
                                    <span className="name">Global Lockdown</span>
                                    <span className="desc">Tüm erişimi anında keser</span>
                                </div>
                                <label className="switch">
                                    <input type="checkbox" checked={system.kilitDurumu} onChange={(e) => handleToggleLockdown(e.target.checked)} />
                                    <span className="slider"></span>
                                </label>
                            </div>
                            <div className="control-item">
                                <div className="info">
                                    <span className="name">Sorgu Sistemi</span>
                                    <span className="desc">Müşteri arama motoru</span>
                                </div>
                                <span className={`status-led ${system.sorguAktif ? 'on' : 'off'}`}></span>
                            </div>
                        </div>

                        <div className="glass-panel alert-card">
                            <h3>HIZLI_EYLEM</h3>
                            <button className="action-button">+ YENİ MÜŞTERİ TANIMLA</button>
                            <button className="action-button outline">SİSTEM LOGLARINI İNCELE</button>
                        </div>
                    </aside>

                    {/* Table Section */}
                    <div className="data-area">
                        <div className="glass-panel table-panel">
                            <div className="table-header">
                                <h2>MÜŞTERİ_VERİTABANI</h2>
                                <input type="text" placeholder="FİLTRELE (KOD/İSİM)..." className="search-input" />
                            </div>
                            <div className="table-scroll">
                                <table className="cyber-table">
                                    <thead>
                                        <tr>
                                            <th>#ID</th>
                                            <th>KOD</th>
                                            <th>KULLANICI_İSMİ</th>
                                            <th>BİTİŞ_TARİHİ</th>
                                            <th>DURUM</th>
                                            <th>EYLEM</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {users.map((u, index) => (
                                            <tr key={u.docId}>
                                                <td><span className="index">{String(index + 1).padStart(2, '0')}</span></td>
                                                <td><code className="pass-code">{u.passcode}</code></td>
                                                <td className="user-name">{u.isim || 'BELİRTİLMEMİŞ'}</td>
                                                <td className="date">{u.expireDate || 'SÜRESİZ'}</td>
                                                <td>
                                                    <span className={`status-pill ${u.isBanned ? 'banned' : u.isActive ? 'active' : 'idle'}`}>
                                                        {u.isBanned ? 'YASAKLI' : u.isActive ? 'AKTİF' : 'PASİF'}
                                                    </span>
                                                </td>
                                                <td>
                                                    <div className="row-actions">
                                                        <button className="row-btn">Düzenle</button>
                                                        <button className="row-btn red">Banla</button>
                                                    </div>
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </main>

            <style jsx>{`
                .god-interface { min-height: 100vh; background: #000; color: #fff; font-family: 'JetBrains Mono', monospace; position: relative; overflow-x: hidden; }
                .cyber-grid { position: fixed; inset: 0; background-image: radial-gradient(#111 1px, transparent 1px); background-size: 30px 30px; pointer-events: none; z-index: 1; }
                .scanline-effect { position: fixed; inset: 0; background: linear-gradient(to bottom, transparent 50%, rgba(0,0,0,0.5) 51%); background-size: 100% 4px; pointer-events: none; z-index: 2; opacity: 0.1; }
                
                .god-content { position: relative; z-index: 3; max-width: 1500px; margin: 0 auto; padding: 40px; }
                
                .god-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 50px; border-bottom: 1px solid #111; padding-bottom: 20px; }
                .logo-area { display: flex; gap: 20px; align-items: center; }
                .hazard-box { width: 45px; height: 45px; background: #ef4444; color: #000; display: flex; align-items: center; justify-content: center; font-size: 1.5rem; font-weight: 900; clip-path: polygon(50% 0%, 100% 25%, 100% 75%, 50% 100%, 0% 75%, 0% 25%); }
                .title-stack h1 { font-size: 1.2rem; letter-spacing: 3px; font-weight: 900; margin: 0; }
                .system-path { font-size: 0.7rem; color: #444; margin-top: 5px; }

                .global-actions { display: flex; align-items: center; gap: 30px; }
                .clock { font-size: 1.1rem; font-weight: bold; color: #333; letter-spacing: 2px; }
                .danger-btn { background: #111; border: 1px solid #333; color: #ef4444; padding: 10px 20px; font-size: 0.8rem; font-weight: bold; cursor: pointer; transition: all 0.3s; }
                .danger-btn:hover { background: #ef4444; color: #000; border-color: #ef4444; box-shadow: 0 0 20px rgba(239,68,68,0.4); }

                .top-stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 40px; }
                .stat-box { background: #050505; border: 1px solid #111; padding: 25px; position: relative; transition: all 0.3s; }
                .stat-box:hover { border-color: currentColor; }
                .stat-box .label { font-size: 0.7rem; color: #555; display: block; margin-bottom: 10px; font-weight: bold; }
                .stat-box .value { font-size: 2.2rem; font-weight: 900; }
                .stat-box.blue { color: #3b82f6; }
                .stat-box.green { color: #22c55e; }
                .stat-box.red { color: #ef4444; }
                .stat-box.amber { color: #f59e0b; }

                .main-layout { display: grid; grid-template-columns: 350px 1fr; gap: 30px; }
                .glass-panel { background: rgba(10, 10, 10, 0.8); border: 1px solid #111; border-radius: 4px; padding: 25px; }
                
                .control-card h3, .alert-card h3, .table-header h2 { font-size: 0.85rem; color: #666; letter-spacing: 2px; margin-bottom: 25px; font-weight: bold; }
                
                .control-item { display: flex; justify-content: space-between; align-items: center; padding: 15px 0; border-bottom: 1px solid #111; }
                .control-item:last-child { border: none; }
                .control-item .info .name { display: block; font-size: 0.95rem; font-weight: bold; }
                .control-item .info .desc { font-size: 0.7rem; color: #444; }
                
                .switch { position: relative; display: inline-block; width: 44px; height: 22px; }
                .switch input { opacity: 0; width: 0; height: 0; }
                .slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: #222; transition: .4s; border-radius: 20px; }
                .slider:before { position: absolute; content: ""; height: 16px; width: 16px; left: 3px; bottom: 3px; background-color: #555; transition: .4s; border-radius: 50%; }
                input:checked + .slider { background-color: #ef4444; }
                input:checked + .slider:before { transform: translateX(22px); background-color: #fff; }
                
                .status-led { width: 12px; height: 12px; border-radius: 50%; box-shadow: inset 0 0 5px rgba(0,0,0,0.5); }
                .status-led.on { background: #22c55e; box-shadow: 0 0 10px #22c55e; }
                .status-led.off { background: #333; }

                .action-button { width: 100%; padding: 15px; margin-bottom: 10px; background: #fff; color: #000; border: none; font-weight: 900; font-size: 0.8rem; cursor: pointer; }
                .action-button.outline { background: transparent; border: 1px solid #222; color: #fff; }

                .table-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; }
                .search-input { background: #050505; border: 1px solid #111; padding: 10px 20px; color: #fff; font-family: inherit; font-size: 0.8rem; width: 300px; }
                
                .table-scroll { overflow-x: auto; }
                .cyber-table { width: 100%; border-collapse: collapse; min-width: 800px; }
                .cyber-table th { text-align: left; padding: 15px; font-size: 0.7rem; color: #444; border-bottom: 2px solid #111; }
                .cyber-table td { padding: 15px; border-bottom: 1px solid #080808; font-size: 0.9rem; }
                
                .index { color: #333; font-weight: bold; }
                .pass-code { background: #111; color: #3b82f6; padding: 3px 8px; border-radius: 3px; font-size: 0.85rem; }
                .user-name { font-weight: bold; color: #ccc; }
                .status-pill { font-size: 0.65rem; padding: 3px 8px; font-weight: 900; }
                .status-pill.active { color: #22c55e; background: rgba(34,197,94,0.05); }
                .status-pill.banned { color: #ef4444; background: rgba(239,68,68,0.05); }
                .status-pill.idle { color: #666; }

                .row-actions { display: flex; gap: 10px; }
                .row-btn { background: #111; border: 1px solid #222; color: #666; padding: 5px 10px; font-size: 0.75rem; cursor: pointer; transition: all 0.2s; }
                .row-btn:hover { background: #fff; color: #000; border-color: #fff; }
                .row-btn.red:hover { background: #ef4444; border-color: #ef4444; }

                @media (max-width: 1200px) {
                    .top-stats { grid-template-columns: repeat(2, 1fr); }
                    .main-layout { grid-template-columns: 1fr; }
                }
            `}</style>
        </div>
    );
}
