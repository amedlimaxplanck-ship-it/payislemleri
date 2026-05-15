'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';

export default function MusteriPanel() {
    const [user, setUser] = useState<any>(null);
    const [ilanlar, setIlanlar] = useState<any[]>([]);
    const [system, setSystem] = useState<any>(null);
    const [loading, setLoading] = useState(true);
    const [theme, setTheme] = useState('light');
    const [activeTab, setActiveTab] = useState('ilanlar');
    const [search, setSearch] = useState('');
    const router = useRouter();

    useEffect(() => {
        fetchData();
        const savedTheme = localStorage.getItem('theme') || 'light';
        setTheme(savedTheme);
        document.documentElement.setAttribute('data-theme', savedTheme);
    }, []);

    const fetchData = async () => {
        try {
            const profRes = await fetch('/api/profilim');
            if (profRes.status === 401) return router.push('/login');
            const profData = await profRes.json();
            setUser(profData);

            const [ilanRes, sysRes] = await Promise.all([
                fetch(`/api/ilanlar?userId=${profData.id}`),
                fetch('/api/sistem/durum')
            ]);

            setIlanlar(await ilanRes.json());
            setSystem(await sysRes.json());
            setLoading(false);
        } catch (error) {
            console.error("Fetch error", error);
        }
    };

    const toggleTheme = () => {
        const newTheme = theme === 'light' ? 'dark' : 'light';
        setTheme(newTheme);
        localStorage.setItem('theme', newTheme);
        document.documentElement.setAttribute('data-theme', newTheme);
    };

    const filteredIlanlar = ilanlar.filter(i => 
        (i.baslik?.toLowerCase() || '').includes(search.toLowerCase()) ||
        (i.docId?.toLowerCase() || '').includes(search.toLowerCase())
    );

    if (loading) return (
        <div className="loading-screen">
            <div className="spinner"></div>
            <p>OTURUM_AÇILIYOR...</p>
            <style jsx>{`
                .loading-screen { height: 100vh; display: flex; flex-direction: column; justify-content: center; align-items: center; background: var(--bg-body); color: var(--text-muted); font-family: inherit; }
                .spinner { width: 30px; height: 30px; border: 2px solid var(--border-color); border-top: 2px solid #007bff; border-radius: 50%; animation: spin 1s linear infinite; margin-bottom: 15px; }
                @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
            `}</style>
        </div>
    );

    return (
        <div className="panel-wrapper animate-slide-up">
            {/* Header */}
            <header className="header">
                <h1>Müşteri<span>Paneli</span></h1>
                <div className="header-controls">
                    <label className="theme-switch">
                        <input type="checkbox" checked={theme === 'dark'} onChange={toggleTheme} />
                        <span className="theme-slider"></span>
                    </label>
                    <button className="logout-btn" onClick={() => router.push('/login')}>ÇIKIŞ YAP</button>
                </div>
            </header>

            {/* Soft Ban Banner */}
            {user?.isSoftBanned && (
                <div className="soft-ban-banner">
                    <h3>DİKKAT: KISITLI ERİŞİM</h3>
                    <p>Hesabınızda şüpheli hareketler tespit edildiği için bazı özellikler kısıtlanmıştır.</p>
                </div>
            )}

            {/* System Announcement */}
            {system?.anonsMesaji && (
                <div className="god-announcement">
                    <div className="icon">📢</div>
                    <div className="text-content">
                        <span className="label">SİSTEM DUYURUSU</span>
                        <p id="announcement-text">{system.anonsMesaji}</p>
                    </div>
                </div>
            )}

            {/* Stats Grid */}
            <div className="stats-grid">
                <div className="stat-card">
                    <h3>{ilanlar.length}</h3>
                    <p>TOPLAM İLAN</p>
                </div>
                <div className="stat-card">
                    <h3>{ilanlar.filter(i => i.durum === 'aktif').length}</h3>
                    <p>AKTİF İLANLAR</p>
                </div>
                <div className="stat-card">
                    <h3>{user?.ilanKotasi === 'sinirsiz' ? '∞' : (user?.ilanKotasi || 0)}</h3>
                    <p>İLAN KOTASI</p>
                </div>
            </div>

            {/* Search */}
            <div className="search-container">
                <input 
                    type="text" 
                    className="search-input" 
                    placeholder="İlan başlığı veya ID ile ara..." 
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                />
            </div>

            {/* Tabs */}
            <div className="tabs">
                <button className={`tab-btn ${activeTab === 'ilanlar' ? 'active' : ''}`} onClick={() => setActiveTab('ilanlar')}>İLANLARIM</button>
                <button className={`tab-btn ${activeTab === 'tickets' ? 'active' : ''}`} onClick={() => setActiveTab('tickets')}>DESTEK TALEPLERİ</button>
                <button className={`tab-btn ${activeTab === 'profil' ? 'active' : ''}`} onClick={() => setActiveTab('profil')}>PROFİL AYARLARI</button>
            </div>

            {/* Tab Content */}
            <div className="tab-content active">
                {activeTab === 'ilanlar' && (
                    <div className="table-container">
                        <table>
                            <thead>
                                <tr>
                                    <th>RESİM</th>
                                    <th>İLAN BAŞLIĞI / ID</th>
                                    <th>DURUM</th>
                                    <th>TARİH</th>
                                    <th>İŞLEMLER</th>
                                </tr>
                            </thead>
                            <tbody>
                                {filteredIlanlar.length === 0 ? (
                                    <tr>
                                        <td colSpan={5} style={{textAlign:'center', padding: '40px', color: 'var(--text-muted)'}}>Henüz ilan bulunmuyor.</td>
                                    </tr>
                                ) : (
                                    filteredIlanlar.map(ilan => (
                                        <tr key={ilan.docId}>
                                            <td><div className="thumb-placeholder"></div></td>
                                            <td>
                                                <div className="ilan-title">{ilan.baslik || 'Başlıksız'}</div>
                                                <div className="ilan-id">{ilan.docId}</div>
                                            </td>
                                            <td>
                                                <span className={`badge ${ilan.durum === 'aktif' ? 'badge-success' : 'badge-danger'}`}>
                                                    {ilan.durum === 'aktif' ? 'AKTİF' : 'PASİF'}
                                                </span>
                                            </td>
                                            <td>{new Date(ilan.createdAt || Date.now()).toLocaleDateString('tr-TR')}</td>
                                            <td>
                                                <button className="action-btn">DÜZENLE</button>
                                                <button className="action-btn delete">SİL</button>
                                            </td>
                                        </tr>
                                    ))
                                )}
                            </tbody>
                        </table>
                    </div>
                )}
                {activeTab === 'tickets' && (
                    <div className="empty-tab">
                        <p>Destek sistemi yakında aktif edilecektir.</p>
                    </div>
                )}
                {activeTab === 'profil' && (
                    <div className="profile-tab">
                        <div className="profile-info">
                            <label>Kullanıcı İsmi</label>
                            <p>{user?.username || 'Belirtilmemiş'}</p>
                            <label>Üyelik Bitiş</label>
                            <p>{user?.expireDate || 'Süresiz'}</p>
                        </div>
                    </div>
                )}
            </div>

            <style jsx>{`
                .panel-wrapper { max-width: 1200px; margin: 0 auto; padding: 25px; }
                
                .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; background: var(--bg-card); padding: 18px 25px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.03); border: 1px solid var(--border-color); }
                .header h1 { font-size: 22px; font-weight: 800; color: var(--text-main); }
                .header h1 span { color: #007bff; }
                
                .header-controls { display: flex; align-items: center; gap: 20px; }
                .theme-switch { position: relative; width: 52px; height: 26px; display: inline-block; }
                .theme-switch input { opacity: 0; width: 0; height: 0; }
                .theme-slider { position: absolute; cursor: pointer; inset: 0; background-color: #e2e8f0; transition: .4s; border-radius: 34px; border: 1px solid rgba(0,0,0,0.05); }
                .theme-slider:before { position: absolute; content: ""; height: 20px; width: 20px; left: 3px; bottom: 2px; background-color: white; transition: .4s cubic-bezier(0.68, -0.55, 0.265, 1.55); border-radius: 50%; box-shadow: 0 2px 5px rgba(0,0,0,0.2); }
                input:checked + .theme-slider { background-color: #007bff; border-color: #007bff; }
                input:checked + .theme-slider:before { transform: translateX(24px); }
                
                .logout-btn { background: rgba(220, 53, 69, 0.1); color: #dc3545; border: 1px solid rgba(220, 53, 69, 0.2); padding: 8px 18px; border-radius: 8px; cursor: pointer; font-weight: 700; font-size: 13px; transition: all 0.2s; }
                .logout-btn:hover { background: #dc3545; color: white; transform: translateY(-1px); }

                .soft-ban-banner { background: rgba(239, 68, 68, 0.1); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.3); padding: 16px 20px; border-radius: 12px; margin-bottom: 20px; text-align: center; animation: pulseWarning 2s infinite; }
                .soft-ban-banner h3 { font-size: 14px; font-weight: 800; margin-bottom: 5px; }
                .soft-ban-banner p { font-size: 12px; font-weight: 600; opacity: 0.8; }

                .god-announcement { display: flex; align-items: center; gap: 15px; background: linear-gradient(135deg, #4f46e5, #312e81); color: white; padding: 16px 20px; border-radius: 12px; margin-bottom: 20px; box-shadow: 0 8px 20px var(--god-glow); border: 1px solid #3730a3; }
                .god-announcement .icon { width: 36px; height: 36px; background: rgba(255,255,255,0.15); border-radius: 50%; display: flex; align-items: center; justify-content: center; }
                .god-announcement .label { font-size: 10px; font-weight: 800; color: rgba(255,255,255,0.7); letter-spacing: 1px; }
                .god-announcement p { font-weight: 700; font-size: 14px; margin: 0; }

                .stats-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-bottom: 25px; }
                .stat-card { background: var(--bg-card); padding: 25px; border-radius: 12px; text-align: center; border: 1px solid var(--border-color); border-bottom: 4px solid #007bff; }
                .stat-card h3 { font-size: 32px; font-weight: 800; margin-bottom: 5px; }
                .stat-card p { font-size: 11px; color: var(--text-muted); font-weight: 700; letter-spacing: 1px; }

                .search-input { width: 100%; padding: 16px 20px; background: var(--input-bg); border: 1px solid var(--border-color); color: var(--text-main); border-radius: 10px; font-size: 15px; outline: none; transition: all 0.3s; }
                .search-input:focus { border-color: #007bff; box-shadow: 0 0 0 4px var(--primary-glow); transform: translateY(-1px); }

                .tabs { display: flex; gap: 10px; margin: 25px 0 20px; background: var(--bg-card); padding: 8px; border-radius: 10px; border: 1px solid var(--border-color); }
                .tab-btn { flex: 1; padding: 12px; background: transparent; border: none; border-radius: 6px; cursor: pointer; font-weight: 600; color: var(--text-muted); font-size: 13px; transition: all 0.3s; }
                .tab-btn.active { background: #007bff; color: white; box-shadow: 0 4px 12px var(--primary-glow); }

                .tab-content { background: var(--bg-card); padding: 25px; border-radius: 12px; border: 1px solid var(--border-color); box-shadow: 0 4px 20px rgba(0,0,0,0.03); }
                
                .table-container { overflow-x: auto; }
                table { width: 100%; border-collapse: collapse; min-width: 800px; }
                th { padding: 16px 20px; text-align: left; background: var(--table-header); color: var(--text-muted); font-size: 11px; font-weight: 800; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid var(--border-color); }
                td { padding: 16px 20px; border-bottom: 1px solid var(--border-color); font-size: 14px; }
                
                .thumb-placeholder { width: 50px; height: 50px; background: var(--bg-body); border-radius: 8px; border: 1px solid var(--border-color); }
                .ilan-title { font-weight: 700; color: var(--text-main); }
                .ilan-id { font-size: 11px; color: var(--text-muted); font-family: monospace; }
                
                .badge { padding: 4px 10px; border-radius: 6px; font-size: 10px; font-weight: 800; }
                .badge-success { background: rgba(16, 185, 129, 0.1); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.2); }
                .badge-danger { background: rgba(239, 68, 68, 0.1); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.2); }
                
                .action-btn { padding: 8px 12px; background: var(--bg-body); border: 1px solid var(--border-color); border-radius: 6px; cursor: pointer; font-size: 11px; font-weight: 700; margin-right: 5px; }
                .action-btn.delete { color: #ef4444; background: rgba(239, 68, 68, 0.05); }
                .action-btn:hover { background: var(--border-color); }

                .empty-tab, .profile-tab { padding: 40px; text-align: center; color: var(--text-muted); }
                .profile-info { text-align: left; max-width: 400px; margin: 0 auto; }
                .profile-info label { display: block; font-size: 11px; font-weight: 800; color: var(--text-muted); margin-bottom: 5px; text-transform: uppercase; }
                .profile-info p { font-size: 16px; font-weight: 700; color: var(--text-main); margin-bottom: 20px; }

                @media (max-width: 768px) {
                    .stats-grid { grid-template-columns: 1fr; }
                    .header { flex-direction: column; gap: 15px; }
                }
            `}</style>
        </div>
    );
}
