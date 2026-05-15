'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';

export default function MusteriPanel() {
    const [user, setUser] = useState<any>(null);
    const [ilanlar, setIlanlar] = useState<any[]>([]);
    const [system, setSystem] = useState<any>(null);
    const [loading, setLoading] = useState(true);
    const router = useRouter();

    useEffect(() => {
        fetchData();
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

    if (loading) return (
        <div className="loading-screen">
            <div className="spinner"></div>
            <p>SİSTEM_YÜKLENİYOR...</p>
            <style jsx>{`
                .loading-screen { height: 100vh; background: #050505; display: flex; flex-direction: column; justify-content: center; align-items: center; color: #3b82f6; font-family: monospace; letter-spacing: 2px; }
                .spinner { width: 40px; height: 40px; border: 2px solid #111; border-top: 2px solid #3b82f6; border-radius: 50%; animation: spin 1s linear infinite; margin-bottom: 20px; }
                @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
            `}</style>
        </div>
    );

    return (
        <div className="supa-panel">
            {/* Background Effects */}
            <div className="grid-overlay"></div>
            <div className="scanlines"></div>

            <main className="panel-content">
                <header className="main-header">
                    <div className="brand">
                        <div className="pulse"></div>
                        <h1>SUPA_DASHBOARD <span className="version">v2.0</span></h1>
                    </div>
                    <div className="user-info">
                        <span className="status-badge">ONLINE</span>
                        <p className="username">{user?.username || 'KULLANICI'}</p>
                        <button className="logout-btn" onClick={() => router.push('/login')}>GÜVENLİ ÇIKIŞ</button>
                    </div>
                </header>

                {system?.anonsMesaji && (
                    <div className="system-alert">
                        <div className="alert-icon">!</div>
                        <div className="alert-text">
                            <span className="label">SİSTEM MESAJI:</span>
                            <p>{system.anonsMesaji}</p>
                        </div>
                    </div>
                )}

                <div className="dashboard-grid">
                    {/* Stats Section */}
                    <section className="stats-grid">
                        <div className="glass-card stat-card">
                            <span className="card-label">AKTİF İLANLAR</span>
                            <div className="card-value">
                                <span className="big-num">{ilanlar.length}</span>
                                <span className="slash">/</span>
                                <span className="limit">{user?.ilanKotasi === 'sinirsiz' ? '∞' : (user?.ilanKotasi || 0)}</span>
                            </div>
                            <div className="progress-bar">
                                <div className="progress-fill" style={{ width: `${Math.min((ilanlar.length / (user?.ilanKotasi === 'sinirsiz' ? 100 : (user?.ilanKotasi || 1))) * 100, 100)}%` }}></div>
                            </div>
                        </div>

                        <div className="glass-card stat-card">
                            <span className="card-label">SİSTEM DURUMU</span>
                            <div className="card-value">
                                <span className={`status-text ${system?.kilitDurumu ? 'locked' : 'active'}`}>
                                    {system?.kilitDurumu ? 'ERİŞİM KISITLI' : 'TAM ERİŞİM'}
                                </span>
                            </div>
                            <p className="card-subtext">Son güncelleme: {new Date().toLocaleTimeString()}</p>
                        </div>
                    </section>

                    {/* Listings Section */}
                    <section className="listings-section">
                        <div className="section-header">
                            <h2>MEVCUT_İLANLAR</h2>
                            <button className="add-btn">+ YENİ EKLE</button>
                        </div>

                        <div className="ilan-grid">
                            {ilanlar.length === 0 ? (
                                <div className="empty-state">
                                    <p>Görüntülenecek ilan bulunamadı.</p>
                                </div>
                            ) : (
                                ilanlar.map(ilan => (
                                    <div key={ilan.docId} className="glass-card ilan-item">
                                        <div className="ilan-info">
                                            <h3>{ilan.baslik || 'Başlıksız İlan'}</h3>
                                            <p className="id-tag">ID: {ilan.docId.slice(0,8)}...</p>
                                        </div>
                                        <div className="ilan-status">
                                            <span className={`badge ${ilan.durum === 'aktif' ? 'success' : 'warning'}`}>
                                                {ilan.durum?.toUpperCase() || 'BEKLEMEDE'}
                                            </span>
                                            <button className="action-btn">DÜZENLE</button>
                                        </div>
                                    </div>
                                ))
                            )}
                        </div>
                    </section>
                </div>
            </main>

            <style jsx>{`
                .supa-panel { min-height: 100vh; background: #050505; color: #fff; font-family: 'Inter', sans-serif; position: relative; overflow-x: hidden; }
                .grid-overlay { position: fixed; inset: 0; background-image: linear-gradient(rgba(20, 20, 20, 0.5) 1px, transparent 1px), linear-gradient(90deg, rgba(20, 20, 20, 0.5) 1px, transparent 1px); background-size: 40px 40px; pointer-events: none; z-index: 1; }
                .scanlines { position: fixed; inset: 0; background: linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.1) 50%), linear-gradient(90deg, rgba(255, 0, 0, 0.02), rgba(0, 255, 0, 0.01), rgba(0, 0, 255, 0.02)); background-size: 100% 4px, 3px 100%; pointer-events: none; z-index: 2; opacity: 0.3; }
                
                .panel-content { position: relative; z-index: 3; max-width: 1200px; margin: 0 auto; padding: 40px 20px; }
                
                .main-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 40px; border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 20px; }
                .brand { display: flex; align-items: center; gap: 15px; }
                .brand h1 { font-size: 1.2rem; letter-spacing: 2px; font-weight: 800; margin: 0; }
                .version { font-size: 0.7rem; color: #3b82f6; opacity: 0.7; }
                .pulse { width: 10px; height: 10px; background: #3b82f6; border-radius: 50%; box-shadow: 0 0 15px #3b82f6; animation: pulse 2s infinite; }
                
                @keyframes pulse { 0% { opacity: 0.4; transform: scale(1); } 50% { opacity: 1; transform: scale(1.2); } 100% { opacity: 0.4; transform: scale(1); } }

                .user-info { display: flex; align-items: center; gap: 20px; }
                .status-badge { font-size: 0.65rem; background: rgba(34, 197, 94, 0.1); color: #22c55e; padding: 3px 8px; border-radius: 4px; border: 1px solid rgba(34, 197, 94, 0.2); }
                .username { font-weight: 600; color: #aaa; margin: 0; }
                .logout-btn { background: none; border: 1px solid #333; color: #666; padding: 8px 15px; border-radius: 6px; cursor: pointer; font-size: 0.8rem; transition: all 0.3s; }
                .logout-btn:hover { border-color: #ef4444; color: #ef4444; }

                .system-alert { background: rgba(59, 130, 246, 0.05); border-left: 4px solid #3b82f6; padding: 20px; border-radius: 0 12px 12px 0; margin-bottom: 30px; display: flex; gap: 20px; align-items: center; }
                .alert-icon { width: 40px; height: 40px; background: #3b82f6; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: bold; flex-shrink: 0; }
                .alert-text .label { font-size: 0.7rem; color: #3b82f6; font-weight: bold; }
                .alert-text p { margin: 5px 0 0; color: #ccc; }

                .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; margin-bottom: 40px; }
                .glass-card { background: rgba(255, 255, 255, 0.02); border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 16px; backdrop-filter: blur(10px); }
                .stat-card { padding: 30px; position: relative; overflow: hidden; }
                .stat-card::after { content: ''; position: absolute; top: 0; left: 0; width: 100%; height: 2px; background: linear-gradient(90deg, transparent, rgba(59,130,246,0.5), transparent); }
                
                .card-label { font-size: 0.75rem; color: #666; letter-spacing: 1px; font-weight: bold; display: block; margin-bottom: 15px; }
                .card-value { display: flex; align-items: baseline; gap: 8px; margin-bottom: 15px; }
                .big-num { font-size: 2.5rem; font-weight: 800; font-variant-numeric: tabular-nums; }
                .slash, .limit { font-size: 1.2rem; color: #333; }
                .progress-bar { height: 4px; background: #111; border-radius: 2px; overflow: hidden; }
                .progress-fill { height: 100%; background: #3b82f6; box-shadow: 0 0 10px #3b82f6; transition: width 1s ease; }
                
                .status-text { font-size: 1.5rem; font-weight: bold; }
                .status-text.active { color: #22c55e; }
                .status-text.locked { color: #ef4444; }
                .card-subtext { font-size: 0.7rem; color: #444; margin: 10px 0 0; }

                .section-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 25px; }
                .section-header h2 { font-size: 1rem; letter-spacing: 2px; color: #666; margin: 0; }
                .add-btn { background: #3b82f6; color: #fff; border: none; padding: 10px 20px; border-radius: 8px; font-weight: bold; cursor: pointer; font-size: 0.85rem; box-shadow: 0 4px 15px rgba(59,130,246,0.3); }

                .ilan-grid { display: flex; flex-direction: column; gap: 15px; }
                .ilan-item { padding: 20px 25px; display: flex; justify-content: space-between; align-items: center; transition: all 0.3s; }
                .ilan-item:hover { background: rgba(255,255,255,0.04); border-color: rgba(59,130,246,0.3); transform: translateX(5px); }
                .ilan-info h3 { margin: 0 0 5px; font-size: 1rem; }
                .id-tag { font-size: 0.7rem; color: #444; margin: 0; font-family: monospace; }
                
                .ilan-status { display: flex; align-items: center; gap: 20px; }
                .badge { font-size: 0.65rem; padding: 4px 10px; border-radius: 4px; font-weight: 800; border: 1px solid transparent; }
                .badge.success { background: rgba(34, 197, 94, 0.1); color: #22c55e; border-color: rgba(34, 197, 94, 0.2); }
                .badge.warning { background: rgba(245, 158, 11, 0.1); color: #f59e0b; border-color: rgba(245, 158, 11, 0.2); }
                
                .action-btn { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); color: #ccc; padding: 6px 12px; border-radius: 6px; font-size: 0.75rem; cursor: pointer; transition: all 0.2s; }
                .action-btn:hover { background: #fff; color: #000; }
                
                .empty-state { padding: 60px; text-align: center; border: 1px dashed #222; border-radius: 16px; color: #444; }

                @media (max-width: 768px) {
                    .main-header { flex-direction: column; gap: 20px; align-items: flex-start; }
                    .stat-card { padding: 20px; }
                    .ilan-item { flex-direction: column; align-items: flex-start; gap: 20px; }
                    .ilan-status { width: 100%; justify-content: space-between; }
                }
            `}</style>
        </div>
    );
}
