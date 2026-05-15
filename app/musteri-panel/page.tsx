'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';

const slugify = (text: string) => {
    return text.toString().toLowerCase()
        .replace(/\s+/g, '-')           // Replace spaces with -
        .replace(/[^\w\-]+/g, '')       // Remove all non-word chars
        .replace(/\-\-+/g, '-')         // Replace multiple - with single -
        .replace(/^-+/, '')             // Trim - from start of text
        .replace(/-+$/, '');            // Trim - from end of text
};

export default function MusteriPanel() {
    const [stats, setStats] = useState({ ilan: 0, dekont: 0, log: 0 });
    const [user, setUser] = useState<any>(null);
    const [logs, setLogs] = useState<any[]>([]);
    const [ilanlar, setIlanlar] = useState<any[]>([]);
    const [activeTab, setActiveTab] = useState('ilanlar');
    const [loading, setLoading] = useState(true);
    const [theme, setTheme] = useState('light');
    const [isSoftBanned, setIsSoftBanned] = useState(false);
    const [showKanban, setShowKanban] = useState(false);
    const [showIlanModal, setShowIlanModal] = useState(false);
    const [systemLocked, setSystemLocked] = useState(false);
    const router = useRouter();

    // New Ilan Form
    const [ilanForm, setIlanForm] = useState({
        urunAdi: '', urunAciklamasi: '', fiyat: '', saticiAdi: '', saticiTel: '',
        anaResim: '', iban: '', slug: ''
    });

    useEffect(() => {
        fetchInitialData();
        setupInactivityTimer();
        const interval = setInterval(refreshData, 15000);
        return () => clearInterval(interval);
    }, []);

    const setupInactivityTimer = () => {
        let timeout: NodeJS.Timeout;
        const reset = () => {
            clearTimeout(timeout);
            timeout = setTimeout(() => {
                alert("10 dakika hareketsizlik nedeniyle oturumunuz sonlandırıldı.");
                handleLogout();
            }, 600000);
        };
        window.addEventListener('mousemove', reset);
        window.addEventListener('keypress', reset);
        reset();
    };

    const fetchInitialData = async () => {
        const token = document.cookie.split('; ').find(row => row.startsWith('token='))?.split('=')[1];
        if (!token) return router.push('/login');

        try {
            const [userRes, systemRes] = await Promise.all([
                fetch('/api/profilim', { headers: { 'Authorization': `Bearer ${token}` } }),
                fetch('/api/sistem/durum', { headers: { 'Authorization': `Bearer ${token}` } })
            ]);

            if (userRes.status === 401) return router.push('/login');

            const userData = await userRes.json();
            const systemData = await systemRes.json();

            setUser(userData);
            setIsSoftBanned(userData.isSoftBanned || false);
            setSystemLocked(systemData.kilitDurumu || false);
            setTheme(localStorage.getItem('panel_theme') || 'light');
            
            await refreshData();
            setLoading(false);
        } catch (error) {
            console.error("Fetch error", error);
        }
    };

    const refreshData = async () => {
        const token = document.cookie.split('; ').find(row => row.startsWith('token='))?.split('=')[1];
        if (!token) return;

        try {
            const [logsRes, statsRes, ilanRes] = await Promise.all([
                fetch('/api/logs-getir', { headers: { 'Authorization': `Bearer ${token}` } }),
                fetch('/api/musteri/stats', { headers: { 'Authorization': `Bearer ${token}` } }),
                fetch(`/api/ilanlar?userId=${user?.id}`, { headers: { 'Authorization': `Bearer ${token}` } })
            ]);

            if (logsRes.ok) setLogs(await logsRes.json());
            if (statsRes.ok) setStats(await statsRes.json());
            if (ilanRes.ok) setIlanlar(await ilanRes.json());
        } catch (e) {}
    };

    const handleIlanKaydet = async () => {
        if (isSoftBanned) return;
        const token = document.cookie.split('; ').find(row => row.startsWith('token='))?.split('=')[1];
        
        const payload = { 
            ...ilanForm, 
            slug: slugify(ilanForm.urunAdi) + '-' + Math.floor(Math.random() * 1000)
        };

        const res = await fetch('/api/ilan-ekle', {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (res.ok) {
            setShowIlanModal(false);
            refreshData();
        }
    };

    const toggleTheme = () => {
        const newTheme = theme === 'light' ? 'dark' : 'light';
        setTheme(newTheme);
        localStorage.setItem('panel_theme', newTheme);
        document.documentElement.setAttribute('data-theme', newTheme);
    };

    const handleLogout = () => {
        document.cookie = "token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
        router.push('/login');
    };

    if (loading) return <div className="loading">YÜKLENİYOR...</div>;

    if (systemLocked) return (
        <div className="lockdown-screen">
            <div className="lock-box">
                <svg viewBox="0 0 24 24" width="64" height="64" fill="#ef4444"><path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zM9 6c0-1.66 1.34-3 3-3s3 1.34 3 3v2H9V6zm9 14H6V10h12v10z"/></svg>
                <h2>Sistem Erişimi Duraklatıldı</h2>
                <p>Güvenlik protokolleri gereği hesabınızın işlemleri geçici olarak durdurulmuştur.</p>
            </div>
            <style jsx>{`
                .lockdown-screen { height: 100vh; background: #000; color: #fff; display: flex; align-items: center; justify-content: center; text-align: center; font-family: 'Plus Jakarta Sans', sans-serif; }
                .lock-box { padding: 40px; border: 1px solid #333; border-radius: 20px; background: #0a0a0a; max-width: 400px; }
                h2 { margin-top: 20px; font-weight: 800; }
                p { color: #666; font-size: 14px; margin-top: 10px; }
            `}</style>
        </div>
    );

    return (
        <div className="panel-wrapper animate-slide-up">
            {isSoftBanned && (
                <div className="soft-ban-banner">
                    ⚠️ ABONELİK SÜRENİZ DOLDU / KISITLANDINIZ. Şu an sadece okuma modundasınız.
                </div>
            )}

            <header className="header">
                <h1>Müşteri<span>Panel</span></h1>
                <div className="header-controls">
                    <button className="theme-toggle" onClick={toggleTheme}>
                        {theme === 'light' ? '🌙' : '☀️'}
                    </button>
                    <button className="logout-btn" onClick={handleLogout}>ÇIKIŞ</button>
                </div>
            </header>

            <div className="stats-grid">
                <div className="stat-card"><h3>{stats.ilan}</h3><p>Aktif İlan</p></div>
                <div className="stat-card"><h3>{stats.dekont}</h3><p>Gelen Dekont</p></div>
                <div className="stat-card"><h3>{stats.log}</h3><p>Sistem Logu</p></div>
            </div>

            <div className="tabs">
                {['ilanlar', 'dekontlar', 'loglar', 'sorgu', 'ayarlar'].map(tab => (
                    <button key={tab} className={`tab-btn ${activeTab === tab ? 'active' : ''}`} onClick={() => setActiveTab(tab)}>
                        {tab.toUpperCase()}
                    </button>
                ))}
            </div>

            <div className="content-card">
                {activeTab === 'ilanlar' && (
                    <div className="tab-view">
                        <div className="view-header">
                            <h2>İlanlarım</h2>
                            <button className="btn-primary" disabled={isSoftBanned} onClick={() => setShowIlanModal(true)}>+ YENİ İLAN</button>
                        </div>
                        <div className="table-responsive">
                            <table>
                                <thead>
                                    <tr><th>BAŞLIK</th><th>FİYAT</th><th>SLUG</th><th>İŞLEM</th></tr>
                                </thead>
                                <tbody>
                                    {ilanlar.map(i => (
                                        <tr key={i.docId}>
                                            <td>{i.urunAdi}</td>
                                            <td>{i.fiyat} TL</td>
                                            <td>{i.slug}</td>
                                            <td><button className="btn-copy" onClick={() => navigator.clipboard.writeText(`${window.location.origin}/ilan/${i.slug}`)}>Link</button></td>
                                        </tr>
                                    ))}
                                    {ilanlar.length === 0 && <tr><td colSpan={4} style={{ textAlign: 'center', padding: '40px', color: '#666' }}>Henüz ilanınız bulunmuyor.</td></tr>}
                                </tbody>
                            </table>
                        </div>
                    </div>
                )}

                {activeTab === 'loglar' && (
                    <div className="tab-view">
                        <div className="view-header">
                            <h2>Sistem Logları</h2>
                            <button className="btn-kanban" onClick={() => setShowKanban(true)}>CANLI PANO</button>
                        </div>
                        <div className="table-responsive">
                            <table>
                                <thead><tr><th>TARİH</th><th>AKSİYON</th><th>DETAY</th><th>IP/CİHAZ</th></tr></thead>
                                <tbody>
                                    {logs.map((log, i) => (
                                        <tr key={i}>
                                            <td>{log.tarih} {log.saat}</td>
                                            <td><span className={`log-badge ${log.aksiyon.includes('Hata') ? 'danger' : 'success'}`}>{log.aksiyon}</span></td>
                                            <td>{log.detay}</td>
                                            <td>{log.ip}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </div>
                )}
            </div>

            {/* Ilan Modal */}
            {showIlanModal && (
                <div className="modal-overlay" onClick={() => setShowIlanModal(false)}>
                    <div className="modal-content" onClick={e => e.stopPropagation()}>
                        <h2>Yeni İlan Oluştur</h2>
                        <div className="form-grid">
                            <input type="text" placeholder="Ürün Adı" onChange={e => setIlanForm({...ilanForm, urunAdi: e.target.value})} />
                            <input type="text" placeholder="Fiyat" onChange={e => setIlanForm({...ilanForm, fiyat: e.target.value})} />
                            <input type="text" placeholder="Satıcı Adı" onChange={e => setIlanForm({...ilanForm, saticiAdi: e.target.value})} />
                            <input type="text" placeholder="Satıcı Tel" onChange={e => setIlanForm({...ilanForm, saticiTel: e.target.value})} />
                            <input type="text" placeholder="Resim URL" onChange={e => setIlanForm({...ilanForm, anaResim: e.target.value})} />
                            <input type="text" placeholder="IBAN" onChange={e => setIlanForm({...ilanForm, iban: e.target.value})} />
                            <textarea placeholder="Ürün Açıklaması" onChange={e => setIlanForm({...ilanForm, urunAciklamasi: e.target.value})}></textarea>
                        </div>
                        <div className="modal-footer">
                            <button className="btn-primary" onClick={handleIlanKaydet}>KAYDET</button>
                        </div>
                    </div>
                </div>
            )}

            {showKanban && (
                <div className="kanban-overlay" onClick={() => setShowKanban(false)}>
                    <div className="kanban-content" onClick={e => e.stopPropagation()}>
                        <div className="kanban-header"><h3>CANLI OPERASYON PANOSU</h3><button onClick={() => setShowKanban(false)}>✕</button></div>
                        <div className="kanban-grid">
                            {['Vitrin', 'Ödeme', 'Adres', 'Bitiş'].map(step => (
                                <div key={step} className="kanban-column">
                                    <div className="col-title">{step}</div>
                                    <div className="col-cards"><div className="empty-card">Veri yok</div></div>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            )}

            <style jsx>{`
                .panel-wrapper { max-width: 1200px; margin: 0 auto; padding: 20px; font-family: 'Plus Jakarta Sans', sans-serif; }
                .soft-ban-banner { background: rgba(239, 68, 68, 0.1); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.2); padding: 12px; border-radius: 10px; margin-bottom: 20px; text-align: center; font-weight: 800; }
                .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; }
                .header h1 { font-size: 22px; font-weight: 800; }
                .header h1 span { color: #3b82f6; }
                .theme-toggle { background: var(--bg-card); border: 1px solid var(--border-color); font-size: 18px; padding: 8px; border-radius: 12px; cursor: pointer; }
                .logout-btn { background: #ef4444; color: white; border: none; padding: 8px 16px; border-radius: 10px; font-size: 11px; font-weight: 800; cursor: pointer; }

                .stats-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin-bottom: 30px; }
                .stat-card { background: var(--bg-card); border: 1px solid var(--border-color); padding: 20px; border-radius: 16px; text-align: center; }

                .tabs { display: flex; gap: 10px; margin-bottom: 20px; overflow-x: auto; }
                .tab-btn { background: var(--bg-card); border: 1px solid var(--border-color); color: var(--text-muted); padding: 10px 20px; border-radius: 12px; cursor: pointer; font-size: 12px; font-weight: 800; transition: 0.2s; }
                .tab-btn.active { background: var(--text-main); color: var(--bg-body); }

                .content-card { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 20px; padding: 25px; min-height: 400px; }
                .view-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 25px; }
                .btn-primary { background: #3b82f6; color: white; border: none; padding: 10px 20px; border-radius: 10px; font-weight: 800; cursor: pointer; }
                .btn-copy { background: #111; color: #fff; border: 1px solid #333; padding: 5px 10px; border-radius: 6px; font-size: 11px; cursor: pointer; }

                table { width: 100%; border-collapse: collapse; }
                th { text-align: left; padding: 15px; font-size: 10px; color: var(--text-muted); border-bottom: 1px solid var(--border-color); }
                td { padding: 15px; border-bottom: 1px solid var(--border-color); font-size: 13px; }

                .log-badge { padding: 4px 8px; border-radius: 6px; font-size: 10px; font-weight: 800; }
                .log-badge.success { background: rgba(16, 185, 129, 0.1); color: #10b981; }
                .log-badge.danger { background: rgba(239, 68, 68, 0.1); color: #ef4444; }

                .modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.5); backdrop-filter: blur(5px); display: flex; align-items: center; justify-content: center; z-index: 2000; }
                .modal-content { background: var(--bg-body); border: 1px solid var(--border-color); padding: 30px; border-radius: 24px; width: 100%; max-width: 500px; }
                .form-grid { display: flex; flex-direction: column; gap: 15px; margin-top: 20px; }
                .form-grid input, .form-grid textarea { background: var(--bg-card); border: 1px solid var(--border-color); padding: 12px; border-radius: 12px; color: var(--text-main); }
                .modal-footer { margin-top: 20px; text-align: right; }

                .kanban-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.8); backdrop-filter: blur(10px); display: flex; align-items: center; justify-content: center; z-index: 1000; padding: 20px; }
                .kanban-content { background: var(--bg-body); border: 1px solid var(--border-color); width: 100%; max-width: 1200px; border-radius: 24px; display: flex; flex-direction: column; max-height: 90vh; }
                .kanban-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; padding: 20px; flex: 1; overflow-y: auto; }
                .kanban-column { background: rgba(125,125,125,0.05); border-radius: 16px; padding: 15px; }

                .loading { height: 100vh; display: flex; align-items: center; justify-content: center; font-weight: 800; color: #666; }
            `}</style>
        </div>
    );
}
