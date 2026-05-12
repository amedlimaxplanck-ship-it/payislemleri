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
            // First get profile to get userId
            const profRes = await fetch('/api/profilim');
            if (profRes.status === 401) return router.push('/login');
            const profData = await profRes.json();
            
            setUser(profData);

            // Get ilanlar and system status
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

    if (loading) return <div className="loading">YÜKLENİYOR...</div>;

    return (
        <div className="panel-container">
            <header className="panel-header">
                <h1>MÜŞTERİ_PORTALI</h1>
                <button onClick={() => router.push('/login')}>ÇIKIŞ</button>
            </header>

            {system?.anonsMesaji && (
                <div className="announcement">
                    <strong>DUYURU:</strong> {system.anonsMesaji}
                </div>
            )}

            <div className="stats-row">
                <div className="mini-card">
                    <p>İLAN KOTASI</p>
                    <h3>{ilanlar.length} / {user?.ilanKotasi || '∞'}</h3>
                </div>
            </div>

            <section className="ilanlar-section">
                <h2>İLANLARIM</h2>
                <div className="ilan-list">
                    {ilanlar.length === 0 ? (
                        <p className="empty">Henüz ilan eklenmemiş.</p>
                    ) : (
                        ilanlar.map(ilan => (
                            <div key={ilan.docId} className="ilan-card">
                                <h4>{ilan.baslik}</h4>
                                <p>{ilan.durum === 'aktif' ? '✅ AKTİF' : '❌ PASİF'}</p>
                            </div>
                        ))
                    )}
                </div>
            </section>

            <style jsx>{`
                .panel-container { padding: 30px; max-width: 1200px; margin: 0 auto; }
                .panel-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; }
                .announcement { background: rgba(59, 130, 246, 0.1); border: 1px solid #3b82f6; padding: 15px; border-radius: 8px; margin-bottom: 20px; color: #fff; }
                .stats-row { margin-bottom: 30px; }
                .mini-card { background: var(--bg-card); padding: 20px; border: 1px solid var(--border); width: 200px; text-align: center; }
                .ilan-card { background: var(--bg-card); padding: 20px; border: 1px solid var(--border); margin-bottom: 10px; display: flex; justify-content: space-between; }
                .loading { height: 100vh; display: flex; justify-content: center; align-items: center; }
            `}</style>
        </div>
    );
}
