'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { sanitize, formatDate, parseDateString } from '@/lib/utils';

export default function GodPanel() {
    const [stats, setStats] = useState({ total: 0, active: 0, tickets: 0 });
    const [system, setSystem] = useState({ kilitDurumu: false, sorguAktif: false, anonsMesaji: '', godBotToken: '', godChatId: '' });
    const [users, setUsers] = useState<any[]>([]);
    const [tickets, setTickets] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const router = useRouter();

    // Modals state
    const [showAddUser, setShowAddUser] = useState(false);
    const [newUser, setNewUser] = useState({ passcode: '', isim: '', duration: '1', ilanKotasi: 'sinirsiz' });

    useEffect(() => {
        fetchData();
        const interval = setInterval(fetchData, 30000); // Refresh every 30s
        return () => clearInterval(interval);
    }, []);

    const fetchData = async () => {
        try {
            const [statusRes, usersRes, ticketsRes] = await Promise.all([
                fetch('/api/sistem/durum'),
                fetch('/api/users'),
                fetch('/api/tickets')
            ]);

            if (statusRes.status === 401) router.push('/login');

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

    const handleToggleLockdown = async (e: any) => {
        const val = e.target.checked;
        await fetch('/api/sistem/kilit', {
            method: 'POST',
            body: JSON.stringify({ kilitDurumu: val })
        });
        setSystem({ ...system, kilitDurumu: val });
    };

    const handleLogout = async () => {
        // Clear cookie would be better via API, but for now just redirect
        document.cookie = "token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
        router.push('/login');
    };

    if (loading) return <div className="loading">SİSTEM YÜKLENİYOR...</div>;

    return (
        <div className="admin-container">
            <header className="admin-header">
                <h1>GOD_PANEL <span>v3.0</span></h1>
                <div className="header-actions">
                    <button className="logout-btn" onClick={handleLogout}>GÜVENLİ ÇIKIŞ</button>
                </div>
            </header>

            <div className="stats-grid">
                <div className="stat-card">
                    <h3>{stats.total}</h3>
                    <p>TOPLAM MÜŞTERİ</p>
                </div>
                <div className="stat-card">
                    <h3>{stats.active}</h3>
                    <p>AKTİF OTURUM</p>
                </div>
                <div className="stat-card warning">
                    <h3>{stats.tickets}</h3>
                    <p>AÇIK TALEPLER</p>
                </div>
            </div>

            <section className="command-center">
                <h2>KOMUTA MERKEZİ</h2>
                <div className="command-grid">
                    <div className="control-box">
                        <div className="control-header">
                            <label>SİSTEM KİLİDİ</label>
                            <input type="checkbox" checked={system.kilitDurumu} onChange={handleToggleLockdown} />
                        </div>
                        <p>Acil durumda tüm sistemi dondurur.</p>
                    </div>
                    {/* Diğer kontroller buraya eklenecek */}
                </div>
            </section>

            <section className="user-management">
                <div className="section-header">
                    <h2>MÜŞTERİ YÖNETİMİ</h2>
                    <button className="add-btn" onClick={() => setShowAddUser(true)}>YENİ MÜŞTERİ EKLE</button>
                </div>

                <div className="table-wrapper">
                    <table>
                        <thead>
                            <tr>
                                <th>KULLANICI</th>
                                <th>ŞİFRE</th>
                                <th>BİTİŞ</th>
                                <th>DURUM</th>
                                <th>AKSİYON</th>
                            </tr>
                        </thead>
                        <tbody>
                            {users.map((user) => (
                                <tr key={user.docId}>
                                    <td>{user.isim || 'İsimsiz'}</td>
                                    <td><code>{user.passcode}</code></td>
                                    <td>{user.expireDate}</td>
                                    <td>
                                        <span className={`status-badge ${user.isBanned ? 'banned' : user.isActive ? 'active' : 'passive'}`}>
                                            {user.isBanned ? 'YASAKLI' : user.isActive ? 'AKTİF' : 'PASİF'}
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
            </section>

            <style jsx>{`
                .admin-container {
                    padding: 40px;
                    max-width: 1400px;
                    margin: 0 auto;
                }
                .admin-header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 40px;
                    border-bottom: 1px solid var(--border);
                    padding-bottom: 20px;
                }
                .admin-header h1 {
                    font-size: 24px;
                    letter-spacing: 4px;
                }
                .admin-header h1 span {
                    color: #ef4444;
                    font-size: 14px;
                }
                .stats-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                    gap: 20px;
                    margin-bottom: 40px;
                }
                .stat-card {
                    background: var(--bg-card);
                    padding: 30px;
                    border: 1px solid var(--border);
                    text-align: center;
                }
                .stat-card h3 {
                    font-size: 40px;
                    margin-bottom: 10px;
                }
                .stat-card p {
                    color: var(--text-dim);
                    font-size: 12px;
                    letter-spacing: 2px;
                }
                .warning h3 { color: #f59e0b; }
                
                .command-center {
                    margin-bottom: 40px;
                }
                .command-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                    gap: 20px;
                    margin-top: 20px;
                }
                .control-box {
                    background: var(--bg-card);
                    padding: 25px;
                    border: 1px solid var(--border);
                }
                .control-header {
                    display: flex;
                    justify-content: space-between;
                    margin-bottom: 10px;
                }
                .table-wrapper {
                    background: var(--bg-card);
                    border: 1px solid var(--border);
                    overflow-x: auto;
                }
                table {
                    width: 100%;
                    border-collapse: collapse;
                }
                th {
                    text-align: left;
                    padding: 20px;
                    font-size: 11px;
                    color: var(--text-dim);
                    border-bottom: 1px solid var(--border);
                }
                td {
                    padding: 20px;
                    border-bottom: 1px solid var(--border);
                }
                .status-badge {
                    font-size: 10px;
                    padding: 4px 8px;
                    font-weight: 800;
                }
                .active { color: #10b981; }
                .banned { color: #ef4444; }
                .passive { color: #64748b; }
                
                .action-btn {
                    background: transparent;
                    border: 1px solid var(--border);
                    color: #fff;
                    padding: 6px 12px;
                    font-size: 11px;
                    cursor: pointer;
                    margin-right: 5px;
                }
                .action-btn.danger { color: #ef4444; border-color: #ef4444; }
                
                .loading {
                    height: 100vh;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    letter-spacing: 10px;
                    font-size: 20px;
                }
            `}</style>
        </div>
    );
}
