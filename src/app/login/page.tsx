'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';

export default function LoginPage() {
    const [code, setCode] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const [clock, setClock] = useState('00:00:00');
    const router = useRouter();

    useEffect(() => {
        const timer = setInterval(() => {
            const now = new Date();
            setClock(now.toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit', second: '2-digit' }));
        }, 1000);
        return () => clearInterval(timer);
    }, []);

    const handleLogin = async () => {
        if (!code.trim()) {
            setError('Lütfen giriş anahtarını girin.');
            return;
        }

        setLoading(true);
        setError('');

        try {
            const res = await fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ code }),
            });

            const data = await res.json();

            if (data.success) {
                // Success state handled by server-side cookies, but we redirect based on role
                if (data.user.role === 'god') {
                    router.push('/god-panel');
                } else {
                    router.push('/musteri-panel');
                }
            } else {
                setError(data.message || 'Giriş başarısız.');
                setLoading(false);
            }
        } catch (err) {
            setError('Sunucu bağlantı hatası.');
            setLoading(false);
        }
    };

    return (
        <main className="login-screen">
            <div className="tech-grid"></div>
            <div className="scanline"></div>
            <div className="mesh"></div>

            {/* Teknik Detaylar (Aestetik) */}
            <div className="corner-decor top-left">SYS_v2.4.0</div>
            <div className="corner-decor top-right">{clock}</div>
            <div className="corner-decor bottom-left">SECURE_PROTOCOL_ACTIVE</div>
            <div className="corner-decor bottom-right">© 2026 SUPA_SYSTEMS</div>

            <div className="login-card-container">
                <div className="card-industrial">
                    <div className="card-header">
                        <div className="status-indicator">
                            <div className="dot"></div>
                            READY
                        </div>
                        <h1 className="title">SUPA PANEL GİRİŞ</h1>
                        <p className="subtitle">YETKİLİ PERSONEL ERİŞİMİ</p>
                    </div>

                    <div className="input-section">
                        <div className="input-group-modern">
                            <label htmlFor="access-code">PROTOCOL_KEY</label>
                            <input
                                type="password"
                                id="access-code"
                                value={code}
                                onChange={(e) => setCode(e.target.value)}
                                onKeyPress={(e) => e.key === 'Enter' && handleLogin()}
                                placeholder="••••••••"
                                autoComplete="off"
                            />
                        </div>

                        {error && <div className="error-msg">{error}</div>}

                        <button 
                            className="btn-industrial" 
                            onClick={handleLogin}
                            disabled={loading}
                        >
                            {loading ? <div className="spinner-mini"></div> : 'OTURUMU DOĞRULA'}
                        </button>
                    </div>

                    <div className="card-footer">
                        <div className="security-badges">
                            <span>AES-256</span>
                            <span>TLS 1.3</span>
                            <span>MFA_READY</span>
                        </div>
                    </div>
                </div>
            </div>

            <style jsx>{`
                .login-screen {
                    min-height: 100vh;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    position: relative;
                    padding: 20px;
                }

                .corner-decor {
                    position: fixed;
                    font-family: 'JetBrains Mono', monospace;
                    font-size: 10px;
                    color: var(--text-dim);
                    letter-spacing: 2px;
                    padding: 30px;
                    opacity: 0.6;
                }
                .top-left { top: 0; left: 0; }
                .top-right { top: 0; right: 0; }
                .bottom-left { bottom: 0; left: 0; }
                .bottom-right { bottom: 0; right: 0; }

                .login-card-container {
                    position: relative;
                    z-index: 10;
                    width: 100%;
                    max-width: 400px;
                    animation: entrance 1s cubic-bezier(0.16, 1, 0.3, 1);
                }

                @keyframes entrance {
                    from { opacity: 0; transform: translateY(40px) scale(0.98); }
                    to { opacity: 1; transform: translateY(0) scale(1); }
                }

                .card-industrial {
                    background: var(--bg-card);
                    backdrop-filter: blur(20px);
                    border: 1px solid var(--border);
                    padding: 50px 40px;
                    position: relative;
                    box-shadow: 0 50px 100px rgba(0,0,0,0.8);
                }

                .card-industrial::before {
                    content: '';
                    position: absolute;
                    top: -1px; left: 20px; right: 20px; height: 1px;
                    background: linear-gradient(90deg, transparent, var(--text-main), transparent);
                    opacity: 0.3;
                }

                .status-indicator {
                    font-family: 'JetBrains Mono', monospace;
                    font-size: 9px;
                    display: flex;
                    align-items: center;
                    gap: 6px;
                    color: #10b981;
                    letter-spacing: 2px;
                    margin-bottom: 20px;
                    justify-content: center;
                }

                .status-indicator .dot {
                    width: 6px; height: 6px;
                    background: #10b981;
                    border-radius: 50%;
                    box-shadow: 0 0 10px #10b981;
                    animation: pulse 2s infinite;
                }

                .title {
                    font-size: 24px;
                    font-weight: 800;
                    letter-spacing: 2px;
                    margin-bottom: 6px;
                    color: #fff;
                    text-align: center;
                }

                .subtitle {
                    font-size: 11px;
                    color: var(--text-dim);
                    letter-spacing: 4px;
                    margin-bottom: 40px;
                    text-align: center;
                    font-weight: 300;
                }

                .input-group-modern {
                    margin-bottom: 25px;
                }

                .input-group-modern label {
                    display: block;
                    font-family: 'JetBrains Mono', monospace;
                    font-size: 9px;
                    color: var(--text-dim);
                    margin-bottom: 8px;
                    letter-spacing: 1px;
                }

                .input-group-modern input {
                    width: 100%;
                    background: rgba(0,0,0,0.4);
                    border: 1px solid var(--border);
                    padding: 16px;
                    color: #fff;
                    font-size: 20px;
                    text-align: center;
                    outline: none;
                    transition: all 0.3s;
                    letter-spacing: 8px;
                }

                .input-group-modern input:focus {
                    border-color: rgba(255,255,255,0.4);
                    background: rgba(0,0,0,0.6);
                }

                .btn-industrial {
                    width: 100%;
                    padding: 18px;
                    background: #fff;
                    color: #000;
                    border: none;
                    font-weight: 800;
                    font-size: 13px;
                    letter-spacing: 2px;
                    cursor: pointer;
                    transition: all 0.3s;
                    margin-top: 10px;
                }

                .btn-industrial:hover {
                    background: #e2e8f0;
                    letter-spacing: 4px;
                }

                .btn-industrial:disabled {
                    background: #1e293b;
                    color: #475569;
                    cursor: not-allowed;
                }

                .error-msg {
                    background: rgba(239, 68, 68, 0.1);
                    border: 1px solid rgba(239, 68, 68, 0.2);
                    color: #fca5a5;
                    padding: 12px;
                    font-size: 12px;
                    margin-bottom: 20px;
                    text-align: center;
                }

                .card-footer {
                    margin-top: 40px;
                }

                .security-badges {
                    display: flex;
                    justify-content: center;
                    gap: 15px;
                    font-family: 'JetBrains Mono', monospace;
                    font-size: 8px;
                    color: var(--text-dim);
                    opacity: 0.5;
                }

                .spinner-mini {
                    width: 18px;
                    height: 18px;
                    border: 2px solid rgba(0,0,0,0.1);
                    border-top: 2px solid #000;
                    border-radius: 50%;
                    animation: spin 0.8s linear infinite;
                }

                @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
            `}</style>
        </main>
    );
}
