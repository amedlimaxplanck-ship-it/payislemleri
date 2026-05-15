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
        // Force Dark Mode for Login Page
        document.documentElement.setAttribute('data-theme', 'dark');
        
        const timer = setInterval(() => {
            const now = new Date();
            setClock(now.toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit', second: '2-digit' }));
        }, 1000);
        return () => clearInterval(timer);
    }, []);

    const handleLogin = async (e?: React.FormEvent) => {
        if (e) e.preventDefault();
        
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
            <div className="bg-noise"></div>
            <div className="scanline"></div>
            
            <div className="tech-decor top-l">ID: SUPA_SYS_77</div>
            <div className="tech-decor top-r">{clock}</div>
            <div className="tech-decor bot-l">ENCRYPTION: AES_256_GCM</div>
            <div className="tech-decor bot-r">LOC: IST_NODE_1</div>

            <div className="login-container">
                <form onSubmit={handleLogin} className="industrial-card">
                    <div className="card-inner">
                        <div className="status-badge">
                            <span className="dot"></span>
                            AUTHENTICATION_REQUIRED
                        </div>

                        <div className="brand">
                            <h1>SUPA<span>PANEL</span></h1>
                            <p>ENTER_ACCESS_PROTOCOL</p>
                        </div>

                        <div className="input-box">
                            <label>PROTOCOL_KEY</label>
                            <input
                                type="password"
                                value={code}
                                onChange={(e) => setCode(e.target.value)}
                                placeholder="••••••••"
                                autoComplete="off"
                                autoFocus
                            />
                        </div>

                        {error && <div className="error-alert">{error}</div>}

                        <button type="submit" disabled={loading} className="login-btn">
                            {loading ? <div className="loader"></div> : 'VALIDATE_ACCESS'}
                        </button>

                        <div className="security-footer">
                            <span>TLS_1.3</span>
                            <span>MFA_READY</span>
                            <span>S_SHIELD_ACTIVE</span>
                        </div>
                    </div>
                </form>
            </div>

            <style jsx>{`
                .login-screen {
                    min-height: 100vh;
                    background: #000;
                    color: #fff;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    position: relative;
                    overflow: hidden;
                    font-family: 'JetBrains Mono', monospace;
                }

                .bg-noise {
                    position: fixed;
                    inset: 0;
                    background-image: url('https://grainy-gradients.vercel.app/noise.svg');
                    opacity: 0.15;
                    pointer-events: none;
                }

                .scanline {
                    position: fixed;
                    inset: 0;
                    background: linear-gradient(to bottom, transparent 50%, rgba(0,0,0,0.5) 51%);
                    background-size: 100% 4px;
                    pointer-events: none;
                    z-index: 100;
                    opacity: 0.1;
                }

                .tech-decor {
                    position: fixed;
                    font-size: 10px;
                    color: #333;
                    letter-spacing: 2px;
                    padding: 40px;
                    font-weight: 800;
                    z-index: 50;
                }
                .top-l { top: 0; left: 0; }
                .top-r { top: 0; right: 0; color: #666; }
                .bot-l { bottom: 0; left: 0; }
                .bot-r { bottom: 0; right: 0; }

                .login-container {
                    position: relative;
                    z-index: 100;
                    width: 100%;
                    max-width: 440px;
                    padding: 20px;
                }

                .industrial-card {
                    background: #080808;
                    border: 1px solid #1a1a1a;
                    padding: 60px 40px;
                    position: relative;
                    box-shadow: 0 40px 100px rgba(0,0,0,0.8);
                }

                .industrial-card::before {
                    content: '';
                    position: absolute;
                    top: -1px; left: 10%; right: 10%; height: 1px;
                    background: linear-gradient(90deg, transparent, #3b82f6, transparent);
                }

                .status-badge {
                    font-size: 9px;
                    color: #fbbf24;
                    letter-spacing: 1.5px;
                    display: flex;
                    align-items: center;
                    gap: 8px;
                    margin-bottom: 40px;
                    justify-content: center;
                }

                .status-badge .dot {
                    width: 6px; height: 6px;
                    background: #fbbf24;
                    border-radius: 50%;
                    box-shadow: 0 0 10px #fbbf24;
                    animation: pulse 2s infinite;
                }

                @keyframes pulse {
                    0% { opacity: 1; transform: scale(1); }
                    50% { opacity: 0.5; transform: scale(0.8); }
                    100% { opacity: 1; transform: scale(1); }
                }

                .brand {
                    text-align: center;
                    margin-bottom: 50px;
                }

                .brand h1 {
                    font-size: 28px;
                    font-weight: 900;
                    letter-spacing: 4px;
                    color: #fff;
                }

                .brand h1 span {
                    color: #3b82f6;
                    text-shadow: 0 0 20px rgba(59, 130, 246, 0.4);
                }

                .brand p {
                    font-size: 10px;
                    color: #444;
                    margin-top: 8px;
                    letter-spacing: 3px;
                }

                .input-box {
                    margin-bottom: 30px;
                }

                .input-box label {
                    display: block;
                    font-size: 9px;
                    color: #666;
                    margin-bottom: 12px;
                    letter-spacing: 2px;
                }

                .input-box input {
                    width: 100%;
                    background: #000;
                    border: 1px solid #222;
                    padding: 18px;
                    color: #fff;
                    font-size: 24px;
                    text-align: center;
                    outline: none;
                    transition: 0.3s;
                    letter-spacing: 10px;
                }

                .input-box input:focus {
                    border-color: #3b82f6;
                    background: #050505;
                }

                .login-btn {
                    width: 100%;
                    background: #fff;
                    color: #000;
                    border: none;
                    padding: 20px;
                    font-weight: 900;
                    font-size: 13px;
                    letter-spacing: 3px;
                    cursor: pointer;
                    transition: 0.3s;
                }

                .login-btn:hover {
                    background: #3b82f6;
                    color: #fff;
                    box-shadow: 0 0 30px rgba(59, 130, 246, 0.3);
                }

                .login-btn:disabled {
                    background: #111;
                    color: #333;
                    cursor: not-allowed;
                }

                .error-alert {
                    background: rgba(239, 68, 68, 0.1);
                    color: #f87171;
                    padding: 12px;
                    font-size: 11px;
                    margin-bottom: 20px;
                    text-align: center;
                    border: 1px solid rgba(239, 68, 68, 0.2);
                }

                .security-footer {
                    margin-top: 50px;
                    display: flex;
                    justify-content: center;
                    gap: 20px;
                    font-size: 8px;
                    color: #222;
                    letter-spacing: 1px;
                }

                .loader {
                    width: 20px; height: 20px;
                    border: 2px solid rgba(0,0,0,0.1);
                    border-top-color: #000;
                    border-radius: 50%;
                    animation: spin 0.8s linear infinite;
                    margin: 0 auto;
                }

                @keyframes spin { to { transform: rotate(360deg); } }
            `}</style>
        </main>
    );
}
