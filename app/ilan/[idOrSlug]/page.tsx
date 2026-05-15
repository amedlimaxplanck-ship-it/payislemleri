'use client';

import { useState, useEffect } from 'react';
import { useParams } from 'next/navigation';
import SahibindenTemplate from './components/SahibindenTemplate';
import PttAvmTemplate from './components/PttAvmTemplate';

export default function AdPage() {
    const { idOrSlug } = useParams();
    const [data, setData] = useState<any>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(false);

    useEffect(() => {
        const fetchIlan = async () => {
            try {
                const res = await fetch(`/api/ilan/${idOrSlug}`);
                if (res.ok) {
                    const ilanData = await res.json();
                    setData(ilanData);
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
        fetchIlan();
    }, [idOrSlug]);

    if (loading) return (
        <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh', fontFamily: 'sans-serif', background: '#f3f4f7', color: '#666' }}>
            İlan yükleniyor...
        </div>
    );

    if (error || !data) return (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100vh', textAlign: 'center', padding: '20px', background: '#fff' }}>
            <div style={{ fontSize: '70px', marginBottom: '20px' }}>⚠️</div>
            <h1 style={{ fontSize: '24px', fontWeight: 'bold', marginBottom: '10px' }}>İlan Yayında Değil</h1>
            <p style={{ color: '#666', marginBottom: '25px' }}>Aradığınız ilan yayından kaldırılmış veya süresi dolmuş olabilir.</p>
            <a href="https://www.sahibinden.com" style={{ background: '#0059a3', color: '#fff', padding: '12px 24px', borderRadius: '4px', textDecoration: 'none', fontWeight: 'bold' }}>Ana Sayfaya Dön</a>
        </div>
    );

    // Render template based on data.sablon
    if (data.sablon === 'sablon2') {
        return <PttAvmTemplate data={data} idOrSlug={idOrSlug as string} />;
    }

    // Default to Sahibinden (sablon1)
    return <SahibindenTemplate data={data} idOrSlug={idOrSlug as string} />;
}
