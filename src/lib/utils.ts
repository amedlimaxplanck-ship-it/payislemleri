export function sanitize(str: string): string {
    if (!str) return "";
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/\//g, '&#x2f;');
}

export function formatDate(date: number | string | Date): string {
    const d = new Date(date);
    return d.toLocaleDateString('tr-TR');
}

export function parseDateString(s: string): string {
    if (!s) return "";
    let p = s.split(".");
    return p.length === 3 ? `${p[2]}-${p[1].padStart(2, '0')}-${p[0].padStart(2, '0')}` : "";
}
