import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/request';
import { jwtVerify } from 'jose'; // Using jose for edge compatibility in middleware

const JWT_SECRET = new TextEncoder().encode(process.env.JWT_SECRET || 'SuperGizliAnahtar2026');

export async function middleware(request: NextRequest) {
    const token = request.cookies.get('token')?.value;
    const { pathname } = request.nextUrl;

    // Public paths
    if (pathname === '/login' || pathname.startsWith('/api/login') || pathname.startsWith('/_next') || pathname === '/') {
        return NextResponse.next();
    }

    if (!token) {
        return NextResponse.redirect(new URL('/login', request.url));
    }

    try {
        const { payload } = await jwtVerify(token, JWT_SECRET);
        
        // Role based access
        if (pathname.startsWith('/god-panel') && payload.role !== 'god') {
            return NextResponse.redirect(new URL('/login', request.url));
        }

        if (pathname.startsWith('/musteri-panel') && payload.role !== 'customer' && payload.role !== 'god') {
            return NextResponse.redirect(new URL('/login', request.url));
        }

        return NextResponse.next();
    } catch (error) {
        return NextResponse.redirect(new URL('/login', request.url));
    }
}

export const config = {
    matcher: ['/((?!api|_next/static|_next/image|favicon.ico).*)'],
};
