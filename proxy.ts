import { NextRequest, NextResponse } from 'next/server';
import { verifyToken } from '@/lib/auth';

export async function proxy(request: NextRequest) {
    const token = request.cookies.get('token')?.value;
    const { pathname } = request.nextUrl;

    if (pathname === '/login' || pathname.startsWith('/api/login') || pathname.startsWith('/_next') || pathname === '/') {
        return NextResponse.next();
    }

    if (!token) {
        return NextResponse.redirect(new URL('/login', request.url));
    }

    try {
        const decoded = await verifyToken(token);
        if (!decoded) {
            return NextResponse.redirect(new URL('/login', request.url));
        }
    } catch (error) {
        return NextResponse.redirect(new URL('/login', request.url));
    }

    return NextResponse.next();
}

export const config = {
    matcher: ['/((?!api|_next/static|_next/image|favicon.ico).*)'],
};
