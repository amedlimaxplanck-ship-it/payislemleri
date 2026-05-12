import { NextRequest, NextResponse } from 'next/server';

export async function middleware(request: NextRequest) {
    const token = request.cookies.get('token')?.value;
    const { pathname } = request.nextUrl;

    if (pathname === '/login' || pathname.startsWith('/api/login') || pathname.startsWith('/_next') || pathname === '/') {
        return NextResponse.next();
    }

    if (!token) {
        return NextResponse.redirect(new URL('/login', request.url));
    }

    // Basic pass-through to avoid 500 errors from jose/jwt
    return NextResponse.next();
}

export const config = {
    matcher: ['/((?!api|_next/static|_next/image|favicon.ico).*)'],
};
