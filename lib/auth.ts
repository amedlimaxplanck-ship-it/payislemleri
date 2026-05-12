import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'SuperGizliAnahtar2026';

export interface JWTPayload {
    id: string;
    role: string;
    sessionId: string;
}

export function createToken(payload: JWTPayload): string {
    return jwt.sign(payload, JWT_SECRET, { expiresIn: '24h' });
}

export function verifyToken(token: string): JWTPayload | null {
    try {
        return jwt.verify(token, JWT_SECRET) as JWTPayload;
    } catch (error) {
        return null;
    }
}
