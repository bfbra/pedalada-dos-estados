import { SignJWT, jwtVerify } from 'jose';
import { env } from '../config/env.js';

const secret = new TextEncoder().encode(env.JWT_SECRET);
const ALG = 'HS256';

// ─── Gerar token para sessão de ciclista ──────────────────
export async function generateSessionToken(payload) {
  return new SignJWT(payload)
    .setProtectedHeader({ alg: ALG })
    .setIssuedAt()
    .setExpirationTime(`${env.SESSION_TTL_HOURS}h`)
    .setIssuer('pedalada-dos-estados')
    .sign(secret);
}

// ─── Verificar token ──────────────────────────────────────
export async function verifyToken(token) {
  const { payload } = await jwtVerify(token, secret, {
    issuer: 'pedalada-dos-estados',
  });
  return payload;
}

// ─── Fastify hook de autenticação ─────────────────────────
export async function authHook(request, reply) {
  const authHeader = request.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return reply.code(401).send({ error: 'Token ausente' });
  }

  try {
    const token = authHeader.slice(7);
    request.auth = await verifyToken(token);
  } catch (err) {
    return reply.code(401).send({ error: 'Token inválido ou expirado' });
  }
}

// ─── Validar token de WebSocket via query param ───────────
export async function validateWsToken(token) {
  try {
    return await verifyToken(token);
  } catch {
    return null;
  }
}

