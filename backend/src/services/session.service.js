import { db, sql } from '../models/schema.js';
import { cyclists, sessions } from '../models/schema.js';
import { eq, and } from 'drizzle-orm';
import { nanoid } from 'nanoid';
import { redis, REDIS_KEYS, TTL } from '../config/redis.js';
import { env } from '../config/env.js';
import crypto from 'node:crypto';

// ─── Hash do telefone (LGPD/privacidade) ──────────────────
function hashPhone(phone) {
  return crypto.createHash('sha256').update(phone).digest('hex');
}

// ─── Gerar seed para avatar determinístico ────────────────
function generateAvatarSeed() {
  return nanoid(8);
}

// ─── Encontrar ou criar ciclista ──────────────────────────
export async function findOrCreateCyclist(waId, profileName) {
  const phoneHash = hashPhone(waId);

  const existing = await db
    .select()
    .from(cyclists)
    .where(eq(cyclists.phoneHash, phoneHash))
    .limit(1);

  if (existing.length > 0) {
    await db
      .update(cyclists)
      .set({ lastActiveAt: new Date() })
      .where(eq(cyclists.id, existing[0].id));
    return existing[0];
  }

  const [created] = await db
    .insert(cyclists)
    .values({
      phoneHash,
      waId,
      displayName: profileName || `Ciclista ${nanoid(4)}`,
      avatarSeed: generateAvatarSeed(),
    })
    .returning();

  return created;
}

// ─── Criar sessão de pedal ────────────────────────────────
export async function createSession(cyclistId) {
  // Encerrar sessões ativas anteriores
  await db
    .update(sessions)
    .set({ status: 'ended', endedAt: new Date() })
    .where(and(
      eq(sessions.cyclistId, cyclistId),
      eq(sessions.status, 'active')
    ));

  const shareToken = nanoid(21);

  const [session] = await db
    .insert(sessions)
    .values({
      cyclistId,
      shareToken,
      status: 'active',
    })
    .returning();

  // Cache no Redis
  await redis.setex(
    REDIS_KEYS.sessionMeta(session.id),
    TTL.sessionMeta,
    JSON.stringify({
      id: session.id,
      cyclistId,
      shareToken,
      startedAt: session.startedAt.toISOString(),
    })
  );

  await redis.set(
    REDIS_KEYS.activeSessionByCyclist(cyclistId),
    session.id,
    'EX', TTL.sessionMeta
  );

  return session;
}

// ─── Encerrar sessão ──────────────────────────────────────
export async function endSession(sessionId) {
  const [session] = await db
    .update(sessions)
    .set({ status: 'ended', endedAt: new Date() })
    .where(eq(sessions.id, sessionId))
    .returning();

  if (session) {
    await redis.del(REDIS_KEYS.sessionMeta(sessionId));
    await redis.del(REDIS_KEYS.sessionPosition(sessionId));
    await redis.del(REDIS_KEYS.activeSessionByCyclist(session.cyclistId));
  }

  return session;
}

// ─── Pausar sessão ────────────────────────────────────────
export async function pauseSession(sessionId) {
  const [session] = await db
    .update(sessions)
    .set({ status: 'paused' })
    .where(eq(sessions.id, sessionId))
    .returning();
  return session;
}

// ─── Retomar sessão ──────────────────────────────────────
export async function resumeSession(sessionId) {
  const [session] = await db
    .update(sessions)
    .set({ status: 'active' })
    .where(eq(sessions.id, sessionId))
    .returning();

  if (session) {
    await redis.setex(
      REDIS_KEYS.sessionMeta(sessionId),
      TTL.sessionMeta,
      JSON.stringify({
        id: session.id,
        cyclistId: session.cyclistId,
        shareToken: session.shareToken,
        startedAt: session.startedAt.toISOString(),
      })
    );
  }
  return session;
}

// ─── Buscar sessão por token de compartilhamento ──────────
export async function getSessionByToken(shareToken) {
  const result = await db
    .select({
      session: sessions,
      cyclist: cyclists,
    })
    .from(sessions)
    .innerJoin(cyclists, eq(sessions.cyclistId, cyclists.id))
    .where(eq(sessions.shareToken, shareToken))
    .limit(1);

  return result[0] || null;
}

// ─── Buscar sessão ativa por ciclista ─────────────────────
export async function getActiveSession(cyclistId) {
  // Tentar cache primeiro
  const cachedId = await redis.get(REDIS_KEYS.activeSessionByCyclist(cyclistId));
  if (cachedId) {
    const meta = await redis.get(REDIS_KEYS.sessionMeta(cachedId));
    if (meta) return JSON.parse(meta);
  }

  const result = await db
    .select()
    .from(sessions)
    .where(and(
      eq(sessions.cyclistId, cyclistId),
      eq(sessions.status, 'active')
    ))
    .limit(1);

  return result[0] || null;
}

// ─── Gerar URL de compartilhamento ────────────────────────
export function getShareUrl(shareToken) {
  return `${env.APP_URL}/s/${shareToken}`;
}

