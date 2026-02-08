import Redis from 'ioredis';
import { env } from '../config/env.js';

// ─── Cliente principal (commands) ─────────────────────────
export const redis = new Redis(env.REDIS_URL, {
  maxRetriesPerRequest: 3,
  retryStrategy: (times) => Math.min(times * 200, 5000),
  enableReadyCheck: true,
  lazyConnect: false,
});

// ─── Cliente dedicado para Pub/Sub (subscriber) ───────────
export const redisSub = new Redis(env.REDIS_URL, {
  maxRetriesPerRequest: 3,
  retryStrategy: (times) => Math.min(times * 200, 5000),
});

// ─── Cliente dedicado para Pub/Sub (publisher) ────────────
export const redisPub = new Redis(env.REDIS_URL, {
  maxRetriesPerRequest: 3,
  retryStrategy: (times) => Math.min(times * 200, 5000),
});

// ─── Keys ─────────────────────────────────────────────────
export const REDIS_KEYS = {
  sessionPosition: (sessionId) => `pos:${sessionId}`,
  sessionChannel: (sessionId) => `ch:session:${sessionId}`,
  discoveryChannel: () => 'ch:discovery',
  sessionMeta: (sessionId) => `meta:${sessionId}`,
  rateLimitWA: (waId) => `rl:wa:${waId}`,
  activeSessionByCyclist: (cyclistId) => `active:${cyclistId}`,
};

// ─── TTL ──────────────────────────────────────────────────
export const TTL = {
  position: env.SESSION_TTL_HOURS * 3600,
  sessionMeta: env.SESSION_TTL_HOURS * 3600,
  rateLimit: 60,
};

redis.on('error', (err) => console.error('[Redis] Erro:', err.message));
redis.on('connect', () => console.log('[Redis] Conectado'));

