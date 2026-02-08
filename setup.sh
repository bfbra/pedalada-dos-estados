#!/bin/bash
set -e

echo "🚴 Criando projeto Pedalada Dos Estados..."

# Create directories
mkdir -p backend/src/{config,middleware,migrations,models,routes,services,websocket}


cat > backend/package.json << 'FILEEOF_8e2fe42c'
{
  "name": "pedalada-dos-estados-backend",
  "version": "1.0.0",
  "type": "module",
  "engines": { "node": ">=20.0.0" },
  "scripts": {
    "dev": "node --watch src/server.js",
    "start": "node src/server.js",
    "migrate": "node src/migrations/run.js",
    "seed": "node src/migrations/seed.js"
  },
  "dependencies": {
    "fastify": "^4.28.0",
    "@fastify/websocket": "^10.0.0",
    "@fastify/cors": "^9.0.0",
    "@fastify/rate-limit": "^9.1.0",
    "@fastify/helmet": "^11.1.0",
    "drizzle-orm": "^0.33.0",
    "postgres": "^3.4.4",
    "ioredis": "^5.4.1",
    "jose": "^5.6.0",
    "nanoid": "^5.0.7",
    "zod": "^3.23.0",
    "pino": "^9.3.0",
    "pino-pretty": "^11.2.0"
  },
  "devDependencies": {
    "drizzle-kit": "^0.24.0"
  }
}

FILEEOF_8e2fe42c

cat > backend/Dockerfile << 'FILEEOF_a5256129'
FROM node:20-alpine AS base
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY src ./src
EXPOSE 3000
CMD ["node", "src/server.js"]

FILEEOF_a5256129

cat > backend/.env.example << 'FILEEOF_ab784fda'
# ─── Server ──────────────────────────────────────────────
NODE_ENV=development
PORT=3000
HOST=0.0.0.0

# ─── PostgreSQL + PostGIS ────────────────────────────────
DATABASE_URL=postgres://pedala:pedala_dev_2024@localhost:5432/pedala_live

# ─── Redis ───────────────────────────────────────────────
REDIS_URL=redis://localhost:6379

# ─── WhatsApp Business API (Meta Cloud API v21.0) ────────
# Obter em: https://developers.facebook.com/apps → WhatsApp → API Setup
WABA_PHONE_NUMBER_ID=
WABA_ACCESS_TOKEN=
WABA_VERIFY_TOKEN=pedala-live-verify-2024
WABA_APP_SECRET=

# ─── JWT ─────────────────────────────────────────────────
# Gerar com: node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
JWT_SECRET=

# ─── Mapbox ──────────────────────────────────────────────
# Obter em: https://account.mapbox.com/access-tokens
MAPBOX_ACCESS_TOKEN=

# ─── App ─────────────────────────────────────────────────
APP_URL=https://pedaladadosestados.com.br
SESSION_TTL_HOURS=4
DISCOVERY_RADIUS_METERS=5000
POSITION_INTERVAL_MS=3000
MAX_INACTIVE_MINUTES=10

FILEEOF_ab784fda

cat > backend/src/config/env.js << 'FILEEOF_36032baa'
import { z } from 'zod';

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.coerce.number().default(3000),
  HOST: z.string().default('0.0.0.0'),

  // PostgreSQL + PostGIS
  DATABASE_URL: z.string().url(),

  // Redis
  REDIS_URL: z.string().url(),

  // WhatsApp Business API (Meta Cloud API)
  WABA_PHONE_NUMBER_ID: z.string().min(1),
  WABA_ACCESS_TOKEN: z.string().min(1),
  WABA_VERIFY_TOKEN: z.string().min(1),
  WABA_APP_SECRET: z.string().min(1),
  WABA_API_VERSION: z.string().default('v21.0'),

  // JWT
  JWT_SECRET: z.string().min(32),

  // Mapbox
  MAPBOX_ACCESS_TOKEN: z.string().min(1),

  // App
  APP_URL: z.string().url().default('https://pedaladadosestados.com.br'),
  SESSION_TTL_HOURS: z.coerce.number().default(4),
  DISCOVERY_RADIUS_METERS: z.coerce.number().default(5000),
  POSITION_INTERVAL_MS: z.coerce.number().default(3000),
  MAX_INACTIVE_MINUTES: z.coerce.number().default(10),
});

export const env = envSchema.parse(process.env);

FILEEOF_36032baa

cat > backend/src/config/redis.js << 'FILEEOF_0de54526'
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

FILEEOF_0de54526

cat > backend/src/models/schema.js << 'FILEEOF_0066ce0d'
import { pgTable, uuid, varchar, timestamp, text, real, index, pgEnum } from 'drizzle-orm/pg-core';
import { sql } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import { env } from '../config/env.js';

// ─── Connection ───────────────────────────────────────────
const queryClient = postgres(env.DATABASE_URL, {
  max: 20,
  idle_timeout: 30,
  connect_timeout: 10,
});

export const db = drizzle(queryClient);
export { sql };

// ─── Enums ────────────────────────────────────────────────
export const sessionStatusEnum = pgEnum('session_status', ['active', 'paused', 'ended']);

// ─── Tables ───────────────────────────────────────────────

export const cyclists = pgTable('cyclists', {
  id: uuid('id').defaultRandom().primaryKey(),
  phoneHash: varchar('phone_hash', { length: 64 }).notNull().unique(),
  waId: varchar('wa_id', { length: 32 }).notNull().unique(),
  displayName: varchar('display_name', { length: 100 }).notNull(),
  avatarSeed: varchar('avatar_seed', { length: 16 }).notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  lastActiveAt: timestamp('last_active_at', { withTimezone: true }).defaultNow().notNull(),
});

export const sessions = pgTable('sessions', {
  id: uuid('id').defaultRandom().primaryKey(),
  cyclistId: uuid('cyclist_id').notNull().references(() => cyclists.id, { onDelete: 'cascade' }),
  status: sessionStatusEnum('status').default('active').notNull(),
  shareToken: varchar('share_token', { length: 21 }).notNull().unique(),
  startedAt: timestamp('started_at', { withTimezone: true }).defaultNow().notNull(),
  endedAt: timestamp('ended_at', { withTimezone: true }),
  routeName: varchar('route_name', { length: 200 }),
  totalDistanceM: real('total_distance_m').default(0),
  avgSpeedKmh: real('avg_speed_kmh').default(0),
}, (table) => ({
  idxCyclistStatus: index('idx_session_cyclist_status').on(table.cyclistId, table.status),
  idxShareToken: index('idx_session_share_token').on(table.shareToken),
}));

export const locations = pgTable('locations', {
  id: uuid('id').defaultRandom().primaryKey(),
  sessionId: uuid('session_id').notNull().references(() => sessions.id, { onDelete: 'cascade' }),
  lat: real('lat').notNull(),
  lng: real('lng').notNull(),
  altitude: real('altitude'),
  speed: real('speed'),
  heading: real('heading'),
  accuracy: real('accuracy'),
  recordedAt: timestamp('recorded_at', { withTimezone: true }).defaultNow().notNull(),
}, (table) => ({
  idxSessionRecorded: index('idx_location_session_recorded').on(table.sessionId, table.recordedAt),
}));

// ─── Raw SQL para PostGIS (executar via migration) ────────
export const postgisMigrationSQL = `
-- Habilitar PostGIS
CREATE EXTENSION IF NOT EXISTS postgis;

-- Adicionar coluna geometry à tabela locations
ALTER TABLE locations ADD COLUMN IF NOT EXISTS point geometry(Point, 4326);

-- Trigger para auto-popular coluna point a partir de lat/lng
CREATE OR REPLACE FUNCTION update_location_point()
RETURNS TRIGGER AS $$
BEGIN
  NEW.point = ST_SetSRID(ST_MakePoint(NEW.lng, NEW.lat), 4326);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_update_location_point ON locations;
CREATE TRIGGER trg_update_location_point
  BEFORE INSERT OR UPDATE OF lat, lng ON locations
  FOR EACH ROW EXECUTE FUNCTION update_location_point();

-- Índice espacial GIST para queries geoespaciais O(log n)
CREATE INDEX IF NOT EXISTS idx_locations_point_gist ON locations USING GIST(point);

-- Índice para busca temporal + espacial combinada
CREATE INDEX IF NOT EXISTS idx_locations_recorded_point
  ON locations (recorded_at DESC) INCLUDE (session_id);

-- View materializada para posições mais recentes por sessão ativa
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_latest_positions AS
SELECT DISTINCT ON (l.session_id)
  l.session_id,
  l.lat,
  l.lng,
  l.point,
  l.speed,
  l.heading,
  l.accuracy,
  l.recorded_at,
  s.cyclist_id,
  c.display_name,
  c.avatar_seed
FROM locations l
JOIN sessions s ON s.id = l.session_id AND s.status = 'active'
JOIN cyclists c ON c.id = s.cyclist_id
ORDER BY l.session_id, l.recorded_at DESC;

CREATE UNIQUE INDEX IF NOT EXISTS idx_mv_latest_session ON mv_latest_positions(session_id);
CREATE INDEX IF NOT EXISTS idx_mv_latest_point ON mv_latest_positions USING GIST(point);

-- Função para refresh incremental (chamada pelo backend a cada 5s)
CREATE OR REPLACE FUNCTION refresh_latest_positions()
RETURNS void AS $$
BEGIN
  REFRESH MATERIALIZED VIEW CONCURRENTLY mv_latest_positions;
END;
$$ LANGUAGE plpgsql;
`;

FILEEOF_0066ce0d

cat > backend/src/middleware/auth.js << 'FILEEOF_a29083d3'
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

FILEEOF_a29083d3

cat > backend/src/server.js << 'FILEEOF_b649a1f3'
import Fastify from 'fastify';
import cors from '@fastify/cors';
import rateLimit from '@fastify/rate-limit';
import helmet from '@fastify/helmet';
import websocket from '@fastify/websocket';
import { env } from './config/env.js';
import { webhookRoutes } from './routes/webhook.routes.js';
import { apiRoutes } from './routes/api.routes.js';
import { websocketRoutes, initRedisSubscriptions } from './websocket/handler.js';
import { refreshLatestPositions } from './services/location.service.js';

// ─── Inicializar Fastify ──────────────────────────────────
const fastify = Fastify({
  logger: {
    level: env.NODE_ENV === 'production' ? 'info' : 'debug',
    transport: env.NODE_ENV !== 'production'
      ? { target: 'pino-pretty', options: { colorize: true } }
      : undefined,
  },
  trustProxy: true,
  bodyLimit: 1048576, // 1MB
});

// ─── Plugins ──────────────────────────────────────────────
await fastify.register(helmet, {
  contentSecurityPolicy: false, // CSP no frontend
});

await fastify.register(cors, {
  origin: [env.APP_URL, 'http://localhost:5173', 'http://localhost:3000'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  credentials: true,
});

await fastify.register(rateLimit, {
  max: 100,
  timeWindow: '1 minute',
  keyGenerator: (request) => request.ip,
});

await fastify.register(websocket, {
  options: {
    maxPayload: 4096,
    perMessageDeflate: false,
  },
});

// ─── Rotas ────────────────────────────────────────────────
await fastify.register(webhookRoutes);
await fastify.register(apiRoutes);
await fastify.register(websocketRoutes);

// ─── Health Check ─────────────────────────────────────────
fastify.get('/health', async () => ({
  status: 'ok',
  uptime: process.uptime(),
  timestamp: new Date().toISOString(),
}));

// ─── Refresh periódico da Materialized View ───────────────
let refreshInterval;

// ─── Start ────────────────────────────────────────────────
async function start() {
  try {
    await fastify.listen({ port: env.PORT, host: env.HOST });
    fastify.log.info(`Pedalada Dos Estados backend rodando em ${env.HOST}:${env.PORT}`);

    // Iniciar subscriptions Redis para broadcast cross-process
    initRedisSubscriptions(fastify.log);

    // Refresh da materialized view a cada 5 segundos
    refreshInterval = setInterval(async () => {
      try {
        await refreshLatestPositions();
      } catch (err) {
        fastify.log.error({ err }, '[MV Refresh] Erro');
      }
    }, 5000);

  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
}

// ─── Graceful Shutdown ────────────────────────────────────
async function shutdown(signal) {
  fastify.log.info(`${signal} recebido, encerrando...`);
  clearInterval(refreshInterval);
  await fastify.close();
  process.exit(0);
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

start();

FILEEOF_b649a1f3

cat > backend/src/migrations/run.js << 'FILEEOF_3fb08126'
import postgres from 'postgres';

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  console.error('DATABASE_URL não definida');
  process.exit(1);
}

const sql = postgres(DATABASE_URL, { max: 1 });

const migration = `
-- ===================================================
-- Pedala Live — Migration 001: Schema Inicial
-- ===================================================

-- Extensões
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "postgis";

-- Enum de status
DO $$ BEGIN
  CREATE TYPE session_status AS ENUM ('active', 'paused', 'ended');
EXCEPTION
  WHEN duplicate_object THEN null;
END $$;

-- Tabela: cyclists
CREATE TABLE IF NOT EXISTS cyclists (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  phone_hash VARCHAR(64) NOT NULL UNIQUE,
  wa_id VARCHAR(32) NOT NULL UNIQUE,
  display_name VARCHAR(100) NOT NULL,
  avatar_seed VARCHAR(16) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_active_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Tabela: sessions
CREATE TABLE IF NOT EXISTS sessions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  cyclist_id UUID NOT NULL REFERENCES cyclists(id) ON DELETE CASCADE,
  status session_status NOT NULL DEFAULT 'active',
  share_token VARCHAR(21) NOT NULL UNIQUE,
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ended_at TIMESTAMPTZ,
  route_name VARCHAR(200),
  total_distance_m REAL DEFAULT 0,
  avg_speed_kmh REAL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_session_cyclist_status ON sessions(cyclist_id, status);
CREATE INDEX IF NOT EXISTS idx_session_share_token ON sessions(share_token);

-- Tabela: locations
CREATE TABLE IF NOT EXISTS locations (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  lat REAL NOT NULL,
  lng REAL NOT NULL,
  point geometry(Point, 4326),
  altitude REAL,
  speed REAL,
  heading REAL,
  accuracy REAL,
  recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_location_session_recorded ON locations(session_id, recorded_at);
CREATE INDEX IF NOT EXISTS idx_locations_point_gist ON locations USING GIST(point);
CREATE INDEX IF NOT EXISTS idx_locations_recorded_point ON locations(recorded_at DESC) INCLUDE (session_id);

-- Trigger: auto-popular coluna point
CREATE OR REPLACE FUNCTION update_location_point()
RETURNS TRIGGER AS $$
BEGIN
  NEW.point = ST_SetSRID(ST_MakePoint(NEW.lng, NEW.lat), 4326);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_update_location_point ON locations;
CREATE TRIGGER trg_update_location_point
  BEFORE INSERT OR UPDATE OF lat, lng ON locations
  FOR EACH ROW EXECUTE FUNCTION update_location_point();

-- Materialized View: posições mais recentes
DROP MATERIALIZED VIEW IF EXISTS mv_latest_positions;
CREATE MATERIALIZED VIEW mv_latest_positions AS
SELECT DISTINCT ON (l.session_id)
  l.session_id,
  l.lat,
  l.lng,
  l.point,
  l.speed,
  l.heading,
  l.accuracy,
  l.recorded_at,
  s.cyclist_id,
  c.display_name,
  c.avatar_seed
FROM locations l
JOIN sessions s ON s.id = l.session_id AND s.status = 'active'
JOIN cyclists c ON c.id = s.cyclist_id
ORDER BY l.session_id, l.recorded_at DESC;

CREATE UNIQUE INDEX IF NOT EXISTS idx_mv_latest_session ON mv_latest_positions(session_id);
CREATE INDEX IF NOT EXISTS idx_mv_latest_point ON mv_latest_positions USING GIST(point);

-- Função: refresh concorrente
CREATE OR REPLACE FUNCTION refresh_latest_positions()
RETURNS void AS $$
BEGIN
  REFRESH MATERIALIZED VIEW CONCURRENTLY mv_latest_positions;
END;
$$ LANGUAGE plpgsql;

-- ===================================================
-- FIM DA MIGRATION
-- ===================================================
`;

async function run() {
  console.log('[Migration] Executando migration 001...');
  try {
    await sql.unsafe(migration);
    console.log('[Migration] Concluída com sucesso.');
  } catch (err) {
    console.error('[Migration] Erro:', err.message);
    process.exit(1);
  } finally {
    await sql.end();
  }
}

run();

FILEEOF_3fb08126

cat > backend/src/services/whatsapp.service.js << 'FILEEOF_46211af4'
import { env } from '../config/env.js';
import crypto from 'node:crypto';

const API_BASE = `https://graph.facebook.com/${env.WABA_API_VERSION}/${env.WABA_PHONE_NUMBER_ID}`;

// ─── Verificação de Assinatura do Webhook ─────────────────
export function verifyWebhookSignature(rawBody, signature) {
  const expectedSig = crypto
    .createHmac('sha256', env.WABA_APP_SECRET)
    .update(rawBody)
    .digest('hex');
  return crypto.timingSafeEqual(
    Buffer.from(`sha256=${expectedSig}`),
    Buffer.from(signature)
  );
}

// ─── Enviar Mensagem de Texto ─────────────────────────────
export async function sendTextMessage(to, text) {
  const response = await fetch(`${API_BASE}/messages`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.WABA_ACCESS_TOKEN}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      messaging_product: 'whatsapp',
      recipient_type: 'individual',
      to,
      type: 'text',
      text: { preview_url: true, body: text },
    }),
  });

  if (!response.ok) {
    const err = await response.json();
    throw new Error(`WABA sendText failed: ${JSON.stringify(err)}`);
  }
  return response.json();
}

// ─── Enviar Mensagem Interativa com Botão ─────────────────
export async function sendInteractiveButton(to, { bodyText, buttons }) {
  const response = await fetch(`${API_BASE}/messages`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.WABA_ACCESS_TOKEN}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      messaging_product: 'whatsapp',
      recipient_type: 'individual',
      to,
      type: 'interactive',
      interactive: {
        type: 'button',
        body: { text: bodyText },
        action: {
          buttons: buttons.map((btn, i) => ({
            type: 'reply',
            reply: { id: btn.id, title: btn.title },
          })),
        },
      },
    }),
  });

  if (!response.ok) {
    const err = await response.json();
    throw new Error(`WABA sendInteractive failed: ${JSON.stringify(err)}`);
  }
  return response.json();
}

// ─── Enviar Mensagem com Link (CTA URL Button) ───────────
export async function sendCTAMessage(to, { headerText, bodyText, footerText, buttonText, url }) {
  const response = await fetch(`${API_BASE}/messages`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.WABA_ACCESS_TOKEN}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      messaging_product: 'whatsapp',
      recipient_type: 'individual',
      to,
      type: 'interactive',
      interactive: {
        type: 'cta_url',
        header: headerText ? { type: 'text', text: headerText } : undefined,
        body: { text: bodyText },
        footer: footerText ? { text: footerText } : undefined,
        action: {
          name: 'cta_url',
          parameters: {
            display_text: buttonText,
            url,
          },
        },
      },
    }),
  });

  if (!response.ok) {
    const err = await response.json();
    throw new Error(`WABA sendCTA failed: ${JSON.stringify(err)}`);
  }
  return response.json();
}

// ─── Enviar Location Request ──────────────────────────────
export async function sendLocationRequest(to, bodyText) {
  const response = await fetch(`${API_BASE}/messages`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.WABA_ACCESS_TOKEN}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      messaging_product: 'whatsapp',
      recipient_type: 'individual',
      to,
      type: 'interactive',
      interactive: {
        type: 'location_request_message',
        body: { text: bodyText },
        action: { name: 'send_location' },
      },
    }),
  });

  if (!response.ok) {
    const err = await response.json();
    throw new Error(`WABA sendLocationRequest failed: ${JSON.stringify(err)}`);
  }
  return response.json();
}

// ─── Marcar Mensagem como Lida ────────────────────────────
export async function markAsRead(messageId) {
  await fetch(`${API_BASE}/messages`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.WABA_ACCESS_TOKEN}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      messaging_product: 'whatsapp',
      status: 'read',
      message_id: messageId,
    }),
  });
}

// ─── Template: Sessão Iniciada ────────────────────────────
export async function sendSessionStartedTemplate(to, { displayName, shareUrl }) {
  return sendCTAMessage(to, {
    headerText: '🚴 Pedalada Dos Estados',
    bodyText: `Olá ${displayName}! Sua sessão de pedal está ativa.\n\nCompartilhe este link com seus amigos para que eles acompanhem sua posição em tempo real:`,
    footerText: 'Envie "parar" para encerrar',
    buttonText: '📍 Abrir Mapa ao Vivo',
    url: shareUrl,
  });
}

FILEEOF_46211af4

cat > backend/src/services/session.service.js << 'FILEEOF_b276cfca'
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

FILEEOF_b276cfca

cat > backend/src/services/location.service.js << 'FILEEOF_38442801'
import { db, sql } from '../models/schema.js';
import { locations, sessions } from '../models/schema.js';
import { eq, and, gte, desc } from 'drizzle-orm';
import { redis, redisPub, REDIS_KEYS, TTL } from '../config/redis.js';
import { env } from '../config/env.js';

// ─── Registrar posição ───────────────────────────────────
export async function recordPosition(sessionId, position) {
  const { lat, lng, altitude, speed, heading, accuracy } = position;
  const now = new Date();

  // 1. Persistir no PostgreSQL
  const [location] = await db
    .insert(locations)
    .values({
      sessionId,
      lat,
      lng,
      altitude: altitude || null,
      speed: speed || null,
      heading: heading || null,
      accuracy: accuracy || null,
      recordedAt: now,
    })
    .returning();

  // 2. Cache no Redis (posição mais recente para acesso rápido)
  const posData = JSON.stringify({
    sessionId,
    lat,
    lng,
    speed,
    heading,
    accuracy,
    altitude,
    recordedAt: now.toISOString(),
  });

  await redis.setex(REDIS_KEYS.sessionPosition(sessionId), TTL.position, posData);

  // 3. Publicar no canal da sessão (observers do mapa)
  await redisPub.publish(REDIS_KEYS.sessionChannel(sessionId), posData);

  // 4. Publicar no canal de descoberta (ciclistas próximos)
  await redisPub.publish(REDIS_KEYS.discoveryChannel(), posData);

  return location;
}

// ─── Buscar última posição (Redis-first) ──────────────────
export async function getLatestPosition(sessionId) {
  const cached = await redis.get(REDIS_KEYS.sessionPosition(sessionId));
  if (cached) return JSON.parse(cached);

  const result = await db
    .select()
    .from(locations)
    .where(eq(locations.sessionId, sessionId))
    .orderBy(desc(locations.recordedAt))
    .limit(1);

  return result[0] || null;
}

// ─── Buscar trail (últimos N pontos para polyline) ────────
export async function getTrail(sessionId, limit = 200) {
  const result = await db
    .select({
      lat: locations.lat,
      lng: locations.lng,
      speed: locations.speed,
      recordedAt: locations.recordedAt,
    })
    .from(locations)
    .where(eq(locations.sessionId, sessionId))
    .orderBy(desc(locations.recordedAt))
    .limit(limit);

  return result.reverse(); // cronológico
}

// ─── Descobrir ciclistas próximos via PostGIS ─────────────
export async function discoverNearbyCyclists(lat, lng, radiusMeters = env.DISCOVERY_RADIUS_METERS, excludeSessionId = null) {
  const query = sql`
    SELECT
      mv.session_id,
      mv.cyclist_id,
      mv.display_name,
      mv.avatar_seed,
      mv.lat,
      mv.lng,
      mv.speed,
      mv.heading,
      mv.recorded_at,
      ST_Distance(
        mv.point::geography,
        ST_SetSRID(ST_MakePoint(${lng}, ${lat}), 4326)::geography
      ) AS distance_m
    FROM mv_latest_positions mv
    WHERE ST_DWithin(
      mv.point::geography,
      ST_SetSRID(ST_MakePoint(${lng}, ${lat}), 4326)::geography,
      ${radiusMeters}
    )
    ${excludeSessionId ? sql`AND mv.session_id != ${excludeSessionId}` : sql``}
    AND mv.recorded_at > NOW() - INTERVAL '${sql.raw(String(env.MAX_INACTIVE_MINUTES))} minutes'
    ORDER BY distance_m ASC
    LIMIT 50
  `;

  const result = await db.execute(query);
  return result.rows || result;
}

// ─── Calcular estatísticas da sessão ──────────────────────
export async function calculateSessionStats(sessionId) {
  const query = sql`
    WITH ordered AS (
      SELECT
        lat, lng, speed, recorded_at,
        LAG(point) OVER (ORDER BY recorded_at) AS prev_point,
        LAG(recorded_at) OVER (ORDER BY recorded_at) AS prev_time
      FROM locations
      WHERE session_id = ${sessionId}
      ORDER BY recorded_at
    )
    SELECT
      COALESCE(SUM(
        ST_Distance(
          ST_SetSRID(ST_MakePoint(lng, lat), 4326)::geography,
          prev_point::geography
        )
      ), 0) AS total_distance_m,
      COALESCE(AVG(speed) FILTER (WHERE speed > 0.5), 0) AS avg_speed_ms,
      COALESCE(MAX(speed), 0) AS max_speed_ms,
      COUNT(*) AS total_points,
      MIN(recorded_at) AS first_point_at,
      MAX(recorded_at) AS last_point_at
    FROM ordered
    WHERE prev_point IS NOT NULL
  `;

  const result = await db.execute(query);
  const row = (result.rows || result)[0];

  return {
    totalDistanceKm: (parseFloat(row.total_distance_m) / 1000).toFixed(2),
    avgSpeedKmh: (parseFloat(row.avg_speed_ms) * 3.6).toFixed(1),
    maxSpeedKmh: (parseFloat(row.max_speed_ms) * 3.6).toFixed(1),
    totalPoints: parseInt(row.total_points),
    durationMinutes: row.first_point_at && row.last_point_at
      ? Math.round((new Date(row.last_point_at) - new Date(row.first_point_at)) / 60000)
      : 0,
  };
}

// ─── Refresh da Materialized View (cron job) ──────────────
export async function refreshLatestPositions() {
  await db.execute(sql`SELECT refresh_latest_positions()`);
}

FILEEOF_38442801

cat > backend/src/routes/webhook.routes.js << 'FILEEOF_a105d00b'
import { env } from '../config/env.js';
import {
  verifyWebhookSignature,
  sendTextMessage,
  sendInteractiveButton,
  sendSessionStartedTemplate,
  sendLocationRequest,
  markAsRead,
} from '../services/whatsapp.service.js';
import {
  findOrCreateCyclist,
  createSession,
  endSession,
  getActiveSession,
  getShareUrl,
} from '../services/session.service.js';
import { recordPosition } from '../services/location.service.js';
import { generateSessionToken } from '../middleware/auth.js';
import { redis, REDIS_KEYS } from '../config/redis.js';

// ─── Comandos reconhecidos ────────────────────────────────
const COMMANDS = {
  START: ['pedalar', 'iniciar', 'start', 'go', 'bora', '🚴', '🚴‍♂️', '🚴‍♀️'],
  STOP: ['parar', 'stop', 'fim', 'encerrar', 'cheguei'],
  STATUS: ['status', 'onde', 'link'],
  HELP: ['ajuda', 'help', 'menu', 'oi', 'olá', 'ola', 'hi'],
};

function matchCommand(text, commands) {
  const normalized = text.toLowerCase().trim();
  return commands.some(cmd => normalized === cmd || normalized.startsWith(cmd + ' '));
}

// ─── Rate limiting por WhatsApp ID ────────────────────────
async function checkRateLimit(waId) {
  const key = REDIS_KEYS.rateLimitWA(waId);
  const count = await redis.incr(key);
  if (count === 1) await redis.expire(key, 60);
  return count <= 10; // max 10 mensagens por minuto
}

// ─── Registrar rotas do webhook ───────────────────────────
export async function webhookRoutes(fastify) {

  // GET - Verificação do webhook (Meta handshake)
  fastify.get('/webhook/whatsapp', {
    schema: {
      querystring: {
        type: 'object',
        properties: {
          'hub.mode': { type: 'string' },
          'hub.verify_token': { type: 'string' },
          'hub.challenge': { type: 'string' },
        },
      },
    },
  }, async (request, reply) => {
    const mode = request.query['hub.mode'];
    const token = request.query['hub.verify_token'];
    const challenge = request.query['hub.challenge'];

    if (mode === 'subscribe' && token === env.WABA_VERIFY_TOKEN) {
      fastify.log.info('[Webhook] Verificação bem-sucedida');
      return reply.code(200).send(challenge);
    }

    return reply.code(403).send('Verificação falhou');
  });

  // POST - Receber mensagens
  fastify.post('/webhook/whatsapp', {
    config: { rawBody: true },
  }, async (request, reply) => {
    // Validar assinatura HMAC
    const signature = request.headers['x-hub-signature-256'];
    if (signature) {
      const rawBody = typeof request.body === 'string'
        ? request.body
        : JSON.stringify(request.body);
      if (!verifyWebhookSignature(rawBody, signature)) {
        fastify.log.warn('[Webhook] Assinatura inválida');
        return reply.code(401).send('Assinatura inválida');
      }
    }

    // Responder 200 imediatamente (Meta exige resposta em <5s)
    reply.code(200).send('OK');

    // Processar assincronamente
    try {
      await processWebhookPayload(request.body, fastify.log);
    } catch (err) {
      fastify.log.error({ err }, '[Webhook] Erro no processamento');
    }
  });
}

// ─── Pipeline de processamento ────────────────────────────
async function processWebhookPayload(body, log) {
  const entries = body?.entry;
  if (!entries?.length) return;

  for (const entry of entries) {
    const changes = entry.changes;
    if (!changes?.length) continue;

    for (const change of changes) {
      if (change.field !== 'messages') continue;

      const value = change.value;
      const messages = value?.messages;
      if (!messages?.length) continue;

      const contacts = value?.contacts || [];

      for (const message of messages) {
        await processMessage(message, contacts, log);
      }
    }
  }
}

// ─── Processar mensagem individual ────────────────────────
async function processMessage(message, contacts, log) {
  const waId = message.from;
  const messageId = message.id;
  const type = message.type;

  // Rate limiting
  if (!(await checkRateLimit(waId))) {
    log.warn({ waId }, '[Webhook] Rate limit excedido');
    return;
  }

  // Marcar como lida
  await markAsRead(messageId);

  // Extrair nome do perfil
  const contact = contacts.find(c => c.wa_id === waId);
  const profileName = contact?.profile?.name || null;

  // Encontrar ou criar ciclista
  const cyclist = await findOrCreateCyclist(waId, profileName);

  // ─── Processar por tipo ─────────────────────────────
  if (type === 'text') {
    await handleTextMessage(waId, message.text.body, cyclist, log);
  } else if (type === 'location') {
    await handleLocationMessage(waId, message.location, cyclist, log);
  } else if (type === 'interactive') {
    const buttonId = message.interactive?.button_reply?.id;
    if (buttonId) {
      await handleButtonReply(waId, buttonId, cyclist, log);
    }
  }
}

// ─── Handler: Mensagem de texto ───────────────────────────
async function handleTextMessage(waId, text, cyclist, log) {
  log.info({ waId, text }, '[Webhook] Texto recebido');

  if (matchCommand(text, COMMANDS.START)) {
    await handleStartCommand(waId, cyclist, log);
  } else if (matchCommand(text, COMMANDS.STOP)) {
    await handleStopCommand(waId, cyclist, log);
  } else if (matchCommand(text, COMMANDS.STATUS)) {
    await handleStatusCommand(waId, cyclist, log);
  } else if (matchCommand(text, COMMANDS.HELP)) {
    await handleHelpCommand(waId, cyclist);
  } else {
    await handleHelpCommand(waId, cyclist);
  }
}

// ─── Handler: Localização recebida via WhatsApp ───────────
async function handleLocationMessage(waId, location, cyclist, log) {
  log.info({ waId, lat: location.latitude, lng: location.longitude }, '[Webhook] Localização recebida');

  const activeSession = await getActiveSession(cyclist.id);
  if (!activeSession) {
    await sendTextMessage(waId, '⚠️ Nenhuma sessão ativa. Envie "pedalar" para iniciar.');
    return;
  }

  await recordPosition(activeSession.id, {
    lat: location.latitude,
    lng: location.longitude,
    altitude: null,
    speed: null,
    heading: null,
    accuracy: null,
  });

  await sendTextMessage(waId, '📍 Posição registrada! Para tracking contínuo, use o link do mapa.');
}

// ─── Handler: Botão interativo ────────────────────────────
async function handleButtonReply(waId, buttonId, cyclist, log) {
  log.info({ waId, buttonId }, '[Webhook] Botão clicado');

  switch (buttonId) {
    case 'btn_start':
      await handleStartCommand(waId, cyclist, log);
      break;
    case 'btn_stop':
      await handleStopCommand(waId, cyclist, log);
      break;
    case 'btn_status':
      await handleStatusCommand(waId, cyclist, log);
      break;
  }
}

// ─── Comando: Iniciar pedal ───────────────────────────────
async function handleStartCommand(waId, cyclist, log) {
  const existing = await getActiveSession(cyclist.id);
  if (existing) {
    const shareUrl = getShareUrl(existing.shareToken);
    await sendTextMessage(waId,
      `🚴 Você já tem uma sessão ativa!\n\n📍 Link: ${shareUrl}\n\nEnvie "parar" para encerrar e iniciar outra.`
    );
    return;
  }

  const session = await createSession(cyclist.id);
  const shareUrl = getShareUrl(session.shareToken);

  // Gerar JWT para o frontend
  const token = await generateSessionToken({
    sessionId: session.id,
    cyclistId: cyclist.id,
    role: 'owner',
  });

  log.info({ sessionId: session.id, cyclistId: cyclist.id }, '[Session] Nova sessão criada');

  await sendSessionStartedTemplate(waId, {
    displayName: cyclist.displayName,
    shareUrl: `${shareUrl}?t=${token}`,
  });
}

// ─── Comando: Parar pedal ─────────────────────────────────
async function handleStopCommand(waId, cyclist, log) {
  const activeSession = await getActiveSession(cyclist.id);
  if (!activeSession) {
    await sendTextMessage(waId, '⚠️ Nenhuma sessão ativa no momento.');
    return;
  }

  const session = await endSession(activeSession.id);
  log.info({ sessionId: activeSession.id }, '[Session] Sessão encerrada');

  await sendTextMessage(waId,
    `🏁 Sessão encerrada!\n\nBom pedal, ${cyclist.displayName}! 🚴‍♂️\n\nEnvie "pedalar" para uma nova sessão.`
  );
}

// ─── Comando: Status ──────────────────────────────────────
async function handleStatusCommand(waId, cyclist, log) {
  const activeSession = await getActiveSession(cyclist.id);
  if (!activeSession) {
    await sendInteractiveButton(waId, {
      bodyText: '📊 Nenhuma sessão ativa.\n\nDeseja iniciar um pedal agora?',
      buttons: [
        { id: 'btn_start', title: '🚴 Pedalar' },
      ],
    });
    return;
  }

  const shareUrl = getShareUrl(activeSession.shareToken);
  await sendTextMessage(waId,
    `📊 Sessão ativa desde ${new Date(activeSession.startedAt).toLocaleTimeString('pt-BR')}\n\n📍 Link: ${shareUrl}\n\nEnvie "parar" para encerrar.`
  );
}

// ─── Comando: Ajuda ───────────────────────────────────────
async function handleHelpCommand(waId, cyclist) {
  await sendInteractiveButton(waId, {
    bodyText: `🚴 *Pedalada Dos Estados 2026*\n\nOlá, ${cyclist.displayName}!\n\nCompartilhe sua posição em tempo real durante seus pedais.\n\n*Comandos:*\n• "pedalar" → Iniciar sessão\n• "parar" → Encerrar sessão\n• "status" → Ver sessão ativa\n• "ajuda" → Este menu`,
    buttons: [
      { id: 'btn_start', title: '🚴 Pedalar' },
      { id: 'btn_status', title: '📊 Status' },
    ],
  });
}

FILEEOF_a105d00b

cat > backend/src/routes/api.routes.js << 'FILEEOF_ab65c0ca'
import { authHook } from '../middleware/auth.js';
import {
  getSessionByToken,
  endSession,
  pauseSession,
  resumeSession,
} from '../services/session.service.js';
import {
  getLatestPosition,
  getTrail,
  calculateSessionStats,
  discoverNearbyCyclists,
} from '../services/location.service.js';

export async function apiRoutes(fastify) {

  // ─── GET /api/session/:shareToken ── Info pública da sessão ──
  fastify.get('/api/session/:shareToken', {
    schema: {
      params: {
        type: 'object',
        properties: { shareToken: { type: 'string', minLength: 21, maxLength: 21 } },
        required: ['shareToken'],
      },
    },
  }, async (request, reply) => {
    const { shareToken } = request.params;
    const data = await getSessionByToken(shareToken);

    if (!data) {
      return reply.code(404).send({ error: 'Sessão não encontrada' });
    }

    const { session, cyclist } = data;
    const latestPos = await getLatestPosition(session.id);

    return {
      session: {
        id: session.id,
        status: session.status,
        startedAt: session.startedAt,
        endedAt: session.endedAt,
        shareToken: session.shareToken,
      },
      cyclist: {
        displayName: cyclist.displayName,
        avatarSeed: cyclist.avatarSeed,
      },
      latestPosition: latestPos,
    };
  });

  // ─── GET /api/session/:shareToken/trail ── Rota percorrida ──
  fastify.get('/api/session/:shareToken/trail', async (request, reply) => {
    const { shareToken } = request.params;
    const limit = parseInt(request.query.limit) || 200;

    const data = await getSessionByToken(shareToken);
    if (!data) return reply.code(404).send({ error: 'Sessão não encontrada' });

    const trail = await getTrail(data.session.id, Math.min(limit, 1000));
    return { trail };
  });

  // ─── GET /api/session/:shareToken/stats ── Estatísticas ─────
  fastify.get('/api/session/:shareToken/stats', async (request, reply) => {
    const { shareToken } = request.params;
    const data = await getSessionByToken(shareToken);
    if (!data) return reply.code(404).send({ error: 'Sessão não encontrada' });

    const stats = await calculateSessionStats(data.session.id);
    return { stats };
  });

  // ─── Rotas autenticadas (owner) ─────────────────────────
  fastify.register(async (app) => {
    app.addHook('preHandler', authHook);

    // POST /api/session/end
    app.post('/api/session/end', async (request, reply) => {
      const { sessionId } = request.auth;
      const session = await endSession(sessionId);
      if (!session) return reply.code(404).send({ error: 'Sessão não encontrada' });
      return { status: 'ended', session };
    });

    // POST /api/session/pause
    app.post('/api/session/pause', async (request, reply) => {
      const { sessionId } = request.auth;
      const session = await pauseSession(sessionId);
      if (!session) return reply.code(404).send({ error: 'Sessão não encontrada' });
      return { status: 'paused', session };
    });

    // POST /api/session/resume
    app.post('/api/session/resume', async (request, reply) => {
      const { sessionId } = request.auth;
      const session = await resumeSession(sessionId);
      if (!session) return reply.code(404).send({ error: 'Sessão não encontrada' });
      return { status: 'active', session };
    });

    // GET /api/discover ── Ciclistas próximos
    app.get('/api/discover', {
      schema: {
        querystring: {
          type: 'object',
          properties: {
            lat: { type: 'number' },
            lng: { type: 'number' },
            radius: { type: 'number', default: 5000 },
          },
          required: ['lat', 'lng'],
        },
      },
    }, async (request, reply) => {
      const { lat, lng, radius } = request.query;
      const { sessionId } = request.auth;
      const nearby = await discoverNearbyCyclists(lat, lng, radius, sessionId);

      return {
        cyclists: nearby.map(c => ({
          sessionId: c.session_id,
          displayName: c.display_name,
          avatarSeed: c.avatar_seed,
          lat: c.lat,
          lng: c.lng,
          speed: c.speed,
          heading: c.heading,
          distanceM: Math.round(parseFloat(c.distance_m)),
          recordedAt: c.recorded_at,
        })),
      };
    });
  });
}

FILEEOF_ab65c0ca

cat > backend/src/websocket/handler.js << 'FILEEOF_bee70a3a'
import { validateWsToken } from '../middleware/auth.js';
import { redisSub, REDIS_KEYS } from '../config/redis.js';
import { recordPosition, getTrail, getLatestPosition, discoverNearbyCyclists } from '../services/location.service.js';
import { getSessionByToken } from '../services/session.service.js';

// ─── Conexões ativas por sessão ───────────────────────────
const sessionSubscribers = new Map(); // sessionId -> Set<WebSocket>
const discoverySubscribers = new Set(); // WebSocket set para discovery

// ─── Registrar rotas WebSocket ────────────────────────────
export async function websocketRoutes(fastify) {

  // ─── WS: Tracking de sessão (owner envia, observers recebem) ──
  fastify.get('/ws/track/:shareToken', { websocket: true }, async (socket, request) => {
    const { shareToken } = request.params;
    const token = request.query.t;

    // Buscar sessão pelo token
    const sessionData = await getSessionByToken(shareToken);
    if (!sessionData) {
      socket.send(JSON.stringify({ type: 'error', message: 'Sessão não encontrada' }));
      socket.close(4004, 'Session not found');
      return;
    }

    const { session, cyclist } = sessionData;
    let role = 'observer';
    let authPayload = null;

    // Verificar se é owner (tem JWT válido)
    if (token) {
      authPayload = await validateWsToken(token);
      if (authPayload?.sessionId === session.id) {
        role = 'owner';
      }
    }

    // Registrar subscriber
    if (!sessionSubscribers.has(session.id)) {
      sessionSubscribers.set(session.id, new Set());
    }
    sessionSubscribers.get(session.id).add(socket);

    fastify.log.info({
      sessionId: session.id,
      role,
      subscribers: sessionSubscribers.get(session.id).size,
    }, '[WS] Conexão estabelecida');

    // Enviar estado inicial
    const latestPos = await getLatestPosition(session.id);
    const trail = await getTrail(session.id, 200);

    socket.send(JSON.stringify({
      type: 'init',
      session: {
        id: session.id,
        status: session.status,
        startedAt: session.startedAt,
        cyclist: {
          displayName: cyclist.displayName,
          avatarSeed: cyclist.avatarSeed,
        },
      },
      role,
      latestPosition: latestPos,
      trail,
      viewerCount: sessionSubscribers.get(session.id).size,
    }));

    // Broadcast viewer count
    broadcastToSession(session.id, {
      type: 'viewers',
      count: sessionSubscribers.get(session.id).size,
    }, socket);

    // ─── Handler: mensagens recebidas do cliente ──────
    socket.on('message', async (raw) => {
      try {
        const msg = JSON.parse(raw.toString());

        if (msg.type === 'position' && role === 'owner') {
          // Owner enviando posição
          const { lat, lng, altitude, speed, heading, accuracy } = msg;
          await recordPosition(session.id, { lat, lng, altitude, speed, heading, accuracy });

          // Broadcast para observers via memória local (complementa Redis pub/sub)
          broadcastToSession(session.id, {
            type: 'position',
            lat, lng, speed, heading, accuracy, altitude,
            recordedAt: new Date().toISOString(),
          }, socket);
        }

        if (msg.type === 'ping') {
          socket.send(JSON.stringify({ type: 'pong', ts: Date.now() }));
        }
      } catch (err) {
        fastify.log.error({ err }, '[WS] Erro ao processar mensagem');
      }
    });

    // ─── Cleanup na desconexão ────────────────────────
    socket.on('close', () => {
      const subs = sessionSubscribers.get(session.id);
      if (subs) {
        subs.delete(socket);
        if (subs.size === 0) {
          sessionSubscribers.delete(session.id);
        } else {
          broadcastToSession(session.id, {
            type: 'viewers',
            count: subs.size,
          });
        }
      }
    });

    socket.on('error', (err) => {
      fastify.log.error({ err }, '[WS] Erro no socket');
    });
  });

  // ─── WS: Discovery (ciclistas próximos) ────────────────
  fastify.get('/ws/discover', { websocket: true }, async (socket, request) => {
    const token = request.query.t;
    const authPayload = await validateWsToken(token);

    if (!authPayload) {
      socket.send(JSON.stringify({ type: 'error', message: 'Autenticação necessária' }));
      socket.close(4001, 'Unauthorized');
      return;
    }

    discoverySubscribers.add(socket);

    socket.on('message', async (raw) => {
      try {
        const msg = JSON.parse(raw.toString());

        if (msg.type === 'discover') {
          const { lat, lng, radius } = msg;
          const nearby = await discoverNearbyCyclists(
            lat, lng,
            radius || undefined,
            authPayload.sessionId
          );

          socket.send(JSON.stringify({
            type: 'nearby',
            cyclists: nearby.map(c => ({
              sessionId: c.session_id,
              displayName: c.display_name,
              avatarSeed: c.avatar_seed,
              lat: c.lat,
              lng: c.lng,
              speed: c.speed,
              heading: c.heading,
              distanceM: Math.round(parseFloat(c.distance_m)),
              recordedAt: c.recorded_at,
            })),
          }));
        }
      } catch (err) {
        fastify.log.error({ err }, '[WS Discovery] Erro');
      }
    });

    socket.on('close', () => {
      discoverySubscribers.delete(socket);
    });
  });
}

// ─── Broadcast para subscribers de uma sessão ─────────────
function broadcastToSession(sessionId, data, excludeSocket = null) {
  const subs = sessionSubscribers.get(sessionId);
  if (!subs) return;

  const payload = JSON.stringify(data);
  for (const ws of subs) {
    if (ws !== excludeSocket && ws.readyState === 1) {
      ws.send(payload);
    }
  }
}

// ─── Redis Pub/Sub listener (para broadcast cross-process) ─
export function initRedisSubscriptions(log) {
  redisSub.psubscribe('ch:session:*', (err) => {
    if (err) log.error({ err }, '[Redis Sub] Erro ao subscrever');
    else log.info('[Redis Sub] Inscrito em ch:session:*');
  });

  redisSub.on('pmessage', (pattern, channel, message) => {
    // ch:session:{sessionId}
    const sessionId = channel.replace('ch:session:', '');
    const subs = sessionSubscribers.get(sessionId);
    if (!subs || subs.size === 0) return;

    // Broadcast para todos os observers (posição já veio formatada)
    for (const ws of subs) {
      if (ws.readyState === 1) {
        ws.send(JSON.stringify({
          type: 'position',
          ...JSON.parse(message),
        }));
      }
    }
  });
}

FILEEOF_bee70a3a

echo "📦 Instalando dependências..."
cd backend
npm install

echo ""
echo "✅ Projeto criado com sucesso!"
echo ""
echo "Próximo passo: configure as variáveis de ambiente no .env"
echo "  cp .env.example .env"
echo "  nano .env"
