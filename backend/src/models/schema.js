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

