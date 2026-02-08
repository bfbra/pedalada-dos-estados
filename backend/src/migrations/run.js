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

