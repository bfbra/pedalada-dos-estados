import postgres from 'postgres';
import { config } from 'dotenv';
config();
const sql = postgres(process.env.DATABASE_URL);
try {
  await sql.unsafe('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"');
  console.log('uuid-ossp OK');
  try { await sql.unsafe('CREATE EXTENSION IF NOT EXISTS postgis'); console.log('postgis OK'); } catch(e) { console.log('postgis skip'); }
  await sql.unsafe("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'session_status') THEN CREATE TYPE session_status AS ENUM ('active','paused','ended'); END IF; END $$");
  console.log('enum OK');
  await sql.unsafe("CREATE TABLE IF NOT EXISTS cyclists (id UUID PRIMARY KEY DEFAULT uuid_generate_v4(), phone_hash VARCHAR(64) UNIQUE NOT NULL, wa_id VARCHAR(20) NOT NULL, display_name VARCHAR(100) NOT NULL DEFAULT 'Ciclista', avatar_seed VARCHAR(20), created_at TIMESTAMPTZ DEFAULT NOW(), last_active_at TIMESTAMPTZ DEFAULT NOW())");
  console.log('cyclists OK');
  await sql.unsafe("CREATE TABLE IF NOT EXISTS sessions (id UUID PRIMARY KEY DEFAULT uuid_generate_v4(), cyclist_id UUID REFERENCES cyclists(id), status session_status DEFAULT 'active', share_token VARCHAR(21) UNIQUE NOT NULL, started_at TIMESTAMPTZ DEFAULT NOW(), ended_at TIMESTAMPTZ, route_name VARCHAR(200), total_distance_m FLOAT, avg_speed_kmh FLOAT)");
  console.log('sessions OK');
  await sql.unsafe("CREATE TABLE IF NOT EXISTS locations (id UUID PRIMARY KEY DEFAULT uuid_generate_v4(), session_id UUID REFERENCES sessions(id), lat DOUBLE PRECISION NOT NULL, lng DOUBLE PRECISION NOT NULL, altitude FLOAT, speed FLOAT, heading FLOAT, accuracy FLOAT, recorded_at TIMESTAMPTZ DEFAULT NOW())");
  console.log('locations OK');
  console.log('Migration concluida!');
} catch(e) { console.error(e); }
await sql.end();
