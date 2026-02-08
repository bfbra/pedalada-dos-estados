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

