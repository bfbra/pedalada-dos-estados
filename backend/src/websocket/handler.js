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

