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

