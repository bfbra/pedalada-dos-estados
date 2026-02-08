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

