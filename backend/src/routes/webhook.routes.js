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

