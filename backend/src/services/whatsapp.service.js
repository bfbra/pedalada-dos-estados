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

