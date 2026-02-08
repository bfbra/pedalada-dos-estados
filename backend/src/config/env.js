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

