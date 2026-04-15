import pino from 'pino';
import { config } from './config';
export const logger = pino({
  level: config.logging.level,
  base: { service: 'trust-api' },
  timestamp: pino.stdTimeFunctions.isoTime,
});
