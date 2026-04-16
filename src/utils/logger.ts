export const logger = {
  info: (obj: unknown, msg?: string) => console.log(JSON.stringify({ level: 'info', ...( typeof obj === 'object' ? obj : { data: obj }), msg })),
  warn: (obj: unknown, msg?: string) => console.warn(JSON.stringify({ level: 'warn', ...(typeof obj === 'object' ? obj : { data: obj }), msg })),
  error: (obj: unknown, msg?: string) => console.error(JSON.stringify({ level: 'error', ...(typeof obj === 'object' ? obj : { data: obj }), msg })),
  fatal: (obj: unknown, msg?: string) => console.error(JSON.stringify({ level: 'fatal', ...(typeof obj === 'object' ? obj : { data: obj }), msg })),
};