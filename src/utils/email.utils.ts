import { promises as dnsPromises } from 'dns';
const DISPOSABLE = new Set(['mailinator.com','guerrillamail.com','tempmail.com','throwaway.email','yopmail.com','trashmail.com','maildrop.cc','10minutemail.com','tempinbox.com','fakeinbox.com','discard.email','spam4.me']);
const FREE = new Set(['gmail.com','yahoo.com','hotmail.com','outlook.com','aol.com','icloud.com','protonmail.com','mail.com','zoho.com','gmx.com','live.com','me.com','googlemail.com']);
const ROLE = new Set(['admin','info','support','help','contact','sales','billing','noreply','no-reply','webmaster','postmaster','abuse','security','marketing','newsletter']);
export async function analyzeEmail(email: string) {
  const valid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  const [username, domain] = email.split('@');
  let mxFound = false;
  if (valid && domain) { try { const mx = await dnsPromises.resolveMx(domain); mxFound = mx.length > 0; } catch { mxFound = false; } }
  const disposable = DISPOSABLE.has(domain?.toLowerCase() ?? '');
  const freeProvider = FREE.has(domain?.toLowerCase() ?? '');
  const roleBased = ROLE.has((username ?? '').toLowerCase().split('+')[0]);
  const isBusiness = !freeProvider && !disposable && mxFound && valid;
  let riskScore = 0;
  if (!valid) riskScore += 40;
  if (!mxFound && valid) riskScore += 20;
  if (disposable) riskScore += 45;
  if (roleBased) riskScore += 10;
  return { valid: valid && mxFound, disposable, free_provider: freeProvider, role_based: roleBased, mx_found: mxFound, is_business: isBusiness, risk_score: Math.min(100, riskScore), domain: domain ?? '' };
}
