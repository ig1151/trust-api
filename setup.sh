#!/bin/bash
set -e

echo "🚀 Building Trust API..."

cat > src/types/index.ts << 'HEREDOC'
export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';
export type TrustLevel = 'trusted' | 'neutral' | 'suspicious' | 'blocked';
export type Recommendation = 'allow' | 'verify' | 'block';
export type WalletType = 'trader' | 'bot' | 'whale' | 'mixer' | 'scammer' | 'dormant' | 'new' | 'unknown';
export type Chain = 'ethereum' | 'solana' | 'bnb' | 'xrp' | 'auto';

export interface TrustRequest {
  email?: string;
  phone?: string;
  ip?: string;
  wallet_address?: string;
  wallet_chain?: Chain;
  country_code?: string;
}

export interface Web2Risk {
  score: number;
  level: RiskLevel;
  email?: {
    valid: boolean;
    disposable: boolean;
    free_provider: boolean;
    role_based: boolean;
    is_business: boolean;
    risk_score: number;
  };
  phone?: {
    valid: boolean;
    line_type: string;
    is_voip: boolean;
    is_likely_fake: boolean;
    risk_score: number;
  };
  ip?: {
    country: string;
    is_vpn: boolean;
    is_proxy: boolean;
    is_tor: boolean;
    is_hosting: boolean;
    threat_level: string;
    risk_score: number;
  };
}

export interface Web3Risk {
  score: number;
  level: RiskLevel;
  wallet_address: string;
  chain: string;
  wallet_type: WalletType;
  wallet_age_days: number;
  total_transactions: number;
  native_balance?: string;
  native_currency: string;
  flags: {
    interacted_with_mixer: boolean;
    interacted_with_known_scam: boolean;
    high_frequency_trading: boolean;
    large_value_transfers: boolean;
    dormant_then_active: boolean;
  };
}

export interface TrustResponse {
  id: string;
  trust_score: number;
  trust_level: TrustLevel;
  recommendation: Recommendation;
  web2_risk?: Web2Risk;
  web3_risk?: Web3Risk;
  signals: { signal: string; severity: 'low' | 'medium' | 'high' | 'critical'; source: string }[];
  checks_performed: string[];
  latency_ms: number;
  created_at: string;
}
HEREDOC

cat > src/utils/config.ts << 'HEREDOC'
import 'dotenv/config';
function required(key: string): string { const val = process.env[key]; if (!val) throw new Error(`Missing required env var: ${key}`); return val; }
function optional(key: string, fallback: string): string { return process.env[key] ?? fallback; }
export const config = {
  anthropic: { apiKey: required('ANTHROPIC_API_KEY'), model: optional('ANTHROPIC_MODEL', 'claude-sonnet-4-20250514') },
  etherscan: { apiKey: required('ETHERSCAN_API_KEY') },
  helius: { apiKey: optional('HELIUS_API_KEY', '') },
  bscscan: { apiKey: optional('BSCSCAN_API_KEY', '') },
  server: { port: parseInt(optional('PORT', '3000'), 10), nodeEnv: optional('NODE_ENV', 'development'), apiVersion: optional('API_VERSION', 'v1') },
  rateLimit: { windowMs: parseInt(optional('RATE_LIMIT_WINDOW_MS', '60000'), 10), maxFree: parseInt(optional('RATE_LIMIT_MAX_FREE', '10'), 10), maxPro: parseInt(optional('RATE_LIMIT_MAX_PRO', '500'), 10) },
  logging: { level: optional('LOG_LEVEL', 'info') },
} as const;
HEREDOC

cat > src/utils/logger.ts << 'HEREDOC'
import pino from 'pino';
import { config } from './config';
export const logger = pino({
  level: config.logging.level,
  base: { service: 'trust-api' },
  timestamp: pino.stdTimeFunctions.isoTime,
});
HEREDOC

cat > src/utils/email.utils.ts << 'HEREDOC'
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
HEREDOC

cat > src/utils/phone.utils.ts << 'HEREDOC'
import { parsePhoneNumberFromString } from 'libphonenumber-js';
const DISPOSABLE_PREFIXES = ['1900','1976','1977','1978','1979'];
export function analyzePhone(phone: string, countryCode?: string) {
  try {
    const parsed = parsePhoneNumberFromString(phone, countryCode as never);
    if (!parsed) return { valid: false, line_type: 'unknown', is_voip: false, is_likely_fake: true, country_code: '', risk_score: 80 };
    const type = parsed.getType();
    const lineType = type === 'MOBILE' ? 'mobile' : type === 'FIXED_LINE' ? 'landline' : type === 'VOIP' ? 'voip' : type === 'TOLL_FREE' ? 'toll_free' : type === 'FIXED_LINE_OR_MOBILE' ? 'mobile' : 'unknown';
    const digits = phone.replace(/\D/g, '').replace(/^1/, '');
    const isLikelyFake = /^(\d)\1{6,}/.test(digits) || digits === '1234567890' || digits.length < 7;
    const isDisposable = DISPOSABLE_PREFIXES.some(p => digits.startsWith(p));
    let riskScore = 0;
    if (!parsed.isValid()) riskScore += 40;
    if (lineType === 'voip') riskScore += 35;
    if (isLikelyFake) riskScore += 40;
    if (isDisposable) riskScore += 50;
    return { valid: parsed.isValid(), line_type: lineType, is_voip: lineType === 'voip', is_likely_fake: isLikelyFake, country_code: parsed.country ?? countryCode ?? '', risk_score: Math.min(100, riskScore) };
  } catch { return { valid: false, line_type: 'unknown', is_voip: false, is_likely_fake: true, country_code: '', risk_score: 80 }; }
}
HEREDOC

cat > src/utils/ip.utils.ts << 'HEREDOC'
import http from 'http';
const HOSTING_ASNS = new Set(['AS16509','AS14618','AS15169','AS396982','AS8075','AS13335','AS14061','AS16276','AS24940','AS20473']);
const VPN_ORGS = ['nordvpn','expressvpn','surfshark','cyberghost','protonvpn','ipvanish','mullvad','privateinternetaccess'];
const TOR_INDICATORS = ['tor','torproject','exit node'];
function httpGet(url: string): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    http.get(url, (res) => { let data = ''; res.on('data', c => data += c); res.on('end', () => { try { resolve(JSON.parse(data)); } catch { reject(new Error('Invalid JSON')); } }); }).on('error', reject);
  });
}
export async function analyzeIP(ip: string) {
  try {
    const data = await httpGet(`http://ip-api.com/json/${ip}?fields=status,country,countryCode,isp,org,as,proxy,hosting,query`);
    if (data.status === 'fail') return { country: '', is_vpn: false, is_proxy: false, is_tor: false, is_hosting: false, threat_level: 'unknown', risk_score: 0 };
    const org = String(data.org ?? '').toLowerCase();
    const isp = String(data.isp ?? '').toLowerCase();
    const asn = String(data.as ?? '');
    const combined = `${org} ${isp}`;
    const isVpn = VPN_ORGS.some(v => combined.includes(v)) || Boolean(data.proxy);
    const isTor = TOR_INDICATORS.some(t => combined.includes(t));
    const isHosting = HOSTING_ASNS.has(asn.split(' ')[0]) || Boolean(data.hosting);
    const isProxy = Boolean(data.proxy);
    let riskScore = 0;
    if (isTor) riskScore += 90;
    else if (isProxy) riskScore += 70;
    else if (isVpn) riskScore += 50;
    else if (isHosting) riskScore += 25;
    const threatLevel = riskScore >= 80 ? 'critical' : riskScore >= 50 ? 'high' : riskScore >= 20 ? 'medium' : 'low';
    return { country: String(data.countryCode ?? ''), is_vpn: isVpn, is_proxy: isProxy, is_tor: isTor, is_hosting: isHosting, threat_level: threatLevel, risk_score: Math.min(100, riskScore) };
  } catch { return { country: '', is_vpn: false, is_proxy: false, is_tor: false, is_hosting: false, threat_level: 'unknown', risk_score: 0 }; }
}
HEREDOC

cat > src/utils/wallet.utils.ts << 'HEREDOC'
import https from 'https';
import http from 'http';
import { config } from './config';
import { logger } from './logger';

const KNOWN_MIXERS = ['0x722122df12d4e14e13ac3b6895a86e84145b6967','0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936','tornado'];
const HOSTING_ASNS = new Set(['AS16509','AS14618','AS15169','AS13335','AS14061']);

function httpsGet(url: string): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => { let data = ''; res.on('data', c => data += c); res.on('end', () => { try { resolve(JSON.parse(data)); } catch { reject(new Error('Invalid JSON')); } }); }).on('error', reject);
  });
}

function httpsPost(hostname: string, path: string, body: Record<string, unknown>): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const req = https.request({ hostname, path, method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } }, (res) => {
      let raw = ''; res.on('data', c => raw += c); res.on('end', () => { try { resolve(JSON.parse(raw)); } catch { reject(new Error('Invalid JSON')); } });
    });
    req.on('error', reject); req.write(data); req.end();
  });
}

export function detectChain(address: string): 'ethereum' | 'solana' | 'bnb' | 'xrp' | 'unknown' {
  if (/^0x[a-fA-F0-9]{40}$/.test(address)) return 'ethereum';
  if (/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(address)) return 'xrp';
  if (/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(address)) return 'solana';
  return 'unknown';
}

async function getEthTxList(address: string): Promise<Record<string, unknown>[]> {
  try {
    const data = await httpsGet(`https://api.etherscan.io/v2/api?chainid=1&module=account&action=txlist&address=${address}&startblock=0&endblock=99999999&page=1&offset=100&sort=asc&apikey=${config.etherscan.apiKey}`);
    if (data.status === '0') return [];
    return (data.result as Record<string, unknown>[]) ?? [];
  } catch (err) { logger.warn({ err }, 'Failed to fetch ETH transactions'); return []; }
}

async function getEthBalance(address: string): Promise<string> {
  try {
    const data = await httpsGet(`https://api.etherscan.io/v2/api?chainid=1&module=account&action=balance&address=${address}&tag=latest&apikey=${config.etherscan.apiKey}`);
    if (data.status === '0') return '0';
    return (Number(BigInt(String(data.result ?? '0'))) / 1e18).toFixed(4);
  } catch { return '0'; }
}

async function getSolTxList(address: string): Promise<Record<string, unknown>[]> {
  if (!config.helius.apiKey) return [];
  try {
    const url = new URL(`https://mainnet.helius-rpc.com/?api-key=${config.helius.apiKey}`);
    const data = await httpsPost(url.hostname, url.pathname + url.search, { jsonrpc: '2.0', id: 1, method: 'getSignaturesForAddress', params: [address, { limit: 100 }] });
    return (data.result as Record<string, unknown>[]) ?? [];
  } catch (err) { logger.warn({ err }, 'Failed to fetch SOL transactions'); return []; }
}

async function getSolBalance(address: string): Promise<string> {
  if (!config.helius.apiKey) return '0';
  try {
    const url = new URL(`https://mainnet.helius-rpc.com/?api-key=${config.helius.apiKey}`);
    const data = await httpsPost(url.hostname, url.pathname + url.search, { jsonrpc: '2.0', id: 1, method: 'getBalance', params: [address] });
    const lamports = (data.result as Record<string, unknown>)?.value ?? 0;
    return (Number(lamports) / 1e9).toFixed(4);
  } catch { return '0'; }
}

async function getXrpTxList(address: string): Promise<Record<string, unknown>[]> {
  try {
    const data = await httpsPost('xrplcluster.com', '/', { method: 'account_tx', params: [{ account: address, limit: 100, ledger_index_min: -1, ledger_index_max: -1 }] });
    const result = data.result as Record<string, unknown>;
    return (result?.transactions as Record<string, unknown>[]) ?? [];
  } catch (err) { logger.warn({ err }, 'Failed to fetch XRP transactions'); return []; }
}

async function getXrpBalance(address: string): Promise<string> {
  try {
    const data = await httpsPost('xrplcluster.com', '/', { method: 'account_info', params: [{ account: address, ledger_index: 'current' }] });
    const result = data.result as Record<string, unknown>;
    const accountData = result?.account_data as Record<string, unknown>;
    return (Number(String(accountData?.Balance ?? '0')) / 1e6).toFixed(4);
  } catch { return '0'; }
}

export async function analyzeWallet(address: string, chainHint?: string) {
  const detectedChain = chainHint && chainHint !== 'auto' ? chainHint as 'ethereum' | 'solana' | 'bnb' | 'xrp' : detectChain(address);
  const chain = detectedChain === 'unknown' ? 'ethereum' : detectedChain;

  let txList: Record<string, unknown>[] = [];
  let balance = '0';
  let currency = 'ETH';

  if (chain === 'ethereum' || chain === 'bnb') {
    const addr = address.toLowerCase();
    [txList, balance] = await Promise.all([getEthTxList(addr), getEthBalance(addr)]);
    currency = chain === 'bnb' ? 'BNB' : 'ETH';
  } else if (chain === 'solana') {
    [txList, balance] = await Promise.all([getSolTxList(address), getSolBalance(address)]);
    currency = 'SOL';
  } else if (chain === 'xrp') {
    [txList, balance] = await Promise.all([getXrpTxList(address), getXrpBalance(address)]);
    currency = 'XRP';
  }

  const timestamps = txList.map(tx => parseInt(String(tx.timeStamp ?? tx.blockTime ?? '0'), 10)).filter(Boolean);
  const firstTs = timestamps.length > 0 ? Math.min(...timestamps) : 0;
  const ageDays = firstTs > 0 ? Math.floor((Date.now() / 1000 - firstTs) / 86400) : 0;

  const mixerInteraction = txList.some(tx => KNOWN_MIXERS.some(m => String(tx.to ?? '').toLowerCase().includes(m)));
  const highFrequency = txList.length >= 10 && (() => { const ts = timestamps.sort(); let rapid = 0; for (let i = 1; i < ts.length; i++) if (ts[i] - ts[i-1] < 60) rapid++; return rapid > txList.length * 0.3; })();
  const largeTransfers = chain === 'ethereum' || chain === 'bnb' ? txList.some(tx => BigInt(String(tx.value ?? '0')) > BigInt('10000000000000000000')) : Number(balance) > 10000;
  const dormantThenActive = ageDays > 365 && txList.length > 0;

  let riskScore = 0;
  const flags = { interacted_with_mixer: mixerInteraction, interacted_with_known_scam: false, high_frequency_trading: highFrequency, large_value_transfers: largeTransfers, dormant_then_active: dormantThenActive };

  if (mixerInteraction) riskScore += 60;
  if (highFrequency) riskScore += 30;
  if (largeTransfers) riskScore += 20;
  if (dormantThenActive) riskScore += 25;
  if (ageDays < 7) riskScore += 15;

  const walletType = txList.length === 0 ? 'new' : mixerInteraction ? 'mixer' : highFrequency ? 'bot' : largeTransfers ? 'whale' : 'trader';

  return {
    chain, wallet_type: walletType as 'trader' | 'bot' | 'whale' | 'mixer' | 'scammer' | 'dormant' | 'new' | 'unknown',
    risk_score: Math.min(100, riskScore),
    level: (riskScore >= 80 ? 'critical' : riskScore >= 50 ? 'high' : riskScore >= 20 ? 'medium' : 'low') as 'low' | 'medium' | 'high' | 'critical',
    wallet_age_days: ageDays, total_transactions: txList.length,
    native_balance: balance, native_currency: currency, flags,
  };
}
HEREDOC

cat > src/utils/validation.ts << 'HEREDOC'
import Joi from 'joi';
export const trustSchema = Joi.object({
  email: Joi.string().optional(),
  phone: Joi.string().optional(),
  ip: Joi.string().optional(),
  wallet_address: Joi.string().optional(),
  wallet_chain: Joi.string().valid('ethereum', 'solana', 'bnb', 'xrp', 'auto').default('auto'),
  country_code: Joi.string().length(2).uppercase().optional(),
}).or('email', 'phone', 'ip', 'wallet_address').messages({
  'object.missing': 'At least one of email, phone, ip or wallet_address is required',
});
HEREDOC

cat > src/services/trust.service.ts << 'HEREDOC'
import { v4 as uuidv4 } from 'uuid';
import { logger } from '../utils/logger';
import { analyzeEmail } from '../utils/email.utils';
import { analyzePhone } from '../utils/phone.utils';
import { analyzeIP } from '../utils/ip.utils';
import { analyzeWallet } from '../utils/wallet.utils';
import type { TrustRequest, TrustResponse, TrustLevel, Recommendation, Web2Risk, Web3Risk } from '../types/index';

function getTrustLevel(score: number): TrustLevel {
  if (score >= 75) return 'trusted';
  if (score >= 50) return 'neutral';
  if (score >= 25) return 'suspicious';
  return 'blocked';
}

function getRecommendation(riskScore: number): Recommendation {
  if (riskScore >= 65) return 'block';
  if (riskScore >= 35) return 'verify';
  return 'allow';
}

function invertScore(riskScore: number): number {
  return Math.max(0, 100 - riskScore);
}

export async function assessTrust(req: TrustRequest): Promise<TrustResponse> {
  const id = `trust_${uuidv4().replace(/-/g, '').slice(0, 12)}`;
  const t0 = Date.now();
  const checksPerformed: string[] = [];
  const signals: TrustResponse['signals'] = [];

  logger.info({ id, hasEmail: !!req.email, hasPhone: !!req.phone, hasIp: !!req.ip, hasWallet: !!req.wallet_address }, 'Starting trust assessment');

  let web2Risk: Web2Risk | undefined;
  let web3Risk: Web3Risk | undefined;
  let web2RiskScore = 0;
  let web3RiskScore = 0;

  // Web2 checks
  if (req.email || req.phone || req.ip) {
    const web2Checks: string[] = [];
    let emailData, phoneData, ipData;

    if (req.email) {
      web2Checks.push('email');
      emailData = await analyzeEmail(req.email);
      if (emailData.disposable) signals.push({ signal: 'Disposable email detected', severity: 'high', source: 'email' });
      if (!emailData.valid) signals.push({ signal: 'Invalid email address', severity: 'critical', source: 'email' });
      if (emailData.role_based) signals.push({ signal: 'Role-based email address', severity: 'low', source: 'email' });
      if (emailData.is_business) signals.push({ signal: 'Business email verified', severity: 'low', source: 'email' });
    }

    if (req.phone) {
      web2Checks.push('phone');
      phoneData = analyzePhone(req.phone, req.country_code);
      if (phoneData.is_voip) signals.push({ signal: 'VoIP phone detected', severity: 'high', source: 'phone' });
      if (phoneData.is_likely_fake) signals.push({ signal: 'Phone appears fake', severity: 'critical', source: 'phone' });
      if (phoneData.valid && !phoneData.is_voip) signals.push({ signal: 'Valid direct phone', severity: 'low', source: 'phone' });
    }

    if (req.ip) {
      web2Checks.push('ip');
      ipData = await analyzeIP(req.ip);
      if (ipData.is_tor) signals.push({ signal: 'Tor exit node detected', severity: 'critical', source: 'ip' });
      if (ipData.is_proxy) signals.push({ signal: 'Proxy detected', severity: 'high', source: 'ip' });
      if (ipData.is_vpn) signals.push({ signal: 'VPN detected', severity: 'high', source: 'ip' });
      if (ipData.is_hosting) signals.push({ signal: 'Datacenter IP', severity: 'medium', source: 'ip' });
    }

    const web2Scores = [emailData?.risk_score ?? 0, phoneData?.risk_score ?? 0, ipData?.risk_score ?? 0].filter((_, i) => [req.email, req.phone, req.ip][i]);
    web2RiskScore = web2Scores.length > 0 ? Math.round(web2Scores.reduce((a, b) => a + b, 0) / web2Scores.length) : 0;

    // Correlation bonuses
    const highRiskCount = [emailData?.disposable, phoneData?.is_likely_fake, ipData?.is_tor, ipData?.is_proxy].filter(Boolean).length;
    if (highRiskCount >= 2) web2RiskScore = Math.min(100, web2RiskScore + 15);

    web2Risk = {
      score: web2RiskScore,
      level: web2RiskScore >= 80 ? 'critical' : web2RiskScore >= 50 ? 'high' : web2RiskScore >= 20 ? 'medium' : 'low',
      ...(emailData && { email: { valid: emailData.valid, disposable: emailData.disposable, free_provider: emailData.free_provider, role_based: emailData.role_based, is_business: emailData.is_business, risk_score: emailData.risk_score } }),
      ...(phoneData && { phone: { valid: phoneData.valid, line_type: phoneData.line_type, is_voip: phoneData.is_voip, is_likely_fake: phoneData.is_likely_fake, risk_score: phoneData.risk_score } }),
      ...(ipData && { ip: { country: ipData.country, is_vpn: ipData.is_vpn, is_proxy: ipData.is_proxy, is_tor: ipData.is_tor, is_hosting: ipData.is_hosting, threat_level: ipData.threat_level, risk_score: ipData.risk_score } }),
    };
    checksPerformed.push(...web2Checks);
  }

  // Web3 checks
  if (req.wallet_address) {
    checksPerformed.push('wallet');
    const walletData = await analyzeWallet(req.wallet_address, req.wallet_chain);
    web3RiskScore = walletData.risk_score;

    if (walletData.flags.interacted_with_mixer) signals.push({ signal: 'Mixer interaction detected', severity: 'critical', source: 'wallet' });
    if (walletData.flags.high_frequency_trading) signals.push({ signal: 'High frequency trading pattern', severity: 'high', source: 'wallet' });
    if (walletData.flags.dormant_then_active) signals.push({ signal: 'Dormant wallet recently activated', severity: 'high', source: 'wallet' });
    if (walletData.flags.large_value_transfers) signals.push({ signal: 'Large value transfers detected', severity: 'medium', source: 'wallet' });
    if (walletData.wallet_age_days < 7) signals.push({ signal: 'Very new wallet', severity: 'medium', source: 'wallet' });

    web3Risk = {
      score: web3RiskScore,
      level: walletData.level,
      wallet_address: req.wallet_address,
      chain: walletData.chain,
      wallet_type: walletData.wallet_type,
      wallet_age_days: walletData.wallet_age_days,
      total_transactions: walletData.total_transactions,
      native_balance: walletData.native_balance,
      native_currency: walletData.native_currency,
      flags: walletData.flags,
    };
  }

  // Combined trust score
  const scores: number[] = [];
  if (web2Risk) scores.push(web2RiskScore);
  if (web3Risk) scores.push(web3RiskScore);
  const combinedRiskScore = scores.length > 0 ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : 0;

  // Cross-signal correlation — risky web2 + risky web3 = extra penalty
  let finalRiskScore = combinedRiskScore;
  if (web2Risk && web3Risk && web2RiskScore > 40 && web3RiskScore > 40) finalRiskScore = Math.min(100, finalRiskScore + 15);

  const trustScore = invertScore(finalRiskScore);
  const trustLevel = getTrustLevel(trustScore);
  const recommendation = getRecommendation(finalRiskScore);

  logger.info({ id, trustScore, trustLevel, recommendation }, 'Trust assessment complete');

  return {
    id, trust_score: trustScore, trust_level: trustLevel, recommendation,
    ...(web2Risk && { web2_risk: web2Risk }),
    ...(web3Risk && { web3_risk: web3Risk }),
    signals, checks_performed: checksPerformed,
    latency_ms: Date.now() - t0, created_at: new Date().toISOString(),
  };
}
HEREDOC

cat > src/middleware/error.middleware.ts << 'HEREDOC'
import { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger';
export function errorHandler(err: Error, req: Request, res: Response, _next: NextFunction): void {
  logger.error({ err, path: req.path }, 'Unhandled error');
  res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'An unexpected error occurred' } });
}
export function notFound(req: Request, res: Response): void { res.status(404).json({ error: { code: 'NOT_FOUND', message: `Route ${req.method} ${req.path} not found` } }); }
HEREDOC

cat > src/middleware/ratelimit.middleware.ts << 'HEREDOC'
import rateLimit from 'express-rate-limit';
import { config } from '../utils/config';
export const rateLimiter = rateLimit({
  windowMs: config.rateLimit.windowMs, max: config.rateLimit.maxFree,
  standardHeaders: 'draft-7', legacyHeaders: false,
  keyGenerator: (req) => req.headers['authorization']?.replace('Bearer ', '') ?? req.ip ?? 'unknown',
  handler: (_req, res) => { res.status(429).json({ error: { code: 'RATE_LIMIT_EXCEEDED', message: 'Too many requests.' } }); },
});
HEREDOC

cat > src/routes/health.route.ts << 'HEREDOC'
import { Router, Request, Response } from 'express';
export const healthRouter = Router();
const startTime = Date.now();
healthRouter.get('/', (_req: Request, res: Response) => {
  res.status(200).json({ status: 'ok', version: '1.0.0', uptime_seconds: Math.floor((Date.now() - startTime) / 1000), timestamp: new Date().toISOString() });
});
HEREDOC

cat > src/routes/trust.route.ts << 'HEREDOC'
import { Router, Request, Response, NextFunction } from 'express';
import { trustSchema } from '../utils/validation';
import { assessTrust } from '../services/trust.service';
import type { TrustRequest } from '../types/index';
export const trustRouter = Router();

trustRouter.post('/', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { error, value } = trustSchema.validate(req.body, { abortEarly: false });
    if (error) { res.status(422).json({ error: { code: 'VALIDATION_ERROR', message: 'Validation failed', details: error.details.map(d => d.message) } }); return; }
    res.status(200).json(await assessTrust(value as TrustRequest));
  } catch (err) { next(err); }
});

trustRouter.get('/', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const body: TrustRequest = { email: req.query.email as string | undefined, phone: req.query.phone as string | undefined, ip: req.query.ip as string | undefined, wallet_address: req.query.wallet_address as string | undefined, wallet_chain: req.query.wallet_chain as string | undefined as never, country_code: req.query.country_code as string | undefined };
    const { error, value } = trustSchema.validate(body, { abortEarly: false });
    if (error) { res.status(422).json({ error: { code: 'VALIDATION_ERROR', message: 'Validation failed', details: error.details.map(d => d.message) } }); return; }
    res.status(200).json(await assessTrust(value as TrustRequest));
  } catch (err) { next(err); }
});
HEREDOC

cat > src/routes/openapi.route.ts << 'HEREDOC'
import { Router, Request, Response } from 'express';
import { config } from '../utils/config';
export const openapiRouter = Router();
export const docsRouter = Router();

const docsHtml = `<!DOCTYPE html>
<html>
<head>
  <title>Trust API — Docs</title>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body { font-family: system-ui, sans-serif; max-width: 800px; margin: 0 auto; padding: 2rem; color: #333; }
    h1 { font-size: 1.8rem; margin-bottom: 0.25rem; }
    h2 { font-size: 1.2rem; margin-top: 2rem; border-bottom: 1px solid #eee; padding-bottom: 0.5rem; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; margin-right: 8px; }
    .get { background: #e3f2fd; color: #1565c0; }
    .post { background: #e8f5e9; color: #2e7d32; }
    .endpoint { background: #f5f5f5; padding: 1rem; border-radius: 8px; margin-bottom: 1rem; }
    .path { font-family: monospace; font-size: 1rem; font-weight: bold; }
    .desc { color: #666; font-size: 0.9rem; margin-top: 0.25rem; }
    pre { background: #1e1e1e; color: #d4d4d4; padding: 1rem; border-radius: 6px; overflow-x: auto; font-size: 13px; }
    table { width: 100%; border-collapse: collapse; font-size: 14px; margin-top: 8px; }
    th, td { text-align: left; padding: 8px; border: 1px solid #ddd; }
    th { background: #f5f5f5; }
  </style>
</head>
<body>
  <h1>Trust API</h1>
  <p>The only API that combines Web2 identity risk and Web3 wallet intelligence into a single unified trust score.</p>
  <p><strong>Base URL:</strong> <code>https://trust-api.onrender.com</code></p>

  <h2>Quick start</h2>
  <pre>const res = await fetch("https://trust-api.onrender.com/v1/assess", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    email: "user@example.com",
    ip: "8.8.8.8",
    wallet_address: "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
  })
});
const { recommendation, trust_score, trust_level } = await res.json();
if (recommendation === "block") rejectUser();
else if (recommendation === "verify") requireKYC();
else allowAccess();</pre>

  <h2>Endpoints</h2>
  <div class="endpoint">
    <div><span class="badge post">POST</span><span class="path">/v1/assess</span></div>
    <div class="desc">Assess trust — pass any combination of email, phone, IP and wallet address</div>
    <pre>curl -X POST https://trust-api.onrender.com/v1/assess \\
  -H "Content-Type: application/json" \\
  -d '{"email": "user@gmail.com", "ip": "8.8.8.8", "wallet_address": "0x..."}'</pre>
  </div>
  <div class="endpoint">
    <div><span class="badge get">GET</span><span class="path">/v1/assess</span></div>
    <div class="desc">Assess trust via query parameters</div>
    <pre>curl "https://trust-api.onrender.com/v1/assess?email=user@gmail.com&wallet_address=0x..."</pre>
  </div>

  <h2>Trust levels</h2>
  <table>
    <tr><th>Level</th><th>Score range</th><th>Meaning</th></tr>
    <tr><td>trusted</td><td>75–100</td><td>Low risk — safe to allow</td></tr>
    <tr><td>neutral</td><td>50–74</td><td>Some signals — proceed with caution</td></tr>
    <tr><td>suspicious</td><td>25–49</td><td>Multiple risk signals — require verification</td></tr>
    <tr><td>blocked</td><td>0–24</td><td>High risk — block or reject</td></tr>
  </table>

  <h2>Supported signals</h2>
  <table>
    <tr><th>Source</th><th>Signals checked</th></tr>
    <tr><td>Email</td><td>Disposable, invalid, role-based, MX records, business detection</td></tr>
    <tr><td>Phone</td><td>VoIP, fake numbers, invalid format, line type</td></tr>
    <tr><td>IP</td><td>Tor, proxy, VPN, datacenter/hosting detection</td></tr>
    <tr><td>Wallet</td><td>Mixer interactions, high frequency trading, large transfers, wallet age, dormant detection</td></tr>
  </table>

  <h2>Supported chains</h2>
  <table>
    <tr><th>Chain</th><th>Auto-detected from</th></tr>
    <tr><td>Ethereum</td><td>0x + 40 hex chars</td></tr>
    <tr><td>Solana</td><td>Base58 32-44 chars</td></tr>
    <tr><td>BNB Chain</td><td>0x + 40 hex chars (specify chain=bnb)</td></tr>
    <tr><td>XRP</td><td>r + base58 24-34 chars</td></tr>
  </table>

  <h2>OpenAPI Spec</h2>
  <p><a href="/openapi.json">Download openapi.json</a></p>
</body>
</html>`;

docsRouter.get('/', (_req: Request, res: Response) => { res.setHeader('Content-Type', 'text/html'); res.send(docsHtml); });

openapiRouter.get('/', (_req: Request, res: Response) => {
  res.status(200).json({
    openapi: '3.0.3',
    info: { title: 'Trust API', version: '1.0.0', description: 'Web2 identity risk + Web3 wallet intelligence in one unified trust score.' },
    servers: [{ url: 'https://trust-api.onrender.com', description: 'Production' }, { url: `http://localhost:${config.server.port}`, description: 'Local' }],
    paths: {
      '/v1/health': { get: { summary: 'Health check', operationId: 'getHealth', responses: { '200': { description: 'OK' } } } },
      '/v1/assess': {
        post: { summary: 'Assess trust', operationId: 'assessPost', requestBody: { required: true, content: { 'application/json': { schema: { $ref: '#/components/schemas/TrustRequest' }, examples: { web2_only: { summary: 'Web2 only', value: { email: 'user@gmail.com', phone: '+14155552671', ip: '8.8.8.8' } }, web3_only: { summary: 'Web3 only', value: { wallet_address: '0x742d35Cc6634C0532925a3b844Bc454e4438f44e' } }, combined: { summary: 'Combined Web2 + Web3', value: { email: 'user@company.com', ip: '8.8.8.8', wallet_address: '0x742d35Cc6634C0532925a3b844Bc454e4438f44e' } } } } } }, responses: { '200': { description: 'Trust assessment' }, '422': { description: 'Validation error' } } },
        get: { summary: 'Assess trust via GET', operationId: 'assessGet', parameters: [{ name: 'email', in: 'query', schema: { type: 'string' } }, { name: 'ip', in: 'query', schema: { type: 'string' } }, { name: 'wallet_address', in: 'query', schema: { type: 'string' } }], responses: { '200': { description: 'Trust assessment' } } },
      },
    },
    components: {
      schemas: {
        TrustRequest: { type: 'object', properties: { email: { type: 'string' }, phone: { type: 'string' }, ip: { type: 'string' }, wallet_address: { type: 'string' }, wallet_chain: { type: 'string', enum: ['ethereum', 'solana', 'bnb', 'xrp', 'auto'], default: 'auto' }, country_code: { type: 'string' } }, minProperties: 1 },
      },
    },
  });
});
HEREDOC

cat > src/app.ts << 'HEREDOC'
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import pinoHttp from 'pino-http';
import { trustRouter } from './routes/trust.route';
import { healthRouter } from './routes/health.route';
import { openapiRouter, docsRouter } from './routes/openapi.route';
import { errorHandler, notFound } from './middleware/error.middleware';
import { rateLimiter } from './middleware/ratelimit.middleware';
import { logger } from './utils/logger';
import { config } from './utils/config';
const app = express();
app.use(helmet()); app.use(cors()); app.use(compression());
app.use(pinoHttp({ logger }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(`/${config.server.apiVersion}/assess`, rateLimiter);
app.use(`/${config.server.apiVersion}/assess`, trustRouter);
app.use(`/${config.server.apiVersion}/health`, healthRouter);
app.use('/openapi.json', openapiRouter);
app.use('/docs', docsRouter);
app.get('/', (_req, res) => res.redirect(`/${config.server.apiVersion}/health`));
app.use(notFound);
app.use(errorHandler);
export { app };
HEREDOC

cat > src/index.ts << 'HEREDOC'
import { app } from './app';
import { config } from './utils/config';

const server = app.listen(config.server.port, () => {
  console.log(`🚀 Trust API started on port ${config.server.port}`);
});

const shutdown = (signal: string) => {
  console.log(`Shutting down (${signal})`);
  server.close(() => { console.log('Closed'); process.exit(0); });
  setTimeout(() => process.exit(1), 10_000);
};

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('unhandledRejection', (reason) => console.error('Unhandled rejection:', reason));
process.on('uncaughtException', (err) => { console.error('Uncaught exception:', err); process.exit(1); });
HEREDOC

cat > jest.config.js << 'HEREDOC'
module.exports = { preset: 'ts-jest', testEnvironment: 'node', rootDir: '.', testMatch: ['**/tests/**/*.test.ts'], collectCoverageFrom: ['src/**/*.ts', '!src/index.ts'], setupFiles: ['<rootDir>/tests/setup.ts'] };
HEREDOC

cat > tests/setup.ts << 'HEREDOC'
process.env.ANTHROPIC_API_KEY = 'sk-ant-test-key';
process.env.ETHERSCAN_API_KEY = 'test-key';
process.env.NODE_ENV = 'test';
process.env.LOG_LEVEL = 'silent';
HEREDOC

cat > .gitignore << 'HEREDOC'
node_modules/
dist/
.env
coverage/
*.log
.DS_Store
HEREDOC

cat > render.yaml << 'HEREDOC'
services:
  - type: web
    name: trust-api
    runtime: node
    buildCommand: npm install && npm run build
    startCommand: node dist/index.js
    healthCheckPath: /v1/health
    envVars:
      - key: NODE_ENV
        value: production
      - key: LOG_LEVEL
        value: info
      - key: ANTHROPIC_API_KEY
        sync: false
      - key: ETHERSCAN_API_KEY
        sync: false
      - key: HELIUS_API_KEY
        sync: false
      - key: BSCSCAN_API_KEY
        sync: false
HEREDOC

echo ""
echo "✅ All files created! Run: npm install"