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
