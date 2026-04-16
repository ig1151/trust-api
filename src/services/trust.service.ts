import { v4 as uuidv4 } from 'uuid';
import { logger } from '../utils/logger';
import { analyzeEmail } from '../utils/email.utils';
import { analyzePhone } from '../utils/phone.utils';
import { analyzeIP } from '../utils/ip.utils';
import { analyzeWallet } from '../utils/wallet.utils';
import type { TrustRequest, TrustResponse, TrustLevel, Recommendation, Web2Risk, Web3Risk } from '../types/index';

// Use case thresholds — stricter for kyc/airdrop, lenient for login
const USE_CASE_THRESHOLDS: Record<string, { blockAt: number; verifyAt: number }> = {
  signup:             { blockAt: 65, verifyAt: 35 },
  login:              { blockAt: 75, verifyAt: 45 },
  checkout:           { blockAt: 55, verifyAt: 25 },
  kyc:                { blockAt: 40, verifyAt: 20 },
  airdrop:            { blockAt: 50, verifyAt: 25 },
  wallet_onboarding:  { blockAt: 55, verifyAt: 30 },
};

function getTrustLevel(score: number): TrustLevel {
  if (score >= 75) return 'trusted';
  if (score >= 50) return 'neutral';
  if (score >= 25) return 'suspicious';
  return 'blocked';
}

function getRecommendation(riskScore: number, useCase: string): Recommendation {
  const t = USE_CASE_THRESHOLDS[useCase] ?? USE_CASE_THRESHOLDS.signup;
  if (riskScore >= t.blockAt) return 'block';
  if (riskScore >= t.verifyAt) return 'verify';
  return 'allow';
}

function getConfidence(checksPerformed: number, signalCount: number): number {
  // More checks + more signals = higher confidence
  const checkWeight = Math.min(checksPerformed / 4, 1) * 0.6;
  const signalWeight = Math.min(signalCount / 5, 1) * 0.4;
  return parseFloat((checkWeight + signalWeight).toFixed(2));
}

function getReasonsFromSignals(signals: TrustResponse['signals']): string[] {
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  return signals
    .filter(s => s.severity !== 'low' || signals.filter(x => x.severity !== 'low').length === 0)
    .sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity])
    .slice(0, 5)
    .map(s => s.signal
      .toLowerCase()
      .replace(/\s+/g, '_')
      .replace(/[^a-z0-9_]/g, '')
    );
}

function invertScore(riskScore: number): number {
  return Math.max(0, 100 - riskScore);
}

export async function assessTrust(req: TrustRequest): Promise<TrustResponse> {
  const id = `trust_${uuidv4().replace(/-/g, '').slice(0, 12)}`;
  const t0 = Date.now();
  const useCase = req.use_case ?? 'signup';
  const checksPerformed: string[] = [];
  const signals: TrustResponse['signals'] = [];

  logger.info({ id, useCase, hasEmail: !!req.email, hasPhone: !!req.phone, hasIp: !!req.ip, hasWallet: !!req.wallet_address }, 'Starting trust assessment');

  let web2Risk: Web2Risk | undefined;
  let web3Risk: Web3Risk | undefined;
  let web2RiskScore = 0;
  let web3RiskScore = 0;

  // Web2 checks
  if (req.email || req.phone || req.ip) {
    let emailData, phoneData, ipData;

    if (req.email) {
      checksPerformed.push('email');
      emailData = await analyzeEmail(req.email);
      if (emailData.disposable) signals.push({ signal: 'Disposable email detected', severity: 'high', source: 'email' });
      if (!emailData.valid) signals.push({ signal: 'Invalid email address', severity: 'critical', source: 'email' });
      if (emailData.role_based) signals.push({ signal: 'Role-based email address', severity: 'low', source: 'email' });
      if (emailData.is_business) signals.push({ signal: 'Business email verified', severity: 'low', source: 'email' });
    }

    if (req.phone) {
      checksPerformed.push('phone');
      phoneData = analyzePhone(req.phone, req.country_code);
      if (phoneData.is_voip) signals.push({ signal: 'VoIP phone detected', severity: 'high', source: 'phone' });
      if (phoneData.is_likely_fake) signals.push({ signal: 'Phone appears fake', severity: 'critical', source: 'phone' });
      if (phoneData.valid && !phoneData.is_voip) signals.push({ signal: 'Valid direct phone', severity: 'low', source: 'phone' });
    }

    if (req.ip) {
      checksPerformed.push('ip');
      ipData = await analyzeIP(req.ip);
      if (ipData.is_tor) signals.push({ signal: 'Tor exit node detected', severity: 'critical', source: 'ip' });
      if (ipData.is_proxy) signals.push({ signal: 'Proxy detected', severity: 'high', source: 'ip' });
      if (ipData.is_vpn) signals.push({ signal: 'VPN detected', severity: 'high', source: 'ip' });
      if (ipData.is_hosting) signals.push({ signal: 'Datacenter IP', severity: 'medium', source: 'ip' });
    }

    const web2Scores = [emailData?.risk_score ?? 0, phoneData?.risk_score ?? 0, ipData?.risk_score ?? 0].filter((_, i) => [req.email, req.phone, req.ip][i]);
    web2RiskScore = web2Scores.length > 0 ? Math.round(web2Scores.reduce((a, b) => a + b, 0) / web2Scores.length) : 0;

    // Correlation bonus
    const highRiskCount = [emailData?.disposable, phoneData?.is_likely_fake, ipData?.is_tor, ipData?.is_proxy].filter(Boolean).length;
    if (highRiskCount >= 2) web2RiskScore = Math.min(100, web2RiskScore + 15);

    web2Risk = {
      score: web2RiskScore,
      level: web2RiskScore >= 80 ? 'critical' : web2RiskScore >= 50 ? 'high' : web2RiskScore >= 20 ? 'medium' : 'low',
      ...(emailData && { email: { valid: emailData.valid, disposable: emailData.disposable, free_provider: emailData.free_provider, role_based: emailData.role_based, is_business: emailData.is_business, risk_score: emailData.risk_score } }),
      ...(phoneData && { phone: { valid: phoneData.valid, line_type: phoneData.line_type, is_voip: phoneData.is_voip, is_likely_fake: phoneData.is_likely_fake, risk_score: phoneData.risk_score } }),
      ...(ipData && { ip: { country: ipData.country, is_vpn: ipData.is_vpn, is_proxy: ipData.is_proxy, is_tor: ipData.is_tor, is_hosting: ipData.is_hosting, threat_level: ipData.threat_level, risk_score: ipData.risk_score } }),
    };
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
    if (walletData.wallet_age_days > 365 && walletData.total_transactions > 0) signals.push({ signal: 'Established wallet with history', severity: 'low', source: 'wallet' });

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

  // Combined risk score
  const scores: number[] = [];
  if (web2Risk) scores.push(web2RiskScore);
  if (web3Risk) scores.push(web3RiskScore);
  let finalRiskScore = scores.length > 0 ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : 0;

  // Cross-signal penalty
  if (web2Risk && web3Risk && web2RiskScore > 40 && web3RiskScore > 40) {
    finalRiskScore = Math.min(100, finalRiskScore + 15);
    signals.push({ signal: 'Multiple risk sources detected', severity: 'high', source: 'combined' });
  }

  const trustScore = invertScore(finalRiskScore);
  const trustLevel = getTrustLevel(trustScore);
  const decision = getRecommendation(finalRiskScore, useCase);
  const confidence = getConfidence(checksPerformed.length, signals.filter(s => s.severity !== 'low').length);
  const reasons = getReasonsFromSignals(signals);

  logger.info({ id, trustScore, trustLevel, decision, confidence, useCase }, 'Trust assessment complete');

  return {
    id, trust_score: trustScore, trust_level: trustLevel,
    decision, recommendation: decision,
    confidence, reasons, use_case: useCase,
    ...(web2Risk && { web2_risk: web2Risk }),
    ...(web3Risk && { web3_risk: web3Risk }),
    signals, checks_performed: checksPerformed,
    latency_ms: Date.now() - t0, created_at: new Date().toISOString(),
  };
}