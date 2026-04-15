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
