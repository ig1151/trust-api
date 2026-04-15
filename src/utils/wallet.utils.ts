import https from 'https';
import { config } from './config';
import { logger } from './logger';

const KNOWN_MIXERS = ['0x722122df12d4e14e13ac3b6895a86e84145b6967','0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936','tornado'];

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
  const highFrequency = txList.length >= 10 && (() => {
    const ts = timestamps.sort((a, b) => a - b);
    let rapid = 0;
    for (let i = 1; i < ts.length; i++) if (ts[i] - ts[i-1] < 60) rapid++;
    return rapid > txList.length * 0.3;
  })();
  const largeTransfers = chain === 'ethereum' || chain === 'bnb'
    ? txList.some(tx => BigInt(String(tx.value ?? '0')) > BigInt('10000000000000000000'))
    : Number(balance) > 10000;
  const dormantThenActive = ageDays > 365 && txList.length > 0;

  let riskScore = 0;
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
    native_balance: balance, native_currency: currency,
    flags: { interacted_with_mixer: mixerInteraction, interacted_with_known_scam: false, high_frequency_trading: highFrequency, large_value_transfers: largeTransfers, dormant_then_active: dormantThenActive },
  };
}