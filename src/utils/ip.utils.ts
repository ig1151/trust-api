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
