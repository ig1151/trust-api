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
