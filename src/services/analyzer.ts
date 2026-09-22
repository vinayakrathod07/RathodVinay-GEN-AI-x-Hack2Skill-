/**
 * PhishGuard Nexus - Cognitive Forensic Analyzer
 * Evaluates Scam Threat Index (0-100%) and the "Dark Triad" of Scam Psychology.
 * @license Apache-2.0
 */

import { DarkTriadScores, ScamRiskLevel, ThreatAnalysis } from '../types';
import { generateAuditHash, sanitizeHtml, validateAndParseUrl } from '../utils/security';

// Heuristic keyword patterns for the Dark Triad
const URGENCY_PATTERNS = [
  /\b(?:within\s+(?:24|48|2|1|few)\s*(?:hours|hrs|minutes|mins)|immediate(?:ly)?|urgent(?:ly)?|expires\s+soon|act\s+now|last\s+chance|strictly\s+confidential|deadline)\b/i,
  /\b(?:only\s+\d+\s+slots?|spots?\s+remaining|limited\s+time|offer\s+revoked)\b/i,
];

const AUTHORITY_PATTERNS = [
  /\b(?:ceo|managing\s+director|board\s+of\s+directors|executive\s+office|hr\s+director|hiring\s+team|confidential\s+assignment|legal\s+department)\b/i,
  /\b(?:telegram|whatsapp|signal|google\s+chat|wire\s+app)\b/i,
];

const SCARCITY_PATTERNS = [
  /\b(?:selected\s+without\s+interview|direct\s+hire|no\s+experience\s+needed|guaranteed\s+salary|\$\d{2,4}\s*(?:\/day|\/hr|daily)|earn\s+from\s+home\s+immediately)\b/i,
  /\b(?:exclusive\s+candidate|shortlisted\s+globally|instant\s+joining|student\s+job)\b/i,
];

const FINANCIAL_TRAP_PATTERNS = [
  /\b(?:equipment\s+fee|hardware\s+deposit|reimbursement\s+check|advance\s+check|software\s+license\s+fee|training\s+fee|training\s+kit|background\s+check\s+fee)\b/i,
  /\b(?:cashier['’]?s?\s*check|fake\s*check|deposit\s*(?:the|a)\s*check|check\s*(?:deposit|clearing|reimbursement))\b/i,
  /\b(?:wire\s+transfer|western\s+union|moneygram|zelle|cash\s*app|crypto|bitcoin|usdt|gift\s*card)\b/i,
  /\b(?:send\s+back\s+the\s+difference|overpayment|vendor\s+(?:account|payment)|office\s+supplies\s+distributor|account\s+verification\s+deposit|refundable\s+deposit|security\s+deposit)\b/i,
  /\b(?:INR|₹|\$|€|£)\s*\d+[,\d]*\b/i,
];

const FREE_WEBMAIL_PATTERNS = [
  /@(?:gmail\.com|yahoo\.com|hotmail\.com|outlook\.com|icloud\.com|mail\.ru|yandex\.com|proton\.me|protonmail\.com)/i,
];

/**
 * Analyzes offer letter text, email contents, or flyer transcripts.
 */
export function analyzeOfferText(rawContent: string, explicitUrl?: string): ThreatAnalysis {
  const content = rawContent || '';
  const indicators: string[] = [];

  // 1. Calculate Dark Triad
  let urgencyHits = 0;
  for (const pattern of URGENCY_PATTERNS) {
    if (pattern.test(content)) urgencyHits += 1;
  }

  let authorityHits = 0;
  for (const pattern of AUTHORITY_PATTERNS) {
    if (pattern.test(content)) authorityHits += 1;
  }

  let scarcityHits = 0;
  for (const pattern of SCARCITY_PATTERNS) {
    if (pattern.test(content)) scarcityHits += 1;
  }

  let financialHits = 0;
  for (const pattern of FINANCIAL_TRAP_PATTERNS) {
    if (pattern.test(content)) financialHits += 1;
  }

  // Domain & URL inspection
  let domainSpoofScore = 10;
  if (explicitUrl) {
    const urlValidation = validateAndParseUrl(explicitUrl);
    if (!urlValidation.isValid) {
      domainSpoofScore = 65;
      indicators.push('Corrupted, invalid, or malformed URL detected.');
    } else if (urlValidation.isSuspicious) {
      domainSpoofScore = 80;
      indicators.push(`Suspicious domain detected: ${urlValidation.reasons.join('; ')}`);
    } else {
      domainSpoofScore = 15;
    }
  }

  // Free webmail impersonation check
  const claimsCorporate = /\b(?:google|microsoft|amazon|apple|meta|stripe|netflix|tcs|infosys|deloitte|accenture)\b/i.test(content);
  const usesFreeWebmail = FREE_WEBMAIL_PATTERNS.some(p => p.test(content));
  if (claimsCorporate && usesFreeWebmail) {
    domainSpoofScore = Math.max(domainSpoofScore, 85);
    indicators.push('Corporate identity claimed but communication originates from a free public webmail address (e.g. Gmail/Yahoo).');
  }

  // Financial trap scoring
  let financialTrapScore = 10;
  if (financialHits > 0) {
    financialTrapScore = Math.min(100, 50 + (financialHits * 20));
    indicators.push('Contains upfront payment, equipment fee, or fake check reimbursement indicators.');
  }

  // Psychological coercion scoring
  const coercionHits = urgencyHits + authorityHits + scarcityHits;
  let psychologicalCoercion = 10;
  if (coercionHits > 0) {
    psychologicalCoercion = Math.min(100, 25 + (coercionHits * 20));
  }

  if (urgencyHits > 0) indicators.push('High artificial urgency detected (short deadline, pressure to sign/pay immediately).');
  if (authorityHits > 0 && /telegram|whatsapp/i.test(content)) {
    psychologicalCoercion = Math.max(psychologicalCoercion, 60);
    indicators.push('Recruiter directs applicant to informal encrypted messaging channels (Telegram/WhatsApp) rather than official corporate portals.');
  }
  if (scarcityHits > 0) indicators.push('Unrealistic promise or instant hiring without formal technical/portfolio interviews.');

  // Cybersecurity Risk Matrix: Critical severity in ANY category dictates overall threat index
  const baseAverage = (financialTrapScore * 0.45) + (domainSpoofScore * 0.30) + (psychologicalCoercion * 0.25);
  const peakRisk = Math.max(financialTrapScore, domainSpoofScore, psychologicalCoercion);

  // If a financial trap or domain spoof is present, prevent dilution
  let weightedScore: number;
  if (peakRisk >= 75) {
    weightedScore = Math.max(baseAverage, peakRisk * 0.9);
  } else if (peakRisk >= 50) {
    weightedScore = Math.max(baseAverage, peakRisk * 0.85);
  } else {
    weightedScore = baseAverage;
  }

  const threatIndex = Math.max(5, Math.min(98, Math.round(weightedScore)));

  // Determine risk level
  let riskLevel: ScamRiskLevel = 'SAFE';
  if (threatIndex >= 70 || financialTrapScore >= 80) riskLevel = 'CRITICAL';
  else if (threatIndex >= 50 || peakRisk >= 60) riskLevel = 'HIGH';
  else if (threatIndex >= 30) riskLevel = 'MODERATE';
  else if (threatIndex >= 18) riskLevel = 'LOW';
  else riskLevel = 'SAFE';

  // Determine forensic verdict
  let verdict = 'No significant recruitment scam or phishing markers detected. Verification passed.';
  if (riskLevel === 'CRITICAL') {
    verdict = 'CRITICAL FRAUD ALERT: High probability of corporate impersonation, advance-fee scam, or fake check deposit trap.';
  } else if (riskLevel === 'HIGH') {
    verdict = 'HIGH RISK WARNING: Multiple suspicious flags identified including irregular communication channels or upfront fee demands.';
  } else if (riskLevel === 'MODERATE') {
    verdict = 'MODERATE SUSPICION: Inconsistent recruitment patterns. Exercise caution and verify via official corporate career sites.';
  }

  const darkTriad: DarkTriadScores = {
    financialTrap: Math.min(100, financialTrapScore),
    domainSpoof: Math.min(100, domainSpoofScore),
    psychologicalCoercion: Math.min(100, psychologicalCoercion),
  };

  const safeNextSteps = [
    'Do NOT send any funds, gift cards, or cryptocurrency for equipment, training, or onboarding.',
    'Do NOT deposit any physical or scanned checks received from an unknown employer.',
    'Cross-reference the job opening directly on the organization\'s official careers website.',
    'Verify recruiter email addresses against authentic corporate MX domain records.',
    'Never provide bank login credentials, OTP codes, or full SSN before an in-person or official HR interview.',
  ];

  const counterScript = `Thank you for the communication. To comply with my personal security protocols:
1. Please provide the internal Job Requisition ID and your direct corporate LinkedIn profile.
2. I will complete onboarding exclusively through your official domain portal (not third-party chat apps).
3. As standard industry policy, I do not advance personal funds for employer-provided equipment.`;

  const victimHotlines = [
    { region: 'United States', agency: 'FBI Internet Crime Complaint Center (IC3)', contact: 'https://ic3.gov' },
    { region: 'United States', agency: 'Federal Trade Commission (FTC)', contact: '1-877-FTC-HELP / https://reportfraud.ftc.gov' },
    { region: 'India', agency: 'National Cyber Crime Reporting Portal', contact: '1930 / https://cybercrime.gov.in' },
    { region: 'United Kingdom', agency: 'Action Fraud National Reporting', contact: '0300 123 2040 / https://actionfraud.police.uk' },
    { region: 'Global', agency: 'Anti-Phishing Working Group (APWG)', contact: 'reportphishing@apwg.org' },
  ];

  const id = `scan_${Date.now()}`;
  const timestamp = new Date().toISOString();
  const hash = generateAuditHash(`${id}_${threatIndex}_${riskLevel}`);

  return {
    id,
    threatIndex,
    riskLevel,
    verdict: sanitizeHtml(verdict),
    darkTriad,
    indicators,
    safeNextSteps,
    counterScript,
    victimHotlines,
    timestamp,
    hash,
  };
}
