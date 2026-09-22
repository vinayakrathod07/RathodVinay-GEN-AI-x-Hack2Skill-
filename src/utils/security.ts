/**
 * PhishGuard Nexus - Security & Defensive Utilities
 * Prevents XSS, validates URLs, masks sensitive PII, and handles cryptographic checksums.
 * @license Apache-2.0
 */

/**
 * Escapes all dangerous characters to strictly prevent Cross-Site Scripting (XSS).
 * Neutralizes <, >, &, ", ', `, and forward slashes.
 */
export function sanitizeHtml(dirty: unknown): string {
  if (dirty === null || dirty === undefined) return '';
  const str = String(dirty);
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
    .replace(/`/g, '&#96;')
    .replace(/\//g, '&#x2F;');
}

/**
 * Strips script tags, javascript: pseudo-protocols, and inline event handlers from strings.
 */
export function stripMaliciousVectors(input: string): string {
  if (!input) return '';
  return input
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
    .replace(/javascript:/gi, '')
    .replace(/data:text\/html/gi, '')
    .replace(/on\w+\s*=/gi, '');
}

/**
 * Normalizes and validates URLs to prevent protocol smuggling and SSRF/open redirects.
 */
export interface UrlValidationResult {
  isValid: boolean;
  sanitized: string;
  protocol: string;
  hostname: string;
  pathname: string;
  isSuspicious: boolean;
  reasons: string[];
}

export function validateAndParseUrl(rawUrl: string): UrlValidationResult {
  const result: UrlValidationResult = {
    isValid: false,
    sanitized: '',
    protocol: '',
    hostname: '',
    pathname: '',
    isSuspicious: false,
    reasons: [],
  };

  if (!rawUrl || typeof rawUrl !== 'string') {
    result.reasons.push('Empty or invalid URL input');
    return result;
  }

  const trimmed = rawUrl.trim();
  let parsedUrl: URL;

  try {
    // Add protocol if omitted
    if (!trimmed.startsWith('http://') && !trimmed.startsWith('https://')) {
      parsedUrl = new URL(`https://${trimmed}`);
    } else {
      parsedUrl = new URL(trimmed);
    }
  } catch {
    result.reasons.push('Invalid URL structure');
    return result;
  }

  // Enforce secure or allowed protocol
  if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
    result.reasons.push(`Disallowed protocol: ${parsedUrl.protocol}`);
    return result;
  }

  result.isValid = true;
  result.protocol = parsedUrl.protocol;
  result.hostname = parsedUrl.hostname.toLowerCase();
  result.pathname = parsedUrl.pathname;
  result.sanitized = parsedUrl.toString();

  // Suspicious TLD check
  const suspiciousTlds = [
    '.top', '.xyz', '.buzz', '.rest', '.live', '.cc', '.info', '.biz', '.tk', '.ml', '.ga', '.cf', '.gq', '.icu', '.monster'
  ];
  if (suspiciousTlds.some(tld => result.hostname.endsWith(tld))) {
    result.isSuspicious = true;
    result.reasons.push('Uses high-risk/frequently abused top-level domain');
  }

  // Punycode / IDN homograph attack check
  if (result.hostname.startsWith('xn--') || result.hostname.includes('.xn--')) {
    result.isSuspicious = true;
    result.reasons.push('Contains Punycode (possible homograph character spoofing)');
  }

  // Multiple hyphens (common typosquat indicator)
  if ((result.hostname.match(/-/g) || []).length >= 2) {
    result.isSuspicious = true;
    result.reasons.push('Excessive hyphens in domain name (common in corporate impersonation)');
  }

  // Direct IP address URL
  const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipPattern.test(result.hostname)) {
    result.isSuspicious = true;
    result.reasons.push('Direct raw IP address in URL instead of branded domain name');
  }

  return result;
}

/**
 * Masks Personally Identifiable Information (PII) before transmission or telemetry storage.
 */
export function maskSensitivePII(text: string): string {
  if (!text) return '';
  return text
    // Credit card numbers (13-16 digits with optional dashes/spaces)
    .replace(/\b(?:\d[ -]*?){13,16}\b/g, '[REDACTED_PAYMENT_CARD]')
    // US SSN (XXX-XX-XXXX)
    .replace(/\b\d{3}-\d{2}-\d{4}\b/g, '[REDACTED_SSN]')
    // Indian Aadhaar (4 digits 4 digits 4 digits)
    .replace(/\b\d{4}\s\d{4}\s\d{4}\b/g, '[REDACTED_AADHAAR]')
    // Bank account numbers with 9-18 digits preceded by keywords
    .replace(/(?:account|acct|iban)[\s:#]+([a-zA-Z0-9]{8,24})/gi, 'account: [REDACTED_ACCOUNT]');
}

/**
 * Safely masks API keys for display (e.g., "AIzaSy...7e4q").
 */
export function maskApiKey(key: string): string {
  if (!key) return '';
  if (key.length <= 8) return '********';
  return `${key.slice(0, 6)}...${key.slice(-4)}`;
}

/**
 * Generates a deterministic lightweight cryptographic-style hash for audit records.
 */
export function generateAuditHash(input: string): string {
  let hash = 0;
  for (let i = 0; i < input.length; i++) {
    const char = input.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash |= 0; // Convert to 32bit integer
  }
  const hex = (hash >>> 0).toString(16).padStart(8, '0');
  return `PGN-${hex.toUpperCase()}`;
}
