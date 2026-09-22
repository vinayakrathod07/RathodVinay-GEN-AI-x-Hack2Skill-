/**
 * PhishGuard Nexus - Security & Sanitization Unit Tests
 * Verifies XSS defense, URL safety checks, and PII masking.
 */

import { describe, expect, it } from 'vitest';
import {
  generateAuditHash,
  maskApiKey,
  maskSensitivePII,
  sanitizeHtml,
  stripMaliciousVectors,
  validateAndParseUrl,
} from '../src/utils/security';

describe('Security & Sanitization Suite', () => {
  describe('sanitizeHtml', () => {
    it('escapes standard HTML injection tags', () => {
      const malicious = '<script>alert("XSS")</script>';
      const sanitized = sanitizeHtml(malicious);
      expect(sanitized).toBe('&lt;script&gt;alert(&quot;XSS&quot;)&lt;&#x2F;script&gt;');
      expect(sanitized).not.toContain('<');
      expect(sanitized).not.toContain('>');
    });

    it('neutralizes double quotes, single quotes, and backticks', () => {
      const payload = '"><img src=x onerror=alert(1)>`';
      const sanitized = sanitizeHtml(payload);
      expect(sanitized).not.toContain('"');
      expect(sanitized).not.toContain('`');
      expect(sanitized).toContain('&quot;');
      expect(sanitized).toContain('&#96;');
    });

    it('handles null, undefined, and non-string inputs safely', () => {
      expect(sanitizeHtml(null)).toBe('');
      expect(sanitizeHtml(undefined)).toBe('');
      expect(sanitizeHtml(12345)).toBe('12345');
    });
  });

  describe('stripMaliciousVectors', () => {
    it('removes script blocks and javascript pseudo-protocols', () => {
      const raw = '<script>evil()</script><a href="javascript:doBad()">Link</a>';
      const cleaned = stripMaliciousVectors(raw);
      expect(cleaned).not.toContain('<script>');
      expect(cleaned).not.toContain('javascript:');
    });

    it('removes inline event handlers like onclick and onerror', () => {
      const raw = '<img src="cat.jpg" onerror="stealCookie()" onload="send()" />';
      const cleaned = stripMaliciousVectors(raw);
      expect(cleaned).not.toContain('onerror=');
      expect(cleaned).not.toContain('onload=');
    });
  });

  describe('validateAndParseUrl', () => {
    it('validates a legitimate HTTPS URL', () => {
      const res = validateAndParseUrl('https://careers.google.com/jobs');
      expect(res.isValid).toBe(true);
      expect(res.protocol).toBe('https:');
      expect(res.hostname).toBe('careers.google.com');
      expect(res.isSuspicious).toBe(false);
    });

    it('flags suspicious top-level domains (.xyz, .top, .buzz)', () => {
      const res = validateAndParseUrl('http://paypal-verification-center.top/login');
      expect(res.isValid).toBe(true);
      expect(res.isSuspicious).toBe(true);
      expect(res.reasons.some(r => r.includes('high-risk'))).toBe(true);
    });

    it('flags punycode domains indicating homograph attacks', () => {
      const res = validateAndParseUrl('https://xn--appl-43a.com');
      expect(res.isValid).toBe(true);
      expect(res.isSuspicious).toBe(true);
      expect(res.reasons.some(r => r.includes('Punycode'))).toBe(true);
    });

    it('flags raw IP addresses in place of corporate domains', () => {
      const res = validateAndParseUrl('http://192.168.1.100/portal');
      expect(res.isValid).toBe(true);
      expect(res.isSuspicious).toBe(true);
      expect(res.reasons.some(r => r.includes('IP address'))).toBe(true);
    });

    it('rejects unsupported or malicious protocols like file:// or javascript:', () => {
      const res = validateAndParseUrl('javascript:alert(1)');
      expect(res.isValid).toBe(false);
    });
  });

  describe('maskSensitivePII', () => {
    it('redacts credit card numbers', () => {
      const text = 'Card number: 4111 2222 3333 4444 expiration 12/28';
      const masked = maskSensitivePII(text);
      expect(masked).toContain('[REDACTED_PAYMENT_CARD]');
      expect(masked).not.toContain('4111');
    });

    it('redacts US Social Security Numbers', () => {
      const text = 'Candidate SSN: 123-45-6789 for tax forms';
      const masked = maskSensitivePII(text);
      expect(masked).toContain('[REDACTED_SSN]');
      expect(masked).not.toContain('123-45-6789');
    });

    it('redacts Indian Aadhaar numbers', () => {
      const text = 'Identity Aadhaar: 1234 5678 9012 submitted';
      const masked = maskSensitivePII(text);
      expect(masked).toContain('[REDACTED_AADHAAR]');
      expect(masked).not.toContain('1234 5678 9012');
    });
  });

  describe('maskApiKey', () => {
    it('safely masks API key displaying only prefix and suffix', () => {
      const masked = maskApiKey('AIzaSyDk8394jklmn781294xQ');
      expect(masked).toBe('AIzaSy...94xQ');
      expect(masked.length).toBeLessThan(16);
    });
  });

  describe('generateAuditHash', () => {
    it('generates consistent and valid formatted audit hashes', () => {
      const hash1 = generateAuditHash('scan_12345');
      const hash2 = generateAuditHash('scan_12345');
      expect(hash1).toBe(hash2);
      expect(hash1.startsWith('PGN-')).toBe(true);
    });
  });
});
