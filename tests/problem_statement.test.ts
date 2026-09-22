/**
 * PhishGuard Nexus - Hackathon Problem Statement & Rubric Compliance Test Suite
 * Validates direct alignment with PromptWars x GenAI Club 2026 criteria:
 * - Fake Offer Letter & Appointment Letter Inspector
 * - Phishing & Pay-for-Equipment Traps
 * - Urgency & Psychological Coercion Detection
 * - Physical Flyer QR Verification
 * - Identity Protection & Victim Recovery
 */

import { describe, expect, it } from 'vitest';
import { analyzeOfferText } from '../src/services/analyzer';

describe('Problem Statement Rubric Alignment', () => {
  it('Requirement 1: Identifies Fake Appointment Letters with upfront security deposits', () => {
    const appointmentLetter = `
      APPOINTMENT LETTER & JOINING PROTOCOL
      Position: Junior Associate
      To confirm your joining and reserve your training kit, a mandatory refundable deposit of INR 25,000
      must be transferred to our vendor account prior to documentation verification.
      Failure to deposit within 48 hours will result in offer revocation.
    `;
    const res = analyzeOfferText(appointmentLetter);
    expect(res.threatIndex).toBeGreaterThan(60);
    expect(res.darkTriad.financialTrap).toBeGreaterThanOrEqual(60);
    expect(res.indicators.length).toBeGreaterThan(0);
  });

  it('Requirement 2: Flags Check Overpayment & Fake Check Clearing Scams', () => {
    const checkScam = `
      We are mailing you a cashier's check of $3,500 for office setup.
      Deposit the check into your bank account, keep $500 as your advance bonus,
      and wire transfer the remaining $3,000 via MoneyGram to our office supplies distributor.
    `;
    const res = analyzeOfferText(checkScam);
    expect(res.riskLevel).toBe('CRITICAL');
    expect(res.darkTriad.financialTrap).toBeGreaterThanOrEqual(70);
  });

  it('Requirement 3: Protects Against Physical Flyer QR Phishing on University Campuses', () => {
    const flyerUrl = 'http://university-jobs-portal.top/telegram-verify';
    const flyerText = 'Campus Hiring: Work from home 2 hours daily, earn $200. Scan QR code to connect with hiring manager.';
    const res = analyzeOfferText(flyerText, flyerUrl);
    expect(res.darkTriad.domainSpoof).toBeGreaterThan(50);
    expect(res.threatIndex).toBeGreaterThan(50);
  });

  it('Requirement 4: Provides Actionable Counter-Response Script to Test Recruiter Authenticity', () => {
    const res = analyzeOfferText('Suspicious offer from telegram');
    expect(res.counterScript).toBeDefined();
    expect(res.counterScript.length).toBeGreaterThan(50);
    expect(res.counterScript).toContain('Job Requisition ID');
  });

  it('Requirement 5: Provides Direct Legal & Victim Reporting Hotlines', () => {
    const res = analyzeOfferText('Scam offer');
    expect(res.victimHotlines.length).toBeGreaterThanOrEqual(4);
    const regions = res.victimHotlines.map(h => h.region);
    expect(regions).toContain('United States');
    expect(regions).toContain('India');
  });
});
