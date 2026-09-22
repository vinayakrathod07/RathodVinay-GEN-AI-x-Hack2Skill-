/**
 * PhishGuard Nexus - Cognitive Forensic Analyzer Unit Tests
 * Verifies Scam Threat Index calculation and Dark Triad psychological indicators.
 */

import { describe, expect, it } from 'vitest';
import { analyzeOfferText } from '../src/services/analyzer';

describe('Cognitive Forensic Analyzer Engine', () => {
  it('correctly scores an upfront equipment payment scam as CRITICAL risk', () => {
    const scamText = `
      Congratulations! You have been selected without interview as our Senior Data Scientist.
      Your starting salary is $95/hr. However, before commencing employment, you must purchase
      mandatory Apple hardware equipment. We will send you an advance check of $4,500.
      You must deposit this check and immediately wire transfer $3,200 to our certified equipment vendor via Zelle or Bitcoin.
      Offer expires within 24 hours if not signed today.
    `;

    const result = analyzeOfferText(scamText);

    expect(result.threatIndex).toBeGreaterThanOrEqual(75);
    expect(result.riskLevel).toBe('CRITICAL');
    expect(result.darkTriad.financialTrap).toBeGreaterThanOrEqual(70);
    expect(result.indicators.some(i => i.toLowerCase().includes('equipment') || i.toLowerCase().includes('check'))).toBe(true);
    expect(result.indicators.some(i => i.toLowerCase().includes('urgency') || i.toLowerCase().includes('deadline'))).toBe(true);
    expect(result.safeNextSteps.length).toBeGreaterThan(0);
    expect(result.victimHotlines.length).toBeGreaterThan(0);
  });

  it('flags executive impersonation via Telegram/WhatsApp', () => {
    const impersonationText = `
      Hello candidate, I am the CEO of Microsoft Executive Office.
      Please contact our hiring director directly on Telegram @ExecutiveHiringBot within 2 hours
      for immediate remote data entry onboarding.
    `;

    const result = analyzeOfferText(impersonationText);

    expect(result.threatIndex).toBeGreaterThan(45);
    expect(result.indicators.some(i => i.toLowerCase().includes('telegram'))).toBe(true);
    expect(result.darkTriad.psychologicalCoercion).toBeGreaterThanOrEqual(35);
  });

  it('detects corporate identity claiming free public webmail address', () => {
    const webmailText = `
      Official Job Offer from Google Cloud Platform Engineering.
      Please send your signed contract and identity documentation to google.recruiting.dept@gmail.com.
    `;

    const result = analyzeOfferText(webmailText);

    expect(result.darkTriad.domainSpoof).toBeGreaterThanOrEqual(80);
    expect(result.indicators.some(i => i.toLowerCase().includes('free public webmail'))).toBe(true);
  });

  it('evaluates legitimate corporate offer letter as SAFE with low threat index', () => {
    const legitText = `
      Dear Alex,
      We are delighted to extend an offer of employment for the Software Engineer role at Stripe.
      Please review the details in our official workday portal at https://stripe.com/careers.
      Standard background verification will be conducted by an accredited third-party agency with no cost to you.
      We look forward to welcoming you to the team.
    `;

    const result = analyzeOfferText(legitText, 'https://stripe.com/careers');

    expect(result.threatIndex).toBeLessThan(35);
    expect(result.riskLevel).toBe('SAFE');
    expect(result.darkTriad.financialTrap).toBeLessThanOrEqual(25);
    expect(result.darkTriad.domainSpoof).toBeLessThanOrEqual(25);
  });

  it('evaluates suspicious URL passed in QR code inspection', () => {
    const result = analyzeOfferText('Scan flyer to claim $500/day remote student job', 'http://amazon-student-careers.xyz/apply');

    expect(result.darkTriad.domainSpoof).toBeGreaterThan(50);
    expect(result.indicators.some(i => i.toLowerCase().includes('suspicious domain'))).toBe(true);
  });
});
