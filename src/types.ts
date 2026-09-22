/**
 * PhishGuard Nexus - Core Domain Types
 * @license Apache-2.0
 */

export type ScamRiskLevel = 'CRITICAL' | 'HIGH' | 'MODERATE' | 'LOW' | 'SAFE';

export interface DarkTriadScores {
  financialTrap: number; // 0 - 100
  domainSpoof: number; // 0 - 100
  psychologicalCoercion: number; // 0 - 100
}

export interface ThreatAnalysis {
  id: string;
  threatIndex: number; // 0 - 100
  riskLevel: ScamRiskLevel;
  verdict: string;
  darkTriad: DarkTriadScores;
  indicators: string[];
  safeNextSteps: string[];
  counterScript: string;
  victimHotlines: {
    region: string;
    agency: string;
    contact: string;
  }[];
  timestamp: string;
  hash: string;
}

export interface AuditRecord {
  id: string;
  date: string;
  sourceType: 'text' | 'qr' | 'image' | 'rental' | 'quiz' | 'header';
  threatIndex: number;
  riskLevel: ScamRiskLevel;
  verdict: string;
  snippet: string;
}

export interface VoiceLanguageOption {
  code: string;
  name: string;
  nativeName: string;
  flag: string;
  sampleGreeting: string;
}

export type FraudCategory =
  | 'offer_letter'
  | 'flyer_qr'
  | 'rental_scam'
  | 'telegram_impersonation'
  | 'check_overpayment'
  | 'equipment_fee';
