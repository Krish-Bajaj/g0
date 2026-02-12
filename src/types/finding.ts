import type { Severity, Confidence, SecurityDomain, Location } from './common.js';

export interface Finding {
  id: string;
  ruleId: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: Confidence;
  domain: SecurityDomain;
  location: Location;
  remediation: string;
  standards: StandardsMapping;
}

export interface StandardsMapping {
  owaspAgentic: string[];
  aiuc1?: string[];
  iso42001?: string[];
  nistAiRmf?: string[];
}

export interface FindingSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}
