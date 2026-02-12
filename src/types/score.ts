import type { Grade, SecurityDomain } from './common.js';

export interface DomainScore {
  domain: SecurityDomain;
  label: string;
  score: number;       // 0-100
  weight: number;
  findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface ScanScore {
  overall: number;     // 0-100
  grade: Grade;
  domains: DomainScore[];
}

export interface ScanResult {
  score: ScanScore;
  findings: import('./finding.js').Finding[];
  graph: import('./agent-graph.js').AgentGraph;
  duration: number;
  timestamp: string;
}
