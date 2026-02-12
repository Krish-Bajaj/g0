import type { SecurityDomain } from '../types/common.js';

export const DOMAIN_WEIGHTS: Record<SecurityDomain, number> = {
  'goal-integrity': 1.5,
  'tool-safety': 1.5,
  'identity-access': 1.2,
  'supply-chain': 1.0,
  'code-execution': 1.3,
  'memory-context': 1.1,
  'data-leakage': 1.3,
};

export const DOMAIN_LABELS: Record<SecurityDomain, string> = {
  'goal-integrity': 'Goal Integrity',
  'tool-safety': 'Tool Safety',
  'identity-access': 'Identity & Access',
  'supply-chain': 'Supply Chain',
  'code-execution': 'Code Execution',
  'memory-context': 'Memory & Context',
  'data-leakage': 'Data Leakage',
};

export const SEVERITY_DEDUCTIONS = {
  critical: 20,
  high: 10,
  medium: 5,
  low: 2.5,
  info: 0,
} as const;
