import type { SecurityDomain } from '../types/common.js';
import type { Finding } from '../types/finding.js';
import type { ScanScore, DomainScore } from '../types/score.js';
import { DOMAIN_WEIGHTS, DOMAIN_LABELS, SEVERITY_DEDUCTIONS } from './weights.js';
import { scoreToGrade } from './grades.js';

const ALL_DOMAINS: SecurityDomain[] = [
  'goal-integrity',
  'tool-safety',
  'identity-access',
  'supply-chain',
  'code-execution',
  'memory-context',
  'data-leakage',
];

export function calculateScore(findings: Finding[]): ScanScore {
  const domains: DomainScore[] = ALL_DOMAINS.map(domain => {
    const domainFindings = findings.filter(f => f.domain === domain);
    const critical = domainFindings.filter(f => f.severity === 'critical').length;
    const high = domainFindings.filter(f => f.severity === 'high').length;
    const medium = domainFindings.filter(f => f.severity === 'medium').length;
    const low = domainFindings.filter(f => f.severity === 'low').length;

    const totalDeduction =
      critical * SEVERITY_DEDUCTIONS.critical +
      high * SEVERITY_DEDUCTIONS.high +
      medium * SEVERITY_DEDUCTIONS.medium +
      low * SEVERITY_DEDUCTIONS.low;

    const score = Math.max(0, Math.round(100 - totalDeduction));

    return {
      domain,
      label: DOMAIN_LABELS[domain],
      score,
      weight: DOMAIN_WEIGHTS[domain],
      findings: domainFindings.length,
      critical,
      high,
      medium,
      low,
    };
  });

  const totalWeight = domains.reduce((sum, d) => sum + d.weight, 0);
  const weightedSum = domains.reduce((sum, d) => sum + d.score * d.weight, 0);
  const overall = Math.round(weightedSum / totalWeight);

  return {
    overall,
    grade: scoreToGrade(overall),
    domains,
  };
}
