import type { SecurityDomain, Severity, Confidence } from './common.js';
import type { AgentGraph } from './agent-graph.js';
import type { Finding } from './finding.js';

export interface Rule {
  id: string;
  name: string;
  domain: SecurityDomain;
  severity: Severity;
  confidence: Confidence;
  description: string;
  frameworks: string[];
  owaspAgentic: string[];
  standards: import('./finding.js').StandardsMapping;
  check: (graph: AgentGraph) => Finding[];
}
