import type { Rule } from '../../types/control.js';
import { goalIntegrityRules } from './goal-integrity.js';
import { toolSafetyRules } from './tool-safety.js';
import { identityAccessRules } from './identity-access.js';
import { supplyChainRules } from './supply-chain.js';
import { codeExecutionRules } from './code-execution.js';
import { memoryContextRules } from './memory-context.js';
import { dataLeakageRules } from './data-leakage.js';

export function getAllRules(): Rule[] {
  return [
    ...goalIntegrityRules,
    ...toolSafetyRules,
    ...identityAccessRules,
    ...supplyChainRules,
    ...codeExecutionRules,
    ...memoryContextRules,
    ...dataLeakageRules,
  ];
}

export function getRulesByDomain(domain: string): Rule[] {
  return getAllRules().filter(r => r.domain === domain);
}

export function getRuleById(id: string): Rule | undefined {
  return getAllRules().find(r => r.id === id);
}
