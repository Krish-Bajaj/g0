import { describe, it, expect } from 'vitest';
import { getAllRules, getRuleById, getRulesByDomain } from '../../src/analyzers/rules/index.js';

describe('Rule Registry', () => {
  it('has 96 rules', () => {
    const rules = getAllRules();
    expect(rules.length).toBe(96);
  });

  it('has unique rule IDs', () => {
    const rules = getAllRules();
    const ids = rules.map(r => r.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('has correct rule counts per domain', () => {
    expect(getRulesByDomain('goal-integrity')).toHaveLength(12);
    expect(getRulesByDomain('tool-safety')).toHaveLength(20);
    expect(getRulesByDomain('identity-access')).toHaveLength(20);
    expect(getRulesByDomain('supply-chain')).toHaveLength(10);
    expect(getRulesByDomain('code-execution')).toHaveLength(16);
    expect(getRulesByDomain('memory-context')).toHaveLength(8);
    expect(getRulesByDomain('data-leakage')).toHaveLength(10);
  });

  it('can find rules by ID', () => {
    const rule = getRuleById('AA-GI-001');
    expect(rule).toBeDefined();
    expect(rule!.domain).toBe('goal-integrity');
  });

  it('returns undefined for unknown rule ID', () => {
    expect(getRuleById('XX-ZZ-999')).toBeUndefined();
  });

  it('every rule has required fields', () => {
    const rules = getAllRules();
    for (const rule of rules) {
      expect(rule.id).toMatch(/^AA-[A-Z]{2}-\d{3}$/);
      expect(rule.name).toBeTruthy();
      expect(rule.domain).toBeTruthy();
      expect(rule.severity).toMatch(/^(critical|high|medium|low|info)$/);
      expect(rule.confidence).toMatch(/^(high|medium|low)$/);
      expect(typeof rule.check).toBe('function');
    }
  });

  it('every rule maps to OWASP standards', () => {
    const rules = getAllRules();
    for (const rule of rules) {
      expect(rule.owaspAgentic).toBeDefined();
      expect(rule.owaspAgentic.length).toBeGreaterThan(0);
      for (const ref of rule.owaspAgentic) {
        expect(ref).toMatch(/^ASI\d{2}$/);
      }
    }
  });

  it('every rule has standards mapping', () => {
    const rules = getAllRules();
    for (const rule of rules) {
      expect(rule.standards).toBeDefined();
      expect(rule.standards.owaspAgentic).toBeDefined();
      expect(rule.standards.owaspAgentic.length).toBeGreaterThan(0);
    }
  });
});
