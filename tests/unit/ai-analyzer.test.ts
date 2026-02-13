import { describe, it, expect, vi } from 'vitest';
import { runAIAnalysis } from '../../src/ai/analyzer.js';
import type { AIProvider } from '../../src/ai/provider.js';
import type { Finding } from '../../src/types/finding.js';
import type { AgentGraph } from '../../src/types/agent-graph.js';

function createMockProvider(responses: string[]): AIProvider {
  let callIndex = 0;
  return {
    name: 'mock',
    async analyze(_prompt: string, _context: string): Promise<string> {
      return responses[callIndex++] ?? '{}';
    },
  };
}

function createMockGraph(): AgentGraph {
  return {
    id: 'test',
    rootPath: '/tmp/test',
    primaryFramework: 'langchain',
    secondaryFrameworks: [],
    agents: [{
      id: 'agent-1',
      name: 'TestAgent',
      framework: 'langchain',
      file: 'agent.py',
      line: 1,
      tools: [],
    }],
    tools: [],
    prompts: [{
      id: 'prompt-1',
      file: 'agent.py',
      line: 5,
      type: 'system',
      content: 'You are a helpful assistant.',
      hasInstructionGuarding: false,
      hasSecrets: false,
      hasUserInputInterpolation: false,
      scopeClarity: 'vague',
    }],
    configs: [],
    models: [],
    vectorDBs: [],
    frameworkVersions: [],
    interAgentLinks: [],
    files: { all: [], python: [], typescript: [], javascript: [], yaml: [], json: [], configs: [] },
  };
}

function createMockFindings(): Finding[] {
  return [
    {
      id: 'AA-GI-001-0',
      ruleId: 'AA-GI-001',
      title: 'No scope boundaries',
      description: 'System prompt lacks scope boundaries.',
      severity: 'high',
      confidence: 'high',
      domain: 'goal-integrity',
      location: { file: 'agent.py', line: 5 },
      remediation: 'Add scope boundaries.',
      standards: { owaspAgentic: ['ASI01'] },
    },
  ];
}

describe('AI Analyzer', () => {
  it('should return enrichments from mock provider', async () => {
    const provider = createMockProvider([
      JSON.stringify({
        findings: [{
          id: 'AA-GI-001-0',
          explanation: 'The system prompt is too vague.',
          remediation: 'Add explicit role definition.',
        }],
      }),
      JSON.stringify({
        assessments: [{
          id: 'AA-GI-001-0',
          falsePositive: false,
        }],
      }),
      JSON.stringify({
        findings: [],
      }),
    ]);

    const result = await runAIAnalysis(
      createMockFindings(),
      createMockGraph(),
      provider,
    );

    expect(result.provider).toBe('mock');
    expect(result.enrichments.size).toBeGreaterThan(0);
    expect(result.duration).toBeGreaterThanOrEqual(0);
  });

  it('should handle provider errors gracefully', async () => {
    const provider: AIProvider = {
      name: 'failing',
      async analyze(): Promise<string> {
        throw new Error('API failure');
      },
    };

    const result = await runAIAnalysis(
      createMockFindings(),
      createMockGraph(),
      provider,
    );

    expect(result.provider).toBe('failing');
    expect(result.enrichments.size).toBe(0);
    expect(result.complexFindings.length).toBe(0);
  });

  it('should handle empty findings', async () => {
    const provider = createMockProvider(['{}', '{}', '{}']);
    const result = await runAIAnalysis([], createMockGraph(), provider);
    expect(result.enrichments.size).toBe(0);
  });
});
