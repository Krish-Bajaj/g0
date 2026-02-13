import * as fs from 'node:fs';
import type { Finding } from '../types/finding.js';
import type { AgentGraph } from '../types/agent-graph.js';
import type { AIAnalysisResult, AIFindingEnrichment, AIComplexFinding } from '../types/score.js';
import type { AIProvider } from './provider.js';
import { EXPLANATION_PROMPT, FALSE_POSITIVE_PROMPT, COMPLEX_PATTERN_PROMPT } from './prompts.js';

const MAX_FINDINGS_PER_BATCH = 20;
const MAX_CONTEXT_CHARS = 8000;

export async function runAIAnalysis(
  findings: Finding[],
  graph: AgentGraph,
  provider: AIProvider,
): Promise<AIAnalysisResult> {
  const startTime = Date.now();
  const enrichments = new Map<string, AIFindingEnrichment>();
  const complexFindings: AIComplexFinding[] = [];

  // Pass 1: Explanation enrichment (top findings by severity)
  const topFindings = prioritizeFindings(findings).slice(0, MAX_FINDINGS_PER_BATCH);
  if (topFindings.length > 0) {
    try {
      const explanations = await runExplanationPass(topFindings, graph, provider);
      for (const [id, enrichment] of explanations) {
        enrichments.set(id, enrichment);
      }
    } catch {
      // Non-fatal: continue without explanations
    }
  }

  // Pass 2: False positive detection
  if (topFindings.length > 0) {
    try {
      const fpResults = await runFalsePositivePass(topFindings, graph, provider);
      for (const [id, fp] of fpResults) {
        const existing = enrichments.get(id);
        if (existing) {
          existing.falsePositive = fp.falsePositive;
          existing.falsePositiveReason = fp.reason;
        } else {
          enrichments.set(id, {
            explanation: '',
            remediation: '',
            falsePositive: fp.falsePositive,
            falsePositiveReason: fp.reason,
          });
        }
      }
    } catch {
      // Non-fatal
    }
  }

  // Pass 3: Complex pattern detection
  try {
    const complex = await runComplexPatternPass(graph, provider);
    complexFindings.push(...complex);
  } catch {
    // Non-fatal
  }

  return {
    enrichments,
    complexFindings,
    provider: provider.name,
    duration: Date.now() - startTime,
  };
}

function prioritizeFindings(findings: Finding[]): Finding[] {
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  return [...findings].sort((a, b) => order[a.severity] - order[b.severity]);
}

function buildFindingContext(finding: Finding, graph: AgentGraph): string {
  let context = `Finding: ${finding.title}\nRule: ${finding.ruleId}\nFile: ${finding.location.file}:${finding.location.line}\n`;
  if (finding.location.snippet) {
    context += `Snippet: ${finding.location.snippet}\n`;
  }

  // Try to include surrounding code
  try {
    const fullPath = `${graph.rootPath}/${finding.location.file}`;
    const content = fs.readFileSync(fullPath, 'utf-8');
    const lines = content.split('\n');
    const start = Math.max(0, finding.location.line - 5);
    const end = Math.min(lines.length, finding.location.line + 10);
    context += `\nCode context:\n${lines.slice(start, end).join('\n')}\n`;
  } catch {
    // File may not be readable
  }

  return context;
}

async function runExplanationPass(
  findings: Finding[],
  graph: AgentGraph,
  provider: AIProvider,
): Promise<Map<string, AIFindingEnrichment>> {
  const result = new Map<string, AIFindingEnrichment>();
  const contexts = findings.map(f => ({
    id: f.id,
    ruleId: f.ruleId,
    title: f.title,
    severity: f.severity,
    context: buildFindingContext(f, graph),
  }));

  const contextStr = JSON.stringify(contexts).slice(0, MAX_CONTEXT_CHARS);
  const response = await provider.analyze(EXPLANATION_PROMPT, contextStr);

  try {
    const parsed = JSON.parse(response) as {
      findings: Array<{ id: string; explanation: string; remediation: string }>;
    };
    for (const item of parsed.findings) {
      result.set(item.id, {
        explanation: item.explanation,
        remediation: item.remediation,
        falsePositive: false,
      });
    }
  } catch {
    // Response wasn't valid JSON; skip
  }

  return result;
}

async function runFalsePositivePass(
  findings: Finding[],
  graph: AgentGraph,
  provider: AIProvider,
): Promise<Map<string, { falsePositive: boolean; reason?: string }>> {
  const result = new Map<string, { falsePositive: boolean; reason?: string }>();
  const contexts = findings.map(f => ({
    id: f.id,
    ruleId: f.ruleId,
    title: f.title,
    context: buildFindingContext(f, graph),
  }));

  const contextStr = JSON.stringify(contexts).slice(0, MAX_CONTEXT_CHARS);
  const response = await provider.analyze(FALSE_POSITIVE_PROMPT, contextStr);

  try {
    const parsed = JSON.parse(response) as {
      assessments: Array<{ id: string; falsePositive: boolean; reason?: string }>;
    };
    for (const item of parsed.assessments) {
      result.set(item.id, {
        falsePositive: item.falsePositive,
        reason: item.reason,
      });
    }
  } catch {
    // Response wasn't valid JSON; skip
  }

  return result;
}

async function runComplexPatternPass(
  graph: AgentGraph,
  provider: AIProvider,
): Promise<AIComplexFinding[]> {
  const summary = buildGraphSummary(graph);
  const response = await provider.analyze(COMPLEX_PATTERN_PROMPT, summary);

  try {
    const parsed = JSON.parse(response) as {
      findings: AIComplexFinding[];
    };
    return parsed.findings ?? [];
  } catch {
    return [];
  }
}

function buildGraphSummary(graph: AgentGraph): string {
  const parts: string[] = [];
  parts.push(`Framework: ${graph.primaryFramework}`);
  parts.push(`Agents (${graph.agents.length}):`);
  for (const agent of graph.agents) {
    parts.push(`  - ${agent.name} (${agent.framework}, tools: ${agent.tools.length}, prompt: ${agent.systemPrompt ? 'yes' : 'no'})`);
  }
  parts.push(`Tools (${graph.tools.length}):`);
  for (const tool of graph.tools) {
    parts.push(`  - ${tool.name}: ${tool.capabilities.join(', ')} (side-effects: ${tool.hasSideEffects})`);
  }
  parts.push(`Prompts (${graph.prompts.length}):`);
  for (const prompt of graph.prompts) {
    parts.push(`  - ${prompt.type} in ${prompt.file} (guarded: ${prompt.hasInstructionGuarding}, scope: ${prompt.scopeClarity})`);
    if (prompt.content) {
      parts.push(`    "${prompt.content.substring(0, 200)}..."`);
    }
  }
  if (graph.interAgentLinks.length > 0) {
    parts.push(`Inter-agent links (${graph.interAgentLinks.length}):`);
    for (const link of graph.interAgentLinks) {
      parts.push(`  - ${link.fromAgent} -> ${link.toAgent} (${link.communicationType}, auth: ${link.hasAuthentication})`);
    }
  }
  return parts.join('\n').slice(0, MAX_CONTEXT_CHARS);
}
