import * as fs from 'node:fs';
import * as yaml from 'yaml';
import type { FileInventory } from '../../types/common.js';
import type { AgentGraph, AgentNode, ToolNode, PromptNode } from '../../types/agent-graph.js';

const CREW_AGENT_PATTERN = /Agent\s*\(/g;
const CREW_TASK_PATTERN = /Task\s*\(/g;
const DELEGATION_PATTERN = /allow_delegation\s*=\s*(True|true)/;

export function parseCrewAI(graph: AgentGraph, files: FileInventory): void {
  // Parse YAML config files first
  for (const file of files.yaml) {
    const basename = file.relativePath.split('/').pop() ?? '';
    if (basename === 'agents.yaml' || basename === 'agents.yml') {
      parseAgentsYaml(file.path, file.relativePath, graph);
    }
  }

  // Parse Python files for CrewAI patterns
  for (const file of files.python) {
    let content: string;
    try {
      content = fs.readFileSync(file.path, 'utf-8');
    } catch {
      continue;
    }

    if (!content.includes('crewai')) continue;

    const lines = content.split('\n');

    // Extract agents defined in Python
    CREW_AGENT_PATTERN.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = CREW_AGENT_PATTERN.exec(content)) !== null) {
      const line = content.substring(0, match.index).split('\n').length;
      const region = content.substring(match.index, match.index + 1000);

      const roleMatch = region.match(/role\s*=\s*["']([^"']+)["']/);
      const goalMatch = region.match(/goal\s*=\s*["']([^"']+)["']/);
      const backstoryMatch = region.match(/backstory\s*=\s*(?:f?"""([\s\S]*?)"""|f?["']([^"']+)["'])/);
      const delegationEnabled = DELEGATION_PATTERN.test(region);

      const agentNode: AgentNode = {
        id: `crewai-agent-${graph.agents.length}`,
        name: roleMatch?.[1] ?? `agent_${line}`,
        framework: 'crewai',
        file: file.relativePath,
        line,
        tools: [],
        delegationEnabled,
      };

      // Backstory is effectively the system prompt
      const backstory = backstoryMatch?.[1] ?? backstoryMatch?.[2];
      if (backstory) {
        agentNode.systemPrompt = backstory;

        graph.prompts.push({
          id: `crewai-prompt-${graph.prompts.length}`,
          file: file.relativePath,
          line,
          type: 'system',
          content: backstory,
          hasInstructionGuarding: /boundary|restrict|never|must not/i.test(backstory),
          hasSecrets: /sk-|ghp_|AKIA|password\s*[:=]/i.test(backstory),
          hasUserInputInterpolation: /\{.*\}/.test(backstory) && region.startsWith('f'),
          scopeClarity: goalMatch ? 'clear' : 'vague',
        });
      }

      graph.agents.push(agentNode);
    }

    // Extract tools
    extractCrewAITools(content, file.relativePath, lines, graph);
  }
}

function parseAgentsYaml(filePath: string, relativePath: string, graph: AgentGraph): void {
  let content: string;
  try {
    content = fs.readFileSync(filePath, 'utf-8');
  } catch {
    return;
  }

  let parsed: Record<string, any>;
  try {
    parsed = yaml.parse(content);
  } catch {
    return;
  }

  if (!parsed || typeof parsed !== 'object') return;

  for (const [name, config] of Object.entries(parsed)) {
    if (!config || typeof config !== 'object') continue;

    const agentConfig = config as Record<string, any>;
    const line = findKeyLine(content, name);

    const agentNode: AgentNode = {
      id: `crewai-agent-${graph.agents.length}`,
      name: agentConfig.role ?? name,
      framework: 'crewai',
      file: relativePath,
      line,
      tools: [],
      delegationEnabled: agentConfig.allow_delegation === true,
    };

    if (agentConfig.backstory) {
      agentNode.systemPrompt = agentConfig.backstory;

      graph.prompts.push({
        id: `crewai-prompt-${graph.prompts.length}`,
        file: relativePath,
        line,
        type: 'system',
        content: agentConfig.backstory,
        hasInstructionGuarding: /boundary|restrict|never|must not/i.test(agentConfig.backstory),
        hasSecrets: /sk-|ghp_|AKIA|password/i.test(agentConfig.backstory),
        hasUserInputInterpolation: /\{.*\}/.test(agentConfig.backstory),
        scopeClarity: agentConfig.goal ? 'clear' : 'vague',
      });
    }

    graph.agents.push(agentNode);
  }
}

function extractCrewAITools(
  content: string,
  filePath: string,
  lines: string[],
  graph: AgentGraph,
): void {
  const toolPatterns = [
    { pattern: /SerperDevTool/g, name: 'SerperDevTool', capabilities: ['network' as const] },
    { pattern: /ScrapeWebsiteTool/g, name: 'ScrapeWebsiteTool', capabilities: ['network' as const] },
    { pattern: /FileReadTool/g, name: 'FileReadTool', capabilities: ['filesystem' as const] },
    { pattern: /DirectoryReadTool/g, name: 'DirectoryReadTool', capabilities: ['filesystem' as const] },
    { pattern: /CodeInterpreterTool/g, name: 'CodeInterpreterTool', capabilities: ['code-execution' as const] },
  ];

  for (const { pattern, name, capabilities } of toolPatterns) {
    pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(content)) !== null) {
      const line = content.substring(0, match.index).split('\n').length;
      graph.tools.push({
        id: `crewai-tool-${graph.tools.length}`,
        name,
        framework: 'crewai',
        file: filePath,
        line,
        description: '',
        parameters: [],
        hasSideEffects: capabilities.some(c => ['network', 'filesystem', 'code-execution', 'shell'].includes(c)),
        hasInputValidation: false,
        hasSandboxing: false,
        capabilities,
      });
    }
  }
}

function findKeyLine(content: string, key: string): number {
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].startsWith(key + ':') || lines[i].startsWith(`"${key}":`)) {
      return i + 1;
    }
  }
  return 1;
}
