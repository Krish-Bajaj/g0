import * as fs from 'node:fs';
import type { FileInventory } from '../../types/common.js';
import type { AgentGraph, AgentNode, ToolNode, PromptNode } from '../../types/agent-graph.js';

const ASSISTANT_CREATE_PATTERN = /(?:assistants\.create|Assistant\.create|client\.beta\.assistants\.create)\s*\(/g;
const RESPONSES_CREATE_PATTERN = /(?:responses\.create|client\.responses\.create)\s*\(/g;
const AGENT_SDK_PATTERN = /Agent\s*\(\s*\n?\s*name\s*=/g;
const FUNCTION_TOOL_PATTERN = /(?:function_tool|FunctionTool)\s*\(/g;

export function parseOpenAI(graph: AgentGraph, files: FileInventory): void {
  for (const file of [...files.python, ...files.typescript, ...files.javascript]) {
    let content: string;
    try {
      content = fs.readFileSync(file.path, 'utf-8');
    } catch {
      continue;
    }

    if (!content.includes('openai') && !content.includes('Agent(')) continue;

    const lines = content.split('\n');

    // Extract assistants
    ASSISTANT_CREATE_PATTERN.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = ASSISTANT_CREATE_PATTERN.exec(content)) !== null) {
      const line = content.substring(0, match.index).split('\n').length;
      const region = content.substring(match.index, match.index + 2000);

      const nameMatch = region.match(/name\s*=\s*["']([^"']+)["']/);
      const instructionsMatch = region.match(/instructions\s*=\s*(?:f?"""([\s\S]*?)"""|f?["']([^"']+)["'])/);

      const agentNode: AgentNode = {
        id: `openai-agent-${graph.agents.length}`,
        name: nameMatch?.[1] ?? `assistant_${line}`,
        framework: 'openai',
        file: file.relativePath,
        line,
        tools: [],
      };

      const instructions = instructionsMatch?.[1] ?? instructionsMatch?.[2];
      if (instructions) {
        agentNode.systemPrompt = instructions;
        graph.prompts.push({
          id: `openai-prompt-${graph.prompts.length}`,
          file: file.relativePath,
          line,
          type: 'system',
          content: instructions,
          hasInstructionGuarding: /boundary|restrict|never|must not/i.test(instructions),
          hasSecrets: /sk-|ghp_|AKIA|password/i.test(instructions),
          hasUserInputInterpolation: /\{.*\}/.test(instructions),
          scopeClarity: assessScope(instructions),
        });
      }

      graph.agents.push(agentNode);
    }

    // Extract OpenAI Agents SDK agents
    AGENT_SDK_PATTERN.lastIndex = 0;
    while ((match = AGENT_SDK_PATTERN.exec(content)) !== null) {
      const line = content.substring(0, match.index).split('\n').length;
      const region = content.substring(match.index, match.index + 2000);

      const nameMatch = region.match(/name\s*=\s*["']([^"']+)["']/);
      const instructionsMatch = region.match(/instructions\s*=\s*(?:f?"""([\s\S]*?)"""|f?["']([^"']+)["'])/);

      const agentNode: AgentNode = {
        id: `openai-agent-${graph.agents.length}`,
        name: nameMatch?.[1] ?? `agent_${line}`,
        framework: 'openai',
        file: file.relativePath,
        line,
        tools: [],
      };

      const instructions = instructionsMatch?.[1] ?? instructionsMatch?.[2];
      if (instructions) {
        agentNode.systemPrompt = instructions;
        graph.prompts.push({
          id: `openai-prompt-${graph.prompts.length}`,
          file: file.relativePath,
          line,
          type: 'system',
          content: instructions,
          hasInstructionGuarding: /boundary|restrict|never|must not/i.test(instructions),
          hasSecrets: /sk-|ghp_|AKIA|password/i.test(instructions),
          hasUserInputInterpolation: /\{.*\}/.test(instructions),
          scopeClarity: assessScope(instructions),
        });
      }

      graph.agents.push(agentNode);
    }

    // Extract function tools
    FUNCTION_TOOL_PATTERN.lastIndex = 0;
    while ((match = FUNCTION_TOOL_PATTERN.exec(content)) !== null) {
      const line = content.substring(0, match.index).split('\n').length;
      const region = content.substring(match.index, match.index + 500);
      const nameMatch = region.match(/name\s*=\s*["']([^"']+)["']/);
      const assignMatch = lines[line - 1]?.match(/(\w+)\s*=/);

      graph.tools.push({
        id: `openai-tool-${graph.tools.length}`,
        name: nameMatch?.[1] ?? assignMatch?.[1] ?? `tool_${line}`,
        framework: 'openai',
        file: file.relativePath,
        line,
        description: '',
        parameters: [],
        hasSideEffects: false,
        hasInputValidation: /schema|parameters|strict/.test(region),
        hasSandboxing: false,
        capabilities: ['other'],
      });
    }

    // Extract responses.create calls (for tool use patterns)
    RESPONSES_CREATE_PATTERN.lastIndex = 0;
    while ((match = RESPONSES_CREATE_PATTERN.exec(content)) !== null) {
      const line = content.substring(0, match.index).split('\n').length;
      const region = content.substring(match.index, match.index + 2000);

      const instructionsMatch = region.match(/instructions\s*=\s*(?:f?"""([\s\S]*?)"""|f?["']([^"']+)["'])/);
      if (instructionsMatch) {
        const instructions = instructionsMatch[1] ?? instructionsMatch[2] ?? '';
        graph.prompts.push({
          id: `openai-prompt-${graph.prompts.length}`,
          file: file.relativePath,
          line,
          type: 'system',
          content: instructions,
          hasInstructionGuarding: /boundary|restrict|never|must not/i.test(instructions),
          hasSecrets: /sk-|ghp_|AKIA|password/i.test(instructions),
          hasUserInputInterpolation: /\{.*\}/.test(instructions),
          scopeClarity: assessScope(instructions),
        });
      }
    }
  }
}

function assessScope(instructions: string): 'clear' | 'vague' | 'missing' {
  if (instructions.length < 10) return 'missing';
  const indicators = [
    /you\s+are\s/i, /your\s+(role|task|purpose)/i,
    /only\s+(do|respond|answer)/i, /do\s+not\s/i,
    /must\s+(not|never|always)/i, /scope/i, /restrict/i,
  ];
  const matches = indicators.filter(p => p.test(instructions)).length;
  if (matches >= 2) return 'clear';
  if (matches >= 1) return 'vague';
  return 'missing';
}
