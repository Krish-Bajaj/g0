import * as fs from 'node:fs';
import type { FileInventory } from '../../types/common.js';
import type { AgentGraph, AgentNode, ToolNode, PromptNode } from '../../types/agent-graph.js';
import {
  isTreeSitterAvailable,
  getFileTreeForLang,
  findFunctionCalls,
  findNodes,
  type Tree,
} from '../ast/index.js';
import {
  findDecorators,
  getDecoratedFunction,
  getKeywordArgInt,
  getKeywordArgString,
  getKeywordArgBool,
} from '../ast/python.js';
import { getKeywordArgument, extractStringValue } from '../ast/queries.js';

const AGENT_PATTERNS = [
  { pattern: /AgentExecutor\s*\(/g, name: 'AgentExecutor' },
  { pattern: /create_react_agent\s*\(/g, name: 'ReactAgent' },
  { pattern: /create_openai_functions_agent\s*\(/g, name: 'OpenAIFunctionsAgent' },
  { pattern: /create_tool_calling_agent\s*\(/g, name: 'ToolCallingAgent' },
  { pattern: /StateGraph\s*\(/g, name: 'LangGraphAgent' },
  { pattern: /create_structured_chat_agent\s*\(/g, name: 'StructuredChatAgent' },
];

const TOOL_PATTERNS = [
  { pattern: /@tool\b/g, type: 'decorator' },
  { pattern: /Tool\s*\(\s*\n?\s*name\s*=/g, type: 'constructor' },
  { pattern: /StructuredTool/g, type: 'class' },
  { pattern: /BaseTool/g, type: 'class' },
  { pattern: /ShellTool/g, type: 'shell' },
  { pattern: /PythonREPLTool/g, type: 'code-exec' },
  { pattern: /SQLDatabaseToolkit/g, type: 'database' },
  { pattern: /FileManagementToolkit/g, type: 'filesystem' },
  { pattern: /RequestsToolkit/g, type: 'network' },
];

const MEMORY_PATTERNS = [
  /ConversationBufferMemory/,
  /ConversationBufferWindowMemory/,
  /ConversationSummaryMemory/,
  /RedisChatMessageHistory/,
  /PostgresChatMessageHistory/,
  /MemorySaver/,
];

export function parseLangChain(graph: AgentGraph, files: FileInventory): void {
  const codeFiles = [...files.python, ...files.typescript, ...files.javascript];

  for (const file of codeFiles) {
    let content: string;
    try {
      content = fs.readFileSync(file.path, 'utf-8');
    } catch {
      continue;
    }

    if (!content.includes('langchain') && !content.includes('langgraph')) continue;

    const lines = content.split('\n');
    const isPython = file.language === 'python';
    const tree = isPython && isTreeSitterAvailable()
      ? getFileTreeForLang(file.path, content, 'python')
      : null;

    if (tree) {
      extractAgentsAST(tree, content, lines, file.relativePath, graph);
      extractToolsAST(tree, lines, file.relativePath, graph);
    } else {
      extractAgentsRegex(content, lines, file.relativePath, graph);
      extractToolsRegex(content, lines, file.relativePath, graph);
    }

    // Prompts use a mix of AST and regex
    extractPrompts(content, file.relativePath, lines, graph);
  }
}

function extractAgentsAST(
  tree: Tree,
  content: string,
  lines: string[],
  filePath: string,
  graph: AgentGraph,
): void {
  const agentCallPatterns = /^(AgentExecutor|create_react_agent|create_openai_functions_agent|create_tool_calling_agent|StateGraph|create_structured_chat_agent)$/;
  const agentCalls = findFunctionCalls(tree, agentCallPatterns);

  for (const call of agentCalls) {
    const callee = call.childForFieldName('function');
    const name = callee?.text ?? 'Agent';

    // Skip agent-creation functions (create_react_agent, etc.) that are nested
    // as arguments to AgentExecutor — they create the chain, not the executor
    if (name !== 'AgentExecutor' && name !== 'StateGraph') {
      let parent = call.parent;
      while (parent) {
        if ((parent.type === 'call' || parent.type === 'call_expression') &&
            parent.childForFieldName('function')?.text === 'AgentExecutor') {
          break;
        }
        parent = parent.parent;
      }
      if (parent) continue; // nested inside AgentExecutor, skip
    }

    const line = call.startPosition.row + 1;
    const memoryType = detectMemory(content);

    const maxIterations = getKeywordArgInt(call, 'max_iterations') ?? undefined;

    const agentNode: AgentNode = {
      id: `langchain-agent-${graph.agents.length}`,
      name: extractAssignmentName(lines, line) || name,
      framework: 'langchain',
      file: filePath,
      line,
      tools: [],
      memoryType,
      maxIterations,
    };

    const systemPrompt = extractSystemPromptNear(content, call.startPosition.row);
    if (systemPrompt) {
      agentNode.systemPrompt = systemPrompt;
    }

    graph.agents.push(agentNode);
  }
}

function extractToolsAST(
  tree: Tree,
  lines: string[],
  filePath: string,
  graph: AgentGraph,
): void {
  // Find @tool decorated functions
  const toolDecorators = findDecorators(tree, 'tool');
  for (const dec of toolDecorators) {
    const func = getDecoratedFunction(dec);
    const funcName = func?.childForFieldName('name')?.text;
    const line = dec.startPosition.row + 1;

    graph.tools.push({
      id: `langchain-tool-${graph.tools.length}`,
      name: funcName ?? `tool_${line}`,
      framework: 'langchain',
      file: filePath,
      line,
      description: '',
      parameters: [],
      hasSideEffects: false,
      hasInputValidation: false,
      hasSandboxing: false,
      capabilities: ['other'],
    });
  }

  // Find known tool constructors
  const knownTools = [
    { pattern: /^ShellTool$/, type: 'shell' },
    { pattern: /^PythonREPLTool$/, type: 'code-exec' },
    { pattern: /^SQLDatabaseToolkit$/, type: 'database' },
    { pattern: /^FileManagementToolkit$/, type: 'filesystem' },
    { pattern: /^RequestsToolkit$/, type: 'network' },
    { pattern: /^StructuredTool$/, type: 'class' },
    { pattern: /^BaseTool$/, type: 'class' },
  ];

  for (const { pattern, type } of knownTools) {
    const calls = findFunctionCalls(tree, pattern);
    for (const call of calls) {
      const line = call.startPosition.row + 1;
      const toolName = extractAssignmentName(lines, line) || call.childForFieldName('function')?.text || `tool_${line}`;

      graph.tools.push({
        id: `langchain-tool-${graph.tools.length}`,
        name: toolName,
        framework: 'langchain',
        file: filePath,
        line,
        description: '',
        parameters: [],
        hasSideEffects: ['shell', 'code-exec', 'database', 'filesystem', 'network'].includes(type),
        hasInputValidation: type === 'class',
        hasSandboxing: false,
        capabilities: mapToolType(type),
      });
    }
  }
}

function extractAgentsRegex(
  content: string,
  lines: string[],
  filePath: string,
  graph: AgentGraph,
): void {
  for (const { pattern, name } of AGENT_PATTERNS) {
    pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(content)) !== null) {
      const line = content.substring(0, match.index).split('\n').length;
      const memoryType = detectMemory(content);

      const agentNode: AgentNode = {
        id: `langchain-agent-${graph.agents.length}`,
        name: extractAssignmentName(lines, line) || name,
        framework: 'langchain',
        file: filePath,
        line,
        tools: [],
        memoryType,
        maxIterations: extractMaxIterations(content, match.index),
      };

      const systemPrompt = extractSystemPromptNear(content, match.index);
      if (systemPrompt) {
        agentNode.systemPrompt = systemPrompt;
      }

      graph.agents.push(agentNode);
    }
  }
}

function extractToolsRegex(
  content: string,
  lines: string[],
  filePath: string,
  graph: AgentGraph,
): void {
  for (const { pattern, type } of TOOL_PATTERNS) {
    pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(content)) !== null) {
      const line = content.substring(0, match.index).split('\n').length;
      const toolName = extractToolName(lines, line, type);

      const toolNode: ToolNode = {
        id: `langchain-tool-${graph.tools.length}`,
        name: toolName,
        framework: 'langchain',
        file: filePath,
        line,
        description: '',
        parameters: [],
        hasSideEffects: ['shell', 'code-exec', 'database', 'filesystem', 'network'].includes(type),
        hasInputValidation: type === 'class',
        hasSandboxing: false,
        capabilities: mapToolType(type),
      };

      graph.tools.push(toolNode);
    }
  }
}

function extractAssignmentName(lines: string[], lineNum: number): string | undefined {
  const line = lines[lineNum - 1];
  if (!line) return undefined;
  const match = line.match(/(\w+)\s*=/);
  return match?.[1];
}

function extractMaxIterations(content: string, startIndex: number): number | undefined {
  const region = content.substring(startIndex, startIndex + 500);
  const match = region.match(/max_iterations\s*=\s*(\d+)/);
  return match ? parseInt(match[1]) : undefined;
}

function extractSystemPromptNear(content: string, index: number): string | undefined {
  const start = Math.max(0, typeof index === 'number' ? index - 2000 : 0);
  const end = typeof index === 'number' ? index + 2000 : content.length;
  const region = content.substring(start, end);
  const match = region.match(/SystemMessage\s*\(\s*content\s*=\s*["'`]([\s\S]*?)["'`]\s*\)/);
  return match?.[1];
}

function extractToolName(lines: string[], lineNum: number, type: string): string {
  if (type === 'decorator') {
    const nextLine = lines[lineNum];
    if (nextLine) {
      const funcMatch = nextLine.match(/def\s+(\w+)/);
      if (funcMatch) return funcMatch[1];
    }
  }
  const line = lines[lineNum - 1];
  if (line) {
    const nameMatch = line.match(/name\s*=\s*["']([^"']+)["']/);
    if (nameMatch) return nameMatch[1];
    const assignMatch = line.match(/(\w+)\s*=/);
    if (assignMatch) return assignMatch[1];
  }
  return `tool_${lineNum}`;
}

function mapToolType(type: string): ToolNode['capabilities'] {
  switch (type) {
    case 'shell': return ['shell'];
    case 'code-exec': return ['code-execution'];
    case 'database': return ['database'];
    case 'filesystem': return ['filesystem'];
    case 'network': return ['network'];
    default: return ['other'];
  }
}

function detectMemory(content: string): string | undefined {
  for (const pattern of MEMORY_PATTERNS) {
    if (pattern.test(content)) {
      const match = content.match(pattern);
      return match?.[0];
    }
  }
  return undefined;
}

function extractPrompts(
  content: string,
  filePath: string,
  lines: string[],
  graph: AgentGraph,
): void {
  // Extract SystemMessage content
  const systemMsgPattern = /SystemMessage\s*\(\s*content\s*=\s*(?:f?"""([\s\S]*?)"""|f?'''([\s\S]*?)'''|f?["']([\s\S]*?)["'])\s*\)/g;
  let match: RegExpExecArray | null;
  while ((match = systemMsgPattern.exec(content)) !== null) {
    const promptContent = match[1] ?? match[2] ?? match[3] ?? '';
    const line = content.substring(0, match.index).split('\n').length;

    graph.prompts.push({
      id: `langchain-prompt-${graph.prompts.length}`,
      file: filePath,
      line,
      type: 'system',
      content: promptContent,
      hasInstructionGuarding: checkInstructionGuarding(promptContent),
      hasSecrets: checkForSecrets(promptContent),
      hasUserInputInterpolation: checkUserInputInterpolation(promptContent, match[0]),
      scopeClarity: assessScopeClarity(promptContent),
    });
  }

  // Extract template strings assigned to prompt-like variables
  const templatePattern = /(?:system_prompt|system_message|SYSTEM_PROMPT|prompt)\s*=\s*(?:f?"""([\s\S]*?)"""|f?'''([\s\S]*?)'''|f?["'`]([\s\S]*?)["'`])/g;
  while ((match = templatePattern.exec(content)) !== null) {
    const promptContent = match[1] ?? match[2] ?? match[3] ?? '';
    const line = content.substring(0, match.index).split('\n').length;

    graph.prompts.push({
      id: `langchain-prompt-${graph.prompts.length}`,
      file: filePath,
      line,
      type: 'system',
      content: promptContent,
      hasInstructionGuarding: checkInstructionGuarding(promptContent),
      hasSecrets: checkForSecrets(promptContent),
      hasUserInputInterpolation: checkUserInputInterpolation(promptContent, match[0]),
      scopeClarity: assessScopeClarity(promptContent),
    });
  }
}

function checkInstructionGuarding(prompt: string): boolean {
  const guards = [
    /ignore\s+(any\s+)?previous/i,
    /do\s+not\s+(follow|obey|respond)/i,
    /you\s+(must|should)\s+not/i,
    /under\s+no\s+circumstances/i,
    /never\s+(reveal|share|disclose)/i,
    /boundary/i,
    /guardrail/i,
  ];
  return guards.some(g => g.test(prompt));
}

function checkForSecrets(prompt: string): boolean {
  const secretPatterns = [
    /sk-[a-zA-Z0-9]{20,}/,
    /ghp_[a-zA-Z0-9]{36}/,
    /gho_[a-zA-Z0-9]{36}/,
    /AKIA[0-9A-Z]{16}/,
    /password\s*[:=]\s*["'][^"']+["']/i,
    /api[_-]?key\s*[:=]\s*["'][^"']+["']/i,
    /secret\s*[:=]\s*["'][^"']+["']/i,
    /token\s*[:=]\s*["'][^"']+["']/i,
  ];
  return secretPatterns.some(p => p.test(prompt));
}

function checkUserInputInterpolation(prompt: string, fullMatch: string): boolean {
  return (
    fullMatch.startsWith('f"') ||
    fullMatch.startsWith("f'") ||
    fullMatch.startsWith('f"""') ||
    fullMatch.startsWith("f'''") ||
    /\{.*user.*\}/i.test(prompt) ||
    /\{.*input.*\}/i.test(prompt) ||
    /\{.*query.*\}/i.test(prompt) ||
    /\$\{.*\}/.test(prompt) ||
    /\.format\s*\(/.test(fullMatch)
  );
}

function assessScopeClarity(prompt: string): 'clear' | 'vague' | 'missing' {
  if (prompt.length < 10) return 'missing';

  const scopeIndicators = [
    /you\s+are\s+(a|an)\s+/i,
    /your\s+(role|task|job|purpose)/i,
    /only\s+(respond|answer|help)/i,
    /do\s+not\s+/i,
    /you\s+(must|should|can|cannot)/i,
    /scope/i,
    /restrict/i,
    /limit/i,
  ];

  const matches = scopeIndicators.filter(p => p.test(prompt)).length;
  if (matches >= 2) return 'clear';
  if (matches >= 1) return 'vague';
  return 'missing';
}
