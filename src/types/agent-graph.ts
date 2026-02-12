import type { FrameworkId, FileInventory } from './common.js';

export interface AgentGraph {
  id: string;
  rootPath: string;
  primaryFramework: FrameworkId;
  secondaryFrameworks: FrameworkId[];
  agents: AgentNode[];
  tools: ToolNode[];
  prompts: PromptNode[];
  configs: ConfigNode[];
  files: FileInventory;
}

export interface AgentNode {
  id: string;
  name: string;
  framework: FrameworkId;
  file: string;
  line: number;
  systemPrompt?: string;
  tools: string[];
  memoryType?: string;
  maxIterations?: number;
  delegationEnabled?: boolean;
}

export interface ToolNode {
  id: string;
  name: string;
  framework: FrameworkId;
  file: string;
  line: number;
  description: string;
  parameters: ToolParameter[];
  hasSideEffects: boolean;
  hasInputValidation: boolean;
  hasSandboxing: boolean;
  capabilities: ToolCapability[];
}

export interface ToolParameter {
  name: string;
  type: string;
  required: boolean;
  hasValidation: boolean;
}

export type ToolCapability =
  | 'filesystem'
  | 'network'
  | 'database'
  | 'shell'
  | 'code-execution'
  | 'email'
  | 'api'
  | 'other';

export interface PromptNode {
  id: string;
  file: string;
  line: number;
  type: 'system' | 'user' | 'template' | 'few_shot';
  content: string;
  hasInstructionGuarding: boolean;
  hasSecrets: boolean;
  hasUserInputInterpolation: boolean;
  scopeClarity: 'clear' | 'vague' | 'missing';
}

export interface ConfigNode {
  id: string;
  file: string;
  type: 'env' | 'yaml' | 'json' | 'toml' | 'python_config';
  secrets: SecretReference[];
  issues: ConfigIssue[];
}

export interface SecretReference {
  key: string;
  line: number;
  isHardcoded: boolean;
}

export interface ConfigIssue {
  type: string;
  message: string;
  line: number;
}
