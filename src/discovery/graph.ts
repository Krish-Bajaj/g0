import * as crypto from 'node:crypto';
import type { FileInventory } from '../types/common.js';
import type { AgentGraph } from '../types/agent-graph.js';
import type { DetectionSummary } from './detector.js';
import { parseLangChain } from '../analyzers/parsers/langchain.js';
import { parseCrewAI } from '../analyzers/parsers/crewai.js';
import { parseMCP } from '../analyzers/parsers/mcp.js';
import { parseOpenAI } from '../analyzers/parsers/openai.js';

export function buildAgentGraph(
  rootPath: string,
  files: FileInventory,
  detection: DetectionSummary,
): AgentGraph {
  const graph: AgentGraph = {
    id: crypto.randomUUID(),
    rootPath,
    primaryFramework: detection.primary,
    secondaryFrameworks: detection.secondary,
    agents: [],
    tools: [],
    prompts: [],
    configs: [],
    files,
  };

  const frameworks = [detection.primary, ...detection.secondary];

  for (const framework of frameworks) {
    switch (framework) {
      case 'langchain':
        parseLangChain(graph, files);
        break;
      case 'crewai':
        parseCrewAI(graph, files);
        break;
      case 'mcp':
        parseMCP(graph, files);
        break;
      case 'openai':
        parseOpenAI(graph, files);
        break;
    }
  }

  return graph;
}
