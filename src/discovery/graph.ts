import * as crypto from 'node:crypto';
import type { FileInventory } from '../types/common.js';
import type { AgentGraph } from '../types/agent-graph.js';
import type { DetectionSummary } from './detector.js';
import { parseLangChain } from '../analyzers/parsers/langchain.js';
import { parseCrewAI } from '../analyzers/parsers/crewai.js';
import { parseMCP } from '../analyzers/parsers/mcp.js';
import { parseOpenAI } from '../analyzers/parsers/openai.js';
import { parseVercelAI } from '../analyzers/parsers/vercel-ai.js';
import { parseBedrock } from '../analyzers/parsers/bedrock.js';
import { parseAutoGen } from '../analyzers/parsers/autogen.js';

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
    models: [],
    vectorDBs: [],
    frameworkVersions: [],
    interAgentLinks: [],
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
      case 'vercel-ai':
        parseVercelAI(graph, files);
        break;
      case 'bedrock':
        parseBedrock(graph, files);
        break;
      case 'autogen':
        parseAutoGen(graph, files);
        break;
    }
  }

  return graph;
}
