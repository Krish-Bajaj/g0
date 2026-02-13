import type { FrameworkId, FileInventory } from '../types/common.js';
import { detectLangChain } from './detectors/langchain.js';
import { detectCrewAI } from './detectors/crewai.js';
import { detectMCP } from './detectors/mcp.js';
import { detectOpenAI } from './detectors/openai.js';
import { detectVercelAI } from './detectors/vercel-ai.js';
import { detectBedrock } from './detectors/bedrock.js';
import { detectAutoGen } from './detectors/autogen.js';
import { detectGeneric } from './detectors/generic.js';

export interface DetectionResult {
  framework: FrameworkId;
  confidence: number;
  evidence: string[];
  files: string[];
}

export interface DetectionSummary {
  primary: FrameworkId;
  secondary: FrameworkId[];
  results: DetectionResult[];
}

type Detector = (files: FileInventory) => DetectionResult | null;

const detectors: Detector[] = [
  detectLangChain,
  detectCrewAI,
  detectMCP,
  detectOpenAI,
  detectVercelAI,
  detectBedrock,
  detectAutoGen,
  detectGeneric,
];

export function detectFrameworks(files: FileInventory): DetectionSummary {
  const results: DetectionResult[] = [];

  for (const detect of detectors) {
    const result = detect(files);
    if (result && result.confidence > 0) {
      results.push(result);
    }
  }

  results.sort((a, b) => b.confidence - a.confidence);

  const primary = results.length > 0 ? results[0].framework : 'generic' as FrameworkId;
  const secondary = results.slice(1)
    .filter(r => r.confidence > 0.3)
    .map(r => r.framework);

  return { primary, secondary, results };
}
