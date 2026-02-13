import * as fs from 'node:fs';
import type { FileInventory } from '../../types/common.js';
import type { DetectionResult } from '../detector.js';

const BEDROCK_DEPS = [
  'boto3',
  'amazon-bedrock',
  'langchain-aws',
  '@aws-sdk/client-bedrock-runtime',
  '@aws-sdk/client-bedrock-agent-runtime',
];

const BEDROCK_PATTERNS = [
  /boto3\.client\s*\(\s*['"]bedrock/,
  /bedrock-runtime/,
  /InvokeModel/,
  /Converse\s*\(/,
  /BedrockAgentRuntime/,
  /ChatBedrock/,
  /from\s+langchain_aws/,
  /BedrockLLM/,
];

export function detectBedrock(files: FileInventory): DetectionResult | null {
  const evidence: string[] = [];
  const matchedFiles: string[] = [];
  let confidence = 0;

  // Check Python and TypeScript/JavaScript files
  for (const file of [...files.python, ...files.typescript, ...files.javascript]) {
    let content: string;
    try {
      content = fs.readFileSync(file.path, 'utf-8');
    } catch {
      continue;
    }

    for (const pattern of BEDROCK_PATTERNS) {
      if (pattern.test(content)) {
        matchedFiles.push(file.relativePath);
        evidence.push(`${file.relativePath}: matches ${pattern.source}`);
        confidence += 0.2;
        break;
      }
    }
  }

  // Check package.json / requirements.txt for bedrock deps
  for (const file of files.configs) {
    let content: string;
    try {
      content = fs.readFileSync(file.path, 'utf-8');
    } catch {
      continue;
    }

    for (const dep of BEDROCK_DEPS) {
      if (content.includes(dep)) {
        evidence.push(`${file.relativePath}: depends on ${dep}`);
        confidence += 0.3;
      }
    }
  }

  if (confidence === 0) return null;

  return {
    framework: 'bedrock',
    confidence: Math.min(confidence, 1),
    evidence,
    files: [...new Set(matchedFiles)],
  };
}
