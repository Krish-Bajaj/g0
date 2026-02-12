import * as fs from 'node:fs';
import type { FileInventory } from '../../types/common.js';
import type { DetectionResult } from '../detector.js';

const MCP_PATTERNS = [
  /from\s+mcp\s+import/,
  /from\s+mcp\.server/,
  /@mcp\.tool/,
  /McpServer/,
  /FastMCP/,
  /require\s*\(\s*['"]@modelcontextprotocol/,
  /from\s+['"]@modelcontextprotocol/,
  /import.*@modelcontextprotocol/,
  /server\.tool\s*\(/,
  /server\.resource\s*\(/,
  /server\.prompt\s*\(/,
];

const MCP_CONFIG_FILES = ['mcp.json', 'claude_desktop_config.json'];

export function detectMCP(files: FileInventory): DetectionResult | null {
  const evidence: string[] = [];
  const matchedFiles: string[] = [];
  let confidence = 0;

  // Check for MCP config files
  for (const file of [...files.json, ...files.configs]) {
    const basename = file.relativePath.split('/').pop() ?? '';
    if (MCP_CONFIG_FILES.includes(basename)) {
      evidence.push(`${file.relativePath}: MCP config file`);
      matchedFiles.push(file.relativePath);
      confidence += 0.3;
    }
  }

  // Check code files
  for (const file of [...files.python, ...files.typescript, ...files.javascript]) {
    let content: string;
    try {
      content = fs.readFileSync(file.path, 'utf-8');
    } catch {
      continue;
    }

    for (const pattern of MCP_PATTERNS) {
      if (pattern.test(content)) {
        matchedFiles.push(file.relativePath);
        evidence.push(`${file.relativePath}: matches ${pattern.source}`);
        confidence += 0.2;
        break;
      }
    }
  }

  // Check deps
  for (const file of files.configs) {
    let content: string;
    try {
      content = fs.readFileSync(file.path, 'utf-8');
    } catch {
      continue;
    }

    if (content.includes('@modelcontextprotocol') || content.includes('"mcp"') || content.includes("'mcp'")) {
      evidence.push(`${file.relativePath}: depends on MCP SDK`);
      confidence += 0.3;
    }
  }

  if (confidence === 0) return null;

  return {
    framework: 'mcp',
    confidence: Math.min(confidence, 1),
    evidence,
    files: [...new Set(matchedFiles)],
  };
}
