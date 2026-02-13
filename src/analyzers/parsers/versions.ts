import * as fs from 'node:fs';
import type { FileInventory } from '../../types/common.js';
import type { FrameworkInfo } from '../../types/agent-graph.js';

const AI_FRAMEWORKS = new Set([
  'langchain', 'langchain-core', 'langchain-openai', 'langchain-anthropic',
  'langchain-community', 'langgraph',
  'crewai', 'crewai-tools',
  'openai',
  'anthropic',
  'mcp', 'fastmcp',
  'autogen', 'pyautogen',
  'transformers', 'torch', 'tensorflow',
  'chromadb', 'pinecone-client', 'faiss-cpu', 'faiss-gpu',
  'weaviate-client', 'qdrant-client', 'pymilvus',
  'pydantic', 'pydantic-ai',
  'llama-index', 'llamaindex',
  'huggingface-hub',
  'boto3', 'botocore',
  'google-generativeai', 'google-cloud-aiplatform',
  'cohere', 'replicate', 'together',
]);

const JS_AI_PACKAGES = new Set([
  'openai', '@openai/agents',
  'anthropic', '@anthropic-ai/sdk',
  'langchain', '@langchain/core', '@langchain/openai', '@langchain/anthropic',
  '@langchain/community', '@langchain/langgraph',
  '@modelcontextprotocol/sdk',
  'ai', '@ai-sdk/openai', '@ai-sdk/anthropic',
  'chromadb', '@pinecone-database/pinecone',
  '@qdrant/js-client-rest',
  'ollama',
  '@google/generative-ai',
  'cohere-ai',
]);

export function extractFrameworkVersions(files: FileInventory): FrameworkInfo[] {
  const versions: FrameworkInfo[] = [];

  for (const file of files.all) {
    const basename = file.relativePath.split('/').pop() ?? '';

    if (basename === 'requirements.txt' || basename === 'requirements-dev.txt') {
      versions.push(...parseRequirementsTxt(file.path, file.relativePath));
    } else if (basename === 'pyproject.toml') {
      versions.push(...parsePyprojectToml(file.path, file.relativePath));
    } else if (basename === 'package.json') {
      versions.push(...parsePackageJson(file.path, file.relativePath));
    }
  }

  return versions;
}

function parseRequirementsTxt(filePath: string, relativePath: string): FrameworkInfo[] {
  let content: string;
  try {
    content = fs.readFileSync(filePath, 'utf-8');
  } catch {
    return [];
  }

  const results: FrameworkInfo[] = [];
  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    // Match: package==1.0.0, package>=1.0.0, package~=1.0.0, package
    const match = trimmed.match(/^([a-zA-Z0-9_-]+)\s*(?:([=~<>!]+)\s*([^\s;,#]+))?/);
    if (!match) continue;

    const pkgName = match[1].toLowerCase();
    if (!AI_FRAMEWORKS.has(pkgName)) continue;

    results.push({
      name: pkgName,
      version: match[3] || undefined,
      file: relativePath,
    });
  }

  return results;
}

function parsePyprojectToml(filePath: string, relativePath: string): FrameworkInfo[] {
  let content: string;
  try {
    content = fs.readFileSync(filePath, 'utf-8');
  } catch {
    return [];
  }

  const results: FrameworkInfo[] = [];
  // Simple TOML dependency parsing - look for dependencies array entries
  const depPattern = /["']([a-zA-Z0-9_-]+)\s*(?:([=~<>!]+)\s*([^"'\s,\]]+))?["']/g;
  let match: RegExpExecArray | null;

  while ((match = depPattern.exec(content)) !== null) {
    const pkgName = match[1].toLowerCase();
    if (!AI_FRAMEWORKS.has(pkgName)) continue;

    results.push({
      name: pkgName,
      version: match[3] || undefined,
      file: relativePath,
    });
  }

  return results;
}

function parsePackageJson(filePath: string, relativePath: string): FrameworkInfo[] {
  let content: string;
  try {
    content = fs.readFileSync(filePath, 'utf-8');
  } catch {
    return [];
  }

  let parsed: Record<string, any>;
  try {
    parsed = JSON.parse(content);
  } catch {
    return [];
  }

  const results: FrameworkInfo[] = [];
  const allDeps = {
    ...parsed.dependencies,
    ...parsed.devDependencies,
  };

  for (const [name, version] of Object.entries(allDeps)) {
    if (!JS_AI_PACKAGES.has(name)) continue;
    results.push({
      name,
      version: typeof version === 'string' ? version.replace(/^[\^~>=<]/, '') : undefined,
      file: relativePath,
    });
  }

  return results;
}
