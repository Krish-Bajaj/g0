import { describe, it, expect } from 'vitest';
import * as path from 'node:path';
import { walkDirectory } from '../../src/discovery/walker.js';
import { detectFrameworks } from '../../src/discovery/detector.js';

const FIXTURES = path.resolve(__dirname, '../fixtures');

describe('walkDirectory', () => {
  it('discovers files in a project', async () => {
    const inventory = await walkDirectory(path.join(FIXTURES, 'vulnerable-agent'));
    expect(inventory.python.length).toBeGreaterThan(0);
  });

  it('categorizes Python files', async () => {
    const inventory = await walkDirectory(path.join(FIXTURES, 'langchain-basic'));
    expect(inventory.python.length).toBeGreaterThan(0);
    expect(inventory.python[0].language).toBe('python');
  });

  it('discovers config files', async () => {
    const inventory = await walkDirectory(path.join(FIXTURES, 'mcp-server'));
    expect(inventory.configs.length + inventory.json.length).toBeGreaterThan(0);
  });
});

describe('detectFrameworks', () => {
  it('detects LangChain', async () => {
    const inventory = await walkDirectory(path.join(FIXTURES, 'langchain-basic'));
    const result = detectFrameworks(inventory);
    expect(result.primary).toBe('langchain');
  });

  it('detects CrewAI', async () => {
    const inventory = await walkDirectory(path.join(FIXTURES, 'crewai-crew'));
    const result = detectFrameworks(inventory);
    expect(result.primary).toBe('crewai');
  });

  it('detects MCP', async () => {
    const inventory = await walkDirectory(path.join(FIXTURES, 'mcp-server'));
    const result = detectFrameworks(inventory);
    expect(result.primary).toBe('mcp');
  });

  it('detects OpenAI', async () => {
    const inventory = await walkDirectory(path.join(FIXTURES, 'openai-assistant'));
    const result = detectFrameworks(inventory);
    expect(result.primary).toBe('openai');
  });
});
