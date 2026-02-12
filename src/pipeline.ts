import * as path from 'node:path';
import type { ScanResult } from './types/score.js';
import type { G0Config } from './types/config.js';
import type { Severity } from './types/common.js';
import { walkDirectory } from './discovery/walker.js';
import { detectFrameworks } from './discovery/detector.js';
import { buildAgentGraph } from './discovery/graph.js';
import { runAnalysis } from './analyzers/engine.js';
import { calculateScore } from './scoring/engine.js';
import { clearASTCache } from './analyzers/ast/index.js';

export interface ScanOptions {
  targetPath: string;
  config?: G0Config;
  severity?: Severity;
  rules?: string[];
  excludeRules?: string[];
  frameworks?: string[];
}

export async function runScan(options: ScanOptions): Promise<ScanResult> {
  const startTime = Date.now();
  const rootPath = path.resolve(options.targetPath);

  // Merge config exclude_rules with CLI excludeRules
  const excludeRules = new Set<string>([
    ...(options.config?.exclude_rules ?? []),
    ...(options.excludeRules ?? []),
  ]);

  const excludePaths = options.config?.exclude_paths ?? [];

  // Clear AST cache from previous scans
  clearASTCache();

  // Step 1: Discovery — walk files
  const files = await walkDirectory(rootPath, excludePaths);

  // Step 2: Detect frameworks
  const detection = detectFrameworks(files);

  // Step 3: Build agent graph (includes parsing)
  const graph = buildAgentGraph(rootPath, files, detection);

  // Step 4: Run analysis rules
  const findings = runAnalysis(graph, {
    excludeRules: excludeRules.size > 0 ? [...excludeRules] : undefined,
    onlyRules: options.rules,
    severity: options.severity,
    frameworks: options.frameworks,
  });

  // Step 5: Calculate score
  const score = calculateScore(findings);

  const duration = Date.now() - startTime;

  return {
    score,
    findings,
    graph,
    duration,
    timestamp: new Date().toISOString(),
  };
}
