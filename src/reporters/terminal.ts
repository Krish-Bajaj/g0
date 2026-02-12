import chalk from 'chalk';
import type { ScanResult } from '../types/score.js';
import {
  printFinding,
  printDomainScores,
  printOverallScore,
  printSummary,
} from '../cli/ui.js';

export interface TerminalOptions {
  showBanner?: boolean;
}

export function reportTerminal(result: ScanResult, options?: TerminalOptions): void {
  const { findings, score, graph, duration } = result;

  // Header
  console.log(chalk.bold('\n  Scan Results'));
  console.log(chalk.dim('  ' + '─'.repeat(60)));
  console.log(`  ${chalk.dim('Path:')} ${graph.rootPath}`);
  console.log(`  ${chalk.dim('Framework:')} ${graph.primaryFramework}${graph.secondaryFrameworks.length > 0 ? ` (+${graph.secondaryFrameworks.join(', ')})` : ''}`);
  console.log(`  ${chalk.dim('Files scanned:')} ${graph.files.all.length}`);
  console.log(`  ${chalk.dim('Agents:')} ${graph.agents.length}  ${chalk.dim('Tools:')} ${graph.tools.length}  ${chalk.dim('Prompts:')} ${graph.prompts.length}`);
  console.log(`  ${chalk.dim('Duration:')} ${(duration / 1000).toFixed(1)}s`);

  // Findings by severity
  if (findings.length > 0) {
    console.log(chalk.bold('\n  Findings'));
    console.log(chalk.dim('  ' + '─'.repeat(60)));

    const sorted = [...findings].sort((a, b) => {
      const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      return order[a.severity] - order[b.severity];
    });

    for (let i = 0; i < sorted.length; i++) {
      printFinding(sorted[i], i);
    }
  } else {
    console.log(chalk.green.bold('\n  No security findings detected!'));
  }

  // Summary
  printSummary(findings);

  // Domain scores
  printDomainScores(score.domains);

  // Overall score
  printOverallScore(score);
  console.log('');
}
