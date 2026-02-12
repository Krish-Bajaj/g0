import * as path from 'node:path';
import * as fs from 'node:fs';
import { Command } from 'commander';
import { runScan } from '../../pipeline.js';
import { reportTerminal } from '../../reporters/terminal.js';
import { reportJson } from '../../reporters/json.js';
import { reportHtml } from '../../reporters/html.js';
import { reportSarif } from '../../reporters/sarif.js';
import { loadConfig } from '../../config/loader.js';
import { createSpinner } from '../ui.js';
import type { Severity } from '../../types/common.js';

export const scanCommand = new Command('scan')
  .description('Scan an AI agent project for security issues')
  .argument('[path]', 'Path to the agent project', '.')
  .option('--json', 'Output as JSON')
  .option('--html [file]', 'Output as HTML report')
  .option('--sarif [file]', 'Output as SARIF 2.1.0')
  .option('-o, --output <file>', 'Write JSON output to file')
  .option('-q, --quiet', 'Suppress terminal output')
  .option('--severity <level>', 'Minimum severity to report (critical|high|medium|low)')
  .option('--config <file>', 'Path to config file (default: .g0.yaml)')
  .option('--rules <ids>', 'Only run specific rules (comma-separated)')
  .option('--exclude-rules <ids>', 'Skip specific rules (comma-separated)')
  .option('--frameworks <ids>', 'Only check specific frameworks (comma-separated)')
  .option('--no-banner', 'Suppress the g0 banner')
  .action(async (targetPath: string, options: {
    json?: boolean;
    html?: string | boolean;
    sarif?: string | boolean;
    output?: string;
    quiet?: boolean;
    severity?: string;
    config?: string;
    rules?: string;
    excludeRules?: string;
    frameworks?: string;
    banner?: boolean;
  }) => {
    const resolvedPath = path.resolve(targetPath);

    if (!fs.existsSync(resolvedPath)) {
      console.error(`Error: Path does not exist: ${resolvedPath}`);
      process.exit(1);
    }

    // Load config
    let config;
    try {
      config = loadConfig(resolvedPath, options.config) ?? undefined;
    } catch (err) {
      console.error(`Config error: ${err instanceof Error ? err.message : err}`);
      process.exit(1);
    }

    const spinner = options.quiet ? null : createSpinner('Scanning agent project...');
    spinner?.start();

    try {
      const result = await runScan({
        targetPath: resolvedPath,
        config,
        severity: options.severity as Severity | undefined,
        rules: options.rules?.split(',').map(s => s.trim()),
        excludeRules: options.excludeRules?.split(',').map(s => s.trim()),
        frameworks: options.frameworks?.split(',').map(s => s.trim()),
      });
      spinner?.stop();

      if (options.sarif) {
        const sarifPath = typeof options.sarif === 'string'
          ? options.sarif
          : undefined;
        const sarif = reportSarif(result, sarifPath);
        if (!sarifPath) {
          console.log(sarif);
        } else if (!options.quiet) {
          console.log(`SARIF report written to: ${sarifPath}`);
        }
      } else if (options.json) {
        const json = reportJson(result, options.output);
        if (!options.output) {
          console.log(json);
        }
      } else if (options.html) {
        const htmlPath = typeof options.html === 'string'
          ? options.html
          : path.join(resolvedPath, 'g0-report.html');
        reportHtml(result, htmlPath);
        if (!options.quiet) {
          console.log(`HTML report written to: ${htmlPath}`);
        }
      } else {
        reportTerminal(result, { showBanner: options.banner !== false });
      }

      // Also write JSON if --output specified alongside terminal
      if (options.output && !options.json) {
        reportJson(result, options.output);
      }
    } catch (error) {
      spinner?.stop();
      console.error('Scan failed:', error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });
