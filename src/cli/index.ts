import { Command } from 'commander';
import { printBanner, getVersion } from './branding.js';
import { scanCommand } from './commands/scan.js';
import { initCommand } from './commands/init.js';
import { gateCommand } from './commands/gate.js';

export function createCli(): Command {
  const program = new Command();

  program
    .name('g0')
    .description('AI Agent Security Scanner — the Snyk for AI agents')
    .version(getVersion())
    .hook('preAction', (thisCommand, actionCommand) => {
      const opts = actionCommand.opts();
      // Suppress banner for machine-readable outputs
      if (opts.json || opts.sarif || opts.quiet || opts.banner === false) return;
      printBanner();
    });

  program.addCommand(scanCommand);
  program.addCommand(initCommand);
  program.addCommand(gateCommand);

  return program;
}
