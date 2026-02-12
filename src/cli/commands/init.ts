import * as fs from 'node:fs';
import * as path from 'node:path';
import { Command } from 'commander';
import chalk from 'chalk';

const DEFAULT_CONFIG = `# g0 Configuration
# See: https://github.com/guard0-ai/g0

# Minimum score to pass CI/CD gate (0-100)
min_score: 70

# Minimum grade to pass (A, B, C, D, F)
# min_grade: C

# Severity threshold - fail if any finding at or above this level
# fail_on: critical

# Exclude specific rules
# exclude_rules:
#   - AA-DL-001  # verbose=True (acceptable in dev)

# Exclude paths from scanning
# exclude_paths:
#   - tests/
#   - docs/
#   - examples/

# Include beta rules (higher false positive rate)
# include_beta: false
`;

export const initCommand = new Command('init')
  .description('Initialize g0 configuration file')
  .option('-f, --force', 'Overwrite existing config')
  .action((options: { force?: boolean }) => {
    const configPath = path.join(process.cwd(), '.g0.yaml');

    if (fs.existsSync(configPath) && !options.force) {
      console.log(chalk.yellow('Config file already exists: .g0.yaml'));
      console.log(chalk.dim('Use --force to overwrite'));
      return;
    }

    fs.writeFileSync(configPath, DEFAULT_CONFIG, 'utf-8');
    console.log(chalk.green('Created .g0.yaml'));
    console.log(chalk.dim('Run `g0 scan` to scan your project'));
  });
