import * as fs from 'node:fs';
import type { Rule } from '../../types/control.js';
import type { Finding } from '../../types/finding.js';
import type { AgentGraph } from '../../types/agent-graph.js';

export const supplyChainRules: Rule[] = [
  {
    id: 'AA-SC-001',
    name: 'Unpinned Python dependencies',
    domain: 'supply-chain',
    severity: 'medium',
    confidence: 'high',
    description: 'Python dependencies are not pinned to specific versions.',
    frameworks: ['all'],
    owaspAgentic: ['ASI04'],
    standards: { owaspAgentic: ['ASI04'], aiuc1: ['C001'], iso42001: ['A.7.3'], nistAiRmf: ['MAP-3.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of graph.files.configs) {
        const basename = file.relativePath.split('/').pop() ?? '';
        if (basename !== 'requirements.txt') continue;

        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i].trim();
          if (!line || line.startsWith('#') || line.startsWith('-')) continue;

          // No version pin (e.g., "langchain" without ==, >=, ~=)
          if (/^[a-zA-Z0-9_-]+\s*$/.test(line)) {
            findings.push({
              id: `AA-SC-001-${findings.length}`,
              ruleId: 'AA-SC-001',
              title: 'Unpinned Python dependency',
              description: `Dependency "${line}" in ${file.relativePath} has no version pin.`,
              severity: 'medium',
              confidence: 'high',
              domain: 'supply-chain',
              location: { file: file.relativePath, line: i + 1, snippet: line },
              remediation: `Pin the dependency to a specific version: ${line}==x.y.z`,
              standards: { owaspAgentic: ['ASI04'], aiuc1: ['C001'], iso42001: ['A.7.3'], nistAiRmf: ['MAP-3.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-SC-002',
    name: 'Unpinned npm dependencies',
    domain: 'supply-chain',
    severity: 'medium',
    confidence: 'high',
    description: 'npm dependencies use loose version ranges.',
    frameworks: ['all'],
    owaspAgentic: ['ASI04'],
    standards: { owaspAgentic: ['ASI04'], aiuc1: ['C001'], iso42001: ['A.7.3'], nistAiRmf: ['MAP-3.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of graph.files.configs) {
        const basename = file.relativePath.split('/').pop() ?? '';
        if (basename !== 'package.json') continue;

        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        let pkg: any;
        try {
          pkg = JSON.parse(content);
        } catch {
          continue;
        }

        const deps = { ...pkg.dependencies, ...pkg.devDependencies };
        for (const [name, version] of Object.entries(deps)) {
          if (typeof version !== 'string') continue;
          // Flag * or latest
          if (version === '*' || version === 'latest') {
            const line = findKeyLine(content, name);
            findings.push({
              id: `AA-SC-002-${findings.length}`,
              ruleId: 'AA-SC-002',
              title: 'Unpinned npm dependency',
              description: `Dependency "${name}" in ${file.relativePath} uses "${version}".`,
              severity: 'medium',
              confidence: 'high',
              domain: 'supply-chain',
              location: { file: file.relativePath, line, snippet: `"${name}": "${version}"` },
              remediation: `Pin ${name} to a specific version range.`,
              standards: { owaspAgentic: ['ASI04'], aiuc1: ['C001'], iso42001: ['A.7.3'], nistAiRmf: ['MAP-3.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-SC-003',
    name: 'Unverified MCP server',
    domain: 'supply-chain',
    severity: 'high',
    confidence: 'medium',
    description: 'MCP server used without version pinning or verification.',
    frameworks: ['mcp'],
    owaspAgentic: ['ASI04'],
    standards: { owaspAgentic: ['ASI04'], aiuc1: ['C001', 'C002'], iso42001: ['A.7.2', 'A.7.3'], nistAiRmf: ['MAP-3.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const config of graph.configs) {
        for (const issue of config.issues) {
          if (issue.type === 'unpinned-mcp-server') {
            findings.push({
              id: `AA-SC-003-${findings.length}`,
              ruleId: 'AA-SC-003',
              title: 'Unpinned MCP server package',
              description: issue.message,
              severity: 'high',
              confidence: 'medium',
              domain: 'supply-chain',
              location: { file: config.file, line: issue.line },
              remediation: 'Pin MCP server packages to specific versions (e.g., package@1.2.3).',
              standards: { owaspAgentic: ['ASI04'], aiuc1: ['C001', 'C002'], iso42001: ['A.7.2', 'A.7.3'], nistAiRmf: ['MAP-3.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-SC-004',
    name: 'npx -y without version pinning',
    domain: 'supply-chain',
    severity: 'high',
    confidence: 'high',
    description: 'npx -y auto-installs packages without version pinning.',
    frameworks: ['mcp'],
    owaspAgentic: ['ASI04'],
    standards: { owaspAgentic: ['ASI04'], aiuc1: ['C001', 'C002'], iso42001: ['A.7.3'], nistAiRmf: ['MAP-3.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const config of graph.configs) {
        for (const issue of config.issues) {
          if (issue.type === 'npx-auto-install') {
            findings.push({
              id: `AA-SC-004-${findings.length}`,
              ruleId: 'AA-SC-004',
              title: 'npx -y auto-install without version pin',
              description: issue.message,
              severity: 'high',
              confidence: 'high',
              domain: 'supply-chain',
              location: { file: config.file, line: issue.line },
              remediation: 'Pin package versions when using npx (e.g., npx package@1.2.3).',
              standards: { owaspAgentic: ['ASI04'], aiuc1: ['C001', 'C002'], iso42001: ['A.7.3'], nistAiRmf: ['MAP-3.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-SC-005',
    name: 'pip install from URL',
    domain: 'supply-chain',
    severity: 'high',
    confidence: 'high',
    description: 'Package installed from URL without hash verification.',
    frameworks: ['all'],
    owaspAgentic: ['ASI04'],
    standards: { owaspAgentic: ['ASI04'], aiuc1: ['C001', 'C002'], iso42001: ['A.7.3'], nistAiRmf: ['MAP-3.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of graph.files.configs) {
        const basename = file.relativePath.split('/').pop() ?? '';
        if (basename !== 'requirements.txt') continue;

        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i].trim();
          if (/^(https?:|git\+|git:)/.test(line) && !line.includes('--hash')) {
            findings.push({
              id: `AA-SC-005-${findings.length}`,
              ruleId: 'AA-SC-005',
              title: 'Package installed from URL without hash',
              description: `Dependency from URL in ${file.relativePath} without hash verification.`,
              severity: 'high',
              confidence: 'high',
              domain: 'supply-chain',
              location: { file: file.relativePath, line: i + 1, snippet: line.substring(0, 80) },
              remediation: 'Add --hash verification or use pinned package registry versions.',
              standards: { owaspAgentic: ['ASI04'], aiuc1: ['C001', 'C002'], iso42001: ['A.7.3'], nistAiRmf: ['MAP-3.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-SC-006',
    name: 'Unverified MCP server',
    domain: 'supply-chain',
    severity: 'high',
    confidence: 'medium',
    description: 'MCP server package is not from the official @modelcontextprotocol scope, increasing supply chain risk.',
    frameworks: ['mcp'],
    owaspAgentic: ['ASI04'],
    standards: { owaspAgentic: ['ASI04'], aiuc1: ['C001', 'C002'], iso42001: ['A.7.2', 'A.7.3'], nistAiRmf: ['MAP-3.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.configs, ...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const mcpServerPattern = /"command"\s*:\s*"npx"\s*,\s*"args"\s*:\s*\[([^\]]*)\]/g;
        let match: RegExpExecArray | null;
        while ((match = mcpServerPattern.exec(content)) !== null) {
          const args = match[1];
          if (args && !/@modelcontextprotocol\//.test(args)) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-SC-006-${findings.length}`,
              ruleId: 'AA-SC-006',
              title: 'Unverified MCP server package',
              description: `MCP server in ${file.relativePath} uses a package not from @modelcontextprotocol scope.`,
              severity: 'high',
              confidence: 'medium',
              domain: 'supply-chain',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 80) },
              remediation: 'Use verified MCP servers from the @modelcontextprotocol scope or audit third-party servers.',
              standards: { owaspAgentic: ['ASI04'], aiuc1: ['C001', 'C002'], iso42001: ['A.7.2', 'A.7.3'], nistAiRmf: ['MAP-3.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-SC-007',
    name: 'Git URL dependency',
    domain: 'supply-chain',
    severity: 'medium',
    confidence: 'high',
    description: 'Dependency installed from a Git URL, bypassing package registry integrity checks.',
    frameworks: ['all'],
    owaspAgentic: ['ASI04'],
    standards: { owaspAgentic: ['ASI04'], aiuc1: ['C001', 'C002'], iso42001: ['A.7.3'], nistAiRmf: ['MAP-3.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of graph.files.configs) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const basename = file.relativePath.split('/').pop() ?? '';

        // Check requirements.txt for git URLs
        if (basename === 'requirements.txt') {
          const lines = content.split('\n');
          for (let i = 0; i < lines.length; i++) {
            const line = lines[i].trim();
            if (/git\+(?:ssh|https?):\/\//.test(line) || /^git:\/\//.test(line)) {
              findings.push({
                id: `AA-SC-007-${findings.length}`,
                ruleId: 'AA-SC-007',
                title: 'Git URL dependency',
                description: `Dependency in ${file.relativePath} is installed from a Git URL, bypassing registry checks.`,
                severity: 'medium',
                confidence: 'high',
                domain: 'supply-chain',
                location: { file: file.relativePath, line: i + 1, snippet: line.substring(0, 80) },
                remediation: 'Use pinned package registry versions instead of Git URLs. If Git URLs are required, pin to a specific commit hash.',
                standards: { owaspAgentic: ['ASI04'], aiuc1: ['C001', 'C002'], iso42001: ['A.7.3'], nistAiRmf: ['MAP-3.1'] },
              });
            }
          }
        }

        // Check package.json for git URL dependencies
        if (basename === 'package.json') {
          let pkg: any;
          try {
            pkg = JSON.parse(content);
          } catch {
            continue;
          }

          const deps = { ...pkg.dependencies, ...pkg.devDependencies };
          for (const [name, version] of Object.entries(deps)) {
            if (typeof version !== 'string') continue;
            if (/git\+(?:ssh|https?):\/\//.test(version) || /^git:\/\//.test(version)) {
              const line = findKeyLine(content, name);
              findings.push({
                id: `AA-SC-007-${findings.length}`,
                ruleId: 'AA-SC-007',
                title: 'Git URL dependency',
                description: `Dependency "${name}" in ${file.relativePath} is installed from a Git URL.`,
                severity: 'medium',
                confidence: 'high',
                domain: 'supply-chain',
                location: { file: file.relativePath, line, snippet: `"${name}": "${version}"` },
                remediation: 'Use pinned package registry versions instead of Git URLs. If Git URLs are required, pin to a specific commit hash.',
                standards: { owaspAgentic: ['ASI04'], aiuc1: ['C001', 'C002'], iso42001: ['A.7.3'], nistAiRmf: ['MAP-3.1'] },
              });
            }
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-SC-008',
    name: 'Missing lockfile',
    domain: 'supply-chain',
    severity: 'medium',
    confidence: 'medium',
    description: 'Project has a dependency manifest but no lockfile, making builds non-deterministic.',
    frameworks: ['all'],
    owaspAgentic: ['ASI04'],
    standards: { owaspAgentic: ['ASI04'], aiuc1: ['C001'], iso42001: ['A.7.3'], nistAiRmf: ['MAP-3.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const configNames = graph.files.configs.map((f) => f.relativePath.split('/').pop() ?? '');

      const hasPackageJson = configNames.includes('package.json');
      const hasNpmLock = configNames.includes('package-lock.json') ||
        configNames.includes('yarn.lock') ||
        configNames.includes('pnpm-lock.yaml');

      const hasRequirements = configNames.includes('requirements.txt');
      const hasPipLock = configNames.includes('Pipfile.lock') || configNames.includes('poetry.lock') || configNames.includes('uv.lock');

      if (hasPackageJson && !hasNpmLock) {
        const pkgFile = graph.files.configs.find((f) => (f.relativePath.split('/').pop() ?? '') === 'package.json');
        findings.push({
          id: `AA-SC-008-${findings.length}`,
          ruleId: 'AA-SC-008',
          title: 'Missing lockfile for npm project',
          description: `package.json found but no lockfile (package-lock.json, yarn.lock, or pnpm-lock.yaml) detected.`,
          severity: 'medium',
          confidence: 'medium',
          domain: 'supply-chain',
          location: { file: pkgFile?.relativePath ?? 'package.json', line: 1 },
          remediation: 'Run npm install, yarn install, or pnpm install to generate a lockfile and commit it to version control.',
          standards: { owaspAgentic: ['ASI04'], aiuc1: ['C001'], iso42001: ['A.7.3'], nistAiRmf: ['MAP-3.1'] },
        });
      }

      if (hasRequirements && !hasPipLock) {
        // Only flag if requirements.txt has unpinned dependencies (no == version pinning)
        const reqFile = graph.files.configs.find((f) => (f.relativePath.split('/').pop() ?? '') === 'requirements.txt');
        let hasUnpinned = false;
        if (reqFile) {
          try {
            const reqContent = fs.readFileSync(reqFile.path, 'utf-8');
            const depLines = reqContent.split('\n').filter(l => l.trim() && !l.trim().startsWith('#') && !l.trim().startsWith('-'));
            hasUnpinned = depLines.some(l => !l.includes('=='));
          } catch { /* ignore */ }
        }
        if (hasUnpinned) {
          findings.push({
            id: `AA-SC-008-${findings.length}`,
            ruleId: 'AA-SC-008',
            title: 'Missing lockfile for Python project',
            description: `requirements.txt found with unpinned dependencies but no lockfile (Pipfile.lock or poetry.lock) detected.`,
            severity: 'medium',
            confidence: 'medium',
            domain: 'supply-chain',
            location: { file: reqFile?.relativePath ?? 'requirements.txt', line: 1 },
            remediation: 'Use pip-tools (pip-compile), Pipenv, or Poetry to generate a lockfile with pinned transitive dependencies.',
            standards: { owaspAgentic: ['ASI04'], aiuc1: ['C001'], iso42001: ['A.7.3'], nistAiRmf: ['MAP-3.1'] },
          });
        }
      }

      return findings;
    },
  },
  {
    id: 'AA-SC-009',
    name: 'Model loaded from URL',
    domain: 'supply-chain',
    severity: 'high',
    confidence: 'medium',
    description: 'ML model is loaded directly from a URL without integrity verification.',
    frameworks: ['all'],
    owaspAgentic: ['ASI04'],
    standards: { owaspAgentic: ['ASI04'], aiuc1: ['C002'], iso42001: ['A.7.2'], nistAiRmf: ['MAP-3.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const modelUrlPatterns = [
          { regex: /from_pretrained\s*\(\s*["']https?:/g, name: 'from_pretrained() with URL' },
          { regex: /torch\.hub\.load\s*\(/g, name: 'torch.hub.load()' },
          { regex: /wget\s+.*\.(?:bin|pt|safetensors|gguf)/g, name: 'wget model download' },
        ];

        for (const { regex, name } of modelUrlPatterns) {
          regex.lastIndex = 0;
          let match: RegExpExecArray | null;
          while ((match = regex.exec(content)) !== null) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-SC-009-${findings.length}`,
              ruleId: 'AA-SC-009',
              title: 'Model loaded from URL',
              description: `${name} in ${file.relativePath} loads a model from a URL without integrity verification.`,
              severity: 'high',
              confidence: 'medium',
              domain: 'supply-chain',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 80) },
              remediation: 'Verify model integrity with checksums or use a trusted model registry with pinned versions.',
              standards: { owaspAgentic: ['ASI04'], aiuc1: ['C002'], iso42001: ['A.7.2'], nistAiRmf: ['MAP-3.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-SC-010',
    name: 'Typosquat risk in AI packages',
    domain: 'supply-chain',
    severity: 'medium',
    confidence: 'medium',
    description: 'Dependency name matches a known typosquat of a popular AI package.',
    frameworks: ['all'],
    owaspAgentic: ['ASI04'],
    standards: { owaspAgentic: ['ASI04'], aiuc1: ['C001'], iso42001: ['A.7.3'], nistAiRmf: ['MAP-3.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const typosquats: Record<string, string> = {
        'langchin': 'langchain',
        'langchian': 'langchain',
        'lanchain': 'langchain',
        'openai-api': 'openai',
        'antropic': 'anthropic',
        'crew-ai': 'crewai',
      };

      for (const file of graph.files.configs) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const basename = file.relativePath.split('/').pop() ?? '';

        if (basename === 'requirements.txt') {
          const lines = content.split('\n');
          for (let i = 0; i < lines.length; i++) {
            const line = lines[i].trim();
            if (!line || line.startsWith('#') || line.startsWith('-')) continue;
            const pkgName = line.split(/[=<>~!]/)[0].trim().toLowerCase();
            if (typosquats[pkgName]) {
              findings.push({
                id: `AA-SC-010-${findings.length}`,
                ruleId: 'AA-SC-010',
                title: 'Potential typosquat package',
                description: `Package "${pkgName}" in ${file.relativePath} may be a typosquat of "${typosquats[pkgName]}".`,
                severity: 'medium',
                confidence: 'medium',
                domain: 'supply-chain',
                location: { file: file.relativePath, line: i + 1, snippet: line },
                remediation: `Verify the package name. Did you mean "${typosquats[pkgName]}"?`,
                standards: { owaspAgentic: ['ASI04'], aiuc1: ['C001'], iso42001: ['A.7.3'], nistAiRmf: ['MAP-3.1'] },
              });
            }
          }
        }

        if (basename === 'package.json') {
          let pkg: any;
          try {
            pkg = JSON.parse(content);
          } catch {
            continue;
          }

          const deps = { ...pkg.dependencies, ...pkg.devDependencies };
          for (const [name] of Object.entries(deps)) {
            const lower = name.toLowerCase();
            if (typosquats[lower]) {
              const line = findKeyLine(content, name);
              findings.push({
                id: `AA-SC-010-${findings.length}`,
                ruleId: 'AA-SC-010',
                title: 'Potential typosquat package',
                description: `Package "${name}" in ${file.relativePath} may be a typosquat of "${typosquats[lower]}".`,
                severity: 'medium',
                confidence: 'medium',
                domain: 'supply-chain',
                location: { file: file.relativePath, line, snippet: `"${name}"` },
                remediation: `Verify the package name. Did you mean "${typosquats[lower]}"?`,
                standards: { owaspAgentic: ['ASI04'], aiuc1: ['C001'], iso42001: ['A.7.3'], nistAiRmf: ['MAP-3.1'] },
              });
            }
          }
        }
      }
      return findings;
    },
  },
];

function findKeyLine(content: string, key: string): number {
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].includes(`"${key}"`)) return i + 1;
  }
  return 1;
}
