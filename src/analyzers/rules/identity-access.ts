import * as fs from 'node:fs';
import * as path from 'node:path';
import type { Rule } from '../../types/control.js';
import type { Finding } from '../../types/finding.js';
import type { AgentGraph } from '../../types/agent-graph.js';
import {
  isTreeSitterAvailable,
  getFileTreeForLang,
  findFunctionCalls,
  findNodes,
} from '../ast/index.js';
import { findRouteHandlers } from '../ast/typescript.js';

const SECRET_PATTERNS = [
  { regex: /(?:^|["'\s=])sk-[a-zA-Z0-9_-]{20,}/g, name: 'OpenAI API key' },
  { regex: /(?:^|["'\s=])ghp_[a-zA-Z0-9]{36}/g, name: 'GitHub personal access token' },
  { regex: /(?:^|["'\s=])gho_[a-zA-Z0-9]{36}/g, name: 'GitHub OAuth token' },
  { regex: /(?:^|["'\s=])AKIA[0-9A-Z]{16}/g, name: 'AWS access key' },
  { regex: /(?:^|["'\s=])xox[bpsra]-[a-zA-Z0-9-]{10,}/g, name: 'Slack token' },
  { regex: /(?:^|["'\s=])glpat-[a-zA-Z0-9_-]{20,}/g, name: 'GitLab personal access token' },
  { regex: /(?:^|["'\s=])sk_live_[a-zA-Z0-9]{20,}/g, name: 'Stripe live key' },
  { regex: /(?:^|["'\s=])rk_live_[a-zA-Z0-9]{20,}/g, name: 'Stripe restricted key' },
  { regex: /(?:^|["'\s=])sq0atp-[a-zA-Z0-9_-]{22,}/g, name: 'Square access token' },
  { regex: /(?:^|["'\s=])SG\.[a-zA-Z0-9_-]{22,}/g, name: 'SendGrid API key' },
];

const HARDCODED_SECRET_PATTERNS = [
  { regex: /(?:api[_-]?key|apikey|secret|token|password|passwd|credential)\s*[:=]\s*["']([^"'\s]{8,})["']/gi, name: 'hardcoded credential' },
];

export const identityAccessRules: Rule[] = [
  {
    id: 'AA-IA-001',
    name: 'Hardcoded API key detected',
    domain: 'identity-access',
    severity: 'critical',
    confidence: 'high',
    description: 'API key or secret token is hardcoded in source code.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of graph.files.all) {
        if (file.language === 'other') continue;
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        for (const { regex, name } of SECRET_PATTERNS) {
          regex.lastIndex = 0;
          let match: RegExpExecArray | null;
          while ((match = regex.exec(content)) !== null) {
            const line = content.substring(0, match.index).split('\n').length;
            const snippet = match[0].trim().substring(0, 20) + '...';
            findings.push({
              id: `AA-IA-001-${findings.length}`,
              ruleId: 'AA-IA-001',
              title: `${name} detected in source code`,
              description: `${name} found hardcoded in ${file.relativePath}.`,
              severity: 'critical',
              confidence: 'high',
              domain: 'identity-access',
              location: { file: file.relativePath, line, snippet },
              remediation: 'Move secrets to environment variables or a secret manager. Never commit secrets to source code.',
              standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-002',
    name: 'Hardcoded credential in config',
    domain: 'identity-access',
    severity: 'critical',
    confidence: 'medium',
    description: 'Credential appears hardcoded in a configuration file.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.yaml, ...graph.files.json, ...graph.files.configs]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        for (const { regex, name } of HARDCODED_SECRET_PATTERNS) {
          regex.lastIndex = 0;
          let match: RegExpExecArray | null;
          while ((match = regex.exec(content)) !== null) {
            const value = match[1];
            if (/^(your[_-]|<|TODO|REPLACE|xxx|placeholder)/i.test(value)) continue;
            if (/^\$\{?[A-Z_]+\}?$/.test(value) || /^process\.env/.test(value)) continue;

            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-IA-002-${findings.length}`,
              ruleId: 'AA-IA-002',
              title: 'Hardcoded credential in config',
              description: `Possible ${name} found in ${file.relativePath}.`,
              severity: 'critical',
              confidence: 'medium',
              domain: 'identity-access',
              location: { file: file.relativePath, line },
              remediation: 'Use environment variables or a secret manager instead of hardcoding credentials.',
              standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-003',
    name: 'API key in prompt content',
    domain: 'identity-access',
    severity: 'critical',
    confidence: 'high',
    description: 'API key or secret found in prompt content, risking exposure to the LLM.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002', 'E001'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const prompt of graph.prompts) {
        if (prompt.hasSecrets) {
          findings.push({
            id: `AA-IA-003-${findings.length}`,
            ruleId: 'AA-IA-003',
            title: 'Secret detected in prompt content',
            description: `Prompt in ${prompt.file} contains what appears to be an API key or secret.`,
            severity: 'critical',
            confidence: 'high',
            domain: 'identity-access',
            location: { file: prompt.file, line: prompt.line },
            remediation: 'Never include API keys in prompts. Use server-side configuration instead.',
            standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002', 'E001'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-004',
    name: '.env file committed',
    domain: 'identity-access',
    severity: 'high',
    confidence: 'high',
    description: '.env file found in project, which may be committed to source control.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of graph.files.all) {
        const basename = path.basename(file.path);
        if (basename === '.env' || basename === '.env.local' || basename === '.env.production') {
          const gitignorePath = path.join(graph.rootPath, '.gitignore');
          let isIgnored = false;
          try {
            const gitignore = fs.readFileSync(gitignorePath, 'utf-8');
            isIgnored = gitignore.includes('.env');
          } catch {
            // No .gitignore found
          }

          if (!isIgnored) {
            findings.push({
              id: `AA-IA-004-${findings.length}`,
              ruleId: 'AA-IA-004',
              title: '.env file may be committed',
              description: `${basename} found and .gitignore does not exclude .env files.`,
              severity: 'high',
              confidence: 'high',
              domain: 'identity-access',
              location: { file: file.relativePath, line: 1 },
              remediation: 'Add .env to .gitignore and use .env.example for templates.',
              standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-005',
    name: 'Secrets in MCP config',
    domain: 'identity-access',
    severity: 'critical',
    confidence: 'high',
    description: 'Hardcoded secrets found in MCP configuration.',
    frameworks: ['mcp'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03', 'ASI04'], aiuc1: ['B002'], iso42001: ['A.6.3', 'A.7.3'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const config of graph.configs) {
        for (const secret of config.secrets) {
          if (secret.isHardcoded) {
            findings.push({
              id: `AA-IA-005-${findings.length}`,
              ruleId: 'AA-IA-005',
              title: 'Hardcoded secret in MCP config',
              description: `Secret "${secret.key}" is hardcoded in ${config.file}.`,
              severity: 'critical',
              confidence: 'high',
              domain: 'identity-access',
              location: { file: config.file, line: secret.line },
              remediation: 'Use environment variable references instead of hardcoded secrets in MCP config.',
              standards: { owaspAgentic: ['ASI03', 'ASI04'], aiuc1: ['B002'], iso42001: ['A.6.3', 'A.7.3'], nistAiRmf: ['MANAGE-2.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-006',
    name: 'No authentication on agent endpoint',
    domain: 'identity-access',
    severity: 'high',
    confidence: 'medium',
    description: 'Agent endpoint has no authentication middleware.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const astLang = file.language === 'python' ? 'python' as const
          : file.language === 'typescript' ? 'typescript' as const
          : file.language === 'javascript' ? 'javascript' as const : null;
        const tree = astLang && isTreeSitterAvailable() ? getFileTreeForLang(file.path, content, astLang) : null;

        if (tree) {
          const handlers = findRouteHandlers(tree);
          for (const { node, path: routePath } of handlers) {
            if (!/agent|chat|completion|invoke/i.test(routePath)) continue;

            const startLine = Math.max(0, node.startPosition.row - 10);
            const endLine = node.endPosition.row + 10;
            const lines = content.split('\n');
            const region = lines.slice(startLine, endLine).join('\n');
            const hasAuth = /auth|jwt|bearer|api[_-]?key|verify|session|middleware/i.test(region);

            if (node.type === 'decorator' && node.parent?.type === 'decorated_definition') {
              const siblings = node.parent.children.filter((c) => c.type === 'decorator');
              const hasAuthDecorator = siblings.some((d) =>
                /auth|login_required|require|protect|verify/i.test(d.text),
              );
              if (hasAuthDecorator) continue;
            }

            if (!hasAuth) {
              const line = node.startPosition.row + 1;
              findings.push({
                id: `AA-IA-006-${findings.length}`,
                ruleId: 'AA-IA-006',
                title: 'Agent endpoint without authentication',
                description: `Agent endpoint in ${file.relativePath} has no apparent authentication.`,
                severity: 'high',
                confidence: 'medium',
                domain: 'identity-access',
                location: { file: file.relativePath, line, snippet: node.text.substring(0, 60) },
                remediation: 'Add authentication middleware (JWT, API key, OAuth) to agent endpoints.',
                standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
              });
            }
          }
        } else {
          const endpointPatterns = [
            /app\.(post|get|put)\s*\(\s*["'].*(?:agent|chat|completion|invoke)/gi,
            /@app\.(?:post|get|route)\s*\(\s*["'].*(?:agent|chat|completion|invoke)/gi,
          ];

          for (const pattern of endpointPatterns) {
            pattern.lastIndex = 0;
            let match: RegExpExecArray | null;
            while ((match = pattern.exec(content)) !== null) {
              const region = content.substring(Math.max(0, match.index - 500), match.index + 500);
              const hasAuth = /auth|jwt|bearer|api[_-]?key|verify|session|middleware/i.test(region);

              if (!hasAuth) {
                const line = content.substring(0, match.index).split('\n').length;
                findings.push({
                  id: `AA-IA-006-${findings.length}`,
                  ruleId: 'AA-IA-006',
                  title: 'Agent endpoint without authentication',
                  description: `Agent endpoint in ${file.relativePath} has no apparent authentication.`,
                  severity: 'high',
                  confidence: 'medium',
                  domain: 'identity-access',
                  location: { file: file.relativePath, line, snippet: match[0] },
                  remediation: 'Add authentication middleware (JWT, API key, OAuth) to agent endpoints.',
                  standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
                });
              }
            }
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-007',
    name: 'Overly permissive CORS',
    domain: 'identity-access',
    severity: 'medium',
    confidence: 'high',
    description: 'CORS is configured to allow all origins.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const corsPatterns = [
          /cors\s*\(\s*\*\s*\)/gi,
          /allow_origins\s*=\s*\[\s*["']\*["']\s*\]/gi,
          /origin\s*:\s*["']\*["']/gi,
          /Access-Control-Allow-Origin.*\*/gi,
        ];

        for (const pattern of corsPatterns) {
          pattern.lastIndex = 0;
          let match: RegExpExecArray | null;
          while ((match = pattern.exec(content)) !== null) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-IA-007-${findings.length}`,
              ruleId: 'AA-IA-007',
              title: 'CORS allows all origins',
              description: `CORS configured with wildcard origin in ${file.relativePath}.`,
              severity: 'medium',
              confidence: 'high',
              domain: 'identity-access',
              location: { file: file.relativePath, line, snippet: match[0] },
              remediation: 'Restrict CORS to specific trusted origins.',
              standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-008',
    name: 'Secrets in environment variables without validation',
    domain: 'identity-access',
    severity: 'low',
    confidence: 'medium',
    description: 'Environment variables for secrets are used without validating they exist.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const unsafeEnvPattern = /os\.environ\s*\[\s*["']([A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD)[A-Z_]*)["']\s*\]/g;
        let match: RegExpExecArray | null;
        while ((match = unsafeEnvPattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-IA-008-${findings.length}`,
            ruleId: 'AA-IA-008',
            title: 'Environment secret accessed without fallback',
            description: `${match[1]} accessed via os.environ[] in ${file.relativePath} (will crash if missing).`,
            severity: 'low',
            confidence: 'medium',
            domain: 'identity-access',
            location: { file: file.relativePath, line, snippet: match[0] },
            remediation: 'Use os.getenv() with a default or validate env vars at startup.',
            standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-009',
    name: 'Private key file in repo',
    domain: 'identity-access',
    severity: 'critical',
    confidence: 'high',
    description: 'Private key file found in the repository, which may be committed to source control.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const privateKeyNames = ['id_rsa', 'id_ed25519'];
      const privateKeyExtensions = ['.pem', '.key'];
      for (const file of graph.files.all) {
        const basename = path.basename(file.path);
        const ext = path.extname(file.path);
        if (privateKeyNames.includes(basename) || privateKeyExtensions.includes(ext)) {
          findings.push({
            id: `AA-IA-009-${findings.length}`,
            ruleId: 'AA-IA-009',
            title: 'Private key file in repository',
            description: `Private key file "${basename}" found in ${file.relativePath}.`,
            severity: 'critical',
            confidence: 'high',
            domain: 'identity-access',
            location: { file: file.relativePath, line: 1 },
            remediation: 'Remove private key files from the repository and add them to .gitignore. Use a secret manager for key storage.',
            standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-010',
    name: 'JWT secret hardcoded',
    domain: 'identity-access',
    severity: 'critical',
    confidence: 'high',
    description: 'JWT signing or verification uses a hardcoded string literal as the secret.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001', 'B002'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const jwtPattern = /jwt\.(sign|verify|encode|decode)\s*\([^)]*["'][^"']{8,}["']/gi;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        jwtPattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = jwtPattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-IA-010-${findings.length}`,
            ruleId: 'AA-IA-010',
            title: 'JWT secret hardcoded',
            description: `JWT ${match[1]} uses a hardcoded secret in ${file.relativePath}.`,
            severity: 'critical',
            confidence: 'high',
            domain: 'identity-access',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Use environment variables or a secret manager for JWT secrets. Never hardcode signing keys.',
            standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001', 'B002'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-011',
    name: 'API key in URL/query string',
    domain: 'identity-access',
    severity: 'high',
    confidence: 'medium',
    description: 'API key or token passed in URL query string, which may be logged or cached.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const urlKeyPattern = /[?&](key|token|api_key|apikey)\s*=/gi;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        urlKeyPattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = urlKeyPattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-IA-011-${findings.length}`,
            ruleId: 'AA-IA-011',
            title: 'API key in URL query string',
            description: `API key/token passed in URL query parameter "${match[1]}" in ${file.relativePath}.`,
            severity: 'high',
            confidence: 'medium',
            domain: 'identity-access',
            location: { file: file.relativePath, line, snippet: match[0] },
            remediation: 'Pass API keys in request headers (e.g., Authorization header) instead of URL query parameters.',
            standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-012',
    name: 'Default/example credentials',
    domain: 'identity-access',
    severity: 'high',
    confidence: 'medium',
    description: 'Default or example credentials detected in source code.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const defaultCredPattern = /password\s*[:=]\s*["'](admin|password|test|123456|default|changeme|secret)["']/gi;
      for (const file of graph.files.all) {
        if (file.language === 'other') continue;
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        defaultCredPattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = defaultCredPattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-IA-012-${findings.length}`,
            ruleId: 'AA-IA-012',
            title: 'Default/example credentials detected',
            description: `Default credential value "${match[1]}" found in ${file.relativePath}.`,
            severity: 'high',
            confidence: 'medium',
            domain: 'identity-access',
            location: { file: file.relativePath, line, snippet: match[0] },
            remediation: 'Replace default credentials with strong, unique values. Use a secret manager for credential storage.',
            standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-013',
    name: 'Secrets in Docker/container config',
    domain: 'identity-access',
    severity: 'critical',
    confidence: 'high',
    description: 'Secrets are hardcoded in Docker or container configuration files.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const dockerEnvPattern = /ENV\s+\w*(SECRET|KEY|TOKEN|PASSWORD)\w*\s*=\s*\S+/gi;
      for (const file of graph.files.all) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        dockerEnvPattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = dockerEnvPattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-IA-013-${findings.length}`,
            ruleId: 'AA-IA-013',
            title: 'Secret in Docker/container config',
            description: `Hardcoded secret in ENV directive found in ${file.relativePath}.`,
            severity: 'critical',
            confidence: 'high',
            domain: 'identity-access',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Use Docker secrets, build args, or runtime environment variables instead of hardcoding secrets in Dockerfiles.',
            standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-014',
    name: 'Shared secrets across environments',
    domain: 'identity-access',
    severity: 'medium',
    confidence: 'medium',
    description: 'The same hardcoded secret value appears in multiple configuration files.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const secretValuePattern = /(?:api[_-]?key|secret|token|password|credential)\s*[:=]\s*["']([^"'\s]{8,})["']/gi;
      const valueToFiles: Map<string, { file: string; line: number }[]> = new Map();

      for (const file of [...graph.files.configs, ...graph.files.yaml, ...graph.files.json]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        secretValuePattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = secretValuePattern.exec(content)) !== null) {
          const value = match[1];
          if (/^(your[_-]|<|TODO|REPLACE|xxx|placeholder|\$\{)/i.test(value)) continue;
          const line = content.substring(0, match.index).split('\n').length;
          if (!valueToFiles.has(value)) {
            valueToFiles.set(value, []);
          }
          valueToFiles.get(value)!.push({ file: file.relativePath, line });
        }
      }

      for (const [_value, locations] of valueToFiles) {
        if (locations.length > 1) {
          const fileList = locations.map((l) => l.file).join(', ');
          findings.push({
            id: `AA-IA-014-${findings.length}`,
            ruleId: 'AA-IA-014',
            title: 'Shared secret across config files',
            description: `The same secret value appears in multiple files: ${fileList}.`,
            severity: 'medium',
            confidence: 'medium',
            domain: 'identity-access',
            location: { file: locations[0].file, line: locations[0].line },
            remediation: 'Use unique secrets per environment. Reference a centralized secret manager instead of duplicating values.',
            standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-015',
    name: 'Missing rate limiting on auth endpoints',
    domain: 'identity-access',
    severity: 'medium',
    confidence: 'medium',
    description: 'Authentication endpoints lack rate limiting, enabling brute-force attacks.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const authEndpointPattern = /(?:login|signin|sign_in|authenticate|auth)\s*[("'\/]/gi;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        authEndpointPattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = authEndpointPattern.exec(content)) !== null) {
          const start = Math.max(0, match.index - 500);
          const end = Math.min(content.length, match.index + 500);
          const region = content.substring(start, end);
          const hasRateLimit = /rate_limit|ratelimit|throttle|limiter/i.test(region);

          if (!hasRateLimit) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-IA-015-${findings.length}`,
              ruleId: 'AA-IA-015',
              title: 'Auth endpoint without rate limiting',
              description: `Authentication endpoint in ${file.relativePath} has no apparent rate limiting.`,
              severity: 'medium',
              confidence: 'medium',
              domain: 'identity-access',
              location: { file: file.relativePath, line, snippet: match[0] },
              remediation: 'Add rate limiting middleware to authentication endpoints to prevent brute-force attacks.',
              standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-016',
    name: 'OAuth without PKCE',
    domain: 'identity-access',
    severity: 'medium',
    confidence: 'medium',
    description: 'OAuth authorization code flow is used without PKCE (Proof Key for Code Exchange).',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const oauthPattern = /authorize.*response_type\s*=\s*code/gi;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        oauthPattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = oauthPattern.exec(content)) !== null) {
          const regionEnd = Math.min(content.length, match.index + match[0].length + 500);
          const region = content.substring(match.index, regionEnd);
          const hasPkce = /code_challenge|code_verifier/i.test(region);

          if (!hasPkce) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-IA-016-${findings.length}`,
              ruleId: 'AA-IA-016',
              title: 'OAuth without PKCE',
              description: `OAuth authorization code flow in ${file.relativePath} does not use PKCE.`,
              severity: 'medium',
              confidence: 'medium',
              domain: 'identity-access',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
              remediation: 'Implement PKCE (code_challenge and code_verifier) in OAuth authorization code flows.',
              standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-017',
    name: 'Bearer token logged',
    domain: 'identity-access',
    severity: 'high',
    confidence: 'medium',
    description: 'Bearer token or authorization header is being logged, risking credential exposure.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002', 'E003'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const tokenLogPattern = /(?:print|console\.log|logging\.\w+|logger\.\w+)\s*\(.*(?:authorization|bearer|auth.*header)/gi;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        tokenLogPattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = tokenLogPattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-IA-017-${findings.length}`,
            ruleId: 'AA-IA-017',
            title: 'Bearer token logged',
            description: `Authorization header or bearer token is being logged in ${file.relativePath}.`,
            severity: 'high',
            confidence: 'medium',
            domain: 'identity-access',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Never log authorization headers or bearer tokens. Redact sensitive values before logging.',
            standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002', 'E003'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-018',
    name: 'Credential in CLI argument',
    domain: 'identity-access',
    severity: 'critical',
    confidence: 'high',
    description: 'Credentials are passed as CLI arguments, which may appear in process listings and shell history.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const cliCredPattern = /--(?:api[_-]?key|password|secret|token)\s*[=\s]\s*[^\s"'$\\]+/gi;
      for (const file of graph.files.all) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        cliCredPattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = cliCredPattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-IA-018-${findings.length}`,
            ruleId: 'AA-IA-018',
            title: 'Credential in CLI argument',
            description: `Credential passed as CLI argument in ${file.relativePath}.`,
            severity: 'critical',
            confidence: 'high',
            domain: 'identity-access',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Use environment variables or config files instead of passing credentials as CLI arguments.',
            standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-019',
    name: 'Insecure token storage (localStorage)',
    domain: 'identity-access',
    severity: 'high',
    confidence: 'medium',
    description: 'Sensitive tokens are stored in localStorage, which is vulnerable to XSS attacks.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const localStoragePattern = /localStorage\.setItem\s*\(\s*["'][^"']*(?:token|key|secret|auth|session|jwt)[^"']*["']/gi;
      for (const file of [...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        localStoragePattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = localStoragePattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-IA-019-${findings.length}`,
            ruleId: 'AA-IA-019',
            title: 'Token stored in localStorage',
            description: `Sensitive token stored in localStorage in ${file.relativePath}.`,
            severity: 'high',
            confidence: 'medium',
            domain: 'identity-access',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Use httpOnly cookies or secure session storage instead of localStorage for sensitive tokens.',
            standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-020',
    name: 'Missing API key scope restriction',
    domain: 'identity-access',
    severity: 'medium',
    confidence: 'low',
    description: 'OpenAI or Anthropic API key is used without organization or project scope restriction.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002', 'B003'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const unscopedKeyPattern = /(?:openai|anthropic).*api[_-]?key(?!.*(?:org|project|scope))/gi;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        unscopedKeyPattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = unscopedKeyPattern.exec(content)) !== null) {
          // Skip if the key is loaded from environment variable (proper pattern)
          const lineStart = content.lastIndexOf('\n', match.index) + 1;
          const lineEnd = content.indexOf('\n', match.index);
          const matchLine = content.substring(lineStart, lineEnd !== -1 ? lineEnd : undefined);
          if (/os\.getenv|os\.environ|process\.env|getenv|environ\.get/.test(matchLine)) continue;

          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-IA-020-${findings.length}`,
            ruleId: 'AA-IA-020',
            title: 'API key without scope restriction',
            description: `API key usage in ${file.relativePath} lacks organization or project scoping.`,
            severity: 'medium',
            confidence: 'low',
            domain: 'identity-access',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Use organization-scoped or project-scoped API keys to limit access. Configure org/project IDs alongside API keys.',
            standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002', 'B003'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
          });
        }
      }
      return findings;
    },
  },
];
