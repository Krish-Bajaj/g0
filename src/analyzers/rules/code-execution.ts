import * as fs from 'node:fs';
import type { Rule } from '../../types/control.js';
import type { Finding } from '../../types/finding.js';
import type { AgentGraph } from '../../types/agent-graph.js';
import {
  isTreeSitterAvailable,
  getFileTreeForLang,
  findFunctionCalls,
  getCallArgument,
} from '../ast/index.js';

export const codeExecutionRules: Rule[] = [
  {
    id: 'AA-CE-001',
    name: 'eval() with dynamic input',
    domain: 'code-execution',
    severity: 'critical',
    confidence: 'high',
    description: 'eval() used with potentially user-controlled input.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001', 'D002'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
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
          const evalCalls = findFunctionCalls(tree, 'eval');
          for (const call of evalCalls) {
            const arg = getCallArgument(call, 0);
            if (arg && (arg.type === 'string' || arg.type === 'string_literal')) continue;

            const line = call.startPosition.row + 1;
            const snippet = call.text.substring(0, 60);
            findings.push({
              id: `AA-CE-001-${findings.length}`,
              ruleId: 'AA-CE-001',
              title: 'eval() with dynamic input',
              description: `eval() in ${file.relativePath} uses dynamic input that may be user-controlled.`,
              severity: 'critical',
              confidence: 'high',
              domain: 'code-execution',
              location: { file: file.relativePath, line, snippet },
              remediation: 'Remove eval() usage. Use safe alternatives like JSON.parse() or ast.literal_eval().',
              standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001', 'D002'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
            });
          }
        } else {
          const evalPattern = /\beval\s*\(/g;
          let match: RegExpExecArray | null;
          while ((match = evalPattern.exec(content)) !== null) {
            const line = content.substring(0, match.index).split('\n').length;
            const region = content.substring(match.index, match.index + 200);
            const hasVariable = !/^eval\s*\(\s*["'`]/.test(region);

            if (hasVariable) {
              findings.push({
                id: `AA-CE-001-${findings.length}`,
                ruleId: 'AA-CE-001',
                title: 'eval() with dynamic input',
                description: `eval() in ${file.relativePath} uses dynamic input that may be user-controlled.`,
                severity: 'critical',
                confidence: 'high',
                domain: 'code-execution',
                location: { file: file.relativePath, line, snippet: region.substring(0, 60) },
                remediation: 'Remove eval() usage. Use safe alternatives like JSON.parse() or ast.literal_eval().',
                standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001', 'D002'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
              });
            }
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-002',
    name: 'exec() with dynamic input',
    domain: 'code-execution',
    severity: 'critical',
    confidence: 'high',
    description: 'exec() used with potentially user-controlled input (Python).',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001', 'D002'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of graph.files.python) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const tree = isTreeSitterAvailable() ? getFileTreeForLang(file.path, content, 'python') : null;

        if (tree) {
          const execCalls = findFunctionCalls(tree, 'exec');
          for (const call of execCalls) {
            const arg = getCallArgument(call, 0);
            if (arg && (arg.type === 'string' || arg.type === 'string_literal')) continue;

            const line = call.startPosition.row + 1;
            const snippet = call.text.substring(0, 60);
            findings.push({
              id: `AA-CE-002-${findings.length}`,
              ruleId: 'AA-CE-002',
              title: 'exec() with dynamic input',
              description: `exec() in ${file.relativePath} uses dynamic input that may be user-controlled.`,
              severity: 'critical',
              confidence: 'high',
              domain: 'code-execution',
              location: { file: file.relativePath, line, snippet },
              remediation: 'Remove exec() usage. Use safe alternatives or sandboxed code execution.',
              standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001', 'D002'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
            });
          }
        } else {
          const execPattern = /\bexec\s*\(/g;
          let match: RegExpExecArray | null;
          while ((match = execPattern.exec(content)) !== null) {
            const line = content.substring(0, match.index).split('\n').length;
            const region = content.substring(match.index, match.index + 200);
            const hasVariable = !/^exec\s*\(\s*["']/.test(region);

            if (hasVariable) {
              findings.push({
                id: `AA-CE-002-${findings.length}`,
                ruleId: 'AA-CE-002',
                title: 'exec() with dynamic input',
                description: `exec() in ${file.relativePath} uses dynamic input that may be user-controlled.`,
                severity: 'critical',
                confidence: 'high',
                domain: 'code-execution',
                location: { file: file.relativePath, line, snippet: region.substring(0, 60) },
                remediation: 'Remove exec() usage. Use safe alternatives or sandboxed code execution.',
                standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001', 'D002'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
              });
            }
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-003',
    name: 'new Function() constructor',
    domain: 'code-execution',
    severity: 'critical',
    confidence: 'high',
    description: 'new Function() creates code from strings, similar to eval().',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const funcPattern = /new\s+Function\s*\(/g;
        let match: RegExpExecArray | null;
        while ((match = funcPattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-003-${findings.length}`,
            ruleId: 'AA-CE-003',
            title: 'new Function() constructor used',
            description: `new Function() in ${file.relativePath} creates executable code from strings.`,
            severity: 'critical',
            confidence: 'high',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0] },
            remediation: 'Remove new Function() usage. Use safe alternatives.',
            standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-004',
    name: 'Python compile() with dynamic input',
    domain: 'code-execution',
    severity: 'high',
    confidence: 'medium',
    description: 'compile() used with potentially dynamic input in Python.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of graph.files.python) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const compilePattern = /\bcompile\s*\([^)]*,\s*["'][^"']*["']\s*,\s*["']exec["']\s*\)/g;
        let match: RegExpExecArray | null;
        while ((match = compilePattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-004-${findings.length}`,
            ruleId: 'AA-CE-004',
            title: 'compile() with exec mode',
            description: `compile() in ${file.relativePath} used in exec mode to create executable code.`,
            severity: 'high',
            confidence: 'medium',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Use safe alternatives to compile()+exec. Consider ast.literal_eval() for data parsing.',
            standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-005',
    name: 'PythonREPL or code interpreter without sandbox',
    domain: 'code-execution',
    severity: 'critical',
    confidence: 'high',
    description: 'Python REPL or code interpreter tool used without sandboxing.',
    frameworks: ['langchain', 'crewai'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3', 'A.5.4'], nistAiRmf: ['MEASURE-1.1', 'MAP-2.3'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const replPatterns = [
          /PythonREPLTool/g,
          /PythonREPL/g,
          /PythonAstREPLTool/g,
          /CodeInterpreterTool/g,
        ];

        for (const pattern of replPatterns) {
          pattern.lastIndex = 0;
          let match: RegExpExecArray | null;
          while ((match = pattern.exec(content)) !== null) {
            const line = content.substring(0, match.index).split('\n').length;
            const region = content.substring(Math.max(0, match.index - 500), match.index + 500);
            const hasSandbox = /sandbox|docker|container|e2b|modal/i.test(region);

            if (!hasSandbox) {
              findings.push({
                id: `AA-CE-005-${findings.length}`,
                ruleId: 'AA-CE-005',
                title: 'Code execution tool without sandbox',
                description: `${match[0]} in ${file.relativePath} executes code without apparent sandboxing.`,
                severity: 'critical',
                confidence: 'high',
                domain: 'code-execution',
                location: { file: file.relativePath, line, snippet: match[0] },
                remediation: 'Run code execution tools in a sandboxed environment (Docker, E2B, etc.).',
                standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3', 'A.5.4'], nistAiRmf: ['MEASURE-1.1', 'MAP-2.3'] },
              });
            }
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-006',
    name: 'pickle.loads or marshal.loads',
    domain: 'code-execution',
    severity: 'critical',
    confidence: 'high',
    description: 'Deserialization of untrusted data can lead to arbitrary code execution.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001', 'A002'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of graph.files.python) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const deserialPatterns = [
          { regex: /pickle\.loads?\s*\(/g, name: 'pickle.load' },
          { regex: /marshal\.loads?\s*\(/g, name: 'marshal.load' },
          { regex: /shelve\.open\s*\(/g, name: 'shelve.open' },
          { regex: /yaml\.load\s*\(\s*[^)]*(?!Loader\s*=\s*yaml\.SafeLoader)/g, name: 'yaml.load (unsafe)' },
        ];

        for (const { regex, name } of deserialPatterns) {
          regex.lastIndex = 0;
          let match: RegExpExecArray | null;
          while ((match = regex.exec(content)) !== null) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-CE-006-${findings.length}`,
              ruleId: 'AA-CE-006',
              title: `Unsafe deserialization: ${name}`,
              description: `${name} in ${file.relativePath} can execute arbitrary code when deserializing untrusted data.`,
              severity: 'critical',
              confidence: 'high',
              domain: 'code-execution',
              location: { file: file.relativePath, line, snippet: match[0] },
              remediation: `Use safe alternatives (json.loads, yaml.safe_load). Never deserialize untrusted data with ${name}.`,
              standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001', 'A002'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-007',
    name: 'subprocess.Popen with shell=True',
    domain: 'code-execution',
    severity: 'critical',
    confidence: 'high',
    description: 'subprocess.Popen with shell=True allows shell injection via untrusted input.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001', 'D002'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of graph.files.python) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const pattern = /subprocess\.Popen\s*\([^)]*shell\s*=\s*True/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-007-${findings.length}`,
            ruleId: 'AA-CE-007',
            title: 'subprocess.Popen with shell=True',
            description: `subprocess.Popen(shell=True) in ${file.relativePath} allows shell injection attacks.`,
            severity: 'critical',
            confidence: 'high',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Use subprocess.Popen with shell=False (default) and pass arguments as a list.',
            standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001', 'D002'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-008',
    name: 'os.system() call',
    domain: 'code-execution',
    severity: 'critical',
    confidence: 'high',
    description: 'os.system() executes commands via the shell, enabling shell injection.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of graph.files.python) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const pattern = /os\.system\s*\(/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-008-${findings.length}`,
            ruleId: 'AA-CE-008',
            title: 'os.system() call detected',
            description: `os.system() in ${file.relativePath} executes commands via the shell, enabling injection attacks.`,
            severity: 'critical',
            confidence: 'high',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0] },
            remediation: 'Replace os.system() with subprocess.run() using a list of arguments and shell=False.',
            standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-009',
    name: 'child_process.exec() in Node',
    domain: 'code-execution',
    severity: 'critical',
    confidence: 'high',
    description: 'child_process.exec() runs commands in a shell, enabling command injection.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const patterns = [
          /(?:require\s*\(\s*["']child_process["']\s*\)|child_process)\.exec\s*\(/g,
          /\bexecSync\s*\(/g,
        ];

        for (const pattern of patterns) {
          pattern.lastIndex = 0;
          let match: RegExpExecArray | null;
          while ((match = pattern.exec(content)) !== null) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-CE-009-${findings.length}`,
              ruleId: 'AA-CE-009',
              title: 'child_process.exec() usage detected',
              description: `child_process exec in ${file.relativePath} runs commands in a shell, enabling injection.`,
              severity: 'critical',
              confidence: 'high',
              domain: 'code-execution',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
              remediation: 'Use child_process.execFile() or child_process.spawn() instead of exec/execSync to avoid shell injection.',
              standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-010',
    name: 'Template injection risk',
    domain: 'code-execution',
    severity: 'high',
    confidence: 'medium',
    description: 'Server-side template rendering with potential user input can lead to template injection.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['D002'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-2.6'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const pattern = /Jinja2|Environment\s*\(.*loader|Template\s*\(.*render|Handlebars\.compile/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          const regionStart = Math.max(0, match.index - 500);
          const regionEnd = Math.min(content.length, match.index + 500);
          const region = content.substring(regionStart, regionEnd);
          const hasUserInput = /user_input|request\.|req\.|params|query/i.test(region);

          if (hasUserInput) {
            findings.push({
              id: `AA-CE-010-${findings.length}`,
              ruleId: 'AA-CE-010',
              title: 'Template injection risk',
              description: `Template rendering in ${file.relativePath} may use user-controlled input, risking server-side template injection.`,
              severity: 'high',
              confidence: 'medium',
              domain: 'code-execution',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
              remediation: 'Avoid passing user input directly into templates. Use sandboxed template environments and validate all inputs.',
              standards: { owaspAgentic: ['ASI05'], aiuc1: ['D002'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-2.6'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-011',
    name: 'SSRF in requests/fetch',
    domain: 'code-execution',
    severity: 'high',
    confidence: 'medium',
    description: 'HTTP requests using variable URLs may be vulnerable to server-side request forgery (SSRF).',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['D002'], iso42001: ['A.5.3'], nistAiRmf: ['MAP-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const pattern = /(?:requests\.get|requests\.post|fetch|urllib\.request\.urlopen)\s*\(\s*(?!["']https?:)/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-011-${findings.length}`,
            ruleId: 'AA-CE-011',
            title: 'Potential SSRF via variable URL',
            description: `HTTP request in ${file.relativePath} uses a variable URL argument, which may allow SSRF attacks.`,
            severity: 'high',
            confidence: 'medium',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Validate and allowlist URLs before making HTTP requests. Block internal/private IP ranges.',
            standards: { owaspAgentic: ['ASI05'], aiuc1: ['D002'], iso42001: ['A.5.3'], nistAiRmf: ['MAP-2.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-012',
    name: 'SQL string concatenation',
    domain: 'code-execution',
    severity: 'critical',
    confidence: 'high',
    description: 'SQL queries built via string concatenation or interpolation are vulnerable to SQL injection.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['D002'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const patterns: RegExp[] = [];
        if (file.language === 'python') {
          patterns.push(/f["'].*(?:SELECT|INSERT|UPDATE|DELETE|DROP).*\{/gi);
        }
        if (file.language === 'typescript' || file.language === 'javascript') {
          patterns.push(/`[^`]*(?:SELECT|INSERT|UPDATE|DELETE|DROP)[^`]*\$\{/gi);
        }
        patterns.push(/"[^"]*(?:SELECT|INSERT|UPDATE|DELETE|DROP)[^"]*"\s*\+/gi);

        for (const pattern of patterns) {
          pattern.lastIndex = 0;
          let match: RegExpExecArray | null;
          while ((match = pattern.exec(content)) !== null) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-CE-012-${findings.length}`,
              ruleId: 'AA-CE-012',
              title: 'SQL injection via string concatenation',
              description: `SQL query in ${file.relativePath} is built using string interpolation or concatenation, risking SQL injection.`,
              severity: 'critical',
              confidence: 'high',
              domain: 'code-execution',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
              remediation: 'Use parameterized queries or prepared statements instead of string concatenation for SQL.',
              standards: { owaspAgentic: ['ASI05'], aiuc1: ['D002'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-013',
    name: 'XML external entity processing',
    domain: 'code-execution',
    severity: 'high',
    confidence: 'medium',
    description: 'XML parsing without defusedxml may be vulnerable to XXE (XML External Entity) attacks.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['A002'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of graph.files.python) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const pattern = /(?:lxml|xml)\.etree/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const hasDefusedxml = /defusedxml/i.test(content);
          if (!hasDefusedxml) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-CE-013-${findings.length}`,
              ruleId: 'AA-CE-013',
              title: 'XML parsing without defusedxml',
              description: `${match[0]} in ${file.relativePath} parses XML without defusedxml, risking XXE attacks.`,
              severity: 'high',
              confidence: 'medium',
              domain: 'code-execution',
              location: { file: file.relativePath, line, snippet: match[0] },
              remediation: 'Use defusedxml instead of lxml.etree or xml.etree to prevent XXE attacks.',
              standards: { owaspAgentic: ['ASI05'], aiuc1: ['A002'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-014',
    name: 'LLM output executed as code',
    domain: 'code-execution',
    severity: 'critical',
    confidence: 'high',
    description: 'exec() or eval() called on a variable likely containing LLM output enables arbitrary code execution.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001', 'A003'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-2.6'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const pattern = /(?:exec|eval)\s*\(\s*(?:response|result|output|completion|message|content|answer|reply)/gi;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-014-${findings.length}`,
            ruleId: 'AA-CE-014',
            title: 'LLM output executed as code',
            description: `exec/eval in ${file.relativePath} is called on a variable that likely contains LLM output, enabling arbitrary code execution.`,
            severity: 'critical',
            confidence: 'high',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Never pass LLM output to exec() or eval(). Use a sandboxed code interpreter or safe parsing instead.',
            standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001', 'A003'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-2.6'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-015',
    name: 'Dynamic import/require',
    domain: 'code-execution',
    severity: 'high',
    confidence: 'medium',
    description: 'Dynamic import or require with a variable argument can load arbitrary modules.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MAP-2.3'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const patterns: RegExp[] = [];
        if (file.language === 'python') {
          patterns.push(/importlib\.import_module\s*\(\s*(?!["'])/g);
        }
        if (file.language === 'typescript' || file.language === 'javascript') {
          patterns.push(/require\s*\(\s*(?!["'])/g);
          patterns.push(/import\s*\(\s*(?!["'])/g);
        }

        for (const pattern of patterns) {
          pattern.lastIndex = 0;
          let match: RegExpExecArray | null;
          while ((match = pattern.exec(content)) !== null) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-CE-015-${findings.length}`,
              ruleId: 'AA-CE-015',
              title: 'Dynamic import/require with variable argument',
              description: `Dynamic module loading in ${file.relativePath} uses a variable argument, which can load arbitrary code.`,
              severity: 'high',
              confidence: 'medium',
              domain: 'code-execution',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
              remediation: 'Use static imports or maintain an allowlist of permitted modules for dynamic imports.',
              standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MAP-2.3'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-016',
    name: 'Unsandboxed Docker socket access',
    domain: 'code-execution',
    severity: 'critical',
    confidence: 'high',
    description: 'Direct access to the Docker socket allows arbitrary container and host-level operations.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3', 'A.6.2'], nistAiRmf: ['MEASURE-1.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const pattern = /\/var\/run\/docker\.sock|docker\.from_env|DockerClient/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-016-${findings.length}`,
            ruleId: 'AA-CE-016',
            title: 'Unsandboxed Docker socket access',
            description: `Docker socket access in ${file.relativePath} allows arbitrary container operations without sandboxing.`,
            severity: 'critical',
            confidence: 'high',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0] },
            remediation: 'Avoid mounting the Docker socket directly. Use a restricted Docker API proxy or rootless Docker.',
            standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3', 'A.6.2'], nistAiRmf: ['MEASURE-1.1'] },
          });
        }
      }
      return findings;
    },
  },
];
