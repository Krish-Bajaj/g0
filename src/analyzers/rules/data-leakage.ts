import * as fs from 'node:fs';
import type { Rule } from '../../types/control.js';
import type { Finding } from '../../types/finding.js';
import type { AgentGraph } from '../../types/agent-graph.js';
import {
  isTreeSitterAvailable,
  getFileTreeForLang,
  findFunctionCalls,
  findNodes,
} from '../ast/index.js';
import { getKeywordArgBool } from '../ast/python.js';

export const dataLeakageRules: Rule[] = [
  {
    id: 'AA-DL-001',
    name: 'verbose=True exposes internal state',
    domain: 'data-leakage',
    severity: 'medium',
    confidence: 'high',
    description: 'verbose=True exposes internal agent reasoning and potentially sensitive data.',
    frameworks: ['langchain', 'crewai'],
    owaspAgentic: ['ASI07'],
    standards: { owaspAgentic: ['ASI07'], aiuc1: ['E001', 'E003'], iso42001: ['A.8.2'], nistAiRmf: ['MEASURE-2.1'] },
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
          // AST: find function calls with verbose=True keyword argument
          const callTypes = ['call_expression', 'call'];
          const calls = findNodes(tree, (node) => callTypes.includes(node.type));
          for (const call of calls) {
            if (getKeywordArgBool(call, 'verbose') === true) {
              const line = call.startPosition.row + 1;
              findings.push({
                id: `AA-DL-001-${findings.length}`,
                ruleId: 'AA-DL-001',
                title: 'verbose=True exposes internal state',
                description: `verbose=True in ${file.relativePath} may expose internal reasoning to end users.`,
                severity: 'medium',
                confidence: 'high',
                domain: 'data-leakage',
                location: { file: file.relativePath, line, snippet: 'verbose=True' },
                remediation: 'Set verbose=False in production. Use structured logging instead.',
                standards: { owaspAgentic: ['ASI07'], aiuc1: ['E001', 'E003'], iso42001: ['A.8.2'], nistAiRmf: ['MEASURE-2.1'] },
              });
            }
          }
        } else {
          const verbosePattern = /verbose\s*=\s*True/g;
          let match: RegExpExecArray | null;
          while ((match = verbosePattern.exec(content)) !== null) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-DL-001-${findings.length}`,
              ruleId: 'AA-DL-001',
              title: 'verbose=True exposes internal state',
              description: `verbose=True in ${file.relativePath} may expose internal reasoning to end users.`,
              severity: 'medium',
              confidence: 'high',
              domain: 'data-leakage',
              location: { file: file.relativePath, line, snippet: 'verbose=True' },
              remediation: 'Set verbose=False in production. Use structured logging instead.',
              standards: { owaspAgentic: ['ASI07'], aiuc1: ['E001', 'E003'], iso42001: ['A.8.2'], nistAiRmf: ['MEASURE-2.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-DL-002',
    name: 'return_intermediate_steps exposes reasoning',
    domain: 'data-leakage',
    severity: 'medium',
    confidence: 'high',
    description: 'return_intermediate_steps=True exposes tool calls and intermediate reasoning.',
    frameworks: ['langchain'],
    owaspAgentic: ['ASI07'],
    standards: { owaspAgentic: ['ASI07'], aiuc1: ['E001'], iso42001: ['A.8.2'], nistAiRmf: ['MEASURE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const pattern = /return_intermediate_steps\s*=\s*True/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-DL-002-${findings.length}`,
            ruleId: 'AA-DL-002',
            title: 'Intermediate steps exposed',
            description: `return_intermediate_steps=True in ${file.relativePath} exposes internal tool calls and reasoning.`,
            severity: 'medium',
            confidence: 'high',
            domain: 'data-leakage',
            location: { file: file.relativePath, line, snippet: 'return_intermediate_steps=True' },
            remediation: 'Disable return_intermediate_steps in production or filter sensitive data from steps.',
            standards: { owaspAgentic: ['ASI07'], aiuc1: ['E001'], iso42001: ['A.8.2'], nistAiRmf: ['MEASURE-2.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-DL-003',
    name: 'Raw error messages exposed',
    domain: 'data-leakage',
    severity: 'medium',
    confidence: 'medium',
    description: 'Raw error messages or stack traces may be exposed to end users.',
    frameworks: ['all'],
    owaspAgentic: ['ASI07'],
    standards: { owaspAgentic: ['ASI07'], aiuc1: ['E001', 'E003'], iso42001: ['A.8.2', 'A.9.3'], nistAiRmf: ['MANAGE-2.4'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const errorPatterns = [
          { regex: /traceback\.print_exc\s*\(\)/g, name: 'traceback.print_exc()' },
          { regex: /traceback\.format_exc\s*\(\)/g, name: 'traceback.format_exc()' },
          { regex: /return\s+.*str\s*\(\s*(?:e|err|error|exception)\s*\)/g, name: 'returning raw error string' },
          { regex: /res(?:ponse)?\.(?:send|json)\s*\(.*(?:err|error)\.(?:message|stack)/g, name: 'exposing error details' },
        ];

        for (const { regex, name } of errorPatterns) {
          regex.lastIndex = 0;
          let match: RegExpExecArray | null;
          while ((match = regex.exec(content)) !== null) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-DL-003-${findings.length}`,
              ruleId: 'AA-DL-003',
              title: 'Raw error exposed to user',
              description: `${name} in ${file.relativePath} may expose internal details to end users.`,
              severity: 'medium',
              confidence: 'medium',
              domain: 'data-leakage',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
              remediation: 'Return generic error messages to users. Log detailed errors server-side.',
              standards: { owaspAgentic: ['ASI07'], aiuc1: ['E001', 'E003'], iso42001: ['A.8.2', 'A.9.3'], nistAiRmf: ['MANAGE-2.4'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-DL-004',
    name: 'PII patterns in prompt content',
    domain: 'data-leakage',
    severity: 'high',
    confidence: 'medium',
    description: 'Prompt contains patterns that look like personal identifiable information.',
    frameworks: ['all'],
    owaspAgentic: ['ASI07'],
    standards: { owaspAgentic: ['ASI07'], aiuc1: ['E001', 'E002'], iso42001: ['A.6.3'], nistAiRmf: ['MEASURE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const prompt of graph.prompts) {
        const piiPatterns = [
          { regex: /\b\d{3}[-.]?\d{2}[-.]?\d{4}\b/, name: 'SSN-like number' },
          { regex: /\b\d{16}\b/, name: 'credit card-like number' },
          { regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/, name: 'email address' },
        ];

        for (const { regex, name } of piiPatterns) {
          if (regex.test(prompt.content)) {
            findings.push({
              id: `AA-DL-004-${findings.length}`,
              ruleId: 'AA-DL-004',
              title: `PII detected in prompt: ${name}`,
              description: `Prompt in ${prompt.file} contains what appears to be ${name}.`,
              severity: 'high',
              confidence: 'medium',
              domain: 'data-leakage',
              location: { file: prompt.file, line: prompt.line },
              remediation: 'Remove PII from prompt templates. Use parameterized references instead.',
              standards: { owaspAgentic: ['ASI07'], aiuc1: ['E001', 'E002'], iso42001: ['A.6.3'], nistAiRmf: ['MEASURE-2.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-DL-005',
    name: 'Debug/logging exposes sensitive data',
    domain: 'data-leakage',
    severity: 'low',
    confidence: 'medium',
    description: 'Debug logging may expose sensitive agent data.',
    frameworks: ['all'],
    owaspAgentic: ['ASI07'],
    standards: { owaspAgentic: ['ASI07'], aiuc1: ['E001', 'E003'], iso42001: ['A.6.4'], nistAiRmf: ['MANAGE-3.1'] },
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
          // AST: find print/console.log/logging.debug calls and check for sensitive args
          const logCalls = findFunctionCalls(tree, /^(print|console\.log|logging\.debug)$/);
          for (const call of logCalls) {
            const args = call.childForFieldName('arguments');
            if (!args) continue;

            const identifiers = findNodes({ rootNode: args } as any, (n) => n.type === 'identifier');
            const hasSensitive = identifiers.some((id) =>
              /api[_-]?key|secret|token|password|credential/i.test(id.text),
            );

            if (hasSensitive) {
              const line = call.startPosition.row + 1;
              findings.push({
                id: `AA-DL-005-${findings.length}`,
                ruleId: 'AA-DL-005',
                title: 'Sensitive data in debug logging',
                description: `Debug logging in ${file.relativePath} may expose sensitive data.`,
                severity: 'low',
                confidence: 'medium',
                domain: 'data-leakage',
                location: { file: file.relativePath, line, snippet: call.text.substring(0, 60) },
                remediation: 'Remove sensitive data from log statements. Use structured logging with redaction.',
                standards: { owaspAgentic: ['ASI07'], aiuc1: ['E001', 'E003'], iso42001: ['A.6.4'], nistAiRmf: ['MANAGE-3.1'] },
              });
            }
          }
        } else {
          const logPatterns = [
            /(?:print|console\.log)\s*\(.*(?:api[_-]?key|secret|token|password|credential)/gi,
            /logging\.debug\s*\(.*(?:api[_-]?key|secret|token|password|credential)/gi,
          ];

          for (const pattern of logPatterns) {
            pattern.lastIndex = 0;
            let match: RegExpExecArray | null;
            while ((match = pattern.exec(content)) !== null) {
              const line = content.substring(0, match.index).split('\n').length;
              findings.push({
                id: `AA-DL-005-${findings.length}`,
                ruleId: 'AA-DL-005',
                title: 'Sensitive data in debug logging',
                description: `Debug logging in ${file.relativePath} may expose sensitive data.`,
                severity: 'low',
                confidence: 'medium',
                domain: 'data-leakage',
                location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
                remediation: 'Remove sensitive data from log statements. Use structured logging with redaction.',
                standards: { owaspAgentic: ['ASI07'], aiuc1: ['E001', 'E003'], iso42001: ['A.6.4'], nistAiRmf: ['MANAGE-3.1'] },
              });
            }
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-DL-006',
    name: 'PII patterns in prompts',
    domain: 'data-leakage',
    severity: 'high',
    confidence: 'medium',
    description: 'Code files contain prompt-like variables with PII patterns such as SSNs or credit card numbers.',
    frameworks: ['all'],
    owaspAgentic: ['ASI07'],
    standards: { owaspAgentic: ['ASI07'], aiuc1: ['E001', 'E002'], iso42001: ['A.6.3'], nistAiRmf: ['MEASURE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const piiInPromptPattern = /(?:prompt|message|template|instruction)\s*=\s*(?:f?["']).*(?:\d{3}-\d{2}-\d{4}|\d{16})/g;
        let match: RegExpExecArray | null;
        while ((match = piiInPromptPattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-DL-006-${findings.length}`,
            ruleId: 'AA-DL-006',
            title: 'PII pattern in code prompt variable',
            description: `Prompt variable in ${file.relativePath} contains what appears to be PII (SSN or credit card pattern).`,
            severity: 'high',
            confidence: 'medium',
            domain: 'data-leakage',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 80) },
            remediation: 'Remove PII from prompt variables. Use parameterized references or redaction.',
            standards: { owaspAgentic: ['ASI07'], aiuc1: ['E001', 'E002'], iso42001: ['A.6.3'], nistAiRmf: ['MEASURE-2.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-DL-007',
    name: 'Sensitive data in logs',
    domain: 'data-leakage',
    severity: 'high',
    confidence: 'medium',
    description: 'Logging statements contain references to sensitive user data fields.',
    frameworks: ['all'],
    owaspAgentic: ['ASI07'],
    standards: { owaspAgentic: ['ASI07'], aiuc1: ['E001', 'E003'], iso42001: ['A.6.4'], nistAiRmf: ['MANAGE-3.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const sensitiveLogPattern = /(?:logging\.\w+|logger\.\w+|console\.\w+|print)\s*\(.*(?:user\.(?:email|name|address|ssn|password)|customer|patient|credit.?card)/gi;
        let match: RegExpExecArray | null;
        while ((match = sensitiveLogPattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-DL-007-${findings.length}`,
            ruleId: 'AA-DL-007',
            title: 'Sensitive data in logs',
            description: `Logging statement in ${file.relativePath} references sensitive user data fields.`,
            severity: 'high',
            confidence: 'medium',
            domain: 'data-leakage',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 80) },
            remediation: 'Redact sensitive fields before logging. Use structured logging with PII masking.',
            standards: { owaspAgentic: ['ASI07'], aiuc1: ['E001', 'E003'], iso42001: ['A.6.4'], nistAiRmf: ['MANAGE-3.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-DL-008',
    name: 'Full stack traces exposed',
    domain: 'data-leakage',
    severity: 'medium',
    confidence: 'medium',
    description: 'Exception handlers expose full stack traces or re-raise errors to end users.',
    frameworks: ['all'],
    owaspAgentic: ['ASI07'],
    standards: { owaspAgentic: ['ASI07'], aiuc1: ['E001', 'E003'], iso42001: ['A.8.2', 'A.9.3'], nistAiRmf: ['MANAGE-2.4'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const tracePatterns = [
          { regex: /except\s*(?:Exception|BaseException|\w*Error)\s*(?:as\s+\w+)?:\s*\n\s*(?:raise|traceback)/g, name: 'Python exception re-raise/traceback' },
          { regex: /\.catch\s*\(\s*\w+\s*=>\s*\{?\s*(?:res|response)\.(?:send|json)\s*\(\s*\w+/g, name: 'JS error sent in response' },
        ];

        for (const { regex, name } of tracePatterns) {
          regex.lastIndex = 0;
          let match: RegExpExecArray | null;
          while ((match = regex.exec(content)) !== null) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-DL-008-${findings.length}`,
              ruleId: 'AA-DL-008',
              title: 'Full stack trace exposed',
              description: `${name} in ${file.relativePath} may expose internal stack traces to end users.`,
              severity: 'medium',
              confidence: 'medium',
              domain: 'data-leakage',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 80) },
              remediation: 'Catch exceptions and return generic error messages. Log full traces server-side only.',
              standards: { owaspAgentic: ['ASI07'], aiuc1: ['E001', 'E003'], iso42001: ['A.8.2', 'A.9.3'], nistAiRmf: ['MANAGE-2.4'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-DL-009',
    name: 'Internal URLs in responses',
    domain: 'data-leakage',
    severity: 'medium',
    confidence: 'medium',
    description: 'Response variables contain internal hostnames or private IP addresses.',
    frameworks: ['all'],
    owaspAgentic: ['ASI07'],
    standards: { owaspAgentic: ['ASI07'], aiuc1: ['E001'], iso42001: ['A.8.2'], nistAiRmf: ['MEASURE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const internalUrlPattern = /(?:response|reply|output|message)\s*=.*(?:localhost|127\.0\.0\.1|\.internal|\.local|\.corp|10\.\d|192\.168\.)/gi;
        let match: RegExpExecArray | null;
        while ((match = internalUrlPattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-DL-009-${findings.length}`,
            ruleId: 'AA-DL-009',
            title: 'Internal URL in response',
            description: `Response variable in ${file.relativePath} contains an internal hostname or private IP address.`,
            severity: 'medium',
            confidence: 'medium',
            domain: 'data-leakage',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 80) },
            remediation: 'Remove internal URLs from response templates. Use public-facing URLs or configuration references.',
            standards: { owaspAgentic: ['ASI07'], aiuc1: ['E001'], iso42001: ['A.8.2'], nistAiRmf: ['MEASURE-2.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-DL-010',
    name: 'Raw LLM response returned to user',
    domain: 'data-leakage',
    severity: 'medium',
    confidence: 'low',
    description: 'LLM response is passed directly to an HTTP response without sanitization or filtering.',
    frameworks: ['all'],
    owaspAgentic: ['ASI07'],
    standards: { owaspAgentic: ['ASI07'], aiuc1: ['A003'], iso42001: ['A.8.2'], nistAiRmf: ['MEASURE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const rawResponsePattern = /(?:res|response)\.(?:send|json)\s*\(\s*(?:result|response|completion|output|answer)/gi;
        let match: RegExpExecArray | null;
        while ((match = rawResponsePattern.exec(content)) !== null) {
          // Check nearby context for sanitization
          const regionStart = Math.max(0, match.index - 300);
          const regionEnd = Math.min(content.length, match.index + 100);
          const region = content.substring(regionStart, regionEnd);
          const hasSanitization = /sanitize|filter|validate|clean|escape|strip|redact/i.test(region);

          if (!hasSanitization) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-DL-010-${findings.length}`,
              ruleId: 'AA-DL-010',
              title: 'Raw LLM response returned to user',
              description: `LLM response in ${file.relativePath} is sent directly to the HTTP response without filtering.`,
              severity: 'medium',
              confidence: 'low',
              domain: 'data-leakage',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 80) },
              remediation: 'Sanitize or filter LLM responses before returning them to users. Validate output format and strip sensitive content.',
              standards: { owaspAgentic: ['ASI07'], aiuc1: ['A003'], iso42001: ['A.8.2'], nistAiRmf: ['MEASURE-2.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
];
