import * as fs from 'node:fs';
import type { Rule } from '../../types/control.js';
import type { Finding } from '../../types/finding.js';
import type { AgentGraph } from '../../types/agent-graph.js';
import {
  isTreeSitterAvailable,
  getFileTreeForLang,
  findFunctionCalls,
} from '../ast/index.js';
import { getKeywordArgBool } from '../ast/python.js';

export const toolSafetyRules: Rule[] = [
  {
    id: 'AA-TS-001',
    name: 'Shell execution tool detected',
    domain: 'tool-safety',
    severity: 'critical',
    confidence: 'high',
    description: 'Agent has access to a shell execution tool, enabling arbitrary command execution.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02', 'ASI05'], aiuc1: ['B003', 'D001'], iso42001: ['A.5.3', 'A.6.2'], nistAiRmf: ['MAP-2.3', 'MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const tool of graph.tools) {
        if (tool.capabilities.includes('shell')) {
          findings.push({
            id: `AA-TS-001-${findings.length}`,
            ruleId: 'AA-TS-001',
            title: 'Shell execution tool detected',
            description: `Tool "${tool.name}" in ${tool.file} provides shell/command execution capability.`,
            severity: 'critical',
            confidence: 'high',
            domain: 'tool-safety',
            location: { file: tool.file, line: tool.line },
            remediation: 'Remove shell execution tool or wrap it with strict input validation and allowlisting.',
            standards: { owaspAgentic: ['ASI02', 'ASI05'], aiuc1: ['B003', 'D001'], iso42001: ['A.5.3', 'A.6.2'], nistAiRmf: ['MAP-2.3', 'MANAGE-2.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-002',
    name: 'Raw SQL tool without parameterization',
    domain: 'tool-safety',
    severity: 'critical',
    confidence: 'high',
    description: 'Tool allows raw SQL execution, risking SQL injection.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02'], aiuc1: ['B003', 'D002'], iso42001: ['A.6.2'], nistAiRmf: ['MAP-2.3'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const tool of graph.tools) {
        if (tool.capabilities.includes('database') && !tool.hasInputValidation) {
          findings.push({
            id: `AA-TS-002-${findings.length}`,
            ruleId: 'AA-TS-002',
            title: 'Database tool without input validation',
            description: `Tool "${tool.name}" in ${tool.file} accesses a database without apparent input validation.`,
            severity: 'critical',
            confidence: 'high',
            domain: 'tool-safety',
            location: { file: tool.file, line: tool.line },
            remediation: 'Use parameterized queries and validate all input before database operations.',
            standards: { owaspAgentic: ['ASI02'], aiuc1: ['B003', 'D002'], iso42001: ['A.6.2'], nistAiRmf: ['MAP-2.3'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-003',
    name: 'Filesystem tool without path validation',
    domain: 'tool-safety',
    severity: 'high',
    confidence: 'high',
    description: 'Tool accesses the filesystem without validating paths, risking path traversal.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02'], aiuc1: ['B003'], iso42001: ['A.6.2'], nistAiRmf: ['MAP-2.3'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const tool of graph.tools) {
        if (tool.capabilities.includes('filesystem') && !tool.hasInputValidation) {
          findings.push({
            id: `AA-TS-003-${findings.length}`,
            ruleId: 'AA-TS-003',
            title: 'Filesystem tool without path validation',
            description: `Tool "${tool.name}" in ${tool.file} accesses the filesystem without input validation.`,
            severity: 'high',
            confidence: 'high',
            domain: 'tool-safety',
            location: { file: tool.file, line: tool.line },
            remediation: 'Validate and sanitize file paths. Use allowlists for permitted directories.',
            standards: { owaspAgentic: ['ASI02'], aiuc1: ['B003'], iso42001: ['A.6.2'], nistAiRmf: ['MAP-2.3'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-004',
    name: 'Tool missing input schema',
    domain: 'tool-safety',
    severity: 'medium',
    confidence: 'high',
    description: 'Tool has no defined input schema, accepting arbitrary input.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02'], aiuc1: ['A002', 'B003'], iso42001: ['A.5.3'], nistAiRmf: ['MAP-2.3'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const tool of graph.tools) {
        if (tool.parameters.length === 0 && !tool.hasInputValidation && tool.hasSideEffects) {
          findings.push({
            id: `AA-TS-004-${findings.length}`,
            ruleId: 'AA-TS-004',
            title: 'Side-effect tool missing input schema',
            description: `Tool "${tool.name}" in ${tool.file} has side effects but no defined input schema.`,
            severity: 'medium',
            confidence: 'high',
            domain: 'tool-safety',
            location: { file: tool.file, line: tool.line },
            remediation: 'Define explicit input schemas with validation for all tool parameters.',
            standards: { owaspAgentic: ['ASI02'], aiuc1: ['A002', 'B003'], iso42001: ['A.5.3'], nistAiRmf: ['MAP-2.3'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-005',
    name: 'Network access tool detected',
    domain: 'tool-safety',
    severity: 'medium',
    confidence: 'high',
    description: 'Tool makes network requests, potentially to arbitrary URLs.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02'], aiuc1: ['B003'], iso42001: ['A.6.2'], nistAiRmf: ['MAP-2.3'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const tool of graph.tools) {
        if (tool.capabilities.includes('network') && !tool.hasInputValidation) {
          findings.push({
            id: `AA-TS-005-${findings.length}`,
            ruleId: 'AA-TS-005',
            title: 'Unrestricted network access tool',
            description: `Tool "${tool.name}" in ${tool.file} makes network requests without URL validation.`,
            severity: 'medium',
            confidence: 'high',
            domain: 'tool-safety',
            location: { file: tool.file, line: tool.line },
            remediation: 'Restrict network tools to allowlisted domains and validate URLs.',
            standards: { owaspAgentic: ['ASI02'], aiuc1: ['B003'], iso42001: ['A.6.2'], nistAiRmf: ['MAP-2.3'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-006',
    name: 'Email sending tool detected',
    domain: 'tool-safety',
    severity: 'high',
    confidence: 'high',
    description: 'Tool can send emails, which could be abused for phishing or spam.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02', 'ASI09'], aiuc1: ['B003'], iso42001: ['A.8.3'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const tool of graph.tools) {
        if (tool.capabilities.includes('email')) {
          findings.push({
            id: `AA-TS-006-${findings.length}`,
            ruleId: 'AA-TS-006',
            title: 'Email sending tool detected',
            description: `Tool "${tool.name}" in ${tool.file} can send emails. This should require human approval.`,
            severity: 'high',
            confidence: 'high',
            domain: 'tool-safety',
            location: { file: tool.file, line: tool.line },
            remediation: 'Gate email sending behind human approval. Validate recipients and content.',
            standards: { owaspAgentic: ['ASI02', 'ASI09'], aiuc1: ['B003'], iso42001: ['A.8.3'], nistAiRmf: ['MANAGE-2.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-007',
    name: 'Subprocess or os.system call in tool',
    domain: 'tool-safety',
    severity: 'critical',
    confidence: 'high',
    description: 'Tool uses subprocess or os.system for command execution.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02', 'ASI05'], aiuc1: ['D001', 'D002'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
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
          const astPatterns = [
            { pattern: /^subprocess\.(call|run|Popen|check_output)$/, name: 'subprocess' },
            { pattern: /^os\.system$/, name: 'os.system' },
            { pattern: /^os\.popen$/, name: 'os.popen' },
            { pattern: /^child_process\.exec$/, name: 'child_process.exec' },
            { pattern: /^execSync$/, name: 'execSync' },
          ];

          for (const { pattern, name } of astPatterns) {
            const calls = findFunctionCalls(tree, pattern);
            for (const call of calls) {
              const shellEnabled = getKeywordArgBool(call, 'shell') === true;
              const line = call.startPosition.row + 1;
              findings.push({
                id: `AA-TS-007-${findings.length}`,
                ruleId: 'AA-TS-007',
                title: `${name} call detected${shellEnabled ? ' with shell=True' : ''}`,
                description: `${name} used in ${file.relativePath}${shellEnabled ? ' with shell=True, enabling shell injection' : ''}.`,
                severity: shellEnabled ? 'critical' : 'high',
                confidence: 'high',
                domain: 'tool-safety',
                location: { file: file.relativePath, line, snippet: call.text.substring(0, 60) },
                remediation: shellEnabled
                  ? 'Use shell=False and pass arguments as a list to prevent shell injection.'
                  : 'Validate and sanitize all inputs before passing to subprocess.',
                standards: { owaspAgentic: ['ASI02', 'ASI05'], aiuc1: ['D001', 'D002'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
              });
            }
          }
        } else {
          const patterns = [
            { regex: /subprocess\.(?:call|run|Popen|check_output)\s*\(/g, name: 'subprocess' },
            { regex: /os\.system\s*\(/g, name: 'os.system' },
            { regex: /os\.popen\s*\(/g, name: 'os.popen' },
            { regex: /child_process\.exec\s*\(/g, name: 'child_process.exec' },
            { regex: /execSync\s*\(/g, name: 'execSync' },
          ];

          for (const { regex, name } of patterns) {
            regex.lastIndex = 0;
            let match: RegExpExecArray | null;
            while ((match = regex.exec(content)) !== null) {
              const line = content.substring(0, match.index).split('\n').length;
              const region = content.substring(match.index, match.index + 200);
              const shellEnabled = /shell\s*=\s*True/.test(region);

              findings.push({
                id: `AA-TS-007-${findings.length}`,
                ruleId: 'AA-TS-007',
                title: `${name} call detected${shellEnabled ? ' with shell=True' : ''}`,
                description: `${name} used in ${file.relativePath}${shellEnabled ? ' with shell=True, enabling shell injection' : ''}.`,
                severity: shellEnabled ? 'critical' : 'high',
                confidence: 'high',
                domain: 'tool-safety',
                location: { file: file.relativePath, line, snippet: match[0] },
                remediation: shellEnabled
                  ? 'Use shell=False and pass arguments as a list to prevent shell injection.'
                  : 'Validate and sanitize all inputs before passing to subprocess.',
                standards: { owaspAgentic: ['ASI02', 'ASI05'], aiuc1: ['D001', 'D002'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
              });
            }
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-008',
    name: 'Too many tools attached to agent',
    domain: 'tool-safety',
    severity: 'medium',
    confidence: 'medium',
    description: 'Agent has excessive number of tools, increasing attack surface.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02'], aiuc1: ['B003'], iso42001: ['A.5.3'], nistAiRmf: ['MAP-2.3'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      if (graph.tools.length > 15) {
        findings.push({
          id: `AA-TS-008-0`,
          ruleId: 'AA-TS-008',
          title: 'Excessive number of tools',
          description: `Project has ${graph.tools.length} tools defined. Large tool sets increase the attack surface.`,
          severity: 'medium',
          confidence: 'medium',
          domain: 'tool-safety',
          location: { file: graph.rootPath, line: 1 },
          remediation: 'Apply principle of least privilege. Only attach tools the agent actually needs.',
          standards: { owaspAgentic: ['ASI02'], aiuc1: ['B003'], iso42001: ['A.5.3'], nistAiRmf: ['MAP-2.3'] },
        });
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-009',
    name: 'Code execution tool without sandboxing',
    domain: 'tool-safety',
    severity: 'critical',
    confidence: 'high',
    description: 'Tool executes code without sandboxing.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02', 'ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const tool of graph.tools) {
        if (tool.capabilities.includes('code-execution') && !tool.hasSandboxing) {
          findings.push({
            id: `AA-TS-009-${findings.length}`,
            ruleId: 'AA-TS-009',
            title: 'Code execution tool without sandboxing',
            description: `Tool "${tool.name}" in ${tool.file} executes code without sandboxing.`,
            severity: 'critical',
            confidence: 'high',
            domain: 'tool-safety',
            location: { file: tool.file, line: tool.line },
            remediation: 'Run code execution in a sandboxed environment (Docker, E2B, subprocess with restrictions).',
            standards: { owaspAgentic: ['ASI02', 'ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-010',
    name: 'Tool with side effects lacks confirmation',
    domain: 'tool-safety',
    severity: 'medium',
    confidence: 'medium',
    description: 'Tool has side effects but no human confirmation mechanism.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02', 'ASI09'], aiuc1: ['B003'], iso42001: ['A.8.3'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const dangerousCaps: string[] = ['shell', 'database', 'email', 'filesystem'];
      for (const tool of graph.tools) {
        if (tool.hasSideEffects && tool.capabilities.some(c => dangerousCaps.includes(c))) {
          findings.push({
            id: `AA-TS-010-${findings.length}`,
            ruleId: 'AA-TS-010',
            title: 'Dangerous tool lacks human-in-the-loop',
            description: `Tool "${tool.name}" in ${tool.file} has dangerous capabilities (${tool.capabilities.join(', ')}) without human approval gates.`,
            severity: 'medium',
            confidence: 'medium',
            domain: 'tool-safety',
            location: { file: tool.file, line: tool.line },
            remediation: 'Implement human-in-the-loop confirmation for dangerous tool actions.',
            standards: { owaspAgentic: ['ASI02', 'ASI09'], aiuc1: ['B003'], iso42001: ['A.8.3'], nistAiRmf: ['MANAGE-2.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-011',
    name: 'Tool with unrestricted network access',
    domain: 'tool-safety',
    severity: 'high',
    confidence: 'medium',
    description: 'Tool has network capability without input validation and no URL allowlist in its description.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02'], aiuc1: ['B003'], iso42001: ['A.6.2'], nistAiRmf: ['MAP-2.3'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const tool of graph.tools) {
        if (
          tool.capabilities.includes('network') &&
          !tool.hasInputValidation &&
          !/(?:allowlist|whitelist|allowed.?url|permitted.?domain)/i.test(tool.description)
        ) {
          findings.push({
            id: `AA-TS-011-${findings.length}`,
            ruleId: 'AA-TS-011',
            title: 'Tool with unrestricted network access',
            description: `Tool "${tool.name}" in ${tool.file} has network capability without input validation or URL allowlist.`,
            severity: 'high',
            confidence: 'medium',
            domain: 'tool-safety',
            location: { file: tool.file, line: tool.line },
            remediation: 'Add URL allowlisting and input validation to restrict network access to approved domains.',
            standards: { owaspAgentic: ['ASI02'], aiuc1: ['B003'], iso42001: ['A.6.2'], nistAiRmf: ['MAP-2.3'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-012',
    name: 'Tool with broad filesystem write',
    domain: 'tool-safety',
    severity: 'high',
    confidence: 'medium',
    description: 'Tool has filesystem capability with side effects and no input validation, allowing broad file writes.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02'], aiuc1: ['B003'], iso42001: ['A.6.2'], nistAiRmf: ['MAP-2.3'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const tool of graph.tools) {
        if (
          tool.capabilities.includes('filesystem') &&
          tool.hasSideEffects &&
          !tool.hasInputValidation &&
          /(?:write|create|delete|overwrite|remove)/i.test(tool.description) &&
          !/(?:restrict|limit|only|allowed.?path|permitted.?dir)/i.test(tool.description)
        ) {
          findings.push({
            id: `AA-TS-012-${findings.length}`,
            ruleId: 'AA-TS-012',
            title: 'Tool with broad filesystem write',
            description: `Tool "${tool.name}" in ${tool.file} can write/create/delete files without path restrictions or input validation.`,
            severity: 'high',
            confidence: 'medium',
            domain: 'tool-safety',
            location: { file: tool.file, line: tool.line },
            remediation: 'Restrict filesystem writes to specific directories. Validate and sanitize all paths.',
            standards: { owaspAgentic: ['ASI02'], aiuc1: ['B003'], iso42001: ['A.6.2'], nistAiRmf: ['MAP-2.3'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-013',
    name: 'Side-effect tool without confirmation',
    domain: 'tool-safety',
    severity: 'high',
    confidence: 'medium',
    description: 'Tool with email, API, or database side effects lacks a confirmation or approval mechanism.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02', 'ASI09'], aiuc1: ['B003'], iso42001: ['A.8.3'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const sideEffectCaps = ['email', 'api', 'database'];
      for (const tool of graph.tools) {
        if (tool.hasSideEffects && tool.capabilities.some(c => sideEffectCaps.includes(c))) {
          findings.push({
            id: `AA-TS-013-${findings.length}`,
            ruleId: 'AA-TS-013',
            title: 'Side-effect tool without confirmation (graph)',
            description: `Tool "${tool.name}" in ${tool.file} has side effects (${tool.capabilities.join(', ')}) without a confirmation mechanism.`,
            severity: 'high',
            confidence: 'medium',
            domain: 'tool-safety',
            location: { file: tool.file, line: tool.line },
            remediation: 'Add human-in-the-loop confirmation before executing side-effect actions like email, API calls, or database writes.',
            standards: { owaspAgentic: ['ASI02', 'ASI09'], aiuc1: ['B003'], iso42001: ['A.8.3'], nistAiRmf: ['MANAGE-2.1'] },
          });
        }
      }

      // Scan code files for send/post/publish patterns without confirm/approve nearby
      const sideEffectRegex = /(?:send_email|send_message|post_to|publish)\s*\(/g;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }
        sideEffectRegex.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = sideEffectRegex.exec(content)) !== null) {
          const start = Math.max(0, match.index - 300);
          const end = Math.min(content.length, match.index + match[0].length + 300);
          const region = content.substring(start, end);
          if (!/(?:confirm|approve|approval|human.?in.?the.?loop|require_confirmation)/i.test(region)) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-TS-013-${findings.length}`,
              ruleId: 'AA-TS-013',
              title: 'Side-effect call without confirmation',
              description: `${match[0].replace(/\s*\($/, '')} in ${file.relativePath} performs a side effect without a confirmation pattern nearby.`,
              severity: 'high',
              confidence: 'medium',
              domain: 'tool-safety',
              location: { file: file.relativePath, line, snippet: match[0] },
              remediation: 'Add confirmation or approval logic before sending emails, messages, or publishing content.',
              standards: { owaspAgentic: ['ASI02', 'ASI09'], aiuc1: ['B003'], iso42001: ['A.8.3'], nistAiRmf: ['MANAGE-2.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-014',
    name: 'Tool description too vague',
    domain: 'tool-safety',
    severity: 'medium',
    confidence: 'medium',
    description: 'Tool has a description shorter than 20 characters, making it hard for the LLM to use correctly.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02'], aiuc1: ['A002'], iso42001: ['A.8.2'], nistAiRmf: ['MAP-1.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const tool of graph.tools) {
        // Only flag non-empty descriptions that are too short; empty means parser couldn't extract it
        if (tool.description.length > 0 && tool.description.length < 20) {
          findings.push({
            id: `AA-TS-014-${findings.length}`,
            ruleId: 'AA-TS-014',
            title: 'Tool description too vague',
            description: `Tool "${tool.name}" in ${tool.file} has a description of only ${tool.description.length} characters ("${tool.description}"). Vague descriptions cause incorrect tool usage by the LLM.`,
            severity: 'medium',
            confidence: 'medium',
            domain: 'tool-safety',
            location: { file: tool.file, line: tool.line },
            remediation: 'Provide a detailed description (20+ characters) explaining what the tool does, its inputs, and its side effects.',
            standards: { owaspAgentic: ['ASI02'], aiuc1: ['A002'], iso42001: ['A.8.2'], nistAiRmf: ['MAP-1.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-015',
    name: 'Agent has too many tools (>15)',
    domain: 'tool-safety',
    severity: 'medium',
    confidence: 'medium',
    description: 'A single agent has more than 15 tools attached, increasing confusion and attack surface.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02'], aiuc1: ['B003'], iso42001: ['A.5.3'], nistAiRmf: ['MAP-2.3'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const agent of graph.agents) {
        if (agent.tools.length > 15) {
          findings.push({
            id: `AA-TS-015-${findings.length}`,
            ruleId: 'AA-TS-015',
            title: 'Agent has too many tools',
            description: `Agent "${agent.name}" in ${agent.file} has ${agent.tools.length} tools attached. Per-agent tool count exceeds 15, increasing attack surface and potential for misuse.`,
            severity: 'medium',
            confidence: 'medium',
            domain: 'tool-safety',
            location: { file: agent.file, line: agent.line },
            remediation: 'Reduce the number of tools per agent. Split into specialized agents with fewer, focused tools.',
            standards: { owaspAgentic: ['ASI02'], aiuc1: ['B003'], iso42001: ['A.5.3'], nistAiRmf: ['MAP-2.3'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-016',
    name: 'Tool lacks input validation',
    domain: 'tool-safety',
    severity: 'high',
    confidence: 'high',
    description: 'Tool has parameters but none are validated, and the tool has side effects.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02'], aiuc1: ['A002', 'B003'], iso42001: ['A.5.3'], nistAiRmf: ['MAP-2.3'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const tool of graph.tools) {
        if (
          tool.parameters.length > 0 &&
          !tool.parameters.some(p => p.hasValidation) &&
          tool.hasSideEffects
        ) {
          findings.push({
            id: `AA-TS-016-${findings.length}`,
            ruleId: 'AA-TS-016',
            title: 'Tool lacks input validation',
            description: `Tool "${tool.name}" in ${tool.file} has ${tool.parameters.length} parameter(s) but none are validated, and the tool has side effects.`,
            severity: 'high',
            confidence: 'high',
            domain: 'tool-safety',
            location: { file: tool.file, line: tool.line },
            remediation: 'Add input validation (type checks, length limits, allowlists) to all tool parameters, especially for tools with side effects.',
            standards: { owaspAgentic: ['ASI02'], aiuc1: ['A002', 'B003'], iso42001: ['A.5.3'], nistAiRmf: ['MAP-2.3'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-017',
    name: 'Tool with delete capability',
    domain: 'tool-safety',
    severity: 'high',
    confidence: 'medium',
    description: 'Tool name or description indicates destructive delete/remove/drop/destroy capability without confirmation.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02', 'ASI09'], aiuc1: ['B003'], iso42001: ['A.8.3'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const destructivePattern = /(?:delete|remove|drop|destroy|purge)/i;
      const confirmPattern = /(?:confirm|approval|approve|human.?in.?the.?loop)/i;
      for (const tool of graph.tools) {
        const nameOrDesc = `${tool.name} ${tool.description}`;
        if (destructivePattern.test(nameOrDesc) && !confirmPattern.test(tool.description)) {
          findings.push({
            id: `AA-TS-017-${findings.length}`,
            ruleId: 'AA-TS-017',
            title: 'Tool with delete capability',
            description: `Tool "${tool.name}" in ${tool.file} has destructive capability (delete/remove/drop/destroy/purge) without a confirmation mechanism.`,
            severity: 'high',
            confidence: 'medium',
            domain: 'tool-safety',
            location: { file: tool.file, line: tool.line },
            remediation: 'Add human confirmation or approval step before executing destructive operations.',
            standards: { owaspAgentic: ['ASI02', 'ASI09'], aiuc1: ['B003'], iso42001: ['A.8.3'], nistAiRmf: ['MANAGE-2.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-018',
    name: 'Tool can modify agent config',
    domain: 'tool-safety',
    severity: 'critical',
    confidence: 'medium',
    description: 'Tool can write to configuration files, system prompts, or agent settings, risking self-modification.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02', 'ASI10'], aiuc1: ['B003'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const configModifyRegex = /(?:write|save|update|modify).*(?:config|prompt|setting|system_message)/gi;
      const toolContextRegex = /(?:tool|function|def\s|@tool|StructuredTool|BaseTool)/;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }
        configModifyRegex.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = configModifyRegex.exec(content)) !== null) {
          const start = Math.max(0, match.index - 500);
          const end = Math.min(content.length, match.index + match[0].length + 200);
          const region = content.substring(start, end);
          if (toolContextRegex.test(region)) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-TS-018-${findings.length}`,
              ruleId: 'AA-TS-018',
              title: 'Tool can modify agent config',
              description: `Code in ${file.relativePath} can modify agent configuration/prompts/settings within a tool context.`,
              severity: 'critical',
              confidence: 'medium',
              domain: 'tool-safety',
              location: { file: file.relativePath, line, snippet: match[0] },
              remediation: 'Prevent tools from modifying agent configuration, system prompts, or settings. Make config read-only to tool execution.',
              standards: { owaspAgentic: ['ASI02', 'ASI10'], aiuc1: ['B003'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-019',
    name: 'HTTP tool without TLS',
    domain: 'tool-safety',
    severity: 'medium',
    confidence: 'high',
    description: 'Tool or API call uses plain HTTP instead of HTTPS, exposing data in transit.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02'], aiuc1: ['E001'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const httpRegex = /["']http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/g;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }
        httpRegex.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = httpRegex.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-TS-019-${findings.length}`,
            ruleId: 'AA-TS-019',
            title: 'HTTP tool without TLS',
            description: `Plain HTTP URL found in ${file.relativePath} at line ${line}. Data in transit is not encrypted.`,
            severity: 'medium',
            confidence: 'high',
            domain: 'tool-safety',
            location: { file: file.relativePath, line, snippet: content.substring(match.index, match.index + 60) },
            remediation: 'Use HTTPS instead of HTTP for all external URLs to ensure data is encrypted in transit.',
            standards: { owaspAgentic: ['ASI02'], aiuc1: ['E001'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-020',
    name: 'Tool timeout not configured',
    domain: 'tool-safety',
    severity: 'medium',
    confidence: 'medium',
    description: 'HTTP/API calls in tool code lack a timeout configuration, risking indefinite hangs.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02', 'ASI08'], aiuc1: ['B003'], iso42001: ['A.9.2'], nistAiRmf: ['MANAGE-3.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const httpCallRegex = /(?:requests\.(?:get|post|put|patch|delete)|fetch|axios)\s*\(/g;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }
        httpCallRegex.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = httpCallRegex.exec(content)) !== null) {
          const start = Math.max(0, match.index - 150);
          const end = Math.min(content.length, match.index + match[0].length + 300);
          const region = content.substring(start, end);
          if (!/timeout/i.test(region)) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-TS-020-${findings.length}`,
              ruleId: 'AA-TS-020',
              title: 'Tool timeout not configured',
              description: `HTTP/API call in ${file.relativePath} at line ${line} does not configure a timeout, risking indefinite hangs.`,
              severity: 'medium',
              confidence: 'medium',
              domain: 'tool-safety',
              location: { file: file.relativePath, line, snippet: match[0] },
              remediation: 'Add a timeout parameter to all HTTP/API calls (e.g., requests.get(url, timeout=30), fetch with AbortController).',
              standards: { owaspAgentic: ['ASI02', 'ASI08'], aiuc1: ['B003'], iso42001: ['A.9.2'], nistAiRmf: ['MANAGE-3.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
];
