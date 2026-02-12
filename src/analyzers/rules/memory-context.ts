import * as fs from 'node:fs';
import type { Rule } from '../../types/control.js';
import type { Finding } from '../../types/finding.js';
import type { AgentGraph } from '../../types/agent-graph.js';
import {
  isTreeSitterAvailable,
  getFileTreeForLang,
  findFunctionCalls,
  getKeywordArgument,
} from '../ast/index.js';

export const memoryContextRules: Rule[] = [
  {
    id: 'AA-MP-001',
    name: 'Unbounded conversation memory',
    domain: 'memory-context',
    severity: 'medium',
    confidence: 'medium',
    description: 'Conversation memory has no size limits, risking context window overflow and memory poisoning.',
    frameworks: ['langchain', 'crewai'],
    owaspAgentic: ['ASI06'],
    standards: { owaspAgentic: ['ASI06'], aiuc1: ['F001'], iso42001: ['A.9.2'], nistAiRmf: ['MANAGE-3.1'] },
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
          // AST: find ConversationBufferMemory calls, verify no k kwarg
          const bufferCalls = findFunctionCalls(tree, 'ConversationBufferMemory');
          const windowCalls = findFunctionCalls(tree, 'ConversationBufferWindowMemory');

          // If using WindowMemory, skip (it has built-in bounds)
          if (windowCalls.length > 0) continue;

          for (const call of bufferCalls) {
            const kArg = getKeywordArgument(call, 'k');
            if (kArg) continue; // Has a limit

            const line = call.startPosition.row + 1;
            findings.push({
              id: `AA-MP-001-${findings.length}`,
              ruleId: 'AA-MP-001',
              title: 'Unbounded conversation memory',
              description: `ConversationBufferMemory in ${file.relativePath} stores all messages without limits.`,
              severity: 'medium',
              confidence: 'medium',
              domain: 'memory-context',
              location: { file: file.relativePath, line, snippet: 'ConversationBufferMemory()' },
              remediation: 'Use ConversationBufferWindowMemory with k parameter or ConversationSummaryMemory.',
              standards: { owaspAgentic: ['ASI06'], aiuc1: ['F001'], iso42001: ['A.9.2'], nistAiRmf: ['MANAGE-3.1'] },
            });
          }
        } else {
          // Regex fallback
          if (/ConversationBufferMemory\s*\(/.test(content) && !/ConversationBufferWindowMemory/.test(content)) {
            const match = content.match(/ConversationBufferMemory\s*\(/);
            if (match) {
              const line = content.substring(0, match.index!).split('\n').length;
              findings.push({
                id: `AA-MP-001-${findings.length}`,
                ruleId: 'AA-MP-001',
                title: 'Unbounded conversation memory',
                description: `ConversationBufferMemory in ${file.relativePath} stores all messages without limits.`,
                severity: 'medium',
                confidence: 'medium',
                domain: 'memory-context',
                location: { file: file.relativePath, line, snippet: 'ConversationBufferMemory()' },
                remediation: 'Use ConversationBufferWindowMemory with k parameter or ConversationSummaryMemory.',
                standards: { owaspAgentic: ['ASI06'], aiuc1: ['F001'], iso42001: ['A.9.2'], nistAiRmf: ['MANAGE-3.1'] },
              });
            }
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-MP-002',
    name: 'No session isolation in memory',
    domain: 'memory-context',
    severity: 'high',
    confidence: 'medium',
    description: 'Memory store has no session isolation, allowing cross-user data leakage.',
    frameworks: ['langchain', 'crewai'],
    owaspAgentic: ['ASI06'],
    standards: { owaspAgentic: ['ASI06'], aiuc1: ['F001', 'F002'], iso42001: ['A.6.3'], nistAiRmf: ['MEASURE-2.1'] },
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
          // AST: find memory store constructors, check for session_id kwarg
          const memoryCallPatterns = /(?:Redis|Postgres|Mongo|SQLite)ChatMessageHistory$/;
          const memoryCalls = findFunctionCalls(tree, memoryCallPatterns);

          for (const call of memoryCalls) {
            const hasSession =
              getKeywordArgument(call, 'session_id') !== null ||
              getKeywordArgument(call, 'user_id') !== null ||
              getKeywordArgument(call, 'namespace') !== null ||
              getKeywordArgument(call, 'prefix') !== null;

            if (!hasSession) {
              const line = call.startPosition.row + 1;
              const callee = call.childForFieldName('function');
              findings.push({
                id: `AA-MP-002-${findings.length}`,
                ruleId: 'AA-MP-002',
                title: 'No session isolation in memory',
                description: `Memory store in ${file.relativePath} has no apparent session isolation.`,
                severity: 'high',
                confidence: 'medium',
                domain: 'memory-context',
                location: { file: file.relativePath, line, snippet: callee?.text ?? call.text.substring(0, 40) },
                remediation: 'Add session_id or user_id to memory stores to isolate user data.',
                standards: { owaspAgentic: ['ASI06'], aiuc1: ['F001', 'F002'], iso42001: ['A.6.3'], nistAiRmf: ['MEASURE-2.1'] },
              });
            }
          }
        } else {
          // Regex fallback
          const memoryPatterns = [
            /(?:Redis|Postgres|Mongo|SQLite)ChatMessageHistory\s*\(/g,
            /RedisChatMessageHistory\s*\(/g,
            /PostgresChatMessageHistory\s*\(/g,
          ];

          for (const pattern of memoryPatterns) {
            pattern.lastIndex = 0;
            let match: RegExpExecArray | null;
            while ((match = pattern.exec(content)) !== null) {
              const region = content.substring(match.index, match.index + 500);
              const hasSessionId = /session_id|user_id|namespace|prefix/i.test(region);

              if (!hasSessionId) {
                const line = content.substring(0, match.index).split('\n').length;
                findings.push({
                  id: `AA-MP-002-${findings.length}`,
                  ruleId: 'AA-MP-002',
                  title: 'No session isolation in memory',
                  description: `Memory store in ${file.relativePath} has no apparent session isolation.`,
                  severity: 'high',
                  confidence: 'medium',
                  domain: 'memory-context',
                  location: { file: file.relativePath, line, snippet: match[0] },
                  remediation: 'Add session_id or user_id to memory stores to isolate user data.',
                  standards: { owaspAgentic: ['ASI06'], aiuc1: ['F001', 'F002'], iso42001: ['A.6.3'], nistAiRmf: ['MEASURE-2.1'] },
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
    id: 'AA-MP-003',
    name: 'No TTL on persistent memory',
    domain: 'memory-context',
    severity: 'medium',
    confidence: 'medium',
    description: 'Persistent memory has no TTL, allowing stale or poisoned data to persist indefinitely.',
    frameworks: ['all'],
    owaspAgentic: ['ASI06'],
    standards: { owaspAgentic: ['ASI06'], aiuc1: ['F001'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-3.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const storePatterns = [
          /(?:Redis|Postgres|Mongo|SQLite)(?:Chat)?(?:MessageHistory|Memory|Store)\s*\(/g,
        ];

        for (const pattern of storePatterns) {
          pattern.lastIndex = 0;
          let match: RegExpExecArray | null;
          while ((match = pattern.exec(content)) !== null) {
            const region = content.substring(match.index, match.index + 500);
            const hasTTL = /ttl|expire|max_age|retention/i.test(region);

            if (!hasTTL) {
              const line = content.substring(0, match.index).split('\n').length;
              findings.push({
                id: `AA-MP-003-${findings.length}`,
                ruleId: 'AA-MP-003',
                title: 'No TTL on persistent memory',
                description: `Persistent memory in ${file.relativePath} has no TTL configured.`,
                severity: 'medium',
                confidence: 'medium',
                domain: 'memory-context',
                location: { file: file.relativePath, line, snippet: match[0] },
                remediation: 'Configure TTL on persistent memory stores to limit data retention.',
                standards: { owaspAgentic: ['ASI06'], aiuc1: ['F001'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-3.1'] },
              });
            }
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-MP-004',
    name: 'No memory namespace isolation',
    domain: 'memory-context',
    severity: 'medium',
    confidence: 'medium',
    description: 'Vector store or memory lacks namespace isolation between agents or users.',
    frameworks: ['all'],
    owaspAgentic: ['ASI06'],
    standards: { owaspAgentic: ['ASI06'], aiuc1: ['F001', 'F002'], iso42001: ['A.6.3'], nistAiRmf: ['MEASURE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const vectorPatterns = [
          /(?:Chroma|Pinecone|Weaviate|Qdrant|FAISS)(?:\.from_|Client)\s*\(/g,
        ];

        for (const pattern of vectorPatterns) {
          pattern.lastIndex = 0;
          let match: RegExpExecArray | null;
          while ((match = pattern.exec(content)) !== null) {
            const region = content.substring(match.index, match.index + 500);
            const hasNamespace = /namespace|collection|index_name|tenant/i.test(region);

            if (!hasNamespace) {
              const line = content.substring(0, match.index).split('\n').length;
              findings.push({
                id: `AA-MP-004-${findings.length}`,
                ruleId: 'AA-MP-004',
                title: 'No namespace isolation in vector store',
                description: `Vector store in ${file.relativePath} lacks namespace isolation.`,
                severity: 'medium',
                confidence: 'medium',
                domain: 'memory-context',
                location: { file: file.relativePath, line, snippet: match[0] },
                remediation: 'Use collection names or namespaces to isolate data per agent or user.',
                standards: { owaspAgentic: ['ASI06'], aiuc1: ['F001', 'F002'], iso42001: ['A.6.3'], nistAiRmf: ['MEASURE-2.1'] },
              });
            }
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-MP-005',
    name: 'Shared memory across users',
    domain: 'memory-context',
    severity: 'high',
    confidence: 'medium',
    description: 'Memory instance is declared at module level without user/session scoping, potentially sharing state across users.',
    frameworks: ['langchain', 'crewai'],
    owaspAgentic: ['ASI06'],
    standards: { owaspAgentic: ['ASI06'], aiuc1: ['F001', 'F002'], iso42001: ['A.6.3'], nistAiRmf: ['MEASURE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const memoryPattern = /memory\s*=\s*(?:ConversationBufferMemory|ChatMessageHistory|InMemoryChatMessageHistory)\s*\(/g;
        let match: RegExpExecArray | null;
        while ((match = memoryPattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          // Check if it's module-level (line < 20 or not indented)
          const matchLine = content.split('\n')[line - 1] ?? '';
          const isModuleLevel = line < 20 || /^\S/.test(matchLine);
          if (isModuleLevel) {
            // Check surrounding context for user_id scoping
            const region = content.substring(Math.max(0, match.index - 200), match.index + 200);
            if (!/user_id|session_id|self\./.test(region)) {
              findings.push({
                id: `AA-MP-005-${findings.length}`,
                ruleId: 'AA-MP-005',
                title: 'Shared memory across users',
                description: `Module-level memory instance in ${file.relativePath} may share state across users.`,
                severity: 'high',
                confidence: 'medium',
                domain: 'memory-context',
                location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
                remediation: 'Create memory instances per user/session, not at module level. Pass user_id or session_id.',
                standards: { owaspAgentic: ['ASI06'], aiuc1: ['F001', 'F002'], iso42001: ['A.6.3'], nistAiRmf: ['MEASURE-2.1'] },
              });
            }
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-MP-006',
    name: 'Memory persisted without encryption',
    domain: 'memory-context',
    severity: 'medium',
    confidence: 'medium',
    description: 'Memory data is persisted to disk or storage without encryption.',
    frameworks: ['all'],
    owaspAgentic: ['ASI06'],
    standards: { owaspAgentic: ['ASI06'], aiuc1: ['F001', 'E001'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const persistPattern = /(?:save_to_file|persist|dump|to_json|to_disk)\s*\(/g;
        let match: RegExpExecArray | null;
        while ((match = persistPattern.exec(content)) !== null) {
          // Check nearby context for encryption patterns
          const regionStart = Math.max(0, match.index - 500);
          const regionEnd = Math.min(content.length, match.index + 500);
          const region = content.substring(regionStart, regionEnd);
          const hasEncryption = /encrypt|cipher|crypto|fernet|aes|kms/i.test(region);

          // Also check if this is in a memory-related context
          const hasMemoryContext = /memory|chat|message|conversation|history/i.test(region);

          if (!hasEncryption && hasMemoryContext) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-MP-006-${findings.length}`,
              ruleId: 'AA-MP-006',
              title: 'Memory persisted without encryption',
              description: `Memory persistence in ${file.relativePath} does not appear to use encryption.`,
              severity: 'medium',
              confidence: 'medium',
              domain: 'memory-context',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
              remediation: 'Encrypt memory data before persisting to disk or storage. Use Fernet, AES, or a KMS.',
              standards: { owaspAgentic: ['ASI06'], aiuc1: ['F001', 'E001'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-MP-007',
    name: 'No context length validation',
    domain: 'memory-context',
    severity: 'medium',
    confidence: 'medium',
    description: 'LLM client is instantiated without max_tokens parameter, risking context window overflow.',
    frameworks: ['all'],
    owaspAgentic: ['ASI06'],
    standards: { owaspAgentic: ['ASI06'], aiuc1: ['F001'], iso42001: ['A.9.2'], nistAiRmf: ['MANAGE-3.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        // Skip if the file uses AgentExecutor with max_iterations (framework-level context control)
        if (/AgentExecutor\s*\([\s\S]*?max_iterations/.test(content)) continue;

        const llmPattern = /(?:ChatOpenAI|OpenAI|Anthropic|ChatAnthropic)\s*\(/g;
        let match: RegExpExecArray | null;
        while ((match = llmPattern.exec(content)) !== null) {
          // Check the call region for max_tokens
          const callEnd = content.indexOf(')', match.index + match[0].length);
          const callRegion = content.substring(match.index, callEnd !== -1 ? callEnd + 1 : match.index + 500);
          if (!/max_tokens|max_output_tokens|maxTokens/.test(callRegion)) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-MP-007-${findings.length}`,
              ruleId: 'AA-MP-007',
              title: 'No context length validation',
              description: `LLM client in ${file.relativePath} does not specify max_tokens, risking unbounded responses.`,
              severity: 'medium',
              confidence: 'medium',
              domain: 'memory-context',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
              remediation: 'Set max_tokens parameter on LLM clients to control response length and prevent context overflow.',
              standards: { owaspAgentic: ['ASI06'], aiuc1: ['F001'], iso42001: ['A.9.2'], nistAiRmf: ['MANAGE-3.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-MP-008',
    name: 'RAG retriever without access control',
    domain: 'memory-context',
    severity: 'high',
    confidence: 'medium',
    description: 'RAG retriever is used without access control, potentially exposing data across users.',
    frameworks: ['all'],
    owaspAgentic: ['ASI06'],
    standards: { owaspAgentic: ['ASI06'], aiuc1: ['F002', 'B001'], iso42001: ['A.6.2'], nistAiRmf: ['MEASURE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const retrieverPattern = /(?:as_retriever|VectorStoreRetriever|SelfQueryRetriever)\s*\(/g;
        let match: RegExpExecArray | null;
        while ((match = retrieverPattern.exec(content)) !== null) {
          // Check surrounding context for access control patterns
          const regionStart = Math.max(0, match.index - 300);
          const regionEnd = Math.min(content.length, match.index + 500);
          const region = content.substring(regionStart, regionEnd);
          const hasAccessControl = /user_id|filter|access_control|permission|namespace|tenant/i.test(region);

          if (!hasAccessControl) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-MP-008-${findings.length}`,
              ruleId: 'AA-MP-008',
              title: 'RAG retriever without access control',
              description: `Retriever in ${file.relativePath} has no apparent access control or filtering.`,
              severity: 'high',
              confidence: 'medium',
              domain: 'memory-context',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
              remediation: 'Add user_id filtering, namespace isolation, or access control to RAG retrievers.',
              standards: { owaspAgentic: ['ASI06'], aiuc1: ['F002', 'B001'], iso42001: ['A.6.2'], nistAiRmf: ['MEASURE-2.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
];
