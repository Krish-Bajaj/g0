import * as fs from 'node:fs';
import type { FileInventory } from '../../types/common.js';
import type { AgentGraph } from '../../types/agent-graph.js';

interface VectorDBPattern {
  importPattern: RegExp;
  constructorPattern: RegExp;
  name: string;
  framework: string;
}

const VECTORDB_PATTERNS: VectorDBPattern[] = [
  {
    importPattern: /(?:from\s+pinecone|import\s+.*pinecone|require\(.*pinecone)/i,
    constructorPattern: /Pinecone\s*\(/,
    name: 'Pinecone',
    framework: 'pinecone',
  },
  {
    importPattern: /(?:from\s+chromadb|import\s+.*chromadb|require\(.*chroma)/i,
    constructorPattern: /(?:Chroma|ChromaDB|chromadb\.Client)\s*\(/,
    name: 'ChromaDB',
    framework: 'chromadb',
  },
  {
    importPattern: /(?:import\s+faiss|from\s+.*faiss|langchain.*faiss)/i,
    constructorPattern: /(?:FAISS|faiss\.Index)\s*[.(]/,
    name: 'FAISS',
    framework: 'faiss',
  },
  {
    importPattern: /(?:from\s+weaviate|import\s+.*weaviate|require\(.*weaviate)/i,
    constructorPattern: /(?:weaviate\.Client|WeaviateClient)\s*\(/,
    name: 'Weaviate',
    framework: 'weaviate',
  },
  {
    importPattern: /(?:from\s+qdrant|import\s+.*qdrant|require\(.*qdrant)/i,
    constructorPattern: /QdrantClient\s*\(/,
    name: 'Qdrant',
    framework: 'qdrant',
  },
  {
    importPattern: /(?:from\s+pymilvus|import\s+.*milvus|require\(.*milvus)/i,
    constructorPattern: /(?:Milvus|MilvusClient|connections\.connect)\s*\(/,
    name: 'Milvus',
    framework: 'milvus',
  },
  {
    importPattern: /pgvector|PGVector/,
    constructorPattern: /PGVector\s*\(/,
    name: 'pgvector',
    framework: 'pgvector',
  },
];

export function detectVectorDBs(graph: AgentGraph, files: FileInventory): void {
  const codeFiles = [
    ...files.python,
    ...files.typescript,
    ...files.javascript,
  ];

  for (const file of codeFiles) {
    let content: string;
    try {
      content = fs.readFileSync(file.path, 'utf-8');
    } catch {
      continue;
    }

    for (const { importPattern, constructorPattern, name, framework } of VECTORDB_PATTERNS) {
      if (importPattern.test(content) || constructorPattern.test(content)) {
        // Find the line number of the constructor or import
        const lines = content.split('\n');
        let line = 1;
        for (let i = 0; i < lines.length; i++) {
          if (constructorPattern.test(lines[i]) || importPattern.test(lines[i])) {
            line = i + 1;
            break;
          }
        }

        // Avoid duplicates
        const exists = graph.vectorDBs.some(
          v => v.name === name && v.file === file.relativePath,
        );
        if (!exists) {
          graph.vectorDBs.push({
            id: `vectordb-${graph.vectorDBs.length}`,
            name,
            framework,
            file: file.relativePath,
            line,
          });
        }
      }
    }
  }
}
