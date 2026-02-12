import * as fs from 'node:fs';
import type { Tree, ASTLanguage } from './parser.js';
import { parseCode, getASTLanguage } from './parser.js';

const contentCache = new Map<string, string>();
const treeCache = new Map<string, Tree | null>();

export function getFileContent(filePath: string): string | null {
  if (contentCache.has(filePath)) return contentCache.get(filePath)!;
  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    contentCache.set(filePath, content);
    return content;
  } catch {
    return null;
  }
}

export function getFileTree(filePath: string, content?: string): Tree | null {
  if (treeCache.has(filePath)) return treeCache.get(filePath)!;

  const lang = getASTLanguage(filePath);
  if (!lang) return null;

  const src = content ?? getFileContent(filePath);
  if (!src) return null;

  const tree = parseCode(src, lang);
  treeCache.set(filePath, tree);
  return tree;
}

export function getFileTreeForLang(filePath: string, content: string, lang: ASTLanguage): Tree | null {
  if (treeCache.has(filePath)) return treeCache.get(filePath)!;
  const tree = parseCode(content, lang);
  treeCache.set(filePath, tree);
  return tree;
}

export function clearASTCache(): void {
  contentCache.clear();
  treeCache.clear();
}
