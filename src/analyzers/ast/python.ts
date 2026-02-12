import type { SyntaxNode, Tree } from './parser.js';
import { findNodes, getKeywordArgument, extractStringValue } from './queries.js';

export function findDecorators(
  tree: Tree,
  name?: string | RegExp,
): SyntaxNode[] {
  return findNodes(tree, (node) => {
    if (node.type !== 'decorator') return false;
    if (!name) return true;

    const children = node.children.filter((c) => c.type !== '@');
    const expr = children[0];
    if (!expr) return false;

    const text = expr.text;
    if (typeof name === 'string') {
      return text === name || text.startsWith(name + '(') || text.startsWith(name + '.');
    }
    return name.test(text);
  });
}

export function getDecoratedFunction(decorator: SyntaxNode): SyntaxNode | null {
  const parent = decorator.parent;
  if (parent?.type !== 'decorated_definition') return null;
  return parent.children.find((c) => c.type === 'function_definition') ?? null;
}

export function findFStrings(tree: Tree): SyntaxNode[] {
  return findNodes(tree, (node) => {
    if (node.type !== 'string') return false;
    return (
      node.children.some((c) => c.type === 'interpolation') ||
      node.text.startsWith('f"') ||
      node.text.startsWith("f'") ||
      node.text.startsWith('f"""') ||
      node.text.startsWith("f'''")
    );
  });
}

export function findClassDefinitions(
  tree: Tree,
  name?: string | RegExp,
): SyntaxNode[] {
  return findNodes(tree, (node) => {
    if (node.type !== 'class_definition') return false;
    if (!name) return true;
    const nameNode = node.childForFieldName('name');
    if (!nameNode) return false;
    if (typeof name === 'string') return nameNode.text === name;
    return name.test(nameNode.text);
  });
}

export function getKeywordArgBool(
  callNode: SyntaxNode,
  name: string,
): boolean | null {
  const value = getKeywordArgument(callNode, name);
  if (!value) return null;
  if (value.type === 'true' || value.text === 'True' || value.text === 'true') return true;
  if (value.type === 'false' || value.text === 'False' || value.text === 'false') return false;
  return null;
}

export function getKeywordArgInt(
  callNode: SyntaxNode,
  name: string,
): number | null {
  const value = getKeywordArgument(callNode, name);
  if (!value) return null;
  if (value.type === 'integer' || value.type === 'number') {
    const num = parseInt(value.text);
    return isNaN(num) ? null : num;
  }
  return null;
}

export function getKeywordArgString(
  callNode: SyntaxNode,
  name: string,
): string | null {
  const value = getKeywordArgument(callNode, name);
  if (!value) return null;
  return extractStringValue(value);
}
