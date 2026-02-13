import type { SyntaxNode, Tree } from './parser.js';
import { findNodes, findFunctionCalls } from './queries.js';

export function findObjectProperty(
  tree: Tree,
  objectName: string,
  propName: string,
): SyntaxNode[] {
  return findNodes(tree, (node) => {
    if (node.type !== 'member_expression' && node.type !== 'property_access_expression')
      return false;
    const obj = node.childForFieldName('object');
    const prop = node.childForFieldName('property');
    return obj?.text === objectName && prop?.text === propName;
  });
}

export function findRouteHandlers(tree: Tree): { node: SyntaxNode; path: string }[] {
  const handlers: { node: SyntaxNode; path: string }[] = [];

  // JS/TS Express: app.get('/path', handler), app.post('/path', handler)
  const expressCalls = findFunctionCalls(tree, /^app\.(get|post|put|delete|patch|route)$/);
  for (const call of expressCalls) {
    const args = call.childForFieldName('arguments');
    if (!args) continue;
    const pathArg = args.children.find(
      (c) => c.type === 'string' || c.type === 'string_literal' || c.type === 'template_string',
    );
    const pathText = pathArg?.text?.replace(/^["'`]|["'`]$/g, '') ?? '';
    handlers.push({ node: call, path: pathText });
  }

  // Python Flask/FastAPI decorators: @app.route('/path'), @app.post('/path')
  const routeDecorators = findNodes(tree, (node) => {
    if (node.type !== 'decorator') return false;
    return /app\.(route|get|post|put|delete|patch)/.test(node.text);
  });
  for (const dec of routeDecorators) {
    const pathMatch = dec.text.match(/["']([^"']+)["']/);
    handlers.push({ node: dec, path: pathMatch?.[1] ?? '' });
  }

  return handlers;
}

export function findTemplateWithInterpolation(tree: Tree): SyntaxNode[] {
  return findNodes(tree, (node) => {
    if (node.type !== 'template_string') return false;
    return node.children.some((c) => c.type === 'template_substitution');
  });
}

export function findTryCatchStatements(tree: Tree): SyntaxNode[] {
  return findNodes(tree, (node) => node.type === 'try_statement');
}

export function findNewExpressions(
  tree: Tree,
  className?: string | RegExp,
): SyntaxNode[] {
  return findNodes(tree, (node) => {
    if (node.type !== 'new_expression') return false;
    if (!className) return true;
    const constructor = node.childForFieldName('constructor');
    if (!constructor) return false;
    if (typeof className === 'string') return constructor.text === className;
    return className.test(constructor.text);
  });
}
