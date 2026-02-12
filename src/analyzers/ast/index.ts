export {
  isTreeSitterAvailable,
  parseCode,
  getASTLanguage,
  type SyntaxNode,
  type Tree,
  type ASTLanguage,
} from './parser.js';

export {
  getFileContent,
  getFileTree,
  getFileTreeForLang,
  clearASTCache,
} from './cache.js';

export {
  findNodes,
  findFunctionCalls,
  findImports,
  findAssignments,
  getCallArgument,
  getKeywordArgument,
  extractStringValue,
  isInDangerousContext,
  canDataFlow,
} from './queries.js';

export {
  findDecorators,
  getDecoratedFunction,
  findFStrings,
  findClassDefinitions,
  getKeywordArgBool,
  getKeywordArgInt,
  getKeywordArgString,
} from './python.js';

export {
  findObjectProperty,
  findRouteHandlers,
  findTemplateWithInterpolation,
  findNewExpressions,
} from './typescript.js';
