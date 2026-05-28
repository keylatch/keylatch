// Minimal Node.js process declaration for TypeScript syntax checking without @types/node.
// fetch, Response, AbortSignal, and console are covered by TypeScript's built-in lib.
declare var process: {
  env: Record<string, string | undefined>;
  exit(code?: number): never;
};
