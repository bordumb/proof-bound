# proofbound-adapter-node

`proofbound-adapter-node` is the strict Node/TypeScript adapter specified by
[Specification 0003](../../docs/specs/0003_typescript_support.md). It exposes
only typed vitest, TypeScript compiler, npm package-reproduction, and vitest
mutation-witness routes. Dependency installation always uses `npm ci
--ignore-scripts`; package scripts, `npm run`, `npm exec`, and `npx` are never
accepted as evidence operations.
