# Repository Guidelines

## Build & Test
- **Install:** `bun install`
- **Build:** `bun run build` (runs `tsc` for type checking)
- **Test All:** `bun test`
- **Test Single:** `bun test path/to/file.test.ts`
- **Deploy:** `npx cdk deploy`

## Code Style & Conventions
- **Format:** 2-space indentation, semicolons required.
- **Naming:** `camelCase` for vars/funcs, `PascalCase` for classes/types.
- **Types:** Strict TS. Define shared types in `lambdas/shared/types.ts`.
- **Imports:** ESM. Group: AWS SDK -> Shared/Lib -> Local.
- **Structure:** 
  - Core logic: `lambdas/shared/`
  - Handlers: `lambdas/step-functions/` or `lambdas/durable/`
  - Infra: `infra/stack.ts` (AWS CDK v2)
- **Stack:** Node.js 24.x, AWS SDK v3, Bun for deps/scripts.
- **Errors:** Throw descriptive `Error` objects for Step Functions retries.
