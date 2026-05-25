# AGENTS.md

## Cursor Cloud specific instructions

### Overview

Supply Chain Guard is a zero-dependency Bun+TypeScript CLI that inspects npm packages and VS Code extensions before installation. There is no backend, no database, and no Docker dependency.

### Runtime

- **Bun** is the only runtime required. It serves as the package manager, test runner, and build tool.
- System tools `git`, `tar`, and `unzip` must be available (pre-installed on most systems).

### Key commands

All commands are documented in `package.json` scripts:

| Task | Command |
|------|---------|
| Install deps | `bun install` |
| Type check | `bun run typecheck` |
| Unit tests | `bun run test` |
| Full CI check | `bun run check` |
| Run CLI | `bun run scguard -- <args>` |
| Build binary | `bun run build` |

`bun run check` is the single pre-PR gate — it runs typecheck, help render, self-test on fixtures, and the full unit test suite.

### Gotchas

- The CLI exit code 1 from `scguard review` is **expected** when findings are high-risk — it means the gate is working. Only exit code from `bun run check` matters for CI.
- npm signature verification (`npm.signature.invalid`) may flag packages in environments without proper npm registry access; use `--offline` to skip network-dependent checks during local dev testing.
- Optional integrations (Socket API, Codex CLI, PI CLI) degrade gracefully when unavailable. Tests do not require them.
- The `.scguard/` directory is created at runtime for reports/cache/work and is git-ignored.
