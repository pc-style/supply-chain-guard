# AGENTS.md

## Cursor Cloud specific instructions

### Overview

Supply Chain Guard is a Bun+TypeScript CLI that inspects npm packages and VS Code extensions before installation. The published CLI has no production npm dependencies; this repo uses dev-only packages (Biome, Playwright for demos, `@types/bun`) for development and testing. There is no backend, no database, and no Docker dependency.

### Runtime

- **Bun** is the only runtime required. It serves as the package manager, test runner, and build tool.
- System tools `git`, `tar`, and `unzip` must be available (pre-installed on most systems).

### Key commands

All commands are documented in `package.json` scripts:

| Task | Command |
|------|---------|
| Install deps | `bun install` |
| Lint / format | `bun run lint` / `bun run format` |
| Type check | `bun run typecheck` |
| Unit tests | `bun run test` |
| Full CI check | `bun run check` |
| Run CLI | `bun run scguard -- <args>` |
| Agent integration | `bun run scguard -- skill install` (runs `npx skills add pc-style/supply-chain-guard -y --skill supply-chain-guard`) |
| Build binary | `bun run build` |

`bun run check` is the single pre-PR gate — it runs Biome, typecheck, help render, self-test on fixtures, and the full unit test suite. Bun `1.3.14` is pinned in `package.json` `engines` and CI.

### Gotchas

- The CLI exit code 1 from `scguard review` is **expected** when findings are high-risk — it means the gate is working. Only exit code from `bun run check` matters for CI.
- npm signature verification (`npm.signature.invalid`) may flag packages in environments without proper npm registry access; use `--offline` to skip network-dependent checks during local dev testing.
- Optional integrations (Socket API, Codex CLI, PI CLI) degrade gracefully when unavailable. Tests do not require them.
- The `.scguard/` directory is created at runtime for reports/cache/work and is git-ignored.
- `site/roadmap.html` is a public progress mirror of `docs/ROADMAP.md`. When you complete a roadmap phase or task (or change the roadmap), update the corresponding status markers (done/in progress/not started, task ticks, "last updated" date) in `site/roadmap.html` in the same PR.
