## Supply Chain Guard (scguard)

Managed by `scguard skill install init`. Toggle with `scguard skill install on` / `scguard skill install off`.

### Package managers — required routing

- **Never** run `bun add`, `bun install`, `npm install`, `npm ci`, `pnpm add`, `pnpm install`, `yarn add`, `yarn install`, or `code --install-extension` directly in this repository.
- **Always** use Supply Chain Guard (or an active `scguard` shell hook) for dependency changes:
  - `scguard review <package[@version]>` — download, scan, and report **without** installing
  - `scguard install <package[@version]>` — scan, then install only if the gate (and any configured agent review) passes
  - `scguard guard <bun|npm|pnpm|yarn> <args...>` — wrap a one-off package-manager invocation
- Activate the shell hook in interactive shells: `eval "$(scguard shell-hook)"` (add to shell profile for persistence).

### Commands

| Task | Command |
|------|---------|
| Scan only | `scguard review <pkg[@ver]>` |
| Scan + install | `scguard install <pkg[@ver]>` |
| VS Code extension | `scguard scan-vsix <path.vsix>` |
| Lockfile / bare install | `scguard scan-lockfile` (used by the shell hook) |
| Health check | `scguard doctor` |
| Skip network checks | add `--offline` |

### Exit codes and bypass

- Exit code `1` from `scguard review` usually means findings blocked the install — that is expected, not a broken CLI.
- One-shot bypass (discouraged): `SCGUARD_BYPASS=1 <command>`
- Reports and prompts: `.scguard/reports/`

### Optional agent review

When configured (`scguard config --agent codex|pi|both`), installs may require Codex or PI approval. The agent must end with `SCGUARD_DECISION: approve`.
