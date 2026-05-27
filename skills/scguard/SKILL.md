---
name: supply-chain-guard
description: >-
  Route npm and VS Code extension installs through Supply Chain Guard (scguard).
  Use when adding dependencies, running package managers, or installing extensions.
  Never call bun/npm/pnpm/yarn install or add directly when this project has scguard enabled.
---

# Supply Chain Guard

This project uses [Supply Chain Guard](https://scguard.pcstyle.dev/) to review packages before they are installed.

## Rules for coding agents

1. **Do not** run `bun add`, `bun install`, `npm install`, `pnpm add`, `yarn add`, or `code --install-extension` unless the project's `AGENTS.md` says scguard is disabled.
2. **Prefer** `scguard review <package[@version]>` to download and analyze without installing.
3. **Use** `scguard install <package[@version]>` when the dependency should be added after the gate passes.
4. **Assume** exit code `1` from `scguard review` means high-risk findings — do not bypass unless the user explicitly requests it.
5. **Run** `scguard doctor` when installs fail unexpectedly (missing shell hook, Socket token, or agent CLIs).

## Common commands

```sh
scguard review axios
scguard install lodash --dev
scguard scan-vsix ./extension.vsix
scguard doctor
eval "$(scguard shell-hook)"   # optional: guard normal PM commands in the shell
```

## Project integration

- Managed instructions live in `AGENTS.md` between `<!-- scguard:agents:BEGIN -->` and `<!-- scguard:agents:END -->`.
- Disable temporarily: `scguard skill install off`
- Re-enable: `scguard skill install on`
