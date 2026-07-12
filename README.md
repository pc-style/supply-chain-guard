# Supply Chain Guard

Inspect npm packages and VS Code extensions before they touch your project.

> [!WARNING]
> Supply Chain Guard is early-stage software. It can miss malicious packages, flag safe packages, and break package-manager flows. Treat it as a warning layer, not proof that a dependency is safe.

Website: [scguard.pcstyle.dev](https://scguard.pcstyle.dev/)

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/pc-style/supply-chain-guard/main/install.sh | bash
eval "$(scguard shell-hook)"
```

The installer clones or updates the project under `~/.local/share/supply-chain-guard`, builds the Bun executable, and links `~/.local/bin/scguard`.

## Use

Review without installing:

```sh
scguard review axios
```

Review, then pass the original package-manager options through to the install:

```sh
scguard install react@19 --dev --exact
scguard install react@19 --pm npm --legacy-peer-deps
```

The shell hook guards `bun`, `npm`, `pnpm`, `yarn`, and local `.vsix` installs through `code`. Bare installs scan the lockfile. The default policy checks versions published within seven days and entries changed since `.scguard/lockfile-baseline.json`; strict uses a 30-day window. Scan failures and hard security findings block the install.

Run an optional agent review with `--agent codex` or `--agent pi`. An explicit rejection or manual-review decision blocks. Agent errors warn under the default policy and block under strict policy.

## Commands

```text
scguard review <package> [--agent codex|pi] [--offline]
scguard install <package> [--pm bun|npm|pnpm|yarn] [install options]
scguard guard bun|npm|pnpm|yarn|code <args...>
scguard shell-hook [--fish]
scguard scan-vsix <extension.vsix> [--json]
scguard doctor
scguard config [--show] [--preset default|strict] [--agent none|codex|pi]
scguard self-test
scguard clean --reports|--cache|--work|--all
scguard skill install [--dry-run] [--skill-source <source>]
```

`clean` removes generated `.scguard` reports, cache, or work directories. `skill install` installs the bundled Supply Chain Guard agent skill through the Vercel skills CLI.

## Reports and checks

Each review writes JSON and Markdown under `.scguard/reports`. The scanner checks lifecycle scripts, suspicious code and credential access, package metadata, executable entries, unusual files, extension activation, Socket scores, OSV advisories, npm signatures, and package-name similarity. Network checks degrade clearly when unavailable and can be disabled with `--offline` or `SCGUARD_OFFLINE=1`.

Socket intelligence uses the org-scoped PURL endpoint and skips safely unless both values are set:

```sh
export SOCKET_API_KEY="..."
export SOCKET_ORG_SLUG="your-org-slug"
```

Public `SCGUARD_*` controls are limited to:

- `SCGUARD_BYPASS=1` runs one guarded command without checks.
- `SCGUARD_OFFLINE=1` disables network checks.
- `SCGUARD_DEBUG=1` prints diagnostic details.
- `SCGUARD_NO_COLOR=1` disables ANSI color. Standard `NO_COLOR` also works.

Package IDs passed to `code --install-extension` are blocked because the editor would download them before inspection. Download the `.vsix`, run `scguard scan-vsix`, then install the reviewed file.

## Development

Supply Chain Guard requires Bun plus `git`, `tar`, and `unzip`. It has no production npm dependencies.

```sh
git clone https://github.com/pc-style/supply-chain-guard.git
cd supply-chain-guard
bun install
bun run check
```

Run the source CLI with `bun run scguard -- <args>`. See [CONTRIBUTING.md](./CONTRIBUTING.md), [CHANGELOG.md](./CHANGELOG.md), [SECURITY.md](./SECURITY.md), and [AGENTS.md](./AGENTS.md).
