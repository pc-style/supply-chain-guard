# Supply Chain Guard

Inspect npm packages and VS Code extensions before they touch your project.

> [!IMPORTANT]
> **Status: beta.** The CLI, report schema, and policies can change before 1.0. The current compatibility target is Bun 1.3.14 on macOS and Linux.

> [!WARNING]
> Supply Chain Guard can miss malicious packages, flag safe packages, and break package-manager flows. Treat it as a warning layer, not proof that a dependency is safe.

Website: [scguard.pcstyle.dev](https://scguard.pcstyle.dev/)

## Install

There is no tagged release yet. Install the currently reviewed source snapshot by immutable commit:

```sh
REF=666e7f338c6bc4f0187c18c0f6f2d846c47ac077
git init "$HOME/.local/share/supply-chain-guard"
git -C "$HOME/.local/share/supply-chain-guard" remote add origin https://github.com/pc-style/supply-chain-guard.git
git -C "$HOME/.local/share/supply-chain-guard" fetch --depth 1 origin "$REF"
git -C "$HOME/.local/share/supply-chain-guard" checkout --detach "$REF"
(
  cd "$HOME/.local/share/supply-chain-guard"
  bun install --frozen-lockfile
  bun run build
)
mkdir -p "$HOME/.local/bin"
cp "$HOME/.local/share/supply-chain-guard/dist/scguard" "$HOME/.local/bin/scguard"
chmod +x "$HOME/.local/bin/scguard"
scguard config
eval "$(scguard shell-hook)"
```

This pins both source and dependencies but does not provide a signed binary or published checksum. Review and change `REF` deliberately when updating. `install.sh` uses the same immutable commit by default and accepts an explicit `SCGUARD_REF`; callers must still obtain and review the installer script itself.

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

## Trust and privacy boundaries

- Static analysis and reports run locally. Reports can include package names, paths, findings, and selected source evidence; they remain under `.scguard/reports` unless you share them.
- Online mode downloads public package or extension artifacts and queries npm, OSV, and—when configured with a token and organization—Socket using package identifiers. `--offline` disables those network checks.
- `--agent codex` and `--agent pi` pass the generated review prompt and report content to the selected local CLI. That CLI may send the content to its configured model provider; do not enable agent review for private artifacts unless that provider is acceptable.
- The gate is not a sandbox. Package installation runs through the selected package manager after approval and retains that package manager's normal privileges.

This repository is the canonical successor to [`pc-style/npm-registry-rewrite`](docs/npm-registry-rewrite-lineage.md); the lineage note records the inherited registry-integrity safety property without claiming a verbatim code copy. The existing MIT license covers the source. No release artifacts are currently signed or published.

## Development

Supply Chain Guard requires Bun plus `git`, `tar`, and `unzip`. It has no production npm dependencies.

```sh
git clone https://github.com/pc-style/supply-chain-guard.git
cd supply-chain-guard
bun install
bun run check
```

Run the source CLI with `bun run scguard -- <args>`. See [CONTRIBUTING.md](./CONTRIBUTING.md), [CHANGELOG.md](./CHANGELOG.md), [SECURITY.md](./SECURITY.md), and [AGENTS.md](./AGENTS.md).
