# Supply Chain Guard

Local install gate for npm packages and VS Code extensions. It analyzes a package artifact before allowing an install, writes JSON/Markdown reports for programmatic review, and can run Codex or PI as a mandatory second-pass reviewer.

## Install Or Update

```sh
curl -fsSL https://raw.githubusercontent.com/pc-style/supply-chain-guard/main/install.sh | bash
```

The installer is also the updater. It clones or pulls the repo into `~/.local/share/supply-chain-guard`, runs `bun install`, creates `~/.local/bin/scguard`, and launches the config TUI.

During install it asks for an optional Socket API token and stores it in `~/.config/supply-chain-guard/env`. Create a token here:

https://socket.dev/dashboard/settings/api-tokens

Recommended Socket scopes:

- `packages:list` for current package score lookup
- `threat-feed:list` later if you want Socket-backed active attack warnings

## Commands

```sh
bun run scguard add <package[@version]> [--dev] [--approve]
bun run scguard add <package[@version]> --agent codex|pi|both --approve
bun run scguard scan-npm <package[@version]> [--json]
bun run scguard scan-vsix <path-to-extension.vsix> [--json]
bun run scguard config
bun run scguard config --show
bun run scguard shell-hook
bun run scguard guard bun|npm|pnpm|yarn|code <args...>
bun run scguard agent-prompt <report.json> --agent codex|pi
bun run scguard agent-review <report.json> --agent codex|pi|both
```

`add` does not install by default. It resolves the package tarball, downloads it to `.scguard/cache`, extracts it to `.scguard/work`, analyzes it, writes reports to `.scguard/reports`, and stops. Add `--approve` to install after the analysis gate passes.

Add `--agent codex`, `--agent pi`, or `--agent both` to run a mandatory coding-agent review before install. The agent must end with `SCGUARD_DECISION: approve`; `reject`, `manual-review`, missing decisions, non-zero exits, or missing agent binaries block the install.

Run `scguard config` to choose the default agent review behavior for every scan and install gate: no agent, Codex, PI, or both. PI runs with `--no-tools --no-context-files`; Codex runs through `codex exec` with a read-only sandbox.

Recommended shell hook:

```sh
eval "$(bun run scguard shell-hook)"
```

After that, habitual commands such as `bun add`, `npm install`, `pnpm update`, `yarn add`, and `code --install-extension ./extension.vsix` go through the guard first. The wrapper emits a weak warning for every package install/update operation because package managers and editor extensions can run untrusted code.

For now, `code --install-extension publisher.name` is blocked because the VS Code CLI would download the extension before this tool can inspect it. Download the `.vsix`, scan it, then install the reviewed artifact.

## Active Supply Chain Incident Mode

Set an advisory when Socket, npm, Microsoft, GitHub, or your own security source reports an active attack:

```sh
export SCGUARD_ACTIVE_INCIDENT="Socket reports active npm supply-chain campaign"
export SCGUARD_ACTIVE_INCIDENT_UNTIL="2026-05-22T12:00:00Z"
```

While active, package operations are staged and analyzed, then the user must type:

```text
I accept the active supply-chain risk
```

If they do not, the install/update command is cancelled.

## Socket Intelligence

Set `SOCKET_API_KEY` to query Socket.dev during npm scans:

```sh
export SOCKET_API_KEY="..."
```

The report records whether Socket was checked, skipped, or errored. If Socket reports elevated `supplyChainRisk`, the guard raises the report risk and can block the install.

## Staging And Takedown Flow

The local staging flow is the `.scguard/cache`, `.scguard/work`, and `.scguard/reports` pipeline. Nothing is installed until analysis completes and approval is explicit.

The local takedown flow is intentionally simple for this first version:

- set `SCGUARD_ACTIVE_INCIDENT` to force explicit acknowledgement on every package operation
- remove the shell hook or unset the advisory after the incident ends
- inspect `.scguard/reports` for the exact packages and artifacts that were staged during the incident

## What It Checks

- install lifecycle scripts such as `preinstall`, `install`, and `postinstall`
- suspicious script text such as `curl | sh`, shell execution, encoded payloads, credential paths, and network fetches
- dependency volume and package metadata signals
- executable `bin` entries
- large files and unusual packed contents
- VS Code extension activation events, main/browser entry points, scripts, and dependency metadata
- Socket.dev package score when `SOCKET_API_KEY` is configured

The first version is intentionally conservative. It blocks installs at `high` risk, warns at `medium`, and always produces report artifacts for agent review.
