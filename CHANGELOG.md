# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `scguard skill` (help) and `scguard skill install` (runs `npx skills add pc-style/supply-chain-guard`) for Codex, Cursor, Pi, and other agents.
- Bundled `skills/scguard/SKILL.md` published with the repo for the Vercel skills CLI.
- Biome for formatting and linting, wired into `bun run check` and CI.
- `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1).
- `CHANGELOG.md` (this file).
- `ACCESSIBILITY.md`, accessibility issue template, PR checklist, and `bun run a11y` CI scan for the marketing site.
- GitHub issue templates for bug reports and feature requests.
- `--json` flag on `scguard review` and `scguard install`.

### Changed

- Pinned Bun to `1.3.14` in `package.json` `engines` and CI.
- README Development section documents clone, install, local CLI, and the pre-PR gate.
- CONTRIBUTING smoke-test example uses `--offline`; test paths and check steps match `package.json`.
- AGENTS.md clarifies zero production npm dependencies vs dev-only tooling.
- Marketing site: skip link, keyboard-operable demo tabs, focus styles, higher-contrast terminal demo colors.
- `CONTRIBUTING.md` and `README.md` link to accessibility and community docs.

## [0.1.1] - 2026-05-25

### Added

- Local install gate for npm packages and VS Code extensions (`scguard review`, `install`, `scan-vsix`, `scan-lockfile`).
- Shell hook for Bun, npm, pnpm, Yarn, and guarded `code --install-extension` for local `.vsix` files.
- JSON and Markdown reports under `.scguard/reports`.
- Optional Socket.dev, OSV, npm signature, and typosquat intelligence (network-dependent).
- Policy presets (`quiet`, `default`, `strict-ci`, `enterprise`, `advisory`).
- Optional Codex and PI agent review integration.
- Static site and demo captures at [scguard.pcstyle.dev](https://scguard.pcstyle.dev/).

[Unreleased]: https://github.com/pc-style/supply-chain-guard/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/pc-style/supply-chain-guard/releases/tag/v0.1.1
