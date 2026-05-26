# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Biome for formatting and linting, wired into `bun run check` and CI.
- `CHANGELOG.md` for contributor release notes.

### Changed

- Pinned Bun to `1.3.14` in `package.json` `engines` and CI.
- README Development section documents clone, install, local CLI, and the pre-PR gate.
- CONTRIBUTING smoke-test example uses `--offline`; test paths and check steps match `package.json`.
- AGENTS.md clarifies zero production npm dependencies vs dev-only tooling.
