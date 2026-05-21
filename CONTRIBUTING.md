# Contributing to Supply Chain Guard

Thanks for taking the time to contribute. This document explains how to get set
up, how to verify your changes, and how to report problems.

## Development Setup

Supply Chain Guard is a Bun + TypeScript project.

```sh
git clone https://github.com/pc-style/supply-chain-guard.git
cd supply-chain-guard
bun install
```

To run the CLI locally without installing it globally:

```sh
bun run scguard -- --help
bun run scguard -- review left-pad
```

## Running the Checks

The single command you need before opening a PR is:

```sh
bun run check
```

This runs:

1. `bunx tsc --noEmit` for type-checking
2. `scguard --help` to make sure the help text still renders
3. `scguard self-test` to run analysis against the bundled fixtures
4. `bun test` for the unit-test suites under `src/*.test.ts`

If any step fails, the change is not ready to land.

## Filing Issues

Use the [issue tracker](https://github.com/pc-style/supply-chain-guard/issues)
and pick the **Bug report** or **Feature request** template. Include:

- The Supply Chain Guard version (`scguard version`)
- Your OS and Bun version (`bun --version`)
- Steps to reproduce
- What you expected vs. what you got

## Reporting Security Issues

Do not file public issues for security problems. Follow the disclosure process
in [SECURITY.md](./SECURITY.md).

## Pull Requests

- Keep PRs focused. One concern per PR is easier to review.
- Add or update tests for any behavior change.
- Update the README and the relevant docs when you change a public-facing
  surface (CLI flags, report shape, env vars).
- Add an entry to `CHANGELOG.md` under `## [Unreleased]` describing the change.
- Use clear, descriptive commit messages. Conventional Commits
  (`feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `test:`) are encouraged but
  not required; what matters is that the subject line tells a future reader
  what changed and why.

## Code Style

- TypeScript `strict` is on. Avoid `any` unless you have a good reason.
- Prefer small, focused modules. Keep the deterministic analyzer pure and free
  of network calls; network/intelligence checks live behind the
  `--offline` / `SCGUARD_OFFLINE` switch and must degrade gracefully.
- No emojis in source, comments, or output.

## License

By contributing you agree that your contributions are licensed under the same
MIT license that covers this repository (see `LICENSE`).
