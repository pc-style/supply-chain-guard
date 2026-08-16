# npm-registry-rewrite lineage

Supply Chain Guard succeeds [`pc-style/npm-registry-rewrite`](https://github.com/pc-style/npm-registry-rewrite), which was archived on 2026-08-16 with its full Git history and branches preserved.

The predecessor's final `main` commit was `c73848cf225d6f566f22b2b465a2695fb6d32608`. Its focused registry-trust implementation downloaded npm tarballs, verified `dist.integrity` (SHA-512) with `dist.shasum` (SHA-1) fallback, and denied a package when verification failed. The corresponding tests are preserved in that repository's `test/reviewer-verification.test.ts` and history.

Before archival, the predecessor's own commands were rerun at that commit on 2026-08-16:

- `bun test`: **26 passed, 0 failed** across 7 files (59 assertions).
- `bun run typecheck`: passed (`tsc --noEmit`).

Supply Chain Guard retains and extends the safety property in `src/analysis.ts`: downloaded npm artifacts are checked against registry or lockfile integrity, mismatches produce the blocking `artifact.integrity-mismatch` finding, and artifact cache identity incorporates integrity (or the tarball URL when integrity is unavailable). Relevant coverage lives in `src/analysis.test.ts`, `src/lockfile.test.ts`, `src/lockfile-policy.test.ts`, and `src/security-regression.test.ts`.

Both projects use the same MIT license. This note records provenance; it does not claim the predecessor's implementation was copied verbatim.
