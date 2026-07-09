# scguard v0.2 Roadmap

The one-sentence product: **look at the artifact before it touches your machine.**

Everything in this plan either makes that sentence true, or deletes something
that distracts from it. Phases are ordered by urgency; each has an explicit
exit criterion so it is obvious when to move on. Phase 0 ships alone. Later
phases can overlap.

---

## Phase 0 — Restore trust (days)

The current build blocks axios and chalk and passes exit code 1 on a clean
`left-pad` scan. Nothing else matters until the verdict can be trusted.
No new features in this phase.

### Tasks

1. **Fix the inverted Socket score.**
   `inspectIntelligence()` in `src/analysis.ts` treats `supplyChainRisk >= 0.7`
   as high risk. Socket's score is higher-is-safer (left-pad scores 100).
   Invert the thresholds: flag *low* scores (e.g. `< 0.3` high, `< 0.5` medium),
   fix the evidence string, and add a regression test asserting a 0.9-score
   package produces no finding.
2. **Migrate off the deprecated Socket endpoint.**
   `checkSocket()` in `src/integrations.ts` calls
   `/v0/npm/{pkg}/{version}/score`, which Socket has deprecated. Move to the
   successor endpoint and re-verify score semantics against their docs.
3. **Replace "any high finding blocks" with a hard-signal block list.**
   `summarizeRisk()` in `src/analysis.ts` blocks on any single high finding.
   Block only on: artifact integrity mismatch, typosquat match, known
   malware / critical OSV advisory, pipe-to-shell or credential access *inside
   a lifecycle script*, and (once verified reliable) failed npm signature.
   Everything else is a warning in the report, never a block.
4. **Demote the noisy patterns.**
   In `PATTERNS_ALL`: `process.env` access, base64 decoding, `dns.*`, and
   `.npmrc`/homedir references in regular source files become low/info
   severity. They stay high only in lifecycle-script scope.
5. **Separate agent error from agent rejection, and add a timeout.**
   `runAgentReview()` in `src/integrations.ts` has no timeout and a pi auth
   failure blocks a clean package. Add a 120s timeout; on agent *error*
   (missing binary, auth failure, timeout) print a warning and continue on
   default policy, block only on explicit `SCGUARD_DECISION: reject` /
   `manual-review`. Strict policy may keep fail-closed behavior.
6. **Make config parse failures loud.**
   `readConfigFile()` in `src/core.ts` silently falls back to defaults on
   malformed JSON, which can silently disable a configured policy. Print a
   warning to stderr naming the config path and the parse error.
7. **Fix the failing test.**
   The scan-lockfile plan-mode test in `src/lockfile-policy.test.ts` asserts
   on ANSI-colored output. Strip ANSI before asserting. `bun run check` must
   pass.

### Exit criterion

`scguard review axios`, `chalk`, `left-pad`, `react`, `zod` all exit 0 with at
most warning-level findings; the malicious fixtures in `src/fixtures/` still
block; `bun run check` is green.

---

## Phase 1 — Cut scope (about a week)

The repo is a platform wrapped around a tripwire. Deleting from working code
is cheap; every removed feature removes a policy interaction nobody can
reason about. Write the v0.2 spec first (one page, the sentence at the top of
this file plus the kept command list), then delete against it.

### Keep

`review`, `install`, `guard` + `shell-hook`, `doctor`, `config`,
`scan-vsix`, `self-test`.

### Cut or park

| Feature | Action |
| --- | --- |
| Presets `quiet`, `strict-ci`, `enterprise`, `advisory` | Collapse to `default` and `strict`. Migration: unknown preset in config maps to `default` with a warning. |
| Active-incident advisory mode (`SCGUARD_ACTIVE_INCIDENT*`) | Delete. |
| npm staged-publish flow (`scan-stage`, `npm stage approve` handling) | Delete (revisit if npm staging becomes mainstream). |
| SBOM output (`--sbom`, `src/sbom.ts`) | Delete or park behind an `experimental` doc. |
| Safe resolver suggestions | Delete; fold "this version is very fresh" into the existing `version.new` finding. |
| Agent mode `both` | Delete; one agent per run. |
| `add` deprecated alias, `agent-prompt`, `agent-review` as public commands | Remove from help; keep internals if the review flow needs them. |
| Unconditional codex+pi prompt file emission in `src/reporting.ts` | Emit prompts only when an agent review is configured. |
| `SCGUARD_*` env vars | Reduce from 13 to roughly: `SCGUARD_BYPASS`, `SCGUARD_OFFLINE`, `SCGUARD_DEBUG`, `SCGUARD_NO_COLOR`. |

### Also in this phase (small correctness fixes that survive any pivot)

- Lockfile baseline: compare `resolved` + `integrity`, not just
  `name@version` (`versionedPackageKey` in `src/core.ts`) — a swapped tarball
  URL at the same version is exactly the attack this tool exists for.
- `scguard install`: stop rebuilding the install command from scratch
  (`buildInstallCommand` in `src/pm.ts`); pass the user's original args
  through after the gate, or document loudly that only specs survive.
- Validate `SCGUARD_LOCKFILE_CONCURRENCY` parsing (NaN guard) while it still
  exists in `src/commands.ts`.

### Exit criterion

Help output fits one screen. `src/commands.ts` shrinks substantially (target:
under ~700 lines). Docs/README describe only what remains. `bun run check`
green.

---

## Phase 2 — Calibration corpus (overlaps Phase 1)

The unit tests cover machinery, not judgment. Add the test that defines what
"correct" means for this product.

### Tasks

1. **Benign corpus test:** top ~50 npm packages (name + pinned version +
   recorded registry fixtures, so the test runs offline and deterministic)
   must produce verdict `allow` with default policy. Record fixtures under
   `src/fixtures/corpus/`.
2. **Malicious corpus test:** the existing malicious fixtures plus 3-5
   recreated real-world attack shapes (postinstall exfil, typosquat name,
   integrity mismatch, credential-stealing install script) must block.
3. Wire both into `bun run check` and CI.
4. Every future pattern/threshold change must keep both suites green — this
   replaces gut feel as the tuning loop.

### Exit criterion

A pattern change that reintroduces the axios false positive fails CI.

---

## Phase 3 — Proxy pivot (the v0.2 headline, 2-4 weeks)

Replace command-line interception with protocol interception. The shell hook
and the hand-rolled parser for four package managers' CLI grammars
(`classifyPackageCommand`, `nonOptionTokens`, spec inference in
`src/commands.ts`) are the most fragile third of the codebase and can never
be complete (misses `npx`, `bunx`, CI, scripts, unhooked shells).

```
bun/npm/pnpm/yarn/npx ──▶ scguard proxy (localhost) ──▶ registry.npmjs.org
                           metadata: stream through
                           tarball:  gate through the Phase 0 engine
                                     clean → stream, risky → 403 + report
```

### Tasks

1. **Spike (2-3 days):** minimal Bun HTTP server that proxies
   `registry.npmjs.org`, streams metadata untouched, and intercepts tarball
   GETs through `scanNpmArtifact()`. Prove `bun add` and `npm install` work
   against it with `registry=http://localhost:<port>`.
2. **Decision gate:** if install-time latency on a warm cache is acceptable
   (target: metadata adds <10ms, first tarball fetch adds only scan time),
   proceed. If not, stop and keep the improved shell hook — Phases 0-2 stand
   on their own.
3. `scguard proxy start|stop|status` + `scguard proxy setup` (writes the
   `.npmrc`/`bunfig.toml` registry line, mirrors what `shell-hook` does today).
4. Verdict cache keyed by tarball sha256 so repeat installs are instant.
5. Auth/scoped-registry passthrough: forward `Authorization` headers,
   pass through non-npmjs scoped registries unproxied.
6. On block: 403 with a readable body pointing at the markdown report path;
   the package manager surfaces the failed fetch.
7. Keep `review` (manual pre-check) and `scan-vsix` as-is — the proxy covers
   installs, not editor extensions.
8. Once the proxy is the recommended path, demote the shell hook to a
   fallback section in the README; delete `guardCommand`'s classification
   machinery when confident.

### Exit criterion

Fresh machine: `scguard proxy setup`, then `bun add axios` installs clean
through the proxy, and installing a malicious fixture tarball is refused with
a report — no shell hook involved, works from npx and CI too.

---

## Phase 4 — Polish and release (ongoing)

- Update README, site, and screenshots to the proxy-first story; regenerate
  demos (`bun run demo-screenshots`).
- `scguard doctor` verifies the proxy is running and the registry line is
  set; make it actually exercise agent auth (a pi token failure must not
  show "pi available").
- CHANGELOG entry framing v0.2 honestly: "v0.1 over-blocked; v0.2 blocks on
  hard signals only, warns on everything else, and intercepts at the
  registry protocol level."
- Tag v0.2.0 once Phases 0-3 exit criteria hold.

---

## Sequencing summary

| Phase | Duration | Depends on | Deliverable |
| --- | --- | --- | --- |
| 0 Restore trust | days | — | Correct verdicts, green `check` |
| 1 Cut scope | ~1 week | 0 | Small surface, small `commands.ts` |
| 2 Calibration corpus | overlaps 1 | 0 | Judgment locked in CI |
| 3 Proxy pivot | 2-4 weeks | 0, 2 (gated by spike) | Protocol-level interception |
| 4 Polish + release | ongoing | 0-3 | v0.2.0 |

The only hard gate is the Phase 3 spike: if proxy latency or compatibility
disappoints, v0.2 ships as Phases 0-2 plus the existing (fixed) shell hook,
and that is still a dramatically better product than v0.1.
