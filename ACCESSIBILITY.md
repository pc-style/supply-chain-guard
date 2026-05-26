# Accessibility

Supply Chain Guard is a **terminal CLI** and a **static marketing site** ([scguard.pcstyle.dev](https://scguard.pcstyle.dev/)). We treat accessibility as part of product quality: people should be able to use the CLI with assistive technology and screen readers, read our docs, and use the website with keyboard-only navigation.

This document follows the [Open Source Guide: Accessibility best practices](https://opensource.guide/accessibility-best-practices-for-your-project/) and [W3C guidance on accessibility statements](https://www.w3.org/WAI/planning/statements/).

## Goals

Where feasible we aim for **[WCAG 2.2 Level AA](https://www.w3.org/WAI/WCAG22/quickref/)** on the marketing site and documentation. The CLI is not a web application; we align with CLI accessibility practices from the same guide (predictable output, plain language, non-color-only status, machine-readable reports).

| Area | Priority | How we meet it |
|------|----------|----------------|
| CLI output | High | Text labels for risk (`HIGH`, `MED`, `LOW`), `NO_COLOR` / `SCGUARD_NO_COLOR`, JSON reports, documented exit codes |
| Documentation | High | Heading hierarchy, descriptive link text, alt text on README images |
| Marketing site | High | Semantic HTML, keyboard focus, tab controls, reduced motion, automated axe scans in CI |
| Agent / Codex / PI flows | Medium | Optional; failures degrade with clear stderr messages |

## Supported environments

| Surface | Support |
|---------|---------|
| **CLI** (`scguard`) | macOS, Linux, Windows (WSL recommended). Tested with Bash and Fish shell hooks. |
| **Terminal** | Any terminal that supports UTF-8. Color is optional (`NO_COLOR=1`, `SCGUARD_NO_COLOR=1`). |
| **Marketing site** | Recent Chromium, Firefox, and Safari. Screen readers: VoiceOver, NVDA (spot-checked). |
| **VS Code extension scanning** | CLI only; no VS Code UI is shipped from this repo. |

Partial support: interactive prompts (`bypass`, incident acknowledgement) require a TTY. Use `SCGUARD_BYPASS=1` or JSON report paths when scripting.

## Known limitations

- The CLI spinner and progress UI are minimized when stdout/stderr is not a TTY.
- Demo terminal animations on the website replay captured CLI output; with JavaScript disabled, static screenshot fallbacks are shown.
- We do not yet run automated accessibility checks against third-party sites (Socket, npm registry).

Workarounds are documented in issue comments when reported.

## Reporting accessibility issues

Please **do not** fold accessibility bugs into generic bug reports if the barrier is specific to assistive technology or keyboard use.

1. Open a new issue and choose **Accessibility issue** (template: [.github/ISSUE_TEMPLATE/accessibility.yml](.github/ISSUE_TEMPLATE/accessibility.yml)).
2. Include severity, surface (CLI / website / docs), OS, terminal or browser, and assistive technology.
3. We treat accessibility reports as expertise, not noise.

Security-sensitive issues still go through [SECURITY.md](./SECURITY.md).

### Severity (for triage)

| Level | Meaning |
|-------|---------|
| **Critical** | Cannot complete a core task (e.g. cannot run `scguard review` or read results with your setup). |
| **High** | Major barrier with a difficult workaround. |
| **Medium** | Inconsistent or confusing experience. |
| **Low** | Minor polish; does not block core flows. |

Track open accessibility work: [issues labeled `accessibility`](https://github.com/pc-style/supply-chain-guard/issues?q=is%3Aissue+is%3Aopen+label%3Aaccessibility).

## Contributor requirements

- **CLI changes:** Preserve text labels for risk and status; respect `NO_COLOR`. Prefer `--json` for machine-readable output on scan commands. Error messages must state what failed and how to fix it.
- **Site changes:** Test keyboard navigation (Tab, arrow keys on demo tabs). Do not remove focus outlines without a visible replacement. Run `bun run a11y` before opening a PR.
- **Docs:** Use real heading levels (`#` → `##` → `###`), descriptive links, and alt text on images.
- **CI:** Pull requests that change `site/` must pass the [accessibility workflow](.github/workflows/a11y.yml) (axe-core via Playwright).

Optional manual checks: [Axe DevTools](https://www.deque.com/axe/devtools/) on the site, VoiceOver or NVDA smoke test on the demo section.

## CLI accessibility notes

- **JSON:** `scguard scan-npm`, `scguard scan-stage`, `scguard scan-vsix`, `scguard review`, and `scguard install` accept `--json` to print the report schema to stdout. Reports are always written under `.scguard/reports/`.
- **Exit codes:** `0` success, `1` usage/runtime error, `2` policy block or failed agent review.
- **Color:** Severity uses words and badges, not color alone. Set `NO_COLOR=1` or `SCGUARD_NO_COLOR=1` for plain text.
- **Help:** `scguard --help` lists commands and environment variables in plain text.

## Website accessibility notes

- Language is declared on `<html lang="en">`.
- Primary navigation and demo tabs are keyboard operable.
- Focus styles use `:focus-visible`.
- `prefers-reduced-motion: reduce` disables non-essential transitions.
- External links that open in a new tab include `(opens in new tab)` in the accessible name where applicable.

## Centering people with disabilities

We welcome contributors with lived experience. If you want to help shape policy, tests, or copy, comment on an accessibility issue or open a discussion. “Nothing about us without us” applies to how we prioritize fixes.
