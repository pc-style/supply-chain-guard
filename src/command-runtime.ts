import { mkdir, rm } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, delimiter, join, relative, resolve } from "node:path";
import {
  freshnessWindowHoursForPreset,
  scanNpm,
  scanNpmLockfileEntry,
  scanVsix,
} from "./analysis";
import type {
  AgentMode,
  LockfileBaseline,
  PackageAgeResult,
  PolicyPreset,
  ScanReason,
} from "./core";
import {
  CACHE_DIR,
  commandExists,
  legacyVersionedPackageKey,
  normalizeAgentMode,
  normalizePolicyPreset,
  REPORT_DIR,
  ROOT,
  readConfig,
  readConfigFile,
  readLockfileBaseline,
  readOption,
  run,
  versionedPackageKey,
  versionedPackageSet,
  WORK_DIR,
  writeConfig,
  writeLockfileBaseline,
} from "./core";
import { installCommandFromOriginalArgs } from "./install-command";
import {
  checkPackageAge,
  resolveAgentMode,
  runAgentReviews,
} from "./integrations";
import {
  type DetectedLockfile,
  detectLockfile,
  type LockfileEntry,
  parseLockfile,
} from "./lockfile";
import { isOfflineMode, OFFLINE_ENV } from "./offline";
import { detectPackageManager } from "./pm";
import { blockOnFailedReview, emitReport } from "./reporting";
import { c, header, style, withSpinner } from "./ui";

// Re-export so other modules (and the main agent's integrations.ts) can import
// the offline helper through a single, stable path if they prefer.
export { isOfflineMode, OFFLINE_ENV };

/**
 * `isOffline` mirrors `isOfflineMode` but with a name matching the task spec.
 * Callers should prefer `isOfflineMode` from `./offline` for new code.
 */
export function isOffline(args: string[] = []): boolean {
  return isOfflineMode(args);
}

export async function reviewOrInstall(
  args: string[],
  opts: { install: boolean },
) {
  const cleanArgs = stripGuardOptions(args);
  const specs = directPackageSpecs(cleanArgs);
  if (specs.length === 0) {
    throw new Error(
      `${opts.install ? "install" : "review"} requires at least one package spec, e.g. 'scguard ${opts.install ? "install" : "review"} react@18.3.1'`,
    );
  }
  const agentMode = await resolveAgentMode(args);
  const json = args.includes("--json");
  const offline = isOfflineMode(args);
  const passed: string[] = [];
  for (const spec of specs) {
    const report = await withSpinner(
      `Resolving graph and simulating install for ${spec}...`,
      () => scanNpm(spec, { offline }),
    );
    let reportPath = await emitReport(report, json);
    if (!report.summary.installAllowed) {
      throw new Error(
        [
          `Blocked ${spec}: high-risk findings.`,
          `  Markdown report: ${reportPath.replace(/\.json$/, ".md")}`,
          `  JSON report:     ${reportPath}`,
          `  To override (not recommended): SCGUARD_BYPASS=1 <your install command>`,
        ].join("\n"),
      );
    }
    if (agentMode.length > 0) {
      const reviews = await runAgentReviews(report, reportPath, agentMode);
      report.agentReviews = reviews;
      reportPath = await emitReport(report, json, { silent: json });
      await blockOnFailedReview(spec, reviews);
    }
    if (!json) printNextSteps(spec, reportPath, opts.install);
    passed.push(spec);
  }
  if (!opts.install) return;
  const detected = detectPackageManager(process.cwd(), args);
  if (detected.source === "default") {
    console.error(
      `${c.amber("scguard", true)} ${c.gray("no lockfile detected; defaulting to")} ${c.white("bun")}. ${c.dim("Override with --pm npm|pnpm|yarn|bun.")}`,
    );
  } else {
    console.error(
      `${c.amber("scguard", true)} ${c.gray(`using ${detected.pm} (${detected.source}: ${detected.detail})`)}`,
    );
  }
  const installCmd = installCommandFromOriginalArgs(detected.pm, cleanArgs);
  await run(installCmd.cmd, installCmd.args);
}

function printNextSteps(
  spec: string,
  reportPath: string,
  willInstall: boolean,
) {
  const _md = reportPath.replace(/\.json$/, ".md");
  console.log(header(`Next steps  ${c.dim(spec)}`));
  if (willInstall) {
    console.log(`${style.ok()}  ${c.gray("gate passed - installing now")}`);
  } else {
    console.log(`  ${c.gray("Inspect the report, then:")}`);
    console.log(
      `    ${c.amber("$", true)} ${c.white(`scguard install ${spec}`)}`,
    );
    console.log(
      `  ${c.gray("Or re-run with --agent codex for a deeper review.")}`,
    );
  }
  console.log("");
}

const DOCTOR_FIX_HINTS: Record<string, string> = {
  "dependency: bun": "curl -fsSL https://bun.sh/install | bash",
  "dependency: git": "apt install git  # or: brew install git",
  "dependency: tar": "apt install tar",
  "dependency: unzip": "apt install unzip",
  "~/.local/bin on PATH": 'export PATH="$HOME/.local/bin:$PATH"',
  "shell hook active": 'eval "$(scguard shell-hook)"',
  "policy preset": "scguard config --preset default",
  "SOCKET_API_KEY configured":
    "scguard config  # or visit socket.dev to get a key",
  "SOCKET_ORG_SLUG configured": "export SOCKET_ORG_SLUG=<your-socket-org-slug>",
};

export async function doctorCommand() {
  const checks: Array<{ name: string; ok: boolean; detail: string }> = [];
  for (const bin of ["bun", "git", "tar", "unzip"]) {
    checks.push({
      name: `dependency: ${bin}`,
      ok: await commandExists(bin),
      detail: `${bin} required`,
    });
  }
  for (const bin of ["codex", "pi"]) {
    const ok = await commandExists(bin);
    checks.push({
      name: `optional agent: ${bin}`,
      ok,
      detail: ok ? "available" : "not installed (agent review unavailable)",
    });
  }
  const localBin = join(homedir(), ".local", "bin");
  const path = (Bun.env.PATH ?? "").split(delimiter);
  checks.push({
    name: `~/.local/bin on PATH`,
    ok: path.includes(localBin),
    detail: path.includes(localBin)
      ? localBin
      : `${localBin} missing from PATH`,
  });
  const hookActive = !!Bun.env.SCGUARD_SHELL_HOOK_ACTIVE;
  checks.push({
    name: `shell hook active`,
    ok: hookActive,
    detail: hookActive ? "active" : 'run: eval "$(scguard shell-hook)"',
  });
  const tokenSet = !!Bun.env.SOCKET_API_KEY;
  const socketOrgSet = !!Bun.env.SOCKET_ORG_SLUG;
  checks.push({
    name: `SOCKET_API_KEY configured`,
    ok: tokenSet,
    detail: tokenSet ? "set" : "unset (Socket scoring disabled)",
  });
  checks.push({
    name: `SOCKET_ORG_SLUG configured`,
    ok: !tokenSet || socketOrgSet,
    detail: socketOrgSet
      ? "set"
      : tokenSet
        ? "unset (Socket PURL scoring disabled)"
        : "not required unless SOCKET_API_KEY is set",
  });
  const config = await readConfig();
  checks.push({
    name: `policy preset`,
    ok: true,
    detail: config.preset,
  });
  checks.push({
    name: `default agent review`,
    ok: true,
    detail: config.agentReview,
  });
  checks.push({ name: `project root`, ok: true, detail: ROOT });
  checks.push({ name: `reports directory`, ok: true, detail: REPORT_DIR });

  console.log(header("scguard doctor"));
  let allOk = true;
  for (const check of checks) {
    const marker = check.ok
      ? `${style.check()} ${c.green("ok  ", true)}`
      : `${style.cross()} ${c.amber("warn", true)}`;
    if (!check.ok) allOk = false;
    console.log(
      `  ${marker}  ${c.white(check.name.padEnd(28))} ${c.dim(check.detail)}`,
    );
    if (!check.ok && DOCTOR_FIX_HINTS[check.name]) {
      console.log(
        `           ${c.dim(`fix: ${DOCTOR_FIX_HINTS[check.name]}`)}`,
      );
    }
  }
  console.log("");
  if (allOk) {
    console.log(`${style.ok()}  ${c.gray("all checks passed.")}`);
  } else {
    console.log(
      `${c.amber("note", true)} ${c.gray("some checks failed. fix the items above for the smoothest experience.")}`,
    );
  }
}

export async function cleanCommand(args: string[]) {
  const all = args.includes("--all");
  const reports = all || args.includes("--reports");
  const cache = all || args.includes("--cache");
  const work = all || args.includes("--work");
  if (!reports && !cache && !work) {
    throw new Error("clean requires one of: --reports, --cache, --work, --all");
  }
  const targets: Array<[string, string]> = [];
  if (reports) targets.push(["reports", REPORT_DIR]);
  if (cache) targets.push(["cache", CACHE_DIR]);
  if (work) targets.push(["work", WORK_DIR]);
  console.log(header("scguard clean"));
  for (const [label, dir] of targets) {
    await rm(dir, { recursive: true, force: true });
    await mkdir(dir, { recursive: true });
    console.log(
      `${style.check()} ${c.green("cleared", true)}  ${c.white(label.padEnd(8))} ${c.dim(dir)}`,
    );
  }
}

export async function guardCommand(args: string[]) {
  const command = args[0];
  if (!command) throw new Error("guard requires the command being wrapped");
  const realArgs = stripGuardOptions(args.slice(1));
  if (Bun.env.SCGUARD_BYPASS === "1") {
    console.error(
      `scguard: SCGUARD_BYPASS=1 set; running ${command} unguarded.`,
    );
    await run(command, realArgs);
    return;
  }
  const classification = classifyPackageCommand(command, realArgs);
  if (!classification.packageOperation) {
    await run(command, realArgs);
    return;
  }

  if (classification.kind === "vsix") {
    await guardVsCodeExtension(command, realArgs, classification.specs);
    return;
  }

  const action = String(classification.action);
  const isBareInstall =
    classification.specs.length === 0 &&
    (action === "install" || action === "i" || action === "ci");
  const specs =
    classification.specs.length > 0
      ? classification.specs
      : await inferSpecsForPackageOperation(action);
  console.error(
    `${c.amber("scguard", true)} ${c.gray(`${classification.action} detected:`)} ${c.white(`${command} ${realArgs.join(" ")}`)}`,
  );
  console.error(
    `${c.amber("scguard", true)} ${c.gray("this command can execute lifecycle code from untrusted packages.")}`,
  );

  if (isBareInstall) {
    const summary = await scanLockfile(
      packageManagerProjectDir(command, realArgs, process.cwd()),
      args.slice(1),
    );
    if (summary.failed.length > 0) throw lockfileFailedScanError(summary);
    if (summary.blockInstall) throw lockfileBlockingError(summary);
    await run(command, realArgs);
    return;
  }

  if (specs.length > 0) {
    console.error(
      `${c.amber("scguard", true)} ${c.gray("staging analysis required for")} ${c.white(specs.join(", "))}`,
    );
    const offline = isOfflineMode(args);
    for (const spec of specs) {
      const report = await withSpinner(
        `Resolving graph and simulating install for ${spec}...`,
        () => scanNpm(spec, { offline }),
      );
      let reportPath = await emitReport(report, false);
      if (!report.summary.installAllowed) {
        throw new Error(
          `Blocked ${spec}: high-risk findings found. See ${reportPath}`,
        );
      }
      const agentMode = await resolveAgentMode(args.slice(1));
      if (agentMode.length > 0) {
        const reviews = await runAgentReviews(report, reportPath, agentMode);
        report.agentReviews = reviews;
        reportPath = await emitReport(report, false);
        await blockOnFailedReview(spec, reviews);
      }
    }
  }

  await run(command, realArgs);
}

async function guardVsCodeExtension(
  command: string,
  args: string[],
  specs: string[],
) {
  const target = specs[0];
  console.error(
    `scguard: VS Code extension install detected: ${command} ${args.join(" ")}`,
  );
  console.error(
    "scguard: extensions run code inside your editor and can access workspace files.",
  );
  if (!target)
    throw new Error(
      "Blocked VS Code extension install: no extension target found.",
    );
  if (!target.endsWith(".vsix")) {
    throw new Error(
      "Blocked VS Code extension install by ID. Download the .vsix first, run scan-vsix, then install the reviewed artifact.",
    );
  }
  const report = await scanVsix(resolve(target));
  let reportPath = await emitReport(report, false);
  if (!report.summary.installAllowed) {
    throw new Error(
      `Blocked ${target}: high-risk findings found. See ${reportPath}`,
    );
  }
  const agentMode = await resolveAgentMode(args);
  if (agentMode.length > 0) {
    const reviews = await runAgentReviews(report, reportPath, agentMode);
    report.agentReviews = reviews;
    reportPath = await emitReport(report, false);
    await blockOnFailedReview(target, reviews);
  }
  await run(command, stripGuardOptions(args));
}

async function inferSpecsForPackageOperation(action: string) {
  if (action === "update" || action === "upgrade") {
    throw new Error(
      "Broad package updates are blocked. Run the command with explicit package specs so each update can be staged and analyzed first.",
    );
  }
  return [];
}

export interface LockfileScanSummary {
  detected: DetectedLockfile;
  preset: PolicyPreset;
  totalPackages: number;
  selected: number;
  skipped: number;
  scanned: number;
  failed: { name: string; version: string; error: string }[];
  blocked: { name: string; version: string; reportPath: string }[];
  warnings: { name: string; version: string; reportPath: string }[];
  blockInstall: boolean;
  baselineUpdated: boolean;
}

type PlannedLockfileScan = {
  entry: LockfileEntry;
  reason: ScanReason;
  packageAge?: PackageAgeResult;
};

type SkippedLockfileEntry = {
  entry: LockfileEntry;
  reason: "outside-fresh-window" | "baseline-unchanged" | "policy";
};

export async function scanLockfileCommand(
  args: string[],
): Promise<LockfileScanSummary> {
  const cwd = args.find((a) => !a.startsWith("--")) ?? process.cwd();
  return scanLockfile(cwd, args);
}

export async function scanLockfile(
  cwd: string,
  args: string[] = [],
): Promise<LockfileScanSummary> {
  const detected = detectLockfile(cwd);
  if (!detected) {
    throw new Error(
      `No lockfile found in ${cwd}. Expected one of: bun.lock, package-lock.json, pnpm-lock.yaml, yarn.lock.`,
    );
  }
  const entries = await parseLockfile(detected);
  if (entries.length === 0) {
    throw new Error(`Parsed ${detected.path} but found no package entries.`);
  }

  const config = await readConfig();
  const baselinePath = lockfileBaselinePath(cwd);
  const baseline = await readLockfileBaseline(baselinePath);
  const offline = isOfflineMode(args);
  const concurrency = 8;
  const ageResults = await collectPackageAges(entries, offline, concurrency);
  const plan = planLockfileSelection(
    entries,
    baseline,
    config.preset,
    ageResults,
  );

  const summary: LockfileScanSummary = {
    detected,
    preset: config.preset,
    totalPackages: entries.length,
    selected: plan.selected.length,
    skipped: plan.skipped.length,
    scanned: 0,
    failed: [],
    blocked: [],
    warnings: [],
    blockInstall: false,
    baselineUpdated: false,
  };

  console.log(header(`scguard scan-lockfile  ${c.dim(detected.kind)}`));
  console.log(`  ${c.gray("lockfile:")} ${c.white(detected.path)}`);
  console.log(`  ${c.gray("preset:")} ${c.white(config.preset)}`);
  console.log(`  ${c.gray("packages:")} ${c.white(String(entries.length))}`);
  console.log(
    `  ${c.gray("selected:")} ${c.white(String(plan.selected.length))}`,
  );
  console.log(
    `  ${c.gray("skipped:")} ${c.white(String(plan.skipped.length))}`,
  );
  if (args.includes("--plan")) {
    printLockfilePlan(cwd, plan, args);
    return summary;
  }
  if (baseline) {
    console.log(
      `  ${c.gray("baseline:")} ${c.white(String(baseline.entries.length))} ${c.dim(`saved ${baseline.generatedAt}`)}`,
    );
  } else {
    console.log(
      `  ${c.gray("baseline:")} ${c.dim("none (full lockfile scan on first bare install)")}`,
    );
  }

  let cursor = 0;
  let completed = 0;
  const total = plan.selected.length;

  const writeProgress = () => {
    if (!process.stderr.isTTY) return;
    const bar = `[${completed}/${total}]`;
    process.stderr.write(
      `\r  ${c.amber("scanning", true)} ${c.gray(bar)}     `,
    );
  };

  async function worker() {
    while (true) {
      const i = cursor++;
      if (i >= plan.selected.length) return;
      const selection = plan.selected[i];
      const entry = selection.entry;
      try {
        const report = await scanNpmLockfileEntry(entry, {
          offline,
          packageAge: selection.packageAge,
        });
        summary.scanned++;
        const reportPath = await emitReport(report, false);
        if (!report.summary.installAllowed) {
          summary.blocked.push({
            name: entry.name,
            version: entry.version,
            reportPath,
          });
        } else if (report.summary.risk === "medium") {
          summary.warnings.push({
            name: entry.name,
            version: entry.version,
            reportPath,
          });
        }
      } catch (err) {
        summary.failed.push({
          name: entry.name,
          version: entry.version,
          error: err instanceof Error ? err.message : String(err),
        });
      } finally {
        completed++;
        writeProgress();
      }
    }
  }

  writeProgress();
  await Promise.all(
    Array.from(
      { length: Math.min(concurrency, Math.max(1, plan.selected.length)) },
      () => worker(),
    ),
  );
  if (process.stderr.isTTY) process.stderr.write("\n");

  summary.blockInstall = shouldBlockLockfileInstall(
    config.preset,
    summary.blocked.length,
    summary.failed.length,
  );
  if (summary.failed.length === 0 && !summary.blockInstall) {
    await writeLockfileBaseline(
      {
        schemaVersion: 1,
        generatedAt: new Date().toISOString(),
        kind: detected.kind,
        entries,
      },
      baselinePath,
    );
    summary.baselineUpdated = true;
  }

  console.log("");
  console.log(
    `  ${style.check()} ${c.green("scanned ", true)} ${c.white(String(summary.scanned))}/${c.white(String(total))}`,
  );
  if (summary.warnings.length > 0) {
    console.log(
      `  ${c.amber("warn    ", true)} ${c.white(String(summary.warnings.length))} ${c.gray("medium-risk packages")}`,
    );
  }
  if (summary.failed.length > 0) {
    console.log(
      `  ${c.amber("skipped ", true)} ${c.white(String(summary.failed.length))} ${c.gray("packages could not be analyzed")}`,
    );
    for (const f of summary.failed.slice(0, 5)) {
      console.log(
        `    ${c.dim(`- ${f.name}@${f.version}: ${f.error.split("\n")[0]}`)}`,
      );
    }
    if (summary.failed.length > 5)
      console.log(`    ${c.dim(`... and ${summary.failed.length - 5} more`)}`);
  }
  if (summary.blocked.length > 0) {
    console.log(
      `  ${c.red("blocked ", true)} ${c.white(String(summary.blocked.length))} ${c.gray("high-risk packages")}`,
    );
    for (const b of summary.blocked) {
      console.log(
        `    ${c.red("-", true)} ${c.white(`${b.name}@${b.version}`)} ${c.dim(b.reportPath)}`,
      );
    }
  }
  if (summary.baselineUpdated) {
    console.log(
      `  ${c.green("baseline", true)} ${c.gray("updated for future bare installs")}`,
    );
  }

  return summary;
}

function printLockfilePlan(
  cwd: string,
  plan: { selected: PlannedLockfileScan[]; skipped: SkippedLockfileEntry[] },
  args: string[],
) {
  console.log("");
  console.log(
    `  ${c.amber("plan", true)} ${c.gray("preview only; no package scans, reports, or baseline updates were run")}`,
  );
  printLockfilePlanEntries("selected", plan.selected);
  printLockfilePlanEntries("skipped", plan.skipped);
  console.log(
    `  ${c.gray("next:")} ${c.white(formatLockfilePlanCommand(cwd, args))}`,
  );
}

function printLockfilePlanEntries(
  label: "selected" | "skipped",
  entries: Array<PlannedLockfileScan | SkippedLockfileEntry>,
) {
  if (entries.length === 0) {
    console.log(`  ${c.gray(`${label} sample:`)} ${c.dim("none")}`);
    return;
  }
  console.log(`  ${c.gray(`${label} sample:`)}`);
  for (const item of entries.slice(0, 5)) {
    console.log(
      `    ${c.dim("-")} ${c.white(`${item.entry.name}@${item.entry.version}`)} ${c.dim(`reason=${item.reason}`)}`,
    );
  }
  if (entries.length > 5) {
    console.log(`    ${c.dim(`... and ${entries.length - 5} more`)}`);
  }
}

function formatLockfilePlanCommand(cwd: string, args: string[]) {
  const parts = ["scguard", "scan-lockfile", formatLockfilePlanCwd(cwd)];
  if (args.includes("--offline")) parts.push("--offline");
  return parts.join(" ");
}

function formatLockfilePlanCwd(cwd: string) {
  const rel = relative(process.cwd(), cwd);
  if (!rel) return ".";
  if (!rel.startsWith("..") && !rel.startsWith("/")) return rel;
  return cwd;
}

export function lockfileBaselinePath(cwd: string) {
  return join(cwd, ".scguard", "lockfile-baseline.json");
}

function lockfileBlockingError(summary: LockfileScanSummary): Error {
  const lines = [
    `Blocked install: ${summary.blocked.length} high-risk package(s) in ${summary.detected.path}.`,
    ...summary.blocked.map(
      (b) => `  - ${b.name}@${b.version}  ${b.reportPath}`,
    ),
    `To bypass for one command (not recommended): SCGUARD_BYPASS=1 <your command>`,
  ];
  return new Error(lines.join("\n"));
}

export function shouldBlockLockfileInstall(
  _preset: PolicyPreset,
  blockedCount: number,
  failedCount = 0,
) {
  if (failedCount > 0) return true;
  return blockedCount > 0;
}

export function planLockfileSelection(
  entries: LockfileEntry[],
  baseline: LockfileBaseline | null,
  preset: PolicyPreset,
  packageAges: Map<string, PackageAgeResult>,
): { selected: PlannedLockfileScan[]; skipped: SkippedLockfileEntry[] } {
  const selected: PlannedLockfileScan[] = [];
  const skipped: SkippedLockfileEntry[] = [];
  const baselineSet = baseline ? versionedPackageSet(baseline.entries) : null;
  const legacyBaselineSet = baseline
    ? new Set(
        baseline.entries
          .filter((entry) => !entry.resolved && !entry.integrity)
          .map(legacyVersionedPackageKey),
      )
    : null;
  const windowHours = freshnessWindowHoursForPreset(preset);
  for (const entry of entries) {
    const key = versionedPackageKey(entry);
    const age = packageAges.get(`${entry.name}@${entry.version}`);
    const versionAgeHours =
      age?.status === "checked" ? age.versionAgeHours : undefined;
    const fresh =
      age?.status !== "checked" ||
      (typeof versionAgeHours === "number" &&
        versionAgeHours >= 0 &&
        versionAgeHours < windowHours);
    const changed = baselineSet
      ? !baselineSet.has(key) &&
        !legacyBaselineSet?.has(legacyVersionedPackageKey(entry))
      : false;

    if (!baselineSet) {
      selected.push({ entry, reason: "policy", packageAge: age });
      continue;
    }

    if (changed) {
      selected.push({
        entry,
        reason: "changed-lockfile-entry",
        packageAge: age,
      });
      continue;
    }

    if (fresh) {
      selected.push({ entry, reason: "fresh-version", packageAge: age });
      continue;
    }

    skipped.push({
      entry,
      reason: baselineSet ? "baseline-unchanged" : "outside-fresh-window",
    });
  }
  return { selected, skipped };
}

async function collectPackageAges(
  entries: LockfileEntry[],
  offline: boolean,
  concurrency: number,
) {
  const results = new Map<string, PackageAgeResult>();
  let cursor = 0;
  async function worker() {
    while (true) {
      const i = cursor++;
      if (i >= entries.length) return;
      const entry = entries[i];
      const key = `${entry.name}@${entry.version}`;
      results.set(
        key,
        await checkPackageAge(entry.name, entry.version, { offline }),
      );
    }
  }
  await Promise.all(
    Array.from(
      { length: Math.min(concurrency, Math.max(1, entries.length)) },
      () => worker(),
    ),
  );
  return results;
}

function lockfileFailedScanError(summary: LockfileScanSummary): Error {
  const lines = [
    `Blocked install: ${summary.failed.length} package(s) in ${summary.detected.path} could not be analyzed.`,
    ...summary.failed
      .slice(0, 20)
      .map((f) => `  - ${f.name}@${f.version}  ${f.error.split("\n")[0]}`),
    summary.failed.length > 20
      ? `  ... and ${summary.failed.length - 20} more`
      : "",
    "To bypass all checks for one command (not recommended): SCGUARD_BYPASS=1 <your command>",
  ].filter(Boolean);
  return new Error(lines.join("\n"));
}

export function classifyPackageCommand(command: string, args: string[]) {
  const base = basename(command);
  if (base === "code" && args.includes("--install-extension")) {
    const index = args.indexOf("--install-extension");
    return {
      packageOperation: true,
      kind: "vsix" as const,
      action: "install-extension",
      specs: args[index + 1] ? [args[index + 1]] : [],
    };
  }
  const sub = findPackageSubcommand(args);
  // Package manager self-updates are not untrusted package operations.
  if (base === "bun" && sub === "upgrade") {
    return {
      packageOperation: false,
      kind: "npm" as const,
      action: sub,
      specs: [],
    };
  }
  if (base === "pnpm" && sub === "self-update") {
    return {
      packageOperation: false,
      kind: "npm" as const,
      action: sub,
      specs: [],
    };
  }
  const installActions = new Set([
    "add",
    "install",
    "i",
    "update",
    "upgrade",
    "ci",
  ]);
  const packageManagers = new Set(["bun", "npm", "pnpm", "yarn"]);
  const bareYarnInstall =
    base === "yarn" &&
    !sub &&
    !args.some((arg) =>
      ["--help", "-h", "--version", "-v", "-V"].includes(arg),
    );
  const packageOperation =
    packageManagers.has(base) &&
    ((!!sub && installActions.has(sub)) || bareYarnInstall);
  const specs = packageOperation ? extractSpecs(base, args) : [];
  return {
    packageOperation,
    kind: "npm" as const,
    action: sub ?? (bareYarnInstall ? "install" : "run"),
    specs,
  };
}

export function packageManagerProjectDir(
  command: string,
  args: string[],
  cwd: string,
): string {
  const base = basename(command).replace(/\.exe$/i, "");
  if (base !== "npm") return cwd;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    let value: string | undefined;
    if (arg === "--prefix" || arg === "-C") value = args[i + 1];
    else if (arg.startsWith("--prefix=")) value = arg.slice(9);
    else if (arg.startsWith("-C=")) value = arg.slice(3);
    if (!value || value.startsWith("-")) continue;
    return resolve(cwd, value);
  }
  return cwd;
}

export function findPackageSubcommand(args: string[]): string | undefined {
  return nonOptionTokens(args)[0];
}

export function nonOptionTokens(args: string[]): string[] {
  const tokens: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg.startsWith("-")) {
      if (arg.includes("=")) continue;
      if (VALUE_OPTIONS.has(arg)) {
        i++;
        continue;
      }
      continue;
    }
    tokens.push(arg);
  }
  return tokens;
}

export function directPackageSpecs(args: string[]): string[] {
  return nonOptionTokens(args);
}

// Options across npm/bun/pnpm/yarn install commands whose next argument is
// their value (not a package spec). Conservative superset; missing entries
// only result in over-scanning, never under-scanning.
const VALUE_OPTIONS = new Set([
  "--prefix",
  "--registry",
  "--tag",
  "--otp",
  "--access",
  "--cache",
  "--userconfig",
  "--globalconfig",
  "--filter",
  "-F",
  "--include",
  "--omit",
  "--save-prefix",
  "--loglevel",
  "--cwd",
  "-C",
  "--cpu",
  "--os",
  "--libc",
  "--node-options",
  "--scope",
  "--workspace",
  "-w",
]);

function extractSpecs(base: string, args: string[]) {
  const tokens = nonOptionTokens(args);
  const sub = tokens[0];
  const rest = sub ? tokens.slice(1) : [];
  if (base === "npm" && (sub === "ci" || rest.length === 0)) return [];
  return rest.filter((arg) => !arg.includes("="));
}

export function stripGuardOptions(args: string[]) {
  const stripped: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "--agent" || arg === "--pm") {
      i++;
      continue;
    }
    if (arg.startsWith("--agent=") || arg.startsWith("--pm=")) continue;
    stripped.push(arg);
  }
  return stripped;
}

export async function configCommand(args: string[]) {
  if (args.includes("--show")) {
    console.log(JSON.stringify(await readConfig(), null, 2));
    return;
  }
  const explicitPreset = readOption(args, "--preset");
  const explicitAgent = readOption(args, "--agent");
  if (explicitPreset !== undefined || explicitAgent !== undefined) {
    const config = await readConfigFile();
    if (explicitPreset !== undefined)
      config.preset = normalizePolicyPreset(explicitPreset);
    if (explicitAgent !== undefined)
      config.agentReview = normalizeAgentMode(explicitAgent);
    await writeConfig(config);
    console.log(
      `${style.check()} ${c.green("saved", true)} ${c.gray("policy:")} ${c.amber(config.preset, true)} ${c.gray("agent:")} ${c.amber(config.agentReview, true)}`,
    );
    return;
  }
  const config = await readConfigFile();
  config.preset = await presetConfigTui(config.preset);
  config.agentReview = await agentConfigTui(config.agentReview);
  await writeConfig(config);
  console.log(
    `${style.check()} ${c.green("saved", true)} ${c.gray("policy:")} ${c.amber(config.preset, true)} ${c.gray("agent:")} ${c.amber(config.agentReview, true)}`,
  );
}

async function presetConfigTui(current: PolicyPreset): Promise<PolicyPreset> {
  const options: Array<{ value: PolicyPreset; label: string; detail: string }> =
    [
      {
        value: "default",
        label: "default",
        detail:
          "Fresh versions under 7 days plus packages changed from the prior baseline.",
      },
      {
        value: "strict",
        label: "strict",
        detail: "Changed lockfile entries plus fresh versions under 30 days.",
      },
    ];
  renderPresetConfigMenu(options, current);
  const answer = prompt("Select 1-2, or press Enter to keep current:");
  if (!answer?.trim()) return current;
  const index = Number(answer.trim()) - 1;
  if (!Number.isInteger(index) || !options[index]) {
    throw new Error("Config cancelled: expected a number from 1 to 2");
  }
  return options[index].value;
}

async function agentConfigTui(current: AgentMode): Promise<AgentMode> {
  const options: Array<{ value: AgentMode; label: string; detail: string }> = [
    {
      value: "none",
      label: "No agent review",
      detail: "Only deterministic local analysis runs before install.",
    },
    {
      value: "codex",
      label: "Codex",
      detail: "Run codex exec in read-only mode for every scan/install gate.",
    },
    {
      value: "pi",
      label: "PI",
      detail: "Run pi -p with no tools for every scan/install gate.",
    },
  ];
  renderAgentConfigMenu(options, current);
  const answer = prompt("Select 1-3, or press Enter to keep current:");
  if (!answer?.trim()) return current;
  const index = Number(answer.trim()) - 1;
  if (!Number.isInteger(index) || !options[index]) {
    throw new Error("Config cancelled: expected a number from 1 to 3");
  }
  return options[index].value;
}

function renderPresetConfigMenu(
  options: Array<{ value: PolicyPreset; label: string; detail: string }>,
  current: PolicyPreset,
) {
  process.stdout.write(`${header("Supply Chain Guard Config")}\n`);
  process.stdout.write(
    `${c.gray("Choose the default lockfile policy preset for bare installs and scans.")}\n`,
  );
  process.stdout.write(`${c.dim("current:")} ${c.amber(current, true)}\n\n`);
  options.forEach((option, optionIndex) => {
    const active = option.value === current;
    const pointer = active ? c.amber("\u276f", true) : c.dim(" ");
    const num = active
      ? c.amber(String(optionIndex + 1), true)
      : c.gray(String(optionIndex + 1));
    const label = active ? c.amber(option.label, true) : c.white(option.label);
    process.stdout.write(`${pointer} ${num}. ${label}\n`);
    process.stdout.write(`   ${c.dim(option.detail)}\n`);
  });
  process.stdout.write("\n");
}

function renderAgentConfigMenu(
  options: Array<{ value: AgentMode; label: string; detail: string }>,
  current: AgentMode,
) {
  process.stdout.write(`${header("Supply Chain Guard Config")}\n`);
  process.stdout.write(
    `${c.gray("Choose default agent review for scans and install gates.")}\n`,
  );
  process.stdout.write(`${c.dim("current:")} ${c.amber(current, true)}\n\n`);
  options.forEach((option, optionIndex) => {
    const active = option.value === current;
    const pointer = active ? c.amber("\u276f", true) : c.dim(" ");
    const num = active
      ? c.amber(String(optionIndex + 1), true)
      : c.gray(String(optionIndex + 1));
    const label = active ? c.amber(option.label, true) : c.white(option.label);
    process.stdout.write(`${pointer} ${num}. ${label}\n`);
    process.stdout.write(`   ${c.dim(option.detail)}\n`);
  });
  process.stdout.write("\n");
}

export async function selfTest() {
  const { analyzeDirectory } = await import("./analysis");
  const { ensureLargeBinFixture } = await import("./fixtures-support");
  await ensureLargeBinFixture();
  const cases: Array<{
    dir: string;
    expect: "low" | "medium" | "high" | "medium-or-high";
  }> = [
    { dir: "benign-package", expect: "low" },
    { dir: "malicious-postinstall", expect: "high" },
    { dir: "credential-exfil", expect: "high" },
    { dir: "encoded-payload", expect: "high" },
    { dir: "large-bin", expect: "medium-or-high" },
  ];
  for (const tc of cases) {
    const fixturePath = join(ROOT, "src", "fixtures", tc.dir);
    const report = await analyzeDirectory(
      `fixture:${tc.dir}`,
      "npm",
      fixturePath,
      "local-fixture",
    );
    const ok =
      tc.expect === "medium-or-high"
        ? report.summary.risk === "medium" || report.summary.risk === "high"
        : report.summary.risk === tc.expect;
    if (!ok) {
      throw new Error(
        `self-test: fixture ${tc.dir} expected risk ${tc.expect}, got ${report.summary.risk}`,
      );
    }
  }
  console.log(
    `${style.ok()}  ${c.gray(`self-test passed (${cases.length} fixtures)`)}`,
  );
}
