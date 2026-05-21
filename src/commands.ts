import { mkdir, rm } from "node:fs/promises";
import { basename, delimiter, join, resolve } from "node:path";
import { homedir } from "node:os";
import {
  CACHE_DIR,
  CLI_ENTRY,
  CONFIG_ENV_PATH,
  REPORT_DIR,
  ROOT,
  WORK_DIR,
  commandExists,
  normalizeAgentMode,
  readActiveAdvisory,
  readConfig,
  readJson,
  readOption,
  requireActiveIncidentAcceptance,
  run,
  writeConfig,
} from "./core";
import type { AgentMode } from "./core";
import { scanNpm, scanNpmStage, scanVsix } from "./analysis";
import { resolveAgentMode, runAgentReviews } from "./integrations";
import { blockOnFailedReview, emitReport } from "./reporting";
import { c, header, style, withSpinner } from "./ui";
import { detectLockfile, parseLockfile, type DetectedLockfile, type LockfileEntry } from "./lockfile";
import type { Report } from "./core";
import { buildInstallCommand, detectPackageManager } from "./pm";
import { isOfflineMode, OFFLINE_ENV } from "./offline";

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

export async function reviewOrInstall(args: string[], opts: { install: boolean }) {
  const cleanArgs = stripGuardOptions(args);
  const specs = cleanArgs.filter((arg) => !arg.startsWith("--") && arg !== "-d");
  if (specs.length === 0) {
    throw new Error(`${opts.install ? "install" : "review"} requires at least one package spec, e.g. 'scguard ${opts.install ? "install" : "review"} react@18.3.1'`);
  }
  const dev = cleanArgs.includes("--dev") || cleanArgs.includes("-d");
  const agentMode = await resolveAgentMode(args);
  const sbom = args.includes("--sbom");
  const offline = isOfflineMode(args);
  const emitOpts = { sbom };
  const passed: string[] = [];
  for (const spec of specs) {
    const report = await withSpinner(
      `Resolving graph and simulating install for ${spec}...`,
      () => scanNpm(spec, { offline }),
    );
    let reportPath = await emitReport(report, false, emitOpts);
    if (!report.summary.installAllowed) {
      throw new Error([
        `Blocked ${spec}: high-risk findings.`,
        `  Markdown report: ${reportPath.replace(/\.json$/, ".md")}`,
        `  JSON report:     ${reportPath}`,
        `  To override (not recommended): SCGUARD_BYPASS=1 <your install command>`,
      ].join("\n"));
    }
    if (agentMode.length > 0) {
      const reviews = await runAgentReviews(report, reportPath, agentMode);
      report.agentReviews = reviews;
      reportPath = await emitReport(report, false, emitOpts);
      blockOnFailedReview(spec, reviews);
    }
    printNextSteps(spec, reportPath, opts.install);
    passed.push(spec);
  }
  if (!opts.install) return;
  requireActiveIncidentAcceptance();
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
  const installCmd = buildInstallCommand(detected.pm, passed, { dev });
  await run(installCmd.cmd, installCmd.args);
}

function printNextSteps(spec: string, reportPath: string, willInstall: boolean) {
  const md = reportPath.replace(/\.json$/, ".md");
  console.log(header(`Next steps  ${c.dim(spec)}`));
  if (willInstall) {
    console.log(`${style.ok()}  ${c.gray("gate passed - installing now")}`);
  } else {
    console.log(`  ${c.gray("Inspect the report, then:")}`);
    console.log(`    ${c.amber("$", true)} ${c.white(`scguard install ${spec}`)}`);
    console.log(`  ${c.gray("Or request a deeper agent review:")}`);
    console.log(`    ${c.amber("$", true)} ${c.white(`scguard agent-review ${reportPath} --agent codex`)}`);
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
  "SOCKET_API_KEY configured": "scguard config  # or visit socket.dev to get a key",
};

export async function doctorCommand() {
  const checks: Array<{ name: string; ok: boolean; detail: string }> = [];
  for (const bin of ["bun", "git", "tar", "unzip"]) {
    checks.push({ name: `dependency: ${bin}`, ok: await commandExists(bin), detail: `${bin} required` });
  }
  for (const bin of ["codex", "pi"]) {
    const ok = await commandExists(bin);
    checks.push({ name: `optional agent: ${bin}`, ok, detail: ok ? "available" : "not installed (agent review unavailable)" });
  }
  const localBin = join(homedir(), ".local", "bin");
  const path = (Bun.env.PATH ?? "").split(delimiter);
  checks.push({ name: `~/.local/bin on PATH`, ok: path.includes(localBin), detail: path.includes(localBin) ? localBin : `${localBin} missing from PATH` });
  const hookActive = !!Bun.env.SCGUARD_SHELL_HOOK_ACTIVE;
  checks.push({ name: `shell hook active`, ok: hookActive, detail: hookActive ? "active" : "run: eval \"$(scguard shell-hook)\"" });
  const tokenSet = !!Bun.env.SOCKET_API_KEY;
  checks.push({ name: `SOCKET_API_KEY configured`, ok: tokenSet, detail: tokenSet ? "set" : "unset (Socket scoring disabled)" });
  const config = await readConfig();
  checks.push({ name: `default agent review`, ok: true, detail: config.agentReview });
  checks.push({ name: `project root`, ok: true, detail: ROOT });
  checks.push({ name: `reports directory`, ok: true, detail: REPORT_DIR });

  console.log(header("scguard doctor"));
  let allOk = true;
  for (const check of checks) {
    const marker = check.ok
      ? `${style.check()} ${c.green("ok  ", true)}`
      : `${style.cross()} ${c.amber("warn", true)}`;
    if (!check.ok) allOk = false;
    console.log(`  ${marker}  ${c.white(check.name.padEnd(28))} ${c.dim(check.detail)}`);
    if (!check.ok && DOCTOR_FIX_HINTS[check.name]) {
      console.log(`           ${c.dim(`fix: ${DOCTOR_FIX_HINTS[check.name]}`)}`);
    }
  }
  console.log("");
  if (allOk) {
    console.log(`${style.ok()}  ${c.gray("all checks passed.")}`);
  } else {
    console.log(`${c.amber("note", true)} ${c.gray("some checks failed. fix the items above for the smoothest experience.")}`);
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
    console.log(`${style.check()} ${c.green("cleared", true)}  ${c.white(label.padEnd(8))} ${c.dim(dir)}`);
  }
}

export async function guardCommand(args: string[]) {
  const command = args[0];
  if (!command) throw new Error("guard requires the command being wrapped");
  const realArgs = stripGuardOptions(args.slice(1));
  if (Bun.env.SCGUARD_BYPASS === "1") {
    console.error(`scguard: SCGUARD_BYPASS=1 set; running ${command} unguarded.`);
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

  if (classification.kind === "npm-stage") {
    await guardNpmStage(command, realArgs, classification.specs);
    return;
  }

  const advisory = readActiveAdvisory();
  const action = String(classification.action);
  const isBareInstall = classification.specs.length === 0 && (action === "install" || action === "i" || action === "ci");
  const specs = classification.specs.length > 0
    ? classification.specs
    : await inferSpecsForPackageOperation(action);
  console.error(`${c.amber("scguard", true)} ${c.gray(`${classification.action} detected:`)} ${c.white(`${command} ${realArgs.join(" ")}`)}`);
  console.error(`${c.amber("scguard", true)} ${c.gray("this command can execute lifecycle code from untrusted packages.")}`);

  if (isBareInstall) {
    const summary = await scanLockfile(process.cwd(), args.slice(1));
    if (summary.blocked.length > 0) throw lockfileBlockingError(summary);
    requireActiveIncidentAcceptance(advisory);
    await run(command, realArgs);
    return;
  }

  if (specs.length > 0) {
    console.error(`${c.amber("scguard", true)} ${c.gray("staging analysis required for")} ${c.white(specs.join(", "))}`);
    const offline = isOfflineMode(args);
    for (const spec of specs) {
      const report = await withSpinner(
        `Resolving graph and simulating install for ${spec}...`,
        () => scanNpm(spec, { offline }),
      );
      let reportPath = await emitReport(report, false);
      if (!report.summary.installAllowed) {
        throw new Error(`Blocked ${spec}: high-risk findings found. See ${reportPath}`);
      }
      const agentMode = await resolveAgentMode(args.slice(1));
      if (agentMode.length > 0) {
        const reviews = await runAgentReviews(report, reportPath, agentMode);
        report.agentReviews = reviews;
        reportPath = await emitReport(report, false);
        blockOnFailedReview(spec, reviews);
      }
    }
  }

  requireActiveIncidentAcceptance(advisory);

  await run(command, realArgs);
}

async function guardVsCodeExtension(command: string, args: string[], specs: string[]) {
  const target = specs[0];
  console.error(`scguard: VS Code extension install detected: ${command} ${args.join(" ")}`);
  console.error("scguard: extensions run code inside your editor and can access workspace files.");
  if (!target) throw new Error("Blocked VS Code extension install: no extension target found.");
  if (!target.endsWith(".vsix")) {
    throw new Error("Blocked VS Code extension install by ID. Download the .vsix first, run scan-vsix, then install the reviewed artifact.");
  }
  const report = await scanVsix(resolve(target));
  let reportPath = await emitReport(report, false);
  if (!report.summary.installAllowed) {
    throw new Error(`Blocked ${target}: high-risk findings found. See ${reportPath}`);
  }
  const agentMode = await resolveAgentMode(args);
  if (agentMode.length > 0) {
    const reviews = await runAgentReviews(report, reportPath, agentMode);
    report.agentReviews = reviews;
    reportPath = await emitReport(report, false);
    blockOnFailedReview(target, reviews);
  }
  requireActiveIncidentAcceptance();
  await run(command, stripGuardOptions(args));
}

async function guardNpmStage(command: string, args: string[], specs: string[]) {
  const stageId = specs[0];
  console.error(`scguard: npm staged publish approval detected: ${command} ${args.join(" ")}`);
  console.error("scguard: staged packages must be downloaded and analyzed before approval.");
  if (!stageId) throw new Error("Blocked npm stage approve: no stage id found.");
  const report = await scanNpmStage(stageId, { offline: isOfflineMode(args) });
  let reportPath = await emitReport(report, false);
  if (!report.summary.installAllowed) {
    throw new Error(`Blocked npm stage approve ${stageId}: high-risk findings found. See ${reportPath}`);
  }
  const agentMode = await resolveAgentMode(args);
  if (agentMode.length > 0) {
    const reviews = await runAgentReviews(report, reportPath, agentMode);
    report.agentReviews = reviews;
    reportPath = await emitReport(report, false);
    blockOnFailedReview(stageId, reviews);
  }
  requireActiveIncidentAcceptance();
  await run(command, stripGuardOptions(args));
}

async function inferSpecsForPackageOperation(action: string) {
  if (action === "update" || action === "upgrade") {
    throw new Error("Broad package updates are blocked. Run the command with explicit package specs so each update can be staged and analyzed first.");
  }
  return [];
}

export interface LockfileScanSummary {
  detected: DetectedLockfile;
  totalPackages: number;
  scanned: number;
  failed: { name: string; version: string; error: string }[];
  blocked: { name: string; version: string; reportPath: string }[];
  warnings: { name: string; version: string; reportPath: string }[];
}

export async function scanLockfileCommand(args: string[]): Promise<LockfileScanSummary> {
  const cwd = args.find((a) => !a.startsWith("--")) ?? process.cwd();
  return scanLockfile(cwd, args);
}

export async function scanLockfile(cwd: string, args: string[] = []): Promise<LockfileScanSummary> {
  const detected = detectLockfile(cwd);
  if (!detected) {
    throw new Error(`No lockfile found in ${cwd}. Expected one of: bun.lock, package-lock.json, pnpm-lock.yaml, yarn.lock.`);
  }
  const entries = await parseLockfile(detected);
  if (entries.length === 0) {
    throw new Error(`Parsed ${detected.path} but found no package entries.`);
  }

  console.log(header(`scguard scan-lockfile  ${c.dim(detected.kind)}`));
  console.log(`  ${c.gray("lockfile:")} ${c.white(detected.path)}`);
  console.log(`  ${c.gray("packages:")} ${c.white(String(entries.length))}`);

  const concurrency = Math.max(1, Number(Bun.env.SCGUARD_LOCKFILE_CONCURRENCY ?? 8));
  const offline = isOfflineMode(args);
  const summary: LockfileScanSummary = {
    detected,
    totalPackages: entries.length,
    scanned: 0,
    failed: [],
    blocked: [],
    warnings: [],
  };

  let cursor = 0;
  let completed = 0;
  const total = entries.length;

  const writeProgress = () => {
    if (!process.stderr.isTTY) return;
    const bar = `[${completed}/${total}]`;
    process.stderr.write(`\r  ${c.amber("scanning", true)} ${c.gray(bar)}     `);
  };

  async function worker() {
    while (true) {
      const i = cursor++;
      if (i >= entries.length) return;
      const entry = entries[i];
      const spec = `${entry.name}@${entry.version}`;
      try {
        const report = await scanNpm(spec, { offline });
        summary.scanned++;
        const reportPath = await emitReport(report, false);
        if (!report.summary.installAllowed) {
          summary.blocked.push({ name: entry.name, version: entry.version, reportPath });
        } else if (report.summary.risk === "medium") {
          summary.warnings.push({ name: entry.name, version: entry.version, reportPath });
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
  await Promise.all(Array.from({ length: concurrency }, () => worker()));
  if (process.stderr.isTTY) process.stderr.write("\n");

  console.log("");
  console.log(`  ${style.check()} ${c.green("scanned ", true)} ${c.white(String(summary.scanned))}/${c.white(String(total))}`);
  if (summary.warnings.length > 0) {
    console.log(`  ${c.amber("warn    ", true)} ${c.white(String(summary.warnings.length))} ${c.gray("medium-risk packages")}`);
  }
  if (summary.failed.length > 0) {
    console.log(`  ${c.amber("skipped ", true)} ${c.white(String(summary.failed.length))} ${c.gray("packages could not be analyzed")}`);
    for (const f of summary.failed.slice(0, 5)) {
      console.log(`    ${c.dim(`- ${f.name}@${f.version}: ${f.error.split("\n")[0]}`)}`);
    }
    if (summary.failed.length > 5) console.log(`    ${c.dim(`... and ${summary.failed.length - 5} more`)}`);
  }
  if (summary.blocked.length > 0) {
    console.log(`  ${c.red("blocked ", true)} ${c.white(String(summary.blocked.length))} ${c.gray("high-risk packages")}`);
    for (const b of summary.blocked) {
      console.log(`    ${c.red("-", true)} ${c.white(`${b.name}@${b.version}`)} ${c.dim(b.reportPath)}`);
    }
  }

  return summary;
}

function lockfileBlockingError(summary: LockfileScanSummary): Error {
  const lines = [
    `Blocked install: ${summary.blocked.length} high-risk package(s) in ${summary.detected.path}.`,
    ...summary.blocked.map((b) => `  - ${b.name}@${b.version}  ${b.reportPath}`),
    `To bypass for one command (not recommended): SCGUARD_BYPASS=1 <your command>`,
  ];
  return new Error(lines.join("\n"));
}

export function classifyPackageCommand(command: string, args: string[]) {
  const base = basename(command);
  if (base === "npm" && args[0] === "stage" && args[1] === "approve") {
    return {
      packageOperation: true,
      kind: "npm-stage" as const,
      action: "stage approve",
      specs: args[2] ? [args[2]] : [],
    };
  }
  if (base === "code" && args.includes("--install-extension")) {
    const index = args.indexOf("--install-extension");
    return {
      packageOperation: true,
      kind: "vsix" as const,
      action: "install-extension",
      specs: args[index + 1] ? [args[index + 1]] : [],
    };
  }
  const sub = args.find((arg) => !arg.startsWith("-"));
  const installActions = new Set(["add", "install", "i", "update", "upgrade", "ci"]);
  const packageManagers = new Set(["bun", "npm", "pnpm", "yarn"]);
  const packageOperation = packageManagers.has(base) && !!sub && installActions.has(sub);
  const specs = packageOperation ? extractSpecs(base, args) : [];
  return { packageOperation, kind: "npm" as const, action: sub ?? "run", specs };
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
]);

function extractSpecs(base: string, args: string[]) {
  const actionIndex = args.findIndex((arg) => !arg.startsWith("-"));
  const rest = actionIndex === -1 ? [] : args.slice(actionIndex + 1);
  if (base === "npm" && (args[actionIndex] === "ci" || rest.length === 0)) return [];
  const specs: string[] = [];
  for (let i = 0; i < rest.length; i++) {
    const arg = rest[i];
    if (arg.startsWith("-")) {
      // `--key=value` carries its value inline; skip the flag only.
      if (arg.includes("=")) continue;
      // For known value-taking options, also skip the following argument.
      if (VALUE_OPTIONS.has(arg)) i++;
      continue;
    }
    if (arg.includes("=")) continue;
    specs.push(arg);
  }
  return specs;
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
    // --sbom is scguard-only. --offline is passed through (bun/npm/pnpm/yarn all honour it).
    if (arg === "--sbom") continue;
    stripped.push(arg);
  }
  return stripped;
}

export function shellHook() {
  const entry = CLI_ENTRY;
  return `[ -f "${CONFIG_ENV_PATH}" ] && source "${CONFIG_ENV_PATH}"
export SCGUARD_SHELL_HOOK_ACTIVE=1
scguard() { command bun run ${entry} "$@"; }
bun() { command bun run ${entry} guard bun "$@"; }
npm() { command bun run ${entry} guard npm "$@"; }
pnpm() { command bun run ${entry} guard pnpm "$@"; }
yarn() { command bun run ${entry} guard yarn "$@"; }
code() { command bun run ${entry} guard code "$@"; }
`;
}

export async function configCommand(args: string[]) {
  if (args.includes("--show")) {
    console.log(JSON.stringify(await readConfig(), null, 2));
    return;
  }
  const explicit = readOption(args, "--agent");
  if (explicit) {
    const config = await readConfig();
    config.agentReview = normalizeAgentMode(explicit);
    await writeConfig(config);
    console.log(`${style.check()} ${c.green("saved", true)} ${c.gray("default agent review:")} ${c.amber(config.agentReview, true)}`);
    return;
  }
  const config = await readConfig();
  config.agentReview = await agentConfigTui(config.agentReview);
  await writeConfig(config);
  console.log(`${style.check()} ${c.green("saved", true)} ${c.gray("default agent review:")} ${c.amber(config.agentReview, true)}`);
}

async function agentConfigTui(current: AgentMode): Promise<AgentMode> {
  const options: Array<{ value: AgentMode; label: string; detail: string }> = [
    { value: "none", label: "No agent review", detail: "Only deterministic local analysis runs before install." },
    { value: "codex", label: "Codex", detail: "Run codex exec in read-only mode for every scan/install gate." },
    { value: "pi", label: "PI", detail: "Run pi -p with no tools for every scan/install gate." },
    { value: "both", label: "Codex + PI", detail: "Require both agents to approve before install continues." },
  ];
  renderAgentConfigMenu(options, current);
  const answer = prompt("Select 1-4, or press Enter to keep current:");
  if (!answer?.trim()) return current;
  const index = Number(answer.trim()) - 1;
  if (!Number.isInteger(index) || !options[index]) {
    throw new Error("Config cancelled: expected a number from 1 to 4");
  }
  return options[index].value;
}

function renderAgentConfigMenu(options: Array<{ value: AgentMode; label: string; detail: string }>, current: AgentMode) {
  process.stdout.write(`${header("Supply Chain Guard Config")}\n`);
  process.stdout.write(`${c.gray("Choose default agent review for scans and install gates.")}\n`);
  process.stdout.write(`${c.dim("current:")} ${c.amber(current, true)}\n\n`);
  options.forEach((option, optionIndex) => {
    const active = option.value === current;
    const pointer = active ? c.amber("\u276f", true) : c.dim(" ");
    const num = active ? c.amber(String(optionIndex + 1), true) : c.gray(String(optionIndex + 1));
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
  const cases: Array<{ dir: string; expect: "low" | "medium" | "high" | "medium-or-high" }> = [
    { dir: "benign-package", expect: "low" },
    { dir: "malicious-postinstall", expect: "high" },
    { dir: "credential-exfil", expect: "high" },
    { dir: "encoded-payload", expect: "high" },
    { dir: "large-bin", expect: "medium-or-high" },
  ];
  for (const tc of cases) {
    const fixturePath = join(ROOT, "src", "fixtures", tc.dir);
    const report = await analyzeDirectory(`fixture:${tc.dir}`, "npm", fixturePath, "local-fixture");
    const ok = tc.expect === "medium-or-high"
      ? report.summary.risk === "medium" || report.summary.risk === "high"
      : report.summary.risk === tc.expect;
    if (!ok) {
      throw new Error(`self-test: fixture ${tc.dir} expected risk ${tc.expect}, got ${report.summary.risk}`);
    }
  }
  console.log(`${style.ok()}  ${c.gray(`self-test passed (${cases.length} fixtures)`)}`);
}
