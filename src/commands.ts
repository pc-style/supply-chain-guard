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

export async function reviewOrInstall(args: string[], opts: { install: boolean }) {
  const cleanArgs = stripGuardOptions(args);
  const specs = cleanArgs.filter((arg) => !arg.startsWith("--") && arg !== "-d");
  if (specs.length === 0) {
    throw new Error(`${opts.install ? "install" : "review"} requires at least one package spec, e.g. 'scguard ${opts.install ? "install" : "review"} react@18.3.1'`);
  }
  const dev = cleanArgs.includes("--dev") || cleanArgs.includes("-d");
  const agentMode = await resolveAgentMode(args);
  const passed: string[] = [];
  for (const spec of specs) {
    const report = await withSpinner(
      `Resolving graph and simulating install for ${spec}...`,
      () => scanNpm(spec),
    );
    let reportPath = await emitReport(report, false);
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
      reportPath = await emitReport(report, false);
      blockOnFailedReview(spec, reviews);
    }
    printNextSteps(spec, reportPath, opts.install);
    passed.push(spec);
  }
  if (!opts.install) return;
  requireActiveIncidentAcceptance();
  await run("bun", ["add", ...(dev ? ["--dev"] : []), ...passed]);
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
  const specs = classification.specs.length > 0
    ? classification.specs
    : await inferSpecsForPackageOperation(String(classification.action));
  console.error(`${c.amber("scguard", true)} ${c.gray(`${classification.action} detected:`)} ${c.white(`${command} ${realArgs.join(" ")}`)}`);
  console.error(`${c.amber("scguard", true)} ${c.gray("this command can execute lifecycle code from untrusted packages.")}`);

  if (specs.length > 0) {
    console.error(`${c.amber("scguard", true)} ${c.gray("staging analysis required for")} ${c.white(specs.join(", "))}`);
    for (const spec of specs) {
      const report = await withSpinner(
        `Resolving graph and simulating install for ${spec}...`,
        () => scanNpm(spec),
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
  const report = await scanNpmStage(stageId);
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
  if (action === "install" || action === "i" || action === "ci") {
    throw new Error([
      `Blocked bare '${action}': scguard cannot yet review the exact tarballs your lockfile resolves to.`,
      `Use explicit specs ('npm install react', 'bun add lodash@4.17.21') so each package can be staged and analyzed.`,
      `To bypass this guard for one command (not recommended): SCGUARD_BYPASS=1 <your command>`,
    ].join("\n"));
  }
  return [];
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
    if (args[i] === "--agent") {
      i++;
      continue;
    }
    stripped.push(args[i]);
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
  const fixtures = join(ROOT, "src", "fixtures", "benign-package");
  const report = await analyzeDirectory("fixture", "npm", fixtures, "local-fixture");
  if (report.summary.risk !== "low") throw new Error("self-test expected low risk fixture");
  console.log(`${style.ok()}  ${c.gray("self-test passed")}`);
}
