#!/usr/bin/env bun
import { mkdir, mkdtemp, readdir, stat } from "node:fs/promises";
import { createHash } from "node:crypto";
import { basename, dirname, join, relative, resolve } from "node:path";
import { homedir } from "node:os";

type Risk = "low" | "medium" | "high";

type Finding = {
  id: string;
  title: string;
  severity: Risk;
  evidence: string;
  recommendation: string;
};

type Report = {
  schemaVersion: 1;
  target: string;
  kind: "npm" | "npm-stage" | "vsix";
  generatedAt: string;
  artifact: {
    source: string;
    sha256: string;
    bytes: number;
  };
  intelligence: {
    socket?: SocketResult;
    activeAdvisory?: ActiveAdvisory;
  };
  packageJson?: Record<string, unknown>;
  summary: {
    risk: Risk;
    findingCount: number;
    installAllowed: boolean;
  };
  findings: Finding[];
  agentReviews?: AgentReview[];
};

type AgentName = "codex" | "pi";
type AgentMode = "none" | AgentName | "both";

type Config = {
  agentReview: AgentMode;
};

type AgentReview = {
  agent: AgentName;
  status: "approved" | "rejected" | "manual-review" | "error";
  outputPath: string;
  exitCode: number;
  summary: string;
};

type SocketResult = {
  status: "checked" | "skipped" | "error";
  package?: string;
  version?: string;
  url?: string;
  supplyChainRisk?: number;
  rawScore?: unknown;
  message?: string;
};

type ActiveAdvisory = {
  active: boolean;
  source: "env";
  message: string;
  until?: string;
};

const ROOT = process.cwd();
const CLI_ENTRY = import.meta.path;
const GUARD_DIR = join(ROOT, ".scguard");
const CACHE_DIR = join(GUARD_DIR, "cache");
const WORK_DIR = join(GUARD_DIR, "work");
const REPORT_DIR = join(GUARD_DIR, "reports");
const CONFIG_ENV_PATH = join(homedir(), ".config", "supply-chain-guard", "env");
const CONFIG_DIR = join(homedir(), ".config", "supply-chain-guard");
const CONFIG_PATH = join(CONFIG_DIR, "config.json");
const DEFAULT_CONFIG: Config = {
  agentReview: "none",
};

const INSTALL_SCRIPTS = new Set(["preinstall", "install", "postinstall", "prepare"]);
const SUSPICIOUS_PATTERNS: Array<[RegExp, string, Risk, string]> = [
  [/curl\s+[^|]+\|\s*(sh|bash)/i, "pipe-to-shell", "high", "Downloads and executes remote shell code."],
  [/wget\s+[^|]+\|\s*(sh|bash)/i, "pipe-to-shell", "high", "Downloads and executes remote shell code."],
  [/(require\(["']child_process["']\)|from ["']node:child_process["']|execSync\(|spawnSync\(|eval\(|new Function\()/, "dynamic-execution", "medium", "Uses dynamic process or code execution."],
  [/(base64\s+-d|Buffer\.from\([^)]*base64)/i, "encoded-payload", "medium", "Decodes base64 payloads."],
  [/(npmrc|\.ssh|id_rsa|AWS_SECRET|GITHUB_TOKEN|NPM_TOKEN|process\.env)/i, "credential-access", "high", "References credentials, tokens, or sensitive local paths."],
  [/(https?:\/\/|fetch\(|XMLHttpRequest)/i, "network-access", "medium", "Performs network access during package code or scripts."],
];

async function main() {
  const cliArgs = normalizeArgv(Bun.argv);
  const [cmd, ...args] = cliArgs;
  if (Bun.env.SCGUARD_DEBUG_ARGV) {
    console.error(JSON.stringify({ argv: Bun.argv, cliArgs, cmd, args }));
  }
  await ensureDirs();

  if (!cmd || cmd === "--help" || cmd === "-h") {
    help();
    return;
  }

  if (cmd === "--version" || cmd === "-v" || cmd === "version") {
    const pkg = await readJson<{ version: string }>(join(dirname(CLI_ENTRY), "..", "package.json"));
    console.log(pkg.version);
    return;
  }

  if (cmd === "scan-npm") {
    const target = requireArg(args[0], "scan-npm requires a package spec");
    const report = await scanNpm(target);
    const reportPath = await emitReport(report, args.includes("--json"));
    await maybeRunConfiguredAgentReview(report, reportPath, args, args.includes("--json"));
    return;
  }

  if (cmd === "scan-stage") {
    const stageId = requireArg(args[0], "scan-stage requires an npm stage id");
    const report = await scanNpmStage(stageId);
    const reportPath = await emitReport(report, args.includes("--json"));
    await maybeRunConfiguredAgentReview(report, reportPath, args, args.includes("--json"));
    return;
  }

  if (cmd === "add") {
    const cleanArgs = stripGuardOptions(args);
    const specs = cleanArgs.filter((arg) => !arg.startsWith("--"));
    if (specs.length === 0) throw new Error("add requires at least one package spec");
    const approve = args.includes("--approve");
    const dev = cleanArgs.includes("--dev") || cleanArgs.includes("-d");
    const agentMode = await resolveAgentMode(args);
    for (const spec of specs) {
      const report = await scanNpm(spec);
      let reportPath = await emitReport(report, false);
      if (!report.summary.installAllowed) {
        throw new Error(`Blocked ${spec}: high-risk findings found. See ${reportPath}`);
      }
      if (agentMode.length > 0) {
        const agentReviews = await runAgentReviews(report, reportPath, agentMode);
        report.agentReviews = agentReviews;
        reportPath = await emitReport(report, false);
        blockOnFailedReview(spec, agentReviews);
      }
      if (!approve) {
        console.log(`Analysis complete for ${spec}. Install withheld until --approve is supplied.`);
        console.log(`Report: ${reportPath}`);
        continue;
      }
      requireActiveIncidentAcceptance();
      await run("bun", ["add", dev ? "--dev" : "", spec].filter(Boolean));
    }
    return;
  }

  if (cmd === "scan-vsix") {
    const file = requireArg(args[0], "scan-vsix requires a .vsix path");
    const report = await scanVsix(resolve(file));
    const reportPath = await emitReport(report, args.includes("--json"));
    await maybeRunConfiguredAgentReview(report, reportPath, args, args.includes("--json"));
    return;
  }

  if (cmd === "agent-prompt") {
    const reportPath = requireArg(args[0], "agent-prompt requires a report path");
    const agent = readOption(args, "--agent") ?? "codex";
    const report = await readJson<Report>(reportPath);
    const promptPath = await writeAgentPrompt(report, agent);
    console.log(promptPath);
    return;
  }

  if (cmd === "agent-review") {
    const reportPath = requireArg(args[0], "agent-review requires a report path");
    const report = await readJson<Report>(reportPath);
    const agentMode = await resolveAgentMode(args);
    const agents = agentMode.length > 0 ? agentMode : ["codex" as const];
    const reviews = await runAgentReviews(report, reportPath, agents);
    console.log(JSON.stringify(reviews, null, 2));
    if (reviews.some((review) => review.status !== "approved")) process.exit(2);
    return;
  }

  if (cmd === "guard") {
    await guardCommand(args);
    return;
  }

  if (cmd === "shell-hook") {
    console.log(shellHook());
    return;
  }

  if (cmd === "config") {
    await configCommand(args);
    return;
  }

  if (cmd === "self-test") {
    const fixtures = join(ROOT, "src", "fixtures", "benign-package");
    const report = await analyzeDirectory("fixture", "npm", fixtures, "local-fixture");
    if (report.summary.risk !== "low") throw new Error("self-test expected low risk fixture");
    console.log("self-test passed");
    return;
  }

  throw new Error(`Unknown command: ${cmd}`);
}

function normalizeArgv(argv: string[]) {
  const raw = argv.slice(1);
  const first = raw[0] ?? "";
  if (first.endsWith("src/cli.ts") || first.endsWith("/scguard") || first.endsWith("\\scguard")) {
    return raw.slice(1);
  }
  return raw;
}

async function scanNpm(spec: string): Promise<Report> {
  debug(`resolving ${spec}`);
  const meta = await resolveNpm(spec);
  const tarball = String(meta.dist.tarball);
  const safeName = meta.name.replaceAll("/", "_").replaceAll("@", "");
  const artifactPath = join(CACHE_DIR, `${safeName}-${meta.version}.tgz`);
  debug(`downloading ${tarball}`);
  await download(tarball, artifactPath);
  debug(`extracting ${artifactPath}`);
  const extracted = await extractTarball(artifactPath);
  const packageDir = await findPackageRoot(extracted);
  debug(`analyzing ${packageDir}`);
  return analyzeDirectory(`${meta.name}@${meta.version}`, "npm", packageDir, tarball, artifactPath, {
    socket: await checkSocket(String(meta.name), String(meta.version)),
  });
}

async function scanVsix(file: string): Promise<Report> {
  const extracted = await mkdtemp(join(WORK_DIR, "vsix-"));
  await run("unzip", ["-q", file, "-d", extracted]);
  const extensionDir = join(extracted, "extension");
  return analyzeDirectory(basename(file), "vsix", extensionDir, file, file);
}

async function scanNpmStage(stageId: string): Promise<Report> {
  const artifactPath = await downloadNpmStage(stageId);
  const extracted = await extractTarball(artifactPath);
  const packageDir = await findPackageRoot(extracted);
  const pkg = await readJson<Record<string, unknown>>(join(packageDir, "package.json"));
  const name = String(pkg.name ?? "unknown");
  const version = String(pkg.version ?? "unknown");
  return analyzeDirectory(`npm-stage:${stageId}:${name}@${version}`, "npm-stage", packageDir, `npm stage download ${stageId}`, artifactPath, {
    socket: name !== "unknown" && version !== "unknown" ? await checkSocket(name, version) : undefined,
  });
}

async function analyzeDirectory(
  target: string,
  kind: "npm" | "npm-stage" | "vsix",
  dir: string,
  source: string,
  artifactPath?: string,
  intelligence: Partial<Report["intelligence"]> = {},
): Promise<Report> {
  const pkgPath = join(dir, "package.json");
  const pkg = await readJson<Record<string, unknown>>(pkgPath);
  const findings: Finding[] = [];
  inspectPackageJson(pkg, kind, findings);
  inspectIntelligence(intelligence, findings);
  await inspectFiles(dir, findings);
  const artifact = artifactPath ? await artifactInfo(artifactPath, source) : { source, sha256: "not-applicable", bytes: 0 };
  const risk = summarizeRisk(findings);
  return {
    schemaVersion: 1,
    target,
    kind,
    generatedAt: new Date().toISOString(),
    artifact,
    intelligence: {
      ...intelligence,
      activeAdvisory: readActiveAdvisory(),
    },
    packageJson: pkg,
    summary: {
      risk,
      findingCount: findings.length,
      installAllowed: risk !== "high",
    },
    findings,
  };
}

function inspectIntelligence(intelligence: Partial<Report["intelligence"]>, findings: Finding[]) {
  if (intelligence.socket?.status === "checked") {
    const risk = intelligence.socket.supplyChainRisk;
    if (typeof risk === "number" && risk >= 0.7) {
      findings.push({
        id: "socket.supply-chain-risk",
        title: "Socket reports elevated supply-chain risk",
        severity: risk >= 0.9 ? "high" : "medium",
        evidence: `supplyChainRisk=${risk}`,
        recommendation: "Require agent review and inspect Socket package details before installing.",
      });
    }
  }
  const advisory = readActiveAdvisory();
  if (advisory.active) {
    findings.push({
      id: "advisory.active-supply-chain-incident",
      title: "Active supply-chain advisory is enabled",
      severity: "medium",
      evidence: advisory.message,
      recommendation: "Use staging flow only and require explicit acknowledgement before package operations.",
    });
  }
}

function inspectPackageJson(pkg: Record<string, unknown>, kind: "npm" | "npm-stage" | "vsix", findings: Finding[]) {
  const scripts = objectValue(pkg.scripts);
  for (const [name, raw] of Object.entries(scripts)) {
    const script = String(raw);
    if (INSTALL_SCRIPTS.has(name)) {
      findings.push({
        id: `script.${name}`,
        title: `Lifecycle script: ${name}`,
        severity: name === "install" || name === "postinstall" ? "high" : "medium",
        evidence: script,
        recommendation: "Manually inspect the script and require agent review before installing.",
      });
    }
    inspectText(`script.${name}`, script, findings);
  }

  const bins = pkg.bin;
  if (bins) {
    findings.push({
      id: "package.bin",
      title: "Package exposes executables",
      severity: "medium",
      evidence: JSON.stringify(bins),
      recommendation: "Review executable entry points before adding to PATH or running commands.",
    });
  }

  if (kind === "vsix") {
    const activationEvents = Array.isArray(pkg.activationEvents) ? pkg.activationEvents : [];
    if (activationEvents.includes("*")) {
      findings.push({
        id: "vscode.activation.all",
        title: "Extension activates on startup",
        severity: "high",
        evidence: JSON.stringify(activationEvents),
        recommendation: "Avoid broad activation unless the publisher and source are trusted.",
      });
    }
    if (pkg.main || pkg.browser) {
      findings.push({
        id: "vscode.entrypoint",
        title: "Extension has executable entry point",
        severity: "medium",
        evidence: JSON.stringify({ main: pkg.main, browser: pkg.browser }),
        recommendation: "Review the extension entry code before installing.",
      });
    }
  }

  const depCount = Object.keys(objectValue(pkg.dependencies)).length;
  if (depCount > 40) {
    findings.push({
      id: "dependencies.large",
      title: "Large dependency surface",
      severity: "medium",
      evidence: `${depCount} runtime dependencies`,
      recommendation: "Use an agent or manual review to inspect newly introduced transitive risk.",
    });
  }
}

async function inspectFiles(dir: string, findings: Finding[]) {
  const files = await walk(dir);
  for (const file of files) {
    const rel = file.slice(dir.length + 1);
    const s = await stat(file);
    if (s.size > 2_000_000) {
      findings.push({
        id: `large-file.${rel}`,
        title: "Large packed file",
        severity: "medium",
        evidence: `${rel} is ${s.size} bytes`,
        recommendation: "Confirm this file is expected in the published artifact.",
      });
    }
    if (rel === "package.json") continue;
    if (!/\.(js|cjs|mjs|ts|sh|ps1|cmd|node)$/i.test(file) || s.size > 300_000) continue;
    const text = await Bun.file(file).text().catch(() => "");
    inspectText(`file.${rel}`, stripComments(text).slice(0, 300_000), findings);
  }
}

function inspectText(scope: string, text: string, findings: Finding[]) {
  for (const [pattern, id, severity, title] of SUSPICIOUS_PATTERNS) {
    const match = text.match(pattern);
    if (!match) continue;
    findings.push({
      id: `${scope}.${id}`,
      title,
      severity,
      evidence: snippet(text, match.index ?? 0),
      recommendation: "Review the exact code path and require a trusted explanation before installing.",
    });
  }
}

async function resolveNpm(spec: string): Promise<Record<string, any>> {
  const { name, version } = parsePackageSpec(spec);
  const res = await fetch(`https://registry.npmjs.org/${encodeURIComponent(name).replace("%40", "@")}`);
  if (!res.ok) throw new Error(`Registry lookup failed for ${name}: ${res.status}`);
  const data = await res.json() as Record<string, any>;
  const resolvedVersion = version && data.versions?.[version] ? version : data["dist-tags"]?.[version ?? "latest"];
  const meta = data.versions?.[resolvedVersion];
  if (!meta) throw new Error(`Version not found: ${spec}`);
  return meta;
}

async function checkSocket(name: string, version: string): Promise<SocketResult> {
  const token = Bun.env.SOCKET_API_KEY;
  const packagePath = `${encodeURIComponent(name).replace("%40", "@")}/${encodeURIComponent(version)}`;
  const url = `https://api.socket.dev/v0/npm/${packagePath}/score`;
  if (!token) {
    return {
      status: "skipped",
      package: name,
      version,
      url,
      message: "SOCKET_API_KEY is not set; Socket intelligence was not queried.",
    };
  }
  try {
    const res = await fetch(url, {
      headers: {
        Authorization: `Basic ${Buffer.from(`${token}:`).toString("base64")}`,
        Accept: "application/json",
      },
    });
    if (!res.ok) {
      return { status: "error", package: name, version, url, message: `Socket returned HTTP ${res.status}` };
    }
    const data = await res.json() as Record<string, any>;
    const score = data.score ?? data;
    const supplyChainRisk = typeof score?.supplyChainRisk === "number" ? score.supplyChainRisk : undefined;
    return { status: "checked", package: name, version, url, supplyChainRisk, rawScore: score };
  } catch (error) {
    return {
      status: "error",
      package: name,
      version,
      url,
      message: error instanceof Error ? error.message : String(error),
    };
  }
}

async function guardCommand(args: string[]) {
  const command = requireArg(args[0], "guard requires the command being wrapped");
  const realArgs = stripGuardOptions(args.slice(1));
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
  console.error(`scguard: package ${classification.action} detected: ${command} ${realArgs.join(" ")}`);
  console.error("scguard: weak warning - package operations can execute untrusted lifecycle code.");

  if (specs.length > 0) {
    console.error(`scguard: staging analysis required for ${specs.join(", ")}`);
    for (const spec of specs) {
      const report = await scanNpm(spec);
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
  console.error("scguard: weak warning - extensions run code inside your editor and can access workspace files.");
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
  if (action !== "install" && action !== "i" && action !== "ci") return [];
  const pkgPath = join(ROOT, "package.json");
  const pkg = await readJson<Record<string, unknown>>(pkgPath);
  const deps = {
    ...objectValue(pkg.dependencies),
    ...objectValue(pkg.devDependencies),
    ...objectValue(pkg.optionalDependencies),
  };
  return Object.entries(deps)
    .filter(([, version]) => typeof version === "string" && !String(version).startsWith("file:") && !String(version).startsWith("workspace:"))
    .map(([name, version]) => `${name}@${String(version).replace(/^[~^]/, "")}`);
}

function requireActiveIncidentAcceptance(advisory = readActiveAdvisory()) {
  if (!advisory.active) return;
  console.error(`scguard: ACTIVE SUPPLY-CHAIN ADVISORY: ${advisory.message}`);
  console.error("scguard: type exactly 'I accept the active supply-chain risk' to continue.");
  const answer = prompt("> ");
  if (answer !== "I accept the active supply-chain risk") {
    throw new Error("Package operation cancelled because active incident risk was not accepted.");
  }
}

function classifyPackageCommand(command: string, args: string[]) {
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

function extractSpecs(base: string, args: string[]) {
  const actionIndex = args.findIndex((arg) => !arg.startsWith("-"));
  const rest = actionIndex === -1 ? [] : args.slice(actionIndex + 1);
  if (base === "npm" && (args[actionIndex] === "ci" || rest.length === 0)) return [];
  return rest.filter((arg) => !arg.startsWith("-") && !arg.includes("="));
}

function readActiveAdvisory(): ActiveAdvisory {
  const message = Bun.env.SCGUARD_ACTIVE_INCIDENT;
  const until = Bun.env.SCGUARD_ACTIVE_INCIDENT_UNTIL;
  if (!message) {
    return { active: false, source: "env", message: "No active supply-chain advisory configured." };
  }
  if (until && Date.parse(until) < Date.now()) {
    return { active: false, source: "env", message: `Configured advisory expired at ${until}.`, until };
  }
  return { active: true, source: "env", message, until };
}

function shellHook() {
  const entry = CLI_ENTRY;
  return `[ -f "${CONFIG_ENV_PATH}" ] && source "${CONFIG_ENV_PATH}"
scguard() { command bun run ${entry} "$@"; }
bun() { command bun run ${entry} guard bun "$@"; }
npm() { command bun run ${entry} guard npm "$@"; }
pnpm() { command bun run ${entry} guard pnpm "$@"; }
yarn() { command bun run ${entry} guard yarn "$@"; }
code() { command bun run ${entry} guard code "$@"; }
`;
}

function parsePackageSpec(spec: string): { name: string; version?: string } {
  if (spec.startsWith("@")) {
    const secondAt = spec.indexOf("@", 1);
    if (secondAt === -1) return { name: spec };
    return { name: spec.slice(0, secondAt), version: spec.slice(secondAt + 1) };
  }
  const at = spec.lastIndexOf("@");
  if (at <= 0) return { name: spec };
  return { name: spec.slice(0, at), version: spec.slice(at + 1) };
}

async function download(url: string, path: string) {
  const res = await fetch(url);
  if (!res.ok || !res.body) throw new Error(`Download failed: ${url}`);
  await Bun.write(path, await res.arrayBuffer());
}

async function extractTarball(path: string) {
  const dir = await mkdtemp(join(WORK_DIR, "npm-"));
  await run("tar", ["-xzf", path, "-C", dir]);
  return dir;
}

async function downloadNpmStage(stageId: string) {
  const dir = await mkdtemp(join(WORK_DIR, "stage-download-"));
  const before = new Set(await readdir(dir));
  await run("npm", ["stage", "download", stageId], { cwd: dir });
  const after = await readdir(dir);
  const created = after.filter((name) => !before.has(name) && name.endsWith(".tgz"));
  if (created.length !== 1) {
    throw new Error(`Expected npm stage download to create one .tgz file, found ${created.length}`);
  }
  const source = join(dir, created[0]);
  const dest = join(CACHE_DIR, `npm-stage-${stageId.replace(/[^a-z0-9_.-]+/gi, "_")}.tgz`);
  await Bun.write(dest, await Bun.file(source).arrayBuffer());
  return dest;
}

async function findPackageRoot(dir: string) {
  const candidates = [join(dir, "package"), ...(await readdir(dir)).map((name) => join(dir, name))];
  for (const candidate of candidates) {
    try {
      const s = await stat(join(candidate, "package.json"));
      if (s.isFile()) return candidate;
    } catch {
      // try next candidate
    }
  }
  throw new Error(`No package.json found in extracted artifact ${dir}`);
}

async function emitReport(report: Report, json: boolean) {
  const base = report.target.replace(/[^a-z0-9_.@-]+/gi, "_");
  const jsonPath = join(REPORT_DIR, `${base}-${Date.now()}.json`);
  await Bun.write(jsonPath, JSON.stringify(report, null, 2));
  await Bun.write(jsonPath.replace(/\.json$/, ".md"), renderMarkdown(report, jsonPath));
  await writeAgentPrompt(report, "codex", jsonPath);
  await writeAgentPrompt(report, "pi", jsonPath);
  if (json) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log(`${report.target}: ${report.summary.risk} risk, ${report.summary.findingCount} findings`);
    console.log(jsonPath);
  }
  return jsonPath;
}

async function runAgentReviews(report: Report, reportPath: string, agents: AgentName[]): Promise<AgentReview[]> {
  const reviews: AgentReview[] = [];
  for (const agent of agents) {
    reviews.push(await runAgentReview(report, reportPath, agent));
  }
  return reviews;
}

async function runAgentReview(report: Report, reportPath: string, agent: AgentName): Promise<AgentReview> {
  if (!await commandExists(agent)) {
    const outputPath = await writeAgentOutput(report, agent, `${agent} command is not installed or not on PATH.`);
    return { agent, status: "error", outputPath, exitCode: 127, summary: `${agent} not found` };
  }
  const prompt = agentReviewPrompt(report, reportPath, agent);
  const outputPath = join(REPORT_DIR, `${report.target.replace(/[^a-z0-9_.@-]+/gi, "_")}-${agent}-review.txt`);
  const cmd = agent === "codex"
    ? ["codex", "exec", "--cd", ROOT, "--sandbox", "read-only", "--skip-git-repo-check", "--ignore-rules", "-"]
    : ["pi", "-p", "--no-tools", "--no-context-files", prompt];
  const proc = agent === "codex"
    ? Bun.spawn(cmd, { stdin: "pipe", stdout: "pipe", stderr: "pipe" })
    : Bun.spawn(cmd, { stdout: "pipe", stderr: "pipe" });
  if (agent === "codex") {
    proc.stdin?.write(prompt);
    proc.stdin?.end();
  }
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ]);
  const output = [stdout, stderr && `\n--- stderr ---\n${stderr}`].filter(Boolean).join("");
  await Bun.write(outputPath, output);
  const status = exitCode === 0 ? parseAgentDecision(output) : "error";
  return {
    agent,
    status,
    outputPath,
    exitCode,
    summary: firstLine(output),
  };
}

function agentReviewPrompt(report: Report, reportPath: string, agent: AgentName) {
  return [
    `You are ${agent === "pi" ? "PI" : "Codex"} acting as a mandatory supply-chain security reviewer before installation.`,
    "",
    "Return a clear final decision on its own line using exactly one of:",
    "SCGUARD_DECISION: approve",
    "SCGUARD_DECISION: reject",
    "SCGUARD_DECISION: manual-review",
    "",
    "Approve only if the package/update appears safe to install based on the report.",
    "Reject if the package appears malicious or unjustifiably dangerous.",
    "Use manual-review if the report is insufficient, ambiguous, or requires human source inspection.",
    "",
    `Repository root: ${ROOT}`,
    `Report path: ${relative(ROOT, reportPath)}`,
    `Target: ${report.target}`,
    `Kind: ${report.kind}`,
    `Risk: ${report.summary.risk}`,
    "",
    "Analyze the JSON report below. Cite the concrete findings and intelligence that drove your decision.",
    "",
    "```json",
    JSON.stringify(report, null, 2),
    "```",
  ].join("\n");
}

function parseAgentDecision(output: string): AgentReview["status"] {
  const match = output.match(/SCGUARD_DECISION:\s*(approve|reject|manual-review)/i);
  if (!match) return "manual-review";
  if (match[1].toLowerCase() === "approve") return "approved";
  if (match[1].toLowerCase() === "reject") return "rejected";
  return "manual-review";
}

function parseAgentMode(args: string[]): AgentName[] {
  const value = readOption(args, "--agent");
  if (!value || value === "none") return [];
  if (value === "codex") return ["codex"];
  if (value === "pi") return ["pi"];
  if (value === "both") return ["codex", "pi"];
  throw new Error("--agent must be one of: none, codex, pi, both");
}

async function resolveAgentMode(args: string[]): Promise<AgentName[]> {
  const explicit = readOption(args, "--agent");
  if (explicit) return parseAgentMode(args);
  return agentsFromMode((await readConfig()).agentReview);
}

function agentsFromMode(mode: AgentMode): AgentName[] {
  if (mode === "codex") return ["codex"];
  if (mode === "pi") return ["pi"];
  if (mode === "both") return ["codex", "pi"];
  return [];
}

async function maybeRunConfiguredAgentReview(report: Report, reportPath: string, args: string[], json: boolean) {
  const agents = await resolveAgentMode(args);
  if (agents.length === 0) return;
  const reviews = await runAgentReviews(report, reportPath, agents);
  report.agentReviews = reviews;
  await emitReport(report, json);
  blockOnFailedReview(report.target, reviews);
}

function blockOnFailedReview(target: string, reviews: AgentReview[]) {
  const failed = reviews.find((review) => review.status !== "approved");
  if (failed) {
    throw new Error(`Blocked ${target}: ${failed.agent} returned ${failed.status}. See ${failed.outputPath}`);
  }
}

async function configCommand(args: string[]) {
  if (args.includes("--show")) {
    console.log(JSON.stringify(await readConfig(), null, 2));
    return;
  }
  const explicit = readOption(args, "--agent");
  if (explicit) {
    const config = await readConfig();
    config.agentReview = normalizeAgentMode(explicit);
    await writeConfig(config);
    console.log(`Saved default agent review: ${config.agentReview}`);
    return;
  }
  const config = await readConfig();
  config.agentReview = await agentConfigTui(config.agentReview);
  await writeConfig(config);
  console.log(`Saved default agent review: ${config.agentReview}`);
}

async function readConfig(): Promise<Config> {
  try {
    const parsed = await readJson<Partial<Config>>(CONFIG_PATH);
    return {
      ...DEFAULT_CONFIG,
      agentReview: normalizeAgentMode(parsed.agentReview ?? DEFAULT_CONFIG.agentReview),
    };
  } catch {
    return DEFAULT_CONFIG;
  }
}

async function writeConfig(config: Config) {
  await mkdir(CONFIG_DIR, { recursive: true });
  await Bun.write(CONFIG_PATH, `${JSON.stringify(config, null, 2)}\n`);
}

function normalizeAgentMode(value: string): AgentMode {
  if (value === "none" || value === "codex" || value === "pi" || value === "both") return value;
  throw new Error("agentReview must be one of: none, codex, pi, both");
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
  process.stdout.write("Supply Chain Guard Config\n\n");
  process.stdout.write("Choose default agent review for scans and install gates.\n");
  process.stdout.write(`Current: ${current}\n\n`);
  options.forEach((option, optionIndex) => {
    const pointer = option.value === current ? "*" : " ";
    process.stdout.write(`${pointer} ${optionIndex + 1}. ${option.label}\n`);
    process.stdout.write(`   ${option.detail}\n`);
  });
  process.stdout.write("\n");
}

function stripGuardOptions(args: string[]) {
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

async function commandExists(command: string) {
  const proc = Bun.spawn(["/bin/sh", "-lc", `command -v ${command}`], { stdout: "ignore", stderr: "ignore" });
  return await proc.exited === 0;
}

async function writeAgentOutput(report: Report, agent: AgentName, output: string) {
  const outputPath = join(REPORT_DIR, `${report.target.replace(/[^a-z0-9_.@-]+/gi, "_")}-${agent}-review.txt`);
  await Bun.write(outputPath, output);
  return outputPath;
}

function firstLine(output: string) {
  return output.split(/\r?\n/).find((line) => line.trim().length > 0)?.slice(0, 240) ?? "";
}

function renderMarkdown(report: Report, reportPath: string) {
  const lines = [
    `# Supply Chain Report: ${report.target}`,
    "",
    `- Kind: ${report.kind}`,
    `- Risk: ${report.summary.risk}`,
    `- Install allowed: ${report.summary.installAllowed}`,
    `- Artifact: ${report.artifact.source}`,
    `- SHA-256: ${report.artifact.sha256}`,
    `- Socket: ${report.intelligence.socket?.status ?? "not-applicable"}`,
    `- Active advisory: ${report.intelligence.activeAdvisory?.active ?? false}`,
    `- JSON: ${reportPath}`,
    "",
    "## Findings",
    "",
  ];
  if (report.findings.length === 0) lines.push("No findings.");
  for (const finding of report.findings) {
    lines.push(`### ${finding.severity.toUpperCase()}: ${finding.title}`);
    lines.push("");
    lines.push(`- ID: ${finding.id}`);
    lines.push(`- Evidence: \`${finding.evidence.replaceAll("`", "'")}\``);
    lines.push(`- Recommendation: ${finding.recommendation}`);
    lines.push("");
  }
  return `${lines.join("\n")}\n`;
}

async function writeAgentPrompt(report: Report, agent: string, reportPath?: string) {
  const base = report.target.replace(/[^a-z0-9_.@-]+/gi, "_");
  const path = join(REPORT_DIR, `${base}-${agent}-prompt.md`);
  const prompt = [
    `You are ${agent === "pi" ? "PI" : "Codex"} reviewing a local supply-chain analysis report before installation.`,
    "",
    `Target: ${report.target}`,
    `Kind: ${report.kind}`,
    `Risk: ${report.summary.risk}`,
    `Report JSON: ${reportPath ?? "(attached or pasted below)"}`,
    "",
    "Tasks:",
    "1. Verify whether each finding is a true risk or expected behavior.",
    "2. Inspect package scripts, executable entry points, extension activation, and network/credential access.",
    "3. Recommend one of: approve, reject, or manual-review.",
    "4. Cite exact files, scripts, or manifest fields that support your recommendation.",
    "5. End with exactly one line: SCGUARD_DECISION: approve, SCGUARD_DECISION: reject, or SCGUARD_DECISION: manual-review.",
    "",
    "Report:",
    "```json",
    JSON.stringify(report, null, 2),
    "```",
    "",
  ].join("\n");
  await Bun.write(path, prompt);
  return path;
}

async function artifactInfo(path: string, source: string) {
  const bytes = Buffer.from(await Bun.file(path).arrayBuffer());
  return {
    source,
    sha256: createHash("sha256").update(bytes).digest("hex"),
    bytes: bytes.byteLength,
  };
}

async function walk(dir: string): Promise<string[]> {
  const out: string[] = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...await walk(path));
    if (entry.isFile()) out.push(path);
  }
  return out;
}

async function ensureDirs() {
  await mkdir(CACHE_DIR, { recursive: true });
  await mkdir(WORK_DIR, { recursive: true });
  await mkdir(REPORT_DIR, { recursive: true });
}

async function run(cmd: string, args: string[], options: { cwd?: string } = {}) {
  const proc = Bun.spawn([cmd, ...args], { cwd: options.cwd, stdout: "inherit", stderr: "inherit" });
  const code = await proc.exited;
  if (code !== 0) throw new Error(`${cmd} ${args.join(" ")} failed with exit code ${code}`);
}

function objectValue(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function summarizeRisk(findings: Finding[]): Risk {
  if (findings.some((finding) => finding.severity === "high")) return "high";
  if (findings.some((finding) => finding.severity === "medium")) return "medium";
  return "low";
}

function snippet(text: string, index: number) {
  return text.slice(Math.max(0, index - 80), index + 160).replace(/\s+/g, " ").trim();
}

function stripComments(text: string) {
  return text
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/^\s*\/\/.*$/gm, "");
}

function requireArg(value: string | undefined, message: string) {
  if (!value) throw new Error(message);
  return value;
}

function readOption(args: string[], name: string) {
  const index = args.indexOf(name);
  return index === -1 ? undefined : args[index + 1];
}

function help() {
  console.log(`Supply Chain Guard

Usage:
  bun run scguard add <package[@version]> [--dev] [--approve]
  bun run scguard scan-npm <package[@version]> [--json]
  bun run scguard scan-stage <stage-id> [--json]
  bun run scguard scan-vsix <extension.vsix> [--json]
  bun run scguard add <package[@version]> --agent codex|pi|both --approve
  bun run scguard agent-review <report.json> --agent codex|pi|both
  bun run scguard config
  bun run scguard config --show
  bun run scguard guard bun|npm|pnpm|yarn|code <args...>
  bun run scguard shell-hook
  bun run scguard agent-prompt <report.json> --agent codex|pi
  bun run scguard self-test
`);
}

function debug(message: string) {
  if (Bun.env.SCGUARD_DEBUG) console.error(`scguard debug: ${message}`);
}

async function readJson<T>(path: string): Promise<T> {
  return await Bun.file(path).json() as T;
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
