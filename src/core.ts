import { mkdir, readdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { homedir } from "node:os";

export type Risk = "low" | "medium" | "high";

export type PolicyPreset = "quiet" | "default" | "strict-ci" | "enterprise" | "advisory";
export type SafeResolverMode = "off" | "suggest";
export type ScanReason = "fresh-version" | "changed-lockfile-entry" | "direct-review" | "policy";

export type VersionedPackage = {
  name: string;
  version: string;
};

export type Finding = {
  id: string;
  title: string;
  severity: Risk;
  evidence: string;
  recommendation: string;
};

export type Report = {
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
    osv?: OsvResult;
    npmSignature?: NpmSignatureResult;
    typosquat?: TyposquatResult;
    packageAge?: PackageAgeResult;
  };
  packageJson?: Record<string, unknown>;
  summary: {
    risk: Risk;
    findingCount: number;
    installAllowed: boolean;
  };
  findings: Finding[];
  agentReviews?: AgentReview[];
  policy?: ReportPolicy;
};

export type ReportPolicy = {
  preset: PolicyPreset;
  safeResolver: SafeResolverMode;
  scanReason: ScanReason;
  safeResolverSuggestion?: SafeResolverSuggestion;
};

export type SafeResolverSuggestion = {
  status: "suggested" | "none" | "unavailable";
  message: string;
  requested?: string;
  resolved: string;
  suggested?: string;
  freshnessWindowHours?: number;
};

export type AgentName = "codex" | "pi";
export type AgentMode = "none" | AgentName | "both";

export type Config = {
  agentReview: AgentMode;
  preset: PolicyPreset;
  safeResolver: SafeResolverMode;
};

export type AgentReview = {
  agent: AgentName;
  status: "approved" | "rejected" | "manual-review" | "error";
  outputPath: string;
  exitCode: number;
  summary: string;
};

export type SocketResult = {
  status: "checked" | "skipped" | "error";
  package?: string;
  version?: string;
  url?: string;
  supplyChainRisk?: number;
  rawScore?: unknown;
  message?: string;
};

export type ActiveAdvisory = {
  active: boolean;
  source: "env";
  message: string;
  until?: string;
};

export type OsvVulnerability = {
  id: string;
  summary?: string;
  severity: Risk;
  references: string[];
  aliases?: string[];
};

export type OsvResult = {
  status: "checked" | "skipped" | "error";
  vulnerabilities?: OsvVulnerability[];
  message?: string;
  url?: string;
};

export type NpmSignatureResult = {
  status: "verified" | "no-signature" | "unverified" | "error" | "skipped";
  keyid?: string;
  message?: string;
};

export type TyposquatMatch = { name: string; distance: number };

export type TyposquatResult = {
  status: "checked" | "skipped";
  exactMatch?: boolean;
  suspiciousMatches?: TyposquatMatch[];
};

export type PackageAgeResult = {
  status: "checked" | "skipped" | "error";
  packageCreatedAt?: string;
  versionPublishedAt?: string;
  packageAgeDays?: number;
  versionAgeHours?: number;
  message?: string;
};

export type LockfileBaseline = {
  schemaVersion: 1;
  generatedAt: string;
  kind?: string;
  entries: VersionedPackage[];
};

export function findProjectRoot(start: string): string {
  let dir = start;
  while (true) {
    if (existsSync(join(dir, "package.json")) || existsSync(join(dir, ".git"))) return dir;
    const parent = dirname(dir);
    if (parent === dir) return start;
    dir = parent;
  }
}

export const ROOT = findProjectRoot(process.cwd());
export const CLI_ENTRY = join(import.meta.dirname, "cli.ts");
export const GUARD_DIR = join(ROOT, ".scguard");
export const CACHE_DIR = join(GUARD_DIR, "cache");
export const WORK_DIR = join(GUARD_DIR, "work");
export const REPORT_DIR = join(GUARD_DIR, "reports");
export const LOCKFILE_BASELINE_PATH = join(GUARD_DIR, "lockfile-baseline.json");
export const CONFIG_ENV_PATH = join(homedir(), ".config", "supply-chain-guard", "env");
export const CONFIG_DIR = join(homedir(), ".config", "supply-chain-guard");
export const CONFIG_PATH = join(CONFIG_DIR, "config.json");
export const DEFAULT_CONFIG: Config = { agentReview: "none", preset: "default", safeResolver: "suggest" };

export async function ensureDirs() {
  await mkdir(CACHE_DIR, { recursive: true });
  await mkdir(WORK_DIR, { recursive: true });
  await mkdir(REPORT_DIR, { recursive: true });
}

export async function run(cmd: string, args: string[], options: { cwd?: string } = {}) {
  const proc = Bun.spawn([cmd, ...args], { cwd: options.cwd, stdout: "inherit", stderr: "inherit" });
  const code = await proc.exited;
  if (code !== 0) throw new Error(`${cmd} ${args.join(" ")} failed with exit code ${code}`);
}

export async function commandExists(command: string) {
  const proc = Bun.spawn(["/bin/sh", "-lc", `command -v ${command}`], { stdout: "ignore", stderr: "ignore" });
  return await proc.exited === 0;
}

export async function readJson<T>(path: string): Promise<T> {
  return await Bun.file(path).json() as T;
}

export function requireArg(value: string | undefined, message: string) {
  if (!value) throw new Error(message);
  return value;
}

export function readOption(args: string[], name: string) {
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === name) return args[i + 1];
    if (arg.startsWith(`${name}=`)) return arg.slice(name.length + 1);
  }
  return undefined;
}

export function debug(message: string) {
  if (Bun.env.SCGUARD_DEBUG) console.error(`scguard: ${message}`);
}

export function objectValue(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

export async function walk(dir: string): Promise<string[]> {
  const out: string[] = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...await walk(path));
    if (entry.isFile()) out.push(path);
  }
  return out;
}

export function normalizeAgentMode(value: string): AgentMode {
  if (value === "none" || value === "codex" || value === "pi" || value === "both") return value;
  throw new Error("agentReview must be one of: none, codex, pi, both");
}

export function normalizePolicyPreset(value: string): PolicyPreset {
  if (value === "quiet" || value === "default" || value === "strict-ci" || value === "enterprise" || value === "advisory") {
    return value;
  }
  throw new Error("preset must be one of: quiet, default, strict-ci, enterprise, advisory");
}

export function normalizeSafeResolverMode(value: string): SafeResolverMode {
  if (value === "off" || value === "suggest") return value;
  throw new Error("safeResolver must be one of: off, suggest");
}

export function normalizeConfig(raw: Partial<Config> | undefined): Config {
  const config = raw && typeof raw === "object" ? raw : {};
  return {
    agentReview: normalizeAgentMode(typeof config.agentReview === "string" ? config.agentReview : DEFAULT_CONFIG.agentReview),
    preset: normalizePolicyPreset(typeof config.preset === "string" ? config.preset : DEFAULT_CONFIG.preset),
    safeResolver: normalizeSafeResolverMode(typeof config.safeResolver === "string" ? config.safeResolver : DEFAULT_CONFIG.safeResolver),
  };
}

export function applyConfigEnv(config: Config, presetOverride = Bun.env.SCGUARD_PRESET): Config {
  if (!presetOverride) return config;
  return { ...config, preset: normalizePolicyPreset(presetOverride) };
}

export async function readConfigFile(): Promise<Config> {
  try {
    const parsed = await readJson<Partial<Config>>(CONFIG_PATH);
    return normalizeConfig(parsed);
  } catch {
    return DEFAULT_CONFIG;
  }
}

export async function readConfig(): Promise<Config> {
  return applyConfigEnv(await readConfigFile());
}

export async function writeConfig(config: Config) {
  await mkdir(CONFIG_DIR, { recursive: true });
  await Bun.write(CONFIG_PATH, `${JSON.stringify(config, null, 2)}\n`);
}

export async function readLockfileBaseline(path = LOCKFILE_BASELINE_PATH): Promise<LockfileBaseline | null> {
  try {
    return await readJson<LockfileBaseline>(path);
  } catch {
    return null;
  }
}

export async function writeLockfileBaseline(baseline: LockfileBaseline, path = LOCKFILE_BASELINE_PATH) {
  await mkdir(dirname(path), { recursive: true });
  await Bun.write(path, `${JSON.stringify(baseline, null, 2)}\n`);
}

export function versionedPackageKey(entry: VersionedPackage) {
  return `${entry.name}@${entry.version}`;
}

export function versionedPackageMap(entries: VersionedPackage[]) {
  return new Map(entries.map((entry) => [entry.name, entry.version]));
}

export function versionedPackageSet(entries: VersionedPackage[]) {
  return new Set(entries.map(versionedPackageKey));
}

export function readActiveAdvisory(): ActiveAdvisory {
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

export function requireActiveIncidentAcceptance(advisory = readActiveAdvisory()) {
  if (!advisory.active) return;
  console.error(`scguard: ACTIVE SUPPLY-CHAIN ADVISORY: ${advisory.message}`);
  console.error("scguard: type exactly 'I accept the active supply-chain risk' to continue.");
  const answer = prompt("> ");
  if (answer !== "I accept the active supply-chain risk") {
    throw new Error("Package operation cancelled because active incident risk was not accepted.");
  }
}
