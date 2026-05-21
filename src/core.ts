import { mkdir, readdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { homedir } from "node:os";

export type Risk = "low" | "medium" | "high";

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
};

export type AgentName = "codex" | "pi";
export type AgentMode = "none" | AgentName | "both";

export type Config = {
  agentReview: AgentMode;
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
export const CONFIG_ENV_PATH = join(homedir(), ".config", "supply-chain-guard", "env");
export const CONFIG_DIR = join(homedir(), ".config", "supply-chain-guard");
export const CONFIG_PATH = join(CONFIG_DIR, "config.json");
export const DEFAULT_CONFIG: Config = { agentReview: "none" };

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
  const index = args.indexOf(name);
  return index === -1 ? undefined : args[index + 1];
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

export async function readConfig(): Promise<Config> {
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

export async function writeConfig(config: Config) {
  await mkdir(CONFIG_DIR, { recursive: true });
  await Bun.write(CONFIG_PATH, `${JSON.stringify(config, null, 2)}\n`);
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
