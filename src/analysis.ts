import { mkdtemp, readdir, stat } from "node:fs/promises";
import { createHash } from "node:crypto";
import { basename, join } from "node:path";
import {
  CACHE_DIR,
  WORK_DIR,
  debug,
  objectValue,
  readActiveAdvisory,
  readJson,
  run,
  walk,
} from "./core";
import type { Finding, Report, Risk } from "./core";
import { checkSocket } from "./integrations";

const INSTALL_SCRIPTS = new Set(["preinstall", "install", "postinstall", "prepare"]);
const SUSPICIOUS_PATTERNS: Array<[RegExp, string, Risk, string]> = [
  [/curl\s+[^|]+\|\s*(sh|bash)/i, "pipe-to-shell", "high", "Downloads and executes remote shell code."],
  [/wget\s+[^|]+\|\s*(sh|bash)/i, "pipe-to-shell", "high", "Downloads and executes remote shell code."],
  [/(require\(["']child_process["']\)|from ["']node:child_process["']|execSync\(|spawnSync\(|eval\(|new Function\()/, "dynamic-execution", "medium", "Uses dynamic process or code execution."],
  [/(base64\s+-d|Buffer\.from\([^)]*base64)/i, "encoded-payload", "medium", "Decodes base64 payloads."],
  [/(npmrc|\.ssh|id_rsa|AWS_SECRET|GITHUB_TOKEN|NPM_TOKEN|process\.env)/i, "credential-access", "high", "References credentials, tokens, or sensitive local paths."],
  [/(https?:\/\/|fetch\(|XMLHttpRequest)/i, "network-access", "medium", "Performs network access during package code or scripts."],
];

export async function scanNpm(spec: string): Promise<Report> {
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

export async function scanVsix(file: string): Promise<Report> {
  const extracted = await mkdtemp(join(WORK_DIR, "vsix-"));
  await run("unzip", ["-q", file, "-d", extracted]);
  const extensionDir = join(extracted, "extension");
  return analyzeDirectory(basename(file), "vsix", extensionDir, file, file);
}

export async function scanNpmStage(stageId: string): Promise<Report> {
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

export async function analyzeDirectory(
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
    const score = intelligence.socket.supplyChainRisk;
    if (typeof score === "number" && score <= 0.3) {
      findings.push({
        id: "socket.supply-chain-risk",
        title: "Socket reports a low supply-chain score",
        severity: score <= 0.1 ? "high" : "medium",
        evidence: `supplyChainRiskScore=${score}`,
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

async function artifactInfo(path: string, source: string) {
  const bytes = Buffer.from(await Bun.file(path).arrayBuffer());
  return {
    source,
    sha256: createHash("sha256").update(bytes).digest("hex"),
    bytes: bytes.byteLength,
  };
}

export async function resolveNpm(spec: string): Promise<Record<string, any>> {
  const { name, version } = parsePackageSpec(spec);
  const res = await fetch(`https://registry.npmjs.org/${encodeURIComponent(name).replace("%40", "@")}`);
  if (!res.ok) throw new Error(`Registry lookup failed for ${name}: ${res.status}`);
  const data = await res.json() as Record<string, any>;
  const versions = Object.keys(data.versions ?? {});
  const resolvedVersion = resolveNpmVersion(versions, data["dist-tags"] ?? {}, version);
  const meta = resolvedVersion ? data.versions?.[resolvedVersion] : undefined;
  if (!meta) {
    throw new Error(`Version not found for ${spec}. Available dist-tags: ${Object.keys(data["dist-tags"] ?? {}).join(", ") || "(none)"}`);
  }
  return meta;
}

export function resolveNpmVersion(versions: string[], distTags: Record<string, string>, requested: string | undefined): string | undefined {
  if (!requested) return distTags.latest;
  if (versions.includes(requested)) return requested;
  if (distTags[requested]) return distTags[requested];
  const range = parseSemverRange(requested);
  if (range) {
    const matches = versions
      .map(parseSemver)
      .filter((v): v is SemVer => v !== null && satisfiesRange(v, range) && !v.prerelease)
      .sort(compareSemver);
    if (matches.length > 0) return formatSemver(matches[matches.length - 1]);
  }
  return undefined;
}

type SemVer = { major: number; minor: number; patch: number; prerelease?: string };

function parseSemver(version: string): SemVer | null {
  const match = version.match(/^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/);
  if (!match) return null;
  return { major: Number(match[1]), minor: Number(match[2]), patch: Number(match[3]), prerelease: match[4] };
}

function formatSemver(v: SemVer): string {
  const base = `${v.major}.${v.minor}.${v.patch}`;
  return v.prerelease ? `${base}-${v.prerelease}` : base;
}

function compareSemver(a: SemVer, b: SemVer): number {
  if (a.major !== b.major) return a.major - b.major;
  if (a.minor !== b.minor) return a.minor - b.minor;
  return a.patch - b.patch;
}

type SemverRange = { op: "^" | "~" | "=" | ">=" | ">"; base: SemVer; matchMajorOnly?: boolean; matchMinorOnly?: boolean };

function parseSemverRange(spec: string): SemverRange | null {
  const trimmed = spec.trim().replace(/^v/i, "");
  const opMatch = trimmed.match(/^(\^|~|>=|>|=)?\s*(.+)$/);
  if (!opMatch) return null;
  const op = (opMatch[1] || "=") as SemverRange["op"];
  const rest = opMatch[2];
  const parts = rest.split(".");
  if (parts.length === 0 || !parts[0] || !/^\d+$/.test(parts[0])) return null;
  const major = Number(parts[0]);
  const minor = parts[1] && /^\d+$/.test(parts[1]) ? Number(parts[1]) : 0;
  const patch = parts[2] && /^\d+$/.test(parts[2].split("-")[0]) ? Number(parts[2].split("-")[0]) : 0;
  return {
    op,
    base: { major, minor, patch },
    matchMajorOnly: parts.length === 1,
    matchMinorOnly: parts.length === 2,
  };
}

function satisfiesRange(v: SemVer, range: SemverRange): boolean {
  const cmp = compareSemver(v, range.base);
  if (range.op === "=") {
    // Partial specs behave like X-ranges: `18` matches any 18.x.x,
    // `1.2` matches any 1.2.x. Only fully-qualified specs require an exact match.
    if (range.matchMajorOnly) return v.major === range.base.major;
    if (range.matchMinorOnly) return v.major === range.base.major && v.minor === range.base.minor;
    return cmp === 0;
  }
  if (range.op === ">") return cmp > 0;
  if (range.op === ">=") return cmp >= 0;
  if (range.op === "^") {
    // npm caret semantics:
    //   ^1.2.3 -> >=1.2.3 <2.0.0
    //   ^0.2.3 -> >=0.2.3 <0.3.0
    //   ^0.0.3 -> >=0.0.3 <0.0.4
    if (cmp < 0) return false;
    if (range.base.major > 0) return v.major === range.base.major;
    if (range.base.minor > 0) return v.major === 0 && v.minor === range.base.minor;
    return v.major === 0 && v.minor === 0 && v.patch === range.base.patch;
  }
  if (range.op === "~") {
    if (range.matchMajorOnly) return v.major === range.base.major && cmp >= 0;
    return v.major === range.base.major && v.minor === range.base.minor && cmp >= 0;
  }
  return false;
}

export function parsePackageSpec(spec: string): { name: string; version?: string } {
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
