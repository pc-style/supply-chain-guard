import { mkdtemp, readdir, stat } from "node:fs/promises";
import { createHash } from "node:crypto";
import { basename, join } from "node:path";
import {
  CACHE_DIR,
  WORK_DIR,
  commandExists,
  debug,
  objectValue,
  readConfig,
  readActiveAdvisory,
  readJson,
  run,
  walk,
} from "./core";
import type {
  Finding,
  PolicyPreset,
  Report,
  ReportPolicy,
  PackageAgeResult,
  Risk,
  SafeResolverMode,
  SafeResolverSuggestion,
  ScanReason,
} from "./core";
import {
  checkOsv,
  checkPackageAge,
  checkSocket,
  checkTyposquat,
  verifyNpmSignatures,
} from "./integrations";

const INSTALL_SCRIPTS = new Set(["preinstall", "install", "postinstall", "prepare"]);

// Patterns checked in ALL contexts (scripts + files).
const PATTERNS_ALL: Array<[RegExp, string, Risk, string]> = [
  [/curl\s+[^|]+\|\s*(sh|bash)/i, "pipe-to-shell", "high", "Downloads and executes remote shell code."],
  [/wget\s+[^|]+\|\s*(sh|bash)/i, "pipe-to-shell", "high", "Downloads and executes remote shell code."],
  [/(npmrc|\.ssh\/|id_rsa|AWS_SECRET|GITHUB_TOKEN|NPM_TOKEN)/i, "credential-access", "high", "References credentials or sensitive key paths."],
  [/(base64\s+-d|Buffer\.from\([^)]*base64)/i, "encoded-payload", "medium", "Decodes base64 payloads."],
  [/\bdns\.(?:resolve|resolve4|resolve6|lookup|setServers)\s*\(/i, "dns-exfiltration", "high", "Uses DNS resolution APIs that are commonly abused for data exfiltration."],
  [/fs\.(?:readFile|readFileSync)\s*\([\s\S]{0,240}?(fetch|axios|https?\.(?:request|get)|XMLHttpRequest)/i, "read-then-send", "high", "Reads local files then sends data over the network."],
  [/(os\.homedir\(\)|~\/\.npmrc|\.npmrc|\.ssh\/id_rsa)/i, "sensitive-path-access", "high", "References sensitive local credential paths."],
  [/process\.env\s*(?:\[[^\]]+\]|\.[A-Z0-9_]+)/i, "env-secret-access", "medium", "Accesses environment variables that may contain credentials."],
];

// Patterns only checked when the scope is a lifecycle script (not generic source files).
const PATTERNS_SCRIPTS_ONLY: Array<[RegExp, string, Risk, string]> = [
  [/(require\(["']child_process["']\)|from ["']node:child_process["']|execSync\(|spawnSync\(|eval\(|new Function\()/, "dynamic-execution", "medium", "Uses dynamic process or code execution."],
  [/(https?:\/\/|fetch\(|XMLHttpRequest)/i, "network-access", "medium", "Performs network access in a lifecycle script."],
  [/process\.env/i, "env-access", "medium", "Reads process environment variables in a lifecycle script."],
];

export async function scanNpm(spec: string, options: { offline?: boolean; packageAge?: PackageAgeResult } = {}): Promise<Report> {
  const parsedSpec = parsePackageSpec(spec);
  const requestedName = parsedSpec.name;
  const requestedVersion = parsedSpec.version;
  debug(`resolving ${spec}`);
  const meta = await resolveNpm(spec);
  const tarball = String(meta.dist.tarball);
  const resolvedName = String(meta.name);
  const version = String(meta.version);
  const safeName = resolvedName.replaceAll("/", "_").replaceAll("@", "");
  const artifactPath = join(CACHE_DIR, `${safeName}-${version}.tgz`);
  const offlineOpt = { offline: options.offline };
  // Fan out intelligence lookups in parallel with the (cached or fresh) tarball download.
  const packageAgePromise = options.packageAge
    ? Promise.resolve(options.packageAge)
    : checkPackageAge(resolvedName, version, offlineOpt);
  const intelPromise = Promise.all([
    checkSocket(resolvedName, version, offlineOpt),
    checkOsv(resolvedName, version, offlineOpt),
    packageAgePromise,
    verifyNpmSignatures(resolvedName, version, meta.dist ?? {}, offlineOpt),
  ]);
  if (await Bun.file(artifactPath).exists()) {
    debug(`cache hit ${artifactPath}`);
  } else {
    debug(`downloading ${tarball}`);
    await download(tarball, artifactPath);
  }
  debug(`extracting ${artifactPath}`);
  const extracted = await extractTarball(artifactPath);
  const packageDir = await findPackageRoot(extracted);
  debug(`analyzing ${packageDir}`);
  const [socket, osv, packageAge, npmSignature] = await intelPromise;
  const config = await readConfig();
  const reportPolicy = await buildReportPolicy({
    preset: config.preset,
    safeResolver: config.safeResolver,
    scanReason: "direct-review",
  }, {
    requestedVersion,
    resolvedVersion: version,
    packageAge,
    name: requestedName,
    offline: options.offline,
  });
  const typosquat = checkTyposquat(resolvedName);
  const report = await analyzeDirectory(`${resolvedName}@${version}`, "npm", packageDir, tarball, artifactPath, {
    socket,
    osv,
    packageAge,
    npmSignature,
    typosquat,
  }, reportPolicy);
  const expectedIntegrity = meta.dist?.integrity ? String(meta.dist.integrity) : undefined;
  if (expectedIntegrity) {
    const ok = await verifyIntegrity(artifactPath, expectedIntegrity);
    if (!ok) {
      report.findings.unshift({
        id: "artifact.integrity-mismatch",
        title: "Tarball integrity mismatch",
        severity: "high",
        evidence: `Registry integrity: ${expectedIntegrity}; downloaded file does not match`,
        recommendation: "Do not install. The downloaded tarball differs from the registry manifest — possible tampering or CDN corruption.",
      });
      report.summary.risk = "high";
      report.summary.installAllowed = false;
      report.summary.findingCount = report.findings.length;
    }
  }
  return report;
}

export async function scanVsix(file: string): Promise<Report> {
  const extracted = await mkdtemp(join(WORK_DIR, "vsix-"));
  await run("unzip", ["-q", file, "-d", extracted]);
  const extensionDir = join(extracted, "extension");
  const config = await readConfig();
  return analyzeDirectory(basename(file), "vsix", extensionDir, file, file, {}, {
    preset: config.preset,
    safeResolver: config.safeResolver,
    scanReason: "policy",
  });
}

export async function scanNpmStage(stageId: string, options: { offline?: boolean } = {}): Promise<Report> {
  const artifactPath = await downloadNpmStage(stageId);
  const extracted = await extractTarball(artifactPath);
  const packageDir = await findPackageRoot(extracted);
  const pkg = await readJson<Record<string, unknown>>(join(packageDir, "package.json"));
  const name = String(pkg.name ?? "unknown");
  const version = String(pkg.version ?? "unknown");
  const known = name !== "unknown" && version !== "unknown";
  const offlineOpt = { offline: options.offline };
  const [socket, osv, packageAge] = known
    ? await Promise.all([
        checkSocket(name, version, offlineOpt),
        checkOsv(name, version, offlineOpt),
        checkPackageAge(name, version, offlineOpt),
      ])
    : [undefined, undefined, undefined];
  const typosquat = known ? checkTyposquat(name) : undefined;
  const config = await readConfig();
  return analyzeDirectory(`npm-stage:${stageId}:${name}@${version}`, "npm-stage", packageDir, `npm stage download ${stageId}`, artifactPath, {
    socket,
    osv,
    packageAge,
    typosquat,
  }, {
    preset: config.preset,
    safeResolver: config.safeResolver,
    scanReason: "policy",
  });
}

export async function analyzeDirectory(
  target: string,
  kind: "npm" | "npm-stage" | "vsix",
  dir: string,
  source: string,
  artifactPath?: string,
  intelligence: Partial<Report["intelligence"]> = {},
  policyOverride?: Partial<ReportPolicy>,
): Promise<Report> {
  const pkgPath = join(dir, "package.json");
  const pkg = await readJson<Record<string, unknown>>(pkgPath);
  const findings: Finding[] = [];
  inspectPackageJson(pkg, kind, findings);
  inspectIntelligence(intelligence, findings);
  await inspectFiles(dir, findings);
  const artifact = artifactPath ? await artifactInfo(artifactPath, source) : { source, sha256: "not-applicable", bytes: 0 };
  const risk = summarizeRisk(findings);
  const config = await readConfig();
  const policy: ReportPolicy = policyOverride
    ? {
        preset: policyOverride.preset ?? config.preset,
        safeResolver: policyOverride.safeResolver ?? config.safeResolver,
        scanReason: policyOverride.scanReason ?? "direct-review",
        ...(policyOverride.safeResolverSuggestion ? { safeResolverSuggestion: policyOverride.safeResolverSuggestion } : {}),
      }
    : {
        preset: config.preset,
        safeResolver: config.safeResolver,
        scanReason: "direct-review",
      };
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
    policy,
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

  // OSV / GHSA known-vulnerability findings
  if (intelligence.osv?.status === "checked" && intelligence.osv.vulnerabilities?.length) {
    for (const v of intelligence.osv.vulnerabilities) {
      const aliases = v.aliases?.length ? ` (aliases: ${v.aliases.join(", ")})` : "";
      findings.push({
        id: `osv.${v.id}`,
        title: `Known advisory: ${v.id}`,
        severity: v.severity,
        evidence: (v.summary ? `${v.summary}${aliases}` : `${v.id}${aliases}`).slice(0, 400),
        recommendation: `Review the advisory at osv.dev/${v.id} and upgrade to a patched version before installing.`,
      });
    }
  }

  // npm registry signature verification
  if (intelligence.npmSignature) {
    const sig = intelligence.npmSignature;
    if (sig.status === "no-signature") {
      findings.push({
        id: "npm.signature.missing",
        title: "No npm registry signature on this version",
        severity: "low",
        evidence: sig.message ?? "dist.signatures was empty in the registry manifest.",
        recommendation: "Older packages may lack signatures; a missing signature on a recent publish is unusual and worth a closer look.",
      });
    } else if (sig.status === "unverified") {
      findings.push({
        id: "npm.signature.invalid",
        title: "npm registry signature failed verification",
        severity: "high",
        evidence: sig.message ?? "Signature did not validate against the npm public keys.",
        recommendation: "Do not install. The tarball or manifest may have been tampered with on the CDN path.",
      });
    } else if (sig.status === "error") {
      findings.push({
        id: "npm.signature.error",
        title: "Could not verify npm registry signature",
        severity: "low",
        evidence: sig.message ?? "Signature verification raised an error.",
        recommendation: "Re-run with network access; if the failure persists, treat the package as unverified.",
      });
    }
  }

  // Typosquat / name-similarity
  if (intelligence.typosquat?.suspiciousMatches?.length) {
    const sample = intelligence.typosquat.suspiciousMatches
      .map((m) => `${m.name} (distance=${m.distance})`)
      .join(", ");
    findings.push({
      id: "name.typosquat",
      title: "Package name closely resembles a popular package",
      severity: "high",
      evidence: `Close matches: ${sample}`,
      recommendation: "Confirm you intended to install this exact name. Confused-deputy typosquats commonly imitate popular packages.",
    });
  }

  // Package + version age signals
  if (intelligence.packageAge?.status === "checked") {
    const { packageAgeDays, versionAgeHours } = intelligence.packageAge;
    if (typeof packageAgeDays === "number" && packageAgeDays >= 0 && packageAgeDays < 22) {
      findings.push({
        id: "package.new",
        title: "Package was first published very recently",
        severity: "medium",
        evidence: `Package first published ${packageAgeDays} day(s) ago.`,
        recommendation: "New packages carry elevated risk; verify the publisher, source repo, and intended use before installing.",
      });
    }
    if (typeof versionAgeHours === "number" && versionAgeHours >= 0 && versionAgeHours < 24) {
      findings.push({
        id: "version.new",
        title: "Version was published in the last 24 hours",
        severity: "medium",
        evidence: `Version published ${versionAgeHours} hour(s) ago.`,
        recommendation: "Brand-new versions are a common vector for compromised maintainer accounts. Pause and verify the publish.",
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
    inspectText(`script.${name}`, script, findings, true);
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
    const stripped = stripComments(text).slice(0, 300_000);
    const minified = isMinified(stripped);
    if (minified) {
      findings.push({
        id: `file.${rel}.minified`,
        title: "Minified or bundled file",
        severity: "medium",
        evidence: `${rel} appears minified (average line length > 250 chars); pattern scanning may have reduced precision`,
        recommendation: "Review the unminified source if available before installing and treat matched patterns as higher risk.",
      });
    }
    inspectText(`file.${rel}`, stripped, findings, false, minified);
  }
}

function isMinified(text: string): boolean {
  const lines = text.split("\n").filter((l) => l.trim().length > 0).slice(0, 20);
  if (lines.length === 0) return false;
  const avg = lines.reduce((sum, l) => sum + l.length, 0) / lines.length;
  return avg > 250;
}

function inspectText(scope: string, text: string, findings: Finding[], isScript: boolean, inMinifiedFile = false) {
  const patterns = isScript ? [...PATTERNS_ALL, ...PATTERNS_SCRIPTS_ONLY] : PATTERNS_ALL;
  for (const [pattern, id, severity, title] of patterns) {
    const match = text.match(pattern);
    if (!match) continue;
    findings.push({
      id: `${scope}.${id}`,
      title: inMinifiedFile ? `${title} (detected in minified file)` : title,
      severity,
      evidence: snippet(text, match.index ?? 0),
      recommendation: inMinifiedFile
        ? "Pattern was found in minified code. Review the original source or deobfuscate before installing."
        : "Review the exact code path and require a trusted explanation before installing.",
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

async function verifyIntegrity(path: string, expected: string): Promise<boolean> {
  if (!expected.startsWith("sha512-")) return true;
  const expectedB64 = expected.slice("sha512-".length);
  const bytes = Buffer.from(await Bun.file(path).arrayBuffer());
  const actual = createHash("sha512").update(bytes).digest("base64");
  return actual === expectedB64;
}

export async function resolveNpm(spec: string): Promise<Record<string, any>> {
  // Try npm view first — it handles workspace:, git deps, dist-tags, and all semver ranges.
  if (await commandExists("npm")) {
    try {
      const proc = Bun.spawn(["npm", "view", spec, "--json"], { stdout: "pipe", stderr: "ignore" });
      const text = await new Response(proc.stdout).text();
      const code = await proc.exited;
      if (code === 0 && text.trim()) {
        const data = JSON.parse(text) as Record<string, any>;
        if (data.name && data.version && data.dist?.tarball) return data;
      }
    } catch {
      // fall through to direct registry lookup
    }
  }
  // Direct registry HTTP fallback (no npm required).
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
  const matches = versions
    .filter((v) => Bun.semver.satisfies(v, requested))
    .sort((a, b) => Bun.semver.order(a, b));
  if (matches.length > 0) return matches[matches.length - 1];
  return undefined;
}

function versionMatchesRequested(version: string, requested: string, versions: string[], distTags: Record<string, string>): boolean {
  if (versions.includes(requested)) return version === requested;
  if (distTags[requested]) return version === distTags[requested];
  return Bun.semver.satisfies(version, requested);
}

type SemVer = { major: number; minor: number; patch: number; prerelease?: string };

function parseSemver(version: string): SemVer | null {
  const match = version.match(/^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/);
  if (!match) return null;
  return { major: Number(match[1]), minor: Number(match[2]), patch: Number(match[3]), prerelease: match[4] };
}

function compareSemver(a: SemVer, b: SemVer): number {
  if (a.major !== b.major) return a.major - b.major;
  if (a.minor !== b.minor) return a.minor - b.minor;
  return a.patch - b.patch;
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

function buildReportPolicy(
  base: Partial<ReportPolicy>,
  context: {
    name?: string;
    requestedVersion?: string;
    resolvedVersion?: string;
    packageAge?: Report["intelligence"]["packageAge"];
    offline?: boolean;
  },
): Promise<ReportPolicy> {
  const preset = base.preset ?? "default";
  const safeResolver = base.safeResolver ?? "suggest";
  const scanReason = base.scanReason ?? "direct-review";
  const freshnessWindowHours = freshnessWindowHoursForPreset(preset);
  const versionAgeHours = context.packageAge?.status === "checked" ? context.packageAge.versionAgeHours : undefined;
  const suggestionPromise = safeResolver === "suggest" && context.name && context.resolvedVersion && typeof versionAgeHours === "number" && versionAgeHours >= 0 && versionAgeHours < freshnessWindowHours
    ? buildSafeResolverSuggestion({
        name: context.name,
        requestedVersion: context.requestedVersion,
        resolvedVersion: context.resolvedVersion,
        freshnessWindowHours,
        offline: context.offline,
      })
    : Promise.resolve(undefined);
  return suggestionPromise.then((safeResolverSuggestion) => ({
    preset,
    safeResolver,
    scanReason,
    ...(safeResolverSuggestion ? { safeResolverSuggestion } : {}),
  }));
}

export function freshnessWindowHoursForPreset(preset: PolicyPreset): number {
  if (preset === "quiet") return 24;
  if (preset === "strict-ci") return 30 * 24;
  if (preset === "enterprise") return 30 * 24;
  return 7 * 24;
}

export async function buildSafeResolverSuggestion(options: {
  name: string;
  requestedVersion?: string;
  resolvedVersion: string;
  freshnessWindowHours: number;
  offline?: boolean;
}): Promise<SafeResolverSuggestion> {
  if (options.offline) {
    return {
      status: "unavailable",
      message: "Offline mode: safe resolver suggestion skipped.",
      resolved: options.resolvedVersion,
      requested: options.requestedVersion,
      freshnessWindowHours: options.freshnessWindowHours,
    };
  }
  const requested = options.requestedVersion;
  if (!requested) {
    return {
      status: "none",
      message: `No older version satisfies the implicit latest-tag request for ${options.name}.`,
      resolved: options.resolvedVersion,
      freshnessWindowHours: options.freshnessWindowHours,
    };
  }
  try {
    const res = await fetch(`https://registry.npmjs.org/${encodeURIComponent(options.name).replace("%40", "@")}`, {
      headers: { Accept: "application/json" },
    });
    if (!res.ok) {
      return {
        status: "unavailable",
        message: `Registry returned HTTP ${res.status}; safe resolver suggestion unavailable.`,
        requested,
        resolved: options.resolvedVersion,
        freshnessWindowHours: options.freshnessWindowHours,
      };
    }
    const data = await res.json() as { versions?: Record<string, Record<string, unknown>>; time?: Record<string, string>; "dist-tags"?: Record<string, string> };
    return pickSafeResolverSuggestion({
      name: options.name,
      requestedVersion: requested,
      resolvedVersion: options.resolvedVersion,
      freshnessWindowHours: options.freshnessWindowHours,
      versions: Object.keys(data.versions ?? {}),
      publishTimes: data.time ?? {},
      distTags: data["dist-tags"] ?? {},
    });
  } catch (error) {
    return {
      status: "unavailable",
      message: error instanceof Error ? error.message : String(error),
      requested,
      resolved: options.resolvedVersion,
      freshnessWindowHours: options.freshnessWindowHours,
    };
  }
}

export function pickSafeResolverSuggestion(options: {
  name: string;
  requestedVersion?: string;
  resolvedVersion: string;
  freshnessWindowHours: number;
  versions: string[];
  publishTimes: Record<string, string>;
  distTags?: Record<string, string>;
}): SafeResolverSuggestion {
  const requested = options.requestedVersion;
  if (!requested) {
    return {
      status: "none",
      message: `No older version satisfies the implicit latest-tag request for ${options.name}.`,
      resolved: options.resolvedVersion,
      freshnessWindowHours: options.freshnessWindowHours,
    };
  }
  const versions = options.versions;
  const distTags = options.distTags ?? {};
  const allowPrerelease = requested.includes("-");
  const candidates = versions
    .filter((version) => version !== options.resolvedVersion)
    .filter((version) => versionMatchesRequested(version, requested, versions, distTags))
    .filter((version) => {
      const parsed = parseSemver(version);
      if (!parsed) return false;
      if (parsed.prerelease && !allowPrerelease) return false;
      const published = options.publishTimes[version];
      if (!published) return false;
      const ageHours = Math.floor((Date.now() - Date.parse(published)) / 3_600_000);
      return Number.isFinite(ageHours) && ageHours >= options.freshnessWindowHours;
    })
    .map((version) => ({
      version,
      parsed: parseSemver(version),
    }))
    .filter((entry): entry is { version: string; parsed: SemVer } => !!entry.parsed)
    .sort((a, b) => compareSemver(a.parsed, b.parsed));
  const suggested = candidates[candidates.length - 1]?.version;
  if (!suggested) {
    return {
      status: "none",
      message: `No older non-prerelease version satisfies ${options.name}@${requested}.`,
      requested,
      resolved: options.resolvedVersion,
      freshnessWindowHours: options.freshnessWindowHours,
    };
  }
  return {
    status: "suggested",
    message: `Safe Resolver suggests ${options.name}@${suggested} instead of the freshly published ${options.resolvedVersion}.`,
    requested,
    resolved: options.resolvedVersion,
    suggested,
    freshnessWindowHours: options.freshnessWindowHours,
  };
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
