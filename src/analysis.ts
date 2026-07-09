import { createHash } from "node:crypto";
import { mkdtemp, readdir, stat } from "node:fs/promises";
import { basename, join } from "node:path";
import type {
  Finding,
  PackageAgeResult,
  PolicyPreset,
  Report,
  ReportPolicy,
  Risk,
  SafeResolverSuggestion,
  ScanReason,
} from "./core";
import {
  CACHE_DIR,
  commandExists,
  debug,
  objectValue,
  readConfig,
  readJson,
  run,
  WORK_DIR,
  walk,
} from "./core";
import {
  checkOsv,
  checkPackageAge,
  checkSocket,
  checkTyposquat,
  verifyNpmSignatures,
} from "./integrations";

const INSTALL_SCRIPTS = new Set([
  "preinstall",
  "install",
  "postinstall",
  "prepare",
]);

// Patterns checked in ALL contexts (scripts + files).
const PATTERNS_ALL: Array<[RegExp, string, Risk, string]> = [
  [
    /curl\s+[^|]+\|\s*(sh|bash)/i,
    "pipe-to-shell",
    "high",
    "Downloads and executes remote shell code.",
  ],
  [
    /wget\s+[^|]+\|\s*(sh|bash)/i,
    "pipe-to-shell",
    "high",
    "Downloads and executes remote shell code.",
  ],
  [
    /(npmrc|\.ssh\/|id_rsa|AWS_SECRET|GITHUB_TOKEN|NPM_TOKEN)/i,
    "credential-access",
    "low",
    "References credentials or sensitive key paths.",
  ],
  [
    /(base64\s+-d|Buffer\.from\([^)]*base64)/i,
    "encoded-payload",
    "low",
    "Decodes base64 payloads.",
  ],
  [
    /\bdns\.(?:resolve|resolve4|resolve6|lookup|setServers)\s*\(/i,
    "dns-exfiltration",
    "low",
    "Uses DNS resolution APIs that are commonly abused for data exfiltration.",
  ],
  [
    /fs\.(?:readFile|readFileSync)\s*\([\s\S]{0,240}?(fetch|axios|https?\.(?:request|get)|XMLHttpRequest)/i,
    "read-then-send",
    "high",
    "Reads local files then sends data over the network.",
  ],
  [
    /(os\.homedir\(\)|~\/\.npmrc|\.npmrc|\.ssh\/id_rsa)/i,
    "sensitive-path-access",
    "low",
    "References sensitive local credential paths.",
  ],
  [
    /process\.env\s*(?:\[[^\]]+\]|\.[A-Z0-9_]+)/i,
    "env-secret-access",
    "low",
    "Accesses environment variables that may contain credentials.",
  ],
];

// Patterns only checked when the scope is a lifecycle script (not generic source files).
const PATTERNS_SCRIPTS_ONLY: Array<[RegExp, string, Risk, string]> = [
  [
    /(npmrc|\.ssh\/|id_rsa|AWS_SECRET|GITHUB_TOKEN|NPM_TOKEN|os\.homedir\(\)|~\/\.npmrc|\.npmrc|\.ssh\/id_rsa|process\.env\s*(?:\[[^\]]+\]|\.[A-Z0-9_]+))/i,
    "credential-access",
    "high",
    "References credentials, sensitive key paths, or environment secrets in a lifecycle script.",
  ],
  [
    /(require\(["']child_process["']\)|from ["']node:child_process["']|execSync\(|spawnSync\(|eval\(|new Function\()/,
    "dynamic-execution",
    "medium",
    "Uses dynamic process or code execution.",
  ],
  [
    /(https?:\/\/|fetch\(|XMLHttpRequest)/i,
    "network-access",
    "medium",
    "Performs network access in a lifecycle script.",
  ],
  [
    /process\.env/i,
    "env-access",
    "medium",
    "Reads process environment variables in a lifecycle script.",
  ],
];

export type ScanNpmOptions = {
  offline?: boolean;
  packageAge?: PackageAgeResult;
  /** Lockfile-pinned tarball URL — must be scanned instead of registry metadata resolution. */
  pinnedTarball?: string;
  /** Lockfile subresource integrity (sha512-...). */
  pinnedIntegrity?: string;
};

export async function scanNpm(
  spec: string,
  options: ScanNpmOptions = {},
): Promise<Report> {
  const parsedSpec = parsePackageSpec(spec);
  const requestedName = parsedSpec.name;
  const requestedVersion = parsedSpec.version;
  if (requestedVersion && !isRegistryVersionSpec(requestedVersion)) {
    throw new Error(
      `Cannot scan non-registry spec ${spec}. Use a registry version/range (e.g. name@1.2.3 or name@^1.0.0), not ${requestedVersion}.`,
    );
  }
  debug(`resolving ${spec}`);
  const meta = await resolveNpm(spec);
  const resolvedName = String(meta.name);
  const version = String(meta.version);
  const tarball = options.pinnedTarball ?? String(meta.dist.tarball);
  if (
    options.pinnedTarball &&
    !isAllowedPinnedTarballUrl(options.pinnedTarball)
  ) {
    throw new Error(
      `Refusing to download lockfile artifact from untrusted URL: ${options.pinnedTarball}`,
    );
  }
  return scanNpmArtifact({
    name: resolvedName,
    version,
    tarball,
    integrity:
      options.pinnedIntegrity ??
      (meta.dist?.integrity ? String(meta.dist.integrity) : undefined),
    dist: meta.dist ?? {},
    requestedName,
    requestedVersion,
    offline: options.offline,
    packageAge: options.packageAge,
    scanReason: "direct-review",
  });
}

export async function scanNpmLockfileEntry(
  entry: {
    name: string;
    version: string;
    resolved?: string;
    integrity?: string;
  },
  options: { offline?: boolean; packageAge?: PackageAgeResult } = {},
): Promise<Report> {
  const spec = `${entry.name}@${entry.version}`;
  if (entry.resolved) {
    return scanNpm(spec, {
      offline: options.offline,
      packageAge: options.packageAge,
      pinnedTarball: entry.resolved,
      pinnedIntegrity: entry.integrity,
    });
  }
  return scanNpm(spec, {
    offline: options.offline,
    packageAge: options.packageAge,
  });
}

async function scanNpmArtifact(context: {
  name: string;
  version: string;
  tarball: string;
  integrity?: string;
  dist: Record<string, unknown>;
  requestedName: string;
  requestedVersion?: string;
  offline?: boolean;
  packageAge?: PackageAgeResult;
  scanReason: ScanReason;
}): Promise<Report> {
  const {
    name,
    version,
    tarball,
    integrity,
    dist,
    requestedName,
    requestedVersion,
    offline,
    packageAge,
    scanReason,
  } = context;
  const safeName = name.replaceAll("/", "_").replaceAll("@", "");
  const artifactPath = join(CACHE_DIR, `${safeName}-${version}.tgz`);
  const offlineOpt = { offline };
  const packageAgePromise = packageAge
    ? Promise.resolve(packageAge)
    : checkPackageAge(name, version, offlineOpt);
  const intelPromise = Promise.all([
    checkSocket(name, version, offlineOpt),
    checkOsv(name, version, offlineOpt),
    packageAgePromise,
    verifyNpmSignatures(name, version, dist, offlineOpt),
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
  const [socket, osv, resolvedPackageAge, npmSignature] = await intelPromise;
  const config = await readConfig();
  const reportPolicy = await buildReportPolicy(
    {
      preset: config.preset,
      safeResolver: config.safeResolver,
      scanReason,
    },
    {
      requestedVersion,
      resolvedVersion: version,
      packageAge: resolvedPackageAge,
      name: requestedName,
      offline,
    },
  );
  const typosquat = checkTyposquat(name);
  const report = await analyzeDirectory(
    `${name}@${version}`,
    "npm",
    packageDir,
    tarball,
    artifactPath,
    {
      socket,
      osv,
      packageAge: resolvedPackageAge,
      npmSignature,
      typosquat,
    },
    reportPolicy,
  );
  if (integrity) {
    const ok = await verifyIntegrity(artifactPath, integrity);
    if (!ok) {
      report.findings.unshift({
        id: "artifact.integrity-mismatch",
        title: "Tarball integrity mismatch",
        severity: "high",
        evidence: `Expected integrity: ${integrity}; downloaded file does not match`,
        recommendation:
          "Do not install. The downloaded tarball differs from the lockfile/registry digest — possible tampering.",
      });
      report.summary.risk = "high";
      report.summary.installAllowed = false;
      report.summary.findingCount = report.findings.length;
    }
  }
  return report;
}

export function isAllowedPinnedTarballUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:") return false;
    const host = parsed.hostname.toLowerCase();
    return (
      host === "registry.npmjs.org" ||
      host.endsWith(".npmjs.org") ||
      host.endsWith(".npmmirror.com")
    );
  } catch {
    return false;
  }
}

export async function scanVsix(file: string): Promise<Report> {
  const extracted = await mkdtemp(join(WORK_DIR, "vsix-"));
  await run("unzip", ["-q", file, "-d", extracted]);
  const extensionDir = join(extracted, "extension");
  const config = await readConfig();
  return analyzeDirectory(
    basename(file),
    "vsix",
    extensionDir,
    file,
    file,
    {},
    {
      preset: config.preset,
      safeResolver: config.safeResolver,
      scanReason: "policy",
    },
  );
}

export async function analyzeDirectory(
  target: string,
  kind: "npm" | "vsix",
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
  const artifact = artifactPath
    ? await artifactInfo(artifactPath, source)
    : { source, sha256: "not-applicable", bytes: 0 };
  const risk = summarizeRisk(findings);
  const installAllowed = !hasBlockingFinding(findings);
  const config = await readConfig();
  const policy: ReportPolicy = policyOverride
    ? {
        preset: policyOverride.preset ?? config.preset,
        safeResolver: policyOverride.safeResolver ?? config.safeResolver,
        scanReason: policyOverride.scanReason ?? "direct-review",
        ...(policyOverride.safeResolverSuggestion
          ? { safeResolverSuggestion: policyOverride.safeResolverSuggestion }
          : {}),
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
    },
    packageJson: pkg,
    summary: {
      risk,
      findingCount: findings.length,
      installAllowed,
    },
    findings,
    policy,
  };
}

function inspectIntelligence(
  intelligence: Partial<Report["intelligence"]>,
  findings: Finding[],
) {
  if (intelligence.socket?.status === "checked") {
    const score = intelligence.socket.supplyChainRisk;
    if (typeof score === "number" && score < 0.5) {
      findings.push({
        id: "socket.supply-chain-risk",
        title: "Socket reports low supply-chain safety score",
        severity: score < 0.3 ? "high" : "medium",
        evidence: `supplyChainRiskScore=${score} (0=highest risk, 1=lowest risk / safest)`,
        recommendation:
          "Require agent review and inspect Socket package details before installing.",
      });
    }
  }

  // OSV / GHSA known-vulnerability findings
  if (
    intelligence.osv?.status === "checked" &&
    intelligence.osv.vulnerabilities?.length
  ) {
    for (const v of intelligence.osv.vulnerabilities) {
      const aliases = v.aliases?.length
        ? ` (aliases: ${v.aliases.join(", ")})`
        : "";
      findings.push({
        id: `osv.${v.id}`,
        title: `Known advisory: ${v.id}`,
        severity: v.severity,
        evidence: (v.summary
          ? `${v.summary}${aliases}`
          : `${v.id}${aliases}`
        ).slice(0, 400),
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
        evidence:
          sig.message ?? "dist.signatures was empty in the registry manifest.",
        recommendation:
          "Older packages may lack signatures; a missing signature on a recent publish is unusual and worth a closer look.",
      });
    } else if (sig.status === "unverified") {
      findings.push({
        id: "npm.signature.invalid",
        title: "npm registry signature failed verification",
        severity: "high",
        evidence:
          sig.message ??
          "Signature did not validate against the npm public keys.",
        recommendation:
          "Do not install. The tarball or manifest may have been tampered with on the CDN path.",
      });
    } else if (sig.status === "error") {
      findings.push({
        id: "npm.signature.error",
        title: "Could not verify npm registry signature",
        severity: "low",
        evidence: sig.message ?? "Signature verification raised an error.",
        recommendation:
          "Re-run with network access; if the failure persists, treat the package as unverified.",
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
      recommendation:
        "Confirm you intended to install this exact name. Confused-deputy typosquats commonly imitate popular packages.",
    });
  }

  // Package + version age signals
  if (intelligence.packageAge?.status === "checked") {
    const { packageAgeDays, versionAgeHours } = intelligence.packageAge;
    if (
      typeof packageAgeDays === "number" &&
      packageAgeDays >= 0 &&
      packageAgeDays < 22
    ) {
      findings.push({
        id: "package.new",
        title: "Package was first published very recently",
        severity: "medium",
        evidence: `Package first published ${packageAgeDays} day(s) ago.`,
        recommendation:
          "New packages carry elevated risk; verify the publisher, source repo, and intended use before installing.",
      });
    }
    if (
      typeof versionAgeHours === "number" &&
      versionAgeHours >= 0 &&
      versionAgeHours < 24
    ) {
      findings.push({
        id: "version.new",
        title: "Version was published in the last 24 hours",
        severity: "medium",
        evidence: `Version published ${versionAgeHours} hour(s) ago.`,
        recommendation:
          "Brand-new versions are a common vector for compromised maintainer accounts. Pause and verify the publish.",
      });
    }
  }
}

function inspectPackageJson(
  pkg: Record<string, unknown>,
  kind: "npm" | "vsix",
  findings: Finding[],
) {
  const scripts = objectValue(pkg.scripts);
  for (const [name, raw] of Object.entries(scripts)) {
    const script = String(raw);
    if (INSTALL_SCRIPTS.has(name)) {
      findings.push({
        id: `script.${name}`,
        title: `Lifecycle script: ${name}`,
        severity:
          name === "install" || name === "postinstall" ? "high" : "medium",
        evidence: script,
        recommendation:
          "Manually inspect the script and require agent review before installing.",
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
      recommendation:
        "Review executable entry points before adding to PATH or running commands.",
    });
  }

  if (kind === "vsix") {
    const activationEvents = Array.isArray(pkg.activationEvents)
      ? pkg.activationEvents
      : [];
    if (activationEvents.includes("*")) {
      findings.push({
        id: "vscode.activation.all",
        title: "Extension activates on startup",
        severity: "high",
        evidence: JSON.stringify(activationEvents),
        recommendation:
          "Avoid broad activation unless the publisher and source are trusted.",
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
      recommendation:
        "Use an agent or manual review to inspect newly introduced transitive risk.",
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
        recommendation:
          "Confirm this file is expected in the published artifact.",
      });
    }
    if (rel === "package.json") continue;
    if (!/\.(js|cjs|mjs|ts|sh|ps1|cmd|node)$/i.test(file) || s.size > 300_000)
      continue;
    const text = await Bun.file(file)
      .text()
      .catch(() => "");
    const stripped = stripComments(text).slice(0, 300_000);
    const minified = isMinified(stripped);
    if (minified) {
      findings.push({
        id: `file.${rel}.minified`,
        title: "Minified or bundled file",
        severity: "medium",
        evidence: `${rel} appears minified (average line length > 250 chars); pattern scanning may have reduced precision`,
        recommendation:
          "Review the unminified source if available before installing and treat matched patterns as higher risk.",
      });
    }
    inspectText(`file.${rel}`, stripped, findings, false, minified);
  }
}

function isMinified(text: string): boolean {
  const lines = text
    .split("\n")
    .filter((l) => l.trim().length > 0)
    .slice(0, 20);
  if (lines.length === 0) return false;
  const avg = lines.reduce((sum, l) => sum + l.length, 0) / lines.length;
  return avg > 250;
}

function inspectText(
  scope: string,
  text: string,
  findings: Finding[],
  isScript: boolean,
  inMinifiedFile = false,
) {
  const patterns = isScript
    ? [...PATTERNS_ALL, ...PATTERNS_SCRIPTS_ONLY]
    : PATTERNS_ALL;
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
  if (findings.some((finding) => finding.severity === "medium"))
    return "medium";
  return "low";
}

function hasBlockingFinding(findings: Finding[]): boolean {
  return findings.some((finding) => {
    if (finding.id === "artifact.integrity-mismatch") return true;
    if (finding.id === "name.typosquat") return true;
    if (finding.id === "npm.signature.invalid") return true;
    if (finding.id.startsWith("osv.") && finding.severity === "high") {
      return true;
    }
    if (
      finding.id.startsWith("script.") &&
      (finding.id.endsWith(".pipe-to-shell") ||
        finding.id.endsWith(".credential-access"))
    ) {
      return true;
    }
    return false;
  });
}

function snippet(text: string, index: number) {
  return text
    .slice(Math.max(0, index - 80), index + 160)
    .replace(/\s+/g, " ")
    .trim();
}

function stripComments(text: string) {
  return text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
}

async function artifactInfo(path: string, source: string) {
  const bytes = Buffer.from(await Bun.file(path).arrayBuffer());
  return {
    source,
    sha256: createHash("sha256").update(bytes).digest("hex"),
    bytes: bytes.byteLength,
  };
}

async function verifyIntegrity(
  path: string,
  expected: string,
): Promise<boolean> {
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
      const proc = Bun.spawn(["npm", "view", spec, "--json"], {
        stdout: "pipe",
        stderr: "ignore",
      });
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
  if (version && !isRegistryVersionSpec(version)) {
    throw new Error(`Cannot resolve non-registry version spec: ${version}`);
  }
  const res = await fetch(
    `https://registry.npmjs.org/${encodeURIComponent(name).replace("%40", "@")}`,
  );
  if (!res.ok)
    throw new Error(`Registry lookup failed for ${name}: ${res.status}`);
  const data = (await res.json()) as Record<string, any>;
  const versions = Object.keys(data.versions ?? {});
  const resolvedVersion = resolveNpmVersion(
    versions,
    data["dist-tags"] ?? {},
    version,
  );
  const meta = resolvedVersion ? data.versions?.[resolvedVersion] : undefined;
  if (!meta) {
    throw new Error(
      `Version not found for ${spec}. Available dist-tags: ${Object.keys(data["dist-tags"] ?? {}).join(", ") || "(none)"}`,
    );
  }
  return meta;
}

export function isRegistryVersionSpec(version: string): boolean {
  if (!version || version.includes("://")) return false;
  if (
    /^(workspace|file|link|git|github|patch|portal|catalog|npm):/i.test(version)
  )
    return false;
  if (/^git\+/i.test(version)) return false;
  if (version.startsWith(".") || version.startsWith("/")) return false;
  if (/^\d+\.\d+\.\d+/.test(version)) return true;
  if (
    /^[~^>=<]/.test(version) ||
    version.includes("||") ||
    version.includes(" - ") ||
    /\d+\.x/.test(version)
  ) {
    return true;
  }
  if (
    /^[a-zA-Z][a-zA-Z0-9._-]*$/.test(version) &&
    !version.includes("/") &&
    !version.includes(":")
  ) {
    return true;
  }
  return false;
}

export function resolveNpmVersion(
  versions: string[],
  distTags: Record<string, string>,
  requested: string | undefined,
): string | undefined {
  if (!requested) return distTags.latest;
  if (!isRegistryVersionSpec(requested)) return undefined;
  if (versions.includes(requested)) return requested;
  if (distTags[requested]) return distTags[requested];
  const matches = versions
    .filter((v) => Bun.semver.satisfies(v, requested))
    .sort((a, b) => Bun.semver.order(a, b));
  if (matches.length > 0) return matches[matches.length - 1];
  return undefined;
}

function versionMatchesRequested(
  version: string,
  requested: string,
  versions: string[],
  distTags: Record<string, string>,
): boolean {
  if (versions.includes(requested)) return version === requested;
  if (distTags[requested]) return version === distTags[requested];
  return Bun.semver.satisfies(version, requested);
}

type SemVer = {
  major: number;
  minor: number;
  patch: number;
  prerelease?: string;
};

function parseSemver(version: string): SemVer | null {
  const match = version.match(
    /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/,
  );
  if (!match) return null;
  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
    prerelease: match[4],
  };
}

function compareSemver(a: SemVer, b: SemVer): number {
  if (a.major !== b.major) return a.major - b.major;
  if (a.minor !== b.minor) return a.minor - b.minor;
  return a.patch - b.patch;
}

export function parsePackageSpec(spec: string): {
  name: string;
  version?: string;
} {
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
  _context: {
    name?: string;
    requestedVersion?: string;
    resolvedVersion?: string;
    packageAge?: Report["intelligence"]["packageAge"];
    offline?: boolean;
  },
): Promise<ReportPolicy> {
  const preset = base.preset ?? "default";
  const safeResolver = base.safeResolver ?? "off";
  const scanReason = base.scanReason ?? "direct-review";
  return Promise.resolve({
    preset,
    safeResolver,
    scanReason,
  });
}

export function freshnessWindowHoursForPreset(preset: PolicyPreset): number {
  if (preset === "strict") return 30 * 24;
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
    const res = await fetch(
      `https://registry.npmjs.org/${encodeURIComponent(options.name).replace("%40", "@")}`,
      {
        headers: { Accept: "application/json" },
      },
    );
    if (!res.ok) {
      return {
        status: "unavailable",
        message: `Registry returned HTTP ${res.status}; safe resolver suggestion unavailable.`,
        requested,
        resolved: options.resolvedVersion,
        freshnessWindowHours: options.freshnessWindowHours,
      };
    }
    const data = (await res.json()) as {
      versions?: Record<string, Record<string, unknown>>;
      time?: Record<string, string>;
      "dist-tags"?: Record<string, string>;
    };
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
    .filter((version) =>
      versionMatchesRequested(version, requested, versions, distTags),
    )
    .filter((version) => {
      const parsed = parseSemver(version);
      if (!parsed) return false;
      if (parsed.prerelease && !allowPrerelease) return false;
      const published = options.publishTimes[version];
      if (!published) return false;
      const ageHours = Math.floor(
        (Date.now() - Date.parse(published)) / 3_600_000,
      );
      return (
        Number.isFinite(ageHours) && ageHours >= options.freshnessWindowHours
      );
    })
    .map((version) => ({
      version,
      parsed: parseSemver(version),
    }))
    .filter(
      (entry): entry is { version: string; parsed: SemVer } => !!entry.parsed,
    )
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

async function findPackageRoot(dir: string) {
  const candidates = [
    join(dir, "package"),
    ...(await readdir(dir)).map((name) => join(dir, name)),
  ];
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
