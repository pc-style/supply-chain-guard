import { createPublicKey, createVerify } from "node:crypto";
import { join, relative } from "node:path";
import type {
  AgentMode,
  AgentName,
  AgentReview,
  NpmSignatureResult,
  OsvResult,
  OsvVulnerability,
  PackageAgeResult,
  Report,
  Risk,
  SocketResult,
  TyposquatResult,
} from "./core";
import {
  commandExists,
  REPORT_DIR,
  ROOT,
  readConfig,
  readOption,
} from "./core";
import topNpmPackages from "./data/top-npm-packages.json";

export async function checkSocket(
  name: string,
  version: string,
  options: { offline?: boolean } = {},
): Promise<SocketResult> {
  const token = Bun.env.SOCKET_API_KEY;
  const packagePath = `${encodeURIComponent(name).replace("%40", "@")}/${encodeURIComponent(version)}`;
  const url = `https://api.socket.dev/v0/npm/${packagePath}/score`;
  if (options.offline) {
    return {
      status: "skipped",
      package: name,
      version,
      url,
      message: "Offline mode enabled; Socket intelligence was not queried.",
    };
  }
  if (!token) {
    return {
      status: "skipped",
      package: name,
      version,
      url,
      message:
        "SOCKET_API_KEY is not set; Socket intelligence was not queried.",
    };
  }
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10_000);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: {
        Authorization: `Basic ${Buffer.from(`${token}:`).toString("base64")}`,
        Accept: "application/json",
      },
    });
    clearTimeout(timeout);
    if (!res.ok) {
      const message =
        res.status === 401 || res.status === 403
          ? `Socket API token is invalid or lacks permission (HTTP ${res.status})`
          : res.status === 429
            ? "Socket API rate limit reached (HTTP 429); score skipped"
            : res.status === 404
              ? `Package not found in Socket index (HTTP 404)`
              : `Socket returned HTTP ${res.status}`;
      return { status: "error", package: name, version, url, message };
    }
    const data = (await res.json()) as Record<string, any>;
    const score = data.score ?? data;
    const rawSupplyChainRisk = score?.supplyChainRisk;
    const supplyChainRisk =
      typeof rawSupplyChainRisk === "number"
        ? rawSupplyChainRisk
        : typeof rawSupplyChainRisk?.score === "number"
          ? rawSupplyChainRisk.score
          : undefined;
    return {
      status: "checked",
      package: name,
      version,
      url,
      supplyChainRisk,
      rawScore: score,
    };
  } catch (error) {
    clearTimeout(timeout);
    const message =
      error instanceof Error && error.name === "AbortError"
        ? "Socket API timed out after 10s"
        : error instanceof Error
          ? error.message
          : String(error);
    return { status: "error", package: name, version, url, message };
  }
}

export async function runAgentReviews(
  report: Report,
  reportPath: string,
  agents: AgentName[],
): Promise<AgentReview[]> {
  const reviews: AgentReview[] = [];
  for (const agent of agents) {
    reviews.push(await runAgentReview(report, reportPath, agent));
  }
  return reviews;
}

export async function runAgentReview(
  report: Report,
  reportPath: string,
  agent: AgentName,
): Promise<AgentReview> {
  if (!(await commandExists(agent))) {
    const outputPath = await writeAgentOutput(
      report,
      agent,
      `${agent} command is not installed or not on PATH.`,
    );
    return {
      agent,
      status: "error",
      outputPath,
      exitCode: 127,
      summary: `${agent} not found`,
    };
  }
  const prompt = agentReviewPrompt(report, reportPath, agent);
  const outputPath = join(
    REPORT_DIR,
    `${report.target.replace(/[^a-z0-9_.@-]+/gi, "_")}-${agent}-review.txt`,
  );
  const cmd =
    agent === "codex"
      ? [
          "codex",
          "exec",
          "--cd",
          ROOT,
          "--sandbox",
          "read-only",
          "--skip-git-repo-check",
          "--ignore-rules",
          "-",
        ]
      : ["pi", "-p", "--no-tools", "--no-context-files", prompt];
  const proc =
    agent === "codex"
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
  const cleanStderr = sanitizeAgentStderr(stderr);
  const output = [
    stdout,
    cleanStderr && `\n--- stderr (sanitized) ---\n${cleanStderr}`,
  ]
    .filter(Boolean)
    .join("");
  await Bun.write(outputPath, output);
  const status = exitCode === 0 ? parseAgentDecision(output) : "error";
  return {
    agent,
    status,
    outputPath,
    exitCode,
    summary: summarizeAgentOutput(output),
  };
}

export function agentReviewPrompt(
  report: Report,
  reportPath: string,
  agent: AgentName,
) {
  return [
    `You are ${agent === "pi" ? "PI" : "Codex"} acting as a mandatory supply-chain security reviewer before installation.`,
    "",
    "Analyze the compact normalized report summary below and cite the concrete findings and intelligence that drove your decision.",
    "Do not approve solely because a package is popular. If minified files or skipped checks create a blind spot, require source/package inspection or manual-review unless the residual risk is explicitly justified.",
    "",
    "At the very end of your response — after all analysis — write your decision on its own line using",
    "exactly one of these three forms (no surrounding text, no quotation marks, no trailing words):",
    "",
    "SCGUARD_DECISION: approve",
    "SCGUARD_DECISION: reject",
    "SCGUARD_DECISION: manual-review",
    "",
    "Do NOT quote or echo these tokens anywhere in your analysis prose.",
    "Write the SCGUARD_DECISION line exactly once, as the final line of your output.",
    "",
    "Decision criteria:",
    "- approve: package appears safe based on the report findings and intelligence.",
    "- reject: package appears malicious or poses unjustifiable risk.",
    "- manual-review: report is insufficient, ambiguous, or requires human inspection of source code.",
    "",
    `Repository root: ${ROOT}`,
    `Report path: ${relative(ROOT, reportPath)}`,
    `Target: ${report.target}`,
    `Kind: ${report.kind}`,
    `Risk: ${report.summary.risk}`,
    "",
    "```json",
    JSON.stringify(normalizedReviewSummary(report), null, 2),
    "```",
  ].join("\n");
}

function sanitizeAgentStderr(stderr: string) {
  return stderr
    .split("\n")
    .filter(
      (line) =>
        !line.includes("```json") &&
        !line.includes('"rawScore"') &&
        !line.includes('"packageJson"'),
    )
    .join("\n")
    .slice(0, 4000);
}

function normalizedReviewSummary(report: Report) {
  const high = report.findings.filter((f) => f.severity === "high");
  const medium = report.findings.filter((f) => f.severity === "medium");
  const minified = report.findings.filter((f) => f.id.endsWith(".minified"));
  return {
    target: report.target,
    kind: report.kind,
    generatedAt: report.generatedAt,
    decisionBasis: {
      verdict: report.summary.installAllowed
        ? report.summary.risk === "medium"
          ? "manual-risk-accepted"
          : "allow"
        : "block",
      installAllowed: report.summary.installAllowed,
      risk: report.summary.risk,
      findingCount: report.summary.findingCount,
      why: report.summary.installAllowed
        ? `No high-severity findings (${medium.length} medium, ${report.findings.filter((f) => f.severity === "low").length} low).`
        : `${high.length} high-severity finding(s) block install.`,
      skippedChecks: minified.map(
        (f) =>
          `Minified file skipped by static scanner: ${f.id.replace(/^file\./, "").replace(/\.minified$/, "")}`,
      ),
      nextAction: minified.length
        ? "Inspect original source/package contents for minified files."
        : "Use findings and intelligence to decide.",
    },
    artifact: report.artifact,
    intelligence: normalizedIntelligence(report),
    findings: report.findings.map((f) => ({
      id: f.id,
      severity: f.severity,
      title: f.title,
      evidence: f.evidence,
      recommendation: f.recommendation,
    })),
  };
}

function normalizedIntelligence(report: Report) {
  const socket = report.intelligence.socket;
  return {
    socket: socket && {
      status: socket.status,
      supplyChainRisk: socket.supplyChainRisk,
      scale:
        "0=lowest risk, 1=highest risk; do not treat as approval confidence",
      message: socket.message,
      components: socketRiskComponents(socket.rawScore).slice(0, 12),
    },
    osv: {
      status: report.intelligence.osv?.status ?? "missing",
      vulnerabilityCount: report.intelligence.osv?.vulnerabilities?.length ?? 0,
      vulnerabilities:
        report.intelligence.osv?.vulnerabilities?.slice(0, 10) ?? [],
      message: report.intelligence.osv?.message,
    },
    npmSignature: report.intelligence.npmSignature,
    typosquat: report.intelligence.typosquat,
    packageAge: report.intelligence.packageAge,
    activeAdvisory: report.intelligence.activeAdvisory,
  };
}

function socketRiskComponents(rawScore: unknown) {
  if (!rawScore || typeof rawScore !== "object") return [];
  return Object.entries(rawScore as Record<string, unknown>)
    .filter(
      ([, value]) =>
        typeof value === "number" ||
        typeof value === "boolean" ||
        typeof value === "string",
    )
    .map(([key, value]) => `${key}=${String(value)}`);
}

export function parseAgentDecision(output: string): AgentReview["status"] {
  // Only accept decisions that appear on their own line with the exact token,
  // optionally followed by surrounding whitespace. This prevents matches inside
  // prose like "I would approve" or "SCGUARD_DECISION: approve-ish".
  const decisionLine =
    /^\s*SCGUARD_DECISION:\s*(approve|reject|manual-review)\s*$/gim;
  const matches: string[] = [];
  for (const m of output.matchAll(decisionLine))
    matches.push(m[1].toLowerCase());
  if (matches.length === 0) return "manual-review";
  // If the agent emitted conflicting decisions, fail closed to manual-review.
  const unique = new Set(matches);
  if (unique.size > 1) return "manual-review";
  const decision = matches[matches.length - 1];
  if (decision === "approve") return "approved";
  if (decision === "reject") return "rejected";
  return "manual-review";
}

export function parseAgentMode(args: string[]): AgentName[] {
  const value = readOption(args, "--agent");
  if (!value || value === "none") return [];
  if (value === "codex") return ["codex"];
  if (value === "pi") return ["pi"];
  if (value === "both") return ["codex", "pi"];
  throw new Error("--agent must be one of: none, codex, pi, both");
}

export async function resolveAgentMode(args: string[]): Promise<AgentName[]> {
  const explicit = readOption(args, "--agent");
  if (explicit) return parseAgentMode(args);
  return agentsFromMode((await readConfig()).agentReview);
}

export function agentsFromMode(mode: AgentMode): AgentName[] {
  if (mode === "codex") return ["codex"];
  if (mode === "pi") return ["pi"];
  if (mode === "both") return ["codex", "pi"];
  return [];
}

export async function writeAgentOutput(
  report: Report,
  agent: AgentName,
  output: string,
) {
  const outputPath = join(
    REPORT_DIR,
    `${report.target.replace(/[^a-z0-9_.@-]+/gi, "_")}-${agent}-review.txt`,
  );
  await Bun.write(outputPath, output);
  return outputPath;
}

export function summarizeAgentOutput(output: string) {
  const lines = output
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  const errorLine = [...lines].reverse().find((line) => /^ERROR:/i.test(line));
  if (errorLine) return errorLine.slice(0, 240);
  return lines.find((line) => line !== "--- stderr ---")?.slice(0, 240) ?? "";
}

// ---------------------------------------------------------------------------
// OSV advisory lookup — https://api.osv.dev/v1/query
// ---------------------------------------------------------------------------

type OsvSeverityEntry = { type?: string; score?: string };
type OsvReference = { type?: string; url?: string };
type OsvRawVuln = {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  severity?: OsvSeverityEntry[];
  database_specific?: { severity?: string; cwe_ids?: string[] };
  references?: OsvReference[];
};

export async function checkOsv(
  name: string,
  version: string,
  options: { offline?: boolean } = {},
): Promise<OsvResult> {
  const url = "https://api.osv.dev/v1/query";
  if (options.offline) {
    return {
      status: "skipped",
      url,
      message: "Offline mode: OSV lookup skipped.",
    };
  }
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10_000);
  try {
    const res = await fetch(url, {
      method: "POST",
      signal: controller.signal,
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({ version, package: { name, ecosystem: "npm" } }),
    });
    clearTimeout(timeout);
    if (!res.ok) {
      return {
        status: "error",
        url,
        message: `OSV returned HTTP ${res.status}`,
      };
    }
    const data = (await res.json()) as { vulns?: OsvRawVuln[] };
    const vulnerabilities: OsvVulnerability[] = (data.vulns ?? []).map((v) => ({
      id: v.id,
      summary: v.summary ?? (v.details ? v.details.slice(0, 240) : undefined),
      severity: classifyOsvSeverity(v),
      references: (v.references ?? [])
        .map((r) => r.url)
        .filter((u): u is string => !!u),
      aliases: v.aliases,
    }));
    return { status: "checked", url, vulnerabilities };
  } catch (error) {
    clearTimeout(timeout);
    const message =
      error instanceof Error && error.name === "AbortError"
        ? "OSV API timed out after 10s"
        : error instanceof Error
          ? error.message
          : String(error);
    return { status: "error", url, message };
  }
}

function classifyOsvSeverity(v: OsvRawVuln): Risk {
  const dbSev = v.database_specific?.severity?.toUpperCase();
  if (dbSev === "CRITICAL" || dbSev === "HIGH") return "high";
  if (dbSev === "MODERATE" || dbSev === "MEDIUM") return "medium";
  if (dbSev === "LOW") return "low";
  for (const s of v.severity ?? []) {
    if (!s.type || !s.score) continue;
    if (s.type.startsWith("CVSS")) {
      const numeric = parseCvssBaseScore(s.score);
      if (numeric !== undefined) {
        if (numeric >= 7) return "high";
        if (numeric >= 4) return "medium";
        return "low";
      }
    }
  }
  // Default for an OSV vuln of unknown severity is medium — never low.
  return "medium";
}

function parseCvssBaseScore(score: string): number | undefined {
  // OSV severity scores are usually CVSS v3/v3.1 vector strings, occasionally bare numbers.
  const numericMatch = score.match(/^(\d+(?:\.\d+)?)$/);
  if (numericMatch) return Number(numericMatch[1]);
  return computeCvssV3BaseScore(score);
}

// CVSS v3.0 / v3.1 base score, per First.org spec §7.1.
export function computeCvssV3BaseScore(vector: string): number | undefined {
  if (!/^CVSS:3\.[01]\//.test(vector)) return undefined;
  const metrics: Record<string, string> = {};
  for (const part of vector.split("/").slice(1)) {
    const [k, v] = part.split(":");
    if (k && v) metrics[k] = v;
  }
  const get = (k: string) => metrics[k];
  const AV = ({ N: 0.85, A: 0.62, L: 0.55, P: 0.2 } as const)[
    get("AV") as "N" | "A" | "L" | "P"
  ];
  const AC = ({ L: 0.77, H: 0.44 } as const)[get("AC") as "L" | "H"];
  const UI = ({ N: 0.85, R: 0.62 } as const)[get("UI") as "N" | "R"];
  const S = get("S");
  if (S !== "U" && S !== "C") return undefined;
  const PR_TABLE =
    S === "C"
      ? ({ N: 0.85, L: 0.68, H: 0.5 } as const)
      : ({ N: 0.85, L: 0.62, H: 0.27 } as const);
  const PR = PR_TABLE[get("PR") as "N" | "L" | "H"];
  const impactValue = (m: string) =>
    (({ N: 0, L: 0.22, H: 0.56 }) as const)[m as "N" | "L" | "H"];
  const C = impactValue(get("C"));
  const I = impactValue(get("I"));
  const A = impactValue(get("A"));
  if ([AV, AC, UI, PR, C, I, A].some((v) => v === undefined)) return undefined;
  const iss = 1 - (1 - C!) * (1 - I!) * (1 - A!);
  const impact =
    S === "C" ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 : 6.42 * iss;
  if (impact <= 0) return 0;
  const exploitability = 8.22 * AV! * AC! * PR! * UI!;
  const raw =
    S === "C"
      ? Math.min(1.08 * (impact + exploitability), 10)
      : Math.min(impact + exploitability, 10);
  // roundUp1: smallest number, specified to one decimal place, ≥ raw.
  return Math.ceil(raw * 10) / 10;
}

// ---------------------------------------------------------------------------
// npm registry signature verification
// ---------------------------------------------------------------------------

type NpmKey = {
  keyid: string;
  key: string;
  scheme?: string;
  expires?: string | null;
};
let npmKeysCache: NpmKey[] | undefined;

async function fetchNpmKeys(): Promise<NpmKey[]> {
  if (npmKeysCache) return npmKeysCache;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10_000);
  let res: Response;
  try {
    res = await fetch("https://registry.npmjs.org/-/npm/v1/keys", {
      signal: controller.signal,
    });
  } catch (error) {
    clearTimeout(timeout);
    if (error instanceof Error && error.name === "AbortError") {
      throw new Error("npm keys lookup timed out after 10s");
    }
    throw error;
  }
  clearTimeout(timeout);
  if (!res.ok) throw new Error(`npm keys lookup failed: HTTP ${res.status}`);
  const data = (await res.json()) as { keys?: NpmKey[] };
  if (!Array.isArray(data.keys) || data.keys.length === 0) {
    throw new Error("npm keys endpoint returned no keys");
  }
  npmKeysCache = data.keys;
  return data.keys;
}

function isKeyUsable(key: NpmKey): boolean {
  if (!key.expires) return true;
  const expiresAt = Date.parse(key.expires);
  return Number.isFinite(expiresAt) && expiresAt > Date.now();
}

function verifyEcdsaSignature(
  message: string,
  sigBase64: string,
  base64Key: string,
): boolean {
  const keyPem = `-----BEGIN PUBLIC KEY-----\n${base64Key}\n-----END PUBLIC KEY-----`;
  const publicKey = createPublicKey({ key: keyPem, format: "pem" });
  const verify = createVerify("SHA256");
  verify.update(message);
  verify.end();
  return verify.verify(publicKey, Buffer.from(sigBase64, "base64"));
}

export async function verifyNpmSignatures(
  name: string,
  version: string,
  dist: { integrity?: unknown; signatures?: unknown },
  options: { offline?: boolean } = {},
): Promise<NpmSignatureResult> {
  if (options.offline) {
    return {
      status: "skipped",
      message: "Offline mode: npm signature verification skipped.",
    };
  }
  const signatures = Array.isArray(dist.signatures)
    ? (dist.signatures as Array<{ keyid?: string; sig?: string }>)
    : [];
  if (signatures.length === 0) {
    return {
      status: "no-signature",
      message: "Registry returned no signatures for this version.",
    };
  }
  const integrity =
    typeof dist.integrity === "string" ? dist.integrity : undefined;
  if (!integrity) {
    return {
      status: "error",
      message: "Cannot verify signature: dist.integrity is missing.",
    };
  }
  try {
    const keys = await fetchNpmKeys();
    const message = `${name}@${version}:${integrity}`;
    for (const sig of signatures) {
      if (!sig.keyid || !sig.sig) {
        return {
          status: "error",
          message: "Malformed signature entry from registry.",
        };
      }
      const key = keys.find((k) => k.keyid === sig.keyid);
      if (!key) {
        return {
          status: "unverified",
          keyid: sig.keyid,
          message: `Signing key ${sig.keyid} not found in the npm key registry.`,
        };
      }
      const ok = verifyEcdsaSignature(message, sig.sig, key.key);
      if (!ok) {
        return {
          status: "unverified",
          keyid: sig.keyid,
          message: `Signature verification failed for keyid ${sig.keyid}.`,
        };
      }
      if (!isKeyUsable(key)) {
        return {
          status: "unverified",
          keyid: sig.keyid,
          message: `Signature was produced with an expired signing key ${sig.keyid} (expires=${key.expires}).`,
        };
      }
    }
    return { status: "verified", keyid: signatures[0].keyid };
  } catch (error) {
    return {
      status: "error",
      message: error instanceof Error ? error.message : String(error),
    };
  }
}

// ---------------------------------------------------------------------------
// Typosquat / name-similarity check vs. bundled top-package list
// ---------------------------------------------------------------------------

const TOP_PACKAGES: string[] = topNpmPackages as string[];
const TOP_PACKAGES_SET = new Set(TOP_PACKAGES);

export function checkTyposquat(name: string): TyposquatResult {
  if (!name || name.length < 3) {
    return { status: "checked", exactMatch: false, suspiciousMatches: [] };
  }
  if (TOP_PACKAGES_SET.has(name)) {
    return { status: "checked", exactMatch: true, suspiciousMatches: [] };
  }
  const matches: Array<{ name: string; distance: number }> = [];
  for (const top of TOP_PACKAGES) {
    if (Math.abs(name.length - top.length) > 2) continue;
    const d = levenshtein(name, top);
    if (d > 0 && d <= 2) {
      matches.push({ name: top, distance: d });
    }
  }
  matches.sort(
    (a, b) => a.distance - b.distance || a.name.localeCompare(b.name),
  );
  return {
    status: "checked",
    exactMatch: false,
    suspiciousMatches: matches.slice(0, 5),
  };
}

export function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;
  let prev = new Array(b.length + 1);
  let cur = new Array(b.length + 1);
  for (let j = 0; j <= b.length; j++) prev[j] = j;
  for (let i = 1; i <= a.length; i++) {
    cur[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      cur[j] = Math.min(cur[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost);
    }
    [prev, cur] = [cur, prev];
  }
  return prev[b.length];
}

// ---------------------------------------------------------------------------
// Package age — first publish date and version publish date
// ---------------------------------------------------------------------------

export async function checkPackageAge(
  name: string,
  version: string,
  options: { offline?: boolean } = {},
): Promise<PackageAgeResult> {
  if (options.offline) {
    return {
      status: "skipped",
      message: "Offline mode: registry time lookup skipped.",
    };
  }
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10_000);
  try {
    const url = `https://registry.npmjs.org/${encodeURIComponent(name).replace("%40", "@")}`;
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { Accept: "application/json" },
    });
    clearTimeout(timeout);
    if (!res.ok) {
      return {
        status: "error",
        message: `Registry returned HTTP ${res.status}`,
      };
    }
    const data = (await res.json()) as { time?: Record<string, string> };
    const time = data.time ?? {};
    const created = time.created;
    const versionPublished = time[version];
    const now = Date.now();
    const packageAgeDays = created
      ? Math.floor((now - Date.parse(created)) / 86_400_000)
      : undefined;
    const versionAgeHours = versionPublished
      ? Math.floor((now - Date.parse(versionPublished)) / 3_600_000)
      : undefined;
    return {
      status: "checked",
      packageCreatedAt: created,
      versionPublishedAt: versionPublished,
      packageAgeDays,
      versionAgeHours,
    };
  } catch (error) {
    clearTimeout(timeout);
    const message =
      error instanceof Error && error.name === "AbortError"
        ? "Registry time lookup timed out after 10s"
        : error instanceof Error
          ? error.message
          : String(error);
    return { status: "error", message };
  }
}

export async function writeAgentPrompt(
  report: Report,
  agent: string,
  reportPath?: string,
) {
  const base = report.target.replace(/[^a-z0-9_.@-]+/gi, "_");
  const path = join(REPORT_DIR, `${base}-${agent}-prompt.md`);
  const agentName: AgentName = agent === "pi" ? "pi" : "codex";
  await Bun.write(
    path,
    agentReviewPrompt(report, reportPath ?? path, agentName),
  );
  return path;
}
