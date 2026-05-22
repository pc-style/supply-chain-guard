import { join, relative } from "node:path";
import { REPORT_DIR, ROOT } from "./core";
import type { AgentReview, Report } from "./core";
import { resolveAgentMode, runAgentReviews, writeAgentPrompt } from "./integrations";
import { buildCycloneDxSbom, sbomPathFor } from "./sbom";
import {
  blockedLine,
  c,
  header,
  meta,
  okLine,
  riskRow,
  riskWord,
  style,
} from "./ui";

export const REPORT_SCHEMA_URL =
  "https://raw.githubusercontent.com/pc-style/supply-chain-guard/main/docs/report-schema.json";

export type EmitReportOptions = {
  sbom?: boolean;
};

export async function emitReport(report: Report, json: boolean, opts: EmitReportOptions = {}) {
  const base = report.target.replace(/[^a-z0-9_.@-]+/gi, "_");
  const jsonPath = join(REPORT_DIR, `${base}-${Date.now()}.json`);
  const serialized = serializeReport(report);
  await Bun.write(jsonPath, JSON.stringify(serialized, null, 2));
  await Bun.write(jsonPath.replace(/\.json$/, ".md"), renderMarkdown(report, jsonPath));
  await writeAgentPrompt(report, "codex", jsonPath);
  await writeAgentPrompt(report, "pi", jsonPath);
  if (opts.sbom) {
    const sbom = buildCycloneDxSbom(report);
    await Bun.write(sbomPathFor(jsonPath), JSON.stringify(sbom, null, 2));
  }
  if (json) {
    console.log(JSON.stringify(serialized, null, 2));
    return jsonPath;
  }
  renderHumanReport(report, jsonPath);
  return jsonPath;
}

function serializeReport(report: Report): Record<string, unknown> {
  return { $schema: REPORT_SCHEMA_URL, ...report };
}

function renderHumanReport(report: Report, jsonPath: string) {
  console.log(header("Supply Chain Guard Report"));
  meta("target", report.target);
  meta("kind", report.kind);
  meta("risk", riskWord(report.summary.risk));
  meta("findings", String(report.summary.findingCount));
  meta("sha256", report.artifact.sha256.slice(0, 16) + (report.artifact.sha256.length > 16 ? "..." : ""));
  if (report.intelligence.socket) meta("socket", report.intelligence.socket.status);
  if (report.intelligence.osv) {
    const vulnCount = report.intelligence.osv.vulnerabilities?.length ?? 0;
    meta("osv", `${report.intelligence.osv.status}${vulnCount ? ` (${vulnCount} advisory${vulnCount === 1 ? "" : "ies"})` : ""}`);
  }
  if (report.intelligence.npmSignature) meta("npm-signature", report.intelligence.npmSignature.status);
  if (report.intelligence.typosquat) {
    const matches = report.intelligence.typosquat.suspiciousMatches?.length ?? 0;
    meta("typosquat", report.intelligence.typosquat.exactMatch
      ? "exact-match"
      : matches > 0
        ? `${matches} close match${matches === 1 ? "" : "es"}`
        : "no-match");
  }
  if (report.intelligence.packageAge?.status === "checked") {
    const a = report.intelligence.packageAge;
    const parts: string[] = [];
    if (typeof a.packageAgeDays === "number") parts.push(`package=${a.packageAgeDays}d`);
    if (typeof a.versionAgeHours === "number") parts.push(`version=${a.versionAgeHours}h`);
    meta("age", parts.join(" ") || "unknown");
  }
  if (report.policy) {
    meta("preset", report.policy.preset);
    meta("scan-reason", report.policy.scanReason);
    if (report.policy.safeResolverSuggestion) {
      meta("safe-resolver", report.policy.safeResolverSuggestion.message);
    }
  }

  if (report.findings.length > 0) {
    console.log(header("Findings"));
    for (const finding of report.findings) {
      console.log(
        riskRow(
          finding.severity,
          finding.id,
          finding.title,
          finding.recommendation,
        ),
      );
    }
  } else {
    console.log(header("Findings"));
    okLine("no findings");
  }

  console.log("");
  if (report.summary.installAllowed) {
    okLine(
      `${report.target}: ${report.summary.risk} risk, ${report.summary.findingCount} finding(s) - install allowed.`,
    );
  } else {
    blockedLine(
      "install blocked.",
      `${report.findings.filter((f) => f.severity === "high").length} high-risk issue(s) found.`,
    );
  }
  console.log(`  ${c.dim("json")} ${c.gray(jsonPath)}`);
  console.log(`  ${c.dim("md  ")} ${c.gray(jsonPath.replace(/\.json$/, ".md"))}`);
}

export function renderMarkdown(report: Report, reportPath: string) {
  const basis = decisionBasis(report);
  const lines = [
    `# Supply Chain Report: ${report.target}`,
    "",
    "## Decision basis",
    "",
    `- Verdict: ${basis.verdict}`,
    `- Why install is ${report.summary.installAllowed ? "allowed" : "blocked"}: ${basis.installReason}`,
    `- Top risks: ${basis.topRisks.join("; ") || "none"}`,
    `- Reassuring signals: ${basis.reassuringSignals.join("; ") || "none"}`,
    `- Skipped/incomplete checks: ${basis.skippedChecks.join("; ") || "none"}`,
    `- Next action: ${basis.nextAction}`,
    "",
    "## Summary",
    "",
    `- Kind: ${report.kind}`,
    `- Risk: ${report.summary.risk}`,
    `- Findings: ${report.summary.findingCount}`,
    `- Install allowed: ${report.summary.installAllowed}`,
    `- Artifact: ${report.artifact.source}`,
    `- SHA-256: ${report.artifact.sha256}`,
    `- JSON: ${relative(ROOT, reportPath)}`,
    "",
    "## Policy",
    "",
    `- Active preset: ${report.policy?.preset ?? "default"}`,
    `- Scan reason: ${report.policy?.scanReason ?? "direct-review"}`,
    `- Safe resolver: ${report.policy?.safeResolverSuggestion?.message ?? (report.policy?.safeResolver ? report.policy.safeResolver : "off")}`,
    "",
    "## Intelligence",
    "",
    ...intelligenceLines(report),
    "",
    "## What was not checked",
    "",
    ...uncheckedLines(report),
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

export function decisionBasis(report: Report) {
  const high = report.findings.filter((f) => f.severity === "high");
  const medium = report.findings.filter((f) => f.severity === "medium");
  const minified = report.findings.filter((f) => f.id.endsWith(".minified"));
  const verdict = report.summary.installAllowed ? (report.summary.risk === "medium" ? "manual-risk-accepted" : "allow") : "block";
  return {
    verdict,
    installReason: report.summary.installAllowed
      ? `no high-severity findings were produced (${medium.length} medium, ${report.findings.filter((f) => f.severity === "low").length} low)`
      : `${high.length} high-severity finding(s) require blocking`,
    topRisks: [...high, ...medium].slice(0, 5).map((f) => `${f.severity}:${f.id}`),
    reassuringSignals: reassuringSignals(report),
    skippedChecks: skippedChecks(report, minified),
    nextAction: minified.length > 0
      ? "Inspect original source/package contents for minified files before relying on static scan results."
      : report.summary.installAllowed ? "Proceed only if this risk profile is acceptable." : "Do not install until findings are resolved.",
  };
}

function intelligenceLines(report: Report) {
  const lines: string[] = [];
  const socket = report.intelligence.socket;
  if (socket) {
    lines.push(`- Socket: ${socket.status}${typeof socket.supplyChainRisk === "number" ? `; supplyChainRisk=${socket.supplyChainRisk} (0=lowest risk, 1=highest risk; guard currently flags <=0.3 as suspicious legacy low-score threshold)` : ""}${socket.message ? `; ${socket.message}` : ""}`);
    const components = socketRiskComponents(socket.rawScore).slice(0, 8);
    if (components.length) lines.push(`  - Socket components: ${components.join(", ")}`);
  } else lines.push("- Socket: not-applicable");
  const osv = report.intelligence.osv;
  lines.push(`- OSV: ${osv?.status ?? "not-applicable"}; vulnerabilities=${osv?.vulnerabilities?.length ?? 0}`);
  if (osv?.vulnerabilities?.length) lines.push(...osv.vulnerabilities.slice(0, 5).map((v) => `  - ${v.severity}: ${v.id}${v.summary ? ` — ${v.summary}` : ""}`));
  lines.push(`- npm signature: ${report.intelligence.npmSignature?.status ?? "not-applicable"}${report.intelligence.npmSignature?.message ? `; ${report.intelligence.npmSignature.message}` : ""}`);
  lines.push(`- Package age: ${report.intelligence.packageAge?.status === "checked" ? `package=${report.intelligence.packageAge.packageAgeDays ?? "?"}d; version=${report.intelligence.packageAge.versionAgeHours ?? "?"}h` : (report.intelligence.packageAge?.status ?? "not-applicable")}`);
  lines.push(`- Active advisory: ${report.intelligence.activeAdvisory?.active ?? false}`);
  return lines;
}

function uncheckedLines(report: Report) {
  const minified = report.findings.filter((f) => f.id.endsWith(".minified"));
  const lines = minified.map((f) => `- Static pattern scanning skipped for minified file: ${f.id.replace(/^file\./, "").replace(/\.minified$/, "")}. Coverage is incomplete until original source is inspected.`);
  if (report.intelligence.socket?.status !== "checked") lines.push(`- Socket intelligence was not checked (${report.intelligence.socket?.status ?? "missing"}).`);
  if (report.intelligence.osv?.status !== "checked") lines.push(`- OSV vulnerability lookup was not checked (${report.intelligence.osv?.status ?? "missing"}).`);
  return lines.length ? lines : ["- No skipped checks recorded by this report."];
}

function reassuringSignals(report: Report) {
  const signals: string[] = [];
  if (report.intelligence.osv?.status === "checked" && !report.intelligence.osv.vulnerabilities?.length) signals.push("OSV returned 0 vulnerabilities");
  if (report.intelligence.npmSignature?.status === "verified") signals.push("npm provenance signature verified");
  if (report.intelligence.typosquat?.exactMatch) signals.push("package name exact-match in popularity baseline");
  if (report.intelligence.packageAge?.status === "checked") signals.push(`package age ${report.intelligence.packageAge.packageAgeDays ?? "?"}d`);
  return signals;
}

function skippedChecks(report: Report, minified = report.findings.filter((f) => f.id.endsWith(".minified"))) {
  return uncheckedLines(report).filter((line) => !line.includes("No skipped checks")).map((line) => line.replace(/^- /, ""));
}

function socketRiskComponents(rawScore: unknown) {
  if (!rawScore || typeof rawScore !== "object") return [];
  const entries = Object.entries(rawScore as Record<string, unknown>);
  return entries
    .filter(([, value]) => typeof value === "number" || typeof value === "boolean" || typeof value === "string")
    .map(([key, value]) => `${key}=${String(value)}`);
}

export async function maybeRunConfiguredAgentReview(report: Report, reportPath: string, args: string[], json: boolean, opts: EmitReportOptions = {}) {
  const agents = await resolveAgentMode(args);
  if (agents.length === 0) return;
  const reviews = await runAgentReviews(report, reportPath, agents);
  report.agentReviews = reviews;
  await emitReport(report, json, opts);
  blockOnFailedReview(report.target, reviews);
}

export function blockOnFailedReview(target: string, reviews: AgentReview[]) {
  const failed = reviews.find((review) => review.status !== "approved");
  if (failed) {
    throw new Error(`Blocked ${target}: ${failed.agent} returned ${failed.status}. See ${failed.outputPath}`);
  }
}
