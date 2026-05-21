import { join } from "node:path";
import { REPORT_DIR } from "./core";
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
  const lines = [
    `# Supply Chain Report: ${report.target}`,
    "",
    `- Kind: ${report.kind}`,
    `- Risk: ${report.summary.risk}`,
    `- Install allowed: ${report.summary.installAllowed}`,
    `- Artifact: ${report.artifact.source}`,
    `- SHA-256: ${report.artifact.sha256}`,
    `- Socket: ${report.intelligence.socket?.status ?? "not-applicable"}`,
    `- OSV: ${report.intelligence.osv?.status ?? "not-applicable"}${
      report.intelligence.osv?.vulnerabilities?.length
        ? ` (${report.intelligence.osv.vulnerabilities.length} advisory)`
        : ""
    }`,
    `- npm signature: ${report.intelligence.npmSignature?.status ?? "not-applicable"}`,
    `- Typosquat: ${
      report.intelligence.typosquat?.exactMatch
        ? "exact-match"
        : report.intelligence.typosquat?.suspiciousMatches?.length
          ? `close: ${report.intelligence.typosquat.suspiciousMatches.map((m) => `${m.name}(${m.distance})`).join(", ")}`
          : "no-match"
    }`,
    `- Package age: ${
      report.intelligence.packageAge?.status === "checked"
        ? `package=${report.intelligence.packageAge.packageAgeDays ?? "?"}d version=${report.intelligence.packageAge.versionAgeHours ?? "?"}h`
        : (report.intelligence.packageAge?.status ?? "not-applicable")
    }`,
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
