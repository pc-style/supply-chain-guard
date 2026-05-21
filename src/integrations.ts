import { join, relative } from "node:path";
import { commandExists, readConfig, readOption, REPORT_DIR, ROOT } from "./core";
import type { AgentMode, AgentName, AgentReview, Report, SocketResult } from "./core";

export async function checkSocket(name: string, version: string): Promise<SocketResult> {
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
    const rawSupplyChainRisk = score?.supplyChainRisk;
    const supplyChainRisk = typeof rawSupplyChainRisk === "number"
      ? rawSupplyChainRisk
      : typeof rawSupplyChainRisk?.score === "number"
        ? rawSupplyChainRisk.score
        : undefined;
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

export async function runAgentReviews(report: Report, reportPath: string, agents: AgentName[]): Promise<AgentReview[]> {
  const reviews: AgentReview[] = [];
  for (const agent of agents) {
    reviews.push(await runAgentReview(report, reportPath, agent));
  }
  return reviews;
}

export async function runAgentReview(report: Report, reportPath: string, agent: AgentName): Promise<AgentReview> {
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
    summary: summarizeAgentOutput(output),
  };
}

export function agentReviewPrompt(report: Report, reportPath: string, agent: AgentName) {
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

export function parseAgentDecision(output: string): AgentReview["status"] {
  // Only accept decisions that appear on their own line with the exact token,
  // optionally followed by surrounding whitespace. This prevents matches inside
  // prose like "I would approve" or "SCGUARD_DECISION: approve-ish".
  const decisionLine = /^\s*SCGUARD_DECISION:\s*(approve|reject|manual-review)\s*$/gim;
  const matches: string[] = [];
  for (const m of output.matchAll(decisionLine)) matches.push(m[1].toLowerCase());
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

export async function writeAgentOutput(report: Report, agent: AgentName, output: string) {
  const outputPath = join(REPORT_DIR, `${report.target.replace(/[^a-z0-9_.@-]+/gi, "_")}-${agent}-review.txt`);
  await Bun.write(outputPath, output);
  return outputPath;
}

export function summarizeAgentOutput(output: string) {
  const lines = output.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const errorLine = [...lines].reverse().find((line) => /^ERROR:/i.test(line));
  if (errorLine) return errorLine.slice(0, 240);
  return lines.find((line) => line !== "--- stderr ---")?.slice(0, 240) ?? "";
}

export async function writeAgentPrompt(report: Report, agent: string, reportPath?: string) {
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
