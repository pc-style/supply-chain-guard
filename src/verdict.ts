import type { Finding, Report, Risk, SafeResolverSuggestion } from "./core";

export type VerdictValue = "allow" | "review" | "block";
export type VerdictConfidence = "high" | "medium" | "low";
export type VerdictCategory =
  | "install-time execution"
  | "credential access"
  | "network exfiltration"
  | "obfuscation/minification"
  | "new package/version"
  | "known advisory"
  | "provenance/signature"
  | "typosquat"
  | "coverage gap"
  | "dependency surface"
  | "editor execution"
  | "active advisory";

export type VerdictRisk = {
  category: VerdictCategory;
  severity: Risk;
  findingId?: string;
  detail: string;
};

export type Verdict = {
  verdict: VerdictValue;
  confidence: VerdictConfidence;
  installAllowed: boolean;
  primaryReason: string;
  categories: VerdictCategory[];
  topRisks: VerdictRisk[];
  reassuringSignals: string[];
  skippedIncompleteChecks: string[];
  exactNextAction: string;
  safeResolver?: {
    resolvedVersion?: string;
    suggestedVersion?: string;
    versionAgeHours?: number;
    command?: string;
    reason: string;
  };
};

type VerdictInput = Pick<
  Report,
  "target" | "kind" | "findings" | "intelligence" | "policy"
>;

export function buildVerdict(report: VerdictInput): Verdict {
  const topRisks = report.findings.map(classifyFinding);
  const categories = unique(topRisks.map((risk) => risk.category));
  const high = topRisks.filter((risk) => risk.severity === "high");
  const medium = topRisks.filter((risk) => risk.severity === "medium");
  const skippedIncompleteChecks = skippedChecks(report);
  const reassuringSignals = buildReassuringSignals(report);
  const safeResolver = safeResolverDetails(report);

  if (safeResolver && !categories.includes("new package/version")) {
    categories.push("new package/version");
  }
  if (
    skippedIncompleteChecks.length > 0 &&
    !categories.includes("coverage gap")
  ) {
    categories.push("coverage gap");
  }

  const verdict: VerdictValue =
    high.length > 0
      ? "block"
      : medium.length > 0 || skippedIncompleteChecks.length > 0 || safeResolver
        ? "review"
        : "allow";
  const installAllowed = verdict !== "block";
  const confidence = chooseConfidence({
    verdict,
    topRisks,
    skippedIncompleteChecks,
    reassuringSignals,
    safeResolver,
  });
  const primaryReason = choosePrimaryReason({
    verdict,
    topRisks,
    skippedIncompleteChecks,
    safeResolver,
  });

  return {
    verdict,
    confidence,
    installAllowed,
    primaryReason,
    categories,
    topRisks: topRisks.slice(0, 8),
    reassuringSignals,
    skippedIncompleteChecks,
    exactNextAction: exactNextAction({
      report,
      verdict,
      primaryReason,
      safeResolver,
    }),
    ...(safeResolver ? { safeResolver } : {}),
  };
}

function classifyFinding(finding: Finding): VerdictRisk {
  return {
    category: categoryForFinding(finding),
    severity: finding.severity,
    findingId: finding.id,
    detail: `${finding.title}: ${finding.evidence}`.slice(0, 280),
  };
}

export function categoryForFinding(finding: Finding): VerdictCategory {
  const id = finding.id;
  const text = `${finding.title} ${finding.evidence}`.toLowerCase();
  if (id.startsWith("script.") || id.includes("install-reachable"))
    return "install-time execution";
  if (
    id.includes("credential") ||
    id.includes("sensitive-path") ||
    id.includes("env-secret")
  )
    return "credential access";
  if (id.includes("dns-exfiltration") || id.includes("read-then-send"))
    return "network exfiltration";
  if (
    id.includes("pipe-to-shell") ||
    (id.includes("network-access") && id.startsWith("script."))
  )
    return "network exfiltration";
  if (
    id.includes("encoded-payload") ||
    id.includes("dynamic-execution") ||
    id.includes("minified") ||
    text.includes("obfuscat")
  )
    return "obfuscation/minification";
  if (id.startsWith("package.new") || id.startsWith("version.new"))
    return "new package/version";
  if (id.startsWith("osv.")) return "known advisory";
  if (id.startsWith("npm.signature") || id.includes("integrity"))
    return "provenance/signature";
  if (id.includes("typosquat")) return "typosquat";
  if (id.startsWith("dependencies.")) return "dependency surface";
  if (id.startsWith("vscode.")) return "editor execution";
  if (id.includes("advisory.active")) return "active advisory";
  if (id.includes("large-file")) return "coverage gap";
  return "coverage gap";
}

function skippedChecks(report: VerdictInput): string[] {
  const skipped: string[] = [];
  for (const finding of report.findings) {
    if (finding.id.endsWith(".minified")) {
      skipped.push(
        `Minified/bundled file reduces static-analysis precision: ${finding.id.replace(/^file\./, "").replace(/\.minified$/, "")}`,
      );
    }
  }
  const socket = report.intelligence.socket;
  if (socket && socket.status !== "checked")
    skipped.push(
      `Socket intelligence ${socket.status}: ${socket.message ?? "not checked"}`,
    );
  const osv = report.intelligence.osv;
  if (osv && osv.status !== "checked")
    skipped.push(
      `OSV advisory lookup ${osv.status}: ${osv.message ?? "not checked"}`,
    );
  const sig = report.intelligence.npmSignature;
  if (sig && (sig.status === "skipped" || sig.status === "error"))
    skipped.push(
      `npm signature verification ${sig.status}: ${sig.message ?? "not checked"}`,
    );
  return unique(skipped);
}

function buildReassuringSignals(report: VerdictInput): string[] {
  const signals: string[] = [];
  if (report.findings.length === 0)
    signals.push("No local static findings were produced.");
  if (
    report.intelligence.osv?.status === "checked" &&
    !report.intelligence.osv.vulnerabilities?.length
  )
    signals.push("OSV returned no known advisories for this version.");
  if (report.intelligence.npmSignature?.status === "verified")
    signals.push("npm registry signature verified.");
  if (report.intelligence.typosquat?.exactMatch)
    signals.push("Package name matches the popularity baseline exactly.");
  if (report.intelligence.packageAge?.status === "checked") {
    const age = report.intelligence.packageAge;
    const parts: string[] = [];
    if (typeof age.packageAgeDays === "number")
      parts.push(`package age ${age.packageAgeDays}d`);
    if (typeof age.versionAgeHours === "number")
      parts.push(`version age ${age.versionAgeHours}h`);
    if (parts.length) signals.push(parts.join(", "));
  }
  return signals;
}

function safeResolverDetails(
  report: VerdictInput,
): Verdict["safeResolver"] | undefined {
  const suggestion = report.policy?.safeResolverSuggestion;
  if (!suggestion || suggestion.status !== "suggested") return undefined;
  const packageName = packageNameFromTarget(report.target);
  return {
    resolvedVersion: suggestion.resolved,
    suggestedVersion: suggestion.suggested,
    versionAgeHours:
      report.intelligence.packageAge?.status === "checked"
        ? report.intelligence.packageAge.versionAgeHours
        : undefined,
    command: safeResolverCommand(packageName, suggestion),
    reason: suggestion.message,
  };
}

function safeResolverCommand(
  packageName: string,
  suggestion: SafeResolverSuggestion,
) {
  if (!suggestion.suggested) return undefined;
  return `scguard review ${packageName}@${suggestion.suggested}`;
}

function packageNameFromTarget(target: string) {
  if (target.startsWith("@")) {
    const secondAt = target.indexOf("@", 1);
    return secondAt === -1 ? target : target.slice(0, secondAt);
  }
  const at = target.lastIndexOf("@");
  return at > 0 ? target.slice(0, at) : target;
}

function chooseConfidence(input: {
  verdict: VerdictValue;
  topRisks: VerdictRisk[];
  skippedIncompleteChecks: string[];
  reassuringSignals: string[];
  safeResolver?: Verdict["safeResolver"];
}): VerdictConfidence {
  if (input.skippedIncompleteChecks.length > 1) return "low";
  if (input.verdict === "block") {
    const installTime = input.topRisks.some(
      (risk) =>
        risk.severity === "high" &&
        (risk.category === "install-time execution" ||
          risk.category === "network exfiltration" ||
          risk.category === "credential access"),
    );
    return installTime
      ? "high"
      : input.skippedIncompleteChecks.length
        ? "medium"
        : "high";
  }
  if (input.verdict === "review")
    return input.skippedIncompleteChecks.length || input.safeResolver
      ? "medium"
      : "high";
  return input.reassuringSignals.length >= 2 ? "high" : "medium";
}

function choosePrimaryReason(input: {
  verdict: VerdictValue;
  topRisks: VerdictRisk[];
  skippedIncompleteChecks: string[];
  safeResolver?: Verdict["safeResolver"];
}) {
  const firstHigh = input.topRisks.find((risk) => risk.severity === "high");
  if (input.verdict === "block" && firstHigh)
    return `${firstHigh.category}: ${firstHigh.detail}`;
  if (input.safeResolver)
    return `Safe Resolver suggests reviewing an older satisfying version: ${input.safeResolver.suggestedVersion}.`;
  const firstMedium = input.topRisks.find((risk) => risk.severity === "medium");
  if (firstMedium) return `${firstMedium.category}: ${firstMedium.detail}`;
  if (input.skippedIncompleteChecks.length)
    return `Coverage gap: ${input.skippedIncompleteChecks[0]}`;
  return "No blocking or review-level supply-chain signals were detected.";
}

function exactNextAction(input: {
  report: VerdictInput;
  verdict: VerdictValue;
  primaryReason: string;
  safeResolver?: Verdict["safeResolver"];
}) {
  if (input.verdict === "block")
    return `Do not install ${input.report.target}; inspect the report and choose a different version or package.`;
  if (input.safeResolver?.command) return input.safeResolver.command;
  if (input.verdict === "review")
    return `Review ${input.report.target} manually or run an agent review before installing.`;
  return `Install may proceed if ${input.report.target} is the package you intended.`;
}

function unique<T>(values: T[]): T[] {
  return [...new Set(values)];
}
