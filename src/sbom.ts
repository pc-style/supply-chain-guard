import { randomUUID } from "node:crypto";
import type { Report } from "./core";

/**
 * Build a minimal CycloneDX 1.5 JSON SBOM for a single scanned component.
 * Includes purl for npm targets and a SHA-256 hash from the report artifact.
 */
export function buildCycloneDxSbom(report: Report): Record<string, unknown> {
  const component = buildComponent(report);
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: report.generatedAt,
      tools: [
        {
          vendor: "pc-style",
          name: "supply-chain-guard",
          // The scanner version is not threaded through reports; "0" keeps the
          // SBOM valid without coupling to package.json reads at scan time.
          version: "0",
        },
      ],
    },
    components: [component],
  };
}

function buildComponent(report: Report) {
  const { name, version } = parseTarget(report);
  const bomRef = `${name}@${version}`;
  const sha256 = report.artifact.sha256;
  const purl = buildPurl(report.kind, name, version);
  const component: Record<string, unknown> = {
    "bom-ref": bomRef,
    type: "library",
    name,
    version,
  };
  if (purl) component.purl = purl;
  if (sha256 && sha256 !== "not-applicable") {
    component.hashes = [{ alg: "SHA-256", content: sha256 }];
  }
  return component;
}

function parseTarget(report: Report): { name: string; version: string } {
  const target = report.target;
  if (report.kind === "npm" || report.kind === "npm-stage") {
    // npm-stage targets look like "npm-stage:<id>:<name>@<version>"
    const cleaned = target.startsWith("npm-stage:")
      ? target.split(":").slice(2).join(":")
      : target;
    const at = cleaned.lastIndexOf("@");
    if (at > 0) {
      return { name: cleaned.slice(0, at), version: cleaned.slice(at + 1) || "0.0.0" };
    }
    return { name: cleaned, version: "0.0.0" };
  }
  // vsix: target is typically the file basename. Try to read from packageJson if available.
  const pkg = report.packageJson ?? {};
  const name = typeof pkg.name === "string" ? pkg.name : target;
  const version = typeof pkg.version === "string" ? pkg.version : "0.0.0";
  return { name, version };
}

function buildPurl(kind: Report["kind"], name: string, version: string): string | undefined {
  if (kind === "npm" || kind === "npm-stage") {
    return `pkg:npm/${encodePurlName(name)}@${encodeURIComponent(version)}`;
  }
  // CycloneDX has no widely-adopted purl scheme for VSIX; omit by design.
  return undefined;
}

function encodePurlName(name: string): string {
  // Scoped packages: keep the `/` between scope and name but URL-encode each part.
  if (name.startsWith("@")) {
    const slash = name.indexOf("/");
    if (slash > 0) {
      const scope = name.slice(0, slash);
      const bare = name.slice(slash + 1);
      return `${encodeURIComponent(scope)}/${encodeURIComponent(bare)}`;
    }
  }
  return encodeURIComponent(name);
}

export function sbomPathFor(reportJsonPath: string): string {
  return reportJsonPath.replace(/\.json$/, "-sbom.cdx.json");
}
