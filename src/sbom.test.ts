import { describe, test, expect } from "bun:test";
import { existsSync } from "node:fs";
import { rm } from "node:fs/promises";
import { join } from "node:path";
import { analyzeDirectory } from "./analysis";
import { emitReport, REPORT_SCHEMA_URL } from "./reporting";
import { buildCycloneDxSbom, sbomPathFor } from "./sbom";
import { ROOT } from "./core";

const FIXTURE = join(ROOT, "src", "fixtures", "benign-package");

describe("buildCycloneDxSbom", () => {
  test("emits a CycloneDX 1.5 document with a single library component", async () => {
    const report = await analyzeDirectory("scguard-test@1.2.3", "npm", FIXTURE, "local-fixture");
    // Force a deterministic name+version+sha for assertion clarity.
    report.target = "left-pad@1.3.0";
    report.artifact.sha256 = "a".repeat(64);

    const sbom = buildCycloneDxSbom(report) as Record<string, any>;
    expect(sbom.bomFormat).toBe("CycloneDX");
    expect(sbom.specVersion).toBe("1.5");
    expect(Array.isArray(sbom.components)).toBe(true);
    expect(sbom.components.length).toBe(1);
    const c = sbom.components[0];
    expect(c.type).toBe("library");
    expect(c.name).toBe("left-pad");
    expect(c.version).toBe("1.3.0");
    expect(c.purl).toBe("pkg:npm/left-pad@1.3.0");
    expect(c.hashes).toEqual([{ alg: "SHA-256", content: "a".repeat(64) }]);
  });

  test("scoped npm names produce a correctly encoded purl", async () => {
    const report = await analyzeDirectory("@scope/pkg@2.0.0", "npm", FIXTURE, "local-fixture");
    report.target = "@scope/pkg@2.0.0";
    const sbom = buildCycloneDxSbom(report) as Record<string, any>;
    expect(sbom.components[0].purl).toBe("pkg:npm/%40scope/pkg@2.0.0");
  });

  test("vsix kind omits the purl (no widely-adopted purl scheme)", async () => {
    const report = await analyzeDirectory("ext.vsix", "vsix", FIXTURE, "local-fixture");
    const sbom = buildCycloneDxSbom(report) as Record<string, any>;
    expect(sbom.components[0].purl).toBeUndefined();
  });
});

describe("emitReport SBOM integration", () => {
  test("writes a sibling .cdx.json file when --sbom is set", async () => {
    const report = await analyzeDirectory("left-pad@1.3.0", "npm", FIXTURE, "local-fixture");
    report.target = "left-pad@1.3.0";
    report.artifact.sha256 = "b".repeat(64);

    const jsonPath = await emitReport(report, false, { sbom: true });
    try {
      const sbomPath = sbomPathFor(jsonPath);
      expect(existsSync(sbomPath)).toBe(true);
      const sbom = JSON.parse(await Bun.file(sbomPath).text());
      expect(sbom.components[0].purl).toBe("pkg:npm/left-pad@1.3.0");
      expect(sbom.components[0].hashes[0].content).toBe("b".repeat(64));

      // The emitted report includes the $schema field pointing at our schema URL.
      const persisted = JSON.parse(await Bun.file(jsonPath).text());
      expect(persisted.$schema).toBe(REPORT_SCHEMA_URL);
      expect(persisted.schemaVersion).toBe(1);
    } finally {
      // Best-effort cleanup of the artifacts created in REPORT_DIR.
      await rm(jsonPath, { force: true }).catch(() => {});
      await rm(jsonPath.replace(/\.json$/, ".md"), { force: true }).catch(() => {});
      await rm(sbomPathFor(jsonPath), { force: true }).catch(() => {});
    }
  });
});
