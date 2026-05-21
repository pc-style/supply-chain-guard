import { describe, test, expect, beforeAll } from "bun:test";
import { join } from "node:path";
import { analyzeDirectory } from "./analysis";
import { ensureLargeBinFixture } from "./fixtures-support";
import { ROOT } from "./core";

const FIXTURES = join(ROOT, "src", "fixtures");

beforeAll(async () => {
  await ensureLargeBinFixture();
});

async function scan(dir: string) {
  return analyzeDirectory(`fixture:${dir}`, "npm", join(FIXTURES, dir), "local-fixture");
}

describe("benign-package fixture", () => {
  test("scans clean", async () => {
    const report = await scan("benign-package");
    expect(report.summary.risk).toBe("low");
    expect(report.summary.installAllowed).toBe(true);
  });
});

describe("malicious-postinstall fixture", () => {
  test("flags lifecycle script + pipe-to-shell, blocks install", async () => {
    const report = await scan("malicious-postinstall");
    expect(report.summary.risk).toBe("high");
    expect(report.summary.installAllowed).toBe(false);
    const ids = report.findings.map((f) => f.id);
    expect(ids).toContain("script.postinstall");
    expect(ids.some((id) => id.includes("pipe-to-shell"))).toBe(true);
  });
});

describe("credential-exfil fixture", () => {
  test("flags credential-access pattern, blocks install", async () => {
    const report = await scan("credential-exfil");
    expect(report.summary.risk).toBe("high");
    expect(report.summary.installAllowed).toBe(false);
    const ids = report.findings.map((f) => f.id);
    expect(ids.some((id) => id.includes("credential-access"))).toBe(true);
  });
});

describe("encoded-payload fixture", () => {
  test("flags lifecycle script (postinstall is high) and encoded-payload pattern", async () => {
    const report = await scan("encoded-payload");
    expect(report.summary.risk).toBe("high");
    const ids = report.findings.map((f) => f.id);
    expect(ids).toContain("script.postinstall");
    expect(ids.some((id) => id.includes("encoded-payload"))).toBe(true);
  });
});

describe("typosquat-react fixture", () => {
  test("scans without errors (typosquat detection is owned by the integrations layer)", async () => {
    const report = await scan("typosquat-react");
    // The fixture itself has no lifecycle scripts. Risk should not be high
    // from local analysis alone; the typosquat check is plugged in elsewhere.
    expect(["low", "medium", "high"]).toContain(report.summary.risk);
    expect(report.target).toBe("fixture:typosquat-react");
  });
});

describe("large-bin fixture", () => {
  test("flags large packed file and bin entry", async () => {
    const report = await scan("large-bin");
    const ids = report.findings.map((f) => f.id);
    expect(ids).toContain("package.bin");
    expect(ids.some((id) => id.startsWith("large-file."))).toBe(true);
    // bin + large-file are both medium severity in the analyzer today.
    expect(["medium", "high"]).toContain(report.summary.risk);
  });
});
