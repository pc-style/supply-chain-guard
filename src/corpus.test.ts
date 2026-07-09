import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { analyzeDirectory } from "./analysis";
import type { Report } from "./core";
import { ROOT } from "./core";

type BenignCorpusEntry = {
  name: string;
  version: string;
};

const FIXTURES = join(ROOT, "src", "fixtures");
const BENIGN_CORPUS_PATH = join(FIXTURES, "corpus", "benign.json");

const benignCorpus = (await Bun.file(
  BENIGN_CORPUS_PATH,
).json()) as BenignCorpusEntry[];

async function scanFixture(
  dir: string,
  intelligence?: Partial<Report["intelligence"]>,
) {
  return analyzeDirectory(
    `fixture:${dir}`,
    "npm",
    join(FIXTURES, dir),
    "local-fixture",
    undefined,
    intelligence,
  );
}

describe("benign calibration corpus", () => {
  let tmpDir: string;

  beforeAll(async () => {
    tmpDir = await mkdtemp(join(tmpdir(), "scguard-benign-corpus-"));
    await Promise.all(
      benignCorpus.map(async ({ name, version }) => {
        const safeName = name.replaceAll("/", "__").replaceAll("@", "_");
        const dir = join(tmpDir, safeName);
        await mkdir(dir, { recursive: true });
        await writeFile(
          join(dir, "package.json"),
          JSON.stringify(
            {
              name,
              version,
              description:
                "Recorded benign corpus metadata fixture for offline judgment calibration.",
              license: "MIT",
            },
            null,
            2,
          ),
        );
      }),
    );
  });

  afterAll(async () => {
    await rm(tmpDir, { recursive: true, force: true });
  });

  test("contains the planned top-package coverage", () => {
    expect(benignCorpus).toHaveLength(50);
    expect(benignCorpus.map((entry) => entry.name)).toEqual(
      expect.arrayContaining(["axios", "chalk", "left-pad", "react", "zod"]),
    );
  });

  test("allows every recorded package under default policy", async () => {
    for (const { name, version } of benignCorpus) {
      const safeName = name.replaceAll("/", "__").replaceAll("@", "_");
      const report = await analyzeDirectory(
        `${name}@${version}`,
        "npm",
        join(tmpDir, safeName),
        "recorded-corpus-fixture",
      );
      expect(report.summary.installAllowed, `${name}@${version}`).toBe(true);
    }
  });

  test("catches an axios-style false positive if high Socket safety scores are inverted", async () => {
    const dir = join(tmpDir, "axios");
    const report = await analyzeDirectory(
      "axios@1.13.2",
      "npm",
      dir,
      "recorded-corpus-fixture",
      undefined,
      { socket: { status: "checked", supplyChainRisk: 0.9 } },
    );
    expect(report.summary.installAllowed).toBe(true);
    expect(
      report.findings.some(
        (finding) => finding.id === "socket.supply-chain-risk",
      ),
    ).toBe(false);
  });
});

describe("malicious calibration corpus", () => {
  test("existing malicious postinstall fixture blocks", async () => {
    const report = await scanFixture("malicious-postinstall");
    expect(report.summary.installAllowed).toBe(false);
    expect(
      report.findings.some((finding) => finding.id.endsWith(".pipe-to-shell")),
    ).toBe(true);
  });

  test("existing credential exfiltration fixture blocks", async () => {
    const report = await scanFixture("credential-exfil");
    expect(report.summary.installAllowed).toBe(false);
    expect(
      report.findings.some((finding) =>
        finding.id.endsWith(".credential-access"),
      ),
    ).toBe(true);
  });

  test("typosquat intelligence blocks", async () => {
    const report = await scanFixture("typosquat-react", {
      typosquat: {
        status: "checked",
        suspiciousMatches: [{ name: "react", distance: 1 }],
      },
    });
    expect(report.summary.installAllowed).toBe(false);
    expect(
      report.findings.some((finding) => finding.id === "name.typosquat"),
    ).toBe(true);
  });

  test("high OSV advisory blocks", async () => {
    const report = await scanFixture("benign-package", {
      osv: {
        status: "checked",
        vulnerabilities: [
          {
            id: "MALICIOUS-CORPUS-POSTINSTALL-EXFIL",
            severity: "high",
            summary:
              "Recreated real-world postinstall exfiltration attack shape.",
            references: [],
          },
        ],
      },
    });
    expect(report.summary.installAllowed).toBe(false);
    expect(
      report.findings.some((finding) => finding.id.startsWith("osv.")),
    ).toBe(true);
  });

  test("invalid npm signature blocks", async () => {
    const report = await scanFixture("benign-package", {
      npmSignature: {
        status: "unverified",
        message: "Recorded corpus fixture: registry signature did not verify.",
      },
    });
    expect(report.summary.installAllowed).toBe(false);
    expect(
      report.findings.some((finding) => finding.id === "npm.signature.invalid"),
    ).toBe(true);
  });
});
