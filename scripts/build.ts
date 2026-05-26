#!/usr/bin/env bun
import { mkdir } from "node:fs/promises";
import { dirname } from "node:path";

const buildInfoPath = "src/buildInfo.ts";
const outfile = Bun.env.SCGUARD_BUILD_OUTFILE ?? "dist/scguard";
const pkg = JSON.parse(await Bun.file("package.json").text()) as {
  version?: string;
};
const versionOverride = Bun.env.SCGUARD_BUILD_VERSION?.trim();
const version = normalizeVersion(versionOverride || pkg.version || "0.0.0");
const commit = gitCommit() ?? "dev";
const originalBuildInfo = await Bun.file(buildInfoPath).text();

let exitCode = 0;
try {
  await Bun.write(
    buildInfoPath,
    `export const BUILD_VERSION = ${JSON.stringify(version)};\nexport const BUILD_COMMIT = ${JSON.stringify(commit)};\n`,
  );
  await mkdir(dirname(outfile), { recursive: true });

  const proc = Bun.spawn(
    ["bun", "build", "src/cli.ts", "--compile", "--outfile", outfile],
    {
      stdout: "inherit",
      stderr: "inherit",
    },
  );
  exitCode = await proc.exited;
  if (exitCode === 0) {
    console.log(
      `Built ${outfile} (${version}${commit !== "dev" ? ` ${commit}` : ""})`,
    );
  }
} finally {
  await Bun.write(buildInfoPath, originalBuildInfo);
}

if (exitCode !== 0) process.exit(exitCode);

function normalizeVersion(version: string) {
  return version.replace(/^v/, "");
}

function gitCommit() {
  const result = Bun.spawnSync(["git", "rev-parse", "--short", "HEAD"], {
    stdout: "pipe",
    stderr: "ignore",
  });
  if (result.exitCode !== 0) return null;
  const sha = new TextDecoder().decode(result.stdout).trim();
  return sha || null;
}
