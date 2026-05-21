import { existsSync } from "node:fs";
import { mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { ROOT } from "./core";

/**
 * The large-bin fixture intentionally contains a >2 MB JS file so the scanner
 * flags it. We generate it on demand instead of committing megabytes into git.
 */
export async function ensureLargeBinFixture() {
  const file = join(ROOT, "src", "fixtures", "large-bin", "bin", "large.js");
  if (existsSync(file)) return file;
  await mkdir(dirname(file), { recursive: true });
  const header = `#!/usr/bin/env node\n// Generated oversized fixture for Supply Chain Guard.\n`;
  const blob = "x".repeat(2_500_000);
  await Bun.write(file, `${header}module.exports = ${JSON.stringify(blob)};\n`);
  return file;
}
