import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

export type PackageManager = "bun" | "npm" | "pnpm" | "yarn";

export type DetectedPm = {
  pm: PackageManager;
  source: "flag" | "lockfile" | "packageManager" | "default";
  detail: string;
};

const PM_VALUES: PackageManager[] = ["bun", "npm", "pnpm", "yarn"];

export function isPackageManager(value: string | undefined): value is PackageManager {
  return !!value && PM_VALUES.includes(value as PackageManager);
}

/**
 * Read the value for a `--pm` flag from a list of CLI args.
 * Supports `--pm npm` and `--pm=npm`.
 */
export function readPmFlag(args: string[]): string | undefined {
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "--pm") return args[i + 1];
    if (arg.startsWith("--pm=")) return arg.slice("--pm=".length);
  }
  return undefined;
}

/**
 * Detect which package manager a project uses.
 * Order: explicit `--pm` flag > lockfile > package.json `packageManager` > default `bun`.
 */
export function detectPackageManager(rootDir: string, args: string[] = []): DetectedPm {
  const flag = readPmFlag(args);
  if (flag) {
    if (!isPackageManager(flag)) {
      throw new Error(`Unknown --pm value: ${flag}. Expected one of: ${PM_VALUES.join(", ")}`);
    }
    return { pm: flag, source: "flag", detail: `--pm ${flag}` };
  }

  if (existsSync(join(rootDir, "bun.lock")) || existsSync(join(rootDir, "bun.lockb"))) {
    return { pm: "bun", source: "lockfile", detail: "bun.lock(b)" };
  }
  if (existsSync(join(rootDir, "pnpm-lock.yaml"))) {
    return { pm: "pnpm", source: "lockfile", detail: "pnpm-lock.yaml" };
  }
  if (existsSync(join(rootDir, "yarn.lock"))) {
    return { pm: "yarn", source: "lockfile", detail: "yarn.lock" };
  }
  if (existsSync(join(rootDir, "package-lock.json"))) {
    return { pm: "npm", source: "lockfile", detail: "package-lock.json" };
  }

  const pkgPath = join(rootDir, "package.json");
  if (existsSync(pkgPath)) {
    try {
      const raw = readFileSync(pkgPath, "utf8");
      const pkg = JSON.parse(raw) as { packageManager?: unknown };
      if (typeof pkg.packageManager === "string") {
        const name = pkg.packageManager.split("@")[0];
        if (isPackageManager(name)) {
          return { pm: name, source: "packageManager", detail: `package.json packageManager=${pkg.packageManager}` };
        }
      }
    } catch {
      // ignore malformed package.json; fall through to default
    }
  }

  return { pm: "bun", source: "default", detail: "no lockfile or packageManager field detected" };
}

/**
 * Build the install command for a package manager.
 * Returns `{ cmd, args }` suitable for `Bun.spawn` / `run()`.
 */
export function buildInstallCommand(pm: PackageManager, specs: string[], opts: { dev?: boolean } = {}): {
  cmd: string;
  args: string[];
} {
  switch (pm) {
    case "bun":
      return { cmd: "bun", args: ["add", ...(opts.dev ? ["--dev"] : []), ...specs] };
    case "npm":
      return { cmd: "npm", args: ["install", ...(opts.dev ? ["--save-dev"] : []), ...specs] };
    case "pnpm":
      return { cmd: "pnpm", args: ["add", ...(opts.dev ? ["--save-dev"] : []), ...specs] };
    case "yarn":
      return { cmd: "yarn", args: ["add", ...(opts.dev ? ["--dev"] : []), ...specs] };
  }
}
