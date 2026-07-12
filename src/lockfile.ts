import { existsSync } from "node:fs";
import { join } from "node:path";

export type LockfileKind = "npm" | "bun" | "pnpm" | "yarn";

export interface LockfileEntry {
  name: string;
  version: string;
  /** Exact tarball URL pinned in the lockfile (npm package-lock, etc.). */
  resolved?: string;
  /** Subresource integrity from the lockfile (e.g. sha512-...). */
  integrity?: string;
}

export interface DetectedLockfile {
  kind: LockfileKind;
  path: string;
}

const LOCKFILES: Array<{ file: string; kind: LockfileKind }> = [
  { file: "bun.lock", kind: "bun" },
  { file: "package-lock.json", kind: "npm" },
  { file: "npm-shrinkwrap.json", kind: "npm" },
  { file: "pnpm-lock.yaml", kind: "pnpm" },
  { file: "yarn.lock", kind: "yarn" },
];

export function detectLockfile(dir: string): DetectedLockfile | null {
  for (const { file, kind } of LOCKFILES) {
    const path = join(dir, file);
    if (existsSync(path)) return { kind, path };
  }
  return null;
}

export async function parseLockfile(
  detected: DetectedLockfile,
): Promise<LockfileEntry[]> {
  const text = await Bun.file(detected.path).text();
  switch (detected.kind) {
    case "npm":
      return parseNpm(text);
    case "bun":
      return parseBun(text);
    case "pnpm":
      return parsePnpm(text);
    case "yarn":
      return parseYarn(text);
  }
}

function dedupe(entries: LockfileEntry[]): LockfileEntry[] {
  const seen = new Map<string, LockfileEntry>();
  for (const e of entries) {
    if (!e.name || !e.version) continue;
    if (
      e.name.startsWith(".") ||
      e.version.startsWith("file:") ||
      e.version.startsWith("link:") ||
      e.version.startsWith("workspace:")
    )
      continue;
    const key = `${e.name}@${e.version}`;
    const existing = seen.get(key);
    if (!existing) {
      seen.set(key, {
        name: e.name,
        version: e.version,
        ...(e.resolved ? { resolved: e.resolved } : {}),
        ...(e.integrity ? { integrity: e.integrity } : {}),
      });
      continue;
    }
    if (!existing.resolved && e.resolved) existing.resolved = e.resolved;
    if (!existing.integrity && e.integrity) existing.integrity = e.integrity;
  }
  return [...seen.values()].sort((a, b) => {
    const ka = `${a.name}@${a.version}`;
    const kb = `${b.name}@${b.version}`;
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  });
}

// ── npm: package-lock.json / npm-shrinkwrap.json ──────────────────────────
// lockfileVersion 2+ uses a `packages` map keyed by node_modules path.
// lockfileVersion 1 uses a nested `dependencies` tree.
export function parseNpm(text: string): LockfileEntry[] {
  const data = JSON.parse(text) as Record<string, unknown>;
  const out: LockfileEntry[] = [];
  const packages = data.packages as
    | Record<
        string,
        {
          name?: string;
          version?: string;
          resolved?: string;
          integrity?: string;
          link?: boolean;
        }
      >
    | undefined;
  if (packages) {
    for (const [path, info] of Object.entries(packages)) {
      if (!path || path === "" || info?.link) continue;
      const version = info?.version;
      if (!version) continue;
      const name =
        info.name ??
        nameFromNpmAliasResolved(info.resolved) ??
        nameFromNodeModulesPath(path);
      if (!name) continue;
      out.push({
        name,
        version,
        ...(isFetchUrl(info.resolved) ? { resolved: info.resolved } : {}),
        ...(typeof info.integrity === "string"
          ? { integrity: info.integrity }
          : {}),
      });
    }
  }
  const deps = data.dependencies as
    | Record<
        string,
        {
          version?: string;
          resolved?: string;
          integrity?: string;
          dependencies?: Record<
            string,
            {
              version?: string;
              resolved?: string;
              integrity?: string;
              dependencies?: unknown;
            }
          >;
        }
      >
    | undefined;
  if (deps) walkNpmV1(deps, out);
  return dedupe(out);
}

function nameFromNodeModulesPath(path: string): string | null {
  const idx = path.lastIndexOf("node_modules/");
  if (idx < 0) return null;
  return path.slice(idx + "node_modules/".length);
}

function parseNpmAliasSpec(value: unknown): LockfileEntry | null {
  if (typeof value !== "string" || !value.startsWith("npm:")) return null;
  const spec = value.slice("npm:".length);
  const at = spec.lastIndexOf("@");
  if (at <= 0) return null;
  const name = spec.slice(0, at);
  const version = spec.slice(at + 1);
  if (!name || !version || !isValidVersion(version)) return null;
  return { name, version };
}

function nameFromNpmAliasResolved(resolved: unknown): string | null {
  return parseNpmAliasSpec(resolved)?.name ?? null;
}

function walkNpmV1(
  deps: Record<
    string,
    {
      version?: string;
      resolved?: string;
      integrity?: string;
      dependencies?: Record<string, unknown>;
    }
  >,
  out: LockfileEntry[],
) {
  for (const [name, info] of Object.entries(deps)) {
    if (info?.version) {
      const alias = parseNpmAliasSpec(info.version);
      out.push({
        name: alias?.name ?? name,
        version: alias?.version ?? info.version,
        ...(isFetchUrl(info.resolved) ? { resolved: info.resolved } : {}),
        ...(typeof info.integrity === "string"
          ? { integrity: info.integrity }
          : {}),
      });
    }
    if (info?.dependencies && typeof info.dependencies === "object") {
      walkNpmV1(info.dependencies as typeof deps, out);
    }
  }
}

// ── bun.lock (text format, lockfileVersion 0/1) ───────────────────────────
// Each entry in `packages` is keyed by package name and the value is an array
// whose first element is `"name@version"`.
export function parseBun(text: string): LockfileEntry[] {
  const out: LockfileEntry[] = [];
  const packagesIdx = text.indexOf('"packages":');
  if (packagesIdx < 0) return out;
  const rest = text.slice(packagesIdx);
  // Match: "anything": [ "name@version", ...
  const re =
    /"([^"\n]+)"\s*:\s*\[\s*"((?:@[^@"/]+\/)?[^@"/]+)@([^"\]]+)"(?:\s*,\s*"([^"]*)")?/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(rest))) {
    const name = m[2];
    const version = m[3];
    if (!isValidVersion(version)) continue;
    const lineEnd = rest.indexOf("\n", re.lastIndex);
    const entryTail = rest.slice(
      re.lastIndex,
      lineEnd < 0 ? rest.length : lineEnd,
    );
    const integrity = entryTail.match(/"(sha(?:256|384|512)-[^"]+)"/)?.[1];
    out.push({
      name,
      version,
      ...(isFetchUrl(m[4]) ? { resolved: m[4] } : {}),
      ...(integrity ? { integrity } : {}),
    });
  }
  return dedupe(out);
}

// ── pnpm-lock.yaml ────────────────────────────────────────────────────────
// `packages:` block with keys like `/@scope/name@1.0.0:` (v5/v6) or
// `name@1.0.0:` (v9+). Skip workspace/file/link entries.
export function parsePnpm(text: string): LockfileEntry[] {
  const out: LockfileEntry[] = [];
  const lines = text.split("\n");
  let inPackages = false;
  let current: LockfileEntry | undefined;
  for (const rawLine of lines) {
    if (/^[a-zA-Z]/.test(rawLine)) {
      inPackages = rawLine.startsWith("packages:");
      current = undefined;
      continue;
    }
    if (!inPackages) continue;
    const m = rawLine.match(
      /^\s{2}'?\/?((?:@[^@/]+\/)?[^@/]+)@([^:'\s]+)'?:\s*$/,
    );
    if (m) {
      const version = m[2];
      if (!isValidVersion(version)) continue;
      current = { name: m[1], version };
      out.push(current);
      continue;
    }
    if (!current) continue;
    const integrity = rawLine.match(/integrity:\s*['"]?([^,'"}\s]+)/)?.[1];
    const tarball = rawLine.match(/tarball:\s*['"]?([^,'"}\s]+)/)?.[1];
    if (integrity) current.integrity = integrity;
    if (isFetchUrl(tarball)) current.resolved = tarball;
  }
  return dedupe(out);
}

// ── yarn.lock (v1 classic + berry) ────────────────────────────────────────
// Entries start at column 0 with one or more comma-separated specs, then a
// `version "x.y.z"` (v1) or `version: x.y.z` (berry) line in the block.
export function parseYarn(text: string): LockfileEntry[] {
  const out: LockfileEntry[] = [];
  const blocks = text.split(/\n(?=\S)/);
  for (const block of blocks) {
    const firstLine = block.split("\n")[0];
    if (
      !firstLine ||
      firstLine.startsWith("#") ||
      firstLine.startsWith("__metadata")
    )
      continue;
    if (!firstLine.includes("@") || !firstLine.endsWith(":")) continue;
    const header = firstLine.slice(0, -1);
    const firstSpec = header
      .split(",")[0]
      .trim()
      .replace(/^"(.*)"$/, "$1");
    const at = firstSpec.lastIndexOf("@");
    if (at <= 0) continue;
    const name = firstSpec.slice(0, at);
    const range = firstSpec.slice(at + 1);
    // Skip non-npm protocols (workspace:, file:, link:, git*, http*, npm:scope/x@...).
    if (/^(workspace|file|link|git|github|https?|patch)[:+]/i.test(range))
      continue;
    const versionMatch = block.match(/\n\s+version[:\s]+"?([^"\n]+)"?/);
    if (!versionMatch) continue;
    const version = versionMatch[1].trim().replace(/^"|"$/g, "");
    if (!isValidVersion(version)) continue;
    const resolved = block
      .match(/\n\s+resolved[:\s]+"?([^"\n]+)"?/)?.[1]
      ?.trim();
    const integrity = block
      .match(/\n\s+integrity[:\s]+"?([^"\n]+)"?/)?.[1]
      ?.trim();
    out.push({
      name,
      version,
      ...(isFetchUrl(resolved) ? { resolved } : {}),
      ...(integrity ? { integrity } : {}),
    });
  }
  return dedupe(out);
}

function isFetchUrl(value: unknown): value is string {
  if (typeof value !== "string") return false;
  try {
    const url = new URL(value);
    return url.protocol === "https:" || url.protocol === "http:";
  } catch {
    return false;
  }
}

function isValidVersion(v: string): boolean {
  // Reject workspace, file, link, git, http protocols — we can only fetch real npm tarballs.
  if (!v) return false;
  if (/^(workspace|file|link|git|github|https?|npm):/i.test(v)) return false;
  return /^\d+\.\d+\.\d+/.test(v);
}
