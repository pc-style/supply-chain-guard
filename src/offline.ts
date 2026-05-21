/**
 * Coordination module for the offline-mode flag.
 *
 * Any code path that performs network I/O must consult `isOfflineMode(args)`
 * (or read the `SCGUARD_OFFLINE` env var directly) before contacting the
 * network. When offline, integrations should degrade gracefully and emit a
 * "skipped: offline" status rather than throwing.
 */

export const OFFLINE_ENV = "SCGUARD_OFFLINE";

export function isOfflineMode(args: string[] = []): boolean {
  return args.includes("--offline") || Bun.env[OFFLINE_ENV] === "1";
}
