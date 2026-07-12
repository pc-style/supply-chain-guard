import type { PackageManager } from "./pm";

export function installCommandFromOriginalArgs(
  pm: PackageManager,
  args: string[],
) {
  const passthrough: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "--agent" || arg === "--pm") {
      i++;
      continue;
    }
    if (
      arg.startsWith("--agent=") ||
      arg.startsWith("--pm=") ||
      arg === "--json" ||
      arg === "--offline"
    ) {
      continue;
    }
    passthrough.push(arg);
  }
  const installArgs =
    pm === "npm" || pm === "pnpm"
      ? passthrough.map((arg) => (arg === "--dev" ? "--save-dev" : arg))
      : passthrough;
  return {
    cmd: pm,
    args: [pm === "npm" ? "install" : "add", ...installArgs],
  };
}
