/** Normalize temporary workspace paths for stable demo output. */
export function normalizeDemoWorkspacePath(
  text: string,
  workspace: string,
  displayWorkspace = "./demo",
): string {
  const aliases = new Set([workspace]);

  if (workspace.startsWith("/var/")) {
    aliases.add(`/private${workspace}`);
  } else if (workspace.startsWith("/private/var/")) {
    aliases.add(workspace.slice("/private".length));
  }

  return [...aliases]
    .sort((a, b) => b.length - a.length)
    .reduce(
      (normalized, alias) => normalized.replaceAll(alias, displayWorkspace),
      text,
    );
}
