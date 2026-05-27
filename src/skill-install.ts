import { existsSync } from "node:fs";
import { mkdir } from "node:fs/promises";
import { dirname, join, relative } from "node:path";
import { BUILD_VERSION } from "./buildInfo";
import { findProjectRoot, ROOT, readOption } from "./core";
import { c, style } from "./ui";

export const SCGUARD_AGENTS_BEGIN = "<!-- scguard:agents:BEGIN -->";
export const SCGUARD_AGENTS_END = "<!-- scguard:agents:END -->";

export const SKILL_BUNDLE_DIR = join(
  import.meta.dirname,
  "..",
  "skills",
  "scguard",
);
export const DEFAULT_CURSOR_SKILL_REL =
  ".cursor/skills/supply-chain-guard/SKILL.md";
export function agentIntegrationPath(projectRoot: string) {
  return join(projectRoot, ".scguard", "agent-integration.json");
}

export type AgentIntegrationState = {
  schemaVersion: 1;
  enabled: boolean;
  installedAt: string;
  updatedAt: string;
  agentsMd: string;
  cursorSkillPath?: string;
  scguardVersion: string;
};

export type SkillInstallResult = {
  action: "init" | "on" | "off" | "status";
  agentsMd: string;
  enabled: boolean;
  cursorSkillPath?: string;
  changed: boolean;
  dryRun: boolean;
};

export async function skillCommand(args: string[]) {
  const [sub, ...rest] = args;
  if (!sub || sub === "--help" || sub === "-h") {
    printSkillHelp();
    return;
  }
  if (sub === "install") {
    await skillInstallCommand(rest);
    return;
  }
  throw skillUsageError(
    `Unknown skill subcommand: ${sub}`,
    "scguard skill install init",
  );
}

export async function skillInstallCommand(args: string[]) {
  const [action, ...rest] = args;
  if (!action || action === "--help" || action === "-h") {
    printSkillInstallHelp();
    return;
  }
  if (
    action === "init" ||
    action === "on" ||
    action === "off" ||
    action === "status"
  ) {
    const result = await runSkillInstallAction(action, rest);
    printSkillInstallResult(result, rest.includes("--json"));
    return;
  }
  throw skillUsageError(
    `Unknown skill install action: ${action}`,
    "scguard skill install init",
  );
}

export async function runSkillInstallAction(
  action: SkillInstallResult["action"],
  args: string[],
): Promise<SkillInstallResult> {
  const dryRun = args.includes("--dry-run");
  const projectRoot =
    readOption(args, "--project") ?? findProjectRoot(process.cwd());
  const agentsMd = resolveAgentsMdPath(
    projectRoot,
    readOption(args, "--agents-md"),
  );
  const installSkill = !args.includes("--no-skill");
  const cursorSkillRel =
    readOption(args, "--skill-path") ?? DEFAULT_CURSOR_SKILL_REL;
  const cursorSkillPath = join(projectRoot, cursorSkillRel);

  if (action === "status") {
    const state = await readAgentIntegrationState(projectRoot);
    const enabled =
      state?.enabled ??
      detectEnabledFromAgentsMd(await readAgentsFile(agentsMd));
    return {
      action,
      agentsMd,
      enabled,
      cursorSkillPath: existsSync(cursorSkillPath)
        ? cursorSkillPath
        : undefined,
      changed: false,
      dryRun,
    };
  }

  const enabled = action !== "off";
  const templateName =
    action === "off" ? "off" : action === "on" ? "on" : "init";
  const body = await loadSubcommandTemplate(templateName);
  const nextContent = upsertAgentsBlock(await readAgentsFile(agentsMd), body);
  const changed = nextContent !== (await readAgentsFile(agentsMd));

  if (!dryRun && changed) {
    await mkdir(dirname(agentsMd), { recursive: true });
    await Bun.write(agentsMd, nextContent);
  }

  let skillCopied = false;
  if (installSkill && (action === "init" || action === "on") && !dryRun) {
    skillCopied = await installCursorSkill(cursorSkillPath);
  }

  const now = new Date().toISOString();
  const prev = await readAgentIntegrationState(projectRoot);
  const state: AgentIntegrationState = {
    schemaVersion: 1,
    enabled,
    installedAt: prev?.installedAt ?? now,
    updatedAt: now,
    agentsMd: relative(projectRoot, agentsMd) || "AGENTS.md",
    cursorSkillPath:
      skillCopied || existsSync(cursorSkillPath)
        ? cursorSkillRel
        : prev?.cursorSkillPath,
    scguardVersion: BUILD_VERSION,
  };

  if (!dryRun) {
    const integrationPath = agentIntegrationPath(projectRoot);
    await mkdir(dirname(integrationPath), { recursive: true });
    await Bun.write(integrationPath, `${JSON.stringify(state, null, 2)}\n`);
  }

  return {
    action,
    agentsMd,
    enabled,
    cursorSkillPath: existsSync(cursorSkillPath) ? cursorSkillPath : undefined,
    changed: changed || skillCopied,
    dryRun,
  };
}

export function resolveAgentsMdPath(projectRoot: string, explicit?: string) {
  if (explicit) return join(projectRoot, explicit);
  const candidates = ["AGENTS.md", "agents.md", join(".cursor", "AGENTS.md")];
  for (const rel of candidates) {
    const path = join(projectRoot, rel);
    if (existsSync(path)) return path;
  }
  return join(projectRoot, "AGENTS.md");
}

export async function readAgentsFile(path: string): Promise<string> {
  try {
    return await Bun.file(path).text();
  } catch {
    return "";
  }
}

export function upsertAgentsBlock(content: string, body: string) {
  const block = formatAgentsBlock(body.trim());
  const begin = content.indexOf(SCGUARD_AGENTS_BEGIN);
  const end = content.indexOf(SCGUARD_AGENTS_END);
  if (begin !== -1 && end !== -1 && end > begin) {
    const before = content.slice(0, begin);
    const after = content.slice(end + SCGUARD_AGENTS_END.length);
    return `${before}${block}${after}`.replace(/\n{3,}/g, "\n\n");
  }
  const trimmed = content.trimEnd();
  const prefix = trimmed.length > 0 ? `${trimmed}\n\n` : "";
  return `${prefix}${block}\n`;
}

export function formatAgentsBlock(body: string) {
  return `${SCGUARD_AGENTS_BEGIN}\n${body}\n${SCGUARD_AGENTS_END}`;
}

export function detectEnabledFromAgentsMd(content: string) {
  if (!content.includes(SCGUARD_AGENTS_BEGIN)) return false;
  return !content.includes("Supply Chain Guard is temporarily disabled");
}

export async function loadSubcommandTemplate(name: string) {
  const path = join(SKILL_BUNDLE_DIR, "subcommands", `${name}.md`);
  try {
    return await Bun.file(path).text();
  } catch {
    throw new Error(`Missing skill template: ${path}`);
  }
}

export async function installCursorSkill(destPath: string) {
  const source = join(SKILL_BUNDLE_DIR, "SKILL.md");
  const next = await Bun.file(source).text();
  const prev = await readAgentsFile(destPath);
  if (prev === next) return false;
  await mkdir(dirname(destPath), { recursive: true });
  await Bun.write(destPath, next);
  return true;
}

export async function readAgentIntegrationState(
  projectRoot: string,
): Promise<AgentIntegrationState | null> {
  try {
    return (await Bun.file(
      agentIntegrationPath(projectRoot),
    ).json()) as AgentIntegrationState;
  } catch {
    return null;
  }
}

function printSkillHelp() {
  console.log(
    `${c.amber("scguard skill", true)} — install agent instructions for this project`,
  );
  console.log("");
  console.log(c.gray("Subcommands:"));
  console.log(
    `  ${c.white("install", true)}   Manage AGENTS.md blocks and optional Cursor skill files`,
  );
  console.log("");
  console.log(c.amber("Examples:", true));
  console.log(`  ${c.blue("scguard skill install init")}`);
  console.log(`  ${c.blue("scguard skill install status --json")}`);
  console.log(`  ${c.blue("scguard skill install --help")}`);
}

function printSkillInstallHelp() {
  console.log(
    `${c.amber("scguard skill install", true)} — agent integration for Codex, Cursor, Pi, and others`,
  );
  console.log("");
  console.log(c.gray("Actions:"));
  console.log(
    `  ${c.white("init", true)}     Append scguard rules to AGENTS.md and install .cursor/skills/supply-chain-guard/SKILL.md`,
  );
  console.log(
    `  ${c.white("on", true)}       Re-enable scguard instructions in AGENTS.md`,
  );
  console.log(
    `  ${c.white("off", true)}      Temporarily disable scguard instructions (agents ignore routing rules)`,
  );
  console.log(
    `  ${c.white("status", true)}   Show whether integration is active`,
  );
  console.log("");
  console.log(c.gray("Options:"));
  console.log(
    `  ${c.amber("--agents-md".padEnd(16), true)} ${c.gray("Path to AGENTS.md (default: AGENTS.md in project root)")}`,
  );
  console.log(
    `  ${c.amber("--project".padEnd(16), true)} ${c.gray("Project root (default: detected from cwd)")}`,
  );
  console.log(
    `  ${c.amber("--skill-path".padEnd(16), true)} ${c.gray(`Cursor skill destination (default: ${DEFAULT_CURSOR_SKILL_REL})`)}`,
  );
  console.log(
    `  ${c.amber("--no-skill".padEnd(16), true)} ${c.gray("Skip copying SKILL.md (AGENTS.md only)")}`,
  );
  console.log(
    `  ${c.amber("--dry-run".padEnd(16), true)} ${c.gray("Print planned changes without writing files")}`,
  );
  console.log(
    `  ${c.amber("--json".padEnd(16), true)} ${c.gray("Machine-readable result on status and mutations")}`,
  );
  console.log("");
  console.log(c.amber("Examples:", true));
  console.log(`  ${c.blue("scguard skill install init")}`);
  console.log(
    `  ${c.blue("scguard skill install init --agents-md .cursor/AGENTS.md")}`,
  );
  console.log(`  ${c.blue("scguard skill install off --dry-run")}`);
  console.log(`  ${c.blue("scguard skill install on")}`);
  console.log(`  ${c.blue("scguard skill install status --json")}`);
}

function printSkillInstallResult(
  result: SkillInstallResult,
  jsonMode: boolean,
) {
  if (jsonMode) {
    console.log(JSON.stringify(result, null, 2));
    return;
  }
  if (result.action === "status") {
    const state = result.enabled
      ? c.green("enabled", true)
      : c.red("disabled", true);
    console.log(`${style.check()} scguard agent integration: ${state}`);
    console.log(`  ${c.gray("agents_md:")} ${c.white(result.agentsMd)}`);
    if (result.cursorSkillPath) {
      console.log(
        `  ${c.gray("cursor_skill:")} ${c.white(result.cursorSkillPath)}`,
      );
    }
    return;
  }
  const verb = result.dryRun
    ? "would update"
    : result.changed
      ? "updated"
      : "unchanged";
  console.log(
    `${style.check()} ${c.green(verb, true)} ${c.gray("(")}${result.action}${c.gray(")")} ${c.white(relative(ROOT, result.agentsMd) || result.agentsMd)}`,
  );
  if (result.cursorSkillPath) {
    console.log(
      `  ${c.gray("cursor_skill:")} ${c.white(relative(ROOT, result.cursorSkillPath) || result.cursorSkillPath)}`,
    );
  }
  console.log(
    `  ${c.gray("state:")} ${result.enabled ? c.green("enabled", true) : c.amber("disabled", true)}`,
  );
}

function skillUsageError(message: string, example: string) {
  return new Error(`${message}\n  ${example}`);
}
