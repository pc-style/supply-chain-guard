import { afterEach, describe, expect, test } from "bun:test";
import { existsSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  detectEnabledFromAgentsMd,
  formatAgentsBlock,
  resolveAgentsMdPath,
  runSkillInstallAction,
  SCGUARD_AGENTS_BEGIN,
  SCGUARD_AGENTS_END,
  upsertAgentsBlock,
} from "./skill-install";

describe("skill install", () => {
  const dirs: string[] = [];

  afterEach(async () => {
    await Promise.all(
      dirs.map((dir) => rm(dir, { recursive: true, force: true })),
    );
    dirs.length = 0;
  });

  async function tempProject() {
    const dir = await mkdtemp(join(tmpdir(), "scguard-skill-"));
    dirs.push(dir);
    return dir;
  }

  test("upsertAgentsBlock appends a new managed section", () => {
    const next = upsertAgentsBlock(
      "# My project\n",
      "route installs through scguard",
    );
    expect(next).toContain(SCGUARD_AGENTS_BEGIN);
    expect(next).toContain("route installs through scguard");
    expect(next).toContain(SCGUARD_AGENTS_END);
  });

  test("upsertAgentsBlock replaces an existing managed section", () => {
    const initial = `# App\n\n${formatAgentsBlock("old rules")}\n`;
    const next = upsertAgentsBlock(initial, "new rules");
    expect(next.match(/scguard:agents:BEGIN/g)?.length).toBe(1);
    expect(next).toContain("new rules");
    expect(next).not.toContain("old rules");
  });

  test("detectEnabledFromAgentsMd respects disabled banner", () => {
    const enabled = formatAgentsBlock("always use scguard");
    const disabled = formatAgentsBlock(
      "> **Supply Chain Guard is temporarily disabled in this project.**",
    );
    expect(detectEnabledFromAgentsMd(enabled)).toBe(true);
    expect(detectEnabledFromAgentsMd(disabled)).toBe(false);
  });

  test("resolveAgentsMdPath prefers existing AGENTS.md", async () => {
    const root = await tempProject();
    const agents = join(root, "AGENTS.md");
    await Bun.write(agents, "# agents\n");
    expect(resolveAgentsMdPath(root)).toBe(agents);
  });

  test("init writes AGENTS.md and cursor skill", async () => {
    const root = await tempProject();
    const result = await runSkillInstallAction("init", [
      "--project",
      root,
      "--no-skill",
    ]);
    expect(result.changed).toBe(true);
    expect(result.enabled).toBe(true);
    const agents = await Bun.file(result.agentsMd).text();
    expect(agents).toContain("Never");
    expect(agents).toContain(SCGUARD_AGENTS_BEGIN);
  });

  test("off and on toggle disabled banner", async () => {
    const root = await tempProject();
    await runSkillInstallAction("init", ["--project", root, "--no-skill"]);
    await runSkillInstallAction("off", ["--project", root, "--no-skill"]);
    let agents = await Bun.file(resolveAgentsMdPath(root)).text();
    expect(agents).toContain("temporarily disabled");
    expect(detectEnabledFromAgentsMd(agents)).toBe(false);

    await runSkillInstallAction("on", ["--project", root, "--no-skill"]);
    agents = await Bun.file(resolveAgentsMdPath(root)).text();
    expect(agents).not.toContain("temporarily disabled");
    expect(detectEnabledFromAgentsMd(agents)).toBe(true);
  });

  test("dry-run does not write files", async () => {
    const root = await tempProject();
    const agentsPath = resolveAgentsMdPath(root);
    const result = await runSkillInstallAction("init", [
      "--project",
      root,
      "--dry-run",
      "--no-skill",
    ]);
    expect(result.dryRun).toBe(true);
    expect(result.changed).toBe(true);
    expect(existsSync(agentsPath)).toBe(false);
  });
});
