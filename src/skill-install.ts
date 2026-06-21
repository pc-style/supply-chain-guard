import { readOption } from "./core";
import { c, style } from "./ui";

export const DEFAULT_SKILL_SOURCE = "pc-style/supply-chain-guard";
export const DEFAULT_SKILL_NAME = "supply-chain-guard";

export function buildSkillsInstallCommand(
  source = DEFAULT_SKILL_SOURCE,
  skillName = DEFAULT_SKILL_NAME,
) {
  return [
    "npx",
    "--yes",
    "--package",
    "skills@latest",
    "skills",
    "add",
    source,
    "-y",
    "--skill",
    skillName,
  ] as const;
}

export async function skillCommand(args: string[]) {
  const [sub, ...rest] = args;

  if (sub === "install") {
    if (rest.includes("--help") || rest.includes("-h")) {
      printSkillInstallHelp();
      return;
    }
    await runSkillInstall(rest);
    return;
  }

  if (sub && sub !== "--help" && sub !== "-h") {
    throw new Error(
      `Unknown skill subcommand: ${sub}\n  scguard skill install`,
    );
  }

  printSkillHelp();
}

export async function runSkillInstall(args: string[]) {
  const dryRun = args.includes("--dry-run");
  readOption(args, "--project");
  const installCwd = skillInstallCwd();
  const source = readOption(args, "--skill-source") ?? DEFAULT_SKILL_SOURCE;
  const command = buildSkillsInstallCommand(source).join(" ");

  if (dryRun) {
    console.log(`${style.check()} would run: ${c.white(command)}`);
    return;
  }

  const proc = Bun.spawn([...buildSkillsInstallCommand(source)], {
    cwd: installCwd,
    stdout: "inherit",
    stderr: "inherit",
    env: {
      HOME: process.env.HOME,
      PATH: process.env.PATH,
      USERPROFILE: process.env.USERPROFILE,
      SystemRoot: process.env.SystemRoot,
      TMPDIR: process.env.TMPDIR,
      TEMP: process.env.TEMP,
      TMP: process.env.TMP,
      NO_COLOR: process.env.NO_COLOR,
      FORCE_COLOR: process.env.FORCE_COLOR,
      CI: process.env.CI,
    },
  });
  const exitCode = await proc.exited;
  if (exitCode !== 0) {
    throw new Error(`skill install failed (exit ${exitCode})\n  ${command}`);
  }
  console.log(
    `${style.check()} ${c.green("installed", true)} ${c.white(DEFAULT_SKILL_NAME)} skill`,
  );
}

export function skillInstallCwd(env = process.env) {
  return (
    env.HOME ?? env.USERPROFILE ?? env.TMPDIR ?? env.TEMP ?? env.TMP ?? "/tmp"
  );
}

function printSkillHelp() {
  console.log(
    `${c.amber("scguard skill", true)} — install the supply-chain-guard agent skill`,
  );
  console.log("");
  console.log(c.gray("Subcommands:"));
  console.log(
    `  ${c.white("install", true)}   Run ${c.blue(`npx --yes --package skills@latest skills add ${DEFAULT_SKILL_SOURCE}`)}`,
  );
  console.log("");
  console.log(c.amber("Examples:", true));
  console.log(`  ${c.blue("scguard skill")}`);
  console.log(`  ${c.blue("scguard skill install")}`);
  console.log(`  ${c.blue("scguard skill install --dry-run")}`);
}

function printSkillInstallHelp() {
  console.log(
    `${c.amber("scguard skill install", true)} — install via skills CLI`,
  );
  console.log("");
  console.log(
    `Runs: ${c.blue(`npx --yes --package skills@latest skills add ${DEFAULT_SKILL_SOURCE} -y --skill ${DEFAULT_SKILL_NAME}`)}`,
  );
  console.log("");
  console.log(c.gray("Options:"));
  console.log(
    `  ${c.amber("--project".padEnd(16), true)} ${c.gray("Accepted for compatibility; not used for installer execution")}`,
  );
  console.log(
    `  ${c.amber("--skill-source".padEnd(16), true)} ${c.gray(`Override skill source (default: ${DEFAULT_SKILL_SOURCE})`)}`,
  );
  console.log(
    `  ${c.amber("--dry-run".padEnd(16), true)} ${c.gray("Print the command without running it")}`,
  );
  console.log("");
  console.log(c.amber("Examples:", true));
  console.log(`  ${c.blue("scguard skill install")}`);
  console.log(`  ${c.blue("scguard skill install --dry-run")}`);
}
