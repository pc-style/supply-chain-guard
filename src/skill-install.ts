import { findProjectRoot, readOption } from "./core";
import { c, style } from "./ui";

export const DEFAULT_SKILL_SOURCE = "pc-style/supply-chain-guard";
export const DEFAULT_SKILL_NAME = "supply-chain-guard";

export function buildSkillsInstallCommand(
  source = DEFAULT_SKILL_SOURCE,
  skillName = DEFAULT_SKILL_NAME,
) {
  return ["npx", "skills", "add", source, "-y", "--skill", skillName] as const;
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
  const projectRoot =
    readOption(args, "--project") ?? findProjectRoot(process.cwd());
  const source = readOption(args, "--skill-source") ?? DEFAULT_SKILL_SOURCE;
  const command = buildSkillsInstallCommand(source).join(" ");

  if (dryRun) {
    console.log(`${style.check()} would run: ${c.white(command)}`);
    return;
  }

  const proc = Bun.spawn([...buildSkillsInstallCommand(source)], {
    cwd: projectRoot,
    stdout: "inherit",
    stderr: "inherit",
    env: process.env,
  });
  const exitCode = await proc.exited;
  if (exitCode !== 0) {
    throw new Error(`skill install failed (exit ${exitCode})\n  ${command}`);
  }
  console.log(
    `${style.check()} ${c.green("installed", true)} ${c.white(DEFAULT_SKILL_NAME)} skill`,
  );
}

function printSkillHelp() {
  console.log(
    `${c.amber("scguard skill", true)} — install the supply-chain-guard agent skill`,
  );
  console.log("");
  console.log(c.gray("Subcommands:"));
  console.log(
    `  ${c.white("install", true)}   Run ${c.blue(`npx skills add ${DEFAULT_SKILL_SOURCE}`)}`,
  );
  console.log("");
  console.log(c.amber("Examples:", true));
  console.log(`  ${c.blue("scguard skill")}`);
  console.log(`  ${c.blue("scguard skill install")}`);
  console.log(`  ${c.blue("scguard skill install --dry-run")}`);
}

function printSkillInstallHelp() {
  console.log(
    `${c.amber("scguard skill install", true)} — install via Vercel skills CLI`,
  );
  console.log("");
  console.log(
    `Runs: ${c.blue(`npx skills add ${DEFAULT_SKILL_SOURCE} -y --skill ${DEFAULT_SKILL_NAME}`)}`,
  );
  console.log("");
  console.log(c.gray("Options:"));
  console.log(
    `  ${c.amber("--project".padEnd(16), true)} ${c.gray("Project root (default: detected from cwd)")}`,
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
