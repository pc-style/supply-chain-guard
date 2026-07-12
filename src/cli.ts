#!/usr/bin/env bun
import { resolve } from "node:path";
import { scanNpm, scanVsix } from "./analysis";
import { BUILD_COMMIT, BUILD_VERSION } from "./buildInfo";
import {
  cleanCommand,
  configCommand,
  doctorCommand,
  guardCommand,
  reviewOrInstall,
  scanLockfileCommand,
  selfTest,
  shellHook,
} from "./commands";
import { ensureDirs, requireArg } from "./core";
import { isOfflineMode } from "./offline";
import { emitReport, maybeRunConfiguredAgentReview } from "./reporting";
import { skillCommand } from "./skill-install";
import { banner, c, style } from "./ui";

async function main() {
  const cliArgs = normalizeArgv(Bun.argv);
  const [cmd, ...args] = cliArgs;
  await ensureDirs();

  const SILENT_CMDS = new Set([
    "shell-hook",
    "doctor",
    "--help",
    "-h",
    "--version",
    "-v",
    "version",
    "self-test",
    "skill",
  ]);
  if (!Bun.env.SCGUARD_SHELL_HOOK_ACTIVE && cmd && !SILENT_CMDS.has(cmd)) {
    process.stderr.write(
      `${c.amber("scguard:", true)} ${c.dim("shell hook not active — package manager commands are unguarded.")}\n` +
        `         ${c.dim('Run: eval "$(scguard shell-hook)"   or add it to your shell profile.')}\n`,
    );
  }

  if (!cmd || cmd === "--help" || cmd === "-h") {
    await help();
    return;
  }

  if (cmd === "--version" || cmd === "-v" || cmd === "version") {
    console.log(formatVersion());
    return;
  }

  if (cmd === "scan-npm") {
    const target = requireArg(args[0], "scan-npm requires a package spec");
    const offline = isOfflineMode(args);
    const report = await scanNpm(target, { offline });
    const reportPath = await emitReport(report, args.includes("--json"));
    await maybeRunConfiguredAgentReview(
      report,
      reportPath,
      args,
      args.includes("--json"),
    );
    return;
  }

  if (cmd === "review") {
    await reviewOrInstall(args, { install: false });
    return;
  }

  if (cmd === "install") {
    await reviewOrInstall(args, { install: true });
    return;
  }

  if (cmd === "doctor") {
    await doctorCommand();
    return;
  }

  if (cmd === "clean") {
    await cleanCommand(args);
    return;
  }

  if (cmd === "scan-lockfile") {
    const summary = await scanLockfileCommand(args);
    if (summary.blockInstall) process.exit(2);
    return;
  }

  if (cmd === "scan-vsix") {
    const file = requireArg(args[0], "scan-vsix requires a .vsix path");
    const report = await scanVsix(resolve(file));
    const reportPath = await emitReport(report, args.includes("--json"));
    await maybeRunConfiguredAgentReview(
      report,
      reportPath,
      args,
      args.includes("--json"),
    );
    return;
  }

  if (cmd === "guard") {
    await guardCommand(args);
    return;
  }

  if (cmd === "shell-hook") {
    const fish = args.includes("--fish");
    console.log(shellHook(fish ? "fish" : "bash"));
    return;
  }

  if (cmd === "config") {
    await configCommand(args);
    return;
  }

  if (cmd === "self-test") {
    await selfTest();
    return;
  }

  if (cmd === "skill") {
    await skillCommand(args);
    return;
  }

  throw new Error(`Unknown command: ${cmd}`);
}

function formatVersion() {
  return BUILD_COMMIT === "dev"
    ? BUILD_VERSION
    : `${BUILD_VERSION} (${BUILD_COMMIT})`;
}

function normalizeArgv(argv: string[]) {
  const raw = argv.slice(1);
  const first = raw[0] ?? "";
  if (
    first.endsWith("src/cli.ts") ||
    first.endsWith("/scguard") ||
    first.endsWith("\\scguard")
  ) {
    return raw.slice(1);
  }
  return raw;
}

async function help() {
  console.log(banner(formatVersion()));
  console.log(
    `${c.red("EARLY STAGE:", true)} ${c.gray("A warning layer, not proof that a package is safe.")}`,
  );
  section("Commands");
  item("review", "<package> [--agent codex|pi] [--offline]");
  item("install", "<package> [--pm bun|npm|pnpm|yarn] [install options]");
  item("guard", "bun|npm|pnpm|yarn|code <args...>");
  item("shell-hook", "[--fish]");
  item("scan-vsix", "<extension.vsix> [--json]");
  item("doctor", "");
  item("config", "[--show] [--preset default|strict] [--agent none|codex|pi]");
  item("self-test", "");
  item("clean", "--reports|--cache|--work|--all");
  item("skill install", "[--dry-run] [--skill-source <source>]");

  section("Environment");
  env("SCGUARD_BYPASS=1", "Skip the guard for a single command.");
  env(
    "SOCKET_API_KEY + SOCKET_ORG_SLUG",
    "Enable Socket.dev PURL intelligence.",
  );
  env("SCGUARD_OFFLINE=1", "Disable all network calls (same as --offline).");
  env("SCGUARD_DEBUG=1", "Print diagnostic details.");
  env("SCGUARD_NO_COLOR=1", "Disable ANSI colors (NO_COLOR also works).");
}

function section(title: string) {
  console.log("");
  console.log(c.amber(title, true));
}

function item(cmd: string, sig: string) {
  console.log(
    `  ${style.prompt()} ${c.white(`scguard ${cmd}`, true)}${sig ? ` ${c.blue(sig)}` : ""}`,
  );
}

function env(key: string, detail: string) {
  console.log(`  ${c.amber(key.padEnd(28), true)} ${c.gray(detail)}`);
}

main().catch((error) => {
  const msg = error instanceof Error ? error.message : String(error);
  console.error(`${style.blocked("error:")} ${c.white(msg)}`);
  process.exit(1);
});
