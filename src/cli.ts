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
  if (Bun.env.SCGUARD_DEBUG_ARGV) {
    console.error(JSON.stringify({ argv: Bun.argv, cliArgs, cmd, args }));
  }
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
  if (
    !Bun.env.SCGUARD_SHELL_HOOK_ACTIVE &&
    !Bun.env.SCGUARD_SUPPRESS_HOOK_WARN &&
    cmd &&
    !SILENT_CMDS.has(cmd)
  ) {
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
    const fish = args.includes("--fish") || Bun.env.SCGUARD_SHELL === "fish";
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
  console.log("");
  console.log(
    `${c.red("WARNING:", true)} ${c.white("Supply Chain Guard is VERY VERY EARLY STAGE.", true)}`,
  );
  console.log(
    c.gray(
      "It can miss malicious packages, flag safe ones, and break package-manager flows. Treat it as a warning layer, not proof of safety.",
    ),
  );
  console.log("");
  section("Common");
  item(
    "scguard review",
    "<package[@version]> [--agent codex|pi] [--offline]",
    "Download, stage, and analyze a package without installing it.",
  );
  item(
    "scguard install",
    "<package[@version]> [--dev] [--pm bun|npm|pnpm|yarn] [--agent codex|pi] [--offline]",
    "Review, then install only after the gate (and any agent review) passes. Direct package installs stay strict even when the app preset is more relaxed.",
  );
  item(
    "scguard scan-vsix",
    "<extension.vsix> [--json]",
    "Analyze a downloaded VS Code extension artifact.",
  );
  item(
    "scguard doctor",
    "",
    "Check dependencies, PATH, shell hook, Socket token, and agent CLIs.",
  );
  item(
    "scguard clean",
    "[--reports] [--cache] [--work] [--all]",
    "Remove cached artifacts, working dirs, or report history.",
  );
  item(
    "scguard config",
    "[--show] [--preset default|strict] [--agent none|codex|pi]",
    "Set the default policy preset and agent-review policy.",
  );

  section("Setup");
  item(
    "scguard shell-hook",
    "[--fish]",
    "Print shell functions that route bun/npm/pnpm/yarn/code through scguard (use --fish for fish shell).",
  );
  item(
    "scguard skill install",
    "[--dry-run] [--skill-source pc-style/supply-chain-guard]",
    "Run npx skills add pc-style/supply-chain-guard for Codex, Cursor, Pi, and other agents.",
  );
  item("scguard version", "", "Print the installed version.");

  section("Advanced");
  item(
    "scguard scan-lockfile",
    "[dir]",
    "Scan lockfile packages using the active preset policy. Used by the shell hook for bare 'install'.",
  );
  item(
    "scguard scan-npm",
    "<package[@version]> [--json]",
    "Scan a published npm package directly.",
  );
  item(
    "scguard guard",
    "bun|npm|pnpm|yarn|code <args...>",
    "Wrap a package-manager command behind the gate.",
  );
  item("scguard self-test", "", "Validate analysis on the bundled fixture.");

  section("Environment");
  env("SCGUARD_BYPASS=1", "Skip the guard for a single command.");
  env(
    "SOCKET_API_KEY",
    "Enable Socket.dev intelligence when SOCKET_ORG_SLUG is also set.",
  );
  env("SOCKET_ORG_SLUG", "Required org slug for Socket PURL intelligence.");
  env("SCGUARD_OFFLINE=1", "Disable all network calls (same as --offline).");
  env("NO_COLOR", "Disable ANSI colors (also honored by SCGUARD_NO_COLOR).");
  env("SCGUARD_NO_COLOR", "Disable ANSI colors in CLI output.");
  console.log("");
}

function section(title: string) {
  console.log("");
  console.log(c.amber(title, true));
}

function item(cmd: string, sig: string, detail: string) {
  const head = `${style.prompt()} ${c.white(cmd, true)}${sig ? ` ${c.blue(sig)}` : ""}`;
  console.log(`  ${head}`);
  console.log(`      ${c.gray(detail)}`);
}

function env(key: string, detail: string) {
  console.log(`  ${c.amber(key.padEnd(28), true)} ${c.gray(detail)}`);
}

main().catch((error) => {
  const msg = error instanceof Error ? error.message : String(error);
  console.error(`${style.blocked("error:")} ${c.white(msg)}`);
  process.exit(1);
});
