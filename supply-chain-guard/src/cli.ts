#!/usr/bin/env bun
import { dirname, join, resolve } from "node:path";
import {
  CLI_ENTRY,
  ensureDirs,
  readJson,
  readOption,
  requireArg,
} from "./core";
import type { Report } from "./core";
import { scanNpm, scanNpmStage, scanVsix } from "./analysis";
import {
  resolveAgentMode,
  runAgentReviews,
  writeAgentPrompt,
} from "./integrations";
import { emitReport, maybeRunConfiguredAgentReview } from "./reporting";
import {
  cleanCommand,
  configCommand,
  doctorCommand,
  guardCommand,
  reviewOrInstall,
  selfTest,
  shellHook,
} from "./commands";
import { banner, c, style } from "./ui";

async function main() {
  const cliArgs = normalizeArgv(Bun.argv);
  const [cmd, ...args] = cliArgs;
  if (Bun.env.SCGUARD_DEBUG_ARGV) {
    console.error(JSON.stringify({ argv: Bun.argv, cliArgs, cmd, args }));
  }
  await ensureDirs();

  if (!cmd || cmd === "--help" || cmd === "-h") {
    await help();
    return;
  }

  if (cmd === "--version" || cmd === "-v" || cmd === "version") {
    const pkg = await readJson<{ version: string }>(join(dirname(CLI_ENTRY), "..", "package.json"));
    console.log(pkg.version);
    return;
  }

  if (cmd === "scan-npm") {
    const target = requireArg(args[0], "scan-npm requires a package spec");
    const report = await scanNpm(target);
    const reportPath = await emitReport(report, args.includes("--json"));
    await maybeRunConfiguredAgentReview(report, reportPath, args, args.includes("--json"));
    return;
  }

  if (cmd === "scan-stage") {
    const stageId = requireArg(args[0], "scan-stage requires an npm stage id");
    const report = await scanNpmStage(stageId);
    const reportPath = await emitReport(report, args.includes("--json"));
    await maybeRunConfiguredAgentReview(report, reportPath, args, args.includes("--json"));
    return;
  }

  if (cmd === "add") {
    console.error("scguard: 'add' is deprecated. Use 'scguard review' to scan-only, or 'scguard install' to scan then install.");
    await reviewOrInstall(args, { install: args.includes("--approve") });
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

  if (cmd === "scan-vsix") {
    const file = requireArg(args[0], "scan-vsix requires a .vsix path");
    const report = await scanVsix(resolve(file));
    const reportPath = await emitReport(report, args.includes("--json"));
    await maybeRunConfiguredAgentReview(report, reportPath, args, args.includes("--json"));
    return;
  }

  if (cmd === "agent-prompt") {
    const reportPath = requireArg(args[0], "agent-prompt requires a report path");
    const agent = readOption(args, "--agent") ?? "codex";
    const report = await readJson<Report>(reportPath);
    const promptPath = await writeAgentPrompt(report, agent);
    console.log(promptPath);
    return;
  }

  if (cmd === "agent-review") {
    const reportPath = requireArg(args[0], "agent-review requires a report path");
    const report = await readJson<Report>(reportPath);
    const agentMode = await resolveAgentMode(args);
    const agents = agentMode.length > 0 ? agentMode : ["codex" as const];
    const reviews = await runAgentReviews(report, reportPath, agents);
    console.log(JSON.stringify(reviews, null, 2));
    if (reviews.some((review) => review.status !== "approved")) process.exit(2);
    return;
  }

  if (cmd === "guard") {
    await guardCommand(args);
    return;
  }

  if (cmd === "shell-hook") {
    console.log(shellHook());
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

  throw new Error(`Unknown command: ${cmd}`);
}

function normalizeArgv(argv: string[]) {
  const raw = argv.slice(1);
  const first = raw[0] ?? "";
  if (first.endsWith("src/cli.ts") || first.endsWith("/scguard") || first.endsWith("\\scguard")) {
    return raw.slice(1);
  }
  return raw;
}

async function help() {
  const pkg = await readJson<{ version: string }>(join(dirname(CLI_ENTRY), "..", "package.json")).catch(() => ({ version: "0.0.0" }));
  console.log(banner(pkg.version));
  console.log("");
  section("Common");
  item("scguard review", "<package[@version]> [--agent codex|pi|both]", "Download, stage, and analyze a package without installing it.");
  item("scguard install", "<package[@version]> [--dev] [--agent codex|pi|both]", "Review, then install only after the gate (and any agent review) passes.");
  item("scguard scan-vsix", "<extension.vsix> [--json]", "Analyze a downloaded VS Code extension artifact.");
  item("scguard doctor", "", "Check dependencies, PATH, shell hook, Socket token, and agent CLIs.");
  item("scguard clean", "[--reports] [--cache] [--work] [--all]", "Remove cached artifacts, working dirs, or report history.");
  item("scguard config", "[--show] [--agent none|codex|pi|both]", "Set the default agent-review policy.");

  section("Setup");
  item("scguard shell-hook", "", "Print shell functions that route bun/npm/pnpm/yarn/code through scguard.");
  item("scguard version", "", "Print the installed version.");

  section("Advanced");
  item("scguard scan-npm", "<package[@version]> [--json]", "Scan a published npm package directly.");
  item("scguard scan-stage", "<stage-id> [--json]", "Scan an npm staged-publish artifact.");
  item("scguard guard", "bun|npm|pnpm|yarn|code <args...>", "Wrap a package-manager command behind the gate.");
  item("scguard agent-prompt", "<report.json> --agent codex|pi", "Emit the agent review prompt for a report.");
  item("scguard agent-review", "<report.json> --agent codex|pi|both", "Run an agent review against a report.");
  item("scguard self-test", "", "Validate analysis on the bundled fixture.");

  section("Environment");
  env("SCGUARD_BYPASS=1", "Skip the guard for a single command.");
  env("SOCKET_API_KEY", "Enable Socket.dev intelligence on npm scans.");
  env("SCGUARD_ACTIVE_INCIDENT", "Require typed acknowledgement during an active advisory.");
  console.log("");
}

function section(title: string) {
  console.log("");
  console.log(c.amber(title, true));
}

function item(cmd: string, sig: string, detail: string) {
  const head = `${style.prompt()} ${c.white(cmd, true)}${sig ? " " + c.blue(sig) : ""}`;
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
