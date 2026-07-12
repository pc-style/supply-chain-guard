import { CLI_ENTRY, CONFIG_ENV_PATH } from "./core";

export function shellHook(shell: "bash" | "fish" = "bash") {
  if (shell === "fish") return shellHookFish();
  return `[ -f "${CONFIG_ENV_PATH}" ] && source "${CONFIG_ENV_PATH}"
export SCGUARD_SHELL_HOOK_ACTIVE=1
scguard() { command bun run ${CLI_ENTRY} "$@"; }
bun() { command bun run ${CLI_ENTRY} guard bun "$@"; }
npm() { command bun run ${CLI_ENTRY} guard npm "$@"; }
pnpm() { command bun run ${CLI_ENTRY} guard pnpm "$@"; }
yarn() { command bun run ${CLI_ENTRY} guard yarn "$@"; }
code() { command bun run ${CLI_ENTRY} guard code "$@"; }
`;
}

export function shellHookFish() {
  return `if test -f "${CONFIG_ENV_PATH}"
    source "${CONFIG_ENV_PATH}"
end
set -gx SCGUARD_SHELL_HOOK_ACTIVE 1
function scguard
    command bun run ${CLI_ENTRY} $argv
end
function bun
    command bun run ${CLI_ENTRY} guard bun $argv
end
function npm
    command bun run ${CLI_ENTRY} guard npm $argv
end
function pnpm
    command bun run ${CLI_ENTRY} guard pnpm $argv
end
function yarn
    command bun run ${CLI_ENTRY} guard yarn $argv
end
function code
    command bun run ${CLI_ENTRY} guard code $argv
end
`;
}
