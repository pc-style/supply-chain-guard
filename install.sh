#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${SCGUARD_REPO_URL:-https://github.com/pc-style/supply-chain-guard.git}"
INSTALL_DIR="${SCGUARD_INSTALL_DIR:-$HOME/.local/share/supply-chain-guard}"
BIN_DIR="${SCGUARD_BIN_DIR:-$HOME/.local/bin}"
BIN_PATH="$BIN_DIR/scguard"
CONFIG_DIR="${SCGUARD_CONFIG_DIR:-$HOME/.config/supply-chain-guard}"
CONFIG_PATH="${SCGUARD_CONFIG_PATH:-$CONFIG_DIR/config.json}"
ENV_PATH="$CONFIG_DIR/env"

ACTION="install"
PURGE=0
for arg in "$@"; do
  case "$arg" in
    --uninstall) ACTION="uninstall" ;;
    --purge)     PURGE=1 ;;
    -h|--help)
      cat <<EOF
Supply Chain Guard installer

Usage:
  install.sh                Install or update Supply Chain Guard.
  install.sh --uninstall    Remove the scguard binary, install directory,
                            and shell hook. Prompts before deleting config.
  install.sh --uninstall --purge
                            Same as --uninstall but also deletes the config
                            directory without prompting.

Environment overrides:
  SCGUARD_REPO_URL          Default: https://github.com/pc-style/supply-chain-guard.git
  SCGUARD_INSTALL_DIR       Default: \$HOME/.local/share/supply-chain-guard
  SCGUARD_BIN_DIR           Default: \$HOME/.local/bin
  SCGUARD_CONFIG_DIR        Default: \$HOME/.config/supply-chain-guard
  SCGUARD_CONFIG_PATH       Default: \$HOME/.config/supply-chain-guard/config.json
EOF
      exit 0
      ;;
    *)
      echo "Unknown argument: $arg" >&2
      echo "Run 'install.sh --help' for usage." >&2
      exit 1
      ;;
  esac
done

remove_shell_hook() {
  local profile
  for profile in "$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.profile" "$HOME/.config/fish/config.fish"; do
    [ -f "$profile" ] || continue
    if grep -q 'scguard shell-hook' "$profile" 2>/dev/null; then
      local tmp
      tmp="$(mktemp)"
      # Drop the marker comment line and the eval line.
      awk '
        /# Supply Chain Guard — intercept package manager installs/ { skip=1; next }
        skip==1 && /scguard shell-hook/ { skip=0; next }
        { print }
      ' "$profile" > "$tmp"
      mv "$tmp" "$profile"
      echo "Removed shell hook from $profile"
    fi
  done
}

if [ "$ACTION" = "uninstall" ]; then
  echo "Uninstalling Supply Chain Guard"

  if [ -f "$BIN_PATH" ] || [ -L "$BIN_PATH" ]; then
    rm -f "$BIN_PATH"
    echo "Removed $BIN_PATH"
  else
    echo "No binary at $BIN_PATH"
  fi

  if [ -d "$INSTALL_DIR" ]; then
    rm -rf "$INSTALL_DIR"
    echo "Removed $INSTALL_DIR"
  else
    echo "No install directory at $INSTALL_DIR"
  fi

  remove_shell_hook

  if [ -d "$CONFIG_DIR" ]; then
    if [ "$PURGE" -eq 1 ]; then
      rm -rf "$CONFIG_DIR"
      echo "Removed $CONFIG_DIR"
    else
      CONFIRM=""
      printf "Also delete config at %s? [y/N] " "$CONFIG_DIR"
      if ! { IFS= read -r CONFIRM < /dev/tty; } 2>/dev/null; then
        IFS= read -r CONFIRM || true
      fi
      case "$CONFIRM" in
        [Yy]*)
          rm -rf "$CONFIG_DIR"
          echo "Removed $CONFIG_DIR"
          ;;
        *)
          echo "Kept $CONFIG_DIR (use --purge to remove non-interactively)"
          ;;
      esac
    fi
  fi

  echo
  echo "Supply Chain Guard uninstalled."
  exit 0
fi

if ! command -v bun >/dev/null 2>&1; then
  echo "bun is required." >&2
  echo "Install Bun: curl -fsSL https://bun.sh/install | bash" >&2
  exit 1
fi

if ! command -v git >/dev/null 2>&1; then
  echo "git is required." >&2
  exit 1
fi

mkdir -p "$BIN_DIR"
mkdir -p "$CONFIG_DIR"

WAS_INSTALLED=0
if [ -d "$INSTALL_DIR/.git" ] || [ -f "$BIN_PATH" ] || [ -L "$BIN_PATH" ]; then
  WAS_INSTALLED=1
fi

echo
cat <<EOF
WARNING: Supply Chain Guard is VERY VERY EARLY STAGE software.
It can miss malicious packages, flag safe packages, and break package-manager flows.
Use it as a local warning layer, not as proof that dependencies are safe.
EOF
echo

if [ -d "$INSTALL_DIR/.git" ]; then
  echo "Updating Supply Chain Guard in $INSTALL_DIR"
  git -C "$INSTALL_DIR" pull --ff-only
else
  echo "Installing Supply Chain Guard into $INSTALL_DIR"
  rm -rf "$INSTALL_DIR"
  git clone "$REPO_URL" "$INSTALL_DIR"
fi

cd "$INSTALL_DIR"
bun install
bun run build
chmod +x dist/scguard

echo
if [ "$WAS_INSTALLED" -eq 1 ] || [ -f "$CONFIG_PATH" ] || [ -f "$ENV_PATH" ]; then
  echo "Existing install/config detected; skipping token setup."
else
  echo "Socket API token setup"
  echo "Create a token here: https://socket.dev/dashboard/settings/api-tokens"
  echo "Recommended minimum scope for current package score lookup: packages:list"
  echo "Optional future active-incident feed scope: threat-feed:list"
  printf "Paste Socket API token, or press Enter to skip: "
  SOCKET_TOKEN_INPUT=""
  if ! { IFS= read -r SOCKET_TOKEN_INPUT < /dev/tty; } 2>/dev/null; then
    IFS= read -r SOCKET_TOKEN_INPUT || true
  fi

  if [ -n "$SOCKET_TOKEN_INPUT" ]; then
    umask 077
    # Quote the token safely so sourcing the env file cannot execute shell metacharacters.
    printf 'export SOCKET_API_KEY=%s\n' "$(printf '%s' "$SOCKET_TOKEN_INPUT" | sed "s/'/'\\\\''/g; s/^/'/; s/$/'/")" > "$ENV_PATH"
    echo "Saved Socket token env to $ENV_PATH"
  elif [ ! -f "$ENV_PATH" ]; then
    umask 077
    cat > "$ENV_PATH" <<EOF
# Optional Socket token for API-backed package scoring.
# Create one at https://socket.dev/dashboard/settings/api-tokens
# Recommended minimum scope: packages:list
# export SOCKET_API_KEY="..."
EOF
  fi
fi

cat > "$BIN_PATH" <<EOF
#!/usr/bin/env bash
[ -f "$ENV_PATH" ] && source "$ENV_PATH"
exec "$INSTALL_DIR/dist/scguard" "\$@"
EOF
chmod +x "$BIN_PATH"

if [ "$WAS_INSTALLED" -eq 1 ]; then
  echo
  echo "Existing install detected; skipping interactive config. Run 'scguard config' any time to change it."
elif [ ! -f "$CONFIG_PATH" ]; then
  if { : < /dev/tty > /dev/tty; } 2>/dev/null; then
    echo
    echo "Launching Supply Chain Guard config."
    "$BIN_PATH" config < /dev/tty || echo "Config skipped. Run: scguard config"
  else
    echo
    echo "Skipping interactive config because no TTY is available. Run: scguard config"
  fi
else
  echo
  echo "Existing config found at $CONFIG_PATH; run 'scguard config' any time to change it."
fi

echo

echo "Installed: $BIN_PATH"
echo

# Warn if the binary directory is not on PATH.
case ":${PATH}:" in
  *":${BIN_DIR}:"*)
    ;;
  *)
    echo "WARNING: $BIN_DIR is not on your PATH."
    echo "Add the following line to your shell profile (~/.bashrc, ~/.zshrc, or ~/.profile):"
    echo "  export PATH=\"$BIN_DIR:\$PATH\""
    echo "Then reload your shell or run: export PATH=\"$BIN_DIR:\$PATH\""
    echo
    ;;
esac

# ── Shell hook auto-install (opt-in) ────────────────────────────────────────
case "${SHELL:-}" in
  *zsh*)  PROFILE="$HOME/.zshrc" ;;
  *fish*) PROFILE="$HOME/.config/fish/config.fish" ;;
  *)      PROFILE="$HOME/.bashrc" ;;
esac

if grep -q 'scguard shell-hook' "$PROFILE" 2>/dev/null; then
  echo "Shell hook already in $PROFILE"
elif [ "$WAS_INSTALLED" -eq 1 ]; then
  echo "Existing install detected; skipping shell hook prompt. Run 'scguard shell-hook' to add it manually."
else
  HOOK_INPUT=""
  printf "Add shell hook (guards bun/npm/pnpm/yarn/code) to %s? [Y/n] " "$PROFILE"
  if ! { IFS= read -r HOOK_INPUT < /dev/tty; } 2>/dev/null; then
    IFS= read -r HOOK_INPUT || true
  fi
  case "$HOOK_INPUT" in
    [Nn]*)
      echo "Skipping shell hook. You can add it manually (see below)."
      ;;
    *)
      mkdir -p "$(dirname "$PROFILE")"
      case "${SHELL:-}" in
        *fish*)
          printf '\n# Supply Chain Guard — intercept package manager installs\neval (scguard shell-hook --fish)\n' >> "$PROFILE"
          ;;
        *)
          printf '\n# Supply Chain Guard — intercept package manager installs\neval "$(scguard shell-hook)"\n' >> "$PROFILE"
          ;;
      esac
      echo "Shell hook added to $PROFILE"
      echo "Reload your shell or run: source $PROFILE"
      ;;
  esac
fi
echo

echo "Add this to your shell profile to guard bun/npm/pnpm/yarn/code commands:"
echo '  eval "$(scguard shell-hook)"'
echo
echo "Or activate it for this terminal now:"
echo '  eval "$(scguard shell-hook)"'
