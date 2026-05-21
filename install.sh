#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${SCGUARD_REPO_URL:-https://github.com/pc-style/supply-chain-guard.git}"
INSTALL_DIR="${SCGUARD_INSTALL_DIR:-$HOME/.local/share/supply-chain-guard}"
BIN_DIR="${SCGUARD_BIN_DIR:-$HOME/.local/bin}"
BIN_PATH="$BIN_DIR/scguard"
CONFIG_DIR="${SCGUARD_CONFIG_DIR:-$HOME/.config/supply-chain-guard}"
ENV_PATH="$CONFIG_DIR/env"

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
chmod +x src/cli.ts

echo
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
  cat > "$ENV_PATH" <<EOF
export SOCKET_API_KEY="$SOCKET_TOKEN_INPUT"
EOF
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

cat > "$BIN_PATH" <<EOF
#!/usr/bin/env bash
[ -f "$ENV_PATH" ] && source "$ENV_PATH"
exec bun run "$INSTALL_DIR/src/cli.ts" "\$@"
EOF
chmod +x "$BIN_PATH"

if { : < /dev/tty > /dev/tty; } 2>/dev/null; then
  echo
  echo "Launching Supply Chain Guard config."
  "$BIN_PATH" config < /dev/tty || echo "Config skipped. Run: scguard config"
else
  echo
  echo "Skipping interactive config because no TTY is available. Run: scguard config"
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
          printf '\n# Supply Chain Guard — intercept package manager installs\neval (scguard shell-hook)\n' >> "$PROFILE"
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
