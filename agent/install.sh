#!/bin/sh
# Remote agent installer (POSIX sh). Served, rendered, by GET /agent/install.sh:
#
#   curl -fsSL https://SERVER/agent/install.sh | \
#     AGENT_SERVER_URL=https://SERVER AGENT_ENROLL_TOKEN=et_... AGENT_NAME=mac-a sh
#
# Environment:
#   AGENT_SERVER_URL     server base URL (default: the server that served this file)
#   AGENT_ENROLL_TOKEN   the ONE-TIME enrollment token (valid 15 min, single use).
#                        Redeemed on this machine; the key goes into the macOS
#                        Keychain or ~/.remote-agent/key-<name> (0600), never
#                        into env.sh or the service definition.
#   AGENT_KEY            a raw key instead of a token (development only)
#   AGENT_NAME           agent label (default: short hostname)
#   AGENT_HOME           install dir (default ~/remote-agent)
#   AGENT_EXECUTORS      optional "module[:setup]" with project executors
#   LLM_BASE_URL         optional, for the built-in chat executor
#
# Zero dependencies: the agent runs on the system python3 (3.9+). The
# installer downloads the agent script from the server (checking
# X-Agent-Script-Version against its sha256), writes env.sh (0600),
# enrolls, then installs a user service: a LaunchAgent on macOS (under
# `caffeinate -s` so the machine does not sleep while the agent runs) or a
# systemd --user unit on Linux. Re-running it updates the script and the
# service and reloads: it is idempotent.
#
# Everything runs inside main(), called on the last line, so a truncated
# download never executes half an install.

DEFAULT_AGENT_SERVER_URL=@@AGENT_SERVER_URL@@
DEFAULT_AGENT_NAME=@@AGENT_NAME@@
DEFAULT_AGENT_ENROLL_TOKEN=@@AGENT_ENROLL_TOKEN@@

say() { printf '%s\n' "remote-agent: $*"; }
die() { printf '%s\n' "remote-agent: error: $*" >&2; exit 1; }
shq() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }
xmlq() { printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'; }

main() {
  set -eu
  AGENT_SERVER_URL="${AGENT_SERVER_URL:-$DEFAULT_AGENT_SERVER_URL}"
  AGENT_ENROLL_TOKEN="${AGENT_ENROLL_TOKEN:-$DEFAULT_AGENT_ENROLL_TOKEN}"
  AGENT_NAME="${AGENT_NAME:-$DEFAULT_AGENT_NAME}"
  AGENT_KEY="${AGENT_KEY:-}"
  AGENT_SERVER_URL="${AGENT_SERVER_URL%/}"
  [ -n "$AGENT_SERVER_URL" ] || die "AGENT_SERVER_URL is required"
  [ -n "$AGENT_ENROLL_TOKEN" ] || [ -n "$AGENT_KEY" ] \
    || die "AGENT_ENROLL_TOKEN or AGENT_KEY is required (admin → Agents → New agent)"
  if [ -z "$AGENT_NAME" ]; then
    AGENT_NAME="$(hostname -s 2>/dev/null || hostname)"
  fi
  SLUG="$(printf '%s' "$AGENT_NAME" | tr -c 'A-Za-z0-9_-' '-' | cut -c1-40)"
  [ -n "$SLUG" ] || SLUG=agent

  HOME_DIR="${AGENT_HOME:-$HOME/remote-agent}"
  command -v python3 >/dev/null 2>&1 || die "python3 not found (3.9+ required)"
  command -v curl >/dev/null 2>&1 || die "curl not found"
  mkdir -p "$HOME_DIR"; chmod 700 "$HOME_DIR"
  HOME_DIR="$(cd "$HOME_DIR" && pwd)"
  PY="$(command -v python3)"
  "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' \
    || die "python3 is older than 3.9 ($PY)"

  # 1. The agent script, verified against the server's version header.
  say "downloading the agent script from $AGENT_SERVER_URL"
  HDRS="$(mktemp)"; TMP="$HOME_DIR/remote_agent.py.new"
  curl -fsSL -D "$HDRS" -o "$TMP" "$AGENT_SERVER_URL/agent/script" || die "download failed"
  WANT="$(tr -d '\r' < "$HDRS" | awk 'tolower($1)=="x-agent-script-version:" {print $2}')"
  rm -f "$HDRS"
  GOT="$("$PY" -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest()[:16])' "$TMP")"
  [ -n "$WANT" ] && [ "$WANT" = "$GOT" ] || die "script version mismatch (header $WANT, sha256 $GOT)"
  "$PY" -m py_compile "$TMP" || die "downloaded script does not compile"
  mv -f "$TMP" "$HOME_DIR/remote_agent.py"; chmod 700 "$HOME_DIR/remote_agent.py"
  say "agent script $GOT installed in $HOME_DIR"

  # 2. env.sh — never holds the key.
  {
    printf 'export AGENT_SERVER_URL=%s\n' "$(shq "$AGENT_SERVER_URL")"
    printf 'export AGENT_NAME=%s\n' "$(shq "$AGENT_NAME")"
    [ -n "${AGENT_EXECUTORS:-}" ] && printf 'export AGENT_EXECUTORS=%s\n' "$(shq "$AGENT_EXECUTORS")"
    [ -n "${LLM_BASE_URL:-}" ] && printf 'export LLM_BASE_URL=%s\n' "$(shq "$LLM_BASE_URL")"
    [ -n "${AGENT_KEY_FILE:-}" ] && printf 'export AGENT_KEY_FILE=%s\n' "$(shq "$AGENT_KEY_FILE")"
    true
  } > "$HOME_DIR/env.sh"
  chmod 600 "$HOME_DIR/env.sh"

  # 3. Enrol (token → key, stored by the agent) or store the raw key.
  if [ -n "$AGENT_ENROLL_TOKEN" ]; then
    say "enrolling $AGENT_NAME at $AGENT_SERVER_URL"
    ( . "$HOME_DIR/env.sh"; AGENT_ENROLL_TOKEN="$AGENT_ENROLL_TOKEN" "$PY" "$HOME_DIR/remote_agent.py" --enroll-only ) \
      || die "enrollment failed (expired or used token? ask an admin for a new one)"
  else
    say "storing the raw key (development mode)"
    ( . "$HOME_DIR/env.sh"; "$PY" -c 'import sys; sys.path.insert(0, sys.argv[1]); import remote_agent as r; print("key stored in the", r.save_key(sys.argv[2], sys.argv[3]))' "$HOME_DIR" "$AGENT_NAME" "$AGENT_KEY" )
  fi

  # 4. A user service that keeps the agent running.
  case "$(uname -s)" in
    Darwin)
      LABEL="remote-agent.$SLUG"
      PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
      LOGF="$HOME/Library/Logs/remote-agent-$SLUG.log"
      mkdir -p "$HOME/Library/LaunchAgents" "$HOME/Library/Logs"
      launchctl bootout "gui/$(id -u)/$LABEL" >/dev/null 2>&1 || true
      cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key><array>
    <string>/bin/sh</string><string>-c</string>
    <string>. $(xmlq "$HOME_DIR")/env.sh; exec /usr/bin/caffeinate -s $(xmlq "$PY") $(xmlq "$HOME_DIR")/remote_agent.py</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>30</integer>
  <key>StandardOutPath</key><string>$(xmlq "$LOGF")</string>
  <key>StandardErrorPath</key><string>$(xmlq "$LOGF")</string>
</dict></plist>
EOF
      chmod 600 "$PLIST"
      launchctl bootstrap "gui/$(id -u)" "$PLIST" || die "launchctl bootstrap failed"
      say "LaunchAgent $LABEL loaded; log: $LOGF"
      say "manage: launchctl kickstart -k gui/$(id -u)/$LABEL | launchctl bootout gui/$(id -u)/$LABEL"
      ;;
    Linux)
      UNIT_DIR="$HOME/.config/systemd/user"; UNIT="remote-agent-$SLUG.service"
      mkdir -p "$UNIT_DIR"
      cat > "$UNIT_DIR/$UNIT" <<EOF
[Unit]
Description=Remote agent $AGENT_NAME (outbound-only)
After=network-online.target

[Service]
Type=simple
EnvironmentFile=$HOME_DIR/env.sh
ExecStart=$PY $HOME_DIR/remote_agent.py
Restart=always
RestartSec=30
KillSignal=SIGTERM
TimeoutStopSec=620

[Install]
WantedBy=default.target
EOF
      # EnvironmentFile wants KEY=value lines: strip the "export ".
      sed -i 's/^export //' "$HOME_DIR/env.sh"
      systemctl --user daemon-reload
      systemctl --user enable --now "$UNIT" || die "systemctl --user enable failed"
      systemctl --user restart "$UNIT"
      say "systemd user unit $UNIT enabled (loginctl enable-linger $USER keeps it up after logout)"
      say "manage: systemctl --user status|restart|stop $UNIT · journalctl --user -u $UNIT -f"
      ;;
    *)
      say "no service manager template for $(uname -s): run it yourself with"
      say "  . $HOME_DIR/env.sh && $PY $HOME_DIR/remote_agent.py"
      ;;
  esac
  say "done"
}

main "$@"
