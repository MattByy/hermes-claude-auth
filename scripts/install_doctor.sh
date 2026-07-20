#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="$HOME/.hermes/bin"
LOG_DIR="$HOME/.hermes/logs"
LAUNCH_AGENTS="$HOME/Library/LaunchAgents"
DOCTOR="$BIN_DIR/hermes-doctor"
PLIST="$LAUNCH_AGENTS/ai.hermes.doctor.plist"
UID_VALUE="$(id -u)"

mkdir -p "$BIN_DIR" "$LOG_DIR" "$LAUNCH_AGENTS"
cp "$REPO_DIR/scripts/hermes_doctor.py" "$DOCTOR"
chmod 755 "$DOCTOR"

cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>ai.hermes.doctor</string>
  <key>ProgramArguments</key>
  <array>
    <string>$DOCTOR</string>
    <string>--profiles</string>
    <string>default</string>
    <string>dad</string>
    <string>shared</string>
    <string>--disable-unused</string>
    <string>--no-claude-smoke</string>
    <string>--no-hermes-smoke</string>
  </array>
  <key>StartInterval</key>
  <integer>300</integer>
  <key>RunAtLoad</key>
  <true/>
  <key>StandardOutPath</key>
  <string>$LOG_DIR/hermes-doctor.launchd.log</string>
  <key>StandardErrorPath</key>
  <string>$LOG_DIR/hermes-doctor.launchd.error.log</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key>
    <string>$HOME/.local/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    <key>HOME</key>
    <string>$HOME</string>
    <key>HERMES_CLAUDE_AUTH_STRICT_SUBSCRIPTION</key>
    <string>1</string>
  </dict>
</dict>
</plist>
PLIST

launchctl bootout "gui/$UID_VALUE" "$PLIST" >/dev/null 2>&1 || true
launchctl bootstrap "gui/$UID_VALUE" "$PLIST"
launchctl kickstart -k "gui/$UID_VALUE/ai.hermes.doctor" >/dev/null 2>&1 || true

"$DOCTOR" --profiles default dad shared --disable-unused --no-claude-smoke --no-hermes-smoke

printf "Installed Hermes doctor:\n"
printf "  Command: %s\n" "$DOCTOR"
printf "  LaunchAgent: %s\n" "$PLIST"
printf "  Status: %s\n" "$HOME/.hermes/health/doctor-status.json"
