# hermes-claude-auth

Use Hermes with your flat-fee Claude Code subscription instead of burning a normal Anthropic API key.

This repo is a local patch layer for `hermes-agent`. It keeps Claude Code OAuth credentials fresh, makes Hermes requests look enough like official Claude Code requests for subscription routing, and repairs the common auth drift that kills long-running Hermes jobs.

## The Problem

Claude Code subscription auth is OAuth-based. The access token looks like:

```text
sk-ant-oat01-...
```

That token is short-lived. The important long-lived thing is the refresh token:

```text
sk-ant-ort01-...
```

Hermes can accidentally keep using an old access token from its environment, credential pool, or cached client. When that happens, a job that started fine suddenly dies with:

```text
HTTP 401: Invalid authentication credentials
Please run /login
```

Running `/login` inside a broken Hermes session is not a real fix. It may refresh Claude Code, but Hermes can still hold the stale token in another place.

This repo fixes that architecture.

## What This Repo Does

There are three pieces.

### 1. Runtime Patch

`anthropic_billing_bypass.py` is copied to:

```text
~/.hermes/patches/anthropic_billing_bypass.py
```

`sitecustomize_hook.py` is installed into the Hermes Python venv as:

```text
~/.hermes/hermes-agent/venv/lib/pythonX.Y/site-packages/sitecustomize.py
```

Python loads `sitecustomize.py` automatically when Hermes starts. That hook patches Hermes at runtime. It does not edit Hermes source files.

The patch:

- pulls the freshest Claude Code OAuth token from macOS Keychain or `~/.claude/.credentials.json`
- refreshes expired Claude Code access tokens
- ignores stale `ANTHROPIC_API_KEY`, `ANTHROPIC_TOKEN`, and `CLAUDE_CODE_OAUTH_TOKEN` when subscription-only mode is enabled
- replaces stale Anthropic client tokens with the fresh Claude Code token
- force-refreshes on HTTP 401, even if local `expiresAt` still claims the token is valid
- prevents Hermes from marking the only `claude_code` pool entry as exhausted after a refreshable 401

### 2. Claude Code Request Shape

Anthropic validates that OAuth subscription requests look like official Claude Code traffic. The patch adds the compatibility bits Hermes is missing:

- Claude Code billing header signature
- Claude Code-ish Stainless SDK headers
- OAuth beta flags
- `?beta=true`
- MCP tool name wrapping/unwrapping
- tool-pair cleanup for orphaned `tool_use` / `tool_result`
- small provider compatibility fixes for Haiku effort and Opus temperature

In normal words: Hermes still does the work, but the outgoing Anthropic request is shaped like Claude Code expects.

### 3. Hermes Doctor

`scripts/hermes_doctor.py` installs as:

```text
~/.hermes/bin/hermes-doctor
```

It checks and repairs local drift:

- mirrors the freshest Claude Code credential between Keychain and `~/.claude/.credentials.json`
- clears stale `claude_code` pool exhaustion after a refreshable 401
- sets noisy auxiliary tasks to `auto` so title/compression/web helpers do not use a separate stale Anthropic auth path
- checks Claude login status
- optionally runs real Claude and Hermes smoke tests
- checks required gateways
- disables unused legacy gateways if requested

The doctor also installs a macOS LaunchAgent that runs a lightweight check every 5 minutes.

## How Token Refresh Works

Source of truth:

```text
macOS Keychain: Claude Code-credentials
~/.claude/.credentials.json
```

Hermes runtime path:

```text
Hermes request
  -> patched Anthropic adapter
  -> resolve fresh Claude Code credential
  -> refresh if expired
  -> build Anthropic client with fresh access token
  -> apply Claude Code request-shape patch
  -> send request
```

Reactive 401 path:

```text
Anthropic returns 401
  -> patch force-refreshes Claude Code OAuth using refresh token
  -> writes fresh token pair back to Keychain / ~/.claude/.credentials.json
  -> updates Hermes credential_pool claude_code entry
  -> clears stale exhausted status
  -> retries same credential instead of killing the task
```

That last part is the important fix. A valid-looking token can still be rejected server-side. So the patch trusts the server's 401 more than the local expiry timestamp.

## Install

From the repo:

```bash
cd /Users/swello/Documents/hermes/hermes-claude-auth
./install.sh
./scripts/install_doctor.sh
```

Remote install:

```bash
curl -fsSL https://raw.githubusercontent.com/kristianvast/hermes-claude-auth/main/install-remote.sh | bash
```

On macOS, `install.sh` also mirrors the Claude Code Keychain credential into:

```text
~/.claude/.credentials.json
```

Restart gateways after install:

```bash
hermes gateway restart
hermes --profile dad gateway restart
hermes --profile shared gateway restart
```

## Verify

Real Claude smoke:

```bash
claude -p 'Reply exactly CLAUDE_OK' --model claude-sonnet-4-6 --output-format text
```

Full Hermes auth smoke:

```bash
~/.hermes/bin/hermes-doctor --profiles default dad shared --disable-unused
```

Fast local status:

```bash
~/.hermes/bin/hermes-doctor --profiles default dad shared --disable-unused --no-claude-smoke --no-hermes-smoke
cat ~/.hermes/health/doctor-status.json
```

Gateway status:

```bash
hermes gateway list
```

Look for patch load messages:

```bash
tail -n 200 ~/.hermes/logs/gateway.error.log | rg 'anthropic_billing_bypass|Credential pool 401'
```

Expected messages include:

```text
[anthropic_billing_bypass] Token refresh hook installed
[anthropic_billing_bypass] Credential pool 401 refresh hook installed
[anthropic_billing_bypass] Bypass installed
```

## Subscription-Only Mode

Default:

```bash
HERMES_CLAUDE_AUTH_STRICT_SUBSCRIPTION=1
```

In this mode, once refreshable Claude Code credentials exist, the patch ignores:

```text
ANTHROPIC_API_KEY
ANTHROPIC_TOKEN
CLAUDE_CODE_OAUTH_TOKEN
```

That is intentional. Otherwise an old shell or launchd environment variable can silently override the fresh Claude subscription token.

To allow normal Anthropic API-key fallback again:

```bash
export HERMES_CLAUDE_AUTH_STRICT_SUBSCRIPTION=0
```

For this setup, leave it on.

## Composio Tool Control

Too many MCP tools can push Hermes into long-context billing/rate-limit trouble. This repo includes a helper:

```bash
~/.hermes/bin/hermes-composio-tools list
~/.hermes/bin/hermes-composio-tools set gmail googlecalendar
~/.hermes/bin/hermes-composio-tools add googledrive
~/.hermes/bin/hermes-composio-tools remove googledrive
```

The `composio` management toolkit is always kept. Changes restart the default gateway unless `--no-restart` is passed.

## Common Failures

### `HTTP 401: Invalid authentication credentials`

Run:

```bash
~/.hermes/bin/hermes-doctor --profiles default dad shared --disable-unused
```

If it says healthy, retry the Hermes job. The doctor probably repaired stale local state.

If Claude itself fails:

```bash
claude auth login
```

Then:

```bash
~/.hermes/bin/hermes-doctor --profiles default dad shared --disable-unused
hermes gateway restart
```

### Hermes says healthy, but one job still fails

That usually means the job process cached an old client. Restart the gateway:

```bash
hermes gateway restart
```

If a worker is stuck:

```bash
ps -axo pid,ppid,etime,command | rg '[h]ermes.*kanban|[h]ermes.*gremlin|[h]ermes.*worker'
```

Kill the specific stuck worker, not everything.

### Pool is stuck exhausted

Check:

```bash
~/.hermes/hermes-agent/venv/bin/python - <<'PY'
import json
from hermes_cli.auth import read_credential_pool
for e in read_credential_pool('anthropic') or []:
    if e.get('source') == 'claude_code':
        print(json.dumps({
            'id': e.get('id'),
            'last_status': e.get('last_status'),
            'last_error_code': e.get('last_error_code'),
            'has_access': bool(e.get('access_token')),
            'has_refresh': bool(e.get('refresh_token')),
            'expires_at_ms': e.get('expires_at_ms'),
        }, indent=2))
PY
```

If `last_status` is `exhausted` with `last_error_code` 401, run:

```bash
~/.hermes/bin/hermes-doctor --profiles default dad shared --disable-unused
```

The doctor now clears that state when Claude Code credentials are valid.

### `HTTP 429: Usage credits are required for long context requests`

This is usually not token refresh. It means the request got too large or routed into a paid/long-context path. Reduce tools/context:

```bash
~/.hermes/bin/hermes-composio-tools set gmail googlecalendar
hermes gateway restart
```

### `HTTP 200: Overloaded`

Anthropic is overloaded. The token is probably fine. Retry later or use a fallback provider if you actually configured one.

## Files This Repo Touches

| Path | Purpose |
|---|---|
| `~/.hermes/patches/anthropic_billing_bypass.py` | Runtime patch copied here |
| `~/.hermes/hermes-agent/venv/.../sitecustomize.py` | Import hook that loads the patch |
| `~/.claude/.credentials.json` | Claude Code credential mirror |
| `~/.hermes/auth.json` | Hermes credential pool; doctor may clear stale `claude_code` 401 state |
| `~/.hermes/bin/hermes-doctor` | Local repair/check command |
| `~/Library/LaunchAgents/ai.hermes.doctor.plist` | macOS doctor monitor |

Hermes source files are not modified.

## Development

Run tests with the Hermes venv:

```bash
cd /Users/swello/Documents/hermes/hermes-claude-auth
~/.hermes/hermes-agent/venv/bin/python -m pytest -q
```

Install local changes:

```bash
./install.sh
./scripts/install_doctor.sh
```

## Uninstall

```bash
./uninstall.sh
```

Remove patch file too:

```bash
./uninstall.sh --purge
```

Remove doctor:

```bash
launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/ai.hermes.doctor.plist
rm -f ~/Library/LaunchAgents/ai.hermes.doctor.plist
rm -f ~/.hermes/bin/hermes-doctor
```

## Credits

- [griffinmartin/opencode-claude-auth](https://github.com/griffinmartin/opencode-claude-auth)
- [NousResearch/hermes-agent](https://github.com/NousResearch/hermes-agent)

## Disclaimer

This uses Claude Code subscription credentials outside the official Claude Code CLI. Anthropic can change this behavior. If they do, this patch may break.

MIT license.
