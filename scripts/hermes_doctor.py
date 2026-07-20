#!/usr/bin/env python3
"""Keep Claude Code subscription auth and Hermes gateways in a sane state."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


HOME = Path.home()
CLAUDE_CREDS = HOME / ".claude" / ".credentials.json"
CLAUDE_STATE = HOME / ".claude.json"
HERMES_HOME = HOME / ".hermes"
HERMES_AUTH = HERMES_HOME / "auth.json"
STATUS_FILE = HERMES_HOME / "health" / "doctor-status.json"
LOG_FILE = HERMES_HOME / "logs" / "hermes-doctor.log"
KEYCHAIN_SERVICE = "Claude Code-credentials"
DEFAULT_PROFILES = ("default", "dad", "shared")
DISABLED_PROFILES = ("gremlin", "researcher", "scout", "wildcard")
AUX_SUBSCRIPTION_SAFE_TASKS = {"compression", "title_generation", "web_extract"}


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def ensure_dirs() -> None:
    STATUS_FILE.parent.mkdir(parents=True, exist_ok=True)
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)


def log(message: str) -> None:
    ensure_dirs()
    line = f"{now()} {message}"
    print(line)
    with LOG_FILE.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def run(
    args: list[str],
    *,
    timeout: int = 30,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    return subprocess.run(
        args,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        env=merged_env,
    )


def json_load(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except Exception as exc:
        log(f"warn: failed to parse {path}: {exc}")
        return None


def atomic_json_write(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(path)


def read_keychain_credentials() -> dict[str, Any] | None:
    if sys.platform != "darwin":
        return None
    proc = run(
        ["security", "find-generic-password", "-s", KEYCHAIN_SERVICE, "-w"],
        timeout=10,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    try:
        return json.loads(proc.stdout)
    except Exception as exc:
        try:
            return json.loads(bytes.fromhex(proc.stdout.strip()).decode())
        except Exception:
            log(f"warn: keychain credential is not valid JSON: {exc}")
            return None


def oauth_record(data: dict[str, Any] | None) -> dict[str, Any]:
    if not data:
        return {}
    value = data.get("claudeAiOauth", data)
    return value if isinstance(value, dict) else {}


def token_summary(data: dict[str, Any] | None) -> dict[str, Any]:
    rec = oauth_record(data)
    exp = rec.get("expiresAt")
    return {
        "has_access": bool(rec.get("accessToken")),
        "has_refresh": bool(rec.get("refreshToken")),
        "expires_at": exp,
        "expires_iso": dt.datetime.fromtimestamp(exp / 1000, dt.timezone.utc).isoformat()
        if isinstance(exp, (int, float))
        else None,
        "access_fingerprint": fingerprint(rec.get("accessToken")),
        "refresh_fingerprint": fingerprint(rec.get("refreshToken")),
    }


def fingerprint(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    return f"{value[:14]}...{value[-6:]}"


def same_oauth(left: dict[str, Any] | None, right: dict[str, Any] | None) -> bool:
    lrec = oauth_record(left)
    rrec = oauth_record(right)
    keys = ("accessToken", "refreshToken", "expiresAt")
    return all(lrec.get(k) == rrec.get(k) for k in keys)


def backup_file(path: Path, backup_dir: Path) -> None:
    if path.exists():
        backup_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, backup_dir / path.name)


def backup_auth(reason: str) -> Path:
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup = HOME / ".claude" / "auth-backups" / f"{stamp}_{reason}"
    backup_file(CLAUDE_CREDS, backup)
    backup_file(CLAUDE_STATE, backup)
    backup_file(HERMES_HOME / "auth.json", backup)
    return backup


def credential_rank(data: dict[str, Any] | None) -> tuple[int, bool]:
    rec = oauth_record(data)
    try:
        expires = int(rec.get("expiresAt") or 0)
    except (TypeError, ValueError):
        expires = 0
    return expires, bool(rec.get("refreshToken"))


def write_keychain_credentials(data: dict[str, Any]) -> None:
    proc = run(
        [
            "security",
            "add-generic-password",
            "-U",
            "-a",
            os.environ.get("USER", HOME.name),
            "-s",
            KEYCHAIN_SERVICE,
            "-w",
            json.dumps(data, separators=(",", ":")),
        ],
        timeout=10,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"failed to update Keychain: {proc.stderr.strip()}")


def synchronize_credentials() -> str | None:
    keychain = read_keychain_credentials()
    file_data = json_load(CLAUDE_CREDS)
    if same_oauth(keychain, file_data):
        return None
    if not keychain and not file_data:
        return None
    backup = backup_auth("doctor_mirror")
    if file_data and (not keychain or credential_rank(file_data) > credential_rank(keychain)):
        write_keychain_credentials(file_data)
        log(f"repair: mirrored fresher credential file to Claude Code Keychain (backup {backup})")
        return "file_to_keychain"
    if keychain:
        atomic_json_write(CLAUDE_CREDS, keychain)
        log(f"repair: mirrored fresher Claude Code Keychain credential to {CLAUDE_CREDS} (backup {backup})")
        return "keychain_to_file"
    return None


def credential_problem(data: dict[str, Any] | None) -> str | None:
    rec = oauth_record(data)
    if not rec.get("accessToken"):
        return "missing_access_token"
    expires, has_refresh = credential_rank(data)
    now_ms = int(time.time() * 1000)
    if expires and expires <= now_ms and not has_refresh:
        return "expired_without_refresh_token"
    return None


def remove_cached_oauth_account() -> bool:
    state = json_load(CLAUDE_STATE)
    if not state or "oauthAccount" not in state:
        return False
    backup = backup_auth("doctor_oauth_account")
    state.pop("oauthAccount", None)
    atomic_json_write(CLAUDE_STATE, state)
    log(f"repair: removed cached oauthAccount from {CLAUDE_STATE} (backup {backup})")
    return True


def repair_auxiliary_config(path: Path = HERMES_HOME / "config.yaml") -> bool:
    """Keep side tasks from pinning a separate native Anthropic auth lane.

    The main Hermes runtime can still use the user's Claude subscription. These
    auxiliary tasks should resolve through ``auto`` so title/compression/web
    helper calls inherit the same refreshed runtime instead of reusing a stale
    direct Anthropic credential.
    """
    try:
        lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    except FileNotFoundError:
        return False

    changed = False
    in_auxiliary = False
    active_task: str | None = None
    out: list[str] = []

    for line in lines:
        stripped = line.strip()
        indent = len(line) - len(line.lstrip(" "))

        if indent == 0:
            in_auxiliary = stripped == "auxiliary:"
            active_task = None
        elif in_auxiliary and indent == 2 and stripped.endswith(":"):
            active_task = stripped[:-1]
        elif in_auxiliary and indent <= 1 and stripped:
            in_auxiliary = False
            active_task = None

        if in_auxiliary and active_task in AUX_SUBSCRIPTION_SAFE_TASKS:
            if indent == 4 and stripped.startswith("provider:"):
                desired = "    provider: auto\n"
                if line != desired:
                    line = desired
                    changed = True
            elif indent == 4 and stripped.startswith("model:"):
                desired = "    model: ''\n"
                if line != desired:
                    line = desired
                    changed = True

        out.append(line)

    if changed:
        backup = path.with_name(f"{path.name}.{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}.aux-backup")
        shutil.copy2(path, backup)
        path.write_text("".join(out), encoding="utf-8")
        log(f"repair: set auxiliary web/compression/title providers to auto in {path} (backup {backup})")
    return changed


def repair_claude_code_pool(file_data: dict[str, Any] | None = None) -> bool:
    """Sync fresh Claude Code credentials into Hermes' anthropic pool.

    A transient 401 used to mark the single ``claude_code`` pool entry as
    exhausted even after Claude Code refreshed successfully.  If the real
    credential file is usable, clear that stale pool failure and mirror the
    fresh token pair into the entry.
    """
    rec = oauth_record(file_data or json_load(CLAUDE_CREDS))
    access = rec.get("accessToken")
    refresh = rec.get("refreshToken")
    expires = rec.get("expiresAt")
    if not isinstance(access, str) or not access:
        return False

    auth = json_load(HERMES_AUTH)
    if not isinstance(auth, dict):
        return False
    pool = auth.get("credential_pool")
    if not isinstance(pool, dict):
        return False
    entries = pool.get("anthropic")
    if not isinstance(entries, list):
        return False

    changed = False
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("source") != "claude_code":
            continue
        if entry.get("access_token") != access:
            entry["access_token"] = access
            changed = True
        if isinstance(refresh, str) and refresh and entry.get("refresh_token") != refresh:
            entry["refresh_token"] = refresh
            changed = True
        if isinstance(expires, (int, float)) and entry.get("expires_at_ms") != expires:
            entry["expires_at_ms"] = expires
            changed = True
        if entry.get("last_status") == "exhausted" and entry.get("last_error_code") == 401:
            for key in (
                "last_status",
                "last_status_at",
                "last_error_code",
                "last_error_reason",
                "last_error_message",
                "last_error_reset_at",
            ):
                if entry.get(key) is not None:
                    entry[key] = None
                    changed = True

    if changed:
        backup = backup_auth("doctor_pool_sync")
        atomic_json_write(HERMES_AUTH, auth)
        log(f"repair: synced fresh Claude Code credential into Hermes pool (backup {backup})")
    return changed


def claude_status() -> dict[str, Any]:
    proc = run(["claude", "auth", "status"], timeout=20)
    if proc.returncode != 0:
        return {"ok": False, "error": (proc.stderr or proc.stdout).strip()}
    try:
        data = json.loads(proc.stdout)
    except Exception:
        return {"ok": False, "error": proc.stdout.strip()}
    return {
        "ok": bool(data.get("loggedIn")),
        "authMethod": data.get("authMethod"),
        "apiProvider": data.get("apiProvider"),
        "email": data.get("email"),
        "subscriptionType": data.get("subscriptionType"),
    }


def claude_smoke(model: str = "claude-sonnet-4-6") -> dict[str, Any]:
    proc = run(
        [
            "claude",
            "-p",
            "Reply with exactly: CLAUDE_DOCTOR_OK",
            "--model",
            model,
            "--output-format",
            "text",
        ],
        timeout=45,
    )
    combined = f"{proc.stdout}\n{proc.stderr}".strip()
    ok = proc.returncode == 0 and "CLAUDE_DOCTOR_OK" in proc.stdout
    return {"ok": ok, "returncode": proc.returncode, "message": classify_error(combined)}


def hermes_smoke() -> dict[str, Any]:
    env = {
        "HERMES_CLAUDE_AUTH_STRICT_SUBSCRIPTION": "1",
        "HERMES_DOCTOR_SMOKE": "1",
    }
    proc = run(
        [
            "hermes",
            "chat",
            "-q",
            "Reply with exactly: HERMES_DOCTOR_OK",
            "--provider",
            "anthropic",
            "-m",
            "claude-sonnet-4-6",
            "-Q",
        ],
        timeout=60,
        env=env,
    )
    combined = f"{proc.stdout}\n{proc.stderr}".strip()
    ok = proc.returncode == 0 and "HERMES_DOCTOR_OK" in proc.stdout
    return {"ok": ok, "returncode": proc.returncode, "message": classify_error(combined)}


def classify_error(text: str) -> str:
    lowered = text.lower()
    if "invalid authentication credentials" in lowered or "please run /login" in lowered:
        return "auth_invalid"
    if "refresh token is no longer valid" in lowered:
        return "refresh_invalid"
    if "overloaded" in lowered:
        return "provider_overloaded"
    if "rate limit" in lowered or "429" in lowered:
        return "provider_rate_limited"
    if "claude_doctor_ok" in lowered or "hermes_doctor_ok" in lowered:
        return "ok"
    return text[-500:] if text else "unknown"


def gateway_list() -> dict[str, bool]:
    proc = run(["hermes", "gateway", "list"], timeout=20)
    statuses: dict[str, bool] = {}
    for line in proc.stdout.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("Gateways:"):
            continue
        parts = stripped.split()
        if len(parts) >= 2:
            statuses[parts[1]] = parts[0] == "✓"
    return statuses


def restart_profile(profile: str) -> bool:
    if profile == "default":
        cmd = ["hermes", "gateway", "restart"]
        fallback = ["hermes", "gateway", "start"]
    else:
        cmd = ["hermes", "--profile", profile, "gateway", "restart"]
        fallback = ["hermes", "--profile", profile, "gateway", "start"]
    proc = run(cmd, timeout=30)
    if proc.returncode != 0:
        proc = run(fallback, timeout=30)
    ok = proc.returncode == 0
    log(f"{'repair' if ok else 'warn'}: {'restarted' if ok else 'failed to restart'} gateway profile {profile}")
    return ok


def restart_gateways(profiles: tuple[str, ...]) -> None:
    for profile in profiles:
        restart_profile(profile)


def disable_profile_launchd(profile: str) -> None:
    plist = HOME / "Library" / "LaunchAgents" / f"ai.hermes.gateway-{profile}.plist"
    if not plist.exists():
        return
    uid = os.getuid()
    run(["launchctl", "bootout", f"gui/{uid}", str(plist)], timeout=15)
    disabled = plist.with_suffix(plist.suffix + ".disabled")
    if not disabled.exists():
        plist.rename(disabled)
        log(f"repair: disabled unused launch agent {plist.name}")


def write_status(data: dict[str, Any]) -> None:
    ensure_dirs()
    data["checked_at"] = now()
    atomic_json_write(STATUS_FILE, data)


def doctor_once(args: argparse.Namespace) -> int:
    ensure_dirs()
    repaired: list[str] = []
    sync_result = synchronize_credentials()
    if sync_result:
        repaired.append(sync_result)
    if repair_auxiliary_config():
        repaired.append("auxiliary_config_auto")
    file_data = json_load(CLAUDE_CREDS)
    if repair_claude_code_pool(file_data):
        repaired.append("claude_code_pool_sync")
    if args.clean_cached_account and remove_cached_oauth_account():
        repaired.append("removed_cached_oauth_account")

    status = claude_status()
    keychain = read_keychain_credentials()
    file_data = json_load(CLAUDE_CREDS)
    report: dict[str, Any] = {
        "state": "unknown",
        "claude_status": status,
        "keychain": token_summary(keychain),
        "credential_file": token_summary(file_data),
        "credentials_match": same_oauth(keychain, file_data),
        "repaired": repaired,
    }

    if not status.get("ok"):
        report["state"] = "needs-login"
        write_status(report)
        log("needs-login: Claude Code is not logged in. Run `claude auth login`.")
        return 2

    local_problem = credential_problem(file_data or keychain)
    if local_problem:
        report["state"] = "needs-login"
        report["credential_problem"] = local_problem
        write_status(report)
        log(f"needs-login: {local_problem}. Run `claude auth login`.")
        return 2

    claude = claude_smoke(args.model) if args.smoke_claude else {"ok": True, "message": "skipped"}
    report["claude_smoke"] = claude
    if not claude["ok"] and claude["message"] in {"auth_invalid", "refresh_invalid"}:
        sync_result = synchronize_credentials()
        if sync_result:
            repaired.append(f"{sync_result}_after_failure")
            claude = claude_smoke(args.model)
            report["claude_smoke"] = claude
        if not claude["ok"]:
            report["state"] = "needs-login"
            report["repaired"] = repaired
            write_status(report)
            log("needs-login: Claude API still rejects OAuth. Run `claude auth login`.")
            return 2

    if not claude["ok"] and claude["message"] in {"provider_overloaded", "provider_rate_limited"}:
        report["state"] = claude["message"]
        write_status(report)
        log(f"{claude['message']}: Claude auth is present but provider is not accepting work.")
        return 3

    hermes = hermes_smoke() if args.smoke_hermes else {"ok": True, "message": "skipped"}
    report["hermes_smoke"] = hermes
    if not hermes["ok"] and hermes["message"] in {"auth_invalid", "refresh_invalid"}:
        sync_result = synchronize_credentials()
        if sync_result:
            repaired.append(f"{sync_result}_for_hermes")
            hermes = hermes_smoke()
            report["hermes_smoke"] = hermes
        if not hermes["ok"]:
            report["state"] = "hermes-auth-broken"
            report["repaired"] = repaired
            write_status(report)
            log("warn: Hermes still fails auth after repair.")
            return 4

    if args.disable_unused:
        for profile in DISABLED_PROFILES:
            disable_profile_launchd(profile)

    gateways = gateway_list()
    report["gateways_before"] = gateways
    missing = [p for p in args.profiles if not gateways.get(p)]
    if args.restart or missing:
        restart_gateways(tuple(dict.fromkeys([*missing, *args.profiles] if args.restart else missing)))
        time.sleep(3)
        gateways = gateway_list()
    report["gateways_after"] = gateways
    down = [p for p in args.profiles if not gateways.get(p)]
    if down:
        report["state"] = "gateway-down"
        report["down_profiles"] = down
        write_status(report)
        log(f"gateway-down: {', '.join(down)}")
        return 5

    report["state"] = "healthy"
    report["repaired"] = repaired
    write_status(report)
    log("healthy: Claude auth, Hermes auth, and required gateways are OK.")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default="claude-sonnet-4-6")
    parser.add_argument("--profiles", nargs="+", default=list(DEFAULT_PROFILES))
    parser.add_argument("--restart", action="store_true", help="Restart required gateways even if they are up.")
    parser.add_argument("--no-claude-smoke", dest="smoke_claude", action="store_false")
    parser.add_argument("--no-hermes-smoke", dest="smoke_hermes", action="store_false")
    parser.add_argument("--disable-unused", action="store_true", help="Disable scout/wildcard launch agents.")
    parser.add_argument(
        "--clean-cached-account",
        action="store_true",
        help="Remove cached oauthAccount metadata from ~/.claude.json.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        return doctor_once(args)
    except subprocess.TimeoutExpired as exc:
        log(f"timeout: {' '.join(exc.cmd) if isinstance(exc.cmd, list) else exc.cmd}")
        write_status({"state": "timeout", "command": exc.cmd})
        return 124
    except Exception as exc:
        log(f"error: {exc}")
        write_status({"state": "error", "error": str(exc)})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
