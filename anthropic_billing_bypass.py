"""
Claude Code OAuth bypass for hermes-agent.
==========================================

Monkey-patches hermes-agent's anthropic adapter so OAuth-authenticated
requests pass Anthropic's server-side billing validator and route to the
Claude Max/Pro subscription tier.

Tracks upstream ``griffinmartin/opencode-claude-auth`` (TypeScript) and
ports its bypass behaviors to Python.

Version history
---------------
- 1.6.0 (2026-06-16): Prefer refreshable Claude Code credentials over static
  Anthropic env/auth.json tokens, refresh expired access tokens at runtime, and
  add subscription-only env scrubbing.
- 1.5.0 (2026-05-06): Fix literal ``\\n`` escapes in system-reminder text,
  lowercase Stainless headers (matches upstream JS SDK), restore Opus 4.6
  temperature stripping, port ``repair_tool_pairs`` (upstream PR #136) and
  haiku effort stripping (upstream PR #126), lowercase tool names after
  unwrap to silence hermes auto-repair (intent of commit 6d9cade), patch
  ``normalize_response`` on both old and new hermes transports.
- 1.4.0-pr10 (2026-04-29): Hermes 0.11.0 ``AnthropicTransport`` support,
  ``mcp__hermes__`` namespacing, accountUuid → user_id metadata.
- 1.1.1 (2026-04-22): macOS Keychain mirror in installer (no module change).
- 1.1.0 (2026-04-22): PascalCase ``mcp_`` tools, ``sdk-cli`` entrypoint,
  ``advisor-tool-2026-03-01`` beta, Stainless headers, ``?beta=true``.
- 1.0.0 (2026-04-09): Billing header, system prompt relocation, prompt-
  caching beta, Opus 4.6 temperature hook.

References
----------
- https://github.com/griffinmartin/opencode-claude-auth
- PR #126: strip ``effort`` for haiku models
- PR #136: repair orphaned tool_use / tool_result pairs
- PR #148: relocate non-identity system entries to first user message
- PR #191: PascalCase tool names after ``mcp_`` prefix
- PR #207: Claude Code 2.1.112 fingerprint + ``?beta=true``
"""

from __future__ import annotations

__version__ = "1.6.0"

import hashlib
import inspect
import json
import logging
import os
import platform
import subprocess
import sys
import time
import traceback
import urllib.parse
import urllib.request
from dataclasses import replace
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("anthropic_billing_bypass")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Shared salt shipped in the Claude Code CLI binary; Anthropic's server uses
# this to verify billing-header signatures.
_BILLING_SALT = "59cf53e54c78"

# Claude Code 2.1.112+ reports ``sdk-cli`` instead of legacy ``cli``.  A
# mismatch with x-stainless-* headers routes the request to third-party
# billing.
_BILLING_ENTRYPOINT = "sdk-cli"

# Sentinel strings — entries in system[] starting with these are kept;
# everything else is relocated to the first user message.
_BILLING_PREFIX = "x-anthropic-billing-header"
_SYSTEM_IDENTITY = "You are Claude Code, Anthropic's official CLI for Claude."

# Hermes prefixes MCP tools with ``mcp_``.  We rewrite that to the standard
# ``mcp__<server>__<tool>`` namespace Anthropic expects from real Claude Code,
# using ``hermes`` as the server name.
_MCP_PREFIX = "mcp_"
_MCP_HERMES_NAMESPACE = "mcp__hermes__"

# Stainless-generated SDK headers Claude Code 2.1.112 sends.  Lowercase to
# match the JS SDK output exactly (HTTP headers are case-insensitive but
# upstream's spoof uses lowercase, and so does our pre-merge code).
_STAINLESS_PACKAGE_VERSION = "0.81.0"
_STAINLESS_NODE_VERSION = "v22.11.0"

# OAuth-only beta flags appended on top of hermes-agent's built-in
# ``claude-code-20250219`` and ``oauth-2025-04-20``.
_EXTRA_OAUTH_BETAS = [
    "prompt-caching-scope-2026-01-05",
    "advisor-tool-2026-03-01",
]

_STATIC_ANTHROPIC_ENV_VARS = (
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_TOKEN",
    "CLAUDE_CODE_OAUTH_TOKEN",
)
_ANTHROPIC_OAUTH_CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
_CLAUDE_CODE_REFRESH_UA_VERSION = "2.1.112"


# ---------------------------------------------------------------------------
# Refreshable Claude Code OAuth token resolution
# ---------------------------------------------------------------------------


def _strict_subscription_mode() -> bool:
    """Default to subscription-only auth for this patch.

    Set ``HERMES_CLAUDE_AUTH_STRICT_SUBSCRIPTION=0`` to preserve Hermes's
    normal API-key fallback behavior.
    """
    value = os.environ.get("HERMES_CLAUDE_AUTH_STRICT_SUBSCRIPTION", "1")
    return value.strip().lower() not in {"0", "false", "no", "off"}


def _is_oauth_like_token(token: Any) -> bool:
    if not isinstance(token, str) or not token:
        return False
    if token.startswith("sk-ant-api"):
        return False
    return token.startswith(("sk-ant-", "eyJ", "cc-"))


def _is_direct_anthropic_endpoint(base_url: Any) -> bool:
    if not base_url:
        return True
    normalized = str(base_url).strip().rstrip("/").lower()
    return not normalized or "anthropic.com" in normalized


def _credential_access_token(creds: Any) -> str:
    if not isinstance(creds, dict):
        return ""
    token = creds.get("accessToken") or creds.get("access_token") or ""
    return token.strip() if isinstance(token, str) else ""


def _credential_refresh_token(creds: Any) -> str:
    if not isinstance(creds, dict):
        return ""
    token = creds.get("refreshToken") or creds.get("refresh_token") or ""
    return token.strip() if isinstance(token, str) else ""


def _credential_expires_at_ms(creds: Any) -> int:
    if not isinstance(creds, dict):
        return 0
    raw = creds.get("expiresAt") or creds.get("expires_at_ms") or 0
    try:
        return int(raw)
    except (TypeError, ValueError):
        return 0


def _credential_is_valid(creds: Any) -> bool:
    token = _credential_access_token(creds)
    if not token:
        return False
    expires_at_ms = _credential_expires_at_ms(creds)
    if not expires_at_ms:
        return True
    return int(time.time() * 1000) < (expires_at_ms - 60_000)


def _parse_claude_code_credentials_payload(raw: str, source: str) -> Optional[Dict[str, Any]]:
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        try:
            data = json.loads(bytes.fromhex(raw.strip()).decode())
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            return None
    oauth_data = data.get("claudeAiOauth") if isinstance(data, dict) else None
    if not isinstance(oauth_data, dict):
        return None
    access_token = oauth_data.get("accessToken")
    if not isinstance(access_token, str) or not access_token:
        return None
    return {
        "accessToken": access_token,
        "refreshToken": oauth_data.get("refreshToken", ""),
        "expiresAt": oauth_data.get("expiresAt", 0),
        "scopes": oauth_data.get("scopes", []),
        "source": source,
    }


def _read_claude_code_credentials_from_keychain() -> Optional[Dict[str, Any]]:
    if platform.system() != "Darwin":
        return None
    try:
        result = subprocess.run(
            ["security", "find-generic-password", "-s", "Claude Code-credentials", "-w"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return _parse_claude_code_credentials_payload(
        result.stdout.strip(), "macos_keychain"
    )


def _read_claude_code_credentials_file() -> Optional[Dict[str, Any]]:
    path = Path.home() / ".claude" / ".credentials.json"
    try:
        return _parse_claude_code_credentials_payload(
            path.read_text(encoding="utf-8"), "claude_code_credentials_file"
        )
    except OSError:
        return None


def _read_local_claude_code_credentials() -> Optional[Dict[str, Any]]:
    candidates = [
        creds
        for creds in (
            _read_claude_code_credentials_from_keychain(),
            _read_claude_code_credentials_file(),
        )
        if creds
    ]
    if not candidates:
        return None
    return max(
        candidates,
        key=lambda creds: (
            _credential_expires_at_ms(creds),
            bool(_credential_refresh_token(creds)),
        ),
    )


def _refresh_anthropic_oauth_token(refresh_token: str) -> Optional[Dict[str, Any]]:
    if not refresh_token:
        return None

    data = urllib.parse.urlencode({
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": _ANTHROPIC_OAUTH_CLIENT_ID,
    }).encode()
    endpoints = (
        "https://platform.claude.com/v1/oauth/token",
        "https://console.anthropic.com/v1/oauth/token",
    )
    for endpoint in endpoints:
        req = urllib.request.Request(
            endpoint,
            data=data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": (
                    f"claude-cli/{_CLAUDE_CODE_REFRESH_UA_VERSION} (external, cli)"
                ),
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                payload = json.loads(resp.read().decode())
        except Exception as exc:
            logger.debug("Claude Code OAuth refresh failed at %s: %s", endpoint, exc)
            continue

        access_token = payload.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            continue
        expires_in = payload.get("expires_in", 3600)
        try:
            expires_in = int(expires_in)
        except (TypeError, ValueError):
            expires_in = 3600
        return {
            "accessToken": access_token,
            "refreshToken": payload.get("refresh_token", refresh_token),
            "expiresAt": int(time.time() * 1000) + (expires_in * 1000),
        }
    return None


def _write_claude_code_credentials_file(creds: Dict[str, Any]) -> None:
    access_token = _credential_access_token(creds)
    refresh_token = _credential_refresh_token(creds)
    if not access_token:
        return
    path = Path.home() / ".claude" / ".credentials.json"
    try:
        existing: Dict[str, Any] = {}
        if path.exists():
            existing = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(existing, dict):
                existing = {}
    except (OSError, json.JSONDecodeError):
        existing = {}

    old_oauth = existing.get("claudeAiOauth")
    old_scopes = old_oauth.get("scopes") if isinstance(old_oauth, dict) else None
    oauth_data: Dict[str, Any] = {
        "accessToken": access_token,
        "refreshToken": refresh_token,
        "expiresAt": _credential_expires_at_ms(creds),
    }
    scopes = creds.get("scopes") if isinstance(creds, dict) else None
    if isinstance(scopes, list):
        oauth_data["scopes"] = scopes
    elif isinstance(old_scopes, list):
        oauth_data["scopes"] = old_scopes

    existing["claudeAiOauth"] = oauth_data
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(".tmp")
    tmp_path.write_text(json.dumps(existing, indent=2), encoding="utf-8")
    tmp_path.replace(path)
    path.chmod(0o600)

    if platform.system() == "Darwin":
        try:
            subprocess.run(
                [
                    "security",
                    "add-generic-password",
                    "-U",
                    "-a",
                    os.environ.get("USER", Path.home().name),
                    "-s",
                    "Claude Code-credentials",
                    "-w",
                    json.dumps(existing, separators=(",", ":")),
                ],
                capture_output=True,
                text=True,
                timeout=5,
                check=True,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            logger.debug("Could not persist refreshed credentials to Keychain: %s", exc)


def _resolve_refreshable_token_locally() -> Optional[str]:
    creds = _read_local_claude_code_credentials()
    if _credential_is_valid(creds):
        return _credential_access_token(creds)
    refresh_token = _credential_refresh_token(creds)
    if not refresh_token:
        return None
    refreshed = _refresh_anthropic_oauth_token(refresh_token)
    if not refreshed:
        return None
    try:
        _write_claude_code_credentials_file(refreshed)
    except OSError as exc:
        logger.debug("Could not persist refreshed Claude Code credentials: %s", exc)
    return _credential_access_token(refreshed)


def _force_refresh_local_claude_code_credentials() -> Optional[Dict[str, Any]]:
    """Refresh Claude Code OAuth even when the local expiry still looks valid.

    Anthropic can reject an access token with 401 before ``expiresAt`` catches
    up, especially after another process rotates the token pair.  Reactive
    auth recovery must therefore refresh on the server signal, not only on the
    local timestamp.
    """
    creds = _read_local_claude_code_credentials()
    refresh_token = _credential_refresh_token(creds)
    if not refresh_token:
        return None
    refreshed = _refresh_anthropic_oauth_token(refresh_token)
    if not refreshed:
        return None
    try:
        _write_claude_code_credentials_file(refreshed)
    except OSError as exc:
        logger.debug("Could not persist force-refreshed Claude Code credentials: %s", exc)
    return refreshed


def _resolve_refreshable_token(aa_module: Any) -> Optional[str]:
    """Resolve the freshest Claude Code OAuth token available.

    New Hermes builds expose this through ``resolve_anthropic_token`` and
    ``read_claude_code_credentials``.  The local fallback keeps this patch
    useful on older installations.
    """
    reader = getattr(aa_module, "read_claude_code_credentials", None)
    creds = None
    if callable(reader):
        try:
            creds = reader()
        except Exception as exc:
            logger.debug("Hermes read_claude_code_credentials failed: %s", exc)
    if _credential_is_valid(creds):
        return _credential_access_token(creds)

    refresh_token = _credential_refresh_token(creds)
    if refresh_token:
        refresh_pure = getattr(aa_module, "refresh_anthropic_oauth_pure", None)
        writer = getattr(aa_module, "_write_claude_code_credentials", None)
        if callable(refresh_pure):
            try:
                refreshed = refresh_pure(refresh_token, use_json=False)
                access_token = refreshed.get("access_token")
                if isinstance(access_token, str) and access_token:
                    if callable(writer):
                        try:
                            writer(
                                access_token,
                                refreshed.get("refresh_token", refresh_token),
                                refreshed.get("expires_at_ms", 0),
                            )
                        except Exception as exc:
                            logger.debug("Hermes credential write failed: %s", exc)
                    return access_token
            except Exception as exc:
                logger.debug("Hermes OAuth refresh failed: %s", exc)

    return _resolve_refreshable_token_locally()


def _scrub_static_anthropic_env_if_possible(aa_module: Any) -> bool:
    if not _strict_subscription_mode():
        return False
    token = _resolve_refreshable_token(aa_module)
    if not token:
        return False
    removed = False
    for key in _STATIC_ANTHROPIC_ENV_VARS:
        if os.environ.get(key):
            os.environ.pop(key, None)
            removed = True
    if removed:
        sys.stderr.write(
            "[anthropic_billing_bypass] Ignoring static Anthropic env auth; "
            "using refreshable Claude Code credentials\n"
        )
    return removed


def _install_token_resolution_hooks(aa_module: Any) -> bool:
    any_installed = False

    if not getattr(aa_module, "_CLAUDE_CODE_TOKEN_RESOLVE_PATCHED", False):
        original_resolve = getattr(aa_module, "resolve_anthropic_token", None)
        if callable(original_resolve):
            def patched_resolve_anthropic_token(*args: Any, **kwargs: Any) -> Optional[str]:
                if _strict_subscription_mode():
                    fresh = _resolve_refreshable_token(aa_module)
                    if fresh:
                        return fresh
                token = original_resolve(*args, **kwargs)
                if _is_oauth_like_token(token):
                    fresh = _resolve_refreshable_token(aa_module)
                    if fresh:
                        return fresh
                return token

            patched_resolve_anthropic_token.__name__ = original_resolve.__name__
            patched_resolve_anthropic_token.__qualname__ = getattr(
                original_resolve, "__qualname__", original_resolve.__name__
            )
            patched_resolve_anthropic_token.__doc__ = original_resolve.__doc__
            patched_resolve_anthropic_token.__wrapped__ = original_resolve  # type: ignore[attr-defined]
            aa_module.resolve_anthropic_token = patched_resolve_anthropic_token
            aa_module._CLAUDE_CODE_TOKEN_RESOLVE_PATCHED = True  # type: ignore[attr-defined]
            any_installed = True

    if not getattr(aa_module, "_CLAUDE_CODE_CLIENT_TOKEN_PATCHED", False):
        original_client = getattr(aa_module, "build_anthropic_client", None)
        if callable(original_client):
            def patched_build_anthropic_client(
                api_key: str,
                base_url: str = None,
                *args: Any,
                **kwargs: Any,
            ) -> Any:
                effective_key = api_key
                if _is_direct_anthropic_endpoint(base_url):
                    fresh = _resolve_refreshable_token(aa_module)
                    if fresh and (
                        _strict_subscription_mode()
                        or not effective_key
                        or _is_oauth_like_token(effective_key)
                    ):
                        if fresh != effective_key:
                            logger.info(
                                "Using fresh Claude Code OAuth token for Anthropic client"
                            )
                        effective_key = fresh
                return original_client(effective_key, base_url, *args, **kwargs)

            patched_build_anthropic_client.__name__ = original_client.__name__
            patched_build_anthropic_client.__qualname__ = getattr(
                original_client, "__qualname__", original_client.__name__
            )
            patched_build_anthropic_client.__doc__ = original_client.__doc__
            patched_build_anthropic_client.__wrapped__ = original_client  # type: ignore[attr-defined]
            aa_module.build_anthropic_client = patched_build_anthropic_client
            aa_module._CLAUDE_CODE_CLIENT_TOKEN_PATCHED = True  # type: ignore[attr-defined]
            any_installed = True

    if any_installed:
        sys.stderr.write(
            "[anthropic_billing_bypass] Token refresh hook installed\n"
        )
    return any_installed


def _install_credential_pool_401_hook() -> bool:
    """Patch Hermes credential pools so Claude Code 401 forces token refresh.

    Hermes already refreshes OAuth entries when their local expiry is near, but
    a rejected access token can still have a future ``expiresAt``.  Without this
    hook a single-entry ``claude_code`` pool is marked exhausted and the task
    dies.  On HTTP 401 we force-refresh the Claude Code credential, update the
    pool entry in-place, and hand it back to the retry loop as the next usable
    credential.
    """
    try:
        from agent import credential_pool as cp  # type: ignore[import-not-found]
    except Exception as exc:
        logger.debug("Cannot import agent.credential_pool for 401 hook: %s", exc)
        return False

    pool_cls = getattr(cp, "CredentialPool", None)
    if pool_cls is None or getattr(pool_cls, "_CLAUDE_CODE_401_REFRESH_PATCHED", False):
        return False

    original_mark = getattr(pool_cls, "mark_exhausted_and_rotate", None)
    if not callable(original_mark):
        return False

    status_ok = getattr(cp, "STATUS_OK", "ok")

    def _refresh_current_claude_code_entry(self: Any, status_code: Optional[int]) -> Optional[Any]:
        if getattr(self, "provider", None) != "anthropic" or status_code != 401:
            return None
        entry = None
        try:
            entry = self.current() or self._select_unlocked()
        except Exception as exc:
            logger.debug("Claude Code 401 hook could not read pool current entry: %s", exc)
            return None
        if entry is None or getattr(entry, "source", None) != "claude_code":
            return None

        refreshed = _force_refresh_local_claude_code_credentials()
        if not refreshed:
            return None

        access_token = _credential_access_token(refreshed)
        refresh_token = _credential_refresh_token(refreshed)
        if not access_token:
            return None

        try:
            updated = replace(
                entry,
                access_token=access_token,
                refresh_token=refresh_token or getattr(entry, "refresh_token", None),
                expires_at_ms=_credential_expires_at_ms(refreshed),
                last_status=status_ok,
                last_status_at=None,
                last_error_code=None,
                last_error_reason=None,
                last_error_message=None,
                last_error_reset_at=None,
            )
            self._replace_entry(entry, updated)
            self._current_id = getattr(updated, "id", getattr(entry, "id", None))
            self._persist()
            logger.info(
                "credential pool: force-refreshed Claude Code OAuth after 401; retrying same entry"
            )
            return updated
        except Exception as exc:
            logger.debug("Claude Code 401 hook failed to update pool entry: %s", exc)
            return None

    def patched_mark_exhausted_and_rotate(
        self: Any,
        *,
        status_code: Optional[int],
        error_context: Optional[Dict[str, Any]] = None,
    ) -> Optional[Any]:
        if status_code == 401:
            refreshed_entry = _refresh_current_claude_code_entry(self, status_code)
            if refreshed_entry is not None:
                return refreshed_entry
        return original_mark(
            self,
            status_code=status_code,
            error_context=error_context,
        )

    patched_mark_exhausted_and_rotate.__name__ = original_mark.__name__
    patched_mark_exhausted_and_rotate.__qualname__ = getattr(
        original_mark, "__qualname__", original_mark.__name__
    )
    patched_mark_exhausted_and_rotate.__doc__ = original_mark.__doc__
    patched_mark_exhausted_and_rotate.__wrapped__ = original_mark  # type: ignore[attr-defined]
    pool_cls.mark_exhausted_and_rotate = patched_mark_exhausted_and_rotate
    pool_cls._CLAUDE_CODE_401_REFRESH_PATCHED = True  # type: ignore[attr-defined]
    sys.stderr.write("[anthropic_billing_bypass] Credential pool 401 refresh hook installed\n")
    return True


# ---------------------------------------------------------------------------
# Tool name transforms (upstream PR #191 + hermes namespacing)
# ---------------------------------------------------------------------------


def _uppercase_first(name: str) -> str:
    if not isinstance(name, str) or not name:
        return name
    return name[0].upper() + name[1:]


def _lowercase_first(name: str) -> str:
    """Used after MCP-namespace unwrap so hermes's tool dispatcher resolves
    the registered snake_case name without its auto-repair warning."""
    if not isinstance(name, str) or not name:
        return name
    return name[0].lower() + name[1:]


def _pascalcase_mcp_name(name: str) -> str:
    """Rewrite ``mcp_foo_bar`` → ``mcp_Foo_bar``.  Mirrors upstream PR #191
    exactly; exposed for tests.  In-flight wrapping uses ``_wrap_tool_name``
    which adds the hermes namespace too.
    """
    if not isinstance(name, str) or not name.startswith(_MCP_PREFIX):
        return name
    rest = name[len(_MCP_PREFIX):]
    if not rest or not rest[0].islower():
        return name
    return _MCP_PREFIX + rest[0].upper() + rest[1:]


def _wrap_tool_name(name: str) -> str:
    if not isinstance(name, str) or not name:
        return name
    if name.startswith(_MCP_HERMES_NAMESPACE):
        return name
    base = name[len(_MCP_PREFIX):] if name.startswith(_MCP_PREFIX) else name
    return _MCP_HERMES_NAMESPACE + _uppercase_first(base)


def _unwrap_tool_name(name: Any) -> Any:
    if not isinstance(name, str):
        return name
    if name.startswith(_MCP_HERMES_NAMESPACE):
        return _lowercase_first(name[len(_MCP_HERMES_NAMESPACE):])
    # Hermes's transport may already strip ``mcp_``, leaving ``_hermes__<tool>``.
    fallback_prefix = _MCP_HERMES_NAMESPACE[len(_MCP_PREFIX):]  # "_hermes__"
    if name.startswith(fallback_prefix):
        return _lowercase_first(name[len(fallback_prefix):])
    return name


def _rewrite_tool_names(api_kwargs: Dict[str, Any]) -> None:
    tools = api_kwargs.get("tools")
    if isinstance(tools, list):
        for tool in tools:
            if isinstance(tool, dict) and "name" in tool:
                tool["name"] = _wrap_tool_name(tool.get("name") or "")

    messages = api_kwargs.get("messages")
    if isinstance(messages, list):
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            content = msg.get("content")
            if not isinstance(content, list):
                continue
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_use":
                    block["name"] = _wrap_tool_name(block.get("name") or "")


# ---------------------------------------------------------------------------
# Account metadata (commit f10468a — accountUuid → user_id)
# ---------------------------------------------------------------------------


def _read_claude_config() -> Dict[str, Any]:
    path = os.path.expanduser("~/.claude.json")
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def _get_account_metadata() -> Dict[str, Any]:
    """Return Anthropic-compatible request metadata.

    ``metadata.account_uuid`` was rejected with HTTP 400 in 2026-04-29; only
    ``user_id`` is accepted.  Returns ``{}`` when the config or oauthAccount
    block is missing so the caller can skip injecting metadata entirely.
    """
    config = _read_claude_config()
    oauth = config.get("oauthAccount") if isinstance(config, dict) else None
    metadata: Dict[str, Any] = {}
    if isinstance(oauth, dict) and isinstance(oauth.get("accountUuid"), str):
        metadata["user_id"] = oauth["accountUuid"]
    return metadata


# ---------------------------------------------------------------------------
# Billing header signing (mirror upstream src/signing.ts)
# ---------------------------------------------------------------------------


def _extract_first_user_message_text(messages: List[Dict[str, Any]]) -> str:
    """Mirrors Claude Code's K19() — first text block of the first user
    message.  Returns ``""`` when none exists; required for billing-header
    signature determinism."""
    for msg in messages:
        if not isinstance(msg, dict) or msg.get("role") != "user":
            continue
        content = msg.get("content")
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    text = block.get("text")
                    if isinstance(text, str) and text:
                        return text
        return ""
    return ""


def _compute_cch(message_text: str) -> str:
    return hashlib.sha256(message_text.encode("utf-8")).hexdigest()[:5]


def _compute_version_suffix(message_text: str, version: str) -> str:
    """SHA-256(salt + chars[4,7,20] + version)[:3]; pads with ``"0"`` when
    the message is shorter than each index.  Matches Claude Code's signing
    routine; deviations break OAuth billing routing."""
    sampled = "".join(
        message_text[i] if i < len(message_text) else "0" for i in (4, 7, 20)
    )
    input_str = f"{_BILLING_SALT}{sampled}{version}"
    return hashlib.sha256(input_str.encode("utf-8")).hexdigest()[:3]


def _build_billing_header_value(
    messages: List[Dict[str, Any]],
    version: str,
    entrypoint: str,
) -> str:
    text = _extract_first_user_message_text(messages)
    suffix = _compute_version_suffix(text, version)
    cch = _compute_cch(text)
    return (
        f"x-anthropic-billing-header: "
        f"cc_version={version}.{suffix}; "
        f"cc_entrypoint={entrypoint}; "
        f"cch={cch};"
    )


# ---------------------------------------------------------------------------
# Stainless SDK spoof headers (lowercase, matches upstream src/index.ts)
# ---------------------------------------------------------------------------


def _stainless_arch() -> str:
    machine = (platform.machine() or "").lower()
    if machine in ("x86_64", "amd64"):
        return "x64"
    if machine in ("arm64", "aarch64"):
        return "arm64"
    if machine in ("i386", "i686"):
        return "ia32"
    return machine or "unknown"


def _stainless_os() -> str:
    return {"Darwin": "MacOS", "Linux": "Linux", "Windows": "Windows"}.get(
        platform.system(), platform.system() or "Unknown"
    )


def _build_spoof_headers() -> Dict[str, str]:
    """Headers real Claude Code 2.1.112 sends that hermes-agent does not.

    The Anthropic SDK (Stainless-generated) automatically attaches
    ``x-stainless-*`` identifying headers.  The validator cross-references
    these with the billing header's ``cc_entrypoint``; absent or mismatched
    values flag the request as third-party.  Lowercase to match upstream's
    JS SDK output.
    """
    return {
        "anthropic-dangerous-direct-browser-access": "true",
        "x-stainless-arch": _stainless_arch(),
        "x-stainless-lang": "js",
        "x-stainless-os": _stainless_os(),
        "x-stainless-package-version": _STAINLESS_PACKAGE_VERSION,
        "x-stainless-retry-count": "0",
        "x-stainless-runtime": "node",
        "x-stainless-runtime-version": _STAINLESS_NODE_VERSION,
        "x-stainless-timeout": "600",
    }


def _merge_spoof_extras(api_kwargs: Dict[str, Any]) -> None:
    """Existing extra_headers/extra_query take precedence so hermes's own
    headers (e.g. fast-mode beta) survive — additive spoof only."""
    merged_headers: Dict[str, str] = dict(_build_spoof_headers())
    existing_headers = api_kwargs.get("extra_headers")
    if isinstance(existing_headers, dict):
        for k, v in existing_headers.items():
            merged_headers[k] = v
    api_kwargs["extra_headers"] = merged_headers

    merged_query: Dict[str, Any] = {"beta": "true"}
    existing_query = api_kwargs.get("extra_query")
    if isinstance(existing_query, dict):
        for k, v in existing_query.items():
            merged_query[k] = v
    api_kwargs["extra_query"] = merged_query


# ---------------------------------------------------------------------------
# Tool pair repair (upstream PR #136)
# ---------------------------------------------------------------------------


def _repair_tool_pairs(messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Strip orphaned ``tool_use`` / ``tool_result`` blocks.

    Anthropic rejects requests where a ``tool_use`` has no matching
    ``tool_result`` (or vice versa).  Long conversations or partial summaries
    can leave these orphans behind; this function removes them and drops
    messages whose content becomes empty as a result.

    Mirrors upstream ``src/transforms.ts::repairToolPairs``.  Returns the
    original list when nothing needs repairing so callers can detect a no-op
    via identity comparison.
    """
    if not isinstance(messages, list):
        return messages

    tool_use_ids: Set[str] = set()
    tool_result_ids: Set[str] = set()

    for msg in messages:
        if not isinstance(msg, dict):
            continue
        content = msg.get("content")
        if not isinstance(content, list):
            continue
        for block in content:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "tool_use":
                bid = block.get("id")
                if isinstance(bid, str):
                    tool_use_ids.add(bid)
            elif block.get("type") == "tool_result":
                tuid = block.get("tool_use_id")
                if isinstance(tuid, str):
                    tool_result_ids.add(tuid)

    orphaned_uses = tool_use_ids - tool_result_ids
    orphaned_results = tool_result_ids - tool_use_ids

    if not orphaned_uses and not orphaned_results:
        return messages

    repaired: List[Dict[str, Any]] = []
    for msg in messages:
        if not isinstance(msg, dict):
            repaired.append(msg)
            continue
        content = msg.get("content")
        if not isinstance(content, list):
            repaired.append(msg)
            continue
        filtered: List[Any] = []
        for block in content:
            if not isinstance(block, dict):
                filtered.append(block)
                continue
            if (
                block.get("type") == "tool_use"
                and block.get("id") in orphaned_uses
            ):
                continue
            if (
                block.get("type") == "tool_result"
                and block.get("tool_use_id") in orphaned_results
            ):
                continue
            filtered.append(block)
        if filtered:
            repaired.append({**msg, "content": filtered})
    return repaired


# ---------------------------------------------------------------------------
# Effort stripping for haiku (upstream PR #126)
# ---------------------------------------------------------------------------


def _model_disables_effort(model: str) -> bool:
    if not isinstance(model, str):
        return False
    return "haiku" in model.lower()


def _strip_effort(api_kwargs: Dict[str, Any]) -> None:
    """Remove ``effort`` for haiku (rejected with HTTP 400).  Drops the
    parent dict if it becomes empty so we don't send ``"output_config": {}``
    which trips a different validator.  Mirrors upstream PR #126."""
    model = api_kwargs.get("model") or ""
    if not _model_disables_effort(model):
        return

    output_config = api_kwargs.get("output_config")
    if isinstance(output_config, dict) and "effort" in output_config:
        del output_config["effort"]
        if not output_config:
            del api_kwargs["output_config"]

    thinking = api_kwargs.get("thinking")
    if isinstance(thinking, dict) and "effort" in thinking:
        del thinking["effort"]
        if not thinking:
            del api_kwargs["thinking"]


# ---------------------------------------------------------------------------
# Temperature fix for Opus 4.6 adaptive thinking (preserved from 1.0.0)
# ---------------------------------------------------------------------------


def _model_supports_adaptive_thinking(model: str) -> bool:
    if not isinstance(model, str):
        return False
    return "4-6" in model or "4.6" in model


def _fix_temperature_for_oauth_adaptive(
    api_kwargs: Dict[str, Any],
    *,
    site: str,
) -> None:
    """Strip non-default ``temperature`` from OAuth requests on Opus 4.6.

    Opus 4.6 with implicit adaptive thinking rejects ``temperature != 1``
    with HTTP 400; dropping the parameter lets the API use its default.
    """
    if "temperature" not in api_kwargs:
        return
    temp = api_kwargs.get("temperature")
    if temp == 1 or temp == 1.0:
        return
    model = api_kwargs.get("model") or ""
    if not _model_supports_adaptive_thinking(model):
        return
    del api_kwargs["temperature"]
    logger.info(
        "Dropped temperature=%r for OAuth adaptive-thinking model %r (site=%s)",
        temp,
        model,
        site,
    )


# ---------------------------------------------------------------------------
# System prompt relocation (upstream PR #148)
# ---------------------------------------------------------------------------


def _prepend_to_first_user_message(
    messages: List[Dict[str, Any]],
    texts: List[str],
) -> None:
    if not texts:
        return
    combined = "\n\n".join(
        f"<system-reminder>\n{t}\n</system-reminder>" for t in texts
    )
    for i, msg in enumerate(messages):
        if not isinstance(msg, dict) or msg.get("role") != "user":
            continue
        content = msg.get("content")
        if isinstance(content, str):
            new_text = f"{combined}\n\n{content}" if content else combined
            messages[i] = {**msg, "content": [{"type": "text", "text": new_text}]}
            return
        if isinstance(content, list):
            new_content = list(content)
            for j, block in enumerate(new_content):
                if isinstance(block, dict) and block.get("type") == "text":
                    existing = block.get("text") or ""
                    new_content[j] = {
                        **block,
                        "text": f"{combined}\n\n{existing}" if existing else combined,
                    }
                    messages[i] = {**msg, "content": new_content}
                    return
            new_content.insert(0, {"type": "text", "text": combined})
            messages[i] = {**msg, "content": new_content}
            return
        messages[i] = {**msg, "content": [{"type": "text", "text": combined}]}
        return


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


def apply_claude_code_bypass(api_kwargs: Dict[str, Any], version: str) -> None:
    """Apply all OAuth bypass transforms in place.

    Idempotent: stale billing headers are dropped before injecting the new
    one and duplicate identity entries are removed.  Safe to call on
    requests that have already been bypassed.
    """
    messages = api_kwargs.get("messages")
    if not isinstance(messages, list) or not messages:
        return

    # Repair orphaned tool pairs first; downstream transforms assume valid
    # tool_use/tool_result pairing.
    repaired = _repair_tool_pairs(messages)
    if repaired is not messages:
        api_kwargs["messages"] = repaired
        messages = repaired

    raw_system = api_kwargs.get("system")
    if raw_system is None:
        system: List[Any] = []
    elif isinstance(raw_system, str):
        system = [{"type": "text", "text": raw_system}] if raw_system else []
    elif isinstance(raw_system, list):
        system = list(raw_system)
    else:
        logger.warning(
            "Unexpected system type %s; skipping bypass",
            type(raw_system).__name__,
        )
        return

    # Build billing header from ORIGINAL messages (before relocation mutates).
    try:
        billing_value = _build_billing_header_value(
            messages, version, _BILLING_ENTRYPOINT
        )
    except Exception as exc:
        logger.warning("Failed to build billing header: %s", exc)
        return
    billing_entry = {"type": "text", "text": billing_value}

    kept: List[Any] = []
    moved_texts: List[str] = []
    identity_seen = False

    for entry in system:
        if not isinstance(entry, dict):
            kept.append(entry)
            continue
        if entry.get("type") != "text":
            kept.append(entry)
            continue
        text = entry.get("text") or ""
        if text.startswith(_BILLING_PREFIX):
            continue  # stale billing header — drop
        if text.startswith(_SYSTEM_IDENTITY):
            if identity_seen:
                continue  # duplicate — drop
            identity_seen = True
            rest = text[len(_SYSTEM_IDENTITY):].lstrip("\n")
            kept.append({"type": "text", "text": _SYSTEM_IDENTITY})
            if rest:
                moved_texts.append(rest)
            continue
        if text:
            moved_texts.append(text)

    if not identity_seen:
        kept.insert(0, {"type": "text", "text": _SYSTEM_IDENTITY})

    api_kwargs["system"] = [billing_entry] + kept

    if moved_texts:
        _prepend_to_first_user_message(messages, moved_texts)

    _rewrite_tool_names(api_kwargs)
    _merge_spoof_extras(api_kwargs)
    _strip_effort(api_kwargs)
    _fix_temperature_for_oauth_adaptive(api_kwargs, site="build_kwargs")

    metadata = _get_account_metadata()
    if metadata:
        existing_meta = api_kwargs.get("metadata")
        if isinstance(existing_meta, dict):
            for k, v in metadata.items():
                existing_meta.setdefault(k, v)
        else:
            api_kwargs["metadata"] = metadata


# ---------------------------------------------------------------------------
# Monkey-patch installation
# ---------------------------------------------------------------------------


def _get_version_safely(aa_module: Any) -> str:
    getter = getattr(aa_module, "_get_claude_code_version", None)
    if callable(getter):
        try:
            version = getter()
            if isinstance(version, str) and version and version[0].isdigit():
                return version
        except Exception:
            pass
    fallback = getattr(aa_module, "_CLAUDE_CODE_VERSION_FALLBACK", None)
    if isinstance(fallback, str) and fallback:
        return fallback
    return "2.1.112"


def _install_response_pascalcase_unhook(
    aa_module: Any, force: bool = False
) -> bool:
    """Patch hermes's response normalizer to unwrap ``mcp__hermes__Foo`` back
    to ``foo`` and lowercase the first character so the tool dispatcher
    resolves the original snake_case name without auto-repair noise.

    Patches both:
      - ``aa_module.normalize_anthropic_response`` (pre-0.11 hermes)
      - ``agent.transports.anthropic.AnthropicTransport.normalize_response``
        (hermes 0.11+)

    Returns True if at least one hook succeeded.
    """
    any_installed = False

    # --- Old hermes: normalize_anthropic_response on the adapter module ---
    original_normalize = getattr(aa_module, "normalize_anthropic_response", None)
    already_old = getattr(aa_module, "_CLAUDE_CODE_RESPONSE_UNHOOK_APPLIED", False)
    if callable(original_normalize) and (force or not already_old):
        def patched_normalize(
            response: Any, strip_tool_prefix: bool = False, **kwargs: Any
        ) -> Any:
            result = original_normalize(
                response, strip_tool_prefix=strip_tool_prefix, **kwargs
            )
            try:
                assistant_message, _finish = result
            except (TypeError, ValueError):
                return result
            tool_calls = getattr(assistant_message, "tool_calls", None)
            if not tool_calls:
                return result
            for tc in tool_calls:
                fn = getattr(tc, "function", None)
                if fn is None:
                    name = getattr(tc, "name", None)
                    if isinstance(name, str):
                        try:
                            tc.name = _unwrap_tool_name(name)
                        except Exception:
                            pass
                    continue
                fn_name = getattr(fn, "name", None)
                if isinstance(fn_name, str):
                    try:
                        fn.name = _unwrap_tool_name(fn_name)
                    except Exception:
                        pass
            return result

        patched_normalize.__name__ = original_normalize.__name__
        patched_normalize.__qualname__ = getattr(
            original_normalize, "__qualname__", original_normalize.__name__
        )
        patched_normalize.__doc__ = original_normalize.__doc__
        patched_normalize.__wrapped__ = original_normalize  # type: ignore[attr-defined]

        aa_module.normalize_anthropic_response = patched_normalize
        aa_module._CLAUDE_CODE_RESPONSE_UNHOOK_APPLIED = True  # type: ignore[attr-defined]
        sys.stderr.write(
            "[anthropic_billing_bypass] Adapter unwrap hook installed\n"
        )
        any_installed = True
    elif callable(original_normalize) and already_old:
        any_installed = True  # already installed in a previous call

    # --- New hermes: AnthropicTransport.normalize_response ---
    try:
        from agent.transports import anthropic as at  # type: ignore[import-not-found]
        cls = getattr(at, "AnthropicTransport", None)
    except Exception as exc:
        logger.debug(
            "AnthropicTransport not importable (%s); skipping transport hook",
            exc,
        )
        cls = None

    if cls is not None:
        already_new = getattr(cls, "_HERMES_MCP_UNWRAP_APPLIED", False)
        if force or not already_new:
            original_transport_normalize = getattr(cls, "normalize_response", None)
            if callable(original_transport_normalize):
                def patched_transport_normalize(
                    self: Any, response: Any, *args: Any, **kwargs: Any
                ) -> Any:
                    result = original_transport_normalize(
                        self, response, *args, **kwargs
                    )
                    tool_calls = getattr(result, "tool_calls", None)
                    if tool_calls:
                        for tc in tool_calls:
                            name = getattr(tc, "name", None)
                            if isinstance(name, str):
                                try:
                                    tc.name = _unwrap_tool_name(name)
                                except Exception:
                                    pass
                            fn = getattr(tc, "function", None)
                            fn_name = (
                                getattr(fn, "name", None) if fn is not None else None
                            )
                            if isinstance(fn_name, str):
                                try:
                                    fn.name = _unwrap_tool_name(fn_name)
                                except Exception:
                                    pass
                    return result

                patched_transport_normalize.__name__ = (
                    original_transport_normalize.__name__
                )
                patched_transport_normalize.__qualname__ = getattr(
                    original_transport_normalize,
                    "__qualname__",
                    original_transport_normalize.__name__,
                )
                patched_transport_normalize.__doc__ = (
                    original_transport_normalize.__doc__
                )
                patched_transport_normalize.__wrapped__ = (  # type: ignore[attr-defined]
                    original_transport_normalize
                )

                cls.normalize_response = patched_transport_normalize
                cls._HERMES_MCP_UNWRAP_APPLIED = True  # type: ignore[attr-defined]
                sys.stderr.write(
                    "[anthropic_billing_bypass] Transport unwrap hook installed\n"
                )
                any_installed = True
        else:
            any_installed = True

    return any_installed


def apply_patches(anthropic_adapter_module: Any = None) -> bool:
    """Install the bypass on hermes-agent's anthropic adapter.

    Idempotent.  Returns False if hermes-agent's API is incompatible with
    this patch (e.g. ``build_anthropic_kwargs`` missing or signature changed).
    """
    aa = anthropic_adapter_module
    if aa is None:
        try:
            from agent import anthropic_adapter as aa  # type: ignore[import-not-found,no-redef]
        except ImportError as exc:
            logger.warning("Cannot import agent.anthropic_adapter: %s", exc)
            return False

    if getattr(aa, "_CLAUDE_CODE_BYPASS_APPLIED", False):
        _scrub_static_anthropic_env_if_possible(aa)
        _install_token_resolution_hooks(aa)
        _install_credential_pool_401_hook()
        return True

    _scrub_static_anthropic_env_if_possible(aa)
    _install_token_resolution_hooks(aa)
    _install_credential_pool_401_hook()

    # 1. Add the OAuth-only beta flags.
    oauth_betas = getattr(aa, "_OAUTH_ONLY_BETAS", None)
    if isinstance(oauth_betas, list):
        for new_beta in _EXTRA_OAUTH_BETAS:
            if new_beta not in oauth_betas:
                oauth_betas.append(new_beta)
                logger.info("Appended beta flag: %s", new_beta)

    # 2. Verify build_anthropic_kwargs presence and signature.
    original_build = getattr(aa, "build_anthropic_kwargs", None)
    if not callable(original_build):
        logger.warning(
            "agent.anthropic_adapter.build_anthropic_kwargs missing; skipping"
        )
        return False

    try:
        sig = inspect.signature(original_build)
        if "is_oauth" not in sig.parameters:
            logger.warning(
                "build_anthropic_kwargs lacks 'is_oauth' param; skipping"
            )
            return False
    except (TypeError, ValueError) as exc:
        logger.warning("Cannot introspect build_anthropic_kwargs: %s", exc)
        return False

    # 3. Wrap build_anthropic_kwargs to apply the bypass on OAuth requests.
    def patched_build(*args: Any, **kwargs: Any) -> Dict[str, Any]:
        result = original_build(*args, **kwargs)

        try:
            bound = sig.bind_partial(*args, **kwargs)
            bound.apply_defaults()
            is_oauth = bool(bound.arguments.get("is_oauth", False))
        except TypeError:
            is_oauth = bool(kwargs.get("is_oauth", False))

        if is_oauth and isinstance(result, dict):
            try:
                apply_claude_code_bypass(result, _get_version_safely(aa))
            except Exception as exc:
                logger.warning(
                    "apply_claude_code_bypass raised %s: %s",
                    type(exc).__name__,
                    exc,
                )
                traceback.print_exc(file=sys.stderr)
        return result

    patched_build.__name__ = original_build.__name__
    patched_build.__qualname__ = getattr(
        original_build, "__qualname__", original_build.__name__
    )
    patched_build.__doc__ = original_build.__doc__
    patched_build.__module__ = getattr(original_build, "__module__", __name__)
    patched_build.__wrapped__ = original_build  # type: ignore[attr-defined]

    aa.build_anthropic_kwargs = patched_build
    aa._CLAUDE_CODE_BYPASS_APPLIED = True  # type: ignore[attr-defined]
    sys.stderr.write("[anthropic_billing_bypass] Bypass installed\n")

    _install_response_pascalcase_unhook(aa)
    return True
