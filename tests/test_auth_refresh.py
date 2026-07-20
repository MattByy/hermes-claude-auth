import json
import importlib.util
import sys
from types import SimpleNamespace
from dataclasses import dataclass, replace

import anthropic_billing_bypass as bypass


def _load_doctor_module():
    path = __import__("pathlib").Path(__file__).resolve().parents[1] / "scripts" / "hermes_doctor.py"
    spec = importlib.util.spec_from_file_location("hermes_doctor", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_parse_claude_code_credentials_payload_extracts_oauth_shape():
    payload = """
    {
      "claudeAiOauth": {
        "accessToken": "fresh-access",
        "refreshToken": "refresh-token",
        "expiresAt": 4102444800000,
        "scopes": ["user:inference"]
      }
    }
    """

    creds = bypass._parse_claude_code_credentials_payload(payload, "test")

    assert creds["accessToken"] == "fresh-access"
    assert creds["refreshToken"] == "refresh-token"
    assert creds["expiresAt"] == 4102444800000
    assert creds["source"] == "test"


def test_parse_claude_code_credentials_payload_accepts_keychain_hex():
    payload = json.dumps(
        {
            "claudeAiOauth": {
                "accessToken": "fresh-access",
                "refreshToken": "refresh-token",
                "expiresAt": 4102444800000,
            }
        }
    )

    creds = bypass._parse_claude_code_credentials_payload(
        payload.encode().hex(), "macos_keychain"
    )

    assert creds["accessToken"] == "fresh-access"
    assert creds["refreshToken"] == "refresh-token"


def test_resolve_refreshable_token_uses_valid_hermes_credentials():
    adapter = SimpleNamespace(
        read_claude_code_credentials=lambda: {
            "accessToken": "fresh-access",
            "refreshToken": "refresh-token",
            "expiresAt": 4102444800000,
        }
    )

    assert bypass._resolve_refreshable_token(adapter) == "fresh-access"


def test_local_credentials_choose_newest_expiry(monkeypatch):
    monkeypatch.setattr(
        bypass,
        "_read_claude_code_credentials_from_keychain",
        lambda: {"accessToken": "stale", "refreshToken": "", "expiresAt": 1},
    )
    monkeypatch.setattr(
        bypass,
        "_read_claude_code_credentials_file",
        lambda: {"accessToken": "fresh", "refreshToken": "refresh", "expiresAt": 2},
    )

    assert bypass._read_local_claude_code_credentials()["accessToken"] == "fresh"


def test_resolve_refreshable_token_refreshes_expired_hermes_credentials():
    writes = []

    adapter = SimpleNamespace(
        read_claude_code_credentials=lambda: {
            "accessToken": "expired-access",
            "refreshToken": "refresh-token",
            "expiresAt": 1,
        },
        refresh_anthropic_oauth_pure=lambda refresh_token, use_json=False: {
            "access_token": "fresh-access",
            "refresh_token": "next-refresh",
            "expires_at_ms": 4102444800000,
        },
        _write_claude_code_credentials=lambda *args: writes.append(args),
    )

    assert bypass._resolve_refreshable_token(adapter) == "fresh-access"
    assert writes == [("fresh-access", "next-refresh", 4102444800000)]


def test_static_env_is_scrubbed_when_refreshable_credentials_exist(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-api03-metered")
    monkeypatch.setenv("ANTHROPIC_TOKEN", "sk-ant-oat01-stale")
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "cc-stale")
    adapter = SimpleNamespace(
        read_claude_code_credentials=lambda: {
            "accessToken": "fresh-access",
            "refreshToken": "refresh-token",
            "expiresAt": 4102444800000,
        }
    )

    assert bypass._scrub_static_anthropic_env_if_possible(adapter) is True

    assert "ANTHROPIC_API_KEY" not in __import__("os").environ
    assert "ANTHROPIC_TOKEN" not in __import__("os").environ
    assert "CLAUDE_CODE_OAUTH_TOKEN" not in __import__("os").environ


def test_token_resolution_hook_prefers_refreshable_token_over_env_token(monkeypatch):
    monkeypatch.setenv("HERMES_CLAUDE_AUTH_STRICT_SUBSCRIPTION", "1")
    adapter = SimpleNamespace(
        resolve_anthropic_token=lambda: "sk-ant-oat01-stale",
        read_claude_code_credentials=lambda: {
            "accessToken": "fresh-access",
            "refreshToken": "refresh-token",
            "expiresAt": 4102444800000,
        },
    )

    assert bypass._install_token_resolution_hooks(adapter) is True

    assert adapter.resolve_anthropic_token() == "fresh-access"


def test_client_hook_replaces_static_key_for_direct_anthropic(monkeypatch):
    monkeypatch.setenv("HERMES_CLAUDE_AUTH_STRICT_SUBSCRIPTION", "1")
    calls = []
    adapter = SimpleNamespace(
        read_claude_code_credentials=lambda: {
            "accessToken": "fresh-access",
            "refreshToken": "refresh-token",
            "expiresAt": 4102444800000,
        },
        build_anthropic_client=lambda api_key, base_url=None, **kwargs: calls.append(
            (api_key, base_url, kwargs)
        ) or object(),
    )

    assert bypass._install_token_resolution_hooks(adapter) is True
    adapter.build_anthropic_client(
        "sk-ant-api03-metered",
        base_url="https://api.anthropic.com",
        timeout=30,
    )

    assert calls == [
        ("fresh-access", "https://api.anthropic.com", {"timeout": 30})
    ]


def test_client_hook_leaves_third_party_endpoint_alone(monkeypatch):
    monkeypatch.setenv("HERMES_CLAUDE_AUTH_STRICT_SUBSCRIPTION", "1")
    calls = []
    adapter = SimpleNamespace(
        read_claude_code_credentials=lambda: {
            "accessToken": "fresh-access",
            "refreshToken": "refresh-token",
            "expiresAt": 4102444800000,
        },
        build_anthropic_client=lambda api_key, base_url=None, **kwargs: calls.append(
            (api_key, base_url, kwargs)
        ) or object(),
    )

    bypass._install_token_resolution_hooks(adapter)
    adapter.build_anthropic_client(
        "third-party-key",
        base_url="https://custom.proxy.local/v1",
    )

    assert calls == [("third-party-key", "https://custom.proxy.local/v1", {})]


def test_doctor_repairs_auxiliary_anthropic_pins(tmp_path):
    doctor = _load_doctor_module()
    config = tmp_path / "config.yaml"
    config.write_text(
        """model:
  provider: anthropic
auxiliary:
  web_extract:
    provider: anthropic
    model: claude-haiku-4-5
    api_key: ''
  compression:
    provider: anthropic
    model: claude-opus-4-8
    api_key: ''
  title_generation:
    provider: anthropic
    model: claude-haiku-4-5
    api_key: ''
  vision:
    provider: auto
    model: ''
delegation:
  provider: anthropic
  model: claude-opus-4-8
""",
        encoding="utf-8",
    )

    assert doctor.repair_auxiliary_config(config) is True

    repaired = config.read_text(encoding="utf-8")
    assert "web_extract:\n    provider: auto\n    model: ''" in repaired
    assert "compression:\n    provider: auto\n    model: ''" in repaired
    assert "title_generation:\n    provider: auto\n    model: ''" in repaired
    assert "delegation:\n  provider: anthropic\n  model: claude-opus-4-8" in repaired


def test_doctor_repairs_stale_claude_code_pool_401(tmp_path, monkeypatch):
    doctor = _load_doctor_module()
    auth = tmp_path / "auth.json"
    auth.write_text(
        json.dumps(
            {
                "credential_pool": {
                    "anthropic": [
                        {
                            "id": "one",
                            "source": "claude_code",
                            "access_token": "stale-access",
                            "refresh_token": "stale-refresh",
                            "expires_at_ms": 1,
                            "last_status": "exhausted",
                            "last_error_code": 401,
                            "last_error_message": "Invalid authentication credentials",
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(doctor, "HERMES_AUTH", auth)
    monkeypatch.setattr(doctor, "backup_auth", lambda reason: tmp_path / reason)
    monkeypatch.setattr(doctor, "log", lambda message: None)

    assert doctor.repair_claude_code_pool(
        {
            "claudeAiOauth": {
                "accessToken": "fresh-access",
                "refreshToken": "fresh-refresh",
                "expiresAt": 4102444800000,
            }
        }
    ) is True

    repaired = json.loads(auth.read_text(encoding="utf-8"))
    entry = repaired["credential_pool"]["anthropic"][0]
    assert entry["access_token"] == "fresh-access"
    assert entry["refresh_token"] == "fresh-refresh"
    assert entry["expires_at_ms"] == 4102444800000
    assert entry["last_status"] is None
    assert entry["last_error_code"] is None


def test_credential_pool_401_hook_force_refreshes_claude_code(monkeypatch):
    @dataclass
    class Entry:
        id: str = "one"
        label: str = "claude_code"
        source: str = "claude_code"
        access_token: str = "stale-access"
        refresh_token: str = "refresh-token"
        expires_at_ms: int = 4102444800000
        last_status: str | None = None
        last_status_at: float | None = None
        last_error_code: int | None = None
        last_error_reason: str | None = None
        last_error_message: str | None = None
        last_error_reset_at: float | None = None

    class CredentialPool:
        provider = "anthropic"

        def __init__(self):
            self.entry = Entry()
            self._current_id = self.entry.id
            self.persisted = False
            self.original_called = False

        def current(self):
            return self.entry

        def _select_unlocked(self):
            return self.entry

        def _replace_entry(self, old, new):
            self.entry = new

        def _persist(self):
            self.persisted = True

        def mark_exhausted_and_rotate(self, *, status_code, error_context=None):
            self.original_called = True
            self.entry = replace(
                self.entry,
                last_status="exhausted",
                last_error_code=status_code,
            )
            return None

    credential_pool_module = SimpleNamespace(
        CredentialPool=CredentialPool,
        STATUS_OK="ok",
    )
    agent_module = SimpleNamespace(credential_pool=credential_pool_module)
    monkeypatch.setitem(sys.modules, "agent", agent_module)
    monkeypatch.setitem(sys.modules, "agent.credential_pool", credential_pool_module)
    monkeypatch.setattr(
        bypass,
        "_force_refresh_local_claude_code_credentials",
        lambda: {
            "accessToken": "fresh-access",
            "refreshToken": "next-refresh",
            "expiresAt": 4102444800001,
        },
    )

    assert bypass._install_credential_pool_401_hook() is True

    pool = CredentialPool()
    result = pool.mark_exhausted_and_rotate(status_code=401)

    assert result.access_token == "fresh-access"
    assert result.refresh_token == "next-refresh"
    assert result.last_status == "ok"
    assert pool.entry.access_token == "fresh-access"
    assert pool.persisted is True
    assert pool.original_called is False
