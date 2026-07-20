#!/usr/bin/env python3
"""Manage the Composio toolkits exposed to the default Hermes gateway."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


CONFIG = Path.home() / ".hermes" / "config.yaml"
REQUIRED_TOOLKIT = "composio"


def read_connection() -> tuple[str, str]:
    text = CONFIG.read_text(encoding="utf-8")
    project = re.search(
        r"url:\s*https://backend\.composio\.dev/v3/mcp/([^/]+)/mcp\?user_id=\S+",
        text,
    )
    api_key = re.search(r"x-api-key:\s*([^\s]+)", text)
    if not project or not api_key:
        raise RuntimeError(f"Composio MCP connection not found in {CONFIG}")
    return project.group(1), api_key.group(1).strip('"\'')


def request(method: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    project_id, api_key = read_connection()
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        f"https://backend.composio.dev/api/v3/mcp/{project_id}",
        data=data,
        headers={"x-api-key": api_key, "Content-Type": "application/json"},
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        raise RuntimeError(f"Composio returned HTTP {exc.code}: {detail}") from exc


def normalized(toolkits: list[str]) -> list[str]:
    cleaned = {item.strip().lower() for item in toolkits if item.strip()}
    cleaned.add(REQUIRED_TOOLKIT)
    return [REQUIRED_TOOLKIT, *sorted(cleaned - {REQUIRED_TOOLKIT})]


def update(toolkits: list[str], restart: bool) -> list[str]:
    desired = normalized(toolkits)
    result = request("PATCH", {"toolkits": desired, "allowed_tools": []})
    actual = normalized(result.get("toolkits") or desired)
    if set(actual) != set(desired):
        raise RuntimeError(f"Composio saved an unexpected toolkit list: {actual}")
    if restart:
        proc = subprocess.run(
            ["hermes", "gateway", "restart"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=60,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"toolkits updated, but gateway restart failed: {proc.stdout.strip()}")
    return actual


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("list", "set", "add", "remove"))
    parser.add_argument("toolkits", nargs="*")
    parser.add_argument("--no-restart", action="store_true")
    args = parser.parse_args()

    current = normalized(request("GET").get("toolkits") or [])
    if args.action == "list":
        print("\n".join(current))
        return 0
    if not args.toolkits:
        parser.error(f"{args.action} requires at least one toolkit")

    if args.action == "set":
        desired = args.toolkits
    elif args.action == "add":
        desired = [*current, *args.toolkits]
    else:
        removals = {item.lower() for item in args.toolkits}
        if REQUIRED_TOOLKIT in removals:
            parser.error(f"{REQUIRED_TOOLKIT} cannot be removed")
        desired = [item for item in current if item not in removals]

    actual = update(desired, restart=not args.no_restart)
    print("Active Composio toolkits: " + ", ".join(actual))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
