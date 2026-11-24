#!/usr/bin/env python3
"""Load RT credentials from a local JSON configuration file."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


class AuthConfigError(ValueError):
    """An invalid or incomplete RT authentication configuration."""


def load_auth(path: Path, system: str) -> dict[str, str]:
    try:
        data: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuthConfigError(f"Could not read auth file {path}: {exc}") from None
    if not isinstance(data, dict):
        raise AuthConfigError(f"{path} must contain a JSON object")

    section = data.get(system)
    if not isinstance(section, dict):
        raise AuthConfigError(f"{path} must contain an object named {system!r}")

    fields = {"rt4": ("url", "name", "password"), "rt5": ("url", "token")}
    if system not in fields:
        raise AuthConfigError(f"Unknown RT system {system!r}")
    missing = [key for key in fields[system] if not isinstance(section.get(key), str) or not section[key].strip()]
    if missing:
        raise AuthConfigError(f"{path}: {system} is missing required field(s): {', '.join(missing)}")
    return {key: section[key].strip() for key in fields[system]}


def redacted_url(value: str) -> str:
    candidate = value if "://" in value else "https://" + value
    parsed = urlsplit(candidate)
    host = parsed.hostname or "<invalid-host>"
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    try:
        port = f":{parsed.port}" if parsed.port is not None else ""
    except ValueError:
        port = ""
    return f"{parsed.scheme}://{host}{port}{parsed.path}"
