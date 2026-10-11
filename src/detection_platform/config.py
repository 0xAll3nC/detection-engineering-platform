"""Lab connection settings, read from the environment.

Values come from environment variables, optionally pre-loaded from a local
`.env` file (gitignored; see `.env.example`). Nothing here has a credential
default, and secrets are never logged or included in reprs.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


class ConfigError(RuntimeError):
    pass


def load_dotenv(path: Path = Path(".env")) -> None:
    """Minimal KEY=VALUE loader. Existing environment variables win."""
    if not path.is_file():
        return
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip().removeprefix("export ").strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


def _require(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise ConfigError(f"{name} is not set (see .env.example)")
    return value


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class WazuhIndexerSettings:
    url: str
    username: str
    password: str = field(repr=False)
    verify_tls: bool = True
    ca_bundle: str | None = None
    index_pattern: str = "wazuh-archives-*"

    @property
    def requests_verify(self) -> bool | str:
        if not self.verify_tls:
            return False
        return self.ca_bundle or True

    @classmethod
    def from_env(cls) -> WazuhIndexerSettings:
        return cls(
            url=_require("WAZUH_INDEXER_URL").rstrip("/"),
            username=_require("WAZUH_INDEXER_USER"),
            password=_require("WAZUH_INDEXER_PASS"),
            verify_tls=_bool("WAZUH_INDEXER_VERIFY_TLS", True),
            ca_bundle=os.environ.get("WAZUH_INDEXER_CA_BUNDLE") or None,
            index_pattern=os.environ.get("WAZUH_INDEX_PATTERN", "wazuh-archives-*"),
        )


@dataclass(frozen=True)
class VictimSettings:
    host: str
    username: str
    password: str = field(repr=False)
    transport: str = "ntlm"

    @classmethod
    def from_env(cls) -> VictimSettings:
        return cls(
            host=_require("ATOMIC_VICTIM_HOST"),
            username=_require("ATOMIC_VICTIM_USER"),
            password=_require("ATOMIC_VICTIM_PASS"),
            transport=os.environ.get("ATOMIC_VICTIM_TRANSPORT", "ntlm"),
        )
