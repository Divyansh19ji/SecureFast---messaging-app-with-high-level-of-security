"""Environment-driven configuration for SecureFast Relay and Device Client."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _load_dotenv() -> None:
    env_path = Path.cwd() / ".env"
    if not env_path.is_file():
        return
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


_load_dotenv()


@dataclass(slots=True)
class RelayConfig:
    host: str = field(default_factory=lambda: os.getenv("SF_RELAY_HOST", "0.0.0.0"))
    port: int = field(default_factory=lambda: int(os.getenv("SF_RELAY_PORT", "8765")))
    max_chunk_bytes: int = field(
        default_factory=lambda: min(2048, max(256, int(os.getenv("SF_MAX_CHUNK_BYTES", "2048"))))
    )
    path_ttl_seconds: int = field(
        default_factory=lambda: int(os.getenv("SF_PATH_TTL_SECONDS", "900"))
    )
    offline_queue_ttl_seconds: int = field(
        default_factory=lambda: int(os.getenv("SF_OFFLINE_QUEUE_TTL_SECONDS", "86400"))
    )
    rate_limit_max_requests: int = field(
        default_factory=lambda: int(os.getenv("SF_RATE_LIMIT_MAX", "2000"))
    )
    rate_limit_window_seconds: int = field(
        default_factory=lambda: int(os.getenv("SF_RATE_LIMIT_WINDOW", "60"))
    )
    cors_origins: list[str] = field(
        default_factory=lambda: [
            origin.strip()
            for origin in os.getenv("SF_CORS_ORIGINS", "*").split(",")
            if origin.strip()
        ]
    )


@dataclass(slots=True)
class ClientConfig:
    host: str = field(default_factory=lambda: os.getenv("SF_CLIENT_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: int(os.getenv("SF_CLIENT_PORT", "8000")))
    relay_url: str = field(
        default_factory=lambda: os.getenv("SF_RELAY_URL", "ws://127.0.0.1:8765")
    )
    default_username: str = field(default_factory=lambda: os.getenv("SF_USERNAME", ""))
    default_role: str = field(default_factory=lambda: os.getenv("SF_ROLE", "ADMIN"))
    max_chunk_bytes: int = field(
        default_factory=lambda: min(2048, max(256, int(os.getenv("SF_MAX_CHUNK_BYTES", "2048"))))
    )
