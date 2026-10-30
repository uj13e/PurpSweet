"""Central configuration.

All defaults bind to loopback so nothing is exposed to the network.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("WEBSEC_DATA_DIR", BASE_DIR / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)


@dataclass
class Settings:
    # FastAPI / UI API server
    api_host: str = os.environ.get("WEBSEC_API_HOST", "127.0.0.1")
    api_port: int = int(os.environ.get("WEBSEC_API_PORT", "8777"))

    # Intercepting proxy (mitmproxy) listener
    proxy_host: str = os.environ.get("WEBSEC_PROXY_HOST", "127.0.0.1")
    proxy_port: int = int(os.environ.get("WEBSEC_PROXY_PORT", "8080"))

    # Where mitmproxy stores its generated CA (~/.mitmproxy by default).
    confdir: str = os.environ.get(
        "WEBSEC_MITM_CONFDIR", str(Path.home() / ".mitmproxy")
    )

    # SQLite database file
    db_path: Path = field(default_factory=lambda: DATA_DIR / "websec.db")

    # Safety rails for active features (used from Stage 2 onward).
    # Rate limiting is mandatory: outbound automated requests must obey these.
    default_max_concurrency: int = 5
    default_min_interval_ms: int = 0  # per-worker delay between requests
    # Hard cap on total requests a single Intruder attack may send (runaway guard).
    intruder_max_total: int = int(os.environ.get("WEBSEC_INTRUDER_MAX_TOTAL", "100000"))
    # Optional upstream proxy for tool-initiated sends (Repeater/Intruder/Scanner),
    # e.g. a corporate proxy, or this tool's own mitmproxy "http://127.0.0.1:8080".
    # Empty = connect directly. Runtime-settable via /api/settings.
    upstream_proxy: str = os.environ.get("WEBSEC_UPSTREAM_PROXY", "")
    # Fast connect timeout so unreachable targets fail quickly instead of hanging.
    connect_timeout: float = float(os.environ.get("WEBSEC_CONNECT_TIMEOUT", "8"))
    # Store response bodies larger than this only as a truncated preview (bytes).
    max_body_store: int = 2_000_000
    # CVE / version diagnostics. Offline (bundled) matching is always available;
    # online NVD lookups are OFF by default and only query nvd.nist.gov (product
    # + version strings, never target data) when explicitly enabled.
    nvd_online: bool = os.environ.get("WEBSEC_NVD_ONLINE", "0") in ("1", "true", "True", "yes")
    nvd_api_key: str = os.environ.get("WEBSEC_NVD_API_KEY", "")

    @property
    def db_url(self) -> str:
        return f"sqlite:///{self.db_path}"


settings = Settings()
