"""Entrypoint: starts the API server (which in turn starts the proxy).

    python run.py

Environment overrides: WEBSEC_API_PORT, WEBSEC_PROXY_PORT, WEBSEC_PROXY_HOST, ...
Everything binds to 127.0.0.1 by default. Authorized-testing use only.
"""
from __future__ import annotations

import uvicorn

from app.config import settings

BANNER = f"""
  Local WebSec Testing Tool  (authorized-testing only)
  ----------------------------------------------------
  UI / API : http://{settings.api_host}:{settings.api_port}
  Proxy    : http://{settings.proxy_host}:{settings.proxy_port}
  CA/setup : http://{settings.api_host}:{settings.api_port}/api/ca

  Point the browser/device you own at the proxy above and trust the CA to
  intercept HTTPS. Active sends (Repeater/Intruder/Scanner) are default-deny
  until you add the target host under Scope.
"""


def main() -> None:
    print(BANNER)
    uvicorn.run(
        "app.main:app",
        host=settings.api_host,
        port=settings.api_port,
        log_level="info",
        reload=False,
    )


if __name__ == "__main__":
    main()
