"""Scope enforcement — the core safety control.

Active/automated features must call `require_in_scope(host)` before sending
anything. The default answer is DENY: if no enabled rule matches the host,
the request is refused. This is a technical guardrail, not just UI text.

Passive proxy capture is *not* gated (you may browse anything through the
proxy); only tool-initiated outbound traffic is gated.

Pattern types (per Scope rule, decided automatically):
  * CIDR block   -> "192.168.1.0/24", "10.0.0.0/8", "2001:db8::/32"
                    Matches when the request host is an IP inside that network.
  * Single IP    -> "192.168.1.10", "::1"  (treated as a /32 or /128 network)
  * Hostname/glob-> "example.com", "*.example.com", "192.168.1.*"
                    Shell-style match against the hostname string (fnmatch).
"""
from __future__ import annotations

import fnmatch
import ipaddress
import threading
from typing import List, Tuple, Union

from sqlalchemy import select

from .db import SessionLocal
from .models import ScopeRule

Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

_GLOB_CHARS = ("*", "?", "[", "]")


class ScopeError(PermissionError):
    """Raised when an active action targets a host outside the allow-list."""


class ScopeManager:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._networks: List[Network] = []  # CIDR blocks and single IPs
        self._globs: List[str] = []          # hostname / glob patterns
        self.reload()

    # ------------------------------------------------------------------ #
    @staticmethod
    def _compile(patterns: List[str]) -> Tuple[List[Network], List[str]]:
        """Partition raw patterns into IP networks vs. hostname globs.

        A pattern is treated as a network only if it has no glob metacharacters
        and parses as an IP/CIDR. Everything else (hostnames, wildcards like
        192.168.1.*) stays a string glob.
        """
        nets: List[Network] = []
        globs: List[str] = []
        for raw in patterns:
            p = raw.strip().lower()
            if not p:
                continue
            net: Network | None = None
            if not any(c in p for c in _GLOB_CHARS):
                try:
                    # strict=False so "192.168.1.10/24" (host bits set) is ok;
                    # a bare IP becomes a /32 or /128 network.
                    net = ipaddress.ip_network(p, strict=False)
                except ValueError:
                    net = None
            if net is not None:
                nets.append(net)
            else:
                globs.append(p)
        return nets, globs

    def reload(self) -> None:
        try:
            with SessionLocal() as db:
                rows = db.execute(
                    select(ScopeRule).where(ScopeRule.enabled == True)  # noqa: E712
                ).scalars().all()
                patterns = [r.host_pattern for r in rows if r.host_pattern.strip()]
        except Exception:
            # Table may not exist yet at import time; startup reloads later.
            patterns = []
        nets, globs = self._compile(patterns)
        with self._lock:
            self._networks = nets
            self._globs = globs

    # ------------------------------------------------------------------ #
    @staticmethod
    def _strip_port(host: str) -> str:
        """Remove a trailing :port without breaking IPv6 literals."""
        host = host.strip().lower()
        if host.startswith("[") and "]" in host:  # [2001:db8::1]:443
            return host[1 : host.index("]")]
        if host.count(":") == 1:  # host:port or 1.2.3.4:port
            return host.split(":", 1)[0]
        return host  # bare hostname (0 colons) or IPv6 literal (2+ colons)

    def is_in_scope(self, host: str | None) -> bool:
        if not host:
            return False
        host = self._strip_port(host)

        # Is the request host itself an IP? If so, test it against CIDR blocks.
        ip: ipaddress._BaseAddress | None = None
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ip = None

        with self._lock:
            if ip is not None:
                for net in self._networks:
                    if ip.version == net.version and ip in net:
                        return True
            for pat in self._globs:
                if pat == host or fnmatch.fnmatch(host, pat):
                    return True
        return False

    def require_in_scope(self, host: str | None) -> None:
        if  self.is_in_scope(host):
            raise ScopeError(
                f"Host '{host}' is not in the authorized testing scope. "
                f"Add it to Scope first (hostname, glob, IP or CIDR). "
                f"Active requests are default-deny."
            )


scope_manager = ScopeManager()
