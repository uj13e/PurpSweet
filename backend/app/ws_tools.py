"""WebSocket Repeater — open a WS connection to an authorized target, send
messages, and see what comes back. Authorized-testing only.

Every connection is scope-gated (default-deny) on its host. The connection is
kept open in the API event loop; a reader task streams incoming frames to the
UI (via the event bus) and buffers them for polling.
"""
from __future__ import annotations

import asyncio
import ssl
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import websockets

from .events import event_bus
from .scope import scope_manager


@dataclass
class WsConn:
    id: str
    url: str
    host: str
    status: str = "open"      # open | closed | error
    error: str = ""
    messages: List[Dict[str, Any]] = field(default_factory=list)
    ws: Any = None
    task: Optional[asyncio.Task] = None


class WsRepeaterManager:
    def __init__(self) -> None:
        self.conns: Dict[str, WsConn] = {}

    def get(self, cid: str) -> Optional[WsConn]:
        return self.conns.get(cid)

    def _record(self, conn: WsConn, direction: str, text: str, binary: bool = False) -> None:
        entry = {"dir": direction, "text": text[:200000], "binary": binary, "ts": time.time()}
        conn.messages.append(entry)
        event_bus.publish("ws_repeater_msg", {"conn_id": conn.id, **entry})

    async def _reader(self, conn: WsConn) -> None:
        try:
            async for message in conn.ws:
                if isinstance(message, bytes):
                    self._record(conn, "in", message.hex(), binary=True)
                else:
                    self._record(conn, "in", message, binary=False)
        except Exception as exc:
            conn.error = f"{type(exc).__name__}: {exc}"
        finally:
            conn.status = "error" if conn.error else "closed"
            event_bus.publish("ws_repeater_state", {"conn_id": conn.id, "status": conn.status, "error": conn.error})

    async def connect(self, url: str, headers: List[List[str]]) -> WsConn:
        parsed = urlparse(url)
        if parsed.scheme not in ("ws", "wss"):
            raise ValueError("URL は ws:// または wss:// で指定してください。")
        host = parsed.hostname or ""
        scope_manager.require_in_scope(host)  # default-deny gate

        sslctx = None
        if parsed.scheme == "wss":
            sslctx = ssl.create_default_context()
            sslctx.check_hostname = False
            sslctx.verify_mode = ssl.CERT_NONE

        extra = [(k, v) for k, v in (headers or []) if k and k.lower() != "host"]
        ws = await websockets.connect(
            url, extra_headers=extra, ssl=sslctx,
            open_timeout=10, max_size=None, ping_interval=None,
        )
        conn = WsConn(id=uuid.uuid4().hex[:12], url=url, host=host)
        conn.ws = ws
        conn.task = asyncio.create_task(self._reader(conn))
        self.conns[conn.id] = conn
        return conn

    async def send(self, cid: str, message: str, is_text: bool = True) -> None:
        conn = self.conns.get(cid)
        if not conn or conn.status != "open":
            raise ValueError("接続がありません(またはクローズ済み)。")
        if is_text:
            await conn.ws.send(message)
            self._record(conn, "out", message, binary=False)
        else:
            data = bytes.fromhex("".join(message.split()))
            await conn.ws.send(data)
            self._record(conn, "out", message, binary=True)

    async def close(self, cid: str) -> None:
        conn = self.conns.get(cid)
        if conn and conn.ws:
            try:
                await conn.ws.close()
            except Exception:
                pass
            conn.status = "closed"


ws_repeater_manager = WsRepeaterManager()
