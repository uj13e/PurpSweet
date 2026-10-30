"""WebSocket event bus.

The API server (uvicorn) owns one asyncio loop; the proxy runs in a separate
thread with its own loop. This bus lets the proxy thread publish events onto
the API loop safely so they can be pushed to connected browsers in real time.
"""
from __future__ import annotations

import asyncio
import json
from typing import Any, Optional, Set

from fastapi import WebSocket


class EventBus:
    def __init__(self) -> None:
        self._clients: Set[WebSocket] = set()
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._lock = asyncio.Lock()

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Called once from API startup, on the API loop."""
        self._loop = loop

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._clients.add(ws)

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self._clients.discard(ws)

    async def _broadcast(self, message: str) -> None:
        async with self._lock:
            clients = list(self._clients)
        dead = []
        for ws in clients:
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)
        if dead:
            async with self._lock:
                for ws in dead:
                    self._clients.discard(ws)

    def publish(self, event_type: str, data: Any) -> None:
        """Thread-safe publish. Safe to call from any thread."""
        if self._loop is None:
            return
        payload = json.dumps({"type": event_type, "data": data}, default=str)
        try:
            asyncio.run_coroutine_threadsafe(self._broadcast(payload), self._loop)
        except RuntimeError:
            # loop not running yet / shutting down
            pass


event_bus = EventBus()
