"""Embedded mitmproxy engine + interception control.

Architecture
------------
mitmproxy runs in its own thread with its own asyncio loop. FastAPI (uvicorn)
runs in the main thread with a separate loop. Cross-thread coordination:

* Captured flows are written to SQLite (engine allows cross-thread) and pushed
  to the browser via `event_bus.publish` (thread-safe).
* Interception: when intercept mode is ON, the async `request` hook parks the
  flow on an asyncio.Event and awaits it *without blocking other flows*. The UI
  (API thread) later calls `resolve_intercept(...)`, which sets that event on
  the proxy loop via `call_soon_threadsafe`. The hook then applies the edited
  request or kills the flow.
"""
from __future__ import annotations

import asyncio
import json
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .config import settings
from .db import SessionLocal
from .events import event_bus
from .models import Flow, WsMessage
from .scope import scope_manager
from .tools import decompress, strip_encoding_headers


def _headers_to_list(headers) -> List[List[str]]:
    out: List[List[str]] = []
    for k, v in headers.fields:
        out.append([k.decode("latin-1"), v.decode("latin-1")])
    return out


def _safe_content(message) -> tuple[bytes, bool, bool]:
    """Return (body_bytes, truncated, decoded_ok).

    `decoded_ok` is False only when the body is still compressed (mitmproxy
    couldn't decode it and neither could we) — the caller keeps the
    content-encoding header in that case so the viewer shows a placeholder
    instead of garbage.
    """
    raw = b""
    try:
        raw = message.raw_content or b""
    except Exception:
        raw = b""
    try:
        enc = message.headers.get("content-encoding", "") or ""
    except Exception:
        enc = ""

    decoded_ok = True
    body = None
    try:
        body = message.content  # mitmproxy-decoded (gzip/deflate via stdlib)
    except Exception:
        body = None
    if body is None:
        # mitmproxy raised (e.g. br/zstd without the optional lib) → try ours.
        body = decompress(raw, enc) if enc else None
        if body is None:
            body = raw
            decoded_ok = not bool(enc)  # raw bytes with an encoding = undecoded
    if body is None:
        body = b""

    truncated = False
    if len(body) > settings.max_body_store:
        body = body[: settings.max_body_store]
        truncated = True
    return body, truncated, decoded_ok


@dataclass
class PendingIntercept:
    flow_id: str
    flow: Any
    event: asyncio.Event
    decision: Optional[Dict[str, Any]] = field(default=None)


class _CaptureAddon:
    def __init__(self, controller: "ProxyController") -> None:
        self.c = controller

    # ---- interception happens on the request leg ----
    async def request(self, flow) -> None:
        # Normalize Accept-Encoding so response bodies stay readable. We strip
        # br/zstd (which need optional libs to decode) and keep gzip/deflate,
        # which mitmproxy decodes with the stdlib. This runs for ALL requests,
        # regardless of intercept, so HTTP history never shows compressed junk.
        try:
            ae = flow.request.headers.get("accept-encoding", "")
            low = ae.lower()
            if ae and ("br" in low or "zstd" in low or "compress" in low):
                flow.request.headers["accept-encoding"] = "gzip, deflate"
        except Exception:
            pass

        if not self.c.intercept_enabled:
            return
        # Don't intercept our own replays or CONNECTs.
        if flow.request.method == "CONNECT":
            return

        fid = flow.id
        ev = asyncio.Event()
        pending = PendingIntercept(flow_id=fid, flow=flow, event=ev)
        self.c.pending[fid] = pending

        event_bus.publish("intercept_add", self.c.intercept_snapshot(flow))
        try:
            await ev.wait()
        finally:
            self.c.pending.pop(fid, None)

        decision = pending.decision or {"action": "forward"}
        if decision.get("action") == "drop":
            event_bus.publish("intercept_resolve", {"flow_id": fid, "action": "drop"})
            flow.kill()
            return
        # Apply edits (method / path / headers / body). Host & scheme preserved.
        self._apply_edits(flow, decision)
        event_bus.publish("intercept_resolve", {"flow_id": fid, "action": "forward"})

    @staticmethod
    def _apply_edits(flow, decision: Dict[str, Any]) -> None:
        req = flow.request
        if "method" in decision and decision["method"]:
            req.method = decision["method"]
        if "path" in decision and decision["path"] is not None:
            req.path = decision["path"]
        if "headers" in decision and isinstance(decision["headers"], list):
            req.headers.clear()
            for pair in decision["headers"]:
                if len(pair) == 2 and pair[0]:
                    req.headers.add(pair[0], pair[1])
        if "body" in decision and decision["body"] is not None:
            body = decision["body"]
            if isinstance(body, str):
                body = body.encode("utf-8", "replace")
            req.content = body

    # ---- persistence happens once the response is in ----
    def response(self, flow) -> None:
        self.c.persist_flow(flow, source="proxy")

    def error(self, flow) -> None:
        # Persist even when the exchange failed, so nothing is silently lost.
        try:
            self.c.persist_flow(flow, source="proxy")
        except Exception:
            pass

    # ---- WebSocket capture ----
    def websocket_message(self, flow) -> None:
        try:
            msg = flow.websocket.messages[-1]
        except Exception:
            return
        try:
            self.c.persist_ws(flow, msg)
        except Exception:
            pass


class ProxyController:
    def __init__(self) -> None:
        self.thread: Optional[threading.Thread] = None
        self.proxy_loop: Optional[asyncio.AbstractEventLoop] = None
        self.master = None
        self.intercept_enabled: bool = False
        self.pending: Dict[str, PendingIntercept] = {}
        self.running: bool = False
        self._started = threading.Event()

    # ---------- lifecycle ----------
    def start(self) -> None:
        if self.running:
            return
        self.thread = threading.Thread(target=self._run, name="mitmproxy", daemon=True)
        self.thread.start()
        self._started.wait(timeout=15)

    def _run(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self.proxy_loop = loop
        try:
            loop.run_until_complete(self._serve())
        except Exception as exc:  # pragma: no cover
            print(f"[proxy] stopped: {exc}")
        finally:
            self.running = False
            self._started.set()

    async def _serve(self) -> None:
        # mitmproxy 11 requires a *running* loop when the master is built, so
        # construct it here (inside the running loop), not in _run().
        from pathlib import Path

        from mitmproxy import certs, options
        from mitmproxy.tools.dump import DumpMaster

        # Pre-generate the CA so the UI can offer the cert download immediately.
        try:
            confdir = Path(settings.confdir)
            confdir.mkdir(parents=True, exist_ok=True)
            certs.CertStore.from_store(confdir, "mitmproxy", 2048)
        except Exception as exc:  # pragma: no cover
            print(f"[proxy] CA pre-generation skipped: {exc}")

        opts = options.Options(
            listen_host=settings.proxy_host,
            listen_port=settings.proxy_port,
            confdir=settings.confdir,
            # Test targets often use self-signed certs; don't hard-fail upstream.
            ssl_insecure=True,
        )
        master = DumpMaster(opts, with_termlog=False, with_dumper=False)
        master.addons.add(_CaptureAddon(self))
        self.master = master
        self.running = True
        self._started.set()
        await master.run()

    def stop(self) -> None:
        if self.master and self.proxy_loop:
            self.proxy_loop.call_soon_threadsafe(self.master.shutdown)

    # ---------- intercept controls ----------
    def set_intercept(self, enabled: bool) -> None:
        self.intercept_enabled = enabled
        # If turning off, release everything currently parked (forward as-is).
        if not enabled:
            for fid in list(self.pending.keys()):
                self.resolve_intercept(fid, {"action": "forward"})
        event_bus.publish("intercept_state", {"enabled": enabled})

    def resolve_intercept(self, flow_id: str, decision: Dict[str, Any]) -> bool:
        pending = self.pending.get(flow_id)
        if not pending or self.proxy_loop is None:
            return False
        pending.decision = decision

        def _set():
            pending.event.set()

        self.proxy_loop.call_soon_threadsafe(_set)
        return True

    def list_pending(self) -> List[Dict[str, Any]]:
        return [self.intercept_snapshot(p.flow) for p in self.pending.values()]

    def intercept_snapshot(self, flow) -> Dict[str, Any]:
        req = flow.request
        try:
            body = req.content or b""
        except Exception:
            body = req.raw_content or b""
        return {
            "flow_id": flow.id,
            "method": req.method,
            "scheme": req.scheme,
            "host": req.host,
            "port": req.port,
            "path": req.path,
            "url": req.url,
            "headers": _headers_to_list(req.headers),
            "body": body.decode("utf-8", "replace"),
            "in_scope": scope_manager.is_in_scope(req.host),
        }

    # ---------- persistence ----------
    def persist_flow(self, flow, source: str) -> None:
        req = flow.request
        resp = flow.response
        req_body, _, _ = _safe_content(req)
        if resp is not None:
            resp_body, truncated, decoded_ok = _safe_content(resp)
            status = resp.status_code
            reason = resp.reason or ""
            resp_headers = _headers_to_list(resp.headers)
            # If we stored the DECODED body, drop content-encoding/length so the
            # viewer treats it as plain text (header would otherwise say "br").
            if decoded_ok:
                resp_headers = strip_encoding_headers(resp_headers)
            mime = resp.headers.get("content-type", "")
            resp_len = len(resp.raw_content or b"") if resp.raw_content else len(resp_body)
        else:
            resp_body, truncated = b"", False
            status, reason, resp_headers, mime, resp_len = 0, "", [], "", 0

        duration_ms = 0
        try:
            if flow.request.timestamp_start and getattr(flow, "response", None) and flow.response.timestamp_end:
                duration_ms = int((flow.response.timestamp_end - flow.request.timestamp_start) * 1000)
        except Exception:
            duration_ms = 0

        row = Flow(
            flow_uuid=flow.id or str(uuid.uuid4()),
            source=source,
            method=req.method,
            scheme=req.scheme,
            host=req.host,
            port=req.port,
            path=req.path,
            url=req.url,
            req_headers=json.dumps(_headers_to_list(req.headers)),
            req_body=req_body,
            status_code=status,
            reason=reason,
            resp_headers=json.dumps(resp_headers),
            resp_body=resp_body,
            resp_body_truncated=truncated,
            resp_length=resp_len,
            mime=mime,
            duration_ms=duration_ms,
            in_scope=scope_manager.is_in_scope(req.host),
        )
        with SessionLocal() as db:
            # Avoid duplicate rows if both response & error fire.
            db.add(row)
            try:
                db.commit()
            except Exception:
                db.rollback()
                return
            db.refresh(row)
            event_bus.publish("flow", _flow_summary(row))

    def persist_ws(self, flow, msg) -> None:
        req = flow.request
        raw = msg.content or b""
        is_text = bool(getattr(msg, "is_text", False))
        if is_text:
            try:
                content = msg.text
            except Exception:
                content = raw.decode("utf-8", "replace")
        else:
            content = raw.hex()
        if len(content) > 200_000:
            content = content[:200_000]
        row = WsMessage(
            conn_id=flow.id,
            host=req.host,
            path=req.path,
            url=req.url,
            from_client=bool(msg.from_client),
            is_text=is_text,
            content=content,
            length=len(raw),
            in_scope=scope_manager.is_in_scope(req.host),
        )
        with SessionLocal() as db:
            db.add(row)
            try:
                db.commit()
            except Exception:
                db.rollback()
                return
            db.refresh(row)
            event_bus.publish("ws_message", {
                "id": row.id,
                "created_at": row.created_at.isoformat() if row.created_at else None,
                "conn_id": row.conn_id, "host": row.host, "path": row.path, "url": row.url,
                "from_client": row.from_client, "is_text": row.is_text,
                "length": row.length, "in_scope": row.in_scope,
                "preview": content[:200],
            })


def _flow_summary(row: Flow) -> Dict[str, Any]:
    return {
        "id": row.id,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "source": row.source,
        "method": row.method,
        "host": row.host,
        "url": row.url,
        "status_code": row.status_code,
        "mime": row.mime,
        "resp_length": row.resp_length,
        "duration_ms": row.duration_ms,
        "in_scope": row.in_scope,
    }


proxy_controller = ProxyController()
