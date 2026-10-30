"""FastAPI application: history, intercept, repeater, scope, realtime WS."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import delete, desc, select
from sqlalchemy.orm import Session

from .config import settings
from .db import get_session, init_db
from .events import event_bus
from .models import Flow, RepeaterTab, ScopeRule
from .intruder import MARKER, intruder_manager, split_markers
from .proxy_controller import proxy_controller
from .repeater import send_request
from .scope import ScopeError, scope_manager
from .schemas import (
    ActiveScanStart,
    CveRunIn,
    IntruderStart,
    InterceptDecision,
    InterceptState,
    PassiveScanIn,
    RepeaterSend,
    RepeaterTabIn,
    ScopeRuleIn,
    SettingsIn,
    TransformIn,
    WsConnectIn,
    WsSendIn,
)
from .ws_tools import ws_repeater_manager
from .scanner import passive_scan_flow, persist_finding, scanner_manager
from . import cve as cve_mod
from .tools import OPS as TRANSFORM_OPS
from .tools import TransformError, decode_body, transform

app = FastAPI(title="Local WebSec Testing Tool", version="0.1.0")

# The UI is same-origin when served from dist; allow localhost dev server too.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        f"http://127.0.0.1:{settings.api_port}",
        f"http://localhost:{settings.api_port}",
        "http://127.0.0.1:5173",
        "http://localhost:5173",
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def _startup() -> None:
    init_db()
    event_bus.bind_loop(asyncio.get_running_loop())
    scope_manager.reload()
    proxy_controller.start()


@app.on_event("shutdown")
async def _shutdown() -> None:
    proxy_controller.stop()


# --------------------------------------------------------------------------- #
# Status / CA
# --------------------------------------------------------------------------- #
def _settings_payload():
    return {
        "upstream_proxy": settings.upstream_proxy,
        "connect_timeout": settings.connect_timeout,
        "nvd_online": settings.nvd_online,
        "nvd_api_key_set": bool(settings.nvd_api_key),
    }


@app.get("/api/settings")
def get_settings():
    return _settings_payload()


@app.post("/api/settings")
def set_settings(payload: SettingsIn):
    if payload.upstream_proxy is not None:
        settings.upstream_proxy = payload.upstream_proxy.strip()
    if payload.connect_timeout is not None:
        settings.connect_timeout = max(1.0, min(float(payload.connect_timeout), 60.0))
    if payload.nvd_online is not None:
        settings.nvd_online = bool(payload.nvd_online)
    if payload.nvd_api_key is not None:
        settings.nvd_api_key = payload.nvd_api_key.strip()
    return _settings_payload()


@app.get("/api/status")
def status():
    return {
        "proxy_running": proxy_controller.running,
        "proxy_host": settings.proxy_host,
        "proxy_port": settings.proxy_port,
        "api_port": settings.api_port,
        "intercept_enabled": proxy_controller.intercept_enabled,
        "pending_intercepts": len(proxy_controller.pending),
        "confdir": settings.confdir,
    }


@app.get("/api/ca")
def ca_info():
    confdir = Path(settings.confdir)
    files = {
        "pem": confdir / "mitmproxy-ca-cert.pem",
        "cer": confdir / "mitmproxy-ca-cert.cer",
        "p12": confdir / "mitmproxy-ca-cert.p12",
    }
    available = {k: str(v) for k, v in files.items() if v.exists()}
    return {
        "confdir": str(confdir),
        "available": available,
        "instructions": {
            "note": "Install this CA ONLY on devices you own/control for testing.",
            "browser": (
                "Configure the browser/OS to use HTTP proxy "
                f"{settings.proxy_host}:{settings.proxy_port}, then import the CA "
                "as a trusted root so HTTPS can be intercepted."
            ),
            "download": "/api/ca/download?fmt=pem",
        },
    }


@app.get("/api/ca/download")
def ca_download(fmt: str = Query("pem", pattern="^(pem|cer|p12)$")):
    confdir = Path(settings.confdir)
    fname = {
        "pem": "mitmproxy-ca-cert.pem",
        "cer": "mitmproxy-ca-cert.cer",
        "p12": "mitmproxy-ca-cert.p12",
    }[fmt]
    path = confdir / fname
    if not path.exists():
        raise HTTPException(404, "CA not generated yet. Send one request through the proxy first.")
    return FileResponse(str(path), filename=fname)


# --------------------------------------------------------------------------- #
# History
# --------------------------------------------------------------------------- #
@app.get("/api/flows")
def list_flows(
    db: Session = Depends(get_session),
    q: Optional[str] = None,
    host: Optional[str] = None,
    method: Optional[str] = None,
    source: Optional[str] = None,
    status_code: Optional[int] = None,
    in_scope: Optional[bool] = None,
    since_id: int = 0,
    limit: int = Query(200, le=2000),
    offset: int = 0,
):
    stmt = select(Flow)
    if host:
        stmt = stmt.where(Flow.host.like(f"%{host}%"))
    if method:
        stmt = stmt.where(Flow.method == method.upper())
    if source:
        stmt = stmt.where(Flow.source == source)
    if status_code is not None:
        stmt = stmt.where(Flow.status_code == status_code)
    if in_scope is not None:
        stmt = stmt.where(Flow.in_scope == in_scope)
    if since_id:
        # Incremental poll: only rows newer than what the client already has.
        stmt = stmt.where(Flow.id > since_id)
    if q:
        like = f"%{q}%"
        stmt = stmt.where((Flow.url.like(like)) | (Flow.path.like(like)))
    stmt = stmt.order_by(desc(Flow.id)).limit(limit).offset(offset)
    rows = db.execute(stmt).scalars().all()
    return [
        {
            "id": r.id,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "source": r.source,
            "method": r.method,
            "scheme": r.scheme,
            "host": r.host,
            "url": r.url,
            "status_code": r.status_code,
            "mime": r.mime,
            "resp_length": r.resp_length,
            "duration_ms": r.duration_ms,
            "in_scope": r.in_scope,
        }
        for r in rows
    ]


def _decode(b: Optional[bytes]) -> str:
    if not b:
        return ""
    return bytes(b).decode("utf-8", "replace")


@app.get("/api/flows/{flow_id}")
def get_flow(flow_id: int, db: Session = Depends(get_session)):
    r = db.get(Flow, flow_id)
    if not r:
        raise HTTPException(404, "not found")
    req_hdrs = json.loads(r.req_headers or "[]")
    req_ct = next((v for k, v in req_hdrs if k.lower() == "content-type"), "")
    req_ce = next((v for k, v in req_hdrs if k.lower() == "content-encoding"), "")
    resp_hdrs = json.loads(r.resp_headers or "[]")
    resp_ce = next((v for k, v in resp_hdrs if k.lower() == "content-encoding"), "")
    return {
        "id": r.id,
        "created_at": r.created_at.isoformat() if r.created_at else None,
        "source": r.source,
        "method": r.method,
        "scheme": r.scheme,
        "host": r.host,
        "port": r.port,
        "path": r.path,
        "url": r.url,
        "req_headers": req_hdrs,
        "req_body": decode_body(r.req_body, req_ct, req_ce),
        "status_code": r.status_code,
        "reason": r.reason,
        "resp_headers": resp_hdrs,
        "resp_body": decode_body(r.resp_body, r.mime, resp_ce),
        "resp_body_truncated": r.resp_body_truncated,
        "resp_length": r.resp_length,
        "mime": r.mime,
        "duration_ms": r.duration_ms,
        "in_scope": r.in_scope,
    }


@app.delete("/api/flows")
def clear_flows(db: Session = Depends(get_session)):
    db.execute(delete(Flow))
    db.commit()
    return {"ok": True}


# --------------------------------------------------------------------------- #
# Intercept
# --------------------------------------------------------------------------- #
@app.get("/api/intercept")
def intercept_status():
    return {
        "enabled": proxy_controller.intercept_enabled,
        "pending": proxy_controller.list_pending(),
    }


@app.post("/api/intercept/state")
def intercept_set(state: InterceptState):
    proxy_controller.set_intercept(state.enabled)
    return {"enabled": proxy_controller.intercept_enabled}


@app.post("/api/intercept/{flow_id}")
def intercept_resolve(flow_id: str, decision: InterceptDecision):
    ok = proxy_controller.resolve_intercept(flow_id, decision.model_dump())
    if not ok:
        raise HTTPException(404, "no such paused flow")
    return {"ok": True}


# --------------------------------------------------------------------------- #
# Repeater
# --------------------------------------------------------------------------- #
@app.post("/api/repeater/send")
def repeater_send(payload: RepeaterSend):
    try:
        return send_request(
            method=payload.method,
            scheme=payload.scheme,
            host=payload.host,
            port=payload.port,
            path=payload.path,
            headers=payload.headers,
            body=payload.body.encode("utf-8", "replace"),
            timeout=payload.timeout,
            verify_tls=payload.verify_tls,
        )
    except ScopeError as exc:
        raise HTTPException(403, str(exc))
    except Exception as exc:  # network errors etc.
        raise HTTPException(502, f"send failed: {exc}")


@app.get("/api/repeater/tabs")
def repeater_tabs(db: Session = Depends(get_session)):
    rows = db.execute(select(RepeaterTab).order_by(RepeaterTab.id)).scalars().all()
    return [
        {
            "id": t.id, "name": t.name, "method": t.method, "scheme": t.scheme,
            "host": t.host, "port": t.port, "path": t.path,
            "headers": json.loads(t.headers or "[]"),
            "body": _decode(t.body),
        }
        for t in rows
    ]


@app.post("/api/repeater/tabs")
def repeater_tab_create(payload: RepeaterTabIn, db: Session = Depends(get_session)):
    t = RepeaterTab(
        name=payload.name, method=payload.method, scheme=payload.scheme,
        host=payload.host, port=payload.port, path=payload.path,
        headers=json.dumps(payload.headers), body=payload.body.encode("utf-8", "replace"),
    )
    db.add(t)
    db.commit()
    db.refresh(t)
    return {"id": t.id}


@app.put("/api/repeater/tabs/{tab_id}")
def repeater_tab_update(tab_id: int, payload: RepeaterTabIn, db: Session = Depends(get_session)):
    t = db.get(RepeaterTab, tab_id)
    if not t:
        raise HTTPException(404, "not found")
    t.name = payload.name
    t.method = payload.method
    t.scheme = payload.scheme
    t.host = payload.host
    t.port = payload.port
    t.path = payload.path
    t.headers = json.dumps(payload.headers)
    t.body = payload.body.encode("utf-8", "replace")
    db.commit()
    return {"ok": True}


@app.delete("/api/repeater/tabs/{tab_id}")
def repeater_tab_delete(tab_id: int, db: Session = Depends(get_session)):
    t = db.get(RepeaterTab, tab_id)
    if t:
        db.delete(t)
        db.commit()
    return {"ok": True}


# --------------------------------------------------------------------------- #
# Scanner (passive analysis + active detection) + findings
# --------------------------------------------------------------------------- #
@app.post("/api/scanner/passive/run")
def scanner_passive_run(payload: PassiveScanIn, db: Session = Depends(get_session)):
    stmt = select(Flow).order_by(desc(Flow.id)).limit(payload.limit)
    if payload.in_scope_only:
        stmt = stmt.where(Flow.in_scope == True)  # noqa: E712
    rows = db.execute(stmt).scalars().all()
    inserted = 0
    scanned = 0
    for r in rows:
        scanned += 1
        for f in passive_scan_flow(r):
            if persist_finding(f):
                inserted += 1
        # Offline CVE / version diagnostics (no network) — automatic on passive run.
        for f in cve_mod.offline_findings_for_flow(r):
            if persist_finding(f):
                inserted += 1
    return {"scanned_flows": scanned, "new_findings": inserted}


@app.get("/api/scanner/findings")
def scanner_findings(
    db: Session = Depends(get_session),
    kind: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(1000, le=5000),
):
    from .models import Finding
    stmt = select(Finding)
    if kind:
        stmt = stmt.where(Finding.kind == kind)
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    SEV = {"high": 0, "medium": 1, "low": 2, "info": 3}
    rows = db.execute(stmt.limit(limit)).scalars().all()
    rows.sort(key=lambda r: (SEV.get(r.severity, 9), -r.id))
    return [
        {
            "id": r.id, "created_at": r.created_at.isoformat() if r.created_at else None,
            "kind": r.kind, "severity": r.severity, "confidence": r.confidence,
            "title": r.title, "detail": r.detail, "host": r.host, "url": r.url,
            "method": r.method, "param": r.param, "evidence": r.evidence,
            "flow_id": getattr(r, "flow_id", 0) or 0,
        }
        for r in rows
    ]


@app.delete("/api/scanner/findings")
def scanner_findings_clear(db: Session = Depends(get_session)):
    from .models import Finding
    db.execute(delete(Finding))
    db.commit()
    return {"ok": True}


@app.post("/api/scanner/active/start")
async def scanner_active_start(payload: ActiveScanStart):
    try:
        scan = scanner_manager.start(payload.model_dump())
    except ScopeError as exc:
        raise HTTPException(403, str(exc))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:
        raise HTTPException(500, f"failed to start: {exc}")
    return {"scan_id": scan.id, "total": scan.total, "status": scan.status}


@app.post("/api/scanner/active/{scan_id}/stop")
def scanner_active_stop(scan_id: str):
    if not scanner_manager.stop(scan_id):
        raise HTTPException(404, "no such scan")
    return {"ok": True}


@app.get("/api/scanner/active/{scan_id}")
def scanner_active_get(scan_id: str):
    s = scanner_manager.get(scan_id)
    if not s:
        raise HTTPException(404, "no such scan")
    return {
        "scan_id": s.id, "status": s.status, "host": s.host,
        "total": s.total, "done": s.done, "found": s.found, "error": s.error,
        "findings": s.findings,
    }


# --------------------------------------------------------------------------- #
# CVE / version diagnostics
# --------------------------------------------------------------------------- #
@app.post("/api/scanner/cve/run")
async def scanner_cve_run(payload: CveRunIn):
    """Fingerprint captured traffic and match software versions against known
    CVEs. Offline (bundled DB) always runs; online NVD lookups only when
    enabled (per-run flag, else the saved setting)."""
    online = payload.online if payload.online is not None else settings.nvd_online
    # Persist an API key supplied for this run so later runs can reuse it.
    if payload.api_key:
        settings.nvd_api_key = payload.api_key.strip()
    try:
        scan = cve_mod.cve_manager.start({
            "in_scope_only": payload.in_scope_only,
            "online": online,
            "api_key": settings.nvd_api_key,
            "limit": payload.limit,
        })
    except Exception as exc:
        raise HTTPException(500, f"failed to start: {exc}")
    return {"cve_id": scan.id, "online": online, "techs": len(scan.techs), "status": scan.status}


@app.get("/api/scanner/cve/{cve_id}")
def scanner_cve_get(cve_id: str):
    s = cve_mod.cve_manager.get(cve_id)
    if not s:
        raise HTTPException(404, "no such cve scan")
    return {
        "cve_id": s.id, "status": s.status, "online": s.online,
        "total": s.total, "done": s.done, "found": s.found, "error": s.error,
        "techs": s.techs, "findings": s.findings,
    }


# --------------------------------------------------------------------------- #
# WebSocket — captured message history + WS Repeater
# --------------------------------------------------------------------------- #
@app.get("/api/ws/messages")
def ws_messages(
    db: Session = Depends(get_session),
    conn: Optional[str] = None,
    host: Optional[str] = None,
    q: Optional[str] = None,
    limit: int = Query(500, le=5000),
):
    from .models import WsMessage
    stmt = select(WsMessage)
    if conn:
        stmt = stmt.where(WsMessage.conn_id == conn)
    if host:
        stmt = stmt.where(WsMessage.host.like(f"%{host}%"))
    if q:
        stmt = stmt.where(WsMessage.content.like(f"%{q}%"))
    rows = db.execute(stmt.order_by(desc(WsMessage.id)).limit(limit)).scalars().all()
    return [
        {
            "id": r.id, "created_at": r.created_at.isoformat() if r.created_at else None,
            "conn_id": r.conn_id, "host": r.host, "path": r.path, "url": r.url,
            "from_client": r.from_client, "is_text": r.is_text, "length": r.length,
            "in_scope": r.in_scope, "preview": (r.content or "")[:300],
        }
        for r in rows
    ]


@app.get("/api/ws/messages/{msg_id}")
def ws_message_detail(msg_id: int, db: Session = Depends(get_session)):
    from .models import WsMessage
    r = db.get(WsMessage, msg_id)
    if not r:
        raise HTTPException(404, "not found")
    return {
        "id": r.id, "conn_id": r.conn_id, "host": r.host, "path": r.path, "url": r.url,
        "from_client": r.from_client, "is_text": r.is_text, "length": r.length,
        "content": r.content, "created_at": r.created_at.isoformat() if r.created_at else None,
    }


@app.get("/api/ws/conns")
def ws_conns(db: Session = Depends(get_session)):
    from .models import WsMessage
    rows = db.execute(select(WsMessage.conn_id, WsMessage.host, WsMessage.path, WsMessage.url, WsMessage.id)).all()
    conns: dict = {}
    for conn_id, host, path, url, mid in rows:
        c = conns.setdefault(conn_id, {"conn_id": conn_id, "host": host, "path": path, "url": url, "count": 0, "last_id": 0})
        c["count"] += 1
        c["last_id"] = max(c["last_id"], mid)
    return sorted(conns.values(), key=lambda c: -c["last_id"])


@app.delete("/api/ws/messages")
def ws_messages_clear(db: Session = Depends(get_session)):
    from .models import WsMessage
    db.execute(delete(WsMessage))
    db.commit()
    return {"ok": True}


@app.post("/api/ws/repeater/connect")
async def ws_repeater_connect(payload: WsConnectIn):
    try:
        conn = await ws_repeater_manager.connect(payload.url, payload.headers)
    except ScopeError as exc:
        raise HTTPException(403, str(exc))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:
        raise HTTPException(502, f"connect failed: {exc}")
    return {"conn_id": conn.id, "status": conn.status, "url": conn.url}


@app.post("/api/ws/repeater/{cid}/send")
async def ws_repeater_send(cid: str, payload: WsSendIn):
    try:
        await ws_repeater_manager.send(cid, payload.message, payload.is_text)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:
        raise HTTPException(502, f"send failed: {exc}")
    return {"ok": True}


@app.post("/api/ws/repeater/{cid}/close")
async def ws_repeater_close(cid: str):
    await ws_repeater_manager.close(cid)
    return {"ok": True}


@app.get("/api/ws/repeater/{cid}")
def ws_repeater_get(cid: str):
    conn = ws_repeater_manager.get(cid)
    if not conn:
        raise HTTPException(404, "no such connection")
    return {
        "conn_id": conn.id, "url": conn.url, "host": conn.host,
        "status": conn.status, "error": conn.error, "messages": conn.messages,
    }


# --------------------------------------------------------------------------- #
# Sitemap
# --------------------------------------------------------------------------- #
@app.get("/api/sitemap")
def sitemap(db: Session = Depends(get_session)):
    rows = db.execute(select(Flow.host, Flow.scheme, Flow.path, Flow.method, Flow.in_scope)).all()
    hosts: dict = {}
    for host, scheme, path, method, in_scope in rows:
        h = hosts.setdefault(host, {"name": host, "scheme": scheme, "in_scope": in_scope, "children": {}, "count": 0, "methods": set()})
        h["count"] += 1
        h["methods"].add(method)
        path_only = (path or "/").split("?")[0]
        segs = [s for s in path_only.split("/") if s != ""]
        node = h
        for seg in segs:
            node = node["children"].setdefault(seg, {"name": seg, "children": {}, "count": 0, "methods": set()})
            node["count"] += 1
            node["methods"].add(method)

    def to_list(children: dict):
        out = []
        for _, n in sorted(children.items()):
            out.append({
                "name": n["name"], "count": n["count"],
                "methods": sorted(n.get("methods", set())),
                "children": to_list(n["children"]),
            })
        return out

    return [
        {
            "name": h["name"], "scheme": h["scheme"], "in_scope": h["in_scope"],
            "count": h["count"], "methods": sorted(h["methods"]),
            "children": to_list(h["children"]),
        }
        for _, h in sorted(hosts.items())
    ]


# --------------------------------------------------------------------------- #
# Decoder / tools (client-side operation applied server-side for correctness)
# --------------------------------------------------------------------------- #
@app.get("/api/tools/ops")
def tools_ops():
    return {"ops": TRANSFORM_OPS}


@app.post("/api/tools/transform")
def tools_transform(payload: TransformIn):
    try:
        return {"output": transform(payload.op, payload.input)}
    except TransformError as exc:
        return {"output": "", "error": str(exc)}


# --------------------------------------------------------------------------- #
# Intruder
# --------------------------------------------------------------------------- #
@app.post("/api/intruder/preview")
def intruder_preview(payload: dict):
    """Validate markers and report the number of payload positions."""
    template = payload.get("template", "")
    try:
        _literals, bases = split_markers(template)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return {"positions": len(bases), "base_values": bases, "marker": MARKER}


@app.post("/api/intruder/start")
async def intruder_start(payload: IntruderStart):
    # async so intruder_manager.start() can schedule the attack on this loop.
    params = payload.model_dump(by_alias=True)
    # normalize payload_sets to plain dicts with 'from' key for the engine
    params["payload_sets"] = [ps for ps in params.get("payload_sets", [])]
    try:
        attack = intruder_manager.start(params)
    except ScopeError as exc:
        raise HTTPException(403, str(exc))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:
        raise HTTPException(500, f"failed to start: {exc}")
    return {
        "attack_id": attack.id, "total": attack.total, "status": attack.status,
        "attack_type": attack.attack_type, "concurrency": attack.concurrency,
        "delay_ms": attack.delay_ms,
    }


@app.post("/api/intruder/{attack_id}/stop")
def intruder_stop(attack_id: str):
    if not intruder_manager.stop(attack_id):
        raise HTTPException(404, "no such attack")
    return {"ok": True}


@app.get("/api/intruder/{attack_id}")
def intruder_get(attack_id: str, offset: int = 0, limit: int = Query(10000, le=50000)):
    """Incremental poll: returns lightweight result summaries in completion order
    starting at `offset` (the number already received). Bodies are fetched on
    demand via the /result/{index} endpoint."""
    a = intruder_manager.get(attack_id)
    if not a:
        raise HTTPException(404, "no such attack")
    total_done = len(a.results)
    new = a.results[offset : offset + limit] if offset < total_done else []
    return {
        "attack_id": a.id, "status": a.status, "attack_type": a.attack_type,
        "host": a.host, "total": a.total, "done": a.done, "error": a.error,
        "grep": a.grep, "concurrency": a.concurrency, "delay_ms": a.delay_ms,
        "results": new,
        "result_count": total_done,
    }


@app.get("/api/intruder/{attack_id}/result/{index}")
def intruder_result_detail(attack_id: str, index: int):
    a = intruder_manager.get(attack_id)
    if not a:
        raise HTTPException(404, "no such attack")
    d = a.details.get(index)
    if d is None:
        return {"index": index, "request": "", "response": "(この結果は詳細未保持: 上限件数のみ保持)"}
    req = d.get("request", "")
    # Error results store a ready-made message; successful ones store raw bytes
    # that we decode here, on demand (not on the hot attack path).
    if d.get("error_text"):
        return {"index": index, "request": req, "response": d["error_text"]}
    head = f"{d.get('http_version', '')} {d.get('status', '')} {d.get('reason', '')}\n"
    head += "\n".join(f"{k}: {v}" for k, v in d.get("headers", []))
    body = decode_body(d.get("raw", b""), d.get("ct", ""))
    if d.get("raw_truncated"):
        body += "\n\n…(truncated)"
    return {"index": index, "request": req, "response": head + "\n\n" + body}


# --------------------------------------------------------------------------- #
# Scope
# --------------------------------------------------------------------------- #
@app.get("/api/scope")
def scope_list(db: Session = Depends(get_session)):
    rows = db.execute(select(ScopeRule).order_by(ScopeRule.id)).scalars().all()
    return [
        {"id": r.id, "host_pattern": r.host_pattern, "enabled": r.enabled, "note": r.note}
        for r in rows
    ]


@app.post("/api/scope")
def scope_add(payload: ScopeRuleIn, db: Session = Depends(get_session)):
    r = ScopeRule(host_pattern=payload.host_pattern.strip(), enabled=payload.enabled, note=payload.note)
    db.add(r)
    db.commit()
    db.refresh(r)
    scope_manager.reload()
    return {"id": r.id}


@app.put("/api/scope/{rule_id}")
def scope_toggle(rule_id: int, payload: ScopeRuleIn, db: Session = Depends(get_session)):
    r = db.get(ScopeRule, rule_id)
    if not r:
        raise HTTPException(404, "not found")
    r.host_pattern = payload.host_pattern.strip()
    r.enabled = payload.enabled
    r.note = payload.note
    db.commit()
    scope_manager.reload()
    return {"ok": True}


@app.delete("/api/scope/{rule_id}")
def scope_delete(rule_id: int, db: Session = Depends(get_session)):
    r = db.get(ScopeRule, rule_id)
    if r:
        db.delete(r)
        db.commit()
        scope_manager.reload()
    return {"ok": True}


# --------------------------------------------------------------------------- #
# WebSocket (realtime flows + intercept events)
# --------------------------------------------------------------------------- #
@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await event_bus.connect(ws)
    try:
        # Send initial snapshot.
        await ws.send_text(json.dumps({
            "type": "hello",
            "data": {
                "intercept_enabled": proxy_controller.intercept_enabled,
                "pending": proxy_controller.list_pending(),
            },
        }))
        while True:
            # We don't expect client messages; keep the socket alive.
            await ws.receive_text()
    except WebSocketDisconnect:
        await event_bus.disconnect(ws)
    except Exception:
        await event_bus.disconnect(ws)


# --------------------------------------------------------------------------- #
# Serve built frontend (if present) so the whole app runs from one origin.
# --------------------------------------------------------------------------- #
_dist = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"
if _dist.exists():
    app.mount("/", StaticFiles(directory=str(_dist), html=True), name="ui")
