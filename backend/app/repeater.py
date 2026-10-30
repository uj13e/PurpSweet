"""Repeater engine — craft one request, send it, compare responses.

Policy: even though Repeater is manual, every tool-initiated send is routed
through the scope gate (default-deny). Add the target host to Scope first.
This keeps a single, auditable rule: this tool never emits traffic to a host
you have not explicitly authorized.
"""
from __future__ import annotations

import json
import time
import uuid
from typing import Any, Dict, List, Optional

import httpx

from .config import settings
from .db import SessionLocal
from .events import event_bus
from .models import Flow
from .scope import scope_manager
from .tools import decode_body, httpx_client_kwargs, strip_encoding_headers


def _list_to_headers(pairs: List[List[str]]) -> List[tuple[str, str]]:
    out = []
    for p in pairs or []:
        if len(p) == 2 and p[0]:
            out.append((str(p[0]), str(p[1])))
    return out


def send_request(
    *,
    method: str,
    scheme: str,
    host: str,
    port: int,
    path: str,
    headers: List[List[str]],
    body: Optional[bytes],
    timeout: float = 30.0,
    verify_tls: bool = False,
) -> Dict[str, Any]:
    """Send a single crafted request. Raises ScopeError if host not authorized."""
    scope_manager.require_in_scope(host)

    if not port:
        port = 443 if scheme == "https" else 80
    netloc = host if (
        (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
    ) else f"{host}:{port}"
    if not path.startswith("/"):
        path = "/" + path
    url = f"{scheme}://{netloc}{path}"

    if body is None:
        body = b""

    # Drop auto-managed framing headers so the HTTP client recomputes the
    # correct Content-Length from the ACTUAL body. A stale Content-Length left
    # over from the edited request otherwise triggers
    # "Too little data for declared Content-Length". This mirrors Burp's
    # default "Update Content-Length" behavior.
    _DROP = {"content-length", "transfer-encoding"}
    hdr_pairs = [(k, v) for (k, v) in _list_to_headers(headers) if k.lower() not in _DROP]

    t0 = time.perf_counter()
    with httpx.Client(verify=verify_tls, follow_redirects=False, **httpx_client_kwargs(timeout)) as client:
        req = client.build_request(method, url, headers=hdr_pairs, content=body)
        resp = client.send(req)
        raw = resp.content
    dt_ms = int((time.perf_counter() - t0) * 1000)

    # httpx has already decoded gzip/deflate (and br/zstd when those libs are
    # present), so the stored body is plain text — drop content-encoding/length
    # so the history viewer doesn't mistake it for still-compressed.
    resp_headers = strip_encoding_headers([[k, v] for k, v in resp.headers.items()])
    truncated = False
    stored = raw
    if len(stored) > settings.max_body_store:
        stored = stored[: settings.max_body_store]
        truncated = True

    row = Flow(
        flow_uuid=str(uuid.uuid4()),
        source="repeater",
        method=method,
        scheme=scheme,
        host=host,
        port=port,
        path=path,
        url=url,
        req_headers=json.dumps(headers or []),
        req_body=body,
        status_code=resp.status_code,
        reason=resp.reason_phrase or "",
        resp_headers=json.dumps(resp_headers),
        resp_body=stored,
        resp_body_truncated=truncated,
        resp_length=len(raw),
        mime=resp.headers.get("content-type", ""),
        duration_ms=dt_ms,
        in_scope=True,
    )
    with SessionLocal() as db:
        db.add(row)
        db.commit()
        db.refresh(row)
        flow_id = row.id

    event_bus.publish("flow", {
        "id": flow_id, "source": "repeater", "method": method, "host": host,
        "url": url, "status_code": resp.status_code,
        "mime": resp.headers.get("content-type", ""),
        "resp_length": len(raw), "duration_ms": dt_ms, "in_scope": True,
    })

    return {
        "flow_id": flow_id,
        "status_code": resp.status_code,
        "reason": resp.reason_phrase or "",
        "headers": resp_headers,
        "body": decode_body(stored, resp.headers.get("content-type", "")),
        "resp_length": len(raw),
        "truncated": truncated,
        "duration_ms": dt_ms,
        "http_version": resp.http_version,
    }
