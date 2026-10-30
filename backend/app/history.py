"""Shared helper to record a tool-initiated request/response into HTTP history.

Repeater has always persisted its sends; Scanner and Intruder now do too (so
their traffic is visible in HTTP history and a finding can point at the exact
exchange that proved it). Bodies are capped to keep the DB from ballooning on
large scans.
"""
from __future__ import annotations

import json
import uuid
from typing import List, Optional, Tuple

from .db import SessionLocal
from .events import event_bus
from .models import Flow
from .tools import strip_encoding_headers

FLOW_BODY_CAP = 200_000


def _summary(row: Flow) -> dict:
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


def record_flow(
    *,
    source: str,
    method: str,
    scheme: str,
    host: str,
    port: int,
    path: str,
    url: str,
    req_headers: List[Tuple[str, str]],
    req_body: bytes,
    status: int,
    reason: str,
    resp_headers: List[Tuple[str, str]],
    resp_body: bytes,
    resp_length: int,
    mime: str,
    duration_ms: int,
    in_scope: bool,
    publish: bool = True,
) -> int:
    """Insert one Flow row and return its id (0 on failure)."""
    rb = bytes(resp_body or b"")
    truncated = False
    if len(rb) > FLOW_BODY_CAP:
        rb = rb[:FLOW_BODY_CAP]
        truncated = True
    qb = bytes(req_body or b"")[:FLOW_BODY_CAP]
    row = Flow(
        flow_uuid=str(uuid.uuid4()),
        source=source,
        method=method,
        scheme=scheme,
        host=host,
        port=port or 0,
        path=path,
        url=url,
        req_headers=json.dumps([[k, v] for k, v in (req_headers or [])]),
        req_body=qb,
        status_code=status,
        reason=reason or "",
        resp_headers=json.dumps(strip_encoding_headers([[k, v] for k, v in (resp_headers or [])])),
        resp_body=rb,
        resp_body_truncated=truncated,
        resp_length=resp_length,
        mime=mime or "",
        duration_ms=duration_ms,
        in_scope=in_scope,
    )
    with SessionLocal() as db:
        db.add(row)
        try:
            db.commit()
            db.refresh(row)
        except Exception:
            db.rollback()
            return 0
        fid = row.id
        if publish:
            event_bus.publish("flow", _summary(row))
    return fid
