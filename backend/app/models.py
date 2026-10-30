"""Database models."""
from __future__ import annotations

import datetime as dt

from sqlalchemy import (
    Boolean,
    DateTime,
    Integer,
    LargeBinary,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class Flow(Base):
    """A single captured request/response pair.

    `source` distinguishes proxy traffic from Repeater/Intruder-generated
    requests so the history stays honest about what the tool itself sent.
    """

    __tablename__ = "flows"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    flow_uuid: Mapped[str] = mapped_column(String(64), index=True, unique=True)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, index=True
    )
    source: Mapped[str] = mapped_column(String(16), default="proxy", index=True)

    # Request
    method: Mapped[str] = mapped_column(String(10), index=True)
    scheme: Mapped[str] = mapped_column(String(8))
    host: Mapped[str] = mapped_column(String(255), index=True)
    port: Mapped[int] = mapped_column(Integer, default=0)
    path: Mapped[str] = mapped_column(Text)
    url: Mapped[str] = mapped_column(Text, index=True)
    req_headers: Mapped[str] = mapped_column(Text, default="[]")  # JSON list[[k,v]]
    req_body: Mapped[bytes] = mapped_column(LargeBinary, default=b"")

    # Response
    status_code: Mapped[int] = mapped_column(Integer, default=0, index=True)
    reason: Mapped[str] = mapped_column(String(128), default="")
    resp_headers: Mapped[str] = mapped_column(Text, default="[]")  # JSON list[[k,v]]
    resp_body: Mapped[bytes] = mapped_column(LargeBinary, default=b"")
    resp_body_truncated: Mapped[bool] = mapped_column(Boolean, default=False)
    resp_length: Mapped[int] = mapped_column(Integer, default=0)
    mime: Mapped[str] = mapped_column(String(128), default="")

    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    in_scope: Mapped[bool] = mapped_column(Boolean, default=False, index=True)


class ScopeRule(Base):
    """An explicit allow-list entry for active features.

    Active tooling (Repeater auto-send, Intruder, Scanner) is default-deny:
    a host must be represented here (and enabled) to be targeted.
    """

    __tablename__ = "scope_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # host pattern, e.g. "example.com" or "*.internal.test"
    host_pattern: Mapped[str] = mapped_column(String(255), index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    note: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )


class WsMessage(Base):
    """A single WebSocket message captured through the proxy."""

    __tablename__ = "ws_messages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, index=True
    )
    conn_id: Mapped[str] = mapped_column(String(64), index=True)  # upgraded flow id
    host: Mapped[str] = mapped_column(String(255), index=True)
    path: Mapped[str] = mapped_column(Text, default="")
    url: Mapped[str] = mapped_column(Text, default="")
    from_client: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    is_text: Mapped[bool] = mapped_column(Boolean, default=True)
    content: Mapped[str] = mapped_column(Text, default="")
    length: Mapped[int] = mapped_column(Integer, default=0)
    in_scope: Mapped[bool] = mapped_column(Boolean, default=False)


class Finding(Base):
    """A scanner finding (passive analysis or active detection).

    Active findings are only ever produced for in-scope hosts (default-deny).
    Severity/confidence follow common DAST conventions.
    """

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, index=True
    )
    kind: Mapped[str] = mapped_column(String(16), index=True)  # passive | active
    severity: Mapped[str] = mapped_column(String(12), index=True)  # info|low|medium|high
    confidence: Mapped[str] = mapped_column(String(12), default="tentative")
    title: Mapped[str] = mapped_column(String(255), index=True)
    detail: Mapped[str] = mapped_column(Text, default="")
    host: Mapped[str] = mapped_column(String(255), default="", index=True)
    url: Mapped[str] = mapped_column(Text, default="")
    method: Mapped[str] = mapped_column(String(10), default="")
    param: Mapped[str] = mapped_column(String(255), default="")
    evidence: Mapped[str] = mapped_column(Text, default="")
    # Stable key for dedupe (kind|title|host|param|url-ish).
    dedupe_key: Mapped[str] = mapped_column(String(512), index=True, default="")
    # The HTTP-history flow that proves this finding (0 = none). Lets the UI
    # jump straight to the request/response that triggered the detection.
    flow_id: Mapped[int] = mapped_column(Integer, default=0, index=True)


class RepeaterTab(Base):
    """Persisted Repeater tab so drafts survive restarts."""

    __tablename__ = "repeater_tabs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128), default="Repeater")
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )
    # The editable request draft, stored as raw fields.
    method: Mapped[str] = mapped_column(String(10), default="GET")
    scheme: Mapped[str] = mapped_column(String(8), default="https")
    host: Mapped[str] = mapped_column(String(255), default="")
    port: Mapped[int] = mapped_column(Integer, default=0)
    path: Mapped[str] = mapped_column(Text, default="/")
    headers: Mapped[str] = mapped_column(Text, default="[]")  # JSON list[[k,v]]
    body: Mapped[bytes] = mapped_column(LargeBinary, default=b"")
