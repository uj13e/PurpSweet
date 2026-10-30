"""Pydantic request/response schemas for the API."""
from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field


class InterceptState(BaseModel):
    enabled: bool


class InterceptDecision(BaseModel):
    action: str = Field("forward", pattern="^(forward|drop)$")
    method: Optional[str] = None
    path: Optional[str] = None
    headers: Optional[List[List[str]]] = None
    body: Optional[str] = None


class RepeaterSend(BaseModel):
    method: str = "GET"
    scheme: str = "https"
    host: str
    port: int = 0
    path: str = "/"
    headers: List[List[str]] = Field(default_factory=list)
    body: str = ""
    timeout: float = 30.0
    verify_tls: bool = False


class TransformIn(BaseModel):
    op: str
    input: str = ""


class SettingsIn(BaseModel):
    upstream_proxy: Optional[str] = None
    connect_timeout: Optional[float] = None
    nvd_online: Optional[bool] = None
    nvd_api_key: Optional[str] = None


class CveRunIn(BaseModel):
    in_scope_only: bool = False
    online: Optional[bool] = None
    api_key: Optional[str] = None
    limit: int = 1000


class PassiveScanIn(BaseModel):
    in_scope_only: bool = False
    limit: int = 5000


class ActiveScanStart(BaseModel):
    scheme: str = "https"
    host: str
    port: int = 0
    method: str = "GET"
    path: str = "/"
    headers: List[List[str]] = Field(default_factory=list)
    body: str = ""
    categories: List[str] = Field(default_factory=lambda: [
        "sqli", "xss", "cmdi", "traversal", "ssti", "openredirect", "crlf",
        "xxe", "nosql", "ldap", "hostheader", "cors",
    ])
    techniques: List[str] = Field(default_factory=lambda: ["error", "boolean", "time", "reflect"])
    time_delay: int = 5
    follow_redirects: bool = True
    scan_headers: bool = False
    concurrency: int = 5
    delay_ms: int = 0
    timeout: float = 20.0
    verify_tls: bool = False
    record_history: bool = True


class WsConnectIn(BaseModel):
    url: str
    headers: List[List[str]] = Field(default_factory=list)


class WsSendIn(BaseModel):
    message: str
    is_text: bool = True


class ScopeRuleIn(BaseModel):
    host_pattern: str
    enabled: bool = True
    note: str = ""


class PayloadSet(BaseModel):
    type: str = "list"  # list | range | file
    values: List[str] = Field(default_factory=list)
    # range params
    from_: int = Field(0, alias="from")
    to: int = 0
    step: int = 1

    model_config = {"populate_by_name": True}


class IntruderStart(BaseModel):
    scheme: str = "https"
    host: str
    port: int = 0
    template: str
    attack_type: str = Field("sniper", pattern="^(sniper|battering_ram|pitchfork|cluster_bomb)$")
    payload_sets: List[PayloadSet] = Field(default_factory=list)
    grep: List[str] = Field(default_factory=list)
    concurrency: int = 5
    delay_ms: int = 0
    retries: int = 3
    timeout: float = 30.0
    verify_tls: bool = False
    record_history: bool = False


class RepeaterTabIn(BaseModel):
    name: str = "Repeater"
    method: str = "GET"
    scheme: str = "https"
    host: str = ""
    port: int = 0
    path: str = "/"
    headers: List[List[str]] = Field(default_factory=list)
    body: str = ""
