"""CVE / known-vulnerability diagnostics.

Two-tier, matching the user's choice:
  * OFFLINE (always on): fingerprint the target's software/components from
    response headers, cookies and body (server banners, X-Powered-By, CMS
    generator tags, JS library versions), then match detected product+version
    against a bundled, curated database of notable CVEs. No network calls.
  * ONLINE (opt-in): additionally query the public NVD API
    (services.nvd.nist.gov) by product+version keyword for fuller coverage.
    Only product/version strings are sent — never target data. Rate-limited.

Detection-only: this reports *likely* known-vulnerable versions from banners.
It does not exploit anything.
"""
from __future__ import annotations

import asyncio
import json
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import httpx

from .config import settings
from .db import SessionLocal
from .events import event_bus
from .tools import decode_body

# --------------------------------------------------------------------------- #
# Version comparison
# --------------------------------------------------------------------------- #
def _vparse(v: str) -> Tuple[int, ...]:
    parts = re.findall(r"\d+", v or "")
    return tuple(int(p) for p in parts) if parts else (0,)


def _vcmp(a: str, b: str) -> int:
    pa, pb = _vparse(a), _vparse(b)
    n = max(len(pa), len(pb))
    pa += (0,) * (n - len(pa))
    pb += (0,) * (n - len(pb))
    return (pa > pb) - (pa < pb)


def _in_range(ver: str, rng: Dict[str, str]) -> bool:
    for op, bound in rng.items():
        c = _vcmp(ver, bound)
        if op == "lt" and not c < 0:
            return False
        if op == "le" and not c <= 0:
            return False
        if op == "gt" and not c > 0:
            return False
        if op == "ge" and not c >= 0:
            return False
        if op == "eq" and not c == 0:
            return False
    return True


# --------------------------------------------------------------------------- #
# Bundled, curated CVE database (notable / high-signal entries).
# Each: product, cve, severity (our scale), cvss, title, ranges (ANY match →
# affected), ref. Offline coverage is intentionally curated, not exhaustive;
# enable online NVD for full coverage.
# --------------------------------------------------------------------------- #
CVE_DB: List[Dict[str, Any]] = [
    # ---- nginx ----
    {"product": "nginx", "cve": "CVE-2021-23017", "severity": "high", "cvss": 7.7,
     "title": "nginx resolver off-by-one heap write", "ranges": [{"ge": "0.6.18", "lt": "1.20.1"}]},
    {"product": "nginx", "cve": "CVE-2019-20372", "severity": "medium", "cvss": 5.3,
     "title": "nginx error_page request smuggling", "ranges": [{"ge": "0.7.12", "lt": "1.17.7"}]},
    {"product": "nginx", "cve": "CVE-2017-7529", "severity": "high", "cvss": 7.5,
     "title": "nginx range filter integer overflow (info leak)", "ranges": [{"ge": "0.5.6", "lt": "1.13.3"}]},
    # ---- Apache httpd ----
    {"product": "apache", "cve": "CVE-2021-41773", "severity": "high", "cvss": 7.5,
     "title": "Apache httpd path traversal / RCE", "ranges": [{"eq": "2.4.49"}]},
    {"product": "apache", "cve": "CVE-2021-42013", "severity": "high", "cvss": 9.8,
     "title": "Apache httpd path traversal / RCE (2.4.50 fix bypass)", "ranges": [{"eq": "2.4.50"}]},
    {"product": "apache", "cve": "CVE-2021-40438", "severity": "high", "cvss": 9.0,
     "title": "Apache mod_proxy SSRF", "ranges": [{"ge": "2.4.0", "lt": "2.4.49"}]},
    {"product": "apache", "cve": "CVE-2019-0211", "severity": "high", "cvss": 7.8,
     "title": "Apache httpd local privilege escalation", "ranges": [{"ge": "2.4.17", "lt": "2.4.39"}]},
    {"product": "apache", "cve": "CVE-2017-15715", "severity": "high", "cvss": 8.1,
     "title": "Apache httpd <FilesMatch> bypass", "ranges": [{"ge": "2.4.0", "lt": "2.4.30"}]},
    # ---- OpenSSL ----
    {"product": "openssl", "cve": "CVE-2014-0160", "severity": "high", "cvss": 7.5,
     "title": "OpenSSL Heartbleed memory disclosure", "ranges": [{"ge": "1.0.1", "lt": "1.0.1g"}]},
    {"product": "openssl", "cve": "CVE-2016-2107", "severity": "medium", "cvss": 5.9,
     "title": "OpenSSL AES-NI padding oracle", "ranges": [{"ge": "1.0.1", "lt": "1.0.2h"}]},
    {"product": "openssl", "cve": "CVE-2022-3602", "severity": "high", "cvss": 7.5,
     "title": "OpenSSL X.509 punycode buffer overflow", "ranges": [{"ge": "3.0.0", "lt": "3.0.7"}]},
    {"product": "openssl", "cve": "CVE-2022-3786", "severity": "high", "cvss": 7.5,
     "title": "OpenSSL X.509 punycode buffer overflow", "ranges": [{"ge": "3.0.0", "lt": "3.0.7"}]},
    # ---- PHP ----
    {"product": "php", "cve": "CVE-2019-11043", "severity": "high", "cvss": 8.7,
     "title": "PHP-FPM env_path_info underflow RCE", "ranges": [{"ge": "7.1.0", "lt": "7.1.33"}, {"ge": "7.2.0", "lt": "7.2.24"}, {"ge": "7.3.0", "lt": "7.3.11"}]},
    {"product": "php", "cve": "CVE-2018-17082", "severity": "medium", "cvss": 6.1,
     "title": "PHP Apache2 XSS via Transfer-Encoding", "ranges": [{"lt": "5.6.38"}, {"ge": "7.0.0", "lt": "7.0.32"}, {"ge": "7.1.0", "lt": "7.1.22"}, {"ge": "7.2.0", "lt": "7.2.10"}]},
    {"product": "php", "cve": "CVE-2019-11042", "severity": "high", "cvss": 8.1,
     "title": "PHP exif_read_data heap overflow", "ranges": [{"ge": "7.1.0", "lt": "7.1.30"}, {"ge": "7.2.0", "lt": "7.2.19"}, {"ge": "7.3.0", "lt": "7.3.6"}]},
    # ---- OpenSSH (banner from Server/SSH, rarely over HTTP but supported) ----
    {"product": "openssh", "cve": "CVE-2024-6387", "severity": "high", "cvss": 8.1,
     "title": "OpenSSH regreSSHion unauthenticated RCE", "ranges": [{"ge": "8.5", "lt": "9.8"}]},
    {"product": "openssh", "cve": "CVE-2018-15473", "severity": "medium", "cvss": 5.3,
     "title": "OpenSSH username enumeration", "ranges": [{"lt": "7.7"}]},
    # ---- jQuery ----
    {"product": "jquery", "cve": "CVE-2020-11022", "severity": "medium", "cvss": 6.1,
     "title": "jQuery htmlPrefilter XSS", "ranges": [{"ge": "1.2", "lt": "3.5.0"}]},
    {"product": "jquery", "cve": "CVE-2020-11023", "severity": "medium", "cvss": 6.1,
     "title": "jQuery <option> XSS", "ranges": [{"ge": "1.0.3", "lt": "3.5.0"}]},
    {"product": "jquery", "cve": "CVE-2019-11358", "severity": "medium", "cvss": 6.1,
     "title": "jQuery prototype pollution ($.extend)", "ranges": [{"lt": "3.4.0"}]},
    {"product": "jquery", "cve": "CVE-2015-9251", "severity": "medium", "cvss": 6.1,
     "title": "jQuery cross-domain ajax XSS", "ranges": [{"lt": "3.0.0"}]},
    # ---- Bootstrap ----
    {"product": "bootstrap", "cve": "CVE-2019-8331", "severity": "medium", "cvss": 6.1,
     "title": "Bootstrap tooltip/popover XSS", "ranges": [{"lt": "3.4.1"}, {"ge": "4.0.0", "lt": "4.3.1"}]},
    {"product": "bootstrap", "cve": "CVE-2018-14041", "severity": "medium", "cvss": 6.1,
     "title": "Bootstrap data-target XSS", "ranges": [{"ge": "4.0.0", "lt": "4.1.2"}]},
    {"product": "bootstrap", "cve": "CVE-2018-20676", "severity": "medium", "cvss": 6.1,
     "title": "Bootstrap tooltip XSS", "ranges": [{"lt": "3.4.0"}]},
    # ---- AngularJS (1.x) ----
    {"product": "angularjs", "cve": "CVE-2020-7676", "severity": "medium", "cvss": 6.1,
     "title": "angular.js <textarea> sanitizer XSS", "ranges": [{"lt": "1.8.0"}]},
    {"product": "angularjs", "cve": "CVE-2019-10768", "severity": "high", "cvss": 7.5,
     "title": "angular merge prototype pollution", "ranges": [{"lt": "1.7.9"}]},
    # ---- lodash ----
    {"product": "lodash", "cve": "CVE-2021-23337", "severity": "high", "cvss": 7.2,
     "title": "lodash command injection via template", "ranges": [{"lt": "4.17.21"}]},
    {"product": "lodash", "cve": "CVE-2019-10744", "severity": "high", "cvss": 9.1,
     "title": "lodash prototype pollution (defaultsDeep)", "ranges": [{"lt": "4.17.12"}]},
    {"product": "lodash", "cve": "CVE-2020-8203", "severity": "high", "cvss": 7.4,
     "title": "lodash prototype pollution (zipObjectDeep)", "ranges": [{"lt": "4.17.16"}]},
    # ---- WordPress core ----
    {"product": "wordpress", "cve": "CVE-2022-21661", "severity": "high", "cvss": 8.0,
     "title": "WordPress WP_Query SQL injection", "ranges": [{"lt": "5.8.3"}]},
    {"product": "wordpress", "cve": "CVE-2022-21662", "severity": "high", "cvss": 8.0,
     "title": "WordPress stored XSS (authored posts)", "ranges": [{"lt": "5.8.3"}]},
    # ---- Drupal ----
    {"product": "drupal", "cve": "CVE-2018-7600", "severity": "high", "cvss": 9.8,
     "title": "Drupalgeddon2 remote code execution", "ranges": [{"ge": "7.0", "lt": "7.58"}, {"ge": "8.0", "lt": "8.5.1"}]},
    {"product": "drupal", "cve": "CVE-2019-6340", "severity": "high", "cvss": 8.1,
     "title": "Drupal REST RCE", "ranges": [{"ge": "8.0", "lt": "8.6.10"}]},
    # ---- IIS ----
    {"product": "iis", "cve": "CVE-2017-7269", "severity": "high", "cvss": 9.8,
     "title": "IIS 6.0 WebDAV ScStoragePathFromUrl overflow", "ranges": [{"eq": "6.0"}]},
]

# product -> NVD keyword used for online search
NVD_KEYWORD = {
    "nginx": "nginx", "apache": "apache http server", "openssl": "openssl",
    "php": "php", "openssh": "openssh", "jquery": "jquery", "bootstrap": "bootstrap",
    "angularjs": "angularjs", "lodash": "lodash", "wordpress": "wordpress",
    "drupal": "drupal", "joomla": "joomla", "iis": "internet information services",
    "express": "express node", "tomcat": "apache tomcat",
}
PRODUCT_LABEL = {
    "nginx": "nginx", "apache": "Apache httpd", "openssl": "OpenSSL", "php": "PHP",
    "openssh": "OpenSSH", "jquery": "jQuery", "bootstrap": "Bootstrap",
    "angularjs": "AngularJS", "lodash": "Lodash", "wordpress": "WordPress",
    "drupal": "Drupal", "joomla": "Joomla", "iis": "Microsoft IIS",
    "express": "Express", "tomcat": "Apache Tomcat",
}


# --------------------------------------------------------------------------- #
# Fingerprinting
# --------------------------------------------------------------------------- #
def _hmap(pairs) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in pairs:
        out[k.lower()] = v
    return out


_SERVER_TOKEN = re.compile(r"([A-Za-z][A-Za-z0-9_\-]*)/(\d+(?:\.\d+)+[a-z]?)")
_BODY_LIB_PATTERNS = [
    ("jquery", re.compile(r"jquery[.\-/@](\d+\.\d+(?:\.\d+)?)", re.I)),
    ("jquery", re.compile(r"jquery\s+v?(\d+\.\d+(?:\.\d+)?)", re.I)),
    ("bootstrap", re.compile(r"bootstrap[.\-/@](\d+\.\d+(?:\.\d+)?)", re.I)),
    ("bootstrap", re.compile(r"bootstrap\s+v?(\d+\.\d+(?:\.\d+)?)", re.I)),
    ("angularjs", re.compile(r"angular(?:js)?[.\-/@](\d+\.\d+(?:\.\d+)?)", re.I)),
    ("angularjs", re.compile(r"angularjs\s+v?(\d+\.\d+(?:\.\d+)?)", re.I)),
    ("lodash", re.compile(r"lodash[.\-/@](\d+\.\d+(?:\.\d+)?)", re.I)),
    ("lodash", re.compile(r"lodash[^\n]{0,40}?VERSION\s*=\s*['\"](\d+\.\d+\.\d+)", re.I)),
]
_GENERATOR_RE = re.compile(r"""<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']""", re.I)
_CMS_MAP = [("wordpress", "wordpress"), ("drupal", "drupal"), ("joomla", "joomla")]


def fingerprint_flow(row) -> List[Dict[str, str]]:
    """Return a list of detected technologies for one captured flow."""
    techs: List[Dict[str, str]] = []
    host, url = row.host, row.url

    def add(product, version, source, evidence):
        techs.append({"host": host, "url": url, "product": product,
                      "version": version or "", "source": source, "evidence": evidence[:200]})

    try:
        resp_pairs = json.loads(row.resp_headers or "[]")
    except Exception:
        resp_pairs = []
    h = _hmap(resp_pairs)

    # ---- Server / X-Powered-By / version headers ----
    server = h.get("server", "")
    for m in _SERVER_TOKEN.finditer(server):
        name, ver = m.group(1).lower(), m.group(2)
        prod = {"nginx": "nginx", "apache": "apache", "openssl": "openssl",
                "microsoft-iis": "iis"}.get(name)
        if prod:
            add(prod, ver, "Server header", server)
    if "microsoft-iis" in server.lower():
        mi = re.search(r"microsoft-iis/(\d+\.\d+)", server, re.I)
        if mi:
            add("iis", mi.group(1), "Server header", server)

    xpb = h.get("x-powered-by", "")
    for m in _SERVER_TOKEN.finditer(xpb):
        name, ver = m.group(1).lower(), m.group(2)
        prod = {"php": "php", "express": "express"}.get(name)
        if prod:
            add(prod, ver, "X-Powered-By", xpb)
    if "asp.net" in xpb.lower():
        av = h.get("x-aspnet-version", "")
        add("aspnet", av, "X-Powered-By / X-AspNet-Version", (xpb + " " + av).strip())

    # ---- cookies (framework hints; usually versionless) ----
    for k, v in resp_pairs:
        if k.lower() != "set-cookie":
            continue
        cl = v.lower()
        if "phpsessid" in cl:
            add("php", "", "PHPSESSID cookie", v.split(";")[0])
        if "wordpress_" in cl or "wp-settings" in cl:
            add("wordpress", "", "WordPress cookie", v.split(";")[0])
        if "laravel_session" in cl:
            add("laravel", "", "Laravel cookie", v.split(";")[0])

    # ---- body: generator meta + JS libraries ----
    ctype = h.get("content-type", "") or getattr(row, "mime", "") or ""
    if "text/html" in ctype or "javascript" in ctype or (not ctype and row.resp_body):
        body = (row.resp_body or b"")[:600_000]
        if body:
            text = decode_body(bytes(body), ctype)
            gm = _GENERATOR_RE.search(text)
            if gm:
                content = gm.group(1)
                low = content.lower()
                for key, prod in _CMS_MAP:
                    if key in low:
                        mver = re.search(r"(\d+\.\d+(?:\.\d+)?)", content)
                        add(prod, mver.group(1) if mver else "", "generator meta", content)
            seen = set()
            for prod, rx in _BODY_LIB_PATTERNS:
                m = rx.search(text)
                if m:
                    key = (prod, m.group(1))
                    if key not in seen:
                        seen.add(key)
                        add(prod, m.group(1), "JS library reference", m.group(0))
    return techs


# --------------------------------------------------------------------------- #
# Matching
# --------------------------------------------------------------------------- #
def match_offline(product: str, version: str) -> List[Dict[str, Any]]:
    """Return bundled-DB CVE entries affecting product+version (version req'd)."""
    if not version:
        return []
    hits = []
    for e in CVE_DB:
        if e["product"] != product:
            continue
        if any(_in_range(version, r) for r in e["ranges"]):
            hits.append(e)
    return hits


def _finding_for_cve(tech: Dict[str, str], cve: str, severity: str, cvss, title: str,
                     source: str, confidence: str, ref: str = "") -> Dict[str, Any]:
    product, version = tech["product"], tech["version"]
    label = PRODUCT_LABEL.get(product, product)
    url = f"https://nvd.nist.gov/vuln/detail/{cve}"
    ref = ref or url
    cvss_s = f" CVSS {cvss}" if cvss else ""
    detail = (f"{label} {version} は {cve}{cvss_s} の影響を受ける可能性があります。"
              f"{title}。検出元: {tech['source']}（{source}）。参考: {ref}")
    f = {
        "kind": "cve", "severity": severity, "confidence": confidence,
        "title": f"{cve}: {title}",
        "host": tech["host"], "url": tech.get("url") or f"https://{tech['host']}/",
        "method": "GET", "param": f"{label} {version}".strip(),
        "evidence": (tech.get("evidence") or f"{label}/{version}")[:400],
        "detail": detail,
        "dedupe_key": f"cve|{cve}|{tech['host']}|{product}|{version}"[:512],
    }
    return f


def offline_findings_for_flow(row) -> List[Dict[str, Any]]:
    """Offline-only CVE findings for one flow (used by the passive scan)."""
    out: List[Dict[str, Any]] = []
    seen = set()
    for tech in fingerprint_flow(row):
        for e in match_offline(tech["product"], tech["version"]):
            key = (e["cve"], tech["host"], tech["version"])
            if key in seen:
                continue
            seen.add(key)
            out.append(_finding_for_cve(tech, e["cve"], e["severity"], e.get("cvss"),
                                        e["title"], "bundled DB", "firm"))
    return out


# --------------------------------------------------------------------------- #
# Online NVD lookup (opt-in)
# --------------------------------------------------------------------------- #
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _nvd_sev(cve_obj) -> Tuple[str, Optional[float]]:
    metrics = cve_obj.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr:
            data = arr[0].get("cvssData", {})
            score = data.get("baseScore")
            sev = data.get("baseSeverity") or arr[0].get("baseSeverity")
            if not sev and score is not None:
                sev = "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"
            return (sev or "MEDIUM"), score
    return ("MEDIUM", None)


def _map_sev(nvd_sev: str) -> str:
    s = (nvd_sev or "").upper()
    if s in ("CRITICAL", "HIGH"):
        return "high"
    if s == "MEDIUM":
        return "medium"
    if s == "LOW":
        return "low"
    return "info"


def _parse_nvd(data: Dict[str, Any]) -> List[Tuple[str, str, Optional[float], str]]:
    out = []
    for item in data.get("vulnerabilities", []):
        c = item.get("cve", {})
        cid = c.get("id", "")
        if not cid:
            continue
        desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
        sev, score = _nvd_sev(c)
        out.append((cid, _map_sev(sev), score, desc[:300]))
    return out


async def nvd_lookup(client: httpx.AsyncClient, product: str, version: str,
                     api_key: str, limit: int = 15) -> List[Tuple[str, str, Optional[float], str]]:
    kw = f"{NVD_KEYWORD.get(product, product)} {version}".strip()
    params = {"keywordSearch": kw, "resultsPerPage": str(limit)}
    headers = {"apiKey": api_key} if api_key else {}
    try:
        r = await client.get(NVD_URL, params=params, headers=headers)
        if r.status_code != 200:
            return []
        data = r.json()
    except Exception:
        return []
    return _parse_nvd(data)


# --------------------------------------------------------------------------- #
# CVE scan job (offline always + optional online), async like the active scan.
# --------------------------------------------------------------------------- #
@dataclass
class CveScan:
    id: str
    online: bool = False
    status: str = "running"
    total: int = 0
    done: int = 0
    found: int = 0
    error: str = ""
    techs: List[Dict[str, str]] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    task: Optional[asyncio.Task] = None


class CveManager:
    def __init__(self) -> None:
        self.scans: Dict[str, CveScan] = {}

    def get(self, sid: str) -> Optional[CveScan]:
        return self.scans.get(sid)

    def start(self, params: Dict[str, Any]) -> CveScan:
        from .models import Flow
        from sqlalchemy import desc, select
        limit = int(params.get("limit") or 1000)
        in_scope_only = bool(params.get("in_scope_only", False))
        online = bool(params.get("online", settings.nvd_online))
        api_key = (params.get("api_key") or settings.nvd_api_key or "").strip()

        with SessionLocal() as db:
            stmt = select(Flow).order_by(desc(Flow.id)).limit(limit)
            if in_scope_only:
                stmt = stmt.where(Flow.in_scope == True)  # noqa: E712
            rows = db.execute(stmt).scalars().all()

        # Fingerprint + dedupe technologies by (host, product, version).
        techs: List[Dict[str, str]] = []
        seen = set()
        for row in rows:
            for tech in fingerprint_flow(row):
                key = (tech["host"], tech["product"], tech["version"])
                if key in seen:
                    continue
                seen.add(key)
                techs.append(tech)

        scan = CveScan(id=uuid.uuid4().hex[:12], online=online, techs=techs)
        self.scans[scan.id] = scan
        scan.task = asyncio.create_task(self._run(scan, techs, online, api_key))
        return scan

    async def _run(self, scan: CveScan, techs, online: bool, api_key: str) -> None:
        try:
            # ---- offline (always) ----
            for tech in techs:
                for e in match_offline(tech["product"], tech["version"]):
                    f = _finding_for_cve(tech, e["cve"], e["severity"], e.get("cvss"),
                                         e["title"], "bundled DB", "firm")
                    if persist_finding(f):
                        scan.findings.append(f)
                        scan.found += 1
                        event_bus.publish("finding", {"cve_id": scan.id, **f})
                scan.done += 1

            # ---- online NVD (opt-in) ----
            if online:
                # Only query techs we have a version for; dedupe by (product,version).
                queries = []
                qseen = set()
                for tech in techs:
                    if not tech["version"]:
                        continue
                    k = (tech["product"], tech["version"])
                    if k in qseen:
                        continue
                    qseen.add(k)
                    queries.append(tech)
                queries = queries[:20]  # hard cap per run
                scan.total = len(techs) + len(queries)
                # NVD rate limit: ~5 req / 30s without key, ~50 with key.
                sleep_s = 0.8 if api_key else 6.5
                timeout = httpx.Timeout(connect=8.0, read=20.0, write=20.0, pool=20.0)
                async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
                    for i, tech in enumerate(queries):
                        if i:
                            await asyncio.sleep(sleep_s)
                        hits = await nvd_lookup(client, tech["product"], tech["version"], api_key)
                        for cid, sev, score, desc in hits:
                            f = _finding_for_cve(tech, cid, sev, score, desc or "(NVD)",
                                                 "NVD online", "tentative")
                            if persist_finding(f):
                                scan.findings.append(f)
                                scan.found += 1
                                event_bus.publish("finding", {"cve_id": scan.id, **f})
                        scan.done += 1
            else:
                scan.total = len(techs)
            scan.status = "done"
        except Exception as exc:  # pragma: no cover
            scan.status = "error"
            scan.error = str(exc)
        scan.total = max(scan.total, scan.done)
        event_bus.publish("cve_done", {"cve_id": scan.id, "status": scan.status,
                                       "found": scan.found, "techs": len(techs)})


def persist_finding(f: Dict[str, Any]) -> bool:
    from sqlalchemy import select

    from .models import Finding
    with SessionLocal() as db:
        exists = db.execute(select(Finding.id).where(Finding.dedupe_key == f["dedupe_key"])).first()
        if exists:
            return False
        db.add(Finding(
            kind=f["kind"], severity=f["severity"], confidence=f["confidence"],
            title=f["title"], detail=f["detail"], host=f["host"], url=f["url"],
            method=f["method"], param=f["param"], evidence=f["evidence"],
            dedupe_key=f["dedupe_key"],
        ))
        try:
            db.commit()
            return True
        except Exception:
            db.rollback()
            return False


cve_manager = CveManager()
