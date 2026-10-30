"""Intruder — automated request generation over payload positions.

Authorized-testing only. Every attack:
  * targets a single fixed host/port/scheme (checked against Scope, default-deny),
  * obeys mandatory rate limits (max concurrency + inter-request delay),
  * is bounded by a hard cap on total requests to prevent runaway load.

Marker syntax (Burp-style): wrap the text to replace with the section sign, e.g.
    id=§1§&name=§bob§
Each §...§ pair is a payload *position*; the text between the markers is the
"base value" (used by Sniper for the positions it is not currently attacking).

Attack modes:
  * sniper        - 1 payload set; one position at a time, others = base value.
  * battering_ram - 1 payload set; same value in ALL positions at once.
  * pitchfork     - N payload sets (one per position); iterate in parallel (zip).
  * cluster_bomb  - N payload sets (one per position); all combinations (product).
"""
from __future__ import annotations

import asyncio
import itertools
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

import httpx

from .config import settings
from .events import event_bus
from .history import record_flow
from .scope import scope_manager
from .tools import decode_body, httpx_client_kwargs

MARKER = "§"  # §
MAX_TOTAL = int(getattr(settings, "intruder_max_total", 0) or 100_000)
# Keep full request/response text for at most this many results (memory bound).
DETAIL_CAP = 5000
DETAIL_BODY_MAX = 20000
# Raw response bytes kept per result for lazy (on-open) rendering. Decoding is
# deferred to the detail endpoint so the attack loop stays off the CPU and the
# UI thread is never starved while an attack runs.
DETAIL_BODY_MAX_BYTES = 32768


# --------------------------------------------------------------------------- #
# Raw request parsing / marker handling (pure functions, unit-tested)
# --------------------------------------------------------------------------- #
def parse_raw_request(raw: str) -> Tuple[str, str, List[List[str]], str]:
    norm = raw.replace("\r\n", "\n")
    idx = norm.find("\n\n")
    head = norm[:idx] if idx >= 0 else norm
    body = norm[idx + 2 :] if idx >= 0 else ""
    lines = head.split("\n")
    first = lines[0].strip() if lines else ""
    parts = first.split()
    method = parts[0] if parts else "GET"
    path = parts[1] if len(parts) > 1 else "/"
    headers: List[List[str]] = []
    for line in lines[1:]:
        c = line.find(":")
        if c > 0:
            headers.append([line[:c].strip(), line[c + 1 :].strip()])
    return method, path, headers, body


def split_markers(template: str) -> Tuple[List[str], List[str]]:
    """Return (literals, base_values). num_positions == len(base_values).

    literals has len == num_positions + 1 and is interleaved with payloads to
    rebuild the request.
    """
    parts = template.split(MARKER)
    if len(parts) % 2 == 0:
        raise ValueError("Unbalanced markers: every position needs a pair of §")
    literals = parts[0::2]
    bases = parts[1::2]
    return literals, bases


def build_from_positions(literals: List[str], payloads: List[str]) -> str:
    out: List[str] = []
    for i, lit in enumerate(literals):
        out.append(lit)
        if i < len(payloads):
            out.append(payloads[i])
    return "".join(out)


# --------------------------------------------------------------------------- #
# Payload expansion
# --------------------------------------------------------------------------- #
def expand_payload_set(ps: Dict[str, Any]) -> List[str]:
    t = (ps.get("type") or "list").lower()
    if t == "range":
        start = int(ps.get("from", 0))
        to = int(ps.get("to", 0))
        step = int(ps.get("step", 1)) or 1
        vals: List[str] = []
        x = start
        if step > 0:
            while x <= to:
                vals.append(str(x)); x += step
        else:
            while x >= to:
                vals.append(str(x)); x += step
        return vals
    # 'list' or 'file' (file already expanded to values on the client)
    values = ps.get("values") or []
    return [str(v) for v in values]


def count_total(attack_type: str, num_pos: int, sets: List[List[str]]) -> int:
    if num_pos == 0:
        return 0
    if attack_type == "sniper":
        return num_pos * len(sets[0]) if sets else 0
    if attack_type == "battering_ram":
        return len(sets[0]) if sets else 0
    if attack_type == "pitchfork":
        return min((len(s) for s in sets), default=0)
    if attack_type == "cluster_bomb":
        total = 1
        for s in sets:
            total *= len(s)
        return total if sets else 0
    return 0


def generate_jobs(
    attack_type: str, num_pos: int, bases: List[str], sets: List[List[str]]
) -> Iterator[List[str]]:
    """Yield one payload tuple (len == num_pos) per request."""
    if num_pos == 0 or not sets:
        return
    if attack_type == "sniper":
        s0 = sets[0]
        for pos in range(num_pos):
            for v in s0:
                tup = list(bases)  # non-targeted positions revert to base value
                tup[pos] = v
                yield tup
    elif attack_type == "battering_ram":
        for v in sets[0]:
            yield [v] * num_pos
    elif attack_type == "pitchfork":
        for combo in zip(*sets):
            yield list(combo)
    elif attack_type == "cluster_bomb":
        for combo in itertools.product(*sets):
            yield list(combo)


# --------------------------------------------------------------------------- #
# Attack state + manager
# --------------------------------------------------------------------------- #
@dataclass
class Attack:
    id: str
    scheme: str
    host: str
    port: int
    attack_type: str
    literals: List[str]
    grep: List[str]
    concurrency: int
    delay_ms: int
    verify_tls: bool
    total: int
    retries: int = 3
    timeout: float = 30.0
    record_history: bool = False
    status: str = "running"  # running | done | stopped | error
    done: int = 0
    error: str = ""
    stop_flag: bool = False
    results: List[Dict[str, Any]] = field(default_factory=list)   # lightweight summaries
    details: Dict[int, Dict[str, str]] = field(default_factory=dict)  # index -> {request, response}
    task: Optional[asyncio.Task] = None


class IntruderManager:
    def __init__(self) -> None:
        self.attacks: Dict[str, Attack] = {}

    def get(self, attack_id: str) -> Optional[Attack]:
        return self.attacks.get(attack_id)

    def stop(self, attack_id: str) -> bool:
        a = self.attacks.get(attack_id)
        if not a:
            return False
        a.stop_flag = True
        return True

    def start(self, params: Dict[str, Any]) -> Attack:
        scheme = params.get("scheme", "https")
        host = params["host"]
        port = int(params.get("port") or (443 if scheme == "https" else 80))

        # Single scope gate for the whole attack (fixed target host).
        scope_manager.require_in_scope(host)

        template = params["template"]
        literals, bases = split_markers(template)
        num_pos = len(bases)
        if num_pos == 0:
            raise ValueError("No payload positions: mark at least one §position§.")

        attack_type = params.get("attack_type", "sniper")
        raw_sets = params.get("payload_sets") or []
        sets = [expand_payload_set(ps) for ps in raw_sets]

        # Validate payload-set count per mode.
        if attack_type in ("sniper", "battering_ram"):
            if not sets or not sets[0]:
                raise ValueError("This mode needs one non-empty payload set.")
            sets = [sets[0]]
        else:  # pitchfork / cluster_bomb
            if len(sets) != num_pos:
                raise ValueError(
                    f"{attack_type} needs one payload set per position "
                    f"({num_pos} positions, got {len(sets)})."
                )
            if any(len(s) == 0 for s in sets):
                raise ValueError("Every payload set must be non-empty.")

        total = count_total(attack_type, num_pos, sets)
        if total <= 0:
            raise ValueError("Nothing to send (empty payloads).")
        if total > MAX_TOTAL:
            raise ValueError(
                f"This attack would send {total:,} requests, over the safety cap "
                f"of {MAX_TOTAL:,}. Narrow the payloads/positions or raise "
                f"WEBSEC_INTRUDER_MAX_TOTAL."
            )

        concurrency = max(1, min(int(params.get("concurrency") or settings.default_max_concurrency), 100))
        delay_ms = max(0, int(params.get("delay_ms") if params.get("delay_ms") is not None else settings.default_min_interval_ms))

        retries = max(0, min(int(params.get("retries", 3)), 10))
        attack = Attack(
            id=uuid.uuid4().hex[:12],
            scheme=scheme, host=host, port=port,
            attack_type=attack_type, literals=literals,
            grep=[g for g in (params.get("grep") or []) if g],
            concurrency=concurrency, delay_ms=delay_ms,
            verify_tls=bool(params.get("verify_tls", False)),
            total=total, retries=retries, timeout=float(params.get("timeout") or 30.0),
            record_history=bool(params.get("record_history", False)),
        )
        self.attacks[attack.id] = attack

        jobs = generate_jobs(attack_type, num_pos, bases, sets)
        attack.task = asyncio.create_task(self._run(attack, jobs))
        return attack

    async def _run(self, attack: Attack, jobs: Iterable[List[str]]) -> None:
        sem = asyncio.Semaphore(attack.concurrency)
        base_url_host = attack.host if (
            (attack.scheme == "https" and attack.port == 443)
            or (attack.scheme == "http" and attack.port == 80)
        ) else f"{attack.host}:{attack.port}"

        # Size the connection pool to the requested concurrency so it actually
        # parallelizes (httpx defaults would bottleneck at 20 keep-alive conns).
        limits = httpx.Limits(
            max_connections=max(attack.concurrency * 2, 40),
            max_keepalive_connections=max(attack.concurrency, 20),
        )
        try:
            async with httpx.AsyncClient(
                verify=attack.verify_tls, follow_redirects=False, limits=limits,
                **httpx_client_kwargs(attack.timeout),
            ) as client:

                async def one(idx: int, tup: List[str]) -> None:
                    if attack.stop_flag:
                        return
                    async with sem:
                        if attack.stop_flag:
                            return
                        await self._send_one(client, attack, base_url_host, idx, tup)
                        if attack.delay_ms:
                            await asyncio.sleep(attack.delay_ms / 1000.0)

                pending: set = set()
                idx = 0
                for tup in jobs:
                    if attack.stop_flag:
                        break
                    pending.add(asyncio.create_task(one(idx, tup)))
                    idx += 1
                    if len(pending) >= attack.concurrency * 2:
                        done, pending = await asyncio.wait(
                            pending, return_when=asyncio.FIRST_COMPLETED
                        )
                if pending:
                    await asyncio.wait(pending)

            attack.status = "stopped" if attack.stop_flag else "done"
        except Exception as exc:  # pragma: no cover
            attack.status = "error"
            attack.error = str(exc)
        event_bus.publish("intruder_done", {
            "attack_id": attack.id, "status": attack.status,
            "done": attack.done, "total": attack.total, "error": attack.error,
        })

    async def _send_one(
        self, client: httpx.AsyncClient, attack: Attack,
        netloc: str, idx: int, tup: List[str],
    ) -> None:
        req_text = build_from_positions(attack.literals, tup)
        method, path, headers, body = parse_raw_request(req_text)
        if not path.startswith("/"):
            path = "/" + path
        url = f"{attack.scheme}://{netloc}{path}"
        drop = {"content-length", "transfer-encoding"}
        hdr_pairs = [(k, v) for k, v in headers if k and k.lower() not in drop]

        keep_detail = idx < DETAIL_CAP
        # Lightweight summary only — request/response bodies are fetched on demand.
        result: Dict[str, Any] = {
            "index": idx, "payloads": tup, "status_code": 0,
            "resp_length": 0, "duration_ms": 0, "matched": False,
            "matches": [], "error": "", "retries": 0, "flow_id": 0,
        }
        body_bytes = body.encode("utf-8", "replace")
        t0 = time.perf_counter()
        # Retry transient network failures (connect/read timeouts, resets) so a
        # flaky hop doesn't lose a result. Only network errors are retried, not
        # HTTP status codes.
        attempts = max(1, attack.retries + 1)
        last_exc: Optional[Exception] = None
        for att in range(attempts):
            if attack.stop_flag:
                break
            try:
                req = client.build_request(method, url, headers=hdr_pairs, content=body_bytes)
                resp = await client.send(req)
                raw = resp.content
                result["status_code"] = resp.status_code
                result["resp_length"] = len(raw)
                result["retries"] = att
                result["error"] = ""
                last_exc = None
                # grep needs the decoded body now; everything else is deferred.
                if attack.grep:
                    text = decode_body(raw, resp.headers.get("content-type", ""))
                    hit = [g for g in attack.grep if g in text]
                    result["matches"] = hit
                    result["matched"] = bool(hit)
                if keep_detail:
                    # Store only raw pieces — NO decode here. The detail endpoint
                    # decodes on demand (keeps the attack loop CPU-light so the
                    # UI stays responsive even at high concurrency).
                    attack.details[idx] = {
                        "request": req_text[:12000],
                        "http_version": resp.http_version,
                        "status": resp.status_code,
                        "reason": resp.reason_phrase or "",
                        "headers": [[k, v] for k, v in resp.headers.items()],
                        "ct": resp.headers.get("content-type", ""),
                        "raw": bytes(raw[:DETAIL_BODY_MAX_BYTES]),
                        "raw_truncated": len(raw) > DETAIL_BODY_MAX_BYTES,
                    }
                # Opt-in: mirror this request into HTTP history (off by default
                # since a big attack would flood it; results are viewable per-row
                # regardless).
                if attack.record_history:
                    try:
                        fid = record_flow(
                            source="intruder", method=method, scheme=attack.scheme,
                            host=attack.host, port=attack.port, path=path, url=url,
                            req_headers=hdr_pairs, req_body=body_bytes,
                            status=resp.status_code, reason=resp.reason_phrase or "",
                            resp_headers=[(k, v) for k, v in resp.headers.items()],
                            resp_body=raw, resp_length=len(raw),
                            mime=resp.headers.get("content-type", ""),
                            duration_ms=int((time.perf_counter() - t0) * 1000), in_scope=True,
                            publish=False,  # avoid flooding the live WS feed
                        )
                        result["flow_id"] = fid
                    except Exception:
                        pass
                break
            except (httpx.TransportError, httpx.TimeoutException) as exc:
                last_exc = exc
                result["retries"] = att + 1
                if att < attempts - 1:
                    await asyncio.sleep(min(0.1 * (att + 1), 1.0))  # brief backoff
                    continue
            except Exception as exc:  # non-network error: don't retry
                last_exc = exc
                break
        if last_exc is not None:
            result["error"] = f"{type(last_exc).__name__}: {last_exc}"
            if keep_detail:
                attack.details[idx] = {"request": req_text[:12000],
                                       "error_text": f"(送信エラー / {result['retries']}回再試行) {result['error']}"}
        result["duration_ms"] = int((time.perf_counter() - t0) * 1000)

        attack.results.append(result)
        attack.done += 1
        # Yield to the event loop so WebSocket pushes and UI polls are serviced
        # promptly even while the attack is saturating the client.
        await asyncio.sleep(0)
        # No per-result WebSocket publish: the UI polls incrementally, and
        # broadcasting every request floods the socket at high speed.


intruder_manager = IntruderManager()
