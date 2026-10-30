# Local WebSec Testing Tool

**English** | [日本語](README.ja.md)

A local, HTTP(S)-intercepting web application for security testing of web systems
that **you own or have explicit written permission to test**. It belongs to the same
category as Burp Suite and OWASP ZAP, built from scratch with Python (FastAPI +
mitmproxy) and React (TypeScript + Vite).

> ⚠️ **Authorized use only.** Do not use this tool against systems you do not own or
> have no explicit permission to test. Everything runs locally (127.0.0.1) and nothing
> is sent to external services by default. Active requests (Repeater, Intruder,
> Scanner, WebSocket Repeater) are sent **only to hosts you have added to Scope and
> enabled** (default deny). You are solely responsible for how you use this software.

## Features

- **Intercepting proxy** — mitmproxy embedded as a library. Intercept HTTP/HTTPS, pause
  a request, edit it (method / path / headers / body), then Forward or Drop. The CA
  certificate is one click away. All traffic is streamed to the UI over WebSocket and
  stored in SQLite.
- **HTTP history** — list view (method / host / status / type / length / time / scope),
  filtering, and raw request/response detail.
- **Repeater** — send from history, edit freely, resend as often as you like, and keep a
  per-tab response history for comparison.
- **Scope** — a default-deny allow-list that gates every active request. Supports
  hostnames, globs, single IPs and **CIDR** ranges (e.g. `10.0.0.0/8`, IPv6 supported).
- **Intruder** — payload markers `§value§`, four attack modes (Sniper / Battering ram /
  Pitchfork / Cluster bomb), payload sources (list / numeric range / file),
  **mandatory rate control** (concurrency and interval), a cap on total requests, and a
  results table (status / length / time / grep match). Every send passes the Scope gate.
- **Decoder** — Base64 / URL / HTML entity / Hex conversion plus MD5, SHA-1/256/512
  hashing, with chained transforms (output of one step feeds the next). Fully local.
- **Comparer** — word / byte (character) / line level diff of two texts
  (A-only = red, B-only = green). Load from history with **→ Comparer**.
- **Sortable tables** — HTTP history, Intruder results and Scanner findings sort by
  clicking the column header.
- **Scanner**
  - *Passive* (nothing is sent): missing security headers, weak cookie attributes,
    exposed private keys / AWS keys / JWTs / card-number-like strings, CORS
    misconfiguration, stack-trace exposure, directory listing, Basic auth over HTTP,
    mixed content, version disclosure (ASP.NET etc.).
  - *Active* (detection-oriented, passes Scope gate + rate control): **possible** SQLi,
    reflected XSS, OS command injection, path traversal / LFI, SSTI, open redirect and
    CRLF injection. Also detects **blind** issues without visible errors:
    time-based (SLEEP / pg_sleep / WAITFOR / sleep / ping, confirmed by a re-send),
    boolean-based (`AND 1=1` vs `AND 1=2`), error-based (DB error signatures) and
    reflection markers (unencoded XSS reflection).
  - Injection points: query, form, **JSON body**, and optionally Cookie / User-Agent /
    Referer headers. Redirects are followed and reachability is checked.
  - **CVE / version diagnostics** — offline matching against a bundled table; optional
    online NVD lookups (off by default; only product + version strings are sent, never
    target data).
- **Sitemap** — intercepted URLs as a host/path tree; add hosts to Scope from here.
- **WebSocket** — message history (direction and body) and a **WS Repeater** that
  connects to a target and sends/receives messages (Scope-gated). Right-click a `101`
  (Upgrade) row in history → "Send to WS Repeater" to carry over the URL and cookies.
- **Context menu** — send a history row to any tool; encode/decode the selected text
  (URL / Base64 / HTML / Hex). Editable fields are replaced in place, others copy.
- **UX** — resizable columns (HTTP history), 50/50 Request/Response split, automatic
  character-encoding detection, and a Japanese / English UI toggle.

### Intruder quick guide

1. From a history entry choose **→ Send to Intruder** (or write a template directly).
2. Select the part you want to vary and click **Set § position** (wraps it in `§value§`).
3. Choose the attack mode and payloads (per position). **Concurrency and interval are
   required.**
4. Click **Start attack**. The table updates live; responses matching your grep terms
   are shown in green.
   - Sniper = one list, one position at a time / Battering ram = same value in all
     positions / Pitchfork = one list per position in parallel / Cluster bomb = every
     combination.
   - If the total exceeds the cap (default 100,000, `WEBSEC_INTRUDER_MAX_TOTAL`) the
     attack is refused.

---

## Getting started

### Requirements

- **Python 3.12 or 3.13 recommended** (3.11 also works).
  - ⚠️ **Python 3.14 is not supported** (as of 2026-09): `zstandard` / `cffi` have no
    prebuilt wheels for 3.14, so installation falls back to a source build that needs
    Visual C++ Build Tools. Create the venv with 3.12/3.13 instead (you do not need to
    uninstall 3.14).
- **Node.js 18+** (required once to build the frontend — see below).

### 1. Backend

Using a virtual environment is recommended. On some Debian-based systems the system
setuptools conflicts with building mitmproxy's dependency `pyperclip`; a clean venv
avoids this.

**Linux / macOS**

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
```

**Windows (PowerShell)**

```powershell
py -0                                   # list installed versions (look for -V:3.12)
# if missing: winget install -e --id Python.Python.3.12
cd backend
py -3.12 -m venv .venv
.\.venv\Scripts\activate                # cmd: .venv\Scripts\activate
python -m pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
```

If PowerShell refuses to run `activate`, run
`Set-ExecutionPolicy -Scope Process RemoteSigned` once and try again.

**Without a venv (Windows):** install with an explicit version, because running
`run.py` directly may pick up Python 3.14 through file association:

```powershell
cd backend
py -3.12 -m pip install --upgrade pip setuptools wheel
py -3.12 -m pip install -r requirements.txt
py -3.12 run.py            # or double-click run.bat
```

`run.bat` uses `.venv` if present, otherwise `py -3.12` / `py -3.13`.

### 2. Frontend (build once)

The built UI (`frontend/dist/`) is not stored in the repository, so build it once:

```bash
cd frontend
npm install
npm run build          # generates dist/, served by the backend
```

For frontend development you can instead run the dev server:

```bash
npm run dev            # http://127.0.0.1:5173 (API/WS are proxied to :8777)
```

### 3. Run

```bash
cd backend
python run.py
```

| Purpose  | URL                   |
|----------|-----------------------|
| UI / API | http://127.0.0.1:8777 |
| Proxy    | http://127.0.0.1:8080 |

Open `http://127.0.0.1:8777` in your browser.

---

## Usage

1. Register the target host(s) in the **Scope** tab (e.g. `example.com`,
   `*.staging.internal`). Until you do, every active request (Repeater etc.) is
   rejected with 403.
2. Set your browser / OS HTTP and HTTPS proxy to `127.0.0.1:8080`.
3. In the **Settings / Help** tab, **download the CA certificate** and install it as a
   trusted root **only on devices you control** (needed to decrypt HTTPS).
4. Browse the target — traffic appears in **HTTP history**. Select a row for raw detail.
5. Use **→ Send to Repeater** to edit, resend and compare.
6. Turn **Intercept** ON to pause each request, then edit and Forward / Drop.

### Environment variables (optional)

| Variable                     | Default             | Description                                               |
|------------------------------|---------------------|-----------------------------------------------------------|
| `WEBSEC_API_HOST`            | `127.0.0.1`         | UI/API bind address                                       |
| `WEBSEC_API_PORT`            | `8777`              | UI/API port                                               |
| `WEBSEC_PROXY_HOST`          | `127.0.0.1`         | Proxy bind address                                        |
| `WEBSEC_PROXY_PORT`          | `8080`              | Proxy listen port                                         |
| `WEBSEC_DATA_DIR`            | `backend/data`      | SQLite storage directory                                  |
| `WEBSEC_MITM_CONFDIR`        | `~/.mitmproxy`      | CA / certificate directory                                |
| `WEBSEC_INTRUDER_MAX_TOTAL`  | `100000`            | Max requests per Intruder attack                          |
| `WEBSEC_UPSTREAM_PROXY`      | *(empty)*           | Upstream proxy for tool-initiated sends                   |
| `WEBSEC_CONNECT_TIMEOUT`     | `8`                 | Connect timeout (seconds) for tool-initiated sends        |
| `WEBSEC_NVD_ONLINE`          | `0`                 | Enable online NVD lookups (`1` / `true` / `yes`)          |
| `WEBSEC_NVD_API_KEY`         | *(empty)*           | Optional NVD API key (raises the rate limit)              |

---

## Architecture

```
frontend/ (React + TypeScript + Vite)
   │  fetch /api/*  +  WebSocket /ws
   ▼
backend/  (FastAPI, :8777)  ── SQLite (SQLAlchemy)
   │
   ├─ ProxyController: runs mitmproxy on a dedicated thread + asyncio loop
   │     · request hook pauses a flow (waits on an asyncio.Event; other flows continue)
   │     · UI resolutions are handed to the proxy loop via call_soon_threadsafe
   │     · response hook stores to the DB and broadcasts over WebSocket (thread-safe)
   ├─ Repeater / Intruder / Scanner: httpx (always through the Scope gate)
   └─ ScopeManager: default-deny allow-list (technical guard for active sends)
```

## Tests

```bash
cd backend && source .venv/bin/activate    # Windows: .venv\Scripts\activate
python selftest.py        # proxy capture / history / detail / Scope gate / Intercept toggle
python intercept_test.py  # pause → edit → Forward, and Drop
```

## Safety design notes

- **Default-deny Scope** — every active-send path must call `require_in_scope()` in
  `app/scope.py`. Unregistered hosts are never contacted; this is enforced in code, not
  just in the UI text.
- **Local-only** — all listeners bind to 127.0.0.1 by default and nothing is sent to
  external services. (Online NVD lookups are opt-in and send only product/version.)
- **Rate control** — concurrency and send-interval defaults live in `config.py` and are
  mandatory for Intruder / Scanner.
- **No built-in authentication** — the UI/API is intended for single-user local use.
  Do not expose it to a network by changing the bind address.

## Data and privacy

The SQLite database (`backend/data/websec.db`) stores everything intercepted by the proxy,
which can include cookies, tokens and personal data. It is git-ignored; never commit or
share it. The mitmproxy CA private key lives in `~/.mitmproxy` (outside this repository).
Remove the CA from your trust store when you finish testing.

## Contributing

Issues and pull requests are welcome. Please keep the authorized-use safeguards (the
default-deny Scope gate and mandatory rate control) intact.

## License

[MIT](LICENSE) © 2026 uj13e

This project builds on [mitmproxy](https://mitmproxy.org/), FastAPI, SQLAlchemy, httpx and
React, each under its own license.
