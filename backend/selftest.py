"""Integration self-test (no external network needed).

Starts the app via TestClient (which boots the mitmproxy thread), stands up a
local origin HTTP server, sends a request THROUGH our proxy to that origin, and
checks that the flow was captured and exposed via the API. Also exercises the
scope gate on Repeater.
"""
import os, tempfile, threading, time
from http.server import BaseHTTPRequestHandler, HTTPServer

# Use a temp DB and non-default ports so a real server can run alongside.
os.environ["WEBSEC_DATA_DIR"] = tempfile.mkdtemp()
os.environ["WEBSEC_PROXY_PORT"] = "8899"
os.environ["WEBSEC_API_PORT"] = "8778"
os.environ["WEBSEC_MITM_CONFDIR"] = tempfile.mkdtemp()

import httpx
from fastapi.testclient import TestClient
from app.main import app
from app.config import settings

ORIGIN_PORT = 9911


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"hello-from-origin"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("X-Test", "1")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def start_origin():
    srv = HTTPServer(("127.0.0.1", ORIGIN_PORT), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def main():
    start_origin()
    results = []
    with TestClient(app) as client:
        # wait for proxy thread to bind
        for _ in range(50):
            st = client.get("/api/status").json()
            if st["proxy_running"]:
                break
            time.sleep(0.2)
        assert st["proxy_running"], "proxy did not start"
        results.append(("proxy_running", st["proxy_running"]))

        # send a request THROUGH our proxy to the local origin
        proxy_url = f"http://127.0.0.1:{settings.proxy_port}"
        with httpx.Client(proxy=proxy_url, timeout=10) as c:
            r = c.get(f"http://127.0.0.1:{ORIGIN_PORT}/probe?x=1")
        results.append(("origin_status", r.status_code))
        results.append(("origin_body", r.text))

        # allow capture to persist
        time.sleep(0.5)
        flows = client.get("/api/flows").json()
        results.append(("flows_captured", len(flows)))
        assert any("/probe" in f["url"] for f in flows), "captured flow missing"
        fid = [f for f in flows if "/probe" in f["url"]][0]["id"]
        detail = client.get(f"/api/flows/{fid}").json()
        results.append(("detail_status", detail["status_code"]))
        results.append(("detail_body", detail["resp_body"]))
        results.append(("detail_xtest_hdr", any(h[0].lower()=="x-test" for h in detail["resp_headers"])))

        # scope gate: repeater to un-scoped host must be blocked (403)
        rr = client.post("/api/repeater/send", json={
            "method": "GET", "scheme": "http", "host": "127.0.0.1",
            "port": ORIGIN_PORT, "path": "/probe"})
        results.append(("repeater_blocked_out_of_scope", rr.status_code))

        # add scope, then repeater should succeed
        client.post("/api/scope", json={"host_pattern": "127.0.0.1"})
        rr2 = client.post("/api/repeater/send", json={
            "method": "GET", "scheme": "http", "host": "127.0.0.1",
            "port": ORIGIN_PORT, "path": "/probe2"})
        results.append(("repeater_after_scope", rr2.status_code))
        if rr2.status_code == 200:
            results.append(("repeater_body", rr2.json()["body"]))

        # intercept state toggle
        client.post("/api/intercept/state", json={"enabled": True})
        results.append(("intercept_enabled", client.get("/api/intercept").json()["enabled"]))
        client.post("/api/intercept/state", json={"enabled": False})

    print("\n==== SELF-TEST RESULTS ====")
    ok = True
    for k, v in results:
        print(f"  {k}: {v!r}")
    # assertions
    checks = dict(results)
    assert checks["origin_body"] == "hello-from-origin"
    assert checks["flows_captured"] >= 1
    assert checks["detail_status"] == 200
    assert checks["detail_body"] == "hello-from-origin"
    assert checks["detail_xtest_hdr"] is True
    assert checks["repeater_blocked_out_of_scope"] == 403
    assert checks["repeater_after_scope"] == 200
    assert checks["intercept_enabled"] is True
    print("\n  ALL CHECKS PASSED ✅")


if __name__ == "__main__":
    main()
