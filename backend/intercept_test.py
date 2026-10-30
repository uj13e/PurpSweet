"""Verify intercept: pause -> edit request -> forward, and pause -> drop."""
import os, tempfile, threading, time
from http.server import BaseHTTPRequestHandler, HTTPServer

os.environ["WEBSEC_DATA_DIR"] = tempfile.mkdtemp()
os.environ["WEBSEC_PROXY_PORT"] = "8898"
os.environ["WEBSEC_API_PORT"] = "8779"
os.environ["WEBSEC_MITM_CONFDIR"] = tempfile.mkdtemp()

import httpx
from fastapi.testclient import TestClient
from app.main import app
from app.config import settings

ORIGIN_PORT = 9912


class Handler(BaseHTTPRequestHandler):
    def _echo(self):
        body = f"{self.command} {self.path} xh={self.headers.get('X-Injected','')}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    do_GET = _echo
    do_POST = _echo
    def log_message(self, *a): pass


def main():
    HTTPServer.allow_reuse_address = True
    srv = HTTPServer(("127.0.0.1", ORIGIN_PORT), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    with TestClient(app) as client:
        for _ in range(50):
            if client.get("/api/status").json()["proxy_running"]:
                break
            time.sleep(0.2)
        client.post("/api/intercept/state", json={"enabled": True})

        proxy_url = f"http://127.0.0.1:{settings.proxy_port}"
        result_box = {}

        def do_req(box):
            try:
                with httpx.Client(proxy=proxy_url, timeout=15) as c:
                    r = c.get(f"http://127.0.0.1:{ORIGIN_PORT}/orig")
                    box["status"] = r.status_code
                    box["body"] = r.text
            except Exception as e:
                box["error"] = str(e)

        t = threading.Thread(target=do_req, args=(result_box,))
        t.start()

        # wait for the paused flow to appear
        pend = []
        for _ in range(50):
            pend = client.get("/api/intercept").json()["pending"]
            if pend:
                break
            time.sleep(0.2)
        assert pend, "no paused flow appeared"
        fid = pend[0]["flow_id"]
        print("paused flow:", pend[0]["method"], pend[0]["path"])

        # edit: change path and inject a header, then forward
        headers = pend[0]["headers"] + [["X-Injected", "yes"]]
        client.post(f"/api/intercept/{fid}", json={
            "action": "forward", "path": "/edited", "headers": headers})
        t.join(timeout=15)

        print("edited-forward result:", result_box)
        assert result_box.get("status") == 200
        assert "/edited" in result_box["body"], result_box
        assert "xh=yes" in result_box["body"], result_box

        # --- now test DROP ---
        box2 = {}
        t2 = threading.Thread(target=do_req, args=(box2,))
        t2.start()
        pend = []
        for _ in range(50):
            pend = client.get("/api/intercept").json()["pending"]
            if pend:
                break
            time.sleep(0.2)
        assert pend, "no paused flow for drop"
        client.post(f"/api/intercept/{pend[0]['flow_id']}", json={"action": "drop"})
        t2.join(timeout=15)
        print("drop result:", box2)
        assert "error" in box2 or box2.get("status") != 200, box2

        client.post("/api/intercept/state", json={"enabled": False})
    print("\n  INTERCEPT CHECKS PASSED ✅")


if __name__ == "__main__":
    main()
