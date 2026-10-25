"""Stand-in for a paid third-party API. Only accepts the real key; echoes whether auth was present."""
import json, re, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
EXPECTED = "Bearer FAKE_TEST_KEY_not_a_secret"

class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass
    def _go(self):
        n = int(self.headers.get("Content-Length") or 0); body = self.rfile.read(n) if n else b""
        ok = self.headers.get("Authorization") == EXPECTED
        m = re.match(r"/v1/redirect(\d{3})?\?to=(.+)", self.path)
        if m:       # simulates an upstream that bounces the call elsewhere (/v1/redirect308?to=... ; default 307)
            self.send_response(int(m.group(1) or 307)); self.send_header("Location", m.group(2))
            self.send_header("Content-Length", "0"); self.end_headers(); return
        if self.path.startswith("/v1/fail"): code, out = 500, {"error": "upstream broke"}
        elif not ok: code, out = 401, {"error": "missing/invalid key"}
        else: code, out = 200, {"ok": True, "path": self.path, "echo": body.decode(), "authed": True}
        b = json.dumps(out).encode(); self.send_response(code)
        self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)
    do_GET = do_POST = do_PUT = _go

def start(port=0):
    import threading
    s = ThreadingHTTPServer(("127.0.0.1", port), H); threading.Thread(target=s.serve_forever, daemon=True).start(); return s

if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1]) if len(sys.argv) > 1 else 9901), H).serve_forever()
