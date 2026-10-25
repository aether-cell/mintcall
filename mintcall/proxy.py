"""Local HTTP forward proxy. The agent sends its call (absolute URL in the request line, or
X-Mintcall-Target) plus X-Mintcall-Grant. The proxy claims the grant against the exact request,
injects the real key from the vault, forwards, and settles. The key never reaches the agent."""
import hashlib, threading, urllib.request, urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from .broker import GrantError
from .agents import auth_from_headers
from .keycache import CachedVault

HOP = {"connection","keep-alive","proxy-connection","proxy-authorization","te","trailers","transfer-encoding","upgrade","host",
       "x-mintcall-grant","x-mintcall-target","x-mintcall-agent","x-mintcall-ts","x-mintcall-nonce","x-mintcall-sig","authorization","content-length","accept-encoding"}

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect: the grant is bound to one exact URL, and urllib would otherwise copy the
    injected key header to whatever origin the Location points at. The 3xx goes back to the agent instead."""
    def redirect_request(self, *a, **kw): return None

_OPENER = urllib.request.build_opener(_NoRedirect)

def make_handler(broker, keys):
    state = {"epoch": broker.revoke_epoch()}
    def get_key(name):
        e = broker.revoke_epoch()           # cheap SQLite read; a revoke from any process bumps it
        if e != state["epoch"]: keys.clear(); state["epoch"] = e
        return keys.get(name)
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def log_message(self, *a): pass
        def _reply(self, code, body=b"", headers=()):
            self.send_response(code)
            for k, v in headers: self.send_header(k, v)
            self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
        def _go(self):
            n = int(self.headers.get("Content-Length") or 0); body = self.rfile.read(n) if n else b""
            url = self.headers.get("X-Mintcall-Target") or self.path
            if not url.startswith(("http://", "https://")):
                return self._reply(400, b"absolute target URL required")
            if self.command == "CONNECT":
                return self._reply(405, b"CONNECT tunnelling not supported: send the request to the proxy in cleartext so it can be bound")
            token = self.headers.get("X-Mintcall-Grant", "")
            try:
                c = broker.claim(token, self.command, url, body, auth=auth_from_headers(self.headers))
            except GrantError as e:
                return self._reply(403, f"mintcall refused: {e}".encode())
            cred = get_key(c["credential"])
            hdrs = {k: v for k, v in self.headers.items() if k.lower() not in HOP}
            hdrs[cred["header"]] = cred["format"].format(secret=cred["secret"])
            req = urllib.request.Request(url, data=body or None, method=self.command, headers=hdrs)
            try:
                with _OPENER.open(req, timeout=30) as r:
                    data, code, rh = r.read(), r.status, r.getheaders()
            except urllib.error.HTTPError as e:
                data, code, rh = e.read(), e.code, list(e.headers.items())
            except Exception as e:
                broker.settle(c, ok=False, status_code=None)
                return self._reply(502, f"upstream error: {e}".encode())
            ok = 200 <= code < 300
            secret = cred["secret"].encode()
            data = data.replace(secret, b"[REDACTED]")  # never echo the key back
            # digest of the body exactly as the agent receives it, so the receipt and the agent's own copy can be compared
            broker.settle(c, ok=ok, status_code=code, response_sha256=hashlib.sha256(data).hexdigest())
            keep = [(k, v) for k, v in rh if k.lower() not in HOP | {"content-length"}]
            self._reply(code, data, keep + [("X-Mintcall-Settled", "1" if ok else "0")])
        do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_CONNECT = _go
    return H

def serve(broker, host="127.0.0.1", port=8787, background=False, key_ttl=30.0):
    """key_ttl: seconds a decrypted credential stays in proxy memory (0 disables the cache)."""
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError("mintcall proxy binds to loopback only")
    keys = CachedVault(broker.vault, ttl=key_ttl)
    srv = ThreadingHTTPServer((host, port), make_handler(broker, keys))
    srv.keys = keys
    _shutdown = srv.shutdown
    def shutdown():
        _shutdown(); keys.clear()
    srv.shutdown = shutdown
    if background:
        threading.Thread(target=srv.serve_forever, daemon=True).start(); return srv
    try: srv.serve_forever()
    finally: keys.clear()
