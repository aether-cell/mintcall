"""Tiny agent-side helper: request a grant, then send the call through the proxy. Holds no API key,
only the agent's own signing key (AgentKey)."""
import json, urllib.request, urllib.error
from .agents import AgentKey, auth_headers
from .broker import request_fields, claim_fields

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Don't follow redirects: they would carry the grant token and claim signature to another origin.
    The 3xx is returned to the caller; the new URL needs its own grant."""
    def redirect_request(self, *a, **kw): return None

_OPENER = urllib.request.build_opener(_NoRedirect)

def request_grant(broker, signer, credential, method, url, body=b"", scope=("read",), cap=0.0, ttl=60, intent=None, task_id=None):
    auth = signer.sign("request", request_fields(credential, method, url, body, scope, cap, ttl, intent, task_id))
    return broker.request(signer.agent_id, credential, method, url, body, scope=scope, cap=cap, ttl=ttl, intent=intent,
                          auth=auth, task_id=task_id)

def call_via_proxy(broker, signer, credential, method, url, body=b"", scope=("read",), cap=0.0, ttl=60,
                   intent=None, proxy="http://127.0.0.1:8787", headers=None, task_id=None):
    g = request_grant(broker, signer, credential, method, url, body, scope, cap, ttl, intent, task_id)
    if g["status"] != "minted":
        return {"pending_approval": g["grant_id"]}
    return send(g["token"], method, url, body, proxy, headers, signer=signer)

def send(token, method, url, body=b"", proxy="http://127.0.0.1:8787", headers=None, signer=None, auth=None):
    h = {"X-Mintcall-Grant": token, "X-Mintcall-Target": url, **(headers or {})}
    if signer is not None and auth is None:
        auth = signer.sign("claim", claim_fields(token.split(".", 1)[0], method, url, body))
    if auth: h.update(auth_headers(auth))
    req = urllib.request.Request(proxy + "/", data=body or None, method=method, headers=h)
    try:
        with _OPENER.open(req, timeout=30) as r: return {"status": r.status, "body": r.read().decode(), "headers": dict(r.headers.items())}
    except urllib.error.HTTPError as e: return {"status": e.code, "body": e.read().decode(), "headers": dict(e.headers.items())}
