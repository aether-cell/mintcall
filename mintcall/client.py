"""Tiny agent-side helper: request a grant, then send the call through the proxy. Holds no API key,
only the agent's own signing key (AgentKey)."""
import json, urllib.request, urllib.error
from .agents import AgentKey, auth_headers
from .broker import request_fields, claim_fields

def request_grant(broker, signer, credential, method, url, body=b"", scope=("read",), cap=0.0, ttl=60, intent=None):
    auth = signer.sign("request", request_fields(credential, method, url, body, scope, cap, ttl, intent))
    return broker.request(signer.agent_id, credential, method, url, body, scope=scope, cap=cap, ttl=ttl, intent=intent, auth=auth)

def call_via_proxy(broker, signer, credential, method, url, body=b"", scope=("read",), cap=0.0, ttl=60,
                   intent=None, proxy="http://127.0.0.1:8787", headers=None):
    g = request_grant(broker, signer, credential, method, url, body, scope, cap, ttl, intent)
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
        with urllib.request.urlopen(req, timeout=30) as r: return {"status": r.status, "body": r.read().decode()}
    except urllib.error.HTTPError as e: return {"status": e.code, "body": e.read().decode()}
