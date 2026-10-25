import json, os, sys, threading, time, urllib.request
from concurrent.futures import ThreadPoolExecutor
import pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "examples"))
from mintcall.broker import Broker, GrantError
from mintcall.policy import Policy, DEFAULT_POLICY
from mintcall.vault import FileVault, VaultError
from mintcall.client import send as _send, request_grant
from mintcall.agents import AgentKey, AgentRegistry
from mintcall.broker import request_fields, claim_fields
from mintcall.proxy import serve
import fake_upstream

KEY = "FAKE_TEST_KEY_not_a_secret"

AGENT = AgentKey.generate("demo-agent")
OTHER = AgentKey.generate("other-agent")

def send(token, method, url, body=b"", proxy=None, signer=AGENT, **kw):
    return _send(token, method, url, body, proxy=proxy, signer=signer, **kw)

class Clock:
    def __init__(self): self.t = time.time()
    def __call__(self): return self.t

@pytest.fixture
def env(tmp_path):
    up = fake_upstream.start(0); api = f"http://127.0.0.1:{up.server_port}"
    v = FileVault(tmp_path / "c.vault", passphrase="pw"); v.put("demo-api", KEY, api)
    clk = Clock(); b = Broker(tmp_path, policy=Policy(json.loads(json.dumps(DEFAULT_POLICY))), vault=v, clock=clk)
    b.agents.add("demo-agent", AGENT.public_b64()); b.agents.add("other-agent", OTHER.public_b64())
    px = serve(b, port=0, background=True); proxy = f"http://127.0.0.1:{px.server_port}"
    yield b, api, proxy, clk, tmp_path
    px.shutdown(); up.shutdown()

def grant(b, api, path="/v1/items", method="GET", body=b"", **kw):
    kw.setdefault("cap", 0.5); kw.setdefault("ttl", 60)
    signer = kw.pop("signer", AGENT)
    return request_grant(b, signer, "demo-api", method, api + path, body, scope=["read"] if method == "GET" else ["write"], **kw)

def sclaim(b, token, method, url, body=b"", signer=AGENT):
    return b.claim(token, method, url, body, auth=signer.sign("claim", claim_fields(token.split(".")[0], method, url, body)))

def test_happy_path_key_injected_agent_never_sees_it(env):
    b, api, proxy, _, home = env
    g = grant(b, api)
    assert KEY not in json.dumps(g)
    r = send(g["token"], "GET", api + "/v1/items", proxy=proxy)
    assert r["status"] == 200 and json.loads(r["body"])["authed"]
    assert KEY not in r["body"]
    assert b.list()[0]["status"] == "settled"

def test_reuse_refused(env):
    b, api, proxy, *_ = env
    g = grant(b, api)
    assert send(g["token"], "GET", api + "/v1/items", proxy=proxy)["status"] == 200
    r = send(g["token"], "GET", api + "/v1/items", proxy=proxy)
    assert r["status"] == 403 and "reuse/replay refused" in r["body"]

def test_replay_on_different_call_refused(env):
    b, api, proxy, *_ = env
    g = grant(b, api, "/v1/items")
    r = send(g["token"], "GET", api + "/v1/other", proxy=proxy)
    assert r["status"] == 403 and "request hash mismatch" in r["body"]
    assert "burned" in r["body"]
    g = grant(b, api, "/v1/items")
    r = send(g["token"], "GET", "http://127.0.0.1:1/v1/items", proxy=proxy)
    assert r["status"] == 403 and "recipient mismatch" in r["body"]

def test_body_tamper_refused(env):
    b, api, proxy, *_ = env
    g = grant(b, api, "/v1/pay", "POST", b'{"amount":1}', cap=1)
    b.approve(g["grant_id"])
    r = send(g["token"], "POST", api + "/v1/pay", b'{"amount":999}', proxy=proxy)
    assert r["status"] == 403 and "hash mismatch" in r["body"]

def test_expiry_refused(env):
    b, api, proxy, clk, _ = env
    g = grant(b, api, ttl=30)
    clk.t += 31
    r = send(g["token"], "GET", api + "/v1/items", proxy=proxy)
    assert r["status"] == 403 and "expired" in r["body"]
    assert b.list()[0]["status"] == "expired"

def test_forged_token_refused(env):
    b, api, proxy, *_ = env
    g = grant(b, api)
    r = send(g["grant_id"] + ".forged", "GET", api + "/v1/items", proxy=proxy)
    assert r["status"] == 403 and "bad token" in r["body"]
    r = send("", "GET", api + "/v1/items", proxy=proxy)
    assert r["status"] == 403

def test_concurrent_claim_only_once(env):
    b, api, *_ = env
    g = grant(b, api)
    def try_claim(_):
        try: sclaim(b, g["token"], "GET", api + "/v1/items"); return 1
        except GrantError: return 0
    with ThreadPoolExecutor(16) as ex: assert sum(ex.map(try_claim, range(32))) == 1

def test_revoke(env):
    b, api, proxy, *_ = env
    g = grant(b, api); assert b.revoke(g["grant_id"]) == 1
    r = send(g["token"], "GET", api + "/v1/items", proxy=proxy)
    assert r["status"] == 403 and "revoked" in r["body"]

def test_ask_policy_needs_approval(env):
    b, api, proxy, *_ = env
    g = grant(b, api, "/v1/orders", "POST", b"{}", cap=2)
    assert g["status"] == "pending_approval"
    assert send(g["token"], "POST", api + "/v1/orders", b"{}", proxy=proxy)["status"] == 403
    b.approve(g["grant_id"])
    assert send(g["token"], "POST", api + "/v1/orders", b"{}", proxy=proxy)["status"] == 200

def test_policy_denies(env):
    b, api, *_ = env
    with pytest.raises(GrantError, match="cap"): grant(b, api, cap=50)
    with pytest.raises(GrantError, match="ttl"): grant(b, api, ttl=3600)
    with pytest.raises(GrantError, match="no matching rule"): request_grant(b, OTHER, "demo-api", "GET", api + "/v1/x", scope=["read"])
    with pytest.raises(GrantError, match="recipient"): request_grant(b, AGENT, "demo-api", "GET", "https://evil.example/v1/x", scope=["read"])

def test_cap_rechecked_at_use_and_failure_not_charged(env):
    b, api, proxy, *_ = env
    # failures do not charge
    g = grant(b, api, "/v1/fail", cap=1.0)
    assert send(g["token"], "GET", api + "/v1/fail", proxy=proxy)["status"] == 500
    assert b.spent("demo-agent", "demo-api") == 0
    # budget 5.0: mint 6 grants up-front (each OK at mint), use them: 6th refused at use
    gs = [grant(b, api, cap=1.0) for _ in range(6)]
    codes = [send(x["token"], "GET", api + "/v1/items", proxy=proxy)["status"] for x in gs]
    assert codes == [200] * 5 + [403]
    assert b.spent("demo-agent", "demo-api") == 5.0

def test_receipt_log_signed_and_tamper_evident(env):
    b, api, proxy, _, home = env
    g = grant(b, api); send(g["token"], "GET", api + "/v1/items", proxy=proxy)
    ok, n, _ = b.log.verify(); assert ok and n >= 3
    p = home / "receipts.jsonl"; lines = p.read_text().splitlines()
    rec = json.loads(lines[0]); rec["data"]["cap"] = 0.0; lines[0] = json.dumps(rec, sort_keys=True)
    p.write_text("\n".join(lines) + "\n")
    ok, i, msg = b.log.verify(); assert not ok and i == 1
    assert KEY not in p.read_text()

def test_vault_encrypted_and_wrong_passphrase(tmp_path):
    v = FileVault(tmp_path / "v", passphrase="right"); v.put("x", KEY, "https://api.example")
    assert KEY not in (tmp_path / "v").read_text()
    with pytest.raises(VaultError): FileVault(tmp_path / "v", passphrase="wrong").get("x")


# ---------- agent authentication ----------
def test_unsigned_request_refused(env):
    b, api, *_ = env
    with pytest.raises(GrantError, match="unsigned"):
        b.request("demo-agent", "demo-api", "GET", api + "/v1/items", scope=["read"], cap=0.5)

def test_request_signed_by_wrong_key_refused(env):
    b, api, *_ = env
    imposter = AgentKey("demo-agent", AgentKey.generate("x").priv)  # claims demo-agent, different key
    with pytest.raises(GrantError, match="bad agent signature"): grant(b, api, signer=imposter)
    # valid signature by other-agent, but asking as demo-agent
    auth = OTHER.sign("request", request_fields("demo-api", "GET", api + "/v1/items", b"", ["read"], 0.5, 60))
    with pytest.raises(GrantError, match="different agent"):
        b.request("demo-agent", "demo-api", "GET", api + "/v1/items", scope=["read"], cap=0.5, auth=auth)
    unknown = AgentKey.generate("ghost")
    with pytest.raises(GrantError, match="unknown agent"): b.request("ghost", "demo-api", "GET", api + "/v1/items", scope=["read"], cap=0.5,
        auth=unknown.sign("request", request_fields("demo-api", "GET", api + "/v1/items", b"", ["read"], 0.5, 60)))

def test_signed_request_params_cannot_be_altered(env):
    b, api, *_ = env
    auth = AGENT.sign("request", request_fields("demo-api", "GET", api + "/v1/items", b"", ["read"], 0.1, 60))
    with pytest.raises(GrantError, match="bad agent signature"):  # cap raised after signing
        b.request("demo-agent", "demo-api", "GET", api + "/v1/items", scope=["read"], cap=0.9, auth=auth)

def test_intent_changed_after_signing_refused(env):
    b, api, *_ = env
    url = api + "/v1/orders"
    signed = {"why": "buy one test item"}
    auth = AGENT.sign("request", request_fields("demo-api", "POST", url, b"{}", ["write"], 2, 60, signed))
    with pytest.raises(GrantError, match="bad agent signature"):  # why swapped before the approver sees it
        b.request("demo-agent", "demo-api", "POST", url, b"{}", scope=["write"], cap=2, ttl=60,
                  intent={"why": "routine refresh"}, auth=auth)
    g = b.request("demo-agent", "demo-api", "POST", url, b"{}", scope=["write"], cap=2, ttl=60, intent=signed,
                  auth=AGENT.sign("request", request_fields("demo-api", "POST", url, b"{}", ["write"], 2, 60, signed)))
    assert g["status"] in ("minted", "pending_approval")

def test_intent_must_describe_the_actual_call(env):
    b, api, *_ = env
    url = api + "/v1/orders"
    def ask(intent, method="POST", cap=2):
        return b.request("demo-agent", "demo-api", method, url, b"{}", scope=["write"], cap=cap, ttl=60, intent=intent,
                         auth=AGENT.sign("request", request_fields("demo-api", method, url, b"{}", ["write"], cap, 60, intent)))
    # validly signed, but the intent shown to the approver describes a harmless GET, not this POST
    with pytest.raises(GrantError, match="intent method does not match"):
        ask({"why": "read items", "method": "GET", "url": url, "cap": 2})
    with pytest.raises(GrantError, match="intent url does not match"):
        ask({"why": "read items", "method": "POST", "url": api + "/v1/items", "cap": 2})
    with pytest.raises(GrantError, match="intent cap does not match"):
        ask({"why": "small buy", "method": "POST", "url": url, "cap": 0.1})
    assert ask({"why": "buy", "method": "post", "url": url, "cap": 2.0})["status"] in ("minted", "pending_approval")

def test_request_signature_replay_and_stale_timestamp_refused(env):
    b, api, _, clk, _ = env
    f = request_fields("demo-api", "GET", api + "/v1/items", b"", ["read"], 0.5, 60)
    auth = AGENT.sign("request", f, ts=clk.t)
    b.request("demo-agent", "demo-api", "GET", api + "/v1/items", scope=["read"], cap=0.5, auth=auth)
    with pytest.raises(GrantError, match="nonce already used"):
        b.request("demo-agent", "demo-api", "GET", api + "/v1/items", scope=["read"], cap=0.5, auth=auth)
    old = AGENT.sign("request", f, ts=clk.t - 120)
    with pytest.raises(GrantError, match="timestamp"):
        b.request("demo-agent", "demo-api", "GET", api + "/v1/items", scope=["read"], cap=0.5, auth=old)

def test_unsigned_or_wrongly_signed_claim_refused_and_grant_survives(env):
    b, api, proxy, *_ = env
    g = grant(b, api); url = api + "/v1/items"
    r = send(g["token"], "GET", url, proxy=proxy, signer=None)
    assert r["status"] == 403 and "unsigned" in r["body"]
    imposter = AgentKey("demo-agent", AgentKey.generate("x").priv)
    r = send(g["token"], "GET", url, proxy=proxy, signer=imposter)
    assert r["status"] == 403 and "bad agent signature" in r["body"]
    # a claim signature made for a different URL does not verify for this one
    bad = AGENT.sign("claim", claim_fields(g["grant_id"], "GET", api + "/v1/other", b""))
    r = send(g["token"], "GET", url, proxy=proxy, signer=None, auth=bad)
    assert r["status"] == 403 and "bad agent signature" in r["body"]
    # an unauthenticated party can't burn the grant; the real agent still can use it
    assert send(g["token"], "GET", url, proxy=proxy)["status"] == 200

def test_claim_signature_replay_refused(env):
    b, api, proxy, *_ = env
    g1 = grant(b, api); url = api + "/v1/items"
    auth = AGENT.sign("claim", claim_fields(g1["grant_id"], "GET", url, b""))
    assert send(g1["token"], "GET", url, proxy=proxy, signer=None, auth=auth)["status"] == 200
    g2 = grant(b, api)  # even with a new grant, the old signature's nonce is spent (and grant_id differs)
    r = send(g1["token"], "GET", url, proxy=proxy, signer=None, auth=auth)
    assert r["status"] == 403 and "nonce already used" in r["body"]

def test_stolen_grant_used_by_other_agent_is_a_strike(env):
    b, api, proxy, *_ = env
    g = grant(b, api)
    r = send(g["token"], "GET", api + "/v1/items", proxy=proxy, signer=OTHER)
    assert r["status"] == 403 and "different agent" in r["body"] and "burned" in r["body"]
    assert b.list()[0]["status"] == "burned"

# ---------- strikes ----------
def test_mismatch_burns_by_default(env):
    b, api, proxy, *_ = env
    g = grant(b, api, "/v1/items")
    assert "burned" in send(g["token"], "GET", api + "/v1/other", proxy=proxy)["body"]
    r = send(g["token"], "GET", api + "/v1/items", proxy=proxy)   # even its own call now
    assert r["status"] == 403 and "burned" in r["body"]

def test_mismatch_allows_n_strikes_when_configured(env):
    b, api, proxy, *_ = env
    b.policy.data["on_mismatch"] = {"mode": "strikes", "max_strikes": 3}
    g = grant(b, api, "/v1/items")
    r1 = send(g["token"], "GET", api + "/v1/x1", proxy=proxy); assert "strike 1/3" in r1["body"]
    r2 = send(g["token"], "GET", api + "/v1/x2", proxy=proxy); assert "strike 2/3" in r2["body"]
    assert send(g["token"], "GET", api + "/v1/items", proxy=proxy)["status"] == 200   # still usable for its call
    g = grant(b, api, "/v1/items")
    for i in range(3): r = send(g["token"], "GET", api + f"/v1/y{i}", proxy=proxy)
    assert "burned" in r["body"]
    assert send(g["token"], "GET", api + "/v1/items", proxy=proxy)["status"] == 403
    ev = [json.loads(l)["event"] for l in (b.home / "receipts.jsonl").read_text().splitlines()]
    assert ev.count("strike") == 5 and b.log.verify()[0]

# ---------- key cache ----------
def test_key_cache_hits_expires_and_clears_on_revoke_and_shutdown(env, tmp_path):
    b, api, _, clk, _ = env
    px = serve(b, port=0, background=True, key_ttl=0.5); proxy = f"http://127.0.0.1:{px.server_port}"
    for _ in range(3): assert send(grant(b, api)["token"], "GET", api + "/v1/items", proxy=proxy)["status"] == 200
    assert px.keys.misses == 1 and px.keys.hits == 2 and len(px.keys) == 1
    time.sleep(0.6)
    assert send(grant(b, api)["token"], "GET", api + "/v1/items", proxy=proxy)["status"] == 200
    assert px.keys.misses == 2                       # expired -> decrypted again
    b.revoke(agent_id="nobody")            # any revoke bumps the epoch...
    assert send(grant(b, api)["token"], "GET", api + "/v1/items", proxy=proxy)["status"] == 200
    assert px.keys.misses == 3                       # ...so the cache was cleared before this call
    px.shutdown(); assert len(px.keys) == 0

# ---------- notifications ----------
def test_pending_approval_fires_command_and_webhook(env, tmp_path):
    b, api, *_ = env
    hits = []
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    class W(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_POST(self):
            hits.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(204); self.end_headers()
    w = ThreadingHTTPServer(("127.0.0.1", 0), W); threading.Thread(target=w.serve_forever, daemon=True).start()
    out = tmp_path / "notified.txt"
    b.policy.data["notify"] = {"command": f'echo "$MINTCALL_EVENT $MINTCALL_GRANT_ID $MINTCALL_AGENT_ID" > {out}',
                               "webhook": f"http://127.0.0.1:{w.server_port}/hook"}
    assert grant(b, api)["status"] == "minted" and b.notify_threads == []   # auto grants don't notify
    g = grant(b, api, "/v1/orders", "POST", b"{}", cap=2, intent={"why": "buy"})
    for t in b.notify_threads: t.join(5)
    assert out.read_text().split() == ["pending_approval", g["grant_id"], "demo-agent"]
    assert hits and hits[0]["grant_id"] == g["grant_id"] and hits[0]["why"] == "buy"
    assert g["token"] not in json.dumps(hits) and g["token"].split(".")[1] not in out.read_text()
    w.shutdown()

def test_agent_cli_add_and_signed_request(tmp_path, monkeypatch):
    from mintcall.cli import main
    monkeypatch.setenv("MINTCALL_PASSPHRASE", "pw"); monkeypatch.setenv("SEC", KEY)
    h = ["--home", str(tmp_path / "h")]
    assert main(h + ["init"]) == 0
    assert main(h + ["add-credential", "demo-api", "--recipient", "http://127.0.0.1:9", "--secret-env", "SEC"]) == 0
    kp = tmp_path / "ak" / "demo-agent.key"
    assert main(h + ["agent", "add", "demo-agent", "--out", str(kp)]) == 0
    assert oct(kp.stat().st_mode & 0o777) == "0o600"
    reg = json.loads((tmp_path / "h" / "agents.json").read_text())
    assert "private" not in json.dumps(reg)
    assert main(h + ["request", "--agent", "demo-agent", "--agent-key", str(kp), "--credential", "demo-api",
                     "--url", "http://127.0.0.1:9/v1/items", "--cap", "0.5"]) == 0
    other = tmp_path / "other.key"; AgentKey.generate("demo-agent").save(other)
    assert main(h + ["request", "--agent", "demo-agent", "--agent-key", str(other), "--credential", "demo-api",
                     "--url", "http://127.0.0.1:9/v1/items", "--cap", "0.5"]) == 2

def test_settle_receipt_carries_digest_of_body_agent_received(env):
    import hashlib
    b, api, proxy, _, home = env
    g = grant(b, api)
    r = send(g["token"], "GET", api + "/v1/items", proxy=proxy)
    assert r["status"] == 200
    recs = [json.loads(l) for l in (home / "receipts.jsonl").read_text().splitlines()]
    st = [x for x in recs if x["event"] == "settle"][-1]
    assert st["data"]["response_sha256"] == hashlib.sha256(r["body"].encode()).hexdigest()

def test_proxy_never_follows_redirects_with_the_injected_key(env):
    b, api, proxy, *_ = env
    seen = []
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    class Evil(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            seen.append(self.headers.get("Authorization")); self.send_response(200)
            self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"ok")
    ev = ThreadingHTTPServer(("127.0.0.1", 0), Evil); threading.Thread(target=ev.serve_forever, daemon=True).start()
    path = f"/v1/redirect?to=http://127.0.0.1:{ev.server_port}/steal"
    r = send(grant(b, api, path)["token"], "GET", api + path, proxy=proxy)
    ev.shutdown()
    assert seen == []                       # neither the proxy (with the key) nor the client (with the grant) followed it
    assert r["status"] == 307               # the agent sees the redirect and needs a fresh grant for the new URL
    assert b.list()[0]["status"] == "failed"  # a 3xx is not a successful call, so nothing is charged
