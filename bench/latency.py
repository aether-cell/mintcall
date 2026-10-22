"""Measure end-to-end proxy call latency (grant already minted; time = agent->proxy->upstream->agent).
Uses the real FileVault (scrypt n=2**15) so decrypt cost is included. Local only."""
import json, os, statistics, sys, tempfile, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..")); sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "examples"))
from mintcall.broker import Broker
from mintcall.policy import Policy, DEFAULT_POLICY
from mintcall.vault import FileVault
from mintcall import client
from mintcall.proxy import serve
import fake_upstream

N = int(sys.argv[1]) if len(sys.argv) > 1 else 30
home = tempfile.mkdtemp(); up = fake_upstream.start(0); api = f"http://127.0.0.1:{up.server_port}"
v = FileVault(os.path.join(home, "c.vault"), passphrase="bench"); v.put("demo-api", "FAKE_TEST_KEY_not_a_secret", api)
pol = json.loads(json.dumps(DEFAULT_POLICY)); pol["rules"][0]["budget"] = 1e9
b = Broker(home, policy=Policy(pol), vault=v)
signer = None
if hasattr(client, "AgentKey"):  # hardened version: signed requests/claims
    from mintcall.agents import AgentKey
    signer = AgentKey.generate("demo-agent"); b.agents.add("demo-agent", signer.public_b64())
kw = {"key_ttl": float(os.environ["KEY_TTL"])} if "KEY_TTL" in os.environ else {}
px = serve(b, port=0, background=True, **kw); proxy = f"http://127.0.0.1:{px.server_port}"
ts = []
for i in range(N):
    url = api + f"/v1/items?id={i}"
    if signer: g = client.request_grant(b, signer, "demo-api", "GET", url, cap=0.01)
    else: g = b.request("demo-agent", "demo-api", "GET", url, scope=["read"], cap=0.01)
    t = time.perf_counter()
    r = client.send(g["token"], "GET", url, proxy=proxy, signer=signer) if signer else client.send(g["token"], "GET", url, proxy=proxy)
    ts.append((time.perf_counter() - t) * 1000); assert r["status"] == 200, r
px.shutdown(); up.shutdown()
print(json.dumps({"n": N, "first_ms": round(ts[0], 1), "median_ms": round(statistics.median(ts), 1),
                  "p95_ms": round(sorted(ts)[int(0.95 * N) - 1], 1), "mean_ms": round(statistics.mean(ts), 1)}))
