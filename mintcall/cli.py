import argparse, getpass, json, os, sys, time
from pathlib import Path
from .broker import Broker, GrantError
from .policy import DEFAULT_POLICY, Policy
from .vault import FileVault, KeyringVault

def home(a): return Path(a.home or os.environ.get("MINTCALL_HOME", "~/.mintcall")).expanduser()
def vault(a):
    h = home(a)
    return KeyringVault(h / "keyring-meta.json") if a.keyring else FileVault(h / "credentials.vault")
def broker(a, with_vault=False): return Broker(home(a), vault=vault(a) if with_vault else None)

def main(argv=None):
    p = argparse.ArgumentParser(prog="mintcall", description="aether-cell mintcall: per-call credential grants for agents")
    p.add_argument("--home"); p.add_argument("--keyring", action="store_true", help="store secrets in OS keyring")
    s = p.add_subparsers(dest="cmd", required=True)
    s.add_parser("init", help="create home dir + example policy")
    c = s.add_parser("add-credential"); c.add_argument("name"); c.add_argument("--recipient", required=True)
    c.add_argument("--header", default="Authorization"); c.add_argument("--format", default="Bearer {secret}")
    c.add_argument("--secret-env", help="read secret from this env var instead of prompting")
    s.add_parser("credentials")
    r = s.add_parser("request", help="agent asks for a grant for ONE call")
    r.add_argument("--agent", required=True); r.add_argument("--credential", required=True)
    r.add_argument("--agent-key", required=True, help="agent's private signing key file (from `mintcall agent add`)")
    r.add_argument("--method", default="GET"); r.add_argument("--url", required=True); r.add_argument("--body", default="")
    r.add_argument("--scope", default="read"); r.add_argument("--cap", type=float, default=0.0)
    r.add_argument("--ttl", type=int, default=60); r.add_argument("--why", default="")
    r.add_argument("--task-id", help="bind the grant to an open task (refused once that task ends)")
    for n in ("approve", "revoke"):
        x = s.add_parser(n); x.add_argument("grant_id", nargs="?")
        if n == "revoke": x.add_argument("--agent")
    rs = s.add_parser("resolve", help="record the real outcome of a call whose upstream response never came back")
    rs.add_argument("grant_id"); rs.add_argument("--note")
    og = rs.add_mutually_exclusive_group(required=True)
    og.add_argument("--performed", dest="performed", action="store_true"); og.add_argument("--not-performed", dest="performed", action="store_false")
    l = s.add_parser("list"); l.add_argument("--status")
    s.add_parser("sweep", help="mark timed-out grants expired")
    s.add_parser("verify-log", help="verify signed receipt chain")
    pr = s.add_parser("proxy"); pr.add_argument("--port", type=int, default=8787)
    pr.add_argument("--key-ttl", type=float, default=30.0, help="seconds decrypted keys stay cached in memory (0 = off)")
    ag = s.add_parser("agent", help="manage agent identities"); ags = ag.add_subparsers(dest="agent_cmd", required=True)
    aa = ags.add_parser("add", help="register an agent: generate a keypair, or register an existing public key")
    aa.add_argument("agent_id"); aa.add_argument("--out", help="where to write the agent's private key (0600)")
    aa.add_argument("--public-key", help="register this base64 Ed25519 public key instead of generating one")
    ar = ags.add_parser("remove"); ar.add_argument("agent_id"); ags.add_parser("list")
    tk = s.add_parser("task", help="runner side: task lifecycle events (task_open / task_end / task_destroyed)")
    tks = tk.add_subparsers(dest="task_cmd", required=True)
    to = tks.add_parser("open"); to.add_argument("task_id"); to.add_argument("--timestamp")
    te = tks.add_parser("end", help="refuse further grants/uses for the task; run BEFORE killing its process group")
    te.add_argument("task_id"); te.add_argument("--timestamp"); te.add_argument("--transition", choices=["done", "cancelled", "suspended"])
    td = tks.add_parser("destroyed", help="runner reports teardown AFTER killing the process group")
    td.add_argument("task_id"); td.add_argument("--timestamp")
    dg = td.add_mutually_exclusive_group(required=True)
    dg.add_argument("--destructor-ok", dest="dok", action="store_true"); dg.add_argument("--destructor-failed", dest="dok", action="store_false")
    tst = tks.add_parser("stuck", help="list ended tasks with grants revoked but no destructorOk=true stamp")
    tst.add_argument("--older-than", type=float, metavar="SECONDS", help="only tasks ended at least this long ago (broker clock)")
    tf = tks.add_parser("event", help="apply a JSON lifecycle event from a file ('-' = stdin)"); tf.add_argument("file")
    sg = s.add_parser("sign-claim", help="agent side: print X-Mintcall-* auth headers for a claim")
    sg.add_argument("--agent-key", required=True); sg.add_argument("--token", required=True)
    sg.add_argument("--method", default="GET"); sg.add_argument("--url", required=True); sg.add_argument("--body", default="")
    a = p.parse_args(argv)
    h = home(a)
    try:
        if a.cmd == "init":
            h.mkdir(parents=True, exist_ok=True); pol = h / "policy.json"
            if not pol.exists(): pol.write_text(json.dumps(DEFAULT_POLICY, indent=2))
            print(f"initialized {h}  (edit {pol})")
        elif a.cmd == "add-credential":
            sec = os.environ[a.secret_env] if a.secret_env else getpass.getpass("secret: ")
            vault(a).put(a.name, sec, a.recipient, a.header, a.format); print(f"stored {a.name} -> {a.recipient}")
        elif a.cmd == "credentials": print("\n".join(vault(a).names()))
        elif a.cmd == "request":
            from .agents import AgentKey
            from .broker import request_fields
            k = AgentKey.load(a.agent_key); sc = a.scope.split(",")
            intent = {"why": a.why, "method": a.method, "url": a.url, "cap": a.cap}
            auth = k.sign("request", request_fields(a.credential, a.method, a.url, a.body.encode(), sc, a.cap, a.ttl, intent, a.task_id))
            g = broker(a, True).request(a.agent, a.credential, a.method, a.url, a.body.encode(),
                scope=sc, cap=a.cap, ttl=a.ttl, intent=intent, auth=auth, task_id=a.task_id)
            print(json.dumps(g, indent=2))
        elif a.cmd == "approve": broker(a).approve(a.grant_id); print("approved", a.grant_id)
        elif a.cmd == "resolve": print(json.dumps(broker(a).resolve(a.grant_id, a.performed, note=a.note or "")))
        elif a.cmd == "revoke": print("revoked", broker(a).revoke(a.grant_id, a.agent))
        elif a.cmd == "list":
            for g in broker(a).list(a.status):
                g["expires_in"] = round(g.pop("expires_at") - time.time()); print(json.dumps(g))
        elif a.cmd == "sweep": print("expired", broker(a).expire_sweep())
        elif a.cmd == "verify-log":
            ok, n, msg = broker(a).log.verify(); print(f"{'OK' if ok else 'FAIL'}: {n} receipts, {msg}"); return 0 if ok else 1
        elif a.cmd == "proxy":
            import signal
            from .proxy import serve
            signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))  # run finally: -> key cache cleared
            b = broker(a, True); print(f"mintcall proxy on http://127.0.0.1:{a.port}", flush=True); serve(b, port=a.port, key_ttl=a.key_ttl)
        elif a.cmd == "agent":
            from .agents import AgentKey, AgentRegistry
            reg = AgentRegistry(h / "agents.json")
            if a.agent_cmd == "add":
                if a.public_key: reg.add(a.agent_id, a.public_key); print(f"registered {a.agent_id}")
                else:
                    if not a.out: print("--out PATH required when generating a key", file=sys.stderr); return 2
                    k = AgentKey.generate(a.agent_id); k.save(a.out); reg.add(a.agent_id, k.public_b64())
                    print(f"registered {a.agent_id}; private key -> {a.out} (give it only to that agent)")
            elif a.agent_cmd == "remove": print("removed" if reg.remove(a.agent_id) else "not found", a.agent_id)
            else: print("\n".join(reg.names()))
        elif a.cmd == "task":
            from datetime import datetime, timezone
            ts = lambda: getattr(a, "timestamp", None) or datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            if a.task_cmd == "open": out = broker(a).task_open({"task_id": a.task_id, "timestamp": ts()})
            elif a.task_cmd == "end":
                ev = {"task_id": a.task_id, "timestamp": ts()}
                if a.transition: ev["transition"] = a.transition
                out = broker(a).task_end(ev)
            elif a.task_cmd == "destroyed": out = broker(a).task_destroyed({"task_id": a.task_id, "timestamp": ts(), "destructorOk": a.dok})
            elif a.task_cmd == "stuck": out = broker(a).stuck_tasks(older_than=a.older_than)
            else: out = broker(a).task_event(json.loads(sys.stdin.read() if a.file == "-" else Path(a.file).read_text()))
            print(json.dumps(out, indent=2))
        elif a.cmd == "sign-claim":
            from .agents import AgentKey, auth_headers
            from .broker import claim_fields
            k = AgentKey.load(a.agent_key)
            for hk, hv in auth_headers(k.sign("claim", claim_fields(a.token.split(".", 1)[0], a.method, a.url, a.body.encode()))).items():
                print(f"{hk}: {hv}")
    except GrantError as e:
        print(f"refused: {e}", file=sys.stderr); return 2
    return 0

if __name__ == "__main__": sys.exit(main())
