"""Grant store + lifecycle: request -> policy -> mint -> claim(verify) -> settle | expire | revoke."""
import functools, hashlib, hmac, json, secrets, sqlite3, threading, time, uuid
from pathlib import Path
from urllib.parse import urlsplit
from .hashing import request_hash, recipient_of
from .policy import Policy
from .receipts import ReceiptLog
from .agents import AgentRegistry, AuthError, MAX_SKEW, body_hash
from . import notify

class GrantError(Exception): pass

SCHEMA = """
CREATE TABLE IF NOT EXISTS grants(
  grant_id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, credential TEXT NOT NULL,
  recipient TEXT NOT NULL, request_hash TEXT NOT NULL, method TEXT, url TEXT,
  intent TEXT, scope TEXT, cap REAL, budget REAL, not_before REAL, expires_at REAL,
  nonce TEXT UNIQUE, token_hash TEXT, status TEXT, receipt_ref TEXT, created REAL);
CREATE TABLE IF NOT EXISTS spend(agent_id TEXT, credential TEXT, amount REAL, grant_id TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS nonces(nonce TEXT PRIMARY KEY, agent_id TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v INTEGER);
CREATE TABLE IF NOT EXISTS tasks(task_id TEXT PRIMARY KEY, state TEXT NOT NULL, opened_at TEXT,
  ended_at TEXT, destructor_ok INTEGER, end_receipt TEXT, destroyed_at TEXT, destroy_receipt TEXT);
"""

TASK_ID_MAX = 128
SAFE_METHODS = ("GET", "HEAD", "OPTIONS")  # reads: retrying them never spends authority twice

def _th(t): return hashlib.sha256(t.encode()).hexdigest()

def _locked(f):
    @functools.wraps(f)
    def w(self, *a, **k):
        with self.lock: return f(self, *a, **k)
    return w

def intent_hash(intent):
    """sha256 of the canonical JSON of the structured intent ({} when none), so the `why` a human
    approves is the `why` the agent signed."""
    return hashlib.sha256(json.dumps(intent or {}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def request_fields(credential, method, url, body, scope, cap, ttl, intent=None, task_id=None):
    """What an agent signs when it asks for a grant (including the intent shown at approval and, when the
    grant is bound to a task, the task_id, so a signed request cannot be re-bound to another task)."""
    f = {"credential": credential, "method": method.upper(), "url": url, "body_sha256": body_hash(body),
         "scope": sorted(scope), "cap": float(cap), "ttl": int(ttl), "intent_sha256": intent_hash(intent)}
    if task_id is not None: f["task_id"] = task_id
    return f

def intent_mismatch(intent, method, url, cap):
    """If the structured intent states the call (method, url, cap), it must state the call actually
    requested, so an approver is never shown a harmless-looking intent for a different call.
    Returns the first mismatching field name, or None."""
    i = intent or {}
    if "method" in i and str(i["method"]).upper() != method.upper(): return "method"
    if "url" in i and i["url"] != url: return "url"
    if "cap" in i:
        try:
            if float(i["cap"]) != float(cap): return "cap"
        except (TypeError, ValueError): return "cap"
    return None

def claim_fields(grant_id, method, url, body):
    """What an agent signs when it presents a grant (binds the signature to the exact call)."""
    return {"grant_id": grant_id, "request_hash": request_hash(method, url, body)}

class Broker:
    def __init__(self, home, policy=None, vault=None, clock=time.time, agents=None, require_auth=True):
        self.home = Path(home); self.home.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.home / "grants.db", isolation_level=None, check_same_thread=False, timeout=10)
        self.db.executescript(SCHEMA)
        try: self.db.execute("ALTER TABLE grants ADD COLUMN strikes INTEGER DEFAULT 0")
        except sqlite3.OperationalError: pass  # already migrated
        try: self.db.execute("ALTER TABLE grants ADD COLUMN task_id TEXT")
        except sqlite3.OperationalError: pass  # already migrated
        for col in ("destroyed_at TEXT", "destroy_receipt TEXT", "ended_clock REAL"):
            try: self.db.execute(f"ALTER TABLE tasks ADD COLUMN {col}")
            except sqlite3.OperationalError: pass
        self.agents = agents or AgentRegistry(self.home / "agents.json")
        self.require_auth = require_auth
        self.notify_threads = []
        self.policy = policy or Policy.load(self.home / "policy.json")
        self.vault = vault
        self.log = ReceiptLog(self.home / "receipts.jsonl", self.home / "receipt-signing.key")
        self.now = clock
        self.lock = threading.RLock()

    # 1-3: request, policy check, mint
    @_locked
    def request(self, agent_id, credential, method, url, body=b"", scope=("read",), cap=0.0,
                ttl=60, intent=None, auth=None, task_id=None):
        if self.require_auth:
            try:
                signer = self.agents.verify("request", request_fields(credential, method, url, body, scope, cap, ttl, intent, task_id), auth)
                if signer != agent_id: raise AuthError("signature is for a different agent")
                self._use_nonce(auth)
            except AuthError as e:
                self.log.append("auth_fail", op="request", claimed_agent=agent_id, reason=str(e))
                raise GrantError(f"auth: {e}")
        if task_id is not None:
            bad_task = self._task_refusal(task_id)
            if bad_task:
                self.log.append("deny", agent_id=agent_id, url=url, task_id=task_id, reason=bad_task)
                raise GrantError(bad_task)
        if self.vault is not None:
            cred = self.vault.get(credential)
            if recipient_of(url) != cred["recipient"]:
                self.log.append("deny", agent_id=agent_id, url=url, reason="recipient not bound to credential")
                raise GrantError("recipient does not match credential's recipient")
        bad = intent_mismatch(intent, method, url, cap)
        if bad:
            self.log.append("deny", agent_id=agent_id, url=url, reason=f"intent {bad} does not match request")
            raise GrantError(f"intent {bad} does not match the requested call")
        decision, reason, rule = self.policy.evaluate(agent_id, credential, method,
                                                      urlsplit(url).path or "/", list(scope), cap, ttl)
        rh = request_hash(method, url, body)
        if method.upper() not in SAFE_METHODS:
            u = self.db.execute("SELECT grant_id FROM grants WHERE agent_id=? AND request_hash=? AND status='unresolved'",
                                (agent_id, rh)).fetchone()
            if u:
                why = f"an identical call (grant {u[0]}) has an unknown outcome; resolve it before retrying"
                self.log.append("deny", agent_id=agent_id, url=url, reason=why)
                raise GrantError(why)
        base = dict(agent_id=agent_id, credential=credential, method=method.upper(), url=url,
                    request_hash=rh, scope=list(scope), cap=cap, ttl=ttl, intent=intent or {},
                    **({"task_id": task_id} if task_id is not None else {}))
        if decision == "deny":
            self.log.append("deny", reason=reason, **base)
            raise GrantError(f"denied: {reason}")
        gid = "g_" + uuid.uuid4().hex
        token = secrets.token_urlsafe(32)
        now = self.now()
        status = "minted" if decision == "auto" else "pending_approval"
        ref = self.log.append("mint" if status == "minted" else "approval_requested",
                              grant_id=gid, decision=decision, reason=reason, **base)
        self.db.execute("INSERT INTO grants(grant_id,agent_id,credential,recipient,request_hash,method,url,intent,scope,"
                        "cap,budget,not_before,expires_at,nonce,token_hash,status,receipt_ref,created,strikes,task_id) "
                        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,?)",
            (gid, agent_id, credential, recipient_of(url), rh, method.upper(), url,
             json.dumps(intent or {}), json.dumps(list(scope)), cap, rule.get("budget", cap),
             now, now + ttl, secrets.token_hex(16), _th(token), status, ref, now, task_id))
        if status == "pending_approval":
            self.notify_threads = notify.fire(self.policy.data.get("notify"), "pending_approval",
                {"grant_id": gid, "agent_id": agent_id, "credential": credential, "method": method.upper(),
                 "url": url, "cap": cap, "expires_at": now + ttl, "why": (intent or {}).get("why", "")})
        return {"grant_id": gid, "token": f"{gid}.{token}", "status": status,
                "expires_at": now + ttl, "request_hash": rh, "receipt_ref": ref, "task_id": task_id}

    # ---- task lifecycle (events come from the runner; teardown itself is the runner's job) ----
    def _task_refusal(self, task_id):
        """None if the task is open, else the reason a grant bound to it must be refused."""
        row = self.db.execute("SELECT state FROM tasks WHERE task_id=?", (task_id,)).fetchone()
        if not row: return f"unknown task {task_id!r} (no task_open received)"
        if row[0] != "open": return f"task {task_id!r} has ended (task_end received): no new grants or uses"
        return None

    @staticmethod
    def _check_event(ev, kind, required):
        if not isinstance(ev, dict): raise GrantError(f"{kind}: event must be a JSON object")
        missing = [k for k in required if k not in ev]
        if missing: raise GrantError(f"{kind}: missing field(s) {', '.join(missing)}")
        tid = ev["task_id"]
        if not isinstance(tid, str) or not tid or len(tid) > TASK_ID_MAX:
            raise GrantError(f"{kind}: task_id must be a non-empty string of at most {TASK_ID_MAX} chars")
        if "event" in ev and ev["event"] != kind: raise GrantError(f"{kind}: event field says {ev['event']!r}")

    @_locked
    def task_open(self, event):
        """event = {"task_id": str, "timestamp": str}. Grants may then be bound to task_id.
        A task_id is single-use: once ended it cannot be reopened."""
        self._check_event(event, "task_open", ("task_id", "timestamp"))
        tid = event["task_id"]
        try:
            self.db.execute("INSERT INTO tasks(task_id,state,opened_at) VALUES(?, 'open', ?)", (tid, str(event["timestamp"])))
        except sqlite3.IntegrityError:
            raise GrantError(f"task_open: task {tid!r} already exists (task ids are single-use)")
        ref = self.log.append("task_open", task_id=tid, timestamp=str(event["timestamp"]))
        return {"task_id": tid, "state": "open", "receipt_ref": ref}

    TRANSITIONS = ("done", "cancelled", "suspended")

    @_locked
    def task_end(self, event):
        """event = {"task_id": str, "timestamp": str, "transition"?: "done"|"cancelled"|"suspended"}.
        In ONE transaction: mark the task ended (so every later mint or claim bound to it is refused with
        a task-ended reason) and revoke its unused grants (minted / pending_approval). Then write a signed
        task_end receipt (grantsRevoked) listing the revoked grant ids. Only after this returns should the
        runner kill the task's process group; the broker never kills anything. A grant already claimed
        (call in flight) is not interrupted; its settle is recorded as usual.
        destructorOk is NOT part of task_end: the broker can only vouch for revocation. The runner reports
        teardown separately with task_destroyed, after the kill."""
        self._check_event(event, "task_end", ("task_id", "timestamp"))
        if "destructorOk" in event:
            raise GrantError("task_end: destructorOk is not accepted here; send it after the kill as task_destroyed")
        tr = event.get("transition")
        if tr is not None and tr not in self.TRANSITIONS:
            raise GrantError(f"task_end: transition must be one of {', '.join(self.TRANSITIONS)}")
        tid, ts = event["task_id"], str(event["timestamp"])
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row = self.db.execute("SELECT state FROM tasks WHERE task_id=?", (tid,)).fetchone()
            if not row: raise GrantError(f"task_end: unknown task {tid!r}")
            if row[0] != "open": raise GrantError(f"task_end: task {tid!r} already ended")
            self.db.execute("UPDATE tasks SET state='ended', ended_at=?, ended_clock=? WHERE task_id=?", (ts, self.now(), tid))
            ids = [r[0] for r in self.db.execute(
                "SELECT grant_id FROM grants WHERE task_id=? AND status IN ('minted','pending_approval') ORDER BY created", (tid,))]
            self.db.execute("UPDATE grants SET status='revoked' WHERE task_id=? AND status IN ('minted','pending_approval')", (tid,))
            self.db.execute("INSERT INTO meta VALUES('revoke_epoch',1) ON CONFLICT(k) DO UPDATE SET v=v+1")
            self.db.execute("COMMIT")
        except Exception:
            if self.db.in_transaction: self.db.execute("ROLLBACK")
            raise
        extra = {"transition": tr} if tr else {}
        ref = self.log.append("task_end", task_id=tid, timestamp=ts, **extra, grantsRevoked=True, revoked_grant_ids=ids)
        self.db.execute("UPDATE tasks SET end_receipt=? WHERE task_id=?", (ref, tid))
        return {"task_id": tid, "state": "ended", "grantsRevoked": True, "revoked_grant_ids": ids, "receipt_ref": ref}

    @_locked
    def task_destroyed(self, event):
        """event = {"task_id": str, "timestamp": str, "destructorOk": bool}. Sent by the runner AFTER it
        killed the task's process group (and released whatever else the task held). Accepted only once,
        and only for a task that already ended. Writes a signed task_destroyed receipt."""
        self._check_event(event, "task_destroyed", ("task_id", "timestamp", "destructorOk"))
        if not isinstance(event["destructorOk"], bool): raise GrantError("task_destroyed: destructorOk must be true or false")
        tid, ts, dok = event["task_id"], str(event["timestamp"]), event["destructorOk"]
        row = self.db.execute("SELECT state, destroyed_at FROM tasks WHERE task_id=?", (tid,)).fetchone()
        if not row: raise GrantError(f"task_destroyed: unknown task {tid!r}")
        if row[0] == "open": raise GrantError(f"task_destroyed: task {tid!r} is still open; send task_end first (refuse, then kill)")
        if row[1] is not None: raise GrantError(f"task_destroyed: task {tid!r} already has a destructor stamp")
        ref = self.log.append("task_destroyed", task_id=tid, timestamp=ts, destructorOk=dok)
        self.db.execute("UPDATE tasks SET destroyed_at=?, destructor_ok=?, destroy_receipt=? WHERE task_id=?", (ts, int(dok), ref, tid))
        return {"task_id": tid, "state": "destroyed" if dok else "destructor_failed", "destructorOk": dok, "receipt_ref": ref}

    def stuck_tasks(self, older_than=None):
        """Tasks a sweep should flag: grants revoked (task_end) but no destructorOk=true stamp yet,
        either because task_destroyed never arrived or because it reported failure.
        age_s is measured on the broker's own clock from task_end (the runner's timestamp is not trusted for this);
        older_than (seconds) keeps only entries at least that old. The broker does not escalate; the reader does."""
        now = self.now()
        rows = self.db.execute("SELECT task_id, ended_at, destroyed_at, destructor_ok, ended_clock FROM tasks WHERE state='ended' "
                               "AND (destroyed_at IS NULL OR destructor_ok=0) ORDER BY COALESCE(ended_clock, 0), ended_at").fetchall()
        out = []
        for t, e, d, _, c in rows:
            age = None if c is None else round(now - c, 3)
            if older_than is not None and (age is None or age < older_than) and c is not None: continue
            out.append({"task_id": t, "ended_at": e, "age_s": age,
                        "reason": "no task_destroyed after task_end" if d is None else "destructorOk=false"})
        return out

    def task_event(self, event):
        """Dispatch a lifecycle event carrying "event": "task_open" | "task_end" | "task_destroyed"."""
        kind = event.get("event") if isinstance(event, dict) else None
        if kind == "task_open": return self.task_open(event)
        if kind == "task_end": return self.task_end(event)
        if kind == "task_destroyed": return self.task_destroyed(event)
        raise GrantError(f"unknown lifecycle event {kind!r} (expected task_open, task_end or task_destroyed)")

    def _use_nonce(self, auth):
        now = self.now()
        if abs(now - float(auth["ts"])) > MAX_SKEW: raise AuthError("signature timestamp outside allowed window")
        self.db.execute("DELETE FROM nonces WHERE ts < ?", (now - 2 * MAX_SKEW,))
        try: self.db.execute("INSERT INTO nonces VALUES(?,?,?)", (auth["nonce"], auth["agent"], float(auth["ts"])))
        except sqlite3.IntegrityError: raise AuthError("nonce already used (replayed signature)")

    def revoke_epoch(self):
        r = self.db.execute("SELECT v FROM meta WHERE k='revoke_epoch'").fetchone(); return r[0] if r else 0

    def _mismatch_cfg(self):
        m = self.policy.data.get("on_mismatch", {"mode": "burn"})
        return m.get("mode", "burn"), int(m.get("max_strikes", 1))

    @_locked
    def approve(self, grant_id, approver="user"):
        cur = self.db.execute("UPDATE grants SET status='minted' WHERE grant_id=? AND status='pending_approval' AND expires_at>?",
                              (grant_id, self.now()))
        if cur.rowcount != 1: raise GrantError("not pending (or expired)")
        self.log.append("approve", grant_id=grant_id, approver=approver)

    @_locked
    def revoke(self, grant_id=None, agent_id=None, by="user"):
        """User-side revoke. Plain DB write; works whether or not the proxy is running."""
        q, a = ("grant_id=?", grant_id) if grant_id else ("agent_id=?", agent_id)
        cur = self.db.execute(f"UPDATE grants SET status='revoked' WHERE {q} AND status IN ('minted','pending_approval')", (a,))
        self.db.execute("INSERT INTO meta VALUES('revoke_epoch',1) ON CONFLICT(k) DO UPDATE SET v=v+1")
        self.log.append("revoke", grant_id=grant_id, agent_id=agent_id, by=by, count=cur.rowcount)
        return cur.rowcount

    def spent(self, agent_id, credential):
        return self.db.execute("SELECT COALESCE(SUM(amount),0) FROM spend WHERE agent_id=? AND credential=?",
                               (agent_id, credential)).fetchone()[0]

    # 4: atomic verify + claim-once
    @_locked
    def claim(self, token, method, url, body=b"", auth=None):
        try: gid, tok = token.split(".", 1)
        except (ValueError, AttributeError): raise self._refuse(None, "malformed grant token")
        now = self.now(); rh = request_hash(method, url, body)
        signer = None
        if self.require_auth:
            try:
                signer = self.agents.verify("claim", claim_fields(gid, method, url, body), auth)
                self._use_nonce(auth)
            except AuthError as e:
                raise self._refuse(gid, f"auth: {e}")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row = self.db.execute("SELECT agent_id,credential,recipient,request_hash,cap,budget,not_before,expires_at,token_hash,status,strikes,task_id "
                                  "FROM grants WHERE grant_id=?", (gid,)).fetchone()
            if not row: raise self._refuse(gid, "unknown grant")
            agent, cred, recip, grh, cap, budget, nb, exp, th, status, strikes, task_id = row
            if not hmac.compare_digest(th, _th(tok)): raise self._refuse(gid, "bad token")
            if task_id is not None:   # checked before status, so a grant revoked by task_end says why
                bad_task = self._task_refusal(task_id)
                if bad_task: raise self._refuse(gid, bad_task)
            if status != "minted": raise self._refuse(gid, f"grant is {status} (reuse/replay refused)")
            if now >= exp:
                self.db.execute("UPDATE grants SET status='expired' WHERE grant_id=?", (gid,))
                self.db.execute("COMMIT"); self.db.execute("BEGIN")
                raise self._refuse(gid, "grant expired")
            if now < nb: raise self._refuse(gid, "grant not yet valid")
            if signer is not None and signer != agent: self._strike(gid, strikes, "claim signed by a different agent")
            if recipient_of(url) != recip: self._strike(gid, strikes, "recipient mismatch")
            if not hmac.compare_digest(grh, rh): self._strike(gid, strikes, "request hash mismatch (bound to a different call)")
            if self.spent(agent, cred) + cap > budget: raise self._refuse(gid, "cap re-check failed: budget exhausted")
            self.db.execute("UPDATE grants SET status='claimed' WHERE grant_id=? AND status='minted'", (gid,))
            self.db.execute("COMMIT")
        except Exception:
            if self.db.in_transaction: self.db.execute("ROLLBACK")
            raise
        self.log.append("claim", grant_id=gid, agent_id=agent, request_hash=rh, signed=signer is not None)
        return {"grant_id": gid, "agent_id": agent, "credential": cred, "cap": cap}

    def _strike(self, gid, strikes, reason):
        """Grant presented for the wrong request. Commit the strike (not rolled back), maybe burn, then refuse."""
        mode, mx = self._mismatch_cfg()
        strikes += 1
        burn = mode == "burn" or strikes >= mx
        self.db.execute("UPDATE grants SET strikes=?, status=CASE WHEN ? THEN 'burned' ELSE status END WHERE grant_id=?",
                        (strikes, burn, gid))
        self.db.execute("COMMIT")
        self.log.append("strike", grant_id=gid, reason=reason, strikes=strikes, burned=burn)
        raise GrantError(reason + (" -> grant burned" if burn else f" (strike {strikes}/{mx})"))

    def _refuse(self, gid, reason):
        if self.db.in_transaction: self.db.execute("ROLLBACK")
        self.log.append("refuse", grant_id=gid, reason=reason)
        return GrantError(reason)

    # settle only on success
    @_locked
    def settle(self, claim, ok, status_code=None, cost=None, response_sha256=None, unresolved=None):
        """unresolved: reason string when the request may have reached upstream but no response came back
        (timeout, reset). Outcome is unknown, not failed: nothing is charged yet, and an identical write
        cannot be granted again until resolve() records what actually happened."""
        gid = claim["grant_id"]
        if unresolved:
            self.db.execute("UPDATE grants SET status='unresolved' WHERE grant_id=?", (gid,))
            self.log.append("unresolved", grant_id=gid, reason=str(unresolved), charged=0.0)
            return
        if ok:
            amt = claim["cap"] if cost is None else min(cost, claim["cap"])
            self.db.execute("INSERT INTO spend VALUES(?,?,?,?,?)", (claim["agent_id"], claim["credential"], amt, gid, self.now()))
            self.db.execute("UPDATE grants SET status='settled' WHERE grant_id=?", (gid,))
        else:
            amt = 0.0
            self.db.execute("UPDATE grants SET status='failed' WHERE grant_id=?", (gid,))
        extra = {"response_sha256": response_sha256} if response_sha256 else {}
        self.log.append("settle" if ok else "fail_no_charge", grant_id=gid, upstream_status=status_code, charged=amt, **extra)

    @_locked
    def resolve(self, grant_id, performed, by="user", note=""):
        """Record the real outcome of an unresolved call, after checking it upstream (operation status,
        idempotency key lookup, or a human looking). performed=True charges the cap as a settle would."""
        row = self.db.execute("SELECT agent_id, credential, cap, status FROM grants WHERE grant_id=?", (grant_id,)).fetchone()
        if not row or row[3] != "unresolved": raise GrantError("not unresolved")
        amt = float(row[2]) if performed else 0.0
        if performed:
            self.db.execute("INSERT INTO spend VALUES(?,?,?,?,?)", (row[0], row[1], amt, grant_id, self.now()))
        self.db.execute("UPDATE grants SET status=? WHERE grant_id=?", ("settled" if performed else "failed", grant_id))
        self.log.append("resolve", grant_id=grant_id, performed=bool(performed), charged=amt, by=by,
                        **({"note": note} if note else {}))
        return {"grant_id": grant_id, "status": "settled" if performed else "failed", "charged": amt}

    @_locked
    def expire_sweep(self):
        cur = self.db.execute("UPDATE grants SET status='expired' WHERE status IN ('minted','pending_approval') AND expires_at<=?", (self.now(),))
        if cur.rowcount: self.log.append("expire_sweep", count=cur.rowcount)
        return cur.rowcount

    @_locked
    def list(self, status=None):
        q = "SELECT grant_id,agent_id,credential,method,url,cap,status,expires_at FROM grants"
        rows = self.db.execute(q + (" WHERE status=?" if status else "") + " ORDER BY created", (status,) if status else ()).fetchall()
        return [dict(zip(["grant_id","agent_id","credential","method","url","cap","status","expires_at"], r)) for r in rows]
