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
"""

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

def request_fields(credential, method, url, body, scope, cap, ttl, intent=None):
    """What an agent signs when it asks for a grant (including the intent shown at approval)."""
    return {"credential": credential, "method": method.upper(), "url": url, "body_sha256": body_hash(body),
            "scope": sorted(scope), "cap": float(cap), "ttl": int(ttl), "intent_sha256": intent_hash(intent)}

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
                ttl=60, intent=None, auth=None):
        if self.require_auth:
            try:
                signer = self.agents.verify("request", request_fields(credential, method, url, body, scope, cap, ttl, intent), auth)
                if signer != agent_id: raise AuthError("signature is for a different agent")
                self._use_nonce(auth)
            except AuthError as e:
                self.log.append("auth_fail", op="request", claimed_agent=agent_id, reason=str(e))
                raise GrantError(f"auth: {e}")
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
        base = dict(agent_id=agent_id, credential=credential, method=method.upper(), url=url,
                    request_hash=rh, scope=list(scope), cap=cap, ttl=ttl, intent=intent or {})
        if decision == "deny":
            self.log.append("deny", reason=reason, **base)
            raise GrantError(f"denied: {reason}")
        gid = "g_" + uuid.uuid4().hex
        token = secrets.token_urlsafe(32)
        now = self.now()
        status = "minted" if decision == "auto" else "pending_approval"
        ref = self.log.append("mint" if status == "minted" else "approval_requested",
                              grant_id=gid, decision=decision, reason=reason, **base)
        self.db.execute("INSERT INTO grants VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0)",
            (gid, agent_id, credential, recipient_of(url), rh, method.upper(), url,
             json.dumps(intent or {}), json.dumps(list(scope)), cap, rule.get("budget", cap),
             now, now + ttl, secrets.token_hex(16), _th(token), status, ref, now))
        if status == "pending_approval":
            self.notify_threads = notify.fire(self.policy.data.get("notify"), "pending_approval",
                {"grant_id": gid, "agent_id": agent_id, "credential": credential, "method": method.upper(),
                 "url": url, "cap": cap, "expires_at": now + ttl, "why": (intent or {}).get("why", "")})
        return {"grant_id": gid, "token": f"{gid}.{token}", "status": status,
                "expires_at": now + ttl, "request_hash": rh, "receipt_ref": ref}

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
            row = self.db.execute("SELECT agent_id,credential,recipient,request_hash,cap,budget,not_before,expires_at,token_hash,status,strikes "
                                  "FROM grants WHERE grant_id=?", (gid,)).fetchone()
            if not row: raise self._refuse(gid, "unknown grant")
            agent, cred, recip, grh, cap, budget, nb, exp, th, status, strikes = row
            if not hmac.compare_digest(th, _th(tok)): raise self._refuse(gid, "bad token")
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
    def settle(self, claim, ok, status_code=None, cost=None):
        gid = claim["grant_id"]
        if ok:
            amt = claim["cap"] if cost is None else min(cost, claim["cap"])
            self.db.execute("INSERT INTO spend VALUES(?,?,?,?,?)", (claim["agent_id"], claim["credential"], amt, gid, self.now()))
            self.db.execute("UPDATE grants SET status='settled' WHERE grant_id=?", (gid,))
        else:
            amt = 0.0
            self.db.execute("UPDATE grants SET status='failed' WHERE grant_id=?", (gid,))
        self.log.append("settle" if ok else "fail_no_charge", grant_id=gid, upstream_status=status_code, charged=amt)

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
