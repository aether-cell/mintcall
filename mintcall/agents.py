"""Per-agent authentication. Each agent has its own Ed25519 keypair; the broker stores only the
public key (agents.json). Every grant request and every claim is signed over a canonical message
that includes a timestamp and a single-use nonce, so a captured signature cannot be replayed."""
import base64, hashlib, json, os, secrets, time
from pathlib import Path
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

class AuthError(Exception): pass

MAX_SKEW = 60  # seconds a signed message stays acceptable

def b64(b): return base64.b64encode(b).decode()

def canonical(op, fields):
    """Deterministic bytes that are signed. `op` separates request-signatures from claim-signatures."""
    return json.dumps({"op": op, **fields}, sort_keys=True, separators=(",", ":")).encode()

def body_hash(body): return hashlib.sha256(body or b"").hexdigest()

class AgentKey:
    """Agent-side private key. Lives with the agent (0600 file), never in the broker home's registry."""
    def __init__(self, agent_id, priv):
        self.agent_id, self.priv = agent_id, priv
    @classmethod
    def generate(cls, agent_id): return cls(agent_id, Ed25519PrivateKey.generate())
    @classmethod
    def load(cls, path):
        d = json.loads(Path(path).read_text())
        return cls(d["agent_id"], Ed25519PrivateKey.from_private_bytes(base64.b64decode(d["private_key"])))
    def save(self, path):
        p = Path(path); p.parent.mkdir(parents=True, exist_ok=True)
        raw = self.priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f: json.dump({"agent_id": self.agent_id, "private_key": b64(raw)}, f)
    def public_b64(self):
        return b64(self.priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    def sign(self, op, fields, ts=None, nonce=None):
        """returns auth dict {agent, ts, nonce, sig}"""
        ts = time.time() if ts is None else ts; nonce = nonce or secrets.token_hex(16)
        msg = canonical(op, {**fields, "agent": self.agent_id, "ts": ts, "nonce": nonce})
        return {"agent": self.agent_id, "ts": ts, "nonce": nonce, "sig": b64(self.priv.sign(msg))}

class AgentRegistry:
    """agent_id -> public key (base64 raw Ed25519). Public keys only; safe to commit/back up."""
    def __init__(self, path): self.path = Path(path)
    def _d(self): return json.loads(self.path.read_text()) if self.path.exists() else {}
    def add(self, agent_id, public_b64):
        Ed25519PublicKey.from_public_bytes(base64.b64decode(public_b64))  # validate
        d = self._d(); d[agent_id] = {"public_key": public_b64, "added": time.time()}
        self.path.parent.mkdir(parents=True, exist_ok=True); self.path.write_text(json.dumps(d, indent=2))
    def remove(self, agent_id):
        d = self._d(); found = d.pop(agent_id, None) is not None; self.path.write_text(json.dumps(d, indent=2)); return found
    def names(self): return sorted(self._d())
    def verify(self, op, fields, auth):
        """Signature check only. Freshness + nonce single-use are enforced by the broker (needs the DB)."""
        if not isinstance(auth, dict) or not all(k in auth for k in ("agent", "ts", "nonce", "sig")):
            raise AuthError("unsigned request (agent signature required)")
        ent = self._d().get(auth["agent"])
        if not ent: raise AuthError(f"unknown agent {auth['agent']!r}")
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(ent["public_key"]))
        msg = canonical(op, {**fields, "agent": auth["agent"], "ts": auth["ts"], "nonce": auth["nonce"]})
        try: pub.verify(base64.b64decode(auth["sig"]), msg)
        except (InvalidSignature, ValueError, TypeError): raise AuthError("bad agent signature")
        return auth["agent"]

def auth_headers(auth):
    return {"X-Mintcall-Agent": auth["agent"], "X-Mintcall-Ts": repr(auth["ts"]),
            "X-Mintcall-Nonce": auth["nonce"], "X-Mintcall-Sig": auth["sig"]}

def auth_from_headers(h):
    if not h.get("X-Mintcall-Sig"): return None
    try: ts = float(h.get("X-Mintcall-Ts", ""))
    except ValueError: return None
    return {"agent": h.get("X-Mintcall-Agent", ""), "ts": ts, "nonce": h.get("X-Mintcall-Nonce", ""), "sig": h["X-Mintcall-Sig"]}
