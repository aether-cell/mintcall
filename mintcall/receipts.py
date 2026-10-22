"""Append-only, hash-chained, Ed25519-signed receipt log (JSONL)."""
import base64, hashlib, json, os, time
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

GENESIS = "0" * 64

def _canon(o): return json.dumps(o, sort_keys=True, separators=(",", ":")).encode()

class ReceiptLog:
    def __init__(self, path, key_path):
        self.path, self.key_path = Path(path), Path(key_path)
        if self.key_path.exists():
            self.sk = serialization.load_pem_private_key(self.key_path.read_bytes(), None)
        else:
            self.sk = Ed25519PrivateKey.generate()
            self.key_path.parent.mkdir(parents=True, exist_ok=True)
            self.key_path.write_bytes(self.sk.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            os.chmod(self.key_path, 0o600)
        self.pk_raw = self.sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def _last(self):
        if not self.path.exists(): return 0, GENESIS
        lines = self.path.read_text().splitlines()
        if not lines: return 0, GENESIS
        last = json.loads(lines[-1]); return last["seq"], last["hash"]

    def append(self, event, **data):
        seq, prev = self._last()
        body = {"seq": seq + 1, "ts": time.time(), "event": event, "prev": prev, "data": data}
        h = hashlib.sha256(_canon(body)).hexdigest()
        rec = {**body, "hash": h, "sig": base64.b64encode(self.sk.sign(h.encode())).decode()}
        with open(self.path, "a") as f:
            f.write(json.dumps(rec, sort_keys=True) + "\n"); f.flush(); os.fsync(f.fileno())
        return f"{self.path.name}#{rec['seq']}:{h[:16]}"

    def verify(self, pubkey_raw=None):
        pk = Ed25519PublicKey.from_public_bytes(pubkey_raw or self.pk_raw)
        prev, n = GENESIS, 0
        if not self.path.exists(): return True, 0, "empty"
        for i, line in enumerate(self.path.read_text().splitlines(), 1):
            r = json.loads(line); sig = r.pop("sig"); h = r.pop("hash")
            if r["seq"] != i: return False, i, "sequence gap"
            if r["prev"] != prev: return False, i, "chain broken"
            if hashlib.sha256(_canon(r)).hexdigest() != h: return False, i, "hash mismatch (tampered)"
            try: pk.verify(base64.b64decode(sig), h.encode())
            except InvalidSignature: return False, i, "bad signature"
            prev, n = h, i
        return True, n, "ok"
