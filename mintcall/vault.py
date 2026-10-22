"""Real credentials live here, never in agent config. Encrypted file (scrypt + Fernet) or OS keyring."""
import base64, json, os
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

class VaultError(Exception): pass

def _key(passphrase: str, salt: bytes) -> bytes:
    return base64.urlsafe_b64encode(Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(passphrase.encode()))

class FileVault:
    """credential name -> {"secret", "header", "format", "recipient"}"""
    def __init__(self, path, passphrase=None):
        self.path = Path(path)
        self.passphrase = passphrase or os.environ.get("MINTCALL_PASSPHRASE")
        if not self.passphrase:
            raise VaultError("set MINTCALL_PASSPHRASE (or use --keyring)")

    def _load(self):
        if not self.path.exists(): return {}
        raw = json.loads(self.path.read_text())
        try:
            data = Fernet(_key(self.passphrase, base64.b64decode(raw["salt"]))).decrypt(raw["ct"].encode())
        except InvalidToken:
            raise VaultError("wrong passphrase or corrupted vault")
        return json.loads(data)

    def _save(self, d):
        salt = os.urandom(16)
        ct = Fernet(_key(self.passphrase, salt)).encrypt(json.dumps(d).encode()).decode()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"v": 1, "salt": base64.b64encode(salt).decode(), "ct": ct}))
        os.chmod(tmp, 0o600); tmp.replace(self.path)

    def put(self, name, secret, recipient, header="Authorization", fmt="Bearer {secret}"):
        d = self._load(); d[name] = {"secret": secret, "recipient": recipient, "header": header, "format": fmt}; self._save(d)

    def get(self, name):
        d = self._load()
        if name not in d: raise VaultError(f"no credential {name!r}")
        return d[name]

    def names(self): return sorted(self._load())

class KeyringVault:
    """Secret in OS keyring; non-secret metadata in a plain JSON sidecar."""
    SERVICE = "aether-cell-mintcall"
    def __init__(self, meta_path):
        import keyring  # optional dependency
        self.kr = keyring; self.meta = Path(meta_path)
    def _m(self): return json.loads(self.meta.read_text()) if self.meta.exists() else {}
    def put(self, name, secret, recipient, header="Authorization", fmt="Bearer {secret}"):
        self.kr.set_password(self.SERVICE, name, secret)
        m = self._m(); m[name] = {"recipient": recipient, "header": header, "format": fmt}
        self.meta.parent.mkdir(parents=True, exist_ok=True); self.meta.write_text(json.dumps(m))
    def get(self, name):
        m = self._m().get(name); s = self.kr.get_password(self.SERVICE, name)
        if not m or s is None: raise VaultError(f"no credential {name!r}")
        return {**m, "secret": s}
    def names(self): return sorted(self._m())
