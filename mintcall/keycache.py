"""In-memory credential cache for the proxy so the scrypt-encrypted vault is not decrypted per call.
Entries expire after `ttl` seconds; `clear()` wipes them (called on revoke and on shutdown).
Python cannot guarantee memory zeroing of str objects; we drop all references so they become garbage."""
import threading, time

class CachedVault:
    def __init__(self, vault, ttl=30.0, clock=time.monotonic):
        self.vault, self.ttl, self.now = vault, ttl, clock
        self._c = {}; self._lock = threading.Lock(); self.hits = self.misses = 0
    def get(self, name):
        with self._lock:
            e = self._c.get(name)
            if e and self.now() < e[0]: self.hits += 1; return e[1]
            self._c.pop(name, None)
        v = self.vault.get(name)  # decrypt outside the lock
        with self._lock:
            self.misses += 1
            if self.ttl > 0: self._c[name] = (self.now() + self.ttl, v)
        return v
    def clear(self):
        with self._lock:
            for k in list(self._c): self._c[k][1].clear() if isinstance(self._c[k][1], dict) else None
            self._c.clear()
    def __len__(self): return len(self._c)
    def __getattr__(self, a): return getattr(self.vault, a)  # put/names pass through
