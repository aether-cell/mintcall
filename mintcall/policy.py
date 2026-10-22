"""Policy file (JSON). First matching rule wins; no match => deny."""
import fnmatch, json
from pathlib import Path

DEFAULT_POLICY = {
  "max_ttl_seconds": 300,
  "rules": [
    {"agent": "demo-agent", "credential": "demo-api", "methods": ["GET"], "path_glob": "/v1/*",
     "scopes": ["read"], "max_cap": 1.0, "budget": 5.0, "max_ttl_seconds": 120, "decision": "auto"},
    {"agent": "demo-agent", "credential": "demo-api", "methods": ["POST"], "path_glob": "/v1/*",
     "scopes": ["write"], "max_cap": 10.0, "budget": 20.0, "max_ttl_seconds": 120, "decision": "ask"}
  ]
}

class Policy:
    def __init__(self, data): self.data = data
    @classmethod
    def load(cls, path): return cls(json.loads(Path(path).read_text()))

    def evaluate(self, agent, credential, method, path, scope, cap, ttl):
        """returns (decision in auto|ask|deny, reason, rule)"""
        if ttl > self.data.get("max_ttl_seconds", 300): return "deny", "ttl above global max", None
        for r in self.data.get("rules", []):
            if not fnmatch.fnmatch(agent, r.get("agent", "*")): continue
            if r.get("credential", "*") != "*" and r["credential"] != credential: continue
            if method.upper() not in [m.upper() for m in r.get("methods", ["*"])] and "*" not in r.get("methods", ["*"]): continue
            if not fnmatch.fnmatch(path, r.get("path_glob", "*")): continue
            if not set(scope) <= set(r.get("scopes", [])): return "deny", "scope not allowed", r
            if cap > r.get("max_cap", 0): return "deny", f"cap {cap} > rule max {r.get('max_cap')}", r
            if ttl > r.get("max_ttl_seconds", 300): return "deny", "ttl above rule max", r
            return r.get("decision", "ask"), "matched rule", r
        return "deny", "no matching rule", None
