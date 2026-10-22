import hashlib, json
from urllib.parse import urlsplit, parse_qsl, urlencode

def canonical_url(url: str) -> str:
    p = urlsplit(url)
    q = urlencode(sorted(parse_qsl(p.query, keep_blank_values=True)))
    port = f":{p.port}" if p.port else ""
    return f"{p.scheme.lower()}://{(p.hostname or '').lower()}{port}{p.path or '/'}" + (f"?{q}" if q else "")

def request_hash(method: str, url: str, body: bytes = b"") -> str:
    """Binds a grant to method + canonical target + exact body bytes."""
    canon = json.dumps({"m": method.upper(), "u": canonical_url(url),
                        "b": hashlib.sha256(body or b"").hexdigest()}, sort_keys=True)
    return hashlib.sha256(canon.encode()).hexdigest()

def recipient_of(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme.lower()}://{(p.hostname or '').lower()}" + (f":{p.port}" if p.port else "")
