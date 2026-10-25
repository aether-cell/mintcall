# Changelog

## Unreleased

### Added
- Proxy marks 3xx responses with `X-Mintcall-Redirect: refused`.
- Regression tests: 307 and 308 (GET and POST), plus 301/302/303, redirecting to a different origin are never followed by the proxy or client, and nothing (no key, no grant token) reaches the other origin.

## Security

### Redirects could carry the injected API key to another origin. Fixed in `dcc7fa7`.
- **What leaked:** the proxy made upstream calls with urllib's default opener, which follows redirects. If the upstream (or anything able to answer for it) returned a 307/308 with a `Location` on a different origin, urllib re-sent the request **with the real API key header the proxy had just injected** to that origin. With urllib this hit GET/HEAD for 301/302/303/307/308, and POST for 301/302/303 (re-sent as a GET). urllib itself does not follow a 307/308 on POST, but the new tests cover that case too. The agent-side client followed redirects the same way, which could send the grant token and claim signature to the other origin too.
- **Fix (`dcc7fa7`):** neither the proxy nor the client follows redirects. The 3xx goes back to the agent unfollowed, the grant is recorded as `fail_no_charge`, and the new URL needs its own grant.
- **Affected scope:** every mintcall version before `dcc7fa7` (v0.1.0 included), for any credential whose upstream can return a cross-origin redirect. Exposure needed an upstream that redirects (by misconfiguration or compromise, or an open redirect on the API host). Agents never saw the key directly. If you ran an earlier version against such an upstream, rotate the affected keys.

## 0.1.0
- Initial release: per-call grants bound to the request hash, claim-once, cap re-checked at use, settle on success, Ed25519 agent auth, signed hash-chained receipts.
