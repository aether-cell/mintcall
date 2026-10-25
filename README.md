# aether-cell mintcall

**Mint-on-call credential broker for AI agents. It runs on your own machine only.**

**Status: v0, looking for design partners — a2a@mail.grokbot.com**

Agent configs (`mcp.json` and similar) hold no secrets. When an agent needs to make a call, it asks the local broker for a grant for **that one call**. The grant is single-use, bound to the request, short-lived and capped. A local proxy checks the grant, injects the real key, forwards the call and records the outcome in a signed receipt. The agent never sees the key, so a stolen config or a captured grant is worthless.

## Install
Requires Python 3.10+. The only runtime dependency is `cryptography`.
```bash
git clone https://github.com/aether-cell/mintcall && cd mintcall
pip install -e .              # or: pip install -e '.[keyring]' to use the OS keyring
pip install pytest && pytest -q tests
```

## 60-second demo
```bash
./demo.sh               # throwaway home + fake upstream API, nothing leaves 127.0.0.1
```
The demo uses the obviously fake key `FAKE_TEST_KEY_not_a_secret`; no real credentials are involved.
The demo shows: key stored encrypted → agent gets its own Ed25519 key → signed grant request minted for `GET /v1/items?id=7` → an unsigned claim is refused (403) → the signed call succeeds with the injected key (HTTP 200) → replaying the grant is refused (403) → a fresh grant used on a different call is refused and burned (403, then 403 even for its own call) → a POST waits for approval → the user revokes the agent's grants → the signed log verifies.

## How it works
| Piece | File | Notes |
|---|---|---|
| Vault | `mintcall/vault.py` | scrypt + Fernet encrypted file (`MINTCALL_PASSPHRASE`), or `--keyring` (OS keyring, `pip install .[keyring]`). Each credential is pinned to one recipient origin. |
| Policy | `~/.mintcall/policy.json` | Rules match agent, credential, method, path glob, scopes, max cap, budget, max TTL and decision (`auto` / `ask`). A request that matches no rule is denied. |
| Grant | `mintcall/broker.py` | Fields: grant_id, agent_id, recipient, request_hash, intent, scope, cap, not_before / expires_at, nonce, status, receipt_ref. Status runs minted → claimed → settled, or ends as failed, expired or revoked. Only a hash of the token is stored. |
| Claim | `Broker.claim` | One `BEGIN IMMEDIATE` transaction checks the token, status, window, recipient and request hash, then **re-checks the cap against spend** before claiming. A grant can be claimed only once. |
| Settle | `Broker.settle` | Spend is committed only on an upstream 2xx response. A failed call is recorded as `fail_no_charge`. |
| Proxy | `mintcall/proxy.py` | Listens on loopback only. The client sends `X-Mintcall-Grant` plus `X-Mintcall-Target`, or uses an absolute URI. The proxy strips any client `Authorization` header, injects the key and redacts the key if it is echoed back. |
| Agent auth | `mintcall/agents.py` | `mintcall agent add NAME --out KEYFILE` generates an Ed25519 keypair; the broker keeps only the public key (`agents.json`), the private key goes to that agent (0600). Every grant request and every claim is signed over a canonical message plus `ts` and a random `nonce`. The broker refuses unsigned, unknown-agent and bad signatures, timestamps more than 60 s off, and reused nonces. Request signatures cover credential, method, URL, body hash, scope, cap and TTL. Claim signatures cover grant_id and request_hash. A claim signed by a different agent than the grant's owner is a strike. |
| Strikes | `policy.json` → `on_mismatch` | A grant presented for the wrong request (hash, recipient or agent mismatch) is a strike that gets committed and logged. `{"mode":"burn"}` (default) burns the grant at once. `{"mode":"strikes","max_strikes":N}` burns it at the Nth strike. Signature failures are refused but are **not** strikes, so a party without the agent key cannot burn someone else's grant. |
| Key cache | `mintcall/keycache.py` | The proxy keeps decrypted credentials in memory for `--key-ttl` seconds (default 30, 0 = off). The cache is cleared on shutdown (including SIGTERM) and whenever any revoke happens. Revoke bumps a counter in the DB that the proxy checks on every call, so a revoke from the CLI also clears it. |
| Notify | `mintcall/notify.py`, `policy.json` → `notify` | `{"command": "...", "webhook": "http://...", "timeout": 5}`. Fires on `pending_approval` in a background thread. The command gets `MINTCALL_EVENT`, `MINTCALL_GRANT_ID`, `MINTCALL_AGENT_ID`, `MINTCALL_CREDENTIAL`, `MINTCALL_METHOD`, `MINTCALL_URL`, `MINTCALL_CAP`, `MINTCALL_EXPIRES_AT` and `MINTCALL_WHY` in its env. The webhook gets the same fields as a JSON POST. Neither ever receives the grant token or the key. |
| Receipts | `receipts.jsonl` | Append-only, SHA-256 hash-chained and Ed25519-signed. Check it with `mintcall verify-log`. |

`request_hash` = sha256(method, canonical URL with sorted query, sha256(body)).

## CLI
```
mintcall init
mintcall add-credential NAME --recipient https://api.example.com [--header X-Api-Key --format "{secret}"]
mintcall agent add A --out ./A.key | --public-key B64      mintcall agent list | remove A
mintcall request --agent A --agent-key ./A.key --credential NAME --method GET --url URL [--body ..] --scope read --cap 0.5 --ttl 60 --why "..."
mintcall approve GRANT_ID      mintcall revoke GRANT_ID | --agent A
mintcall list [--status minted] mintcall sweep   mintcall verify-log
mintcall proxy --port 8787 [--key-ttl 30]
mintcall sign-claim --agent-key ./A.key --token TOKEN --url URL [--method GET]   # prints X-Mintcall-{Agent,Ts,Nonce,Sig} headers
```
Agents that call the proxy directly send `X-Mintcall-Grant` and `X-Mintcall-Target`, plus the four signature headers (`mintcall.client.send(..., signer=key)` does this for you).

## Wrapping an MCP server
See `examples/mcp_tool_wrapper.py` and `examples/mcp.json`. The tool body calls `call_via_proxy(...)` where it used to call `requests.get(url, headers={key})`. The MCP process never opens the vault and needs no passphrase. If the `mcp` SDK is installed, it runs as a FastMCP server (`--serve`).

## Tests
`pytest -q tests` (36 tests) covers reuse, replay to a different path, recipient or body, expiry, forged tokens, a concurrent claim race (32 threads, 1 success), revoke, approval flow, policy denials, cap re-check at use, no charge on failure, tamper detection in the receipt log, and vault encryption. It also covers agent auth: unsigned requests, wrong keys, an agent impersonating another, params or intent changed after signing, nonce replay, stale timestamps, unsigned or mis-signed claims, claim-signature replay, and a stolen grant used by another agent. Plus burn vs N-strikes, key-cache hit/expiry/revoke/shutdown, the notify command and webhook, and the `agent add` CLI. Redirects: 301/302/303 and 307/308 (GET and POST) to another origin are never followed by the proxy or client, and the injected key never reaches the other origin.

## Latency (`bench/latency.py`, local, fake upstream, real scrypt vault)
| | median | p95 |
|---|---|---|
| v0 (decrypt vault on every call, unsigned) | 106–109 ms | 125–134 ms |
| now, cache off (`--key-ttl 0`) + Ed25519 sign/verify | 121 ms | 162 ms |
| now, cache on (default 30 s) | 15.6–16.4 ms | 24 ms |

Almost all of the v0 cost was the scrypt KDF (n=2^15) on each decrypt. The first call after start, expiry or revoke still pays it (~125 ms). Signature checking adds only a few ms. These numbers do **not** include `request` (minting), which still decrypts the vault once to check the recipient.

## Threat model limits (known limits, v0)
- **HTTPS upstreams:** the agent → proxy hop is plain HTTP on loopback, and the proxy makes the HTTPS call upstream. `CONNECT` tunnelling and transparent MITM are not supported. Clients must address the proxy explicitly.
- **A compromised local machine can still drive the broker.** Agents now authenticate with their own Ed25519 keys. But agent key files are plain 0600 files: malware running as the same user can read them, and it can also read `agents.json`, `grants.db` and the policy and change them. Per-agent auth separates *agents* from each other. It does not protect against a hostile local user. The `approve`/`revoke`/`agent add` CLI is not authenticated beyond file permissions.
- Notifications are fire-and-forget: there are no retries, no signature on the webhook, and nobody is told if the hook fails. Approval itself still happens only through the CLI.
- Nonces are kept for 2×60 s. Clock skew between agent and broker is limited to ±60 s. The structured `intent` (`--why`) is covered by the request signature (`intent_sha256`), so it can't be swapped before an approver sees it; if the intent states `method`, `url` or `cap`, the broker refuses the request unless they match the actual call, so an approver is never shown a harmless-looking intent for a different call. The `why` itself is still free text the agent writes.
- The key cache keeps decrypted secrets in Python memory for up to `--key-ttl`. Python cannot reliably zero strings, so "clear" drops the references and they are not wiped.
- The cost charged equals the grant's cap. There is no per-response metering.
- The receipt signing key sits next to the log (0600). It proves the log is internally consistent, but it does not protect against an attacker who has that key.
- Single SQLite DB; not tested under multi-process load.

## Threat model + vs secretless /grant

**Assets:** upstream API keys and upstream spend. **Adversaries:** a prompt-injected or buggy agent, a leaked `mcp.json` or agent log, a captured grant token, and one local agent trying to use another's grants. **Out of scope:** root or same-user malware, and a compromised upstream.

| Threat | Mitigation |
|---|---|
| Agent config or log leaks | No secrets in the config. Grants are single-use, request-bound and expire in seconds to minutes. |
| Grant replayed or redirected to another call | `request_hash` binding plus claim-once; the mismatch is a strike and burns the grant by default. |
| Grant stolen by another agent | The claim must be signed by the owning agent's key. If not, it is a strike. |
| Signed message replayed | `ts` window plus a single-use nonce. |
| Overspend through pre-minted grants | The cap is re-checked against spend in the claim transaction. Spend is only charged on 2xx. |
| Key echoed back by the upstream | The proxy redacts the key from response bodies. |
| Upstream redirects the call to another origin | The proxy never follows redirects (fixed in `dcc7fa7`; see CHANGELOG). The 3xx goes back to the agent with `X-Mintcall-Redirect: refused`, and reaching the new URL needs a fresh grant. |
| Silent misuse | Hash-chained, Ed25519-signed receipts, and a notify hook on approvals. |

**What secretless provides** (opena2a-org/secretless-ai, commit `a18cd3da`): `broker start` serves `POST /grant` from a grant file. Agents are identified by **ATX** issuer-signed (Ed25519) identity assertions, with trust, revocation and bindings in that file. The broker exchanges for a **short-lived, scoped token** through **RFC 8693 token exchange** against a configured identity provider, and **the broker makes the downstream call itself**, so the agent never holds the long-lived secret. Decisions go to an audit log, and an optional AIM check can deny unverified agents. This is a solid identity-first design. If you already run an IdP that supports token exchange and want standards-based scoped tokens, it covers that well, and mintcall does not try to replace it.

**What mintcall adds** (the residual a scoped short-lived token does not cover by itself):
- **Request-hash binding:** a grant is good for one exact `method + canonical URL + body hash`, not for "anything in scope for N minutes."
- **Single-use claim-once:** one atomic claim, and a second use is refused even within the TTL.
- **Cap re-checked at use:** spend is re-validated inside the claim transaction, so a stack of grants minted ahead of time cannot overrun the budget.
- **Settle-on-success:** spend is committed only on an upstream 2xx response. Failures are recorded as `fail_no_charge`.
- **Response digest:** every settle or `fail_no_charge` receipt carries `response_sha256`, the sha256 of the response body exactly as the agent received it (after key redaction). If the agent's own note about a call disagrees with what came back, the digest shows it.
- **No identity provider needed:** it works with plain API keys (`X-Api-Key`, `Bearer`) for providers that offer no token exchange at all. Agent identity is a local Ed25519 key.

What mintcall does **not** have that secretless does: standards-based federated identity (ATX/RFC 8693), revocation lists distributed by issuers, and upstream tokens that are actually down-scoped. A mintcall grant is scoped by local policy, but the injected key is still the full-power key.

License: Apache-2.0.
