# Changelog

## Unreleased

### Changed
- **`destructorOk` moved out of `task_end` into a separate `task_destroyed` event.** The broker can only vouch for revocation, so `task_end {task_id, timestamp, transition?}` now records `grantsRevoked: true` with `revoked_grant_ids`, and refuses a `destructorOk` field. After killing the process group, the runner sends `task_destroyed {task_id, timestamp, destructorOk}` (CLI `mintcall task destroyed`), which writes its own signed receipt. New `Broker.stuck_tasks()` / `mintcall task stuck` lists tasks with grants revoked but no `destructorOk=true`. `examples/task_runner.py` now does refuse, kill, check the group is gone, destructor, stamp. Suggested by lousbud_reef.

### Added
- **Unknown outcomes are not failures.** A timeout or reset after the request was sent now marks the grant `unresolved` (504, `X-Mintcall-Outcome: unknown`, signed `unresolved` receipt, nothing charged) instead of `failed`. While it is unresolved, an identical write (same agent and request hash) cannot be granted again; reads and different writes are unaffected. `Broker.resolve()` / `mintcall resolve GRANT_ID --performed|--not-performed` records what actually happened. Connection refused or a DNS failure stays a plain `failed` (502, `X-Mintcall-Outcome: not_sent`). Prompted by AiiCLI's post "A retry can spend an agent's authority twice" on Moltbook.
- **Per-task-id grant scoping.** Grants can carry an optional `task_id` (covered by the request signature). The broker accepts `task_open {task_id, timestamp}` and `task_end {task_id, timestamp, destructorOk}` (Python API `Broker.task_open/task_end/task_event`, CLI `mintcall task open|end|event`). A task-bound grant can be minted or used only while its task is open; unknown or ended tasks get 403 with the reason. On `task_end` the broker first refuses all new grants and uses for the task and revokes its unused grants, then writes a signed `task_end` receipt listing `revoked_grant_ids`. Teardown is the runner's job: kill the process group only after `task_end` returns (see `examples/task_runner.py`). Sample events in `examples/task_events.jsonl`.
- Proxy marks 3xx responses with `X-Mintcall-Redirect: refused`.
- Regression tests: 307 and 308 (GET and POST), plus 301/302/303, redirecting to a different origin are never followed by the proxy or client, and nothing (no key, no grant token) reaches the other origin.

## Security

### Redirects could carry the injected API key to another origin. Fixed in `dcc7fa7`.
- **What leaked:** the proxy made upstream calls with urllib's default opener, which follows redirects. If the upstream (or anything able to answer for it) returned a 307/308 with a `Location` on a different origin, urllib re-sent the request **with the real API key header the proxy had just injected** to that origin. With urllib this hit GET/HEAD for 301/302/303/307/308, and POST for 301/302/303 (re-sent as a GET). urllib itself does not follow a 307/308 on POST, but the new tests cover that case too. The agent-side client followed redirects the same way, which could send the grant token and claim signature to the other origin too.
- **Fix (`dcc7fa7`):** neither the proxy nor the client follows redirects. The 3xx goes back to the agent unfollowed, the grant is recorded as `fail_no_charge`, and the new URL needs its own grant.
- **Affected scope:** every mintcall version before `dcc7fa7` (v0.1.0 included), for any credential whose upstream can return a cross-origin redirect. Exposure needed an upstream that redirects (by misconfiguration or compromise, or an open redirect on the API host). Agents never saw the key directly. If you ran an earlier version against such an upstream, rotate the affected keys.

## 0.1.0
- Initial release: per-call grants bound to the request hash, claim-once, cap re-checked at use, settle on success, Ed25519 agent auth, signed hash-chained receipts.
