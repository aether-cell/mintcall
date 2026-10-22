#!/usr/bin/env bash
# aether-cell mintcall — one-minute demo. Fully local; uses a throwaway home + fake upstream API.
set -euo pipefail
cd "$(dirname "$0")"
PY=${PY:-python3}
export MINTCALL_HOME=$(mktemp -d) MINTCALL_PASSPHRASE=demo-passphrase DEMO_KEY=FAKE_TEST_KEY_not_a_secret
mc() { $PY -m mintcall.cli "$@"; }
$PY examples/fake_upstream.py 9901 & UP=$!
PX=; trap 'kill $UP ${PX:-} 2>/dev/null; rm -rf "$MINTCALL_HOME"' EXIT
echo "== 1. init + store the real key in the encrypted vault (not in any agent config)"
mc init; mc add-credential demo-api --recipient http://127.0.0.1:9901 --secret-env DEMO_KEY
unset DEMO_KEY
echo "== 1b. register the agent: it gets its own Ed25519 key; the broker keeps only the public half"
AK=$MINTCALL_HOME/agent/demo-agent.key; mc agent add demo-agent --out "$AK"
mc proxy --port 8787 >/dev/null & PX=$!; sleep 1.5
echo "== 2. agent requests a grant for ONE call (auto-approved by policy)"
TOKEN=$(mc request --agent demo-agent --agent-key "$AK" --credential demo-api --url "http://127.0.0.1:9901/v1/items?id=7" --cap 0.5 --ttl 30 --why "list item 7" | $PY -c 'import json,sys;print(json.load(sys.stdin)["token"])')
call() {  # every claim is signed by the agent key (timestamp + nonce => a signature can't be replayed)
  local -a H=(); while IFS= read -r l; do H+=(-H "$l"); done < <(mc sign-claim --agent-key "$AK" --token "$TOKEN" --url "$1")
  curl -s -w "  [HTTP %{http_code}]\n" -H "X-Mintcall-Grant: $TOKEN" -H "X-Mintcall-Target: $1" "${H[@]}" http://127.0.0.1:8787/; }
unsigned() { curl -s -w "  [HTTP %{http_code}]\n" -H "X-Mintcall-Grant: $TOKEN" -H "X-Mintcall-Target: $1" http://127.0.0.1:8787/; }
echo "== 2b. same grant, unsigned claim";                             unsigned "http://127.0.0.1:9901/v1/items?id=7"
echo "== 3. call through proxy (key injected, agent never sees it)"; call "http://127.0.0.1:9901/v1/items?id=7"
echo "== 4. replay same grant";                                       call "http://127.0.0.1:9901/v1/items?id=7"
TOKEN=$(mc request --agent demo-agent --agent-key "$AK" --credential demo-api --url "http://127.0.0.1:9901/v1/items?id=8" --cap 0.5 | $PY -c 'import json,sys;print(json.load(sys.stdin)["token"])')
echo "== 5. fresh grant used for a different call";                  call "http://127.0.0.1:9901/v1/items?id=9"
echo "== 5b. that grant is now burned, even for its own call";        call "http://127.0.0.1:9901/v1/items?id=8"
echo "== 6. POST needs approval per policy"
mc request --agent demo-agent --agent-key "$AK" --credential demo-api --method POST --url http://127.0.0.1:9901/v1/orders --scope write --cap 2 | grep -E '"(status|grant_id)"'
echo "== 7. user revokes everything for this agent"; mc revoke --agent demo-agent
echo "== 8. grants"; mc list
echo "== 9. verify signed receipt log"; mc verify-log
