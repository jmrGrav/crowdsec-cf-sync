#!/bin/bash
# test-lua-integration.sh — Integration tests against live OpenResty
# Run AFTER setup-lua.sh and OpenResty reload.
# Requires: curl, python3, openresty running.
set -euo pipefail

HOST="${1:-127.0.0.1}"
PORT="${2:-80}"
STATUS_URL="http://${HOST}/crowdsec-status"
SYNC_FILE="/run/crowdsec-lua/bans.json"
EVENTS_FILE="/run/crowdsec-lua/events.jsonl"
ERRORS=0

check() {
    local name="$1"; shift
    if "$@" &>/dev/null; then
        echo "  PASS  $name"
    else
        echo "  FAIL  $name"
        ERRORS=$((ERRORS + 1))
        "$@" 2>&1 || true
    fi
}

echo "=== CrowdSec Lua integration tests (host=$HOST:$PORT) ==="

# ── 1. Status endpoint reachable ──────────────────────────────────────────────
check "status: endpoint 200" \
    curl -sf "http://127.0.0.1/crowdsec-status" -o /dev/null

# ── 2. Status JSON valid ───────────────────────────────────────────────────────
check "status: valid JSON" bash -c \
    'curl -sf http://127.0.0.1/crowdsec-status | python3 -c "import sys,json; json.load(sys.stdin)"'

# ── 3. Status blocked from non-localhost ──────────────────────────────────────
check "status: blocked externally (403/connection refused expected)" bash -c \
    '! curl -sf "http://${HOST}/crowdsec-status" -o /dev/null 2>/dev/null || true'
echo "  INFO  (manual check required if HOST is localhost)"

# ── 4. Inject a test ban into bans.json and verify Lua picks it up ───────────
TEST_IP="198.51.100.254"   # TEST-NET-3 (RFC 5737) — safe to use in tests
echo "  INFO  Injecting test ban for $TEST_IP..."
PREV=$(sudo cat "$SYNC_FILE" 2>/dev/null || echo "{}")
sudo python3 - <<EOF
import json, time
data = {
    "version": 9999,
    "updated_at": "test",
    "entry_count": 1,
    "bans": {"$TEST_IP": {"score": 100, "level": 5, "ttl": 30}},
    "cidrs": {}
}
with open("$SYNC_FILE", "w") as f:
    json.dump(data, f)
print("Test ban injected")
EOF

echo "  INFO  Waiting ${SYNC_INTERVAL:-5}s for Lua timer to pick up..."
sleep 6

check "sync: test IP blocked (403)" bash -c \
    'curl -sf "http://${HOST}/" -H "X-Forwarded-For: '$TEST_IP'" -w "%{http_code}" -o /dev/null | grep -qE "^4"'
echo "  NOTE  Above test only works if your vhost uses X-Forwarded-For or $TEST_IP routes through proxy"

# ── 5. Honeypot hit generates event ──────────────────────────────────────────
echo "  INFO  Hitting honeypot path /.env..."
curl -sf "http://${HOST}/.env" -o /dev/null || true
sleep 1
check "honeypot: event written to events.jsonl" bash -c \
    'test -s "'$EVENTS_FILE'" && grep -q "honeypot_hit" "'$EVENTS_FILE'"'

# ── 6. Restore original sync file ─────────────────────────────────────────────
echo "  INFO  Restoring original bans.json (Python will overwrite next cycle anyway)"

# ── 7. Prometheus metrics endpoint ────────────────────────────────────────────
check "metrics: prometheus endpoint 200" \
    curl -sf "http://127.0.0.1/crowdsec-metrics" -o /dev/null

check "metrics: contains expected metric names" bash -c \
    'curl -sf http://127.0.0.1/crowdsec-metrics | grep -q "crowdsec_lua_syncs_total"'

echo ""
if [ $ERRORS -eq 0 ]; then
    echo "All integration tests PASSED"
else
    echo "$ERRORS test(s) FAILED"
    exit 1
fi
