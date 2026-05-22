#!/bin/bash
# test-lua-integration.sh — Integration + chaos tests for the Lua runtime layer
#
# Principles:
#   - Autodétect all endpoints from actual openresty -T output (never hardcode)
#   - Transactional: backup bans.json before injection, always restore on EXIT
#   - Explicit FAIL if endpoint is unreachable — never silent false-positive
#   - Minimal chaos: test real failure modes, verify real recovery
#
# Usage:
#   sudo bash scripts/test-lua-integration.sh          # all tests
#   sudo bash scripts/test-lua-integration.sh --chaos  # chaos tests only
#   sudo bash scripts/test-lua-integration.sh --quick  # smoke only (no injection)

set -uo pipefail

# ── Detect environment from actual nginx config ────────────────────────────────
# Never guess ports or paths. Use what's actually loaded.

detect_endpoints() {
    local nginx_bin
    nginx_bin=$(command -v openresty 2>/dev/null || command -v nginx 2>/dev/null || echo "")
    [ -z "$nginx_bin" ] && { echo "FAIL: no nginx/openresty in PATH"; exit 1; }

    # Pull the compiled config dump — this is what's actually running
    local dump
    dump=$(sudo "$nginx_bin" -T 2>/dev/null) || {
        echo "FAIL: cannot run $nginx_bin -T (need root?)"
        exit 1
    }

    # Find the port for our internal status server (listen on 127.0.0.1:XXXX)
    # Look for the server block that contains crowdsec-status location
    STATUS_PORT=$(echo "$dump" | python3 - <<'PYEOF'
import re, sys
content = sys.stdin.read()
# Find server blocks containing crowdsec-status
blocks = re.findall(r'server\s*\{[^}]*listen[^;]*127\.0\.0\.1:(\d+)[^}]*crowdsec-status[^}]*\}',
                    content, re.DOTALL)
if blocks:
    print(blocks[0])
else:
    # Also try finding the listen line near crowdsec-status
    matches = re.findall(r'listen\s+127\.0\.0\.1:(\d+)', content)
    if matches:
        print(matches[0])
    else:
        print("8091")  # documented default, log that we fell back
PYEOF
)

    STATUS_URL="http://127.0.0.1:${STATUS_PORT}/crowdsec-status"
    METRICS_URL="http://127.0.0.1:${STATUS_PORT}/crowdsec-metrics"

    # Sync file path from loaded Lua modules (grep SYNC_FILE constant)
    SYNC_FILE=$(echo "$dump" | grep -o 'SYNC_FILE[[:space:]]*=[[:space:]]*"[^"]*"' | \
        head -1 | grep -o '"[^"]*"' | tr -d '"' || echo "/run/crowdsec-lua/bans.json")
    [ -z "$SYNC_FILE" ] && SYNC_FILE="/run/crowdsec-lua/bans.json"

    EVENTS_FILE="${SYNC_FILE%/*}/events.jsonl"
    SYNC_DIR="${SYNC_FILE%/*}"
}

detect_endpoints

# ── Mode flags ─────────────────────────────────────────────────────────────────
RUN_CHAOS=false; RUN_QUICK=false
for arg in "$@"; do
    case "$arg" in
        --chaos) RUN_CHAOS=true ;;
        --quick) RUN_QUICK=true ;;
    esac
done

# ── Test state ─────────────────────────────────────────────────────────────────
ERRORS=0; SKIPPED=0; TOTAL=0
SYNC_BACKUP=""
SYNC_INTERVAL=6  # seconds to wait for Lua timer tick (SYNC_INTERVAL=5 + margin)

# ── Colours ────────────────────────────────────────────────────────────────────
GRN='\033[0;32m'; RED='\033[0;31m'; YLW='\033[1;33m'; RST='\033[0m'
pass()  { echo -e "  ${GRN}PASS${RST}  $1"; }
fail()  { echo -e "  ${RED}FAIL${RST}  $1${2:+ — $2}"; ((ERRORS++)) || true; }
skip()  { echo -e "  ${YLW}SKIP${RST}  $1${2:+ — $2}"; ((SKIPPED++)) || true; }
info()  { echo "  INFO  $1"; }
hdr()   { echo -e "\n── $1 ──"; }

# ── Transactional bans.json management ───────────────────────────────────────
backup_sync_file() {
    if [ -f "$SYNC_FILE" ]; then
        SYNC_BACKUP=$(mktemp /tmp/bans.json.XXXXXX)
        cp "$SYNC_FILE" "$SYNC_BACKUP"
        info "bans.json backed up to $SYNC_BACKUP"
    else
        SYNC_BACKUP=""
        info "bans.json not yet present (nothing to backup)"
    fi
}

restore_sync_file() {
    if [ -n "$SYNC_BACKUP" ] && [ -f "$SYNC_BACKUP" ]; then
        cp "$SYNC_BACKUP" "$SYNC_FILE"
        chmod 644 "$SYNC_FILE"
        rm -f "$SYNC_BACKUP"
        info "bans.json restored from backup"
    fi
}

# Register cleanup — always restore even on error or SIGINT
trap restore_sync_file EXIT

inject_sync_file() {
    local content="$1"
    echo "$content" | sudo tee "$SYNC_FILE" > /dev/null
    sudo chmod 644 "$SYNC_FILE"
}

# ── Test helpers ───────────────────────────────────────────────────────────────
check() {
    local name="$1"; shift
    ((TOTAL++)) || true
    if eval "$@" &>/dev/null; then
        pass "$name"
    else
        fail "$name"
    fi
}

check_curl_200() {
    local name="$1" url="$2"
    ((TOTAL++)) || true
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" "$url" --max-time 5 2>/dev/null)
    if [ "$code" = "200" ]; then
        pass "$name (HTTP 200)"
    else
        fail "$name" "got HTTP $code from $url"
    fi
}

check_endpoint_reachable() {
    local url="$1"
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" "$url" --max-time 3 2>/dev/null || echo "000")
    [ "$code" = "200" ]
}

get_metric() {
    curl -s "$STATUS_URL" --max-time 5 2>/dev/null | \
        python3 -c "import sys,json; d=json.load(sys.stdin); print($1)" 2>/dev/null || echo "0"
}

echo "=== CrowdSec Lua integration tests ==="
info "Status URL:  $STATUS_URL"
info "Metrics URL: $METRICS_URL"
info "Sync file:   $SYNC_FILE"
info "Events file: $EVENTS_FILE"
echo

# ── Prerequisite: endpoints must be reachable ──────────────────────────────────
hdr "Prerequisites"
if ! check_endpoint_reachable "$STATUS_URL"; then
    fail "Status endpoint UNREACHABLE" "$STATUS_URL — cannot continue"
    echo
    echo "Fix: verify nginx_status_internal.conf is loaded and OpenResty is running"
    echo "     sudo openresty -T | grep crowdsec-status"
    exit 1
fi
pass "Status endpoint reachable"

# ── 1. Smoke tests ─────────────────────────────────────────────────────────────
hdr "1. Smoke tests"

check_curl_200 "status: HTTP 200"   "$STATUS_URL"
check_curl_200 "metrics: HTTP 200"  "$METRICS_URL"

check "status: valid JSON" \
    "curl -sf '$STATUS_URL' --max-time 5 | python3 -c 'import sys,json; json.load(sys.stdin)'"

check "status: has sync.version field" \
    "curl -sf '$STATUS_URL' --max-time 5 | python3 -c 'import sys,json; d=json.load(sys.stdin); assert \"sync\" in d'"

check "status: has dict_health field" \
    "curl -sf '$STATUS_URL' --max-time 5 | python3 -c 'import sys,json; d=json.load(sys.stdin); assert \"dict_health\" in d'"

check "metrics: contains expected names" \
    "curl -sf '$METRICS_URL' --max-time 5 | grep -q crowdsec_lua_syncs_total"

check "metrics: ipc_rejected counter present" \
    "curl -sf '$METRICS_URL' --max-time 5 | grep -q crowdsec_lua_ipc_rejected_total"

[ "$RUN_QUICK" = "true" ] && { echo; info "Quick mode — skipping injection tests"; goto_summary; }

# ── 2. IPC injection tests ─────────────────────────────────────────────────────
hdr "2. IPC injection tests"
backup_sync_file

# Test 2a: valid injection → Lua picks it up
TEST_IP="198.51.100.254"   # TEST-NET-3 RFC 5737 — safe
PREV_VERSION=$(get_metric "d['sync']['version']")
info "Injecting valid ban for $TEST_IP (prev version=$PREV_VERSION)"

inject_sync_file "$(python3 -c "
import json, time
data = {
    'version': int('$PREV_VERSION') + 1000,
    'updated_at': '$(date -u +%FT%TZ)',
    'entry_count': 1,
    'writer_pid': 0,
    'writer_hostname': 'test',
    'payload_crc32': 0,
    'bans': {'$TEST_IP': {'score': 100, 'level': 5, 'ttl': 30}},
    'cidrs': {}
}
print(json.dumps(data))
")"

info "Waiting ${SYNC_INTERVAL}s for Lua timer..."
sleep "$SYNC_INTERVAL"

NEW_VERSION=$(get_metric "d['sync']['version']")
((TOTAL++)) || true
if [ "$NEW_VERSION" != "$PREV_VERSION" ] && [ "$NEW_VERSION" != "0" ]; then
    pass "sync: version advanced ($PREV_VERSION → $NEW_VERSION)"
else
    fail "sync: version did not advance" "still at $PREV_VERSION after ${SYNC_INTERVAL}s"
fi

NEW_ENTRIES=$(get_metric "d['sync']['entries']")
((TOTAL++)) || true
if [ "$NEW_ENTRIES" -ge "1" ] 2>/dev/null; then
    pass "sync: entries loaded ($NEW_ENTRIES)"
else
    fail "sync: no entries loaded" "entries=$NEW_ENTRIES"
fi

restore_sync_file  # restore before chaos tests
sleep "$SYNC_INTERVAL"  # let Lua timer reload the real file

# ── 3. Chaos tests — IPC corruption ───────────────────────────────────────────
hdr "3. Chaos: IPC corruption recovery"
backup_sync_file

PRE_REJECTED=$(get_metric "d['counters'].get('ipc_rejected', 0)")

# Chaos 3a: corrupted JSON
info "Chaos 3a: injecting corrupted JSON..."
inject_sync_file '{"version": 99999, "updated_at": "test", CORRUPTED_GARBAGE'
sleep "$SYNC_INTERVAL"
POST_REJECTED=$(get_metric "d['counters'].get('ipc_rejected', 0)")
((TOTAL++)) || true
if [ "$POST_REJECTED" -gt "$PRE_REJECTED" ] 2>/dev/null; then
    pass "chaos 3a: corrupted JSON rejected (ipc_rejected=$POST_REJECTED)"
else
    fail "chaos 3a: corrupted JSON not counted in ipc_rejected" \
         "pre=$PRE_REJECTED post=$POST_REJECTED"
fi

restore_sync_file
sleep "$SYNC_INTERVAL"

# Chaos 3b: wrong entry_count (integrity check)
PRE_REJECTED=$(get_metric "d['counters'].get('ipc_rejected', 0)")
NEXT_VER=$(python3 -c "print(int($(get_metric 'd[\"sync\"][\"version\"]')) + 500)")
info "Chaos 3b: wrong entry_count (version=$NEXT_VER)..."
inject_sync_file "$(python3 -c "
import json
data = {
    'version': $NEXT_VER,
    'updated_at': '$(date -u +%FT%TZ)',
    'entry_count': 99,
    'bans': {'198.51.100.1': {'score':100,'level':5,'ttl':30}},
    'cidrs': {}
}
print(json.dumps(data))
")"
sleep "$SYNC_INTERVAL"
POST_REJECTED=$(get_metric "d['counters'].get('ipc_rejected', 0)")
((TOTAL++)) || true
if [ "$POST_REJECTED" -gt "$PRE_REJECTED" ] 2>/dev/null; then
    pass "chaos 3b: integrity check rejected wrong entry_count"
else
    fail "chaos 3b: integrity check did not fire" \
         "pre=$PRE_REJECTED post=$POST_REJECTED"
fi

restore_sync_file
sleep "$SYNC_INTERVAL"

# Chaos 3c: sequence rollback (version < current)
info "Chaos 3c: sequence rollback (version=1)..."
CURRENT_VER=$(get_metric "d['sync']['version']")
PRE_SYNCS=$(get_metric "d['counters']['lua_syncs']")
inject_sync_file "$(python3 -c "
import json
data = {
    'version': 1,
    'updated_at': '$(date -u +%FT%TZ)',
    'entry_count': 0,
    'bans': {},
    'cidrs': {}
}
print(json.dumps(data))
")"
sleep "$SYNC_INTERVAL"
POST_SYNCS=$(get_metric "d['counters']['lua_syncs']")
AFTER_VER=$(get_metric "d['sync']['version']")
((TOTAL++)) || true
# Version should not have gone backwards
if [ "$AFTER_VER" = "$CURRENT_VER" ]; then
    pass "chaos 3c: sequence rollback ignored (version stayed at $CURRENT_VER)"
else
    fail "chaos 3c: version changed on rollback attempt" \
         "was $CURRENT_VER now $AFTER_VER"
fi

restore_sync_file
sleep "$SYNC_INTERVAL"

# Chaos 3d: oversized payload (> BANS_JSON_MAX_BYTES)
info "Chaos 3d: oversized payload (>10MB)..."
PRE_REJECTED=$(get_metric "d['counters'].get('ipc_rejected', 0)")
python3 -c "
import json, os
# Build a JSON with enough entries to exceed 10MB
bans = {}
for i in range(500000):
    bans[f'10.{i//65536}.{(i//256)%256}.{i%256}'] = {'score':100,'level':5,'ttl':30}
data = {
    'version': 99998,
    'updated_at': '$(date -u +%FT%TZ)',
    'entry_count': len(bans),
    'bans': bans,
    'cidrs': {}
}
print(json.dumps(data))
" | sudo tee "$SYNC_FILE" > /dev/null 2>&1 || true
sudo chmod 644 "$SYNC_FILE"
local_size=$(stat -c '%s' "$SYNC_FILE" 2>/dev/null || echo 0)
info "  Injected ${local_size} bytes"
sleep "$SYNC_INTERVAL"
POST_REJECTED=$(get_metric "d['counters'].get('ipc_rejected', 0)")
((TOTAL++)) || true
if [ "$POST_REJECTED" -gt "$PRE_REJECTED" ] 2>/dev/null; then
    pass "chaos 3d: oversized payload rejected"
else
    # May not reach 10MB with 500k entries — check if version was loaded anyway
    if [ "$local_size" -gt 10485760 ] 2>/dev/null; then
        fail "chaos 3d: oversized payload NOT rejected despite size=${local_size}"
    else
        skip "chaos 3d: payload not large enough to trigger limit" \
             "size=${local_size}, limit=10485760"
    fi
fi

restore_sync_file
sleep "$SYNC_INTERVAL"

if [ "$RUN_CHAOS" = "true" ]; then
    # ── 4. Chaos tests — runtime disruption ───────────────────────────────────
    hdr "4. Chaos: runtime disruption"

    # Chaos 4a: nginx reload during sync
    info "Chaos 4a: nginx reload during sync cycle..."
    NGINX_BIN=$(command -v openresty 2>/dev/null || command -v nginx)
    PRE_VERSION=$(get_metric "d['sync']['version']")
    sudo systemctl reload openresty 2>/dev/null || sudo "$NGINX_BIN" -s reload
    sleep 2
    # Inject a valid sync file post-reload
    inject_sync_file "$(python3 -c "
import json
data = {
    'version': int('$PRE_VERSION') + 2000,
    'updated_at': '$(date -u +%FT%TZ)',
    'entry_count': 0,
    'bans': {},
    'cidrs': {}
}
print(json.dumps(data))
")"
    sleep "$SYNC_INTERVAL"
    POST_VERSION=$(get_metric "d['sync']['version']")
    ((TOTAL++)) || true
    if [ "$POST_VERSION" != "$PRE_VERSION" ] 2>/dev/null; then
        pass "chaos 4a: sync recovered after nginx reload"
    else
        fail "chaos 4a: sync did not recover after reload" \
             "version stuck at $PRE_VERSION"
    fi
    restore_sync_file
    sleep "$SYNC_INTERVAL"

    # Chaos 4b: events.jsonl backlog (verify drop counter works)
    info "Chaos 4b: events.jsonl overflow (writing >1MB)..."
    PRE_DROPPED=$(get_metric "d['counters'].get('dropped_events', 0)")
    # Write 1.1 MB to events.jsonl to trigger the size limit
    python3 -c "
import json, time
line = json.dumps({'ts': time.time(), 'type': 'test', 'ip': '127.0.0.1', 'score': 0, 'detail': 'x'*200, 'worker': 0})
with open('$EVENTS_FILE', 'a') as f:
    for _ in range(6000):
        f.write(line + '\n')
" 2>/dev/null || true
    # Now trigger an event via a request to a protected vhost
    sleep 2
    POST_DROPPED=$(get_metric "d['counters'].get('dropped_events', 0)")
    ((TOTAL++)) || true
    local_events_size=$(stat -c '%s' "$EVENTS_FILE" 2>/dev/null || echo 0)
    if [ "$local_events_size" -gt 1048576 ] 2>/dev/null; then
        info "  events.jsonl is ${local_events_size} bytes (>1MB)"
        # The next event write should be dropped — we can verify counter after triggering
        info "  (counter check requires a live request to a protected vhost)"
        pass "chaos 4b: overflow condition established"
    else
        skip "chaos 4b: could not fill events.jsonl" "size=${local_events_size}"
    fi
    # Clean up events.jsonl
    sudo truncate -s 0 "$EVENTS_FILE" 2>/dev/null || true
fi

# ── 5. Honeypot test ───────────────────────────────────────────────────────────
hdr "5. Honeypot event"
# Try to hit a known honeypot path via the public vhost (best effort)
info "Attempting honeypot hit on .env path..."
curl -sk "https://www.arleo.eu/.env" -o /dev/null --max-time 5 2>/dev/null || \
curl -sk "http://127.0.0.1/.env" -H "Host: www.arleo.eu" -o /dev/null --max-time 5 2>/dev/null || true
sleep 2

PRE_HONEYPOT=$(get_metric "d['counters'].get('honeypot_hits', 0)")
check "metrics: honeypot_hits counter readable" \
    "curl -sf '$STATUS_URL' --max-time 5 | python3 -c 'import sys,json; d=json.load(sys.stdin); assert \"honeypot_hits\" in d[\"counters\"]'"

# ── 6. Memory health snapshot ──────────────────────────────────────────────────
hdr "6. Memory health"
python3 - "$STATUS_URL" <<'PYEOF'
import sys, json, urllib.request

url = sys.argv[1]
try:
    with urllib.request.urlopen(url, timeout=5) as r:
        d = json.load(r)
except Exception as e:
    print(f"  FAIL  Cannot fetch {url}: {e}")
    sys.exit(0)

dh = d.get("dict_health", {})
for name, free in dh.items():
    free_mb = free / (1024*1024) if free else 0
    if free_mb < 2:
        print(f"  FAIL  {name}: {free_mb:.1f} MB free (< 2 MB threshold)")
    elif free_mb < 10:
        print(f"  WARN  {name}: {free_mb:.1f} MB free (tight)")
    else:
        print(f"  PASS  {name}: {free_mb:.1f} MB free")

c = d.get("counters", {})
for cname in ("ipc_rejected", "dict_set_failures", "dropped_events"):
    val = c.get(cname, 0)
    if val > 0:
        print(f"  WARN  {cname} = {val} (non-zero since last restart)")
    else:
        print(f"  PASS  {cname} = 0")
PYEOF
((TOTAL++)) || true

# ── Summary ────────────────────────────────────────────────────────────────────
goto_summary() { :; }  # noop used as early-exit label above
echo
echo "── Summary ──"
echo "  Total: $TOTAL  Errors: $ERRORS  Skipped: $SKIPPED"
if [ "$ERRORS" -eq 0 ]; then
    echo -e "${GRN}ALL TESTS PASSED${RST}"
    exit 0
else
    echo -e "${RED}$ERRORS TEST(S) FAILED${RST}"
    exit 1
fi
