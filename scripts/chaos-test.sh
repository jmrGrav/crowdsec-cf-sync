#!/bin/bash
# chaos-test.sh — Targeted chaos tests for V3.3.3 hardening
#
# Tests failure modes NOT covered by test-lua-integration.sh:
#   1. Stale timestamp (bans.json older than BANS_STALE_SECS)
#   2. Future timestamp (bans.json written from a clock-skewed host)
#   3. Events.jsonl flood → dropped_events counter
#   4. Memory pressure flag via oversized-but-valid payload
#   5. Python meta section propagation to Lua metrics
#
# Principles:
#   - Autodétect endpoints (never hardcode)
#   - Transactional: always restore bans.json on EXIT
#   - Each test: read counter BEFORE, inject fault, wait, verify counter CHANGED
#   - FAIL explicitly — never silent false-positive
#
# Usage:
#   sudo bash scripts/chaos-test.sh
#   sudo bash scripts/chaos-test.sh --test stale   # run single test by name
#
# Requires: running OpenResty with Lua layer active (same as test-lua-integration.sh)

set -uo pipefail

# ── Autodétect endpoints ──────────────────────────────────────────────────────
detect_endpoints() {
    local nginx_bin
    nginx_bin=$(command -v openresty 2>/dev/null || command -v nginx 2>/dev/null || echo "")
    [ -z "$nginx_bin" ] && { echo "FAIL: no nginx/openresty in PATH"; exit 1; }

    local dump
    dump=$(sudo "$nginx_bin" -T 2>/dev/null) || {
        echo "FAIL: cannot run $nginx_bin -T (need root?)"; exit 1
    }

    STATUS_PORT=$(echo "$dump" | python3 - <<'PYEOF'
import re, sys
content = sys.stdin.read()
blocks = re.findall(r'server\s*\{[^}]*listen[^;]*127\.0\.0\.1:(\d+)[^}]*crowdsec-status[^}]*\}',
                    content, re.DOTALL)
print(blocks[0] if blocks else "8091")
PYEOF
)
    STATUS_URL="http://127.0.0.1:${STATUS_PORT}/crowdsec-status"
    SYNC_FILE=$(echo "$dump" | grep -o 'SYNC_FILE[[:space:]]*=[[:space:]]*"[^"]*"' | \
        head -1 | grep -o '"[^"]*"' | tr -d '"')
    [ -z "$SYNC_FILE" ] && SYNC_FILE="/run/crowdsec-lua/bans.json"
    SYNC_DIR="${SYNC_FILE%/*}"
    EVENTS_FILE="${SYNC_DIR}/events.jsonl"
}

detect_endpoints

# ── State management ──────────────────────────────────────────────────────────
SYNC_BACKUP=""
SYNC_INTERVAL=7   # SYNC_INTERVAL=5s + 2s margin
ERRORS=0; TOTAL=0; SKIPPED=0
TARGET_TEST="${1:-}"  # e.g. --test stale

backup_sync_file() {
    if [ -f "$SYNC_FILE" ]; then
        SYNC_BACKUP=$(mktemp /tmp/chaos-bans-backup.XXXXXX.json)
        cp "$SYNC_FILE" "$SYNC_BACKUP"
    fi
}

restore_sync_file() {
    if [ -n "$SYNC_BACKUP" ] && [ -f "$SYNC_BACKUP" ]; then
        cp "$SYNC_BACKUP" "$SYNC_FILE" 2>/dev/null || true
        rm -f "$SYNC_BACKUP"
        SYNC_BACKUP=""
    fi
    # Also clean any oversized events.jsonl we may have created
    if [ -f "${EVENTS_FILE}.chaos_backup" ]; then
        mv "${EVENTS_FILE}.chaos_backup" "$EVENTS_FILE" 2>/dev/null || true
    fi
}

trap restore_sync_file EXIT

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RESET='\033[0m'
pass() { echo -e "  ${GREEN}PASS${RESET} $1"; }
fail() { echo -e "  ${RED}FAIL${RESET} $1"; ERRORS=$((ERRORS+1)); }
skip() { echo -e "  ${YELLOW}SKIP${RESET} $1"; }
info() { echo -e "       $1"; }

# ── Helpers ───────────────────────────────────────────────────────────────────
get_counter() {
    # get_counter <json_path> — e.g. get_counter ".ipc.rejected_total"
    curl -s "$STATUS_URL" 2>/dev/null | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    keys = '$1'.lstrip('.').split('.')
    for k in keys: d = d[k]
    print(int(d))
except: print(-1)
"
}

assert_counter_increased() {
    local label="$1" before="$2" after="$3"
    TOTAL=$((TOTAL+1))
    if [ "$after" -gt "$before" ] 2>/dev/null; then
        pass "$label (${before} → ${after})"
    else
        fail "$label — expected counter to increase (was ${before}, got ${after})"
    fi
}

assert_counter_unchanged() {
    local label="$1" before="$2" after="$3"
    TOTAL=$((TOTAL+1))
    if [ "$after" -eq "$before" ] 2>/dev/null; then
        pass "$label (unchanged at ${before})"
    else
        fail "$label — expected unchanged (was ${before}, got ${after})"
    fi
}

write_valid_bans_json() {
    # write_valid_bans_json <version> <updated_at_epoch> [<ip>]
    local ver="$1" epoch="$2" ip="${3:-10.0.0.1}"
    python3 - "$SYNC_FILE" "$ver" "$epoch" "$ip" <<'PYEOF'
import json, sys, tempfile, os
dest, ver, epoch, ip = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
payload = {
    "version": ver,
    "updated_at_epoch": epoch,
    "updated_at": f"epoch-{epoch}",
    "entry_count": 1,
    "writer_pid": os.getpid(),
    "writer_hostname": "chaos-test",
    "bans": {ip: {"score": 100, "level": 5, "ttl": 3600}},
    "cidrs": {},
    "meta": {"cycle_count": 1, "cf_api_errors": 0, "wal_entries": 0,
             "lua_sync_errors": 0, "degraded": False}
}
d = os.path.dirname(dest)
tmp_fd, tmp_path = tempfile.mkstemp(dir=d, suffix=".tmp")
os.fchmod(tmp_fd, 0o644)
with os.fdopen(tmp_fd, "w") as f:
    json.dump(payload, f)
os.replace(tmp_path, dest)
PYEOF
}

# ── Verify endpoint reachable ─────────────────────────────────────────────────
echo "=== crowdsec-cf-sync chaos-test.sh ==="
echo ""
echo "Endpoint : $STATUS_URL"
echo "Sync file: $SYNC_FILE"
echo ""

if ! curl -sf "$STATUS_URL" > /dev/null 2>&1; then
    echo -e "${RED}FATAL${RESET}: $STATUS_URL not reachable."
    echo "  Start OpenResty and ensure /crowdsec-status is configured."
    exit 2
fi

CURRENT_VERSION=$(get_counter ".sync.version")
info "Current sync version: $CURRENT_VERSION"
backup_sync_file

# ── Test selection ────────────────────────────────────────────────────────────
RUN_TEST() {
    local name="$1"
    [ -n "$TARGET_TEST" ] && [ "$TARGET_TEST" != "--test" ] && return 0
    [ -n "$TARGET_TEST" ] && [ "${2:-}" != "$name" ] && return 1
    return 0
}

# ─────────────────────────────────────────────────────────────────────────────
# TEST 1 — Stale timestamp: bans.json with updated_at_epoch > BANS_STALE_SECS ago
# Expected: ipc_rejected increments, sync version does NOT advance
# ─────────────────────────────────────────────────────────────────────────────
echo "── Test 1: Stale timestamp rejection ───────────────────────────────────"

rejected_before=$(get_counter ".ipc.rejected_total")

STALE_EPOCH=$(( $(date +%s) - 700 ))   # 700s ago > BANS_STALE_SECS=600
NEW_VER=$(( CURRENT_VERSION + 1 ))
write_valid_bans_json "$NEW_VER" "$STALE_EPOCH"

sleep $SYNC_INTERVAL

rejected_after=$(get_counter ".ipc.rejected_total")

assert_counter_increased "ipc_rejected incremented on stale timestamp" \
    "$rejected_before" "$rejected_after"
# sync version may advance concurrently (Python's own valid push) — not asserted here

restore_sync_file; backup_sync_file
# Refresh CURRENT_VERSION: Python may have pushed during the sleep, advancing last_version.
# Test 2 must inject a version higher than the current last_version.
CURRENT_VERSION=$(get_counter ".sync.version")
sleep 2

# ─────────────────────────────────────────────────────────────────────────────
# TEST 2 — Future timestamp: bans.json with updated_at_epoch > BANS_FUTURE_SECS ahead
# Expected: ipc_rejected increments, sync version does NOT advance
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "── Test 2: Future timestamp rejection ──────────────────────────────────"

rejected_before=$(get_counter ".ipc.rejected_total")

FUTURE_EPOCH=$(( $(date +%s) + 400 ))  # 400s in future > BANS_FUTURE_SECS=300
NEW_VER=$(( CURRENT_VERSION + 1 ))
write_valid_bans_json "$NEW_VER" "$FUTURE_EPOCH"

sleep $SYNC_INTERVAL

rejected_after=$(get_counter ".ipc.rejected_total")

assert_counter_increased "ipc_rejected incremented on future timestamp" \
    "$rejected_before" "$rejected_after"
# sync version may advance concurrently (Python's own valid push) — not asserted here

restore_sync_file; backup_sync_file
CURRENT_VERSION=$(get_counter ".sync.version")
sleep 2

# ─────────────────────────────────────────────────────────────────────────────
# TEST 3 — Events.jsonl flood: fill events.jsonl beyond EVENTS_MAX_BYTES,
#           then trigger events.write() via an actual honeypot HTTPS request.
# Expected: dropped_events counter increments.
#
# events.write() is only called during request processing (access.lua or
# heuristics.lua), NOT during bans.json loading. This test auto-detects a
# CrowdSec-protected vhost and uses `curl -k --resolve` to bypass DNS.
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "── Test 3: events.jsonl flood → dropped_events ─────────────────────────"

# Auto-detect a CrowdSec-protected HTTPS vhost (one that includes crowdsec_access).
# Store dump first — piping into "python3 - <<'HEREDOC'" causes the heredoc to shadow
# stdin, leaving sys.stdin.read() empty. Use -c with a stored variable instead.
_NGINX_DUMP=$(sudo openresty -T 2>/dev/null)
LUA_VHOST=$(echo "$_NGINX_DUMP" | python3 -c "
import re, sys
content = sys.stdin.read()
matches = re.findall(
    r'server_name\s+([\w.\-]+)\s*;.*?include\s+snippets/crowdsec_access\.conf',
    content, re.DOTALL)
# Exclude wildcard _ placeholder
real = [m for m in matches if m != '_']
print(real[0] if real else '')
")

dropped_before=$(get_counter ".ipc.dropped_events")
honeypot_before=$(get_counter ".heuristics.honeypot_hits")

if [ -z "$LUA_VHOST" ]; then
    info "SKIP: no CrowdSec-protected HTTPS vhost detected in openresty -T"
    SKIPPED=$((SKIPPED+1))
else
    info "Detected Lua-protected vhost: $LUA_VHOST"

    # Backup existing events file if present
    [ -f "$EVENTS_FILE" ] && sudo cp "$EVENTS_FILE" "${EVENTS_FILE}.chaos_backup"

    # Fill events.jsonl to 1.1 MB (beyond EVENTS_MAX_BYTES=1MB)
    sudo python3 - "$EVENTS_FILE" <<'PYEOF'
import json, os, sys
dest = sys.argv[1]
line = json.dumps({"ts": 1.0, "type": "chaos_flood", "ip": "1.2.3.4",
                   "score": 50, "detail": "x" * 200, "worker": 0}) + "\n"
os.makedirs(os.path.dirname(dest), exist_ok=True)
with open(dest, "w") as f:
    written = 0
    while written < 1_150_000:   # 1.1 MB > EVENTS_MAX_BYTES
        f.write(line)
        written += len(line)
print(f"events.jsonl: {os.path.getsize(dest)//1024} KB written")
PYEOF

    # Trigger events.write() via honeypot path on a CrowdSec-protected HTTPS vhost.
    # --resolve bypasses DNS so we hit 127.0.0.1 directly. -k skips TLS cert check.
    curl -k -s -m 5 -o /dev/null \
        --resolve "${LUA_VHOST}:443:127.0.0.1" \
        "https://${LUA_VHOST}/.env" 2>/dev/null || true
    sleep 1
    curl -k -s -m 5 -o /dev/null \
        --resolve "${LUA_VHOST}:443:127.0.0.1" \
        "https://${LUA_VHOST}/.env" 2>/dev/null || true
    sleep 2

    dropped_after=$(get_counter ".ipc.dropped_events")
    honeypot_after=$(get_counter ".heuristics.honeypot_hits")

    TOTAL=$((TOTAL+1))
    if [ "$honeypot_after" -gt "$honeypot_before" ] 2>/dev/null; then
        info "honeypot_hits: $honeypot_before → $honeypot_after (events.write was called)"
        assert_counter_increased "dropped_events incremented after events flood" \
            "$dropped_before" "$dropped_after"
    else
        fail "events.write not triggered (honeypot_hits unchanged: ${honeypot_before})"
        info "  Try: curl -k --resolve ${LUA_VHOST}:443:127.0.0.1 https://${LUA_VHOST}/.env"
    fi

    # Restore events file
    if [ -f "${EVENTS_FILE}.chaos_backup" ]; then
        sudo mv "${EVENTS_FILE}.chaos_backup" "$EVENTS_FILE"
    else
        sudo rm -f "$EVENTS_FILE"
    fi
fi

restore_sync_file; backup_sync_file
sleep 2

# ─────────────────────────────────────────────────────────────────────────────
# TEST 4 — Python meta propagation: write bans.json with meta.cycle_count = 9999
# Expected: /crowdsec-status shows python.cycle_count = 9999
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "── Test 4: Python meta section → Lua metrics ───────────────────────────"

TOTAL=$((TOTAL+1))
# Use CURRENT_VERSION + 1 so that after restore (CURRENT_VERSION),
# Python's next push (CURRENT_VERSION+2) is accepted normally.
# Using large offsets raises last_version and blocks Python for hundreds of cycles.
NOW_EPOCH=$(date +%s)
NEW_VER=$(( CURRENT_VERSION + 1 ))

python3 - "$SYNC_FILE" "$NEW_VER" "$NOW_EPOCH" <<'PYEOF'
import json, os, sys, tempfile
dest, ver, epoch = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
payload = {
    "version": ver,
    "updated_at_epoch": epoch,
    "updated_at": "chaos-test",
    "entry_count": 0,
    "writer_pid": os.getpid(),
    "writer_hostname": "chaos-test",
    "bans": {},
    "cidrs": {},
    "meta": {
        "cycle_count": 9999,
        "cf_api_errors": 42,
        "wal_entries": 7,
        "lua_sync_errors": 0,
        "degraded": False,
    }
}
d = os.path.dirname(dest)
tmp_fd, tmp_path = tempfile.mkstemp(dir=d, suffix=".tmp")
os.fchmod(tmp_fd, 0o644)
with os.fdopen(tmp_fd, "w") as f:
    json.dump(payload, f)
os.replace(tmp_path, dest)
PYEOF

sleep $SYNC_INTERVAL

cycle=$(get_counter ".python.cycle_count")
cf_err=$(get_counter ".python.cf_api_errors")

if [ "$cycle" -eq 9999 ] 2>/dev/null && [ "$cf_err" -eq 42 ] 2>/dev/null; then
    pass "python.cycle_count=9999 and python.cf_api_errors=42 visible in Lua metrics"
else
    fail "python meta not propagated (cycle_count=$cycle, cf_api_errors=$cf_err, expected 9999/42)"
fi

restore_sync_file
sleep 2

# ─────────────────────────────────────────────────────────────────────────────
# TEST 5 — Memory pressure flag: verify sync.lua sets memory_pressure state key
#           (non-destructive — just reads current state, can't easily simulate
#            50 MB dict fill without real traffic; verify flag mechanics instead)
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "── Test 5: Memory pressure state key exists ────────────────────────────"
TOTAL=$((TOTAL+1))

pressure_events=$(get_counter ".memory.pressure_events_total")
cache_free=$(curl -s "$STATUS_URL" 2>/dev/null | \
    python3 -c "import sys,json; d=json.load(sys.stdin); print(d['memory']['cache_free_bytes'] or 0)")

# The pressure flag key exists in state dict (value 0 = no pressure in healthy state)
status_json=$(curl -s "$STATUS_URL")
has_pressure=$(echo "$status_json" | python3 -c "
import sys,json
d=json.load(sys.stdin)
v = d.get('memory',{}).get('pressure_active')
print('present' if v is not None else 'missing')
")

if [ "$has_pressure" = "present" ]; then
    pass "memory_pressure_active field present in /crowdsec-status"
    info "cache_free_bytes=${cache_free}, pressure_events_total=${pressure_events}"
else
    fail "memory_pressure_active field missing from /crowdsec-status"
fi

# ── Final report ──────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════════════════════════════"
echo " Results: $((TOTAL - ERRORS))/${TOTAL} passed  (${SKIPPED} skipped)"
[ "$ERRORS" -gt 0 ] && echo -e " ${RED}${ERRORS} test(s) FAILED${RESET}"
echo "══════════════════════════════════════════════════════════════════════════"

[ "$ERRORS" -gt 0 ] && exit 1
exit 0
