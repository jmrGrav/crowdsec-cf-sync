#!/bin/bash
# test-lua-unit.sh — Validate Lua modules with resty CLI (no nginx needed)
# Requires: openresty package (resty CLI available)
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
LUA_PATH="$REPO/lua/?.lua;;"
ERRORS=0

run_test() {
    local name="$1"
    local script="$2"
    if LUA_PATH="$LUA_PATH" resty --http-conf 'lua_shared_dict crowdsec_cache 1m; lua_shared_dict crowdsec_metrics 1m; lua_shared_dict crowdsec_state 1m;' \
        -e "$script" 2>&1 | grep -q "PASS"; then
        echo "  PASS  $name"
    else
        echo "  FAIL  $name"
        ERRORS=$((ERRORS + 1))
        LUA_PATH="$LUA_PATH" resty -e "$script" 2>&1 || true
    fi
}

echo "=== CrowdSec Lua unit tests ==="

# Test 1: init module loads
run_test "init: module loads" '
    local cs = require "crowdsec.init"
    assert(cs.LEVEL_DENY == 5, "LEVEL_DENY mismatch")
    assert(cs.score_to_level(100) == 5, "score_to_level(100)")
    assert(cs.score_to_level(50) == 2, "score_to_level(50)")
    assert(cs.score_to_level(15) == 1, "score_to_level(15)")
    assert(cs.score_to_level(0) == 0, "score_to_level(0)")
    print("PASS")
'

# Test 2: encode/decode round-trip
run_test "init: encode/decode verdict" '
    local cs = require "crowdsec.init"
    local enc = cs.encode_verdict(5, 90, "p")
    assert(enc == "5:90:p", "encode mismatch: " .. enc)
    local dec = cs.decode_verdict(enc)
    assert(dec.level == 5, "level")
    assert(dec.score == 90, "score")
    assert(dec.source == "p", "source")
    -- backward compat: no source
    local dec2 = cs.decode_verdict("3:60")
    assert(dec2.level == 3)
    print("PASS")
'

# Test 3: lookup — CIDR prefix extractors (via sync key format)
run_test "lookup: prefix24/prefix16 via cache keys" '
    local cs = require "crowdsec.init"
    -- Simulate what sync.lua writes
    local cache = cs.cache
    cache:set("cidr24:1.2.3", "5:100:p", 60)
    cache:set("ip:4.5.6.7", "1:20:h", 60)
    local lookup = require "crowdsec.lookup"
    local v1 = lookup.get_verdict("1.2.3.99")
    assert(v1 and v1.level == 5, "cidr24 miss")
    local v2 = lookup.get_verdict("4.5.6.7")
    assert(v2 and v2.score == 20, "exact miss")
    local v3 = lookup.get_verdict("9.9.9.9")
    assert(v3 == nil, "should miss")
    print("PASS")
'

# Test 4: heuristic scoring (path detection)
run_test "heuristics: path scoring" '
    local h = require "crowdsec.heuristics"
    assert(h.is_honeypot("/.env"), "/.env not honeypot")
    assert(h.is_honeypot("/.git/config"), ".git/config not honeypot")
    assert(not h.is_honeypot("/robots.txt"), "/robots.txt is honeypot?")
    print("PASS")
'

# Test 5: tarpit concurrency bound
run_test "tarpit: concurrency limit respected" '
    local cs = require "crowdsec.init"
    -- Manually set tarpit_active to MAX
    cs.state:set("tarpit_active", cs.MAX_TARPITS, 0)
    local tarpit = require "crowdsec.tarpit"
    -- Override sleep to avoid actual waiting
    ngx.sleep = function(n) end
    local result = tarpit.sleep("1.2.3.4")
    assert(result == false, "should have been skipped when at max")
    local skipped = cs.metrics:get("tarpit_skipped") or 0
    assert(skipped >= 1, "tarpit_skipped counter not incremented")
    print("PASS")
'

echo ""
if [ $ERRORS -eq 0 ]; then
    echo "All tests PASSED"
else
    echo "$ERRORS test(s) FAILED"
    exit 1
fi
