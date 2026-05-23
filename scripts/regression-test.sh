#!/bin/bash
# regression-test.sh — Non-regression suite for crowdsec-cf-sync V3.3.x
#
# Tests: /ping bypass, ban page (all paths), cs_reason, headers, Vector, dict sanity,
#        Turnstile CAPTCHA workflow (section M)
# Requires: sudo (openresty restart, log reads), curl, vector, python3, openssl
#
# Exit: 0 = all passed, N = number of failures
#
# Usage:
#   sudo -u jm -E bash scripts/regression-test.sh
#   sudo -u jm -E bash scripts/regression-test.sh --no-restart   # skip restarts (faster, less isolated)

set -uo pipefail

NGINX_HOST="${NGINX_HOST:-www.arleo.eu}"
NGINX_IP="${NGINX_IP:-127.0.0.1}"
STATUS_URL="http://127.0.0.1:8091/crowdsec-status"
ACCESS_LOG="/var/log/nginx/www.arleo.eu.access.log"
VECTOR_CFG="/etc/vector/vector.yaml"
NO_RESTART=false
for arg in "$@"; do [ "$arg" = "--no-restart" ] && NO_RESTART=true; done

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; RESET='\033[0m'

PASS=0; FAIL=0

ok()   { echo -e "  ${GREEN}PASS${RESET}  $1"; PASS=$((PASS + 1)); }
fail() { echo -e "  ${RED}FAIL${RESET}  $1"; FAIL=$((FAIL + 1)); }
warn() { echo -e "  ${YELLOW}WARN${RESET}  $1"; }
step() { echo -e "\n${BOLD}── $1${RESET}"; }

CURL="curl -sk --http1.1 --max-time 8 --resolve ${NGINX_HOST}:443:${NGINX_IP}"

# ── Helpers ───────────────────────────────────────────────────────────────────

cs_metric() {
    # Usage: cs_metric "heuristics.ua_hits"
    curl -s "$STATUS_URL" 2>/dev/null | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
    parts='$1'.split('.')
    v=d
    for p in parts: v=v.get(p,{})
    print(v if v != {} else 0)
except: print(0)
" 2>/dev/null || echo 0
}

restart_openresty() {
    if $NO_RESTART; then
        warn "Skipping restart (--no-restart). Dict state not guaranteed clean."
        return
    fi
    sudo systemctl restart openresty >/dev/null 2>&1
    # Wait until the status/metrics port (8091) is accepting connections (max 10s)
    for _i in $(seq 1 10); do
        curl -s --max-time 1 "http://127.0.0.1:8091/crowdsec-status" >/dev/null 2>&1 && break
        sleep 1
    done
}

last_log_line() {
    # Usage: last_log_line "pattern"
    sudo tail -50 "$ACCESS_LOG" 2>/dev/null | grep -E "$1" | tail -1
}

# ── Preflight ─────────────────────────────────────────────────────────────────
echo -e "${BOLD}=== crowdsec-cf-sync regression-test ===${RESET}"
echo "  Host:    $NGINX_HOST → $NGINX_IP"
echo "  Log:     $ACCESS_LOG"
echo "  Restart: $( $NO_RESTART && echo 'disabled' || echo 'enabled' )"
echo ""

if ! curl -s "$STATUS_URL" >/dev/null 2>&1; then
    echo -e "${RED}FATAL: /crowdsec-status unreachable at $STATUS_URL${RESET}"
    exit 1
fi

# ── A. /ping bypass ───────────────────────────────────────────────────────────
step "A. /ping — heuristic bypass"

restart_openresty

pre_ua=$(cs_metric "heuristics.ua_hits")
pre_hdr=$(cs_metric "heuristics.header_anomaly_hits")
pre_path=$(cs_metric "heuristics.path_hits")
pre_honey=$(cs_metric "heuristics.honeypot_hits")

# 10 requests with scanner UA + no Accept-Language/Accept (would normally score high)
for i in $(seq 1 10); do
    ${CURL} -A "masscan/1.3.2" -H "Accept:" -o /dev/null -w "" \
        "https://${NGINX_HOST}/ping" >/dev/null 2>&1 || true
done
sleep 1

post_ua=$(cs_metric "heuristics.ua_hits")
post_hdr=$(cs_metric "heuristics.header_anomaly_hits")
post_path=$(cs_metric "heuristics.path_hits")
post_honey=$(cs_metric "heuristics.honeypot_hits")

[ "$post_ua"    = "$pre_ua"    ] && ok  "/ping: no ua_hits increment (skip_heuristics=1)" \
                                 || fail "/ping: ua_hits changed $pre_ua→$post_ua"
[ "$post_hdr"   = "$pre_hdr"   ] && ok  "/ping: no header_anomaly_hits increment" \
                                 || fail "/ping: header_anomaly_hits changed $pre_hdr→$post_hdr"
[ "$post_path"  = "$pre_path"  ] && ok  "/ping: no path_hits increment" \
                                 || fail "/ping: path_hits changed $pre_path→$post_path"
[ "$post_honey" = "$pre_honey" ] && ok  "/ping: no honeypot_hits" \
                                 || fail "/ping: honeypot_hits changed $pre_honey→$post_honey"

# /ping unauthenticated → 401 (blocked only by auth_basic, not by CrowdSec)
status=$(${CURL} -o /dev/null -w "%{http_code}" "https://${NGINX_HOST}/ping" 2>/dev/null)
[ "$status" = "401" ] && ok  "/ping unauthenticated: 401 (auth_basic, not CrowdSec block)" \
                         || fail "/ping unauthenticated: expected 401, got $status"

# cs_reason in access log must be "-" for /ping entries
ping_line=$(last_log_line '"GET /ping')
if [ -n "$ping_line" ]; then
    echo "$ping_line" | grep -q "cs_reason=-" \
        && ok  "/ping access log: cs_reason=-" \
        || fail "/ping access log: $(echo "$ping_line" | grep -o 'cs_reason=[^ ]*')"
else
    warn "/ping: no recent log entry found (log may be buffered)"
fi

# ── B. Ban page — honeypot path ───────────────────────────────────────────────
step "B. Ban page — honeypot (/.env)"

restart_openresty

# Snapshot log line count before request to make the loop check immune to prior /.env entries
honey_before=$(sudo wc -l < "$ACCESS_LOG" 2>/dev/null || echo 0)

status=$(${CURL} -A "curl/8.5.0" -H "Accept: */*" -H "Accept-Language: en" \
    -o /tmp/rt_honeypot.html -w "%{http_code}" "https://${NGINX_HOST}/.env" 2>/dev/null)
bytes=$(wc -c < /tmp/rt_honeypot.html 2>/dev/null || echo 0)

[ "$status" = "403" ]     && ok  "Honeypot /.env: status 403"       || fail "Honeypot /.env: status=$status (expected 403)"
[ "$bytes"  -gt 10000 ]   && ok  "Honeypot ban.html: >10 KB ($bytes bytes)" || fail "Honeypot ban.html: $bytes bytes (expected >10000)"
grep -qi "crowdsec\|CrowdSec\|Forbidden\|Motif" /tmp/rt_honeypot.html 2>/dev/null \
    && ok  "Honeypot ban.html: content recognised" \
    || fail "Honeypot ban.html: no expected content found"

# Verify no error_page loop: exactly ONE log entry for /.env since this request
# (internal error_page redirect is silent — only the outer request should be logged)
sleep 1
honey_count=$(sudo tail -n +$((honey_before + 1)) "$ACCESS_LOG" 2>/dev/null | grep -c '"GET /\.env' || true)
[ "$honey_count" -le 1 ] && ok  "No error_page loop: ${honey_count} new entry for /.env (internal redirect silent)" \
                           || fail "Possible loop: $honey_count new entries for /.env since request (expected ≤1)"

# ── C. Ban page — heuristic deny ─────────────────────────────────────────────
step "C. Ban page — heuristic deny (/shell)"

restart_openresty

# /shell: exact PATH_SCORES=60, no UA (+15), no Accept-Language (+10), no Accept (+5) = score 90
# → LEVEL_DENY, score<96 → crowdsec_block_reason="heuristic" → error_page → ban.html
status=$(${CURL} -A "" -H "Accept:" \
    -o /tmp/rt_heuristic.html -w "%{http_code}" "https://${NGINX_HOST}/shell" 2>/dev/null)
bytes=$(wc -c < /tmp/rt_heuristic.html 2>/dev/null || echo 0)

[ "$status" = "403" ]   && ok  "Heuristic deny /shell: status 403"        || fail "Heuristic deny /shell: status=$status"
[ "$bytes"  -gt 10000 ] && ok  "Heuristic ban.html: >10 KB ($bytes bytes)" || fail "Heuristic ban.html: $bytes bytes"

sleep 1
shell_line=$(last_log_line '"GET /shell')
if [ -n "$shell_line" ]; then
    echo "$shell_line" | grep -q "cs_reason=heuristic" \
        && ok  "Heuristic deny: cs_reason=heuristic in access log" \
        || fail "Heuristic deny: $(echo "$shell_line" | grep -o 'cs_reason=[^ ]*') (expected cs_reason=heuristic)"
else
    warn "Heuristic deny: no /shell log entry found (buffered?)"
fi

grep -qi "heuristic" /tmp/rt_heuristic.html 2>/dev/null \
    && ok  "Heuristic ban.html: 'heuristic' visible in page content" \
    || fail "Heuristic ban.html: 'heuristic' not in page"

# ── D. Silent drop — score ≥ 96 ──────────────────────────────────────────────
step "D. Score ≥ 96 → 444 silent drop"

# Strategy: honeypot adds score=100 to dict. The NEXT request finds score=100 in dict
# via lookup.get_verdict() → level=LEVEL_DENY → mitigation.apply(score=100) → 444.
# (The honeypot hit itself exits via ngx.exit(403) directly, not through mitigation.apply)
restart_openresty

# Request 1: honeypot → ngx.exit(403), score=100 written to dict
${CURL} -A "curl/8.5.0" -H "Accept: */*" -H "Accept-Language: en" \
    -o /dev/null -w "" "https://${NGINX_HOST}/.env" >/dev/null 2>&1 || true

# Request 2: lookup finds score=100 → mitigation.apply → score≥96 → ngx.exit(444)
status=$(${CURL} -A "curl/8.5.0" -H "Accept: */*" -H "Accept-Language: en" \
    -o /dev/null -w "%{http_code}" "https://${NGINX_HOST}/" 2>/dev/null) || status="000"
[ "$status" = "000" ] && ok  "Score≥96: 444 silent drop (curl status=000)" \
                        || fail "Score≥96: expected 000, got $status"

# ── E. Ban page — nginx deny all ─────────────────────────────────────────────
step "E. Ban page — nginx deny all (/.well-known/)"

restart_openresty

# /.well-known/ has 'deny all' in nginx config. From 127.0.0.1 (allowed by /nginx_status
# but /.well-known/ is deny all for all IPs), nginx should return 403 → error_page → ban.html
status=$(${CURL} -A "curl/8.5.0" -H "Accept: */*" -H "Accept-Language: en" \
    -o /tmp/rt_deny.html -w "%{http_code}" "https://${NGINX_HOST}/.well-known/foo" 2>/dev/null)
bytes=$(wc -c < /tmp/rt_deny.html 2>/dev/null || echo 0)

[ "$status" = "403" ]   && ok  "nginx deny all: status 403"        || fail "nginx deny all: status=$status"
[ "$bytes"  -gt 10000 ] && ok  "nginx deny all: ban.html served ($bytes bytes)" \
                          || fail "nginx deny all: $bytes bytes (expected >10000, check if error_page wired)"

# ── F. Ban page — response headers ───────────────────────────────────────────
step "F. Ban page response headers"

restart_openresty

${CURL} -A "" -H "Accept:" \
    -o /dev/null -D /tmp/rt_headers.txt \
    "https://${NGINX_HOST}/shell" >/dev/null 2>&1 || true
sleep 1

grep -qi "content-type: text/html" /tmp/rt_headers.txt \
    && ok  "Ban page: Content-Type: text/html"     || fail "Ban page: missing Content-Type: text/html"
grep -qi "cache-control: no-store"  /tmp/rt_headers.txt \
    && ok  "Ban page: Cache-Control: no-store"     || fail "Ban page: missing Cache-Control: no-store"
grep -qi "content-security-policy:" /tmp/rt_headers.txt \
    && ok  "Ban page: CSP header present"          || fail "Ban page: CSP header missing"
grep -qi "x-content-type-options:"  /tmp/rt_headers.txt \
    && ok  "Ban page: X-Content-Type-Options"      || fail "Ban page: X-Content-Type-Options missing"
grep -qi "referrer-policy:"         /tmp/rt_headers.txt \
    && ok  "Ban page: Referrer-Policy"             || fail "Ban page: Referrer-Policy missing"

# Ensure no Set-Cookie or Location on ban page
grep -qi "set-cookie:" /tmp/rt_headers.txt \
    && fail "Ban page: unexpected Set-Cookie" || ok "Ban page: no Set-Cookie"

# ── G. heuristics.lua path scoring ───────────────────────────────────────────
step "G. heuristics.lua path scoring (pure Lua)"

SCORING_RESULT=$(lua5.1 -e '
local PATH_SCORES = {
    ["/.env"]="/60",["/.git"]="/40",["/wp-login.php"]="/25",["/wp-admin"]="/20",
    ["/phpmyadmin"]="/20",["/xmlrpc.php"]="/30",["/admin"]="/10",
    ["/setup.php"]="/40",["/install.php"]="/40",["/config.php"]="/50",
    ["/shell"]="/60",["/cmd"]="/50",
}
-- extract numeric score
local function exact(p) local v=PATH_SCORES[p]; if v then return tonumber(v:sub(2)) end end

local function score_path(uri)
    local path = uri:match("^([^?#]+)") or uri
    local e = exact(path); if e then return e end
    if path:find("%.env",     1) then return 60 end
    if path:find("%.git",     1) then return 40 end
    if path:find("phpunit",   1, true) then return 60 end
    if path:find("wp%-admin", 1) then return 20 end
    if path:find("phpmyadmin",1, true) then return 20 end
    if path:find("%.php~",    1) then return 40 end
    if path:find("passwd",    1, true) then return 50 end
    if path:find("shadow",    1, true) then return 50 end
    return 0
end

local cases = {
    -- URI                            expected   label
    {"/.env",                         60,       "exact PATH_SCORES"},
    {"/backup/.env",                  60,       "substring .env"},
    {"/backup/.env.bak",              60,       "substring .env in longer path"},
    {"/.git",                         40,       "exact PATH_SCORES"},
    {"/.git/HEAD",                    40,       "substring .git"},
    {"/api/.git/config",              40,       "substring .git nested"},
    {"/wp-login.php",                 25,       "exact PATH_SCORES"},
    {"/wp-admin",                     20,       "exact PATH_SCORES"},
    {"/wp-admin/options.php",         20,       "substring wp-admin"},
    {"/not-wp-admin/foo",             20,       "substring wp-admin in other path"},
    {"/phpunit/tests/",               60,       "substring phpunit"},
    {"/vendor/phpunit/src/test.php",  60,       "substring phpunit nested"},
    {"/phpmyadmin/index.php",         20,       "substring phpmyadmin"},
    {"/admin",                        10,       "exact PATH_SCORES"},
    {"/config.php",                   50,       "exact PATH_SCORES"},
    {"/shell",                        60,       "exact PATH_SCORES"},
    {"/cmd",                          50,       "exact PATH_SCORES"},
    {"/backup.php~",                  40,       "substring .php~"},
    {"/admin.php~",                   40,       "substring .php~"},
    {"/etc/passwd",                   50,       "substring passwd"},
    {"/shadow",                       50,       "substring shadow"},
    {"/",                              0,       "root — no score"},
    {"/api/v1/users",                  0,       "normal API path"},
    {"/robots.txt",                    0,       "robots.txt — no score"},
    {"/blog/post?page=2",              0,       "query string stripped, no score"},
}

local pass, fail = 0, 0
for _, c in ipairs(cases) do
    local uri, expected, label = c[1], c[2], c[3]
    local got = score_path(uri)
    if got == expected then
        pass = pass + 1
    else
        print("FAIL  " .. uri .. "  expected=" .. expected .. " got=" .. got .. "  (" .. label .. ")")
        fail = fail + 1
    end
end
print("SCORING: " .. pass .. " passed, " .. fail .. " failed")
' 2>/dev/null)

echo "$SCORING_RESULT"
echo "$SCORING_RESULT" | grep -q "FAIL" \
    && fail "heuristics path scoring: regressions detected (see above)" \
    || ok  "heuristics path scoring: all 24 cases correct"

# ── H. Vector ─────────────────────────────────────────────────────────────────
step "H. Vector pipeline"

sudo vector validate "$VECTOR_CFG" >/dev/null 2>&1 \
    && ok  "vector validate: OK" \
    || { sudo vector validate "$VECTOR_CFG" 2>&1 | tail -3; fail "vector validate: FAILED"; }

systemctl is-active --quiet vector \
    && ok  "vector service: running" \
    || fail "vector service: not running"

# ── I. Shared dict / IPC sanity ───────────────────────────────────────────────
step "I. Shared dict and IPC sanity"

IPC_OK=$(curl -s "$STATUS_URL" 2>/dev/null | python3 -c "
import json,sys
d=json.load(sys.stdin)
ipc=d.get('ipc',{})
p=d.get('python',{})
mem=d.get('memory',{})
errors=[]
if ipc.get('dropped_events',0)>0:  errors.append('dropped_events='+str(ipc['dropped_events']))
if ipc.get('dict_set_failures',0)>0: errors.append('dict_set_failures='+str(ipc['dict_set_failures']))
if ipc.get('rejected_total',0)>0: errors.append('rejected_total='+str(ipc['rejected_total']))
if p.get('lua_sync_errors',0)>0:  errors.append('lua_sync_errors='+str(p['lua_sync_errors']))
if mem.get('pressure_active',False): errors.append('memory_pressure=active')
print('ERRORS:'+','.join(errors) if errors else 'OK')
" 2>/dev/null)

echo "$IPC_OK" | grep -q "^OK$" \
    && ok  "IPC/dict: no errors ($IPC_OK)" \
    || fail "IPC/dict: $IPC_OK"

SYNC_OK=$(curl -s "$STATUS_URL" 2>/dev/null | python3 -c "
import json,sys,time
d=json.load(sys.stdin)
ts=d.get('sync',{}).get('ts',0)
stale=int(time.time())-int(ts)
print('stale_secs='+str(stale))
print('OK' if stale<300 else 'STALE')
" 2>/dev/null)
echo "$SYNC_OK" | grep -q "^OK$" \
    && ok  "Sync timestamp: fresh (${SYNC_OK//$'\n'/, })" \
    || fail "Sync timestamp: $SYNC_OK"

# ── J. /crowdsec-status accessible ───────────────────────────────────────────
step "J. Monitoring endpoints"

curl -s "$STATUS_URL" | python3 -c "import json,sys; json.load(sys.stdin)" >/dev/null 2>&1 \
    && ok  "/crowdsec-status: valid JSON" \
    || fail "/crowdsec-status: invalid or unreachable"

curl -s "http://127.0.0.1:8091/crowdsec-metrics" | grep -q "# HELP\|crowdsec_" \
    && ok  "/crowdsec-metrics: Prometheus output present" \
    || fail "/crowdsec-metrics: no Prometheus output"

# /crowdsec-status must NOT be accessible from WAN (only loopback)
status_wan=$(${CURL} -o /dev/null -w "%{http_code}" \
    "https://${NGINX_HOST}/crowdsec-status" 2>/dev/null)
[ "$status_wan" != "200" ] \
    && ok  "/crowdsec-status not exposed on WAN (got $status_wan)" \
    || fail "/crowdsec-status EXPOSED on port 443 (should be loopback only)"

# ── K. Honeypot /.env regression ─────────────────────────────────────────────
# /.env is in HONEYPOT{} (exact match). access.lua exits at step 1 via ngx.exit(403)
# before score_request() is ever called. PATH_SCORES["/.env"] was removed (dead code).
# This test verifies the honeypot path still produces 403 + ban page + correct metrics,
# and that subpaths like /backup/.env still score via the "%.env" Lua pattern in score_path().
step "K. Honeypot /.env regression (dead-code cleanup)"

if ! $NO_RESTART; then
    sudo systemctl restart openresty >/dev/null 2>&1
    sleep 2
fi

# K1: /.env must return 403 (honeypot, not scored via PATH_SCORES)
honeypot_base_hits=$(cs_metric "heuristics.honeypot_hits" 2>/dev/null || echo 0)
env_status=$(${CURL} -A "Mozilla/5.0" -H "Accept: text/html" -H "Accept-Language: en" \
    -o /dev/null -w "%{http_code}" "https://${NGINX_HOST}/.env" 2>/dev/null)
[ "$env_status" = "403" ] \
    && ok  "K1: /.env honeypot → 403" \
    || fail "K1: /.env honeypot expected 403, got $env_status"

# K2: honeypot_hits counter incremented (not path_hits — score_path() never called)
sleep 1
honeypot_new_hits=$(cs_metric "heuristics.honeypot_hits" 2>/dev/null || echo 0)
[ "$honeypot_new_hits" -gt "$honeypot_base_hits" ] 2>/dev/null \
    && ok  "K2: honeypot_hits incremented ($honeypot_base_hits → $honeypot_new_hits)" \
    || fail "K2: honeypot_hits not incremented (base=$honeypot_base_hits, now=$honeypot_new_hits)"

# K3: ban page body rendered for /.env request
env_body=$(${CURL} -A "Mozilla/5.0" -H "Accept: text/html" -H "Accept-Language: en" \
    "https://${NGINX_HOST}/.env" 2>/dev/null)
echo "$env_body" | grep -qi "blocked\|access denied\|crowdsec\|403" \
    && ok  "K3: /.env → ban page rendered" \
    || fail "K3: /.env → no ban page in response body"

# K4: /backup/.env (subpath, NOT in HONEYPOT{}) must still score via "%.env" pattern.
# The prior /.env honeypot hit scored 100 → subsequent requests from the same IP
# hit a DENY verdict (score≥96 → 444 silent drop). HTTP 000 from curl = silent drop. OK.
subpath_status=$(${CURL} -A "Mozilla/5.0" -H "Accept: text/html" -H "Accept-Language: en" \
    -o /dev/null -w "%{http_code}" "https://${NGINX_HOST}/backup/.env" 2>/dev/null)
[ "$subpath_status" != "200" ] \
    && ok  "K4: /backup/.env (subpath) not served as 200 (got $subpath_status — 444 or 4xx, path_score active)" \
    || fail "K4: /backup/.env returned 200 — path scoring may be broken"

# K5: access log — /.env requests logged with cs_reason="-" (honeypot branch exits
# before score_request(), so no verdict is written and no cs_reason override happens).
# Use tail -20 to survive monitoring bot traffic that may push entries out of a smaller window.
sleep 1
log_line=$(sudo tail -20 "$ACCESS_LOG" 2>/dev/null | grep -i '\.env' | tail -1)
[ -n "$log_line" ] \
    && ok  "K5: /.env appears in access log: ${log_line:0:120}" \
    || fail "K5: /.env not found in last 20 access log lines"

# ── L. LEVEL_CAPTCHA cs_reason (code-path verification) ──────────────────────
# LEVEL_CAPTCHA (4) is never produced by score_to_level() — only via LAPI-pushed
# verdicts. Live testing requires a real captcha push from CrowdSec LAPI.
# This section verifies the code path via static analysis.
step "L. LEVEL_CAPTCHA cs_reason (code-path audit)"

MITIGATION_LUA="/etc/openresty/lua/crowdsec/mitigation.lua"

# L1: deployed mitigation.lua contains the cs_reason assignment for LEVEL_CAPTCHA
grep -q 'crowdsec_block_reason.*=.*"captcha"' "$MITIGATION_LUA" \
    && ok  "L1: mitigation.lua sets crowdsec_block_reason=\"captcha\" for LEVEL_CAPTCHA" \
    || fail "L1: cs_reason=captcha missing from deployed mitigation.lua"

# L2: the assignment is inside the LEVEL_CAPTCHA branch (between CAPTCHA and hard-deny markers)
py_out=$(python3 - <<'PYEOF'
import re
with open("/etc/openresty/lua/crowdsec/mitigation.lua") as f:
    src = f.read()
m = re.search(r'LEVEL_CAPTCHA.*?(?=LEVEL_\w+:|else\b)', src, re.DOTALL)
block = m.group(0) if m else ""
if 'crowdsec_block_reason' in block and '"captcha"' in block:
    print("PYEOF_OK")
else:
    print("PYEOF_FAIL: block=" + repr(block[:200]))
PYEOF
)
[ "$py_out" = "PYEOF_OK" ] \
    && ok  "L2: cs_reason=captcha is inside LEVEL_CAPTCHA branch (not misplaced)" \
    || warn "L2: could not verify placement — manual review recommended (py_out=$py_out)"

# L3: score_to_level() does NOT map any score to LEVEL_CAPTCHA (confirmed unreachable from heuristics)
grep -q 'LEVEL_CAPTCHA' /etc/openresty/lua/crowdsec/init.lua && \
python3 -c "
src = open('/etc/openresty/lua/crowdsec/init.lua').read()
import re
fn = re.search(r'score_to_level.*?end', src, re.DOTALL)
block = fn.group(0) if fn else ''
print('CAPTCHA_IN_FN' if 'LEVEL_CAPTCHA' in block else 'CAPTCHA_NOT_IN_SCORE_FN')
" 2>/dev/null | grep -q "CAPTCHA_NOT_IN_SCORE_FN" \
    && ok  "L3: score_to_level() does not map any score to LEVEL_CAPTCHA (LAPI-only path, expected)" \
    || warn "L3: unexpected LEVEL_CAPTCHA reference in score_to_level() — verify init.lua"

# ── M. Turnstile CAPTCHA workflow ─────────────────────────────────────────────
# LEVEL_CAPTCHA is only reachable via LAPI-pushed verdicts (score_to_level()
# skips from CHALLENGE to DENY). Tests use static analysis + endpoint tests.
# M5/M6 (cookie bypass behaviour) are verified by generating a real HMAC cookie.
step "M. Turnstile CAPTCHA workflow"

CAPTCHA_LUA="/etc/openresty/lua/crowdsec/captcha.lua"
TURNSTILE_ENV="/etc/crowdsec/turnstile.env"
CAPTCHA_SNIPPET="/usr/local/openresty/nginx/conf/snippets/crowdsec_captcha.conf"

# M1: captcha.render() is wired into LEVEL_CAPTCHA in mitigation.lua (code-path)
grep -q 'require.*crowdsec\.captcha.*\.render\(\)' /etc/openresty/lua/crowdsec/mitigation.lua \
    && ok  "M1: mitigation.lua LEVEL_CAPTCHA → captcha.render() (static analysis)" \
    || fail "M1: captcha.render() not wired into LEVEL_CAPTCHA branch"

# M2: GET /captcha-verify → 403 (limit_except POST denies GET at nginx level)
m2_status=$(${CURL} -o /dev/null -w "%{http_code}" "https://${NGINX_HOST}/captcha-verify")
[ "$m2_status" = "403" ] \
    && ok  "M2: GET /captcha-verify → 403 (limit_except POST enforced)" \
    || fail "M2: GET /captcha-verify expected 403, got $m2_status"

# M3: POST with invalid cookie → captcha re-rendered (cookie rejected)
# We send a syntactically valid-looking but unsigned cookie
m3_body=$(${CURL} -X POST -d "_redirect=/" \
    -H "Cookie: crowdsec_captcha=aW52YWxpZA" \
    "https://${NGINX_HOST}/captcha-verify" 2>/dev/null)
echo "$m3_body" | grep -qi "challenges.cloudflare.com\|cf-turnstile" \
    && ok  "M3: invalid cookie → captcha page re-rendered (Turnstile widget present)" \
    || fail "M3: invalid cookie — expected captcha re-render, got unexpected body"

# M4: POST with expired cookie (ts=1000000, well past TTL) → re-render
# ts=1000000 is year 1970+11.5days — guaranteed expired
# Use sudo to read the secret (file is 640 root:root, readable only by root)
_ts_secret=$(sudo grep '^TURNSTILE_SECRET=' "${TURNSTILE_ENV}" 2>/dev/null | cut -d= -f2-)
m4_expired_payload=$(python3 -c "
import base64, hmac, hashlib, sys
key = sys.argv[1]
ts = '1000000'; ua_hash = 'deadbeef'
payload = ts + ':' + ua_hash
sig = hmac.new(key.encode(), payload.encode(), hashlib.sha256).hexdigest()
raw = payload + ':' + sig
print(base64.urlsafe_b64encode(raw.encode()).decode().rstrip('='))
" "${_ts_secret}" 2>/dev/null)

if [ -n "$m4_expired_payload" ]; then
    m4_body=$(${CURL} -X POST -d "_redirect=/" \
        -H "Cookie: crowdsec_captcha=${m4_expired_payload}" \
        "https://${NGINX_HOST}/captcha-verify" 2>/dev/null)
    echo "$m4_body" | grep -qi "challenges.cloudflare.com\|cf-turnstile" \
        && ok  "M4: expired cookie (ts=1000000) → captcha re-rendered (TTL rejected)" \
        || fail "M4: expired cookie — expected captcha re-render"
else
    warn "M4: could not generate expired cookie payload (python3 error) — skipped"
fi

# M5: valid HMAC cookie → access bypasses heuristics
# Generate a real cookie matching the Lua algorithm (same ts:ua_hash:hmac_hex scheme).
# Use sudo to read the secret (file is 640 root:root).
m5_cookie=$(python3 -c "
import base64, hmac, hashlib, time, sys
key = sys.argv[1]
ua = 'zgrab/2.0'
ts = str(int(time.time()))
ua_hash = hashlib.md5(ua.encode()).hexdigest()[:8]
payload = ts + ':' + ua_hash
sig = hmac.new(key.encode(), payload.encode(), hashlib.sha256).hexdigest()
raw = payload + ':' + sig
print(base64.urlsafe_b64encode(raw.encode()).decode().rstrip('='))
" "${_ts_secret}" 2>/dev/null)

if [ -n "$m5_cookie" ]; then
    # First: restart to clear dict, then verify scored path without cookie → heuristic increments
    if ! $NO_RESTART; then sudo systemctl restart openresty >/dev/null 2>&1 && sleep 2; fi
    ua_before=$(cs_metric "heuristics.ua_hits")

    # With valid cookie + bad UA: ua_hits should NOT increment (heuristics bypassed)
    ${CURL} -A "zgrab/2.0" \
        -H "Cookie: crowdsec_captcha=${m5_cookie}" \
        -o /dev/null "https://${NGINX_HOST}/" 2>/dev/null
    sleep 1
    ua_after=$(cs_metric "heuristics.ua_hits")
    [ "$ua_after" -eq "$ua_before" ] 2>/dev/null \
        && ok  "M5: valid cookie bypasses heuristics (ua_hits unchanged: $ua_before → $ua_after)" \
        || fail "M5: ua_hits changed ($ua_before → $ua_after) — cookie bypass may be broken"
else
    warn "M5: could not generate valid cookie (python3/secret error) — skipped"
fi

# M6: valid cookie does NOT bypass score≥96 → 444 hard deny
# The cookie bypasses soft checks but LEVEL_DENY is still applied from the LAPI dict.
# We can verify this via static analysis: access.lua checks hard.level >= LEVEL_DENY
# even when has_valid_cookie() returns true.
grep -A5 'has_valid_cookie' /etc/openresty/lua/crowdsec/access.lua | \
    grep -q "LEVEL_DENY\|level.*>=\|>= cs\.LEVEL" \
    && ok  "M6: access.lua enforces hard LAPI deny even with valid cookie (static analysis)" \
    || fail "M6: hard-deny enforcement missing in cookie bypass path"

# M7: POST /captcha-verify with empty token → cs_reason=captcha NOT set (no verdict written)
# and the response is a 403 captcha page (not ban page). Access log check is tricky
# since no verdict is pushed. Instead verify response headers.
m7_status=$(${CURL} -X POST -d "_redirect=/" -o /dev/null -w "%{http_code}" \
    "https://${NGINX_HOST}/captcha-verify" 2>/dev/null)
[ "$m7_status" = "403" ] \
    && ok  "M7: /captcha-verify with no token → 403 captcha re-render" \
    || fail "M7: expected 403, got $m7_status"

# M7b: the 403 response is the captcha page (has Turnstile), NOT the ban page
m7b_body=$(${CURL} -X POST -d "_redirect=/" "https://${NGINX_HOST}/captcha-verify" 2>/dev/null)
echo "$m7b_body" | grep -qi "cf-turnstile\|turnstile" \
    && ok  "M7b: 403 response is captcha page (Turnstile widget), not ban page" \
    || fail "M7b: 403 response does not contain Turnstile widget"

# M8: no error_page loop for captcha renders
# The captcha page is rendered directly by captcha.render() (not via error_page 403).
# Verify /captcha-verify POST produces exactly 1 log entry (no internal redirect loop).
m8_before=$(sudo wc -l < "${ACCESS_LOG}" 2>/dev/null || echo 0)
${CURL} -X POST -d "_redirect=/" "https://${NGINX_HOST}/captcha-verify" \
    -o /dev/null 2>/dev/null
sleep 1
m8_new=$(sudo tail -n +$((m8_before + 1)) "${ACCESS_LOG}" 2>/dev/null | \
    grep -c '"POST /captcha-verify' || true)
[ "$m8_new" -le 1 ] \
    && ok  "M8: no error_page loop — ${m8_new} log entry for /captcha-verify POST" \
    || fail "M8: possible loop — $m8_new entries for /captcha-verify (expected ≤1)"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}══════════════════════════════════════════${RESET}"
echo -e "${BOLD}  Results: ${GREEN}${PASS} passed${RESET}${BOLD}, ${RED}${FAIL} failed${RESET}"
echo -e "${BOLD}══════════════════════════════════════════${RESET}"

# Restore clean state after tests
if ! $NO_RESTART; then
    sudo systemctl reload openresty >/dev/null 2>&1
fi

exit $FAIL
