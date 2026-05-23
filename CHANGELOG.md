# Changelog

All notable changes to this project will be documented in this file.

## [3.5.0] - 2026-05-23

### Summary

In-band AppSec fusion: CrowdSec Coraza/CRS (AppSec) signal integrated as a score
contributor into the Lua behavioral engine. `final_score = lua_score + appsec_delta`;
AppSec becomes a high-quality signal provider while the Lua engine remains the
decision layer. CAPTCHA challenge preserved as the default escalation for borderline
IPs (40–69); AppSec WAF matches (70 pts) push directly to LEVEL_DENY.

Also fixes a critical `ngx.hmac_sha256` nil error in `captcha.lua` (removed in
OpenResty ≥ 1.19.9) that caused the entire `check()` pcall to fail-open, silently
bypassing all CrowdSec checks for every request.

### Added

- **`init.lua` — V3.5.0 AppSec fusion constants**:
  - `APPSEC_SCORE = 70` — score added when Coraza/CRS confirms a WAF match; 70 puts
    the IP squarely in LEVEL_DENY territory (score ≥ 70).
  - `RECIDIVE_BONUS_PCT = 25` — % boost applied to any heuristic delta when the IP
    already has a score in the shared dict (recidivists escalate faster).

- **`lookup.lua` — recidive bonus in `add_heuristic_score()`**: if `cur.source == "h"`,
  the incoming delta is multiplied by `1 + RECIDIVE_BONUS_PCT/100` (ceil). Applied to
  both AppSec and behavioral heuristic deltas.

- **`access.lua` — step 3b: in-band AppSec check** (`$crowdsec_appsec_fusion = 1`):
  - Calls `cs_official.AppSecCheck(ip)` directly (one HTTP round-trip to 127.0.0.1:7422,
    ~1-3ms). Returns ok=false → appsec_delta = APPSEC_SCORE (70).
  - Score persisted to shared dict BEFORE behavioral heuristics (step 4) so the
    recidive_bonus logic in `add_heuristic_score()` sees it.
  - Under memory pressure: AppSec verdict applied inline (no dict write), avoids OOM.
  - Enabled per-vhost: `set $crowdsec_appsec_fusion 1;` + `set $crowdsec_disable_appsec 1;`
    (the `disable_appsec` flag prevents cs.Allow() from making a redundant second
    AppSec call).
  - Guard: pcall on `ngx.var.crowdsec_appsec_fusion` prevents "variable not found"
    errors in vhosts that do not declare it.

- **`captcha.lua` — gsub replacement fix**: `render()` now uses function-form gsub
  (`function() return val end`) instead of string replacement for `__SITEKEY__` and
  `__REDIRECT__`. Prevents `invalid capture index` runtime error when redirect URL
  contains `%XX` percent-encoded sequences (e.g. XSS payloads in the original URI).

### Fixed

- **`captcha.lua` — `ngx.hmac_sha256` nil dereference (critical)**:
  - OpenResty ≥ 1.19.9 removed `ngx.hmac_sha256`. Calling it returned nil, causing
    `attempt to call field 'hmac_sha256' (a nil value)` inside `sign()`.
  - The error propagated to `check()` via pcall, causing ALL requests to fail-open
    (silent bypass of honeypot, heuristics, verdict enforcement).
  - Fix: lazy `_hmac_fn` initializer checks `ngx.hmac_sha256` first; if nil, falls back
    to `resty.openssl.hmac` (HMAC-SHA256 via OpenSSL FFI). Backward-compatible.

### Security invariants preserved

- LAPI-pushed verdicts (source="p") are never downgraded by AppSec score.
- AppSec check gated on `not skip_heuristics` — monitoring paths unaffected.
- Stale mode (deadman): AppSec score IS persisted (Coraza/CRS is always fresh); soft
  verdicts below LEVEL_DENY are still suspended in stale mode.
- Fail-open pcall wrapper in `check()` ensures any AppSec error passes the request
  rather than hard-faulting nginx.
- Cookie bypass still enforces hard LAPI denies (LEVEL_DENY+) even when AppSec enabled.

## [3.4.1] - 2026-05-23

### Summary

Challenge-first mitigation strategy with full false-positive correction. Rewrites the
score→level mapping so heuristics can now produce Turnstile CAPTCHA challenges directly.
Fixes a header-parsing bug that caused every request to score +30 above intended values,
and fixes the CAPTCHA response architecture so Turnstile renders correctly from any path
(not only from `/captcha-verify`).

GoTestWAF grade target: eliminate the Application Security false-positive wall (was F/0%
true-negatives) by fixing the raw header bug. API Security grade unchanged (A+).

### Changed

- **`init.lua` — `score_to_level()` — challenge-first strategy**:
  - Old: `0→allow, 1+→ratelimit, 31+→tarpit, 61+→challenge, 81+→deny(403), 96+→deny(444)`
  - New: `0–39→allow, 40–69→captcha, 70–89→deny(403), 90+→deny(444)`
  - `LEVEL_RATELIMIT (1)`, `LEVEL_TARPIT (2)`, `LEVEL_CHALLENGE (3)` remain defined but are
    no longer emitted by `score_to_level()`; still valid for LAPI-pushed verdicts.

- **`mitigation.lua` — 444 threshold lowered** from score ≥ 96 to score ≥ 90 (aligns with
  new mapping); LEVEL_CAPTCHA branch redesigned — see Bug Fix 2 below.

- **Regression tests** (58 total, up from 47):
  - Section L updated: L3 now asserts LEVEL_CAPTCHA IS in `score_to_level()` (expected).
  - Section M updated: M1/M1b verify new CAPTCHA architecture (content-phase render).
  - Section N (9 tests) — thresholds: N.A allow, N.B captcha+Turnstile, N.C deny-soft,
    N.D deny-hard, N.E cookie-bypass LEVEL_DENY+ guard.

### Fixed

- **Bug 1 — `access.lua`: `ngx.req.get_headers(50, true)` raw=true** — the `raw=true`
  parameter preserves original header casing (`User-Agent`, `Accept-Language`, `Accept`)
  but all downstream lookups used lowercase keys (`user-agent`, `accept-language`,
  `accept`), causing every key lookup to return nil. Effect: every request scored +30
  extra from headers/UA regardless of what was sent, inflating all scores by 30 points.
  A browser with full headers would score as high as a scanner with no headers.
  - Fix: `ngx.req.get_headers(50)` — default lowercase mode; header lookups now work
    as intended.
  - Impact: real browsers with Accept-Language and Accept headers correctly score 0 for
    those signals; bad UAs (zgrab, masscan) correctly score 30; curl's User-Agent scores 0.
  - Scores: `/shell` + curl = 70 (was 90 → DENY hard); `/config.php` + browser = 60
    (was 90 → CAPTCHA); `/setup.php` + browser = 50 (was 80 → CAPTCHA).

- **Bug 2 — CAPTCHA render from access phase (error_page override)**: `captcha.render()`
  called from `access_by_lua_block` calls `ngx.say(turnstile_html)` then `ngx.exit(403)`.
  In the access phase, `ngx.exit(403)` triggers `error_page 403 /crowdsec-ban-page`, which
  replaces the Turnstile HTML with the ban page before the response is sent.
  - Fix: LEVEL_CAPTCHA in `mitigation.lua` now sets `crowdsec_block_reason = "captcha"` and
    calls `ngx.exit(403)` directly — no `captcha.render()` in access phase.
  - `snippets/crowdsec_ban_page.conf` content handler checks `crowdsec_block_reason`:
    if `"captcha"`, calls `captcha.render()` from content phase (where `ngx.say()` output
    is sent before `ngx.exit(403)` fires, preventing a second error_page redirect).
  - Result: Turnstile challenge page served correctly for heuristic CAPTCHA escalations,
    including the new case where heuristics produce LEVEL_CAPTCHA.

- **Regression test timing**: section C log check now does `systemctl reload` before
  `grep` to drain the `buffer=32k flush=5s` access log buffer.

### Security invariants preserved

All V3.4.0 security guarantees carry forward unchanged:
- Bypass cookie HMAC enforced; expired/wrong-UA cookies rejected.
- Cookie bypass still enforces LEVEL_DENY+ from LAPI (hard bans survive CAPTCHA solve).
- LAPI-pushed verdicts take priority over heuristic scores (source="p" never downgraded).
- Honeypots (/.env, /.git/config, /wp-admin/install.php, …) exit before scoring.
- error_page loop prevention (`$crowdsec_error_page = 1`).
- safe_path() open-redirect guard on CAPTCHA redirect target.
- POST-only `/captcha-verify` (limit_except POST).
- UA binding in captcha cookie (md5[:8]).
- fail-closed CF token validation (network error → re-render, not bypass).

## [3.4.0] - 2026-05-23

### Added

- **`lua/crowdsec/captcha.lua`** — Cloudflare Turnstile CAPTCHA workflow (stateless, no Redis):
  - `has_valid_cookie()` — validates HMAC-SHA256 signed cookie; called at top of `access.lua`
    before honeypots and heuristics; valid cookie skips soft mitigations but still enforces
    LEVEL_DENY+ from LAPI (hard bans remain effective after solve).
  - `render(redirect_hint)` — serves inline challenge page (HTTP 403); sitekey injected from
    env at render time; `__REDIRECT__` HTML-escaped to prevent XSS; CSP: Turnstile domains +
    inline script hash (`sha256-X4Sgww…`); `Cache-Control: no-store`.
  - `verify()` — handles `POST /captcha-verify`; validates Turnstile token with CF API (3s
    timeout, fail closed); issues `crowdsec_captcha` cookie on success; 303 redirect to
    original URI preserved across re-renders.
  - Cookie format: `base64url(ts:ua_hash:hmac_hex)`, TTL 20 min, HttpOnly + Secure +
    SameSite=Lax. UA bound via `md5(UA)[:8]` (NAT/mobile compatible). Stateless: all
    state in the signed cookie — no disk, no Redis, no new system dependency.

- **`access.lua` — Section 0b: captcha cookie bypass**: after the error_page guard and before
  honeypot check, a valid HMAC cookie skips honeypots, heuristics, and soft mitigations.
  LAPI hard denies (LEVEL_DENY+) still apply — `lookup.get_verdict()` is called and
  `mitigation.apply()` executed if level ≥ 5.

- **`mitigation.lua` — LEVEL_CAPTCHA branch wired**: `captcha.render()` is now called from
  the LEVEL_CAPTCHA (4) branch; `crowdsec_block_reason = "captcha"` set before render so
  access logs and ban page show the correct reason. Previously dead code — LEVEL_CAPTCHA is
  only reachable via LAPI `remediation: captcha` decisions.

- **System infrastructure** (not in repo — deployed separately):
  - `/etc/crowdsec/turnstile.env` (640 root:root) — `TURNSTILE_SITEKEY` + `TURNSTILE_SECRET`
  - `/etc/systemd/system/openresty.service.d/turnstile.conf` — `EnvironmentFile=` drop-in
  - `nginx.conf` main context — `env TURNSTILE_SITEKEY; env TURNSTILE_SECRET;` (all three
    required: env file + systemd drop-in + nginx env directive)
  - `snippets/crowdsec_captcha.conf` — `location = /captcha-verify` with empty
    `access_by_lua_block {}` (prevents crowdsec loop), `limit_except POST { deny all; }`,
    `content_by_lua_block { require("crowdsec.captcha").verify() }`
  - `www.arleo.eu` vhost — `include snippets/crowdsec_captcha.conf;`
  - `crowdsec_openresty.conf` `init_by_lua_block` — `require "crowdsec.captcha"`

- **Regression tests — sections K, L, M** (47 total, up from 39):
  - Section K (5 tests) — `/.env` honeypot non-regression: confirms honeypot triggers before
    `score_path()`, no double-count, access log updated correctly.
  - Section L (3 tests) — LEVEL_CAPTCHA code-path audit: static analysis verifies
    `captcha.render()` called in mitigation.lua, `crowdsec_block_reason` set, cookie bypass
    in access.lua enforces LEVEL_DENY+.
  - Section M (9 tests) — Turnstile workflow: GET /captcha-verify → 403, invalid cookie →
    re-render, expired cookie → re-render, valid cookie → heuristics bypassed, no error_page
    loop, no redirect preserved through re-render.

### Fixed

- **`mitigation.lua` — LEVEL_CAPTCHA `cs_reason` missing** (known debt from 3.3.4): added
  `ngx.var.crowdsec_block_reason = "captcha"` before `captcha.render()`.

- **`heuristics.lua` — `PATH_SCORES["/.env"] = 60` dead code** (known debt from 3.3.4):
  removed. The honeypot check in `access.lua` exits on `/.env` before `score_path()` is
  reached; the entry was never evaluated.

- **`scripts/regression-test.sh` — honeypot log-grep false positive**: section B used
  `tail -20` which could match prior-run log entries. Fixed with a before/after line-count
  snapshot: `honey_before=$(sudo wc -l < "$ACCESS_LOG")` + `tail -n +$((honey_before+1))`.

- **`scripts/regression-test.sh` — port readiness race**: `restart_openresty()` previously
  `sleep 3` which was insufficient. Now polls port 8091 with a retry loop (up to 10s).

### Security

- Cookie forgery: HMAC-SHA256 (binary, via `ngx.hmac_sha256`) over `ts:ua_hash`; flip any
  byte → mismatch → no bypass. Verified by tamper test.
- Open redirect: `safe_path()` rejects `//host`, absolute URLs, `\r`/`\n` injection. Uses
  `find(str, 1, true)` (plain-string, no Lua pattern) to avoid null-byte pattern crash.
- POST-only: `limit_except POST { deny all; }` at nginx level — GET/HEAD on `/captcha-verify`
  returns 403 without reaching Lua.
- HTTP→HTTPS: `/captcha-verify` on port 80 receives 301 redirect; cookie is `Secure`.
- LAPI ban post-solve: verified via live test — hard ban injected after cookie issue still
  returns 403; cookie bypass does not override LEVEL_DENY+.
- SECRET absence: `has_valid_cookie()` returns `false` immediately if `SECRET == ""`.

### Operations

- **Secret rotation**: `TURNSTILE_SECRET` is read at worker startup via `os.getenv()` — it
  is not re-read per request. After rotating `/etc/crowdsec/turnstile.env`:
  ```
  systemctl restart openresty   # restart required — reload does NOT re-exec workers
  ```
  Reload (`systemctl reload openresty`) replaces config but keeps workers alive; workers
  retain the old secret until they exit. Only `restart` guarantees all workers pick up the
  new value.

### Known remaining technical debt

- **LEVEL_CAPTCHA not reachable via local heuristics**: `score_to_level()` maps scores
  directly from CHALLENGE (3) to DENY (5); LEVEL_CAPTCHA (4) is only issued by LAPI with
  `remediation: captcha`. The workflow is fully implemented; activation requires a CrowdSec
  scenario or manual `cscli decisions add --type captcha`.
- **No rate-limit on `/captcha-verify`**: repeated POST with invalid tokens causes CF to
  reject (re-render loop, no bypass). Existing `limit_req` on the vhost provides ambient
  protection; a dedicated `limit_req_zone` on this location would be more precise.

## [3.3.4] - 2026-05-23

### Fixed

- **heuristics.lua — 4 broken path patterns** (`path:find("%.env", 1, true)` and 3 others):
  the `true` flag (plain-string search) caused the Lua `%`-escape sequences to be searched
  literally, so `/backup/.env`, `/.git/HEAD`, `/wp-admin/options.php`, and `*.php~` all scored
  0 instead of 60 / 40 / 20 / 40. Removed the `true` flag; patterns now use Lua pattern
  matching as intended (`"%.env"` = literal `.env`, `"wp%-admin"` = `wp-admin`).

- **access.lua — error_page 403 infinite loop**: adding `error_page 403 /crowdsec-ban-page`
  without a guard caused heuristic-banned IPs to trigger a recursive
  `access → error_page → access → 403 → …` cycle. Fixed with a `$crowdsec_error_page`
  nginx variable set in the internal location's rewrite phase; `access.lua` returns
  immediately when it reads `"1"`, breaking the loop cleanly.

- **access.lua — monitoring bypass (`$crowdsec_skip_heuristics`)**: BetterStack probes
  hitting `/ping` accumulated heuristic score due to scanner-like UA, missing
  `Accept-Language`, etc. Setting `set $crowdsec_skip_heuristics 1;` in the `/ping` location
  bypasses honeypot, UA, header, and path scoring while preserving LAPI-pushed bans.

- **mitigation.lua — cs_reason for heuristic denies**: LEVEL_DENY exits from heuristic
  verdicts (score 81–95) logged `cs_reason=-` in the access log and showed "block" on the
  ban page. Now sets `ngx.var.crowdsec_block_reason = "heuristic"` (guarded by
  `verdict.source == "h"`) before `ngx.exit(403)`.

- **Vector pipeline — CAPI + crowdsec engine decisions**: `crowdsec_decisions_filter`
  only matched `origin == "cscli"`, silently dropping CAPI (≈100 entries/day) and
  crowdsec engine decisions (≈12). Filter extended to `cscli || crowdsec || CAPI`.

### Added

- **`snippets/crowdsec_ban_page.conf`** — universal ban page snippet: `error_page 403
  /crowdsec-ban-page` with an `internal` content handler that renders `ban.html` for all
  403 sources (heuristic deny, nginx `deny all`, `return 403`). AppSec + LAPI bans already
  write their own body before `ngx.exit(403)` and are unaffected.

- **`scripts/regression-test.sh`** — 31-test non-regression suite (exit 1 on failure).
  Sections: /ping bypass (6 tests), honeypot ban page (4), heuristic ban page (4), silent
  drop 444 (1), nginx deny ban page (2), ban page headers (6), heuristics path scoring
  (25 Lua cases), Vector pipeline (2), shared dict / IPC sanity (2), monitoring endpoints
  (3). Usage: `sudo -u jm -E bash scripts/regression-test.sh`.

- **`docs/HARDENING_REPORT_V3.3.4.md`** — pre-release hardening report: full architecture
  diagram, exact error_page / skip_heuristics / cs_reason flows, performance results
  (300 req × 2 scenarios, stable memory, 0 Lua errors), all-locations security audit,
  remaining technical debt, and pre-release checklist.

### Changed

- **`docs/runtime-layout.md`** — corrected "dual path" section: `/etc/openresty` is a
  system symlink to `/usr/local/openresty/nginx/conf`; there is one physical Lua directory,
  not two. Documents the circular-symlink trap explicitly.

- **`scripts/release-v3.sh`** — removed `luac -p` syntax check: `luac` 5.1 rejects valid
  LuaJIT `goto` statements in `sync.lua` (false positive). `openresty -t` is the
  authoritative validator.

### Known remaining technical debt

- **LEVEL_CAPTCHA `cs_reason`**: the captcha branch of `mitigation.lua` does not set
  `ngx.var.crowdsec_block_reason`. No production hits currently; one-line fix deferred to
  avoid scope creep.
- **`PATH_SCORES["/.env"] = 60`**: dead code — the honeypot check exits before
  `score_path()` is reached for the exact path `/.env`. Cosmetic only, no functional impact.
- **`luac` 5.1 false positive**: `sync.lua` uses `goto` (valid LuaJIT) which standard
  `luac` 5.1 rejects. Use `openresty -t` for all Lua syntax validation, not `luac`.

## [3.2.0] - 2026-05-22

### Added

- **OpenResty Lua mitigation layer** — custom high-performance bouncer in `lua/crowdsec/`; zero external deps, zero per-request I/O, sub-millisecond verdict lookup via `ngx.shared.dict`
- **Python → Lua IPC** — `push_lua_state()` writes `/run/crowdsec-lua/bans.json` atomically after each sync cycle; Lua reloads via `ngx.timer.every(5)` background timer
- **Lua → Python IPC** — OpenResty appends escalation events to `/run/crowdsec-lua/events.jsonl`; Python reads via atomic rename (race-free vs. Lua append) at start of each cycle
- **Adaptive mitigation levels** (L0–L5): allow → rate-limit → tarpit → JS challenge → CAPTCHA → hard deny (403/444 based on score)
- **Local heuristics scoring** — UA analysis, header coherence, path sensitivity, burst detection; scores accumulate per IP in shared dict with TTL; escalation events emitted to Python when threshold crossed
- **Honeypot routes** — `/.env`, `/.git/config`, `/wp-admin/install.php`, `/phpmyadmin/index.php`, and others; instant +100 score + escalation event on any hit
- **Bounded tarpit** — `ngx.sleep()` with `MAX_TARPITS = 20` concurrent ceiling; fail-open when limit exceeded to protect nginx workers from fd/memory exhaustion
- **Verdict cache integrity** — entry count checksum in `bans.json`; Lua rejects partial/truncated files; sequence number prevents stale-file replay
- **Source tagging** — verdict format extended to `"level:score:src"` (`p` = Python-pushed, `h` = heuristic-only); enables per-source metrics and debug
- **Dict health monitoring** — `flush_expired()` called each sync tick; `cache:free_space()` reported in metrics; Prometheus endpoint at `/crowdsec-metrics`
- **JSON debug endpoint** — `/crowdsec-status` (127.0.0.1 only) returns full Lua layer state, counters, tarpit status, sync metadata
- **systemd ReadWritePaths** — `/run/crowdsec-lua/` added; `After=openresty.service` added

### New files

| Path | Purpose |
|---|---|
| `lua/crowdsec/init.lua` | Constants, shared dict handles, encode/decode helpers |
| `lua/crowdsec/lookup.lua` | O(1) verdict lookup: exact IP → /24 CIDR → /16 CIDR |
| `lua/crowdsec/heuristics.lua` | Per-request local scoring (UA, headers, path, burst) |
| `lua/crowdsec/mitigation.lua` | Apply verdict: rate-limit / tarpit / challenge / deny |
| `lua/crowdsec/tarpit.lua` | Bounded coroutine sleep with concurrency semaphore |
| `lua/crowdsec/sync.lua` | Background ngx.timer.every() file loader |
| `lua/crowdsec/events.lua` | Deferred escalation event writer (ngx.timer.at(0)) |
| `lua/crowdsec/access.lua` | Per-request entry point (access_by_lua_block) |
| `lua/crowdsec/metrics.lua` | JSON + Prometheus debug endpoints |
| `nginx/crowdsec_shared_dicts.conf` | `lua_shared_dict` declarations (http block) |
| `nginx/crowdsec_init.conf` | `lua_package_path`, `init_by_lua_block`, `init_worker_by_lua_block` |
| `nginx/crowdsec_access.conf` | Per-vhost include (`access_by_lua_block`) |
| `nginx/crowdsec_status.conf` | `/crowdsec-status` and `/crowdsec-metrics` locations |
| `systemd/crowdsec-cf-sync.service` | Updated unit with `/run/crowdsec-lua/` in ReadWritePaths |
| `scripts/setup-lua.sh` | One-time setup: sync dir, Lua modules, nginx snippets, systemd |
| `scripts/test-lua-unit.sh` | resty CLI unit tests (no nginx required) |
| `scripts/test-lua-integration.sh` | Live integration tests (OpenResty must be running) |

### Changed

- `main()` — startup log now includes `lua=enabled/disabled`
- Main loop — `read_lua_events()` + `process_lua_events()` called at cycle start; `push_lua_state()` called after all local state is up to date
- `_Metrics` — added `lua_syncs`, `lua_sync_errors`, `lua_escalations` counters
- `_lua_sync_version` — global monotonic counter for Lua sync file versioning
- New env var: `LUA_ENABLED` (default `1`; set `0` to disable Lua push entirely)
- New env var: `LUA_SYNC_DIR` (default `/run/crowdsec-lua`)

## [3.1.0] - 2026-05-22

### Fixed
- **CIDR-aware reconciliation** — `reconcile_state()` now builds `cidr_nets` from active `/24` CIDR blocks and checks every IP against them via `_ip_in_cf()`; IPs already covered by a CIDR block are no longer flagged as drift, preventing duplicate CF rules accumulating silently
- **WAL crash-durability** — `_wal_log()` now calls `f.flush()` + `os.fsync()` after every append; WAL entries survive hard power-off without loss
- **Atomic write durability** — `_atomic_write_json()` calls `os.fsync()` on the temp file before `os.replace()`; state files survive crash-on-rename
- **Single CF API call per reconciliation** — `reconcile_state()` calls `_fetch_cf_rules()` once and passes the result to `get_cf_blocked_ips()` / `get_cf_rules_by_tag()`; eliminates 2 redundant CF calls per reconciliation cycle
- **Boot degraded mode** — if Cloudflare is unreachable at startup, the daemon enters degraded mode (no rule modifications) and auto-recovers on each subsequent cycle without crashing

### Added
- **State versioning with sha256 checksum** — all state files written in `{"version": 1, "updated_at": "...", "sha256": "...", "state": {...}}` envelope; sha256 verified on load; mismatch → corrupt file renamed to `.bak`, daemon continues with clean default; V3 flat format accepted and migrated transparently on next save
- **WAL sequential IDs** — each WAL entry carries `"id"` (monotonically increasing across restarts) initialized from line count of existing WAL file; improves post-mortem tracing
- **Jitter in HTTP retry** — `_http_call()` adds `random.uniform(0, base_wait * 0.3)` to each retry wait to prevent thundering-herd when Cloudflare, CrowdSec, or AbuseIPDB recovers after a brief outage
- **CF quota warning** — `_fetch_cf_rules()` logs `WARNING` and increments `cf_quota_warnings` metric when rule count reaches 800/1000
- **`ip -j addr` for own-IP detection** — `_build_protected_networks()` uses `ip -j addr` (reliable, machine-readable) instead of `hostname -I`; fallback to `socket.getaddrinfo(gethostname())` if `ip` is unavailable
- **systemd hardening** — service unit adds `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=strict`, `ProtectHome`, `ProtectKernelTunables`, `ProtectKernelModules`, `ProtectControlGroups`, `RestrictSUIDSGID`, `MemoryDenyWriteExecute`, `LockPersonality`, `RestrictRealtime`, `SystemCallArchitectures=native`, `ReadWritePaths=/var/log/crowdsec/`, `ReadOnlyPaths=/var/log/nginx/`
- **V1/V2 archived** — `crowdsec-cf-sync.py` (1.0.0) and `crowdsec-cf-syncV2.py` (2.0.0) moved to `archived/`; `crowdsec-cf-syncV3.py` is the single active script

### Changed
- `_load_json_state()` — reads versioned envelope; falls back to V3 flat dict transparently
- `_atomic_write_json()` — wraps state in versioned envelope with sha256 before writing
- `_wal_log()` — adds `id` field; calls fsync
- `_fetch_cf_rules()` — extracted from inline calls; single shared function with quota warning
- `_parse_cf_rules_by_tag()` — extracted helper; accepts pre-fetched rules list
- `_build_protected_networks()` — uses `ip -j addr` with socket fallback
- `_http_call()` — jitter added to retry wait

## [3.0.0] - 2026-05-22

### Added
- **Anti-self-ban** — immutable protected ranges (RFC1918, Cloudflare anycast, Tailscale CGNAT 100.64.0.0/10, loopback, link-local) checked in `is_protected()` before every `add_cf_rule()` call; own IPs loaded from `ip -j addr` at startup
- **Circuit breakers** — `CircuitBreaker` class for Cloudflare, CrowdSec, and AbuseIPDB APIs; opens after `CF_CB_THRESHOLD` (default 5) consecutive failures, resets after `CF_CB_RESET_SECS` (default 120s); prevents cascade failures when an API is down
- **DRY_RUN / shadow mode** — `CF_DRY_RUN=1` simulates all Cloudflare operations without applying them; logged as `[DRY RUN]`; health endpoint reports `"mode": "dry_run"`
- **Health + Prometheus metrics HTTP endpoint** — `http://127.0.0.1:CF_HEALTH_PORT/health` (JSON) and `/metrics` (Prometheus text format); disabled when `CF_HEALTH_PORT=0`; metrics: cycles, CF API calls/errors, rules added/removed, drift events, circuit breaker trips, AbuseIPDB reports, recidivists, CIDR blocks, protected blocks
- **WAL (Write-Ahead Log)** — every Cloudflare operation intent appended to `/var/log/crowdsec/cf-sync-wal.jsonl` before API call; trimmed to 10,000 lines on startup; provides audit trail for post-mortem analysis
- **SIGHUP hot reload** — `SIGHUP` signal triggers reload of CrowdSec allowlist and protected ranges without daemon restart; logged as `Hot reload terminé`
- **sd_notify watchdog** — `_sd_notify()` sends `READY=1`, `WATCHDOG=1` (each cycle), and `STOPPING=1` via `NOTIFY_SOCKET` unix socket for native systemd watchdog integration (`WatchdogSec=`)
- **Adaptive mitigation** — `CF_MIN_CONFIDENCE` (default `low`) gates which scenarios are synced to Cloudflare; `low` = all, `medium` = excludes low-confidence scanners, `high` = only confirmed threats; uses `_scenario_confidence()` heuristic on scenario name
- **Rule collapsing** — `collapse_ips()` uses `ipaddress.collapse_addresses()` to coalesce adjacent IPs into minimal CIDR set before CF batch operations, reducing API call count
- **Drift detection / reconciliation** — `reconcile_state()` compares active CF rules against current CrowdSec bans every `CF_RECONCILE_SECS` (default 300s); orphaned CF rules removed, missing bans re-added, drift events shipped to BetterStack and counted in metrics
- **Recidivist cursor** — `_cursor` timestamp stored in `recidivists.json` prevents re-processing the same ban events across restarts; initialized to `now` on first V3 run to avoid retroactively re-counting bans that V2 already processed
- `WAL_FILE` — new state file `/var/log/crowdsec/cf-sync-wal.jsonl`

### Changed
- `sync_recidivists()` — cursor-based dedup replaces full 48h re-scan each cycle; `purge_old_recidivists()` preserves `_cursor` key
- `sync_cloudflare()` — now accepts `cs_allowlist` parameter; applies adaptive mitigation filter via `_should_sync_to_cf()` before adding CF rules
- `add_cf_rule()` — `is_protected()` guard added; WAL entry written before API call; DRY_RUN path logs intent without calling CF API
- New env vars: `CF_DRY_RUN`, `CF_HEALTH_PORT`, `CF_RECONCILE_SECS`, `CF_MIN_CONFIDENCE`, `CF_CB_THRESHOLD`, `CF_CB_RESET_SECS`

## [2.0.0] - 2026-05-21

### Added
- **Graceful shutdown** — SIGTERM/SIGINT handled via `threading.Event`; sleep is interruptible
- **Atomic JSON writes** — all state files written via `tempfile.mkstemp()` + `os.replace()` (no partial writes on crash)
- **HTTP retry with exponential backoff** — retries on 429/5xx with configurable `max_retries` and `backoff` (stdlib `urllib` only, no external deps)
- **RotatingFileHandler** — log file capped at 5 MB × 3 backups
- **IP/CIDR validation** — `ipaddress.ip_address()` guard before every Cloudflare API call; CIDRs (e.g. `cidr-auto-ban/N-ips`) silently skipped instead of generating 422 errors on AbuseIPDB
- **Config validation at startup** — missing required env vars → immediate `sys.exit` with a clear message
- **JSON state corruption recovery** — corrupt state file automatically renamed to `.bak`, daemon continues with a clean default
- **Cycle timing metrics** — each sync cycle duration logged at DEBUG level
- **Shutdown checks between sub-tasks** — `_shutdown.is_set()` guard between every major step of the cycle
- **AbuseIPDB check for OpenResty bouncer blocks** — when the nginx/OpenResty bouncer denies a request, V2 queries AbuseIPDB `/check` (once per IP per 24 h) and ships an enriched event to BetterStack with `abuse_score`, `country`, `isp`, `total_reports`
- `BOUNCER_CHECK_STATE` — new state file `/var/log/crowdsec/bouncer-abusecheck.json`
- `ABUSEIPDB_CHECK_URL` / `BETTERSTACK_INGEST` read from environment (no hardcoded account URLs)

### Fixed
- **Infinite recidivist escalation loop** — `get_recent_local_bans()` now skips `recidivist-escalation` entries in the `decision` branch (not just the `alert` branch), preventing re-processing of escalated bans
- **AbuseIPDB 422 spam** — CIDR entries (e.g. `192.175.111.0/24`) validated and skipped before being sent to AbuseIPDB, which only accepts single IPs
- **Belt-and-suspenders guard in `sync_recidivists()`** — secondary `ipaddress.ip_address()` validation prevents non-IP keys from ever reaching the escalation path

### Changed
- All state persistence functions split into `load_*/save_*` pairs with `_load_json_state()` / `_atomic_write_json()` helpers
- HTTP calls unified through `_http_call()` with retry logic; timeouts now consistently enforced
- Logging via `logging.handlers.RotatingFileHandler` replaces bare `logging.FileHandler`

## [1.0.0] - 2026-05-21

### Added
- CrowdSec → Cloudflare IP Access Rules synchronisation (60s interval)
- AbuseIPDB reporting for newly banned IPs (48h lookback)
- Recidivist escalation: 2nd ban → 24h, 3rd+ → 7 days
- ModSecurity anomaly score ≥ 5 → immediate Cloudflare ban (2h) + AbuseIPDB report
- Automatic /24 CIDR block when 2+ distinct IPs from the same subnet are banned within 7 days
- Cloudflare WAF event polling (5-minute window, 3-hit threshold)
- CrowdSec allowlist integration (skips allowlisted IPs)
- `cscli decisions list` with client-side origin filtering (workaround for CrowdSec #4470 go-sqlite3 timeout)
- BetterStack log ingestion for WAF events
