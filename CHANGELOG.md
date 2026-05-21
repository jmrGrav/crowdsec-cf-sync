# Changelog

All notable changes to this project will be documented in this file.

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
