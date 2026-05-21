# Changelog

All notable changes to this project will be documented in this file.

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
