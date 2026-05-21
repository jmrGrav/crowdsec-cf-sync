# Changelog

All notable changes to this project will be documented in this file.

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
