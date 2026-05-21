# Changelog

All notable changes to this project will be documented in this file.

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
