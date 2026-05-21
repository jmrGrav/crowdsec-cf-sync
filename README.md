# crowdsec-cf-sync

A Python daemon that bridges [CrowdSec](https://www.crowdsec.net/) and [Cloudflare](https://www.cloudflare.com/) Firewall, with AbuseIPDB reporting, recidivist escalation, ModSecurity-based instant bans, and automatic /24 CIDR blocking.

Three versions are available in this repository:

| File | Version | Status |
|---|---|---|
| `crowdsec-cf-syncV3.py` | **3.0.0** — recommended | Active, production-ready |
| `crowdsec-cf-syncV2.py` | 2.0.0 — previous | Stable, kept for reference |
| `crowdsec-cf-sync.py` | 1.0.0 — legacy | Archived, kept for reference |

## Features

- **CrowdSec → Cloudflare sync** — pushes active local bans (origin `crowdsec`/`cscli`) to Cloudflare IP Access Rules every 60 seconds
- **AbuseIPDB reporting** — reports newly banned IPs with scenario context and recent nginx URIs
- **Recidivist escalation** — tracks repeat offenders: 2nd ban → 24h Cloudflare block, 3rd+ → 7 days
- **ModSecurity instant ban** — ModSecurity anomaly score ≥ 5 → immediate 2h Cloudflare block + AbuseIPDB report
- **Auto /24 CIDR block** — when 2+ distinct IPs from the same /24 are banned within 7 days, the entire subnet is blocked for 24h
- **Cloudflare WAF polling** — detects mass-hits on WAF rules and escalates via CrowdSec

### V3 additions

- **Anti-self-ban** — immutable protected ranges (RFC1918, Cloudflare anycast, Tailscale CGNAT, own IPs) guard every `add_cf_rule()` call
- **Circuit breakers** — graceful degradation when Cloudflare, CrowdSec, or AbuseIPDB APIs are down; auto-reset after configurable timeout
- **DRY_RUN / shadow mode** — `CF_DRY_RUN=1` simulates without applying; safe for testing against production state
- **Health + Prometheus metrics** — `http://127.0.0.1:CF_HEALTH_PORT/health` (JSON) and `/metrics` (Prometheus text); scrape-ready for Grafana
- **WAL (Write-Ahead Log)** — append-only journal at `/var/log/crowdsec/cf-sync-wal.jsonl` for every Cloudflare operation
- **SIGHUP hot reload** — reload allowlist and config without daemon restart
- **sd_notify watchdog** — native systemd `WatchdogSec=` integration via `NOTIFY_SOCKET`
- **Adaptive mitigation** — `CF_MIN_CONFIDENCE` gates scenarios by confidence level (low / medium / high)
- **Rule collapsing** — `ipaddress.collapse_addresses()` coalesces adjacent IPs into minimal CIDR set before CF batch
- **Drift detection** — periodic reconciliation (default 300s) removes orphaned CF rules and re-adds missing bans; alerts BetterStack on drift
- **Recidivist cursor** — cursor-based dedup prevents re-counting ban events across restarts

### V2 additions

- **Graceful shutdown** — SIGTERM/SIGINT handled via `threading.Event`; sleep is interruptible
- **Atomic JSON writes** — all state files written via `tempfile.mkstemp()` + `os.replace()`
- **HTTP retry with exponential backoff** — retries on 429/5xx (stdlib `urllib` only, no extra deps)
- **RotatingFileHandler** — log capped at 5 MB × 3 backups
- **IP/CIDR validation** — `ipaddress.ip_address()` guard before every Cloudflare and AbuseIPDB call
- **Config validation at startup** — missing env vars → immediate exit with a clear error
- **JSON state corruption recovery** — corrupt state file renamed to `.bak`, daemon continues cleanly
- **AbuseIPDB `/check` for OpenResty bouncer blocks** — queries abuse score, country, ISP, total reports once per IP per 24 h, ships enriched event to BetterStack

## Requirements

- Python 3.9+ (stdlib only — no external dependencies)
- [CrowdSec](https://www.crowdsec.net/) with `cscli` in PATH
- Cloudflare account with Zone-level Firewall Write permissions
- AbuseIPDB account
- (Optional) BetterStack account for WAF event and bouncer log ingestion

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `CF_API_TOKEN` | Yes | Cloudflare API token (Zone Firewall Write) |
| `CF_ZONE_ID` | Yes | Cloudflare Zone ID |
| `ABUSEIPDB_KEY` | Yes | AbuseIPDB API key |
| `CS_API_KEY` | No | CrowdSec LAPI key (optional) |
| `BETTERSTACK_TOKEN` | No | BetterStack source token for log ingestion |
| `BETTERSTACK_INGEST` | No | BetterStack ingest URL (e.g. `https://your-source.betterstackdata.com/`) |
| `CF_DRY_RUN` | No | Set to `1` to enable shadow mode (no CF/AbuseIPDB writes) |
| `CF_HEALTH_PORT` | No | HTTP port for `/health` and `/metrics` (default `8765`; `0` = disabled) |
| `CF_RECONCILE_SECS` | No | Reconciliation interval in seconds (default `300`) |
| `CF_MIN_CONFIDENCE` | No | Minimum scenario confidence to sync to CF: `low` (default), `medium`, `high` |
| `CF_CB_THRESHOLD` | No | Circuit breaker failure threshold before opening (default `5`) |
| `CF_CB_RESET_SECS` | No | Circuit breaker reset timeout in seconds (default `120`) |

## State Files

The daemon maintains JSON state files under `/var/log/crowdsec/`:

| File | Purpose |
|---|---|
| `abuseipdb-reported.json` | IPs already reported to AbuseIPDB (dedup) |
| `recidivists.json` | Repeat offender tracking (count + last seen) |
| `modsec-banned.json` | ModSecurity temporary bans |
| `cidr-banned.json` | Active /24 CIDR blocks |
| `cf_waf_state.json` | Cloudflare WAF polling cursor |
| `bouncer-abusecheck.json` | AbuseIPDB check cache for bouncer-blocked IPs *(V2+)* |
| `cf-sync-wal.jsonl` | Write-Ahead Log of CF operation intents *(V3 only)* |
| `cf-sync.log` | Daemon log |

## Systemd Service

```ini
[Unit]
Description=CrowdSec → Cloudflare IP Sync
After=network.target crowdsec.service

[Service]
Type=notify
EnvironmentFile=/etc/crowdsec/cf-sync.env
ExecStart=/usr/bin/python3 /usr/local/bin/crowdsec-cf-syncV3.py
Restart=on-failure
RestartSec=10
WatchdogSec=120

[Install]
WantedBy=multi-user.target
```

> **V3 note**: `Type=notify` and `WatchdogSec=120` enable sd_notify watchdog. V3 sends `READY=1` at startup and `WATCHDOG=1` every cycle; systemd will restart the daemon if it stops sending heartbeats.

Create `/etc/crowdsec/cf-sync.env` with your secrets (never commit this file):

```env
CF_API_TOKEN=your_cloudflare_token
CF_ZONE_ID=your_zone_id
ABUSEIPDB_KEY=your_abuseipdb_key
BETTERSTACK_TOKEN=your_betterstack_token
BETTERSTACK_INGEST=https://your-source.betterstackdata.com/
```

## CrowdSec decisions.log poller

The daemon reads from `/var/log/crowdsec/decisions.log` (JSON lines). This file must be produced by a separate poller (e.g. a script that calls `cscli decisions list -o json` and writes one JSON object per line with a `cs` key containing decision fields).

## Notes

- The `cscli decisions list` command is called **without** `--origin` to avoid a 25s+ SQLite timeout in CrowdSec ≤ 1.7.8 ([crowdsecurity/crowdsec#4470](https://github.com/crowdsecurity/crowdsec/issues/4470)). Origin filtering is done client-side in Python.
- AbuseIPDB reporting uses the `report` endpoint only for ban events. CIDRs are silently skipped — the AbuseIPDB API requires a single IP address (V1 sent CIDRs and got 422 errors; fixed in V2).

## License

MIT — see [LICENSE](LICENSE)
