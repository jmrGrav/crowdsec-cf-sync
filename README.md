# crowdsec-cf-sync

A Python daemon that bridges [CrowdSec](https://www.crowdsec.net/) and [Cloudflare](https://www.cloudflare.com/) Firewall, with AbuseIPDB reporting, recidivist escalation, ModSecurity-based instant bans, and automatic /24 CIDR blocking.

## Features

- **CrowdSec → Cloudflare sync** — pushes active local bans (origin `crowdsec`/`cscli`) to Cloudflare IP Access Rules every 60 seconds
- **AbuseIPDB reporting** — reports newly banned IPs with scenario context and recent nginx URIs
- **Recidivist escalation** — tracks repeat offenders: 2nd ban → 24h Cloudflare block, 3rd+ → 7 days
- **ModSecurity instant ban** — ModSecurity anomaly score ≥ 5 → immediate 2h Cloudflare block + AbuseIPDB report
- **Auto /24 CIDR block** — when 2+ distinct IPs from the same /24 are banned within 7 days, the entire subnet is blocked for 24h
- **Cloudflare WAF polling** — detects mass-hits on WAF rules and escalates via CrowdSec

## Requirements

- Python 3.9+ (stdlib only — no external dependencies)
- [CrowdSec](https://www.crowdsec.net/) with `cscli` in PATH
- Cloudflare account with Zone-level Firewall Write permissions
- AbuseIPDB account
- (Optional) BetterStack account for WAF event log ingestion

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `CF_API_TOKEN` | Yes | Cloudflare API token (Zone Firewall Write) |
| `CF_ZONE_ID` | Yes | Cloudflare Zone ID |
| `ABUSEIPDB_KEY` | Yes | AbuseIPDB API key |
| `CS_API_KEY` | No | CrowdSec LAPI key (optional) |
| `BETTERSTACK_TOKEN` | No | BetterStack source token for WAF event ingestion |
| `BETTERSTACK_INGEST` | No | BetterStack ingest URL (e.g. `https://in.logs.betterstack.com`) |

## State Files

The daemon maintains JSON state files under `/var/log/crowdsec/`:

| File | Purpose |
|---|---|
| `abuseipdb-reported.json` | IPs already reported to AbuseIPDB (dedup) |
| `recidivists.json` | Repeat offender tracking (count + last seen) |
| `modsec-banned.json` | ModSecurity temporary bans |
| `cidr-banned.json` | Active /24 CIDR blocks |
| `cf_waf_state.json` | Cloudflare WAF polling cursor |
| `cf-sync.log` | Daemon log |

## Systemd Service

```ini
[Unit]
Description=CrowdSec → Cloudflare IP Sync
After=network.target crowdsec.service

[Service]
Type=simple
EnvironmentFile=/etc/crowdsec/cf-sync.env
ExecStart=/usr/bin/python3 /usr/local/bin/crowdsec-cf-sync.py
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Create `/etc/crowdsec/cf-sync.env` with your secrets:

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
- AbuseIPDB reporting uses the `report` endpoint only (not `check`). CIDRs are skipped — the AbuseIPDB API requires a single IP address.

## License

MIT — see [LICENSE](LICENSE)
