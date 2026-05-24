# CrowdSec Notifier Architecture

## Overview

Starting from V3.6.0, crowdsec-cf-sync introduces a **split push model**:

- **Hot path** — `crowdsec-notifier` receives events directly from CrowdSec's notification plugin. Pushes new bans to Cloudflare in ~1–5 seconds.
- **Cold path** — `crowdsec-cf-sync` retains authoritative control over expiry cleanup, drift reconciliation, and state consistency.

This separation aligns with the architecture constraint: CrowdSec MUST NOT become the authoritative Cloudflare synchronization engine. The Python supervisor remains the source of truth.

## Component Map

```
CrowdSec scenario fires
        │
        ▼
   LAPI ban decision
        │
        ├── cloudflare_notifier plugin (group_wait=5s, threshold=1)
        │         │
        │         ▼ ~1-6s total latency
        │   crowdsec-notifier.py /crowdsec/cloudflare
        │         │
        │         └── Cloudflare access rules API (POST)
        │
        └── abuseipdb_notifier plugin (group_wait=30s, threshold=10)
                  │
                  ▼
            crowdsec-notifier.py /crowdsec/abuseipdb
                  │
                  └── AbuseIPDB v2 API (POST)

crowdsec-cf-sync (parallel, independent loop):
  every 60s  → sync_cloudflare():  skips to_add (CF_NOTIFIER_ACTIVE=1), runs to_delete (expiry)
  every 300s → reconcile_state():  CIDR-aware drift detection, fixes missed bans, removes ghosts
```

## Key Design Decisions

### `CF_NOTIFIER_ACTIVE=1`

When this flag is set in `/etc/crowdsec/cf-sync.env`, `sync_cloudflare()` logs
`"push deleguee"` and skips the `to_add` loop. The `to_delete` loop still runs,
ensuring expired bans are removed from Cloudflare.

`reconcile_state()` is NOT gated by this flag — it remains a permanent safety net
that detects and corrects drift regardless of which component pushed the ban.

### `SYNC_ABUSEIPDB=0`

Disables the supervisor's own `sync_abuseipdb()` function to prevent double reporting
when `crowdsec-notifier` is live on the AbuseIPDB channel.

### Anti-self-ban protection

`crowdsec-notifier.py` builds `_protected_networks` at startup:
- RFC1918 + loopback + link-local + CGNAT
- All Cloudflare CDN IP ranges (blocking them would disable the proxy)
- All own server IPs via `ip -j addr`

This mirrors the `_build_protected_networks()` logic in `crowdsec-cf-sync`.

### Dedup

| Channel      | Key             | TTL    | Purpose                           |
|---|---|---|---|
| AbuseIPDB    | `{ip}:{scenario}` | 7 days | Prevent resubmitting known attacks |
| Cloudflare   | `{ip}`          | 120s   | Suppress burst duplicates only    |

CF dedup TTL is intentionally short — `reconcile_state()` handles long-term drift correction.

## Rollout Phases

| Phase | AbuseIPDB | Cloudflare | CF_NOTIFIER_ACTIVE | SYNC_ABUSEIPDB |
|---|---|---|---|---|
| 1 (shadow) | DRY_RUN=1 | CF_DRY_RUN=1 | 0 | 1 |
| 2 (CF live) | DRY_RUN=1 | live | 0 | 1 |
| 3 (all live) | live | live | 0 | 1 |
| 4 (notifier primary) | live | live | 1 | 0 |

## Files

| File | Location | Purpose |
|---|---|---|
| `crowdsec-cf-sync` | `/usr/local/bin/` | Supervisor daemon |
| `crowdsec-notifier.py` | `/usr/local/bin/` | HTTP receiver for CrowdSec plugins |
| `crowdsec-cf-sync.service` | `/etc/systemd/system/` | Supervisor unit |
| `crowdsec-notifier.service` | `/etc/systemd/system/` | Notifier unit |
| `abuseipdb.yaml` | `/etc/crowdsec/notifications/` | AbuseIPDB plugin config |
| `cloudflare.yaml` | `/etc/crowdsec/notifications/` | Cloudflare plugin config |
| `profiles.yaml` | `/etc/crowdsec/` | Notification routing |
| `cf-sync.env` | `/etc/crowdsec/` | Secrets and flags (never commit) |

## Rollback

Restore supervisor as primary CF writer in under 60 seconds:

```bash
# Disable notifier CF push
sudo sed -i 's/^CF_NOTIFIER_ACTIVE=1/CF_NOTIFIER_ACTIVE=0/' /etc/crowdsec/cf-sync.env
sudo systemctl restart crowdsec-cf-sync

# Re-enable supervisor AbuseIPDB if needed
sudo sed -i 's/^SYNC_ABUSEIPDB=0/SYNC_ABUSEIPDB=1/' /etc/crowdsec/cf-sync.env
sudo systemctl restart crowdsec-cf-sync

# Put notifier back to dry-run
sudo systemctl edit --full crowdsec-notifier
# Add: Environment=NOTIFIER_DRY_RUN=1
# Add: Environment=NOTIFIER_CF_DRY_RUN=1
sudo systemctl daemon-reload && sudo systemctl restart crowdsec-notifier
```
