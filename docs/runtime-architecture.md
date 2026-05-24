# Runtime Architecture

## Overview

Two independent processes cooperate via a shared filesystem IPC. The Python daemon is the **control plane** (source of truth, all I/O); the Lua layer is the **data plane** (per-request enforcement, zero I/O).

```
┌─────────────────────────────────────────────────────────────────────┐
│                        CONTROL PLANE (Python)                       │
│                                                                     │
│  crowdsec-cf-sync — single process, runs as root               │
│                                                                     │
│  ┌─────────────┐   ┌──────────────┐   ┌────────────────────────┐  │
│  │ CrowdSec    │   │  Cloudflare  │   │  AbuseIPDB / heuristic  │  │
│  │ LAPI        │   │  Firewall    │   │  escalation feed        │  │
│  │ (HTTP/API)  │   │  Rules API   │   │                         │  │
│  └──────┬──────┘   └──────┬───────┘   └────────────┬────────────┘  │
│         │                 │                          │              │
│         └─────────────────┴──────────────────────────┘             │
│                           │                                         │
│                    ┌──────▼──────┐                                  │
│                    │  bans.json  │  atomic rename (mkstemp→replace) │
│                    │  +meta+crc32│  mode 644, /run/crowdsec-lua/    │
│                    └──────┬──────┘                                  │
└───────────────────────────┼─────────────────────────────────────────┘
                            │ filesystem IPC (no socket, no pipe)
┌───────────────────────────┼─────────────────────────────────────────┐
│                    DATA PLANE (Lua / OpenResty)                     │
│                           │                                         │
│                    ┌──────▼──────┐                                  │
│                    │  sync.lua   │  ngx.timer.every(5) background   │
│                    │             │  reads bans.json, loads dict     │
│                    └──────┬──────┘                                  │
│                           │                                         │
│         ┌─────────────────┼─────────────────┐                      │
│         ▼                 ▼                  ▼                      │
│  cscf_verdicts    crowdsec_metrics   crowdsec_state                 │
│  (50 MB dict)     (10 MB dict)       (5 MB dict)                   │
│                                                                     │
│  Per-request path (access.lua — < 50 µs per request):              │
│    1. Honeypot check       → instant deny + event                  │
│    2. Deadman check        → stale mode if sync_ts > 120s old      │
│    3. Verdict lookup       → cscf_verdicts get() — O(1)            │
│    4. Heuristic scoring    → suspended when stale or mem_pressure  │
│    5. Apply mitigation     → tarpit / challenge / deny / allow      │
└─────────────────────────────────────────────────────────────────────┘
```

## Python Control Plane

### Responsibilities

| Domain | What Python does |
|--------|-----------------|
| CrowdSec | Poll LAPI for new bans/unbans |
| Cloudflare | Add/remove firewall rules via API |
| Lua IPC | Write `bans.json` atomically every 60 s |
| Escalation | Receive Lua events, escalate to CF/CS |
| WAL | Append every CF change for audit/replay |
| Auto-heal | Monitor Lua `sync_version`; reload OpenResty if frozen |
| Doctor | System health audit on demand |

### Operational modes

| Mode | Trigger | Behaviour |
|------|---------|-----------|
| Normal | CF + CrowdSec reachable | Full sync cycle |
| Degraded | CF API errors > threshold | Pause CF changes, continue Lua sync |
| Boot-healthy=False | CF unreachable at boot | Read-only for 30 s, then re-attempt |

### IPC protocol (Python → Lua)

Every 60 s (configurable), Python writes `/run/crowdsec-lua/bans.json`:

```json
{
  "version":          <int, monotonic counter starting at 1>,
  "updated_at":       "<ISO-8601 UTC>",
  "updated_at_epoch": <unix timestamp int>,
  "entry_count":      <int>,
  "writer_pid":       <int>,
  "writer_hostname":  "<str>",
  "bans":  { "<ip>": {"score": <int>, "level": <int>, "ttl": <int>} },
  "cidrs": { "<cidr>": {"score": <int>, "level": <int>, "ttl": <int>} },
  "meta":  {
    "cycle_count":     <int>,
    "cf_api_errors":   <int>,
    "wal_entries":     <int>,
    "lua_sync_errors": <int>,
    "degraded":        <bool>
  },
  "payload_crc32": <uint32>
}
```

Write is atomic: `mkstemp` → `fchmod(0o644)` → `fsync` → `os.replace`. Lua never reads a partial file.

## Lua Data Plane

### Shared dicts

| Dict name | Size | Purpose |
|-----------|------|---------|
| `cscf_verdicts` | 50 MB | Verdict cache — `"ip:X.X.X.X"` → `"level:score:src"` |
| `crowdsec_metrics` | 10 MB | Counters (cache hits, syncs, heuristics, …) |
| `crowdsec_state` | 5 MB | State flags (sync_ts, memory_pressure, tarpit_active, …) |

All dict accesses use `ngx.shared.*` — no locks, workers share memory via the OS mmap. Each worker maintains its own Lua upvalues (e.g., `last_version`) which reset on `systemctl reload openresty`.

### Module responsibilities

| Module | Role |
|--------|------|
| `init.lua` | Constants, shared dict handles, verdict codec |
| `sync.lua` | Background timer — parse/validate bans.json, load dicts |
| `access.lua` | Per-request entry point — honeypot → verdict → mitigation |
| `lookup.lua` | Dict read, CIDR prefix fallback, heuristic score accumulation |
| `heuristics.lua` | UA / header / path / burst scoring |
| `mitigation.lua` | Apply verdict: tarpit / challenge / captcha / deny |
| `events.lua` | Append escalation events to `events.jsonl` |
| `metrics.lua` | `/crowdsec-status` (JSON) + `/crowdsec-metrics` (Prometheus) |

### Degraded modes (Lua)

| Condition | Trigger | Effect |
|-----------|---------|--------|
| Stale sync | `ngx.time() - sync_ts > 120 s` | Suspend heuristics + soft mitigations; hard denies still apply |
| Memory pressure | `cscf_verdicts free_pct < 10%` | Suppress heuristic dict writes; existing verdicts preserved |
| Hard stop | `cscf_verdicts free_space < 2 MB` | Skip dict load entirely during sync |
| IPC rejection | Stale/future timestamp, bad CRC | Increment `ipc_rejected`; keep previous state |
| Lua error | Any `pcall` failure in `access.lua` | Fail-open: request passes, error logged at `ngx.ERR` |

## IPC Integrity Checks (sync.lua)

Applied in order before any dict write:

1. **Payload size** — reject if `#content > 10 MB`
2. **JSON parse** — reject on invalid JSON
3. **Sequence guard** — reject if `data.version <= last_version` (silent, no counter)
4. **Timestamp validation** — reject if `updated_at_epoch` is > 600 s stale or > 300 s in the future → `ipc_rejected++`
5. **Memory hard-stop** — abort if `cache:free_space() < 2 MB`

## Metrics Endpoints (Lua)

| Endpoint | Format | Auth |
|----------|--------|------|
| `/crowdsec-status` | JSON | 127.0.0.1 only |
| `/crowdsec-metrics` | Prometheus text | 127.0.0.1 only |

Both served from `127.0.0.1:8091` (default). Port is configured in `crowdsec_cf_sync_generated.conf`.

## Python Health / Metrics

| Endpoint | Format | Port |
|----------|--------|------|
| `/health` | JSON | 8765 |
| `/metrics` | JSON | 8765 |

Served by a minimal HTTP thread in the Python daemon. Not exposed to the internet.
