# Recovery Procedures

Runbook for the most common failure modes. Verify state before acting — never assume.

## 1. Stale sync (Lua deadman mode)

**Symptom**: `/crowdsec-status` shows `sync.ts` more than 120 s old; requests are processed with hard-deny-only policy (soft mitigations suspended).

**Diagnose**:
```bash
curl -s http://127.0.0.1:8091/crowdsec-status | python3 -c "
import sys, json, time
d = json.load(sys.stdin)
ts = d['sync']['ts']
age = int(time.time()) - ts if ts else 'never'
print(f'sync_ts age: {age}s, version: {d[\"sync\"][\"version\"]}')
print(f'stale_checks: {d[\"mitigation\"][\"stale_checks\"]}')
"
```

**Root causes and fixes**:

| Cause | Fix |
|-------|-----|
| Python daemon stopped | `systemctl start crowdsec-cf-sync` |
| Python daemon running but not writing | `journalctl -u crowdsec-cf-sync -n 50 --no-pager` |
| Lua sequence guard blocking (last_version > Python version) | `systemctl reload openresty` (resets last_version=0) |
| bans.json timestamp too old (timestamp validation) | Python writes fresh timestamp each cycle — restart daemon |
| `/run/crowdsec-lua/` missing (tmpfs unmounted) | `systemctl restart crowdsec-cf-sync` (RuntimeDirectory recreates it) |

**Auto-heal**: the Python daemon auto-detects a frozen `sync_version` and triggers `systemctl reload openresty` after 120 s (at most once per hour). Check logs: `journalctl -u crowdsec-cf-sync | grep autoheal`.

---

## 2. Dict full (`cscf_verdicts` at capacity)

**Symptom**: `dict_set_failures` counter climbing; `/crowdsec-status` shows `memory.cache_free_bytes` near 0; new verdicts are not stored.

**Diagnose**:
```bash
curl -s http://127.0.0.1:8091/crowdsec-status | python3 -c "
import sys, json
d = json.load(sys.stdin)
m = d['memory']
print(f'cache_free_bytes: {m[\"cache_free_bytes\"]}')
print(f'cache_free_pct: {m[\"cache_free_pct\"]}%')
print(f'pressure_active: {m[\"pressure_active\"]}')
print(f'pressure_events: {m[\"pressure_events_total\"]}')
print(f'dict_set_failures: {d[\"ipc\"][\"dict_set_failures\"]}')
"
```

**Three-level response**:

| Level | Threshold | Automatic response | Manual action |
|-------|-----------|--------------------|---------------|
| Healthy | `free_pct > 10%` | None | None |
| Memory pressure | `free_pct < 10%` | Heuristic writes suspended; existing verdicts preserved | Check entry count; consider reducing TTLs |
| Hard stop | `free_space < 2 MB` | Dict load skipped entirely during sync | Reload OpenResty to clear dicts, then reduce ban TTLs |

**Force-clear the dict** (emergency):
```bash
systemctl restart openresty   # clears ALL shared dicts — also clears metrics
# OR: reduce ban count in CrowdSec, wait for expiry
```

After hard stop, verify sync resumes:
```bash
systemctl reload openresty    # soft clear (workers restart, dicts preserved)
systemctl restart crowdsec-cf-sync
```

---

## 3. Failed OpenResty reload

**Symptom**: `systemctl reload openresty` returns non-zero; requests still served by old workers.

**Diagnose**:
```bash
openresty -t   # test config syntax
journalctl -u openresty -n 20 --no-pager
```

**Common causes**:

| Cause | Fix |
|-------|-----|
| Lua syntax error in a module | Check `journalctl -u openresty` for `[error]`; restore previous `.lua` file |
| Missing `include` file | Check the failing include path; restore from backup |
| Shared dict size mismatch | Verify `crowdsec_shared_dicts.conf` matches `init.lua` constants |

**Rollback Lua to previous version**:
```bash
cp /etc/openresty/lua/crowdsec/sync.lua.bak /etc/openresty/lua/crowdsec/sync.lua
openresty -t && systemctl reload openresty
```

---

## 4. Python daemon crash / restart loop

**Symptom**: `systemctl status crowdsec-cf-sync` shows repeated restarts; `ActiveState: activating`.

**Diagnose**:
```bash
journalctl -u crowdsec-cf-sync -n 100 --no-pager | grep -E "ERROR|Traceback|Exception"
```

**Rollback Python daemon**:
```bash
# Backup was created by deploy script
cp /usr/local/bin/crowdsec-cf-sync.bak /usr/local/bin/crowdsec-cf-sync
systemctl start crowdsec-cf-sync
```

---

## 5. Cloudflare API errors

**Symptom**: `cf_api_errors` counter climbing; bans not appearing in CF firewall.

**Diagnose**:
```bash
curl -s http://127.0.0.1:8765/metrics | python3 -m json.tool | grep cf_api_errors
journalctl -u crowdsec-cf-sync | grep -i "cloudflare\|CF API\|cf_api"
```

**Common causes**:

| Cause | Fix |
|-------|-----|
| `CF_API_TOKEN` expired | Rotate token, update `/etc/systemd/system/crowdsec-cf-sync.service`, `systemctl daemon-reload && systemctl restart crowdsec-cf-sync` |
| CF zone quota (1000 rules) | Run `/usr/local/bin/crowdsec-cf-sync doctor`; reduce ban TTLs or increase cleanup frequency |
| CF API rate limit | Daemon self-limits; errors are transient — wait for next cycle |
| CF API outage | Monitor CF status page; daemon continues Lua sync in the meantime |

---

## 6. Events.jsonl full (dropped events)

**Symptom**: `dropped_events` counter climbing; Lua escalations not reaching Python.

**Diagnose**:
```bash
ls -lh /run/crowdsec-lua/events.jsonl
curl -s http://127.0.0.1:8091/crowdsec-status | python3 -c "
import sys,json; d=json.load(sys.stdin); print('dropped_events:', d['ipc']['dropped_events'])"
```

**Fix**: Python reads and truncates `events.jsonl` each cycle (every 60 s). If the file is permanently stuck above 1 MB, Python may have stopped reading it.

```bash
# Force clear (events in the file are lost)
sudo truncate -s 0 /run/crowdsec-lua/events.jsonl
```

---

## 7. IPC rejected loop

**Symptom**: `ipc_rejected` climbing without any corresponding sync failure; `sync.version` not advancing.

**Diagnose**:
```bash
# Check what's in bans.json
sudo python3 -c "
import json
with open('/run/crowdsec-lua/bans.json') as f:
    d = json.load(f)
import time
now = time.time()
epoch = d.get('updated_at_epoch', 0)
print(f'version: {d[\"version\"]}, age: {now-epoch:.0f}s, entries: {d[\"entry_count\"]}')
"
```

| Cause | Diagnosis | Fix |
|-------|-----------|-----|
| Clock skew > 600 s (stale) | `bans.json` age > 600 s | Fix NTP; restart daemon |
| Clock skew > 300 s (future) | `bans.json` epoch > now+300 | Fix NTP; restart daemon |
| Sequence guard (last_version stuck) | Python version < Lua last_version | `systemctl reload openresty` |

---

## Doctor command

Run a comprehensive health audit:

```bash
/usr/local/bin/crowdsec-cf-sync doctor
```

Checks: daemon status, WAL, state files, CF API, CrowdSec LAPI, Lua sync, dict memory, permissions, nginx config.

Exit codes: `0` = healthy, `1` = degraded (warnings), `2` = broken (failures).
