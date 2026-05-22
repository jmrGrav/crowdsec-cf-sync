# Runtime Layout

Directory and file inventory for production deployment on OpenResty.
Run `openresty -T 2>/dev/null | grep "configuration file"` to see all active config files.

## IPC directory

```
/run/crowdsec-lua/          drwxrwxr-x root www-data
  bans.json                 -rw-r--r-- root root  (written by Python, read by Lua)
  events.jsonl              -rw-r--r-- root root  (written by Lua, read by Python)
```

`/run/` is a tmpfs; the directory is re-created by the systemd unit (`RuntimeDirectory=crowdsec-lua`) on each boot.

## Python daemon

```
/usr/local/bin/crowdsec-cf-syncV3.py    executable, root
/etc/systemd/system/crowdsec-cf-sync.service
```

State files (survives across restarts):
```
/var/lib/crowdsec-cf-sync/
  recidiv_state.json        # per-IP offence history
  modsec_state.json         # ModSecurity escalation cache
  cidr_state.json           # banned CIDR blocks
  wal.jsonl                 # WAL — one CF action per line
```

Health / metrics port: `127.0.0.1:8765` (`/health`, `/metrics`).

## Lua modules

```
/etc/openresty/lua/crowdsec/
  init.lua        # constants, shared dict handles, verdict codec
  sync.lua        # background timer — bans.json → dicts
  access.lua      # per-request entry point
  lookup.lua      # verdict dict read + CIDR prefix fallback
  heuristics.lua  # UA / header / path / burst scoring
  mitigation.lua  # tarpit / challenge / deny / allow
  events.lua      # escalation event append
  metrics.lua     # /crowdsec-status + /crowdsec-metrics handlers
  tarpit.lua      # tarpit sleep implementation
```

On dual-path installs (OpenResty from package + from source), files are mirrored:
```
/usr/local/openresty/nginx/conf/lua/crowdsec/   (same files)
```

The `lua_package_path` in `crowdsec_openresty.conf` controls which path is searched first.

## OpenResty configuration files

```
/etc/openresty/conf.d/
  crowdsec_openresty.conf     # lua_package_path, init_by_lua_block, init_worker_by_lua_block
  crowdsec_shared_dicts.conf  # lua_shared_dict declarations (cscf_verdicts, crowdsec_metrics, crowdsec_state)
  default.conf                # default_server returning 444

/usr/local/openresty/nginx/conf/snippets/
  crowdsec_access.conf        # access_by_lua_block { require("crowdsec.access").check() }
  crowdsec_status.conf        # server { listen 127.0.0.1:8091; /crowdsec-status; /crowdsec-metrics }
```

Per-vhost: `include snippets/crowdsec_access.conf;` inside each `server {}` block to enable enforcement.

## Shared dict declarations

```nginx
# /etc/openresty/conf.d/crowdsec_shared_dicts.conf
lua_shared_dict cscf_verdicts    50m;   # verdict cache
lua_shared_dict crowdsec_metrics 10m;   # counters
lua_shared_dict crowdsec_state    5m;   # flags (sync_ts, memory_pressure, …)
```

Sizes must match constants in `init.lua` (`CSCF_VERDICTS_SIZE = 52428800`).

## Status / metrics server

```nginx
# /usr/local/openresty/nginx/conf/snippets/crowdsec_status.conf
server {
    listen 127.0.0.1:8091;
    location = /crowdsec-status  { content_by_lua_block { require("crowdsec.metrics").handle() } }
    location = /crowdsec-metrics { content_by_lua_block { require("crowdsec.metrics").handle_prometheus() } }
}
```

Accessible only from loopback. Verify port: `openresty -T | grep -A2 'crowdsec-status'`.

## Permissions summary

| Path | Owner | Mode | Why |
|------|-------|------|-----|
| `/run/crowdsec-lua/` | root:www-data | 775 | Python writes, OpenResty (www-data) reads |
| `/run/crowdsec-lua/bans.json` | root:root | 644 | Readable by www-data |
| `/run/crowdsec-lua/events.jsonl` | root:root | 644 | Written by Lua workers via `ngx.shared` |
| `/etc/openresty/lua/crowdsec/*.lua` | root:root | 644 | Read at `init_by_lua_block` |
| `/usr/local/bin/crowdsec-cf-syncV3.py` | root:root | 755 | Run as root |

## OpenResty reload vs restart

| Operation | Effect on Lua |
|-----------|--------------|
| `systemctl reload openresty` | Workers soft-restart; `last_version` resets to 0; dicts preserved |
| `systemctl restart openresty` | Full restart; all shared dicts cleared |

After restarting the Python daemon without reloading OpenResty: Python's `_lua_sync_version` resets to 1, but Lua's `last_version` still holds the last accepted version. The sequence guard will silently reject Python's pushes until version catches up. **Always run `systemctl reload openresty` after restarting the Python daemon.**
