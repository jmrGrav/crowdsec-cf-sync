# Install Matrix

Compatibility table for crowdsec-cf-sync V3.3.x on different OpenResty variants and with the CrowdSec official bouncer.

## OpenResty variants

| Variant | Status | Notes |
|---------|--------|-------|
| OpenResty from openresty.org package | ✅ Supported | Tested on OpenResty/1.29.2.4. `lua_package_path` must include `/etc/openresty/lua` |
| OpenResty from Ubuntu/Debian apt | ✅ Supported | Same as above; paths may differ (`/usr/local/openresty/`) |
| nginx + lua-nginx-module (luarocks) | ⚠️ Untested | Should work; `lua_package_path` must point to module directory |
| Nginx without Lua support | ❌ Not supported | Lua data plane requires `ngx_http_lua_module` |

## CrowdSec bouncer coexistence

The official `crowdsec-openresty-bouncer` uses a `crowdsec_cache` shared dict and the `cs` global table. Our layer uses separate dicts (`cscf_verdicts`, `crowdsec_metrics`, `crowdsec_state`) and the `crowdsec.*` module namespace, so they do not conflict.

| Scenario | Status | Notes |
|----------|--------|-------|
| With `crowdsec-openresty-bouncer` active | ✅ Compatible | Both init blocks coexist in `init_by_lua_block`. Order: bouncer first, then our `require "crowdsec.init"` block |
| Without the official bouncer | ✅ Supported | Our layer is self-contained |
| Both layers checking the same request | ✅ Safe | Each layer has its own dict and module namespace; no shared state |

### `init_by_lua_block` ordering

The `crowdsec_openresty.conf` loads both layers in the correct order:

```nginx
init_by_lua_block {
    -- 1. Official bouncer (uses cs global, crowdsec_cache dict)
    cs = require "crowdsec"
    cs.init("/etc/crowdsec/bouncers/crowdsec-openresty-bouncer.conf", "...")

    -- 2. CF Sync custom layer (uses crowdsec.* namespace, separate dicts)
    require "crowdsec.init"
    require "crowdsec.lookup"
    require "crowdsec.heuristics"
    require "crowdsec.mitigation"
    require "crowdsec.tarpit"
    require "crowdsec.events"
    require "crowdsec.access"
    require "crowdsec.metrics"
}
```

### `init_worker_by_lua_block`

The background sync timer is started here:

```nginx
init_worker_by_lua_block {
    cs = require "crowdsec"
    require("crowdsec.sync").start()
}
```

## Python requirements

| Dependency | Version | Source |
|------------|---------|--------|
| Python | ≥ 3.10 | stdlib: `zlib`, `socket`, `json`, `subprocess`, `pathlib` |
| All runtime deps | stdlib only | No pip packages required |

Tested on Python 3.12.3 (Ubuntu 24.04).

## CrowdSec LAPI

| Version | Status | Notes |
|---------|--------|-------|
| CrowdSec ≥ 1.5.x | ✅ Supported | Uses `/v1/decisions` endpoint |
| CrowdSec 1.7.8 | ✅ Tested (production) | `?origin=` filter has a 25 s+ timeout bug (known). Workaround: fetch-all + filter in Python |
| CrowdSec < 1.5 | ❌ Unknown | Untested |

## Cloudflare

| Plan | Firewall rules limit | Notes |
|------|---------------------|-------|
| Free | 5 rules (non-Ruleset) / 1000 custom rules | CF Sync uses Custom Firewall Rules via the Ruleset API |
| Pro | 20 rules (non-Ruleset) / 1000 custom rules | |
| Business / Enterprise | Higher limits | |

The daemon tracks rule count and warns at 70% / 85% / 95% of the 1000-rule limit.

## Systemd hardening

The unit file enforces:

```ini
NoNewPrivileges=yes
ProtectSystem=strict
PrivateTmp=yes
RuntimeDirectory=crowdsec-lua
RuntimeDirectoryMode=0775
```

`RuntimeDirectory=crowdsec-lua` creates `/run/crowdsec-lua/` at boot with mode 775, group www-data (the OpenResty worker user). This directory is automatically removed on service stop.

## Upgrade path (V3.3.x → V3.3.x+1)

1. Verify syntax: `python3 -m py_compile /tmp/crowdsec-cf-syncV3.py`
2. Backup: `cp /usr/local/bin/crowdsec-cf-syncV3.py /usr/local/bin/crowdsec-cf-syncV3.py.bak`
3. Deploy Python: `cp /tmp/crowdsec-cf-syncV3.py /usr/local/bin/`
4. Deploy Lua (if changed): `cp lua/crowdsec/*.lua /etc/openresty/lua/crowdsec/`
5. Reload OpenResty: `systemctl reload openresty` — resets `last_version=0` in Lua
6. Restart daemon: `systemctl restart crowdsec-cf-sync`
7. Verify: `curl -s http://127.0.0.1:8091/crowdsec-status | python3 -m json.tool`
8. Check: `python3 /usr/local/bin/crowdsec-cf-syncV3.py doctor`
