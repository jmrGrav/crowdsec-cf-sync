--[[
  crowdsec/sync.lua — background file-based sync: bans.json → shared dict

  Python writes /run/crowdsec-lua/bans.json atomically every sync cycle.
  This module loads it into crowdsec_cache every SYNC_INTERVAL seconds
  via ngx.timer.every() so per-request lookups are pure shared dict reads.

  bans.json format (written by Python push_lua_state()):
  {
    "version": 42,
    "updated_at": "2026-05-22T01:07:00Z",
    "bans": {
      "1.2.3.4": {"score": 100, "level": 5, "ttl": 3600, "reason": "crowdsec-ban"}
    },
    "cidrs": {
      "5.6.7.0/24": {"score": 100, "level": 5, "ttl": 86400}
    }
  }

  CIDR layout:
    /24 → key "cidr24:<a.b.c>"
    /16 → key "cidr16:<a.b>"
  Lookup code checks exact → /24 → /16 in order (3 dict reads max).
--]]

local M     = {}
local cjson = require "cjson.safe"
local cs    = require "crowdsec.init"

local last_version = 0

-- ── CIDR prefix extractors ────────────────────────────────────────────────────

local function prefix24(cidr)
    local a, b, c = cidr:match("^(%d+)%.(%d+)%.(%d+)%.")
    if a then return a .. "." .. b .. "." .. c end
    return nil
end

local function prefix16(cidr)
    local a, b = cidr:match("^(%d+)%.(%d+)%.")
    if a then return a .. "." .. b end
    return nil
end

-- ── Core reload ───────────────────────────────────────────────────────────────

local function load_sync_file()
    local t0 = ngx.now()

    -- ── Dict saturation policy ────────────────────────────────────────────────
    --   Level 1 HEALTHY  : free_pct >= 10%    — normal operation
    --   Level 2 PRESSURE : free_pct < 10%     — suppress heuristic writes;
    --                                           existing verdicts preserved;
    --                                           set memory_pressure=1 flag
    --   Level 3 CRITICAL : free_bytes < 2 MB  — skip dict load entirely;
    --                                           no new verdicts; log WARN
    -- Thresholds: DICT_MIN_FREE=2MB (init.lua), MEM_PRESSURE_PCT=90% (init.lua)
    local cache = cs.cache
    local free_before = cache:free_space() or 0
    if free_before < cs.DICT_MIN_FREE then
        ngx.log(ngx.WARN,
            "[crowdsec:sync] component=sync event=skip_low_memory",
            " free_bytes=", free_before,
            " threshold=", cs.DICT_MIN_FREE)
        return
    end

    -- ── Memory pressure: soft-stop at MEM_PRESSURE_PCT% full ─────────────────
    -- Set a flag in state dict that access.lua reads to suppress heuristic writes.
    -- Suppressing new writes keeps the dict stable during sustained pressure.
    -- Rate-limit WARN to once per 60s to avoid log spam.
    local free_pct = (free_before / cs.CSCF_VERDICTS_SIZE) * 100
    local is_pressure = free_pct < (100 - cs.MEM_PRESSURE_PCT)
    cs.state:set("memory_pressure", is_pressure and 1 or 0, cs.SYNC_INTERVAL * 6)
    if is_pressure then
        cs.metrics:incr("memory_pressure_events", 1, 0)
        local last_warn = cs.state:get("mem_pressure_warn_ts") or 0
        if (ngx.time() - last_warn) > 60 then
            ngx.log(ngx.WARN,
                "[crowdsec:sync] component=sync event=memory_pressure",
                " free_bytes=", free_before,
                " free_pct=", string.format("%.1f", free_pct),
                " threshold_pct=", 100 - cs.MEM_PRESSURE_PCT)
            cs.state:set("mem_pressure_warn_ts", ngx.time(), 300)
        end
    end

    local f, ferr = io.open(cs.SYNC_FILE, "r")
    if not f then
        -- File absent at first boot is normal; Python writes it after first cycle
        ngx.log(ngx.DEBUG, "[crowdsec:sync] file not found: ", ferr)
        return
    end

    local content = f:read("*a")
    f:close()

    if not content or content == "" then return end

    -- ── Payload size guard: reject before JSON parse ──────────────────────────
    -- A corrupted or injected bans.json could be arbitrarily large.
    -- We check #content (bytes) before allocating a parse tree.
    if #content > cs.BANS_JSON_MAX_BYTES then
        ngx.log(ngx.WARN,
            "[crowdsec:sync] component=sync event=payload_too_large",
            " size_bytes=", #content,
            " limit_bytes=", cs.BANS_JSON_MAX_BYTES)
        cs.metrics:incr("ipc_rejected", 1, 0)
        return
    end

    local data, perr = cjson.decode(content)
    if not data then
        ngx.log(ngx.WARN,
            "[crowdsec:sync] component=sync event=parse_error error=", tostring(perr),
            " size_bytes=", #content)
        cs.metrics:incr("ipc_rejected", 1, 0)
        return
    end

    -- ── Sequence guard: ignore stale or replayed files ────────────────────────
    local ver = tonumber(data.version) or 0
    if ver <= last_version then return end

    -- ── Timestamp validation: reject stale or future-dated files ─────────────
    -- Python writes updated_at_epoch (Unix seconds) alongside the ISO string.
    -- Stale files indicate a snapshot restore or paused Python daemon.
    -- Future-dated files indicate severe clock skew on the Python side.
    local uat = tonumber(data.updated_at_epoch)
    if uat then
        local now = ngx.time()
        local age = now - uat
        if age > cs.BANS_STALE_SECS then
            ngx.log(ngx.WARN,
                "[crowdsec:sync] component=sync event=ipc_stale_file",
                " age_secs=", age,
                " limit=", cs.BANS_STALE_SECS,
                " version=", ver)
            cs.metrics:incr("ipc_rejected", 1, 0)
            return
        end
        if (uat - now) > cs.BANS_FUTURE_SECS then
            ngx.log(ngx.WARN,
                "[crowdsec:sync] component=sync event=ipc_future_timestamp",
                " delta_secs=", uat - now,
                " limit=", cs.BANS_FUTURE_SECS,
                " version=", ver)
            cs.metrics:incr("ipc_rejected", 1, 0)
            return
        end
    end

    local metrics = cs.metrics
    local state   = cs.state

    -- ── Field type validation ──────────────────────────────────────────────────
    -- Explicit type checks at the trust boundary. data comes from an external
    -- file; malformed fields would silently produce wrong verdicts if accepted.
    if type(data.bans)  ~= "table" and data.bans  ~= nil then
        ngx.log(ngx.WARN, "[crowdsec:sync] component=sync event=field_type_error field=bans")
        return
    end
    if type(data.cidrs) ~= "table" and data.cidrs ~= nil then
        ngx.log(ngx.WARN, "[crowdsec:sync] component=sync event=field_type_error field=cidrs")
        return
    end

    local bans  = data.bans  or {}
    local cidrs = data.cidrs or {}

    -- ── Entry count integrity check ────────────────────────────────────────────
    -- Python writes "entry_count": len(bans) + len(cidrs)
    -- Counts parsed entries; mismatch → truncated/partial file → reject.
    local expected = tonumber(data.entry_count)
    if expected then
        local actual_bans  = 0; for _ in pairs(bans)  do actual_bans  = actual_bans  + 1 end
        local actual_cidrs = 0; for _ in pairs(cidrs) do actual_cidrs = actual_cidrs + 1 end
        local actual = actual_bans + actual_cidrs
        if actual ~= expected then
            ngx.log(ngx.WARN,
                "[crowdsec:sync] component=sync event=integrity_fail",
                " expected=", expected, " got=", actual, " version=", ver)
            return
        end
    end

    -- Accept this version
    last_version = ver
    local loaded = 0
    local evicted = 0  -- set() failures due to full dict

    -- ── Flush stale dict entries to free memory (periodic) ────────────────────
    cache:flush_expired()

    -- ── Individual IP bans ────────────────────────────────────────────────────
    for ip, info in pairs(bans) do
        if type(info) ~= "table" then goto continue_bans end  -- skip malformed entry
        local score  = math.max(0, math.min(100000, tonumber(info.score)  or 100))
        local level  = math.max(0, math.min(cs.LEVEL_DENY, tonumber(info.level) or cs.score_to_level(score)))
        local ttl    = math.max(1, math.min(86400 * 7, tonumber(info.ttl) or 3600))

        -- Don't downgrade an IP that heuristics escalated beyond Python's level
        local existing = cs.decode_verdict(cache:get("ip:" .. ip))
        if not existing or existing.level <= level then
            local ok, serr, sforced = cache:set("ip:" .. ip, level .. ":" .. score .. ":p", ttl)
            if not ok then
                -- Dict full: set() failed — entry not stored
                evicted = evicted + 1
            end
        end
        loaded = loaded + 1
        ::continue_bans::
    end

    -- ── CIDR bans ─────────────────────────────────────────────────────────────
    for cidr, info in pairs(cidrs) do
        if type(info) ~= "table" then goto continue_cidrs end
        local score = math.max(0, math.min(100000, tonumber(info.score) or 100))
        local level = math.max(0, math.min(cs.LEVEL_DENY, tonumber(info.level) or 5))
        local ttl   = math.max(1, math.min(86400 * 30, tonumber(info.ttl) or 86400))
        local val   = level .. ":" .. score .. ":p"

        local p24 = prefix24(cidr)
        if p24 then
            local ok, _ = cache:set("cidr24:" .. p24, val, ttl)
            if not ok then evicted = evicted + 1 end
            loaded = loaded + 1
        else
            local p16 = prefix16(cidr)
            if p16 then
                local ok, _ = cache:set("cidr16:" .. p16, val, ttl)
                if not ok then evicted = evicted + 1 end
                loaded = loaded + 1
            end
        end
        ::continue_cidrs::
    end

    -- ── Update sync metadata ──────────────────────────────────────────────────
    state:set("sync_version", ver)
    state:set("sync_ts",      ngx.time())
    state:set("sync_entries", loaded)

    metrics:set("lua_cache_entries", loaded)
    metrics:incr("lua_syncs", 1, 0)
    if evicted > 0 then
        metrics:incr("dict_set_failures", evicted, 0)
        ngx.log(ngx.WARN,
            "[crowdsec:sync] component=sync event=dict_full",
            " failed_sets=", evicted,
            " version=", ver)
    end

    -- Dict health metrics
    local free_after = cache:free_space()
    if free_after then metrics:set("cache_free_bytes", free_after) end

    local dt_ms = math.floor((ngx.now() - t0) * 1000)
    metrics:set("sync_duration_ms", dt_ms)

    -- ── Python daemon meta counters ───────────────────────────────────────────
    -- Python writes a "meta" section with its own operational counters.
    -- Store them in the metrics dict so they appear in /crowdsec-status and
    -- /crowdsec-metrics without requiring a separate HTTP call to port 8765.
    local meta = data.meta
    if meta then
        if meta.cycle_count     then metrics:set("py_cycle_count",    tonumber(meta.cycle_count)    or 0) end
        if meta.cf_api_errors   then metrics:set("py_cf_api_errors",  tonumber(meta.cf_api_errors)  or 0) end
        if meta.wal_entries     then metrics:set("py_wal_entries",    tonumber(meta.wal_entries)    or 0) end
        if meta.lua_sync_errors then metrics:set("py_lua_sync_errors",tonumber(meta.lua_sync_errors)or 0) end
        -- degraded: store as 1/0 for Prometheus compatibility
        if meta.degraded ~= nil then
            metrics:set("py_degraded", meta.degraded and 1 or 0)
        end
    end

    local log_level = evicted > 0 and ngx.WARN or ngx.INFO
    ngx.log(log_level,
        "[crowdsec:sync] component=sync event=reload",
        " version=", ver,
        " entries=", loaded,
        " failed=", evicted,
        " duration_ms=", dt_ms,
        " free_bytes=", free_after or "?",
        " status=", evicted > 0 and "partial" or "ok")
end

-- ── Public init ───────────────────────────────────────────────────────────────
-- Call from init_worker_by_lua_block once per worker.

function M.start()
    -- Immediate load (don't wait for first timer tick)
    local ok, err = pcall(load_sync_file)
    if not ok then
        ngx.log(ngx.WARN, "[crowdsec:sync] initial load failed: ", err)
    end

    -- Recurring background timer
    local ok2, err2 = ngx.timer.every(cs.SYNC_INTERVAL, function(premature)
        if premature then return end
        local ok3, err3 = pcall(load_sync_file)
        if not ok3 then
            ngx.log(ngx.WARN, "[crowdsec:sync] periodic load failed: ", err3)
        end
    end)

    if not ok2 then
        ngx.log(ngx.ERR, "[crowdsec:sync] ngx.timer.every failed: ", err2)
    end
end

return M
