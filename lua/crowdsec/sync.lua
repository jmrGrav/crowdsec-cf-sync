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
    local f, ferr = io.open(cs.SYNC_FILE, "r")
    if not f then
        -- File absent at first boot is normal; Python writes it after first cycle
        ngx.log(ngx.DEBUG, "[crowdsec:sync] file not found: ", ferr)
        return
    end

    local content = f:read("*a")
    f:close()

    if not content or content == "" then return end

    local data, perr = cjson.decode(content)
    if not data then
        ngx.log(ngx.WARN, "[crowdsec:sync] JSON parse error: ", perr)
        return
    end

    -- ── Sequence guard: ignore stale or replayed files ────────────────────────
    local ver = tonumber(data.version) or 0
    if ver <= last_version then return end

    local cache   = cs.cache
    local metrics = cs.metrics
    local state   = cs.state

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
            ngx.log(ngx.WARN, "[crowdsec:sync] integrity check failed: expected ",
                    expected, " entries, got ", actual, " — rejecting version ", ver)
            return
        end
    end

    -- Accept this version
    last_version = ver
    local loaded = 0

    -- ── Flush stale dict entries to free memory (periodic) ────────────────────
    cache:flush_expired()

    -- ── Individual IP bans ────────────────────────────────────────────────────
    for ip, info in pairs(bans) do
        local score  = tonumber(info.score)  or 100
        local level  = tonumber(info.level)  or cs.score_to_level(score)
        local ttl    = tonumber(info.ttl)    or 3600
        local source = info.reason           or "python"

        -- Don't downgrade an IP that heuristics escalated beyond Python's level
        local existing = cs.decode_verdict(cache:get("ip:" .. ip))
        if not existing or existing.level <= level then
            -- Extended compact format: "level:score:src"
            cache:set("ip:" .. ip, level .. ":" .. score .. ":p", ttl)
        end
        loaded = loaded + 1
    end

    -- ── CIDR bans ─────────────────────────────────────────────────────────────
    for cidr, info in pairs(cidrs) do
        local score = tonumber(info.score) or 100
        local level = tonumber(info.level) or 5
        local ttl   = tonumber(info.ttl)   or 86400
        local val   = level .. ":" .. score .. ":p"

        local p24 = prefix24(cidr)
        if p24 then
            cache:set("cidr24:" .. p24, val, ttl)
            loaded = loaded + 1
        else
            local p16 = prefix16(cidr)
            if p16 then
                cache:set("cidr16:" .. p16, val, ttl)
                loaded = loaded + 1
            end
        end
    end

    -- ── Update sync metadata ──────────────────────────────────────────────────
    state:set("sync_version", ver)
    state:set("sync_ts",      ngx.time())
    state:set("sync_entries", loaded)

    metrics:set("lua_cache_entries", loaded)
    metrics:incr("lua_syncs", 1, 0)

    -- Dict health metric (bytes remaining before eviction)
    local free = cache:free_space()
    if free then metrics:set("cache_free_bytes", free) end

    ngx.log(ngx.INFO, "[crowdsec:sync] loaded ", loaded,
            " entries (version ", ver, ", free=", free or "?", "B)")
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
