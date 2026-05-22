--[[
  crowdsec/metrics.lua — /crowdsec-status JSON debug endpoint

  Accessible only from 127.0.0.1 (enforce in nginx config).
  Returns current shared dict state + all counters.

  Metrics logged here are also useful for Prometheus scraping if you
  forward this endpoint to a metrics exporter or add a /metrics path.
--]]

local M     = {}
local cjson = require "cjson"
local cs    = require "crowdsec.init"

local function g(key)  return cs.metrics:get(key) or 0 end
local function s(key)  return cs.state:get(key) end

function M.handle()
    local cache = cs.cache

    -- Dict health
    local cache_free   = cache:free_space()
    local metrics_free = cs.metrics:free_space()
    local state_free   = cs.state:free_space()

    local data = {
        ts            = ngx.now(),
        worker_id     = ngx.worker.id(),
        -- Sync metadata
        sync = {
            version = s("sync_version"),
            ts      = s("sync_ts"),
            entries = s("sync_entries"),
        },
        -- Tarpit
        tarpit_active = s("tarpit_active") or 0,
        -- Dict health (bytes free)
        dict_health = {
            cscf_verdicts_free    = cache_free,
            crowdsec_metrics_free = metrics_free,
            crowdsec_state_free   = state_free,
        },
        -- Counters
        counters = {
            lua_syncs         = g("lua_syncs"),
            lua_cache_entries = g("lua_cache_entries"),
            cache_free_bytes  = g("cache_free_bytes"),
            heuristic_hits    = g("heuristic_hits"),
            honeypot_hits     = g("honeypot_hits"),
            escalations       = g("escalations"),
            tarpit_total      = g("tarpit_total"),
            tarpit_skipped    = g("tarpit_skipped"),
            tarpits           = g("tarpits"),
            denies            = g("denies"),
            challenges        = g("challenges"),
            captchas          = g("captchas"),
            ratelimit_drops   = g("ratelimit_drops"),
            -- Per-level
            level_0_hits      = g("level_0_hits"),
            level_1_hits      = g("level_1_hits"),
            level_2_hits      = g("level_2_hits"),
            level_3_hits      = g("level_3_hits"),
            level_4_hits      = g("level_4_hits"),
            level_5_hits      = g("level_5_hits"),
        },
    }

    ngx.header["Content-Type"] = "application/json"
    ngx.header["Cache-Control"] = "no-store"
    ngx.say(cjson.encode(data))
end

-- Prometheus text format handler (/crowdsec-metrics)
function M.handle_prometheus()
    local lines = {}
    local function add(name, val, help)
        if help then
            table.insert(lines, "# HELP " .. name .. " " .. help)
            table.insert(lines, "# TYPE " .. name .. " counter")
        end
        table.insert(lines, name .. " " .. tostring(val or 0))
    end

    add("crowdsec_lua_syncs_total",         g("lua_syncs"),         "Total Lua state syncs from Python")
    add("crowdsec_lua_cache_entries",        g("lua_cache_entries"), "Current entries in Lua verdict cache")
    add("crowdsec_lua_heuristic_hits_total", g("heuristic_hits"),    "Total heuristic scoring events")
    add("crowdsec_lua_honeypot_hits_total",  g("honeypot_hits"),     "Total honeypot path hits")
    add("crowdsec_lua_escalations_total",    g("escalations"),       "Total Lua→Python escalation events")
    add("crowdsec_lua_tarpit_total",         g("tarpit_total"),      "Total tarpitted requests")
    add("crowdsec_lua_tarpit_skipped_total", g("tarpit_skipped"),    "Tarpit skipped (concurrency limit)")
    add("crowdsec_lua_denies_total",         g("denies"),            "Total hard denies (403/444)")
    add("crowdsec_lua_challenges_total",     g("challenges"),        "Total JS challenge responses")
    add("crowdsec_lua_ratelimit_drops_total",g("ratelimit_drops"),   "Total rate-limit drops")

    ngx.header["Content-Type"] = "text/plain; version=0.0.4"
    ngx.say(table.concat(lines, "\n") .. "\n")
end

return M
