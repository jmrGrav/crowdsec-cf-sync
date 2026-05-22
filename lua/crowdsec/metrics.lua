--[[
  crowdsec/metrics.lua — /crowdsec-status JSON debug endpoint + /crowdsec-metrics Prometheus

  Accessible only from 127.0.0.1 (enforce in nginx config).
  Returns current shared dict state + all counters.
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

    -- Cache hit ratio (avoid division by zero)
    local hits   = g("cache_hits")
    local misses = g("cache_misses")
    local total_lookups = hits + misses
    local hit_ratio = total_lookups > 0 and
        string.format("%.3f", hits / total_lookups) or "n/a"

    -- Memory pressure state
    local mem_pressure_active = s("memory_pressure") == 1
    local cache_free_pct = cache_free and
        string.format("%.1f", (cache_free / cs.CSCF_VERDICTS_SIZE) * 100) or "?"

    local data = {
        ts        = ngx.now(),
        worker_id = ngx.worker.id(),

        -- Sync state
        sync = {
            version      = s("sync_version"),
            ts           = s("sync_ts"),
            entries      = s("sync_entries"),
            duration_ms  = g("sync_duration_ms"),
        },

        -- Memory
        memory = {
            pressure_active       = mem_pressure_active,
            pressure_events_total = g("memory_pressure_events"),
            cache_free_bytes      = cache_free,
            cache_free_pct        = cache_free_pct,
            metrics_free_bytes    = metrics_free,
            state_free_bytes      = state_free,
        },

        -- IPC integrity counters
        ipc = {
            rejected_total   = g("ipc_rejected"),
            dict_set_failures= g("dict_set_failures"),
            dropped_events   = g("dropped_events"),
        },

        -- Tarpit concurrency
        tarpit = {
            active  = s("tarpit_active") or 0,
            total   = g("tarpit_total"),
            skipped = g("tarpit_skipped"),
        },

        -- Mitigation breakdown
        mitigation = {
            total_checks    = g("total_checks"),
            allows          = g("level_0_hits"),
            rate_limits     = g("ratelimit_drops"),
            tarpits         = g("tarpits"),
            challenges      = g("challenges"),
            captchas        = g("captchas"),
            denies          = g("denies"),
            escalations     = g("escalations"),
            stale_checks    = g("sync_stale_checks"),
        },

        -- Cache performance
        cache = {
            hits            = hits,
            misses          = misses,
            hit_ratio       = hit_ratio,
            entries         = g("lua_cache_entries"),
            evictions       = g("dict_set_failures"),
        },

        -- Heuristic signals
        heuristics = {
            total_hits          = g("heuristic_hits"),
            honeypot_hits       = g("honeypot_hits"),
            ua_hits             = g("ua_hits"),
            header_anomaly_hits = g("header_anomaly_hits"),
            path_hits           = g("path_hits"),
            burst_hits          = g("burst_hits"),
        },

        -- Python daemon counters (pushed via bans.json meta section)
        python = {
            cycle_count      = g("py_cycle_count"),
            cf_api_errors    = g("py_cf_api_errors"),
            wal_entries      = g("py_wal_entries"),
            lua_sync_errors  = g("py_lua_sync_errors"),
            degraded         = g("py_degraded") == 1,
        },

        -- Raw counters (kept for backwards compat)
        counters = {
            lua_syncs         = g("lua_syncs"),
            lua_cache_entries = g("lua_cache_entries"),
            cache_free_bytes  = g("cache_free_bytes"),
        },
    }

    ngx.header["Content-Type"] = "application/json"
    ngx.header["Cache-Control"] = "no-store"
    ngx.say(cjson.encode(data))
end

-- ── Prometheus text format handler (/crowdsec-metrics) ────────────────────────
function M.handle_prometheus()
    local lines = {}
    local function add(name, val, help, typ)
        if help then
            table.insert(lines, "# HELP " .. name .. " " .. help)
            table.insert(lines, "# TYPE " .. name .. " " .. (typ or "counter"))
        end
        table.insert(lines, name .. " " .. tostring(val or 0))
    end

    -- Sync
    add("crowdsec_lua_syncs_total",          g("lua_syncs"),          "Total Lua state syncs from Python")
    add("crowdsec_lua_sync_duration_ms",     g("sync_duration_ms"),   "Last bans.json reload duration (ms)", "gauge")
    add("crowdsec_lua_sync_stale_checks",    g("sync_stale_checks"),  "Requests processed in stale/deadman mode")

    -- Cache
    add("crowdsec_lua_cache_entries",        g("lua_cache_entries"),  "Current entries in Lua verdict cache", "gauge")
    add("crowdsec_lua_cache_hits_total",     g("cache_hits"),         "Total verdict cache hits")
    add("crowdsec_lua_cache_misses_total",   g("cache_misses"),       "Total verdict cache misses")
    add("crowdsec_lua_cache_free_bytes",     g("cache_free_bytes"),   "Verdict dict free space (bytes)", "gauge")

    -- Memory pressure
    add("crowdsec_lua_memory_pressure_active",
        s("memory_pressure") == 1 and 1 or 0,
        "1 when cscf_verdicts > MEM_PRESSURE_PCT% full", "gauge")
    add("crowdsec_lua_memory_pressure_events_total",
        g("memory_pressure_events"),
        "Sync cycles that detected memory pressure")

    -- Mitigation
    add("crowdsec_lua_total_checks_total",   g("total_checks"),       "Total requests entering Lua check")
    add("crowdsec_lua_heuristic_hits_total", g("heuristic_hits"),     "Total heuristic scoring events")
    add("crowdsec_lua_honeypot_hits_total",  g("honeypot_hits"),      "Total honeypot path hits")
    add("crowdsec_lua_escalations_total",    g("escalations"),        "Total Lua→Python escalation events")
    add("crowdsec_lua_tarpit_total",         g("tarpit_total"),       "Total tarpitted requests")
    add("crowdsec_lua_tarpit_skipped_total", g("tarpit_skipped"),     "Tarpit skipped (concurrency limit)")
    add("crowdsec_lua_denies_total",         g("denies"),             "Total hard denies (403/444)")
    add("crowdsec_lua_challenges_total",     g("challenges"),         "Total JS challenge responses")
    add("crowdsec_lua_ratelimit_drops_total",g("ratelimit_drops"),    "Total rate-limit drops")

    -- Heuristic signals
    add("crowdsec_lua_ua_hits_total",           g("ua_hits"),            "Requests scoring by User-Agent analysis")
    add("crowdsec_lua_header_anomaly_hits_total",g("header_anomaly_hits"),"Requests scoring by header anomaly")
    add("crowdsec_lua_path_hits_total",         g("path_hits"),          "Requests scoring by sensitive path")
    add("crowdsec_lua_burst_hits_total",        g("burst_hits"),         "Requests scoring by burst detection")

    -- IPC integrity
    add("crowdsec_lua_ipc_rejected_total",   g("ipc_rejected"),       "IPC payloads rejected (size/parse/integrity/timestamp)")
    add("crowdsec_lua_dict_set_failures",    g("dict_set_failures"),  "Dict set() failures (memory full)")
    add("crowdsec_lua_dropped_events_total", g("dropped_events"),     "Events dropped (events.jsonl size limit)")

    -- Python daemon metrics (via bans.json meta)
    add("crowdsec_py_cycle_count",           g("py_cycle_count"),     "Python daemon sync cycles", "gauge")
    add("crowdsec_py_cf_api_errors_total",   g("py_cf_api_errors"),   "Python CF API errors")
    add("crowdsec_py_wal_entries_total",     g("py_wal_entries"),     "Python WAL entries written")
    add("crowdsec_py_lua_sync_errors_total", g("py_lua_sync_errors"), "Python Lua push errors")
    add("crowdsec_py_degraded",
        g("py_degraded") == 1 and 1 or 0,
        "1 when Python daemon is in degraded mode", "gauge")

    ngx.header["Content-Type"] = "text/plain; version=0.0.4"
    ngx.say(table.concat(lines, "\n") .. "\n")
end

return M
