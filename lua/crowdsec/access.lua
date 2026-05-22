--[[
  crowdsec/access.lua — per-request entry point

  Called from access_by_lua_block in every vhost.
  Decision path (in order):

    1. Honeypot check   → instant deny + escalation event
    2. Deadman check    → if sync stale, suspend soft mitigations
    3. Verdict lookup   → shared dict only, O(1)
    4. Local heuristics → accumulate score (skipped when stale)
    5. Apply mitigation → ngx.exit() if action required

  Entire check() is wrapped in pcall: any Lua/module error is logged and
  the request passes (fail-open). This ensures nginx never hard-errors on
  a module bug or shared dict unavailability.

  Zero network I/O. Zero file I/O. Per-request overhead < 50µs typical.
--]]

local M          = {}
local cs         = require "crowdsec.init"
local lookup     = require "crowdsec.lookup"
local heuristics = require "crowdsec.heuristics"
local mitigation = require "crowdsec.mitigation"
local events     = require "crowdsec.events"

-- ── Deadman check ─────────────────────────────────────────────────────────────
-- Returns true if the last successful sync is older than DEADMAN_SECS.
-- Stale mode: restrict mitigation to hard denies (level 5) only.
-- Tarpits and challenges on stale data waste resources and risk false-positives.
local function sync_is_stale()
    local ts = cs.state:get("sync_ts")
    if not ts then return true end
    return (ngx.time() - ts) > cs.DEADMAN_SECS
end

function M.check()
    local ok, err = pcall(function()

        local ip = ngx.var.remote_addr
        if not ip or ip == "" then return end

        local uri    = ngx.var.request_uri or "/"
        local method = ngx.req.get_method()

        -- ── 1. Honeypot ───────────────────────────────────────────────────────
        if heuristics.is_honeypot(uri) then
            cs.metrics:incr("honeypot_hits", 1, 0)
            local verdict = lookup.add_heuristic_score(ip, 100, 3600)
            events.write("honeypot_hit", ip, verdict and verdict.score or 100, uri)
            ngx.exit(ngx.HTTP_FORBIDDEN)
            return
        end

        -- ── 2. Deadman check ──────────────────────────────────────────────────
        local stale = sync_is_stale()
        if stale then
            cs.metrics:incr("sync_stale_checks", 1, 0)
        end

        -- ── 3. Verdict lookup (Python-pushed bans) ────────────────────────────
        local verdict = lookup.get_verdict(ip)
        if verdict and verdict.level >= cs.LEVEL_DENY then
            -- Hard deny always applies, even in stale mode
            mitigation.apply(verdict, ip)
            return
        end

        -- ── 4. Local heuristics (suspended in stale mode) ────────────────────
        -- Skip when sync is stale to avoid false-positives from outdated scoring.
        if not stale then
            local hdrs = ngx.req.get_headers(50, true)
            local delta = heuristics.score_request(ip, uri, method, hdrs)

            if delta > 0 then
                local upgraded = lookup.get_verdict(ip)
                if upgraded and (not verdict or upgraded.level > verdict.level) then
                    verdict = upgraded
                end
            end
        end

        -- ── 5. Apply mitigation ───────────────────────────────────────────────
        if verdict and verdict.level > cs.LEVEL_ALLOW then
            if stale and verdict.level < cs.LEVEL_DENY then
                return  -- soft verdicts (tarpit/challenge) suspended in stale mode
            end
            mitigation.apply(verdict, ip)
        end

    end)

    if not ok then
        ngx.log(ngx.ERR,
            "[crowdsec:access] component=access event=error status=fail_open error=", tostring(err))
    end
end

return M
