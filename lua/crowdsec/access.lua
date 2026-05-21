--[[
  crowdsec/access.lua — per-request entry point

  Called from access_by_lua_block in every vhost.
  Decision path (in order):

    1. Honeypot check  → instant deny + escalation event
    2. Verdict lookup  → shared dict only, O(1)
    3. Local heuristics → accumulate score (may upgrade verdict)
    4. Apply mitigation → ngx.exit() if action required

  Zero network I/O. Zero file I/O. Per-request overhead < 50µs typical.
--]]

local M          = {}
local cs         = require "crowdsec.init"
local lookup     = require "crowdsec.lookup"
local heuristics = require "crowdsec.heuristics"
local mitigation = require "crowdsec.mitigation"
local events     = require "crowdsec.events"

function M.check()
    local ip  = ngx.var.remote_addr
    if not ip or ip == "" then return end

    local uri    = ngx.var.request_uri or "/"
    local method = ngx.req.get_method()

    -- ── 1. Honeypot ───────────────────────────────────────────────────────────
    if heuristics.is_honeypot(uri) then
        cs.metrics:incr("honeypot_hits", 1, 0)
        -- Instant +100 and escalate to Python
        local verdict = lookup.add_heuristic_score(ip, 100, 3600)
        events.write("honeypot_hit", ip, verdict and verdict.score or 100, uri)
        ngx.exit(ngx.HTTP_FORBIDDEN)
        return
    end

    -- ── 2. Verdict lookup (Python-pushed bans) ────────────────────────────────
    local verdict = lookup.get_verdict(ip)
    if verdict and verdict.level >= cs.LEVEL_DENY then
        -- Fast path: known-bad IP, skip heuristics
        mitigation.apply(verdict, ip)
        return
    end

    -- ── 3. Local heuristics ───────────────────────────────────────────────────
    -- Get headers with a cap — avoids allocating huge tables for header-stuffing attacks
    local hdrs = ngx.req.get_headers(50, true)
    local delta = heuristics.score_request(ip, uri, method, hdrs)

    -- Re-fetch verdict if heuristics upgraded it
    if delta > 0 then
        local upgraded = lookup.get_verdict(ip)
        if upgraded and (not verdict or upgraded.level > verdict.level) then
            verdict = upgraded
        end
    end

    -- ── 4. Apply mitigation ───────────────────────────────────────────────────
    if verdict and verdict.level > cs.LEVEL_ALLOW then
        mitigation.apply(verdict, ip)
    end
end

return M
