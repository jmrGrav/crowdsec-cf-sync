--[[
  crowdsec/access.lua — per-request entry point

  Called from access_by_lua_block in every vhost.
  Decision path (in order):

    0. Internal guards  → crowdsec_error_page loop prevention
    0b. Captcha cookie  → if valid, enforce hard LAPI denies then allow
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

        -- crowdsec_error_page=1 is set by the /crowdsec-ban-page internal location.
        -- Skipping here prevents an access→error_page→access loop: when an IP is
        -- heuristic-banned and error_page redirects to /crowdsec-ban-page, this
        -- guard lets the error page render without re-triggering a 403.
        if ngx.var.crowdsec_error_page == "1" then return end

        cs.metrics:incr("total_checks", 1, 0)

        local uri    = ngx.var.request_uri or "/"
        local method = ngx.req.get_method()

        -- skip_heuristics: set via $crowdsec_skip_heuristics=1 in nginx location block.
        -- Bypasses honeypot scoring, header anomaly scoring, and heuristic-only denies.
        -- LAPI-pushed verdicts (source="p") still apply — this is NOT a security bypass.
        local skip_heuristics = ngx.var.crowdsec_skip_heuristics == "1"

        -- ── 0b. Captcha cookie bypass ─────────────────────────────────────────
        -- A valid HMAC-signed cookie means the client already passed Turnstile.
        -- Skip honeypots, heuristics, and soft mitigations — but still enforce
        -- LAPI hard denies (LEVEL_DENY+) so post-solve bans remain effective.
        local captcha = require "crowdsec.captcha"
        if captcha.has_valid_cookie() then
            local hard = lookup.get_verdict(ip)
            if hard and hard.level >= cs.LEVEL_DENY then
                mitigation.apply(hard, ip)
            end
            return
        end

        -- ── 1. Honeypot ───────────────────────────────────────────────────────
        if not skip_heuristics and heuristics.is_honeypot(uri) then
            cs.metrics:incr("honeypot_hits", 1, 0)
            local verdict = lookup.add_heuristic_score(ip, 100, 3600)
            events.write("honeypot_hit", ip, verdict and verdict.score or 100, uri)
            ngx.exit(ngx.HTTP_FORBIDDEN)
            return
        end

        -- ── 2. Deadman + memory pressure checks ──────────────────────────────
        local stale = sync_is_stale()
        if stale then
            cs.metrics:incr("sync_stale_checks", 1, 0)
        end
        -- memory_pressure: set by sync.lua when cscf_verdicts > MEM_PRESSURE_PCT% full.
        -- Suppresses new heuristic writes to the dict while preserving existing verdicts.
        local mem_pressure = cs.state:get("memory_pressure") == 1

        -- ── 3. Verdict lookup (Python-pushed bans) ────────────────────────────
        local verdict = lookup.get_verdict(ip)
        if verdict and verdict.level >= cs.LEVEL_DENY then
            -- Hard deny always applies, even in stale or pressure mode
            mitigation.apply(verdict, ip)
            return
        end

        -- ── 4. Local heuristics (suspended when stale or under memory pressure) ──
        -- Skip when stale: avoids false-positives from outdated scoring.
        -- Skip when memory pressure: avoids writing new entries to a nearly-full dict.
        if not stale and not mem_pressure and not skip_heuristics then
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
            -- skip_heuristics: do not enforce heuristic-only verdicts (monitoring paths)
            if skip_heuristics and verdict.source == "h" then return end
            mitigation.apply(verdict, ip)
        end

    end)

    if not ok then
        ngx.log(ngx.ERR,
            "[crowdsec:access] component=access event=error status=fail_open error=", tostring(err))
    end
end

return M
