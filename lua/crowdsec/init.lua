--[[
  crowdsec/init.lua — constants, shared dict handles, pure helpers
  Loaded once at nginx startup; safe to require from any context.
--]]

local M = {}

-- ── Shared dicts ──────────────────────────────────────────────────────────────
M.cache   = ngx.shared.crowdsec_cache    -- ip/cidr verdicts
M.metrics = ngx.shared.crowdsec_metrics  -- counters
M.state   = ngx.shared.crowdsec_state    -- sync metadata + tarpit semaphore

-- ── IPC paths (must match Python LUA_SYNC_FILE / LUA_EVENTS_FILE) ────────────
M.SYNC_FILE   = "/run/crowdsec-lua/bans.json"
M.EVENTS_FILE = "/run/crowdsec-lua/events.jsonl"

-- ── Tuning ────────────────────────────────────────────────────────────────────
M.SYNC_INTERVAL    = 5    -- seconds between bans.json reloads
M.MAX_TARPITS      = 20   -- max concurrent sleeping workers (memory + conn bound)
M.TARPIT_MIN       = 3    -- min tarpit delay seconds
M.TARPIT_MAX       = 12   -- max tarpit delay seconds
M.HEURISTIC_TTL    = 7200 -- seconds to keep heuristic-only score in cache
M.BURST_WINDOW     = 60   -- seconds for burst counter TTL
M.BURST_THRESHOLD  = 120  -- requests per BURST_WINDOW before rate-limit kicks in

-- ── Fail behavior ─────────────────────────────────────────────────────────────
-- FAIL_OPEN = true  → unknown IPs pass (safe default; Python/CF still block them)
-- FAIL_OPEN = false → deny on any lookup error (strict mode)
M.FAIL_OPEN = true

-- ── Mitigation levels ─────────────────────────────────────────────────────────
M.LEVEL_ALLOW     = 0
M.LEVEL_RATELIMIT = 1  -- leaky bucket, 429 when exceeded
M.LEVEL_TARPIT    = 2  -- bounded coroutine sleep then 429
M.LEVEL_CHALLENGE = 3  -- JS challenge redirect (or 429 with hint)
M.LEVEL_CAPTCHA   = 4  -- CAPTCHA redirect (or 403)
M.LEVEL_DENY      = 5  -- 403 (score < 96) or 444 (score >= 96)
M.LEVEL_ESCALATE  = 6  -- reserved; Python daemon handles CF escalation

-- ── Score → level mapping ─────────────────────────────────────────────────────
function M.score_to_level(score)
    if score >= 96 then return M.LEVEL_DENY       -- silent drop (444)
    elseif score >= 81 then return M.LEVEL_DENY   -- 403
    elseif score >= 61 then return M.LEVEL_CHALLENGE
    elseif score >= 31 then return M.LEVEL_TARPIT
    elseif score >= 1  then return M.LEVEL_RATELIMIT
    else return M.LEVEL_ALLOW
    end
end

-- ── Compact verdict encoding ──────────────────────────────────────────────────
-- Shared dict stores "level:score" strings — one dict:get() per lookup, no JSON decode.
-- src: "p" = Python-pushed, "h" = heuristic, omit for unknown
function M.encode_verdict(level, score, src)
    if src then
        return level .. ":" .. score .. ":" .. src
    end
    return level .. ":" .. score
end

-- source: "p" = Python-pushed, "h" = heuristic-only (omitted → unknown)
function M.decode_verdict(raw)
    if not raw then return nil end
    -- Extended format: "level:score:src"
    local level, score, src = raw:match("^(%d+):(%d+):?(%a*)$")
    if level then
        return { level = tonumber(level), score = tonumber(score), source = src or "?" }
    end
    return nil
end

return M
