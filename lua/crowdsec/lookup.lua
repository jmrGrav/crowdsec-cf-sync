--[[
  crowdsec/lookup.lua — O(1) verdict lookup from shared dict
  Called per-request. ZERO I/O. ZERO allocations beyond string ops.

  Cache key layout:
    "ip:<addr>"       — exact IP match          (e.g. "ip:1.2.3.4")
    "cidr24:<prefix>" — /24 CIDR match prefix   (e.g. "cidr24:1.2.3")
    "cidr16:<prefix>" — /16 CIDR match prefix   (e.g. "cidr16:1.2")
    "hits:<addr>"     — burst counter (auto-TTL)
    "rl:<addr>"       — rate-limit counter (auto-TTL)
    "esc:<addr>"      — escalation dedup flag    (5min TTL)
--]]

local M  = {}
local cs = require "crowdsec.init"

-- ── IP prefix extractors (pure string, no splits) ────────────────────────────

local function prefix24(ip)
    -- "1.2.3.4" → "1.2.3"
    local s, e = ip:find("%d+%.%d+%.%d+%.")
    if s == 1 then return ip:sub(s, e - 1) end
    return nil
end

local function prefix16(ip)
    -- "1.2.3.4" → "1.2"
    local s, e = ip:find("%d+%.%d+%.")
    if s == 1 then return ip:sub(s, e - 1) end
    return nil
end

-- ── Verdict lookup — 3 dict reads max ────────────────────────────────────────

function M.get_verdict(ip)
    local cache = cs.cache

    -- 1. Exact IP
    local v = cs.decode_verdict(cache:get("ip:" .. ip))
    if v then
        cs.metrics:incr("cache_hits", 1, 0)
        return v
    end

    -- 2. /24 CIDR
    local p24 = prefix24(ip)
    if p24 then
        v = cs.decode_verdict(cache:get("cidr24:" .. p24))
        if v then
            cs.metrics:incr("cache_hits", 1, 0)
            return v
        end
    end

    -- 3. /16 CIDR
    local p16 = prefix16(ip)
    if p16 then
        v = cs.decode_verdict(cache:get("cidr16:" .. p16))
        if v then
            cs.metrics:incr("cache_hits", 1, 0)
            return v
        end
    end

    cs.metrics:incr("cache_misses", 1, 0)
    return nil
end

-- ── Heuristic score accumulator ───────────────────────────────────────────────
-- Adds `delta` to current heuristic score for `ip`, recomputes level, updates cache.
-- Returns new {level, score}.

function M.add_heuristic_score(ip, delta, ttl)
    if delta <= 0 then return nil end

    local cache = cs.cache
    local key   = "ip:" .. ip
    local raw   = cache:get(key)
    local cur   = cs.decode_verdict(raw)

    local old_score = cur and cur.score or 0
    local new_score = math.min(100, old_score + delta)
    local new_level = cs.score_to_level(new_score)

    -- Don't downgrade a Python-pushed level (e.g. CF ban = level 5)
    if cur and cur.level > new_level then
        new_level = cur.level
    end

    cache:set(key, cs.encode_verdict(new_level, new_score, "h"), ttl or cs.HEURISTIC_TTL)
    return { level = new_level, score = new_score, source = "h" }
end

-- ── Burst counter ─────────────────────────────────────────────────────────────
-- Returns request count for this IP in the current burst window.
function M.incr_burst(ip)
    local count, err = cs.cache:incr("hits:" .. ip, 1, 0, cs.BURST_WINDOW)
    if err then return 0 end
    return count or 0
end

return M
