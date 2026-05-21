--[[
  crowdsec/tarpit.lua — bounded coroutine sleep (tarpit)

  ngx.sleep() yields the coroutine without blocking the event loop.
  However, each sleeping coroutine holds an nginx connection open (memory + fd).
  We bound concurrency via crowdsec_state["tarpit_active"] to prevent:
    - runaway memory consumption under scan storms
    - fd exhaustion
    - starving legitimate requests

  Behavior when limit exceeded: FAIL-OPEN — skip sleep, let caller apply deny/429.
--]]

local M  = {}
local cs = require "crowdsec.init"

function M.sleep(ip)
    local state = cs.state

    -- Read current count (no incr yet — check first)
    local active = state:get("tarpit_active") or 0

    if active >= cs.MAX_TARPITS then
        -- Limit exceeded: don't tarpit this request
        cs.metrics:incr("tarpit_skipped", 1, 0)
        return false
    end

    -- Atomically increment the active counter
    local new_count, err = state:incr("tarpit_active", 1, 0)
    if err or not new_count then
        -- init key if missing
        state:set("tarpit_active", 1, 0)
    elseif new_count > cs.MAX_TARPITS then
        -- Someone else incremented concurrently — back out and skip
        state:incr("tarpit_active", -1, 0)
        cs.metrics:incr("tarpit_skipped", 1, 0)
        return false
    end

    cs.metrics:incr("tarpit_total", 1, 0)

    -- Random sleep — breaks scan timing assumptions
    local delay = cs.TARPIT_MIN + math.random() * (cs.TARPIT_MAX - cs.TARPIT_MIN)
    ngx.sleep(delay)

    -- Decrement counter; protect against underflow
    local after = state:incr("tarpit_active", -1, 0)
    if after and after < 0 then
        state:set("tarpit_active", 0, 0)
    end

    return true
end

return M
