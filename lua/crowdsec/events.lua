--[[
  crowdsec/events.lua — write escalation events for Python daemon

  Lua appends JSON lines to /run/crowdsec-lua/events.jsonl.
  Python reads and truncates the file at the start of each cycle.

  All writes are deferred via ngx.timer.at(0, ...) so the request
  context is never blocked by I/O, even if the disk is slow.
--]]

local M    = {}
local cjson = require "cjson.safe"
local cs    = require "crowdsec.init"

function M.write(event_type, ip, score, detail)
    local entry = {
        ts     = ngx.now(),
        type   = event_type,
        ip     = ip,
        score  = score,
        detail = detail or "",
        worker = ngx.worker.id(),
    }

    local line, enc_err = cjson.encode(entry)
    if not line then
        ngx.log(ngx.WARN, "[crowdsec:events] encode failed: ", enc_err)
        return
    end

    -- Defer file I/O to background timer (never block request context)
    local ok, timer_err = ngx.timer.at(0, function(premature, l)
        if premature then return end
        local f, ferr = io.open(cs.EVENTS_FILE, "a")
        if not f then
            ngx.log(ngx.WARN, "[crowdsec:events] open failed: ", ferr)
            return
        end
        f:write(l .. "\n")
        f:close()
    end, line)

    if not ok then
        ngx.log(ngx.WARN, "[crowdsec:events] timer.at(0) failed: ", timer_err)
    end
end

return M
