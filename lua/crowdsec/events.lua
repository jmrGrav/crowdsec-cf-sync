--[[
  crowdsec/events.lua — write escalation events for Python daemon

  Lua appends JSON lines to /run/crowdsec-lua/events.jsonl.
  Python atomically renames the file at the start of each cycle.

  All writes are deferred via ngx.timer.at(0, ...) so the request
  context is never blocked by I/O, even if the disk is slow.

  Size guard: if the file exceeds EVENTS_MAX_BYTES, the event is dropped
  and a counter is incremented. This happens only when Python is stopped;
  in normal operation Python drains the file every 60s.

  Drop policy: drop the incoming event (not oldest ones). The file
  accumulates Python-prioritised events; we never rewrite it to avoid
  partial-write races with the Python rename.
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
        ngx.log(ngx.WARN,
            "[crowdsec:events] component=events event=encode_failed error=", tostring(enc_err))
        return
    end

    -- Defer file I/O to background timer (never block request context)
    local ok, timer_err = ngx.timer.at(0, function(premature, l)
        if premature then return end

        -- ── Size guard before appending ───────────────────────────────────────
        -- Check current file size. If over limit, drop this event and count it.
        -- We do NOT truncate the file here — Python owns the file lifecycle.
        local stat_f = io.open(cs.EVENTS_FILE, "r")
        if stat_f then
            stat_f:seek("end")
            local current_size = stat_f:seek()
            stat_f:close()
            if current_size > cs.EVENTS_MAX_BYTES then
                cs.metrics:incr("dropped_events", 1, 0)
                ngx.log(ngx.WARN,
                    "[crowdsec:events] component=events event=dropped",
                    " reason=size_limit",
                    " current_bytes=", current_size,
                    " limit_bytes=", cs.EVENTS_MAX_BYTES)
                return
            end
        end

        local f, ferr = io.open(cs.EVENTS_FILE, "a")
        if not f then
            ngx.log(ngx.WARN,
                "[crowdsec:events] component=events event=open_failed error=", tostring(ferr))
            return
        end
        f:write(l .. "\n")
        f:close()
    end, line)

    if not ok then
        ngx.log(ngx.WARN,
            "[crowdsec:events] component=events event=timer_failed error=", tostring(timer_err))
    end
end

return M
