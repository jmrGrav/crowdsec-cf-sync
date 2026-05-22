--[[
  crowdsec/heuristics.lua — local request scoring

  Produces a delta score (0..100) for a single request based on:
    - user-agent analysis
    - header coherence
    - path sensitivity
    - burst rate
    - honeypot hits

  Scores accumulate in the shared dict per IP via lookup.add_heuristic_score().
  When cumulative score crosses ESCALATION_THRESHOLD, an event is emitted
  to Python via events.write() for potential CrowdSec/CF escalation.

  Per-request overhead: ~3-8 string comparisons + 2-4 dict ops → microseconds.
--]]

local M      = {}
local cs     = require "crowdsec.init"
local lookup = require "crowdsec.lookup"
local events = require "crowdsec.events"

-- ── Escalation threshold ──────────────────────────────────────────────────────
-- When cumulative heuristic score reaches this, notify Python daemon.
local ESCALATION_THRESHOLD = 80
-- Dedup window: don't re-escalate the same IP within 5 min
local ESCALATION_DEDUP_TTL = 300

-- ── Honeypot paths ────────────────────────────────────────────────────────────
-- Visiting these → instant +100 score + escalation event.
local HONEYPOT = {
    ["/.env"]                 = true,
    ["/.git/config"]          = true,
    ["/wp-admin/install.php"] = true,
    ["/phpmyadmin/index.php"] = true,
    ["/cgi-bin/test-cgi"]     = true,
    ["/server-status"]        = true,
    ["/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"] = true,
    ["/autodiscover/autodiscover.xml"] = true,
    ["/owa/auth/logon.aspx"]  = true,
}

-- ── Sensitive paths (scored but not instant-deny) ─────────────────────────────
local PATH_SCORES = {
    ["/.env"]          = 60,
    ["/.git"]          = 40,
    ["/wp-login.php"]  = 25,
    ["/wp-admin"]      = 20,
    ["/phpmyadmin"]    = 20,
    ["/xmlrpc.php"]    = 30,
    ["/admin"]         = 10,
    ["/setup.php"]     = 40,
    ["/install.php"]   = 40,
    ["/config.php"]    = 50,
    ["/shell"]         = 60,
    ["/cmd"]           = 50,
}

-- ── Known scanner UA fragments (lowercase) ────────────────────────────────────
local BAD_UA = {
    "zgrab", "masscan", "nuclei", "nessus", "nikto", "sqlmap",
    "dirbuster", "gobuster", "wfuzz", "hydra", "nmap scripting",
    "python-requests/", "go-http-client/", "libwww-perl",
    "scrapy/", "ahrefsbot", "semrushbot", "dotbot",
    "censys", "shodan", "binaryedge", "internetmeasurement",
}

-- ── Scoring helpers ───────────────────────────────────────────────────────────

local function score_ua(ua)
    if not ua or ua == "" then
        return 15  -- missing UA is suspicious on HTTP/1.1
    end
    local lc = ua:lower()
    for _, frag in ipairs(BAD_UA) do
        if lc:find(frag, 1, true) then
            return 30
        end
    end
    return 0
end

local function score_headers(hdrs)
    local s = 0
    -- Accept-Language: browsers always send this; scanners often don't
    if not hdrs["accept-language"] then s = s + 10 end
    -- Accept: raw HTTP clients often omit or send "*/*" with no alternatives
    if not hdrs["accept"] then s = s + 5 end
    return s
end

local function score_path(uri)
    -- Strip query string
    local path = uri:match("^([^?#]+)") or uri

    local exact = PATH_SCORES[path]
    if exact then return exact end

    -- Prefix / substring checks (ordered cheapest-first)
    if path:find("%.env",    1, true) then return 60 end
    if path:find("%.git",    1, true) then return 40 end
    if path:find("phpunit",  1, true) then return 60 end
    if path:find("wp%-admin",1, true) then return 20 end
    if path:find("phpmyadmin",1, true)then return 20 end
    if path:find("%.php~",   1, true) then return 40 end  -- backup PHP files
    if path:find("passwd",   1, true) then return 50 end
    if path:find("shadow",   1, true) then return 50 end

    return 0
end

-- ── Public API ────────────────────────────────────────────────────────────────

-- Returns true if this URI is a honeypot path.
function M.is_honeypot(uri)
    local path = uri:match("^([^?#]+)") or uri
    return HONEYPOT[path] == true
end

-- Score a request and accumulate in shared dict.
-- Returns delta score (for this request only; not cumulative).
function M.score_request(ip, uri, method, hdrs)
    local ua_score   = score_ua(hdrs["user-agent"])
    local hdr_score  = score_headers(hdrs)
    local path_score = score_path(uri)

    -- Burst detection: too many requests from same IP in BURST_WINDOW
    local burst = lookup.incr_burst(ip)
    local burst_score = 0
    if burst > cs.BURST_THRESHOLD then
        burst_score = math.min(25, math.floor((burst - cs.BURST_THRESHOLD) / 10))
        cs.metrics:incr("burst_hits", 1, 0)
    end

    -- Per-signal counters for observability (only when signal contributed)
    if ua_score   > 0 then cs.metrics:incr("ua_hits",            1, 0) end
    if hdr_score  > 0 then cs.metrics:incr("header_anomaly_hits", 1, 0) end
    if path_score > 0 then cs.metrics:incr("path_hits",          1, 0) end

    local delta = ua_score + hdr_score + path_score + burst_score

    if delta <= 0 then return 0 end

    -- Accumulate in cache
    local verdict = lookup.add_heuristic_score(ip, delta, cs.HEURISTIC_TTL)
    cs.metrics:incr("heuristic_hits", 1, 0)

    -- Escalate to Python if above threshold (with dedup)
    if verdict and verdict.score >= ESCALATION_THRESHOLD then
        local esc_key = "esc:" .. ip
        local already = cs.state:get(esc_key)
        if not already then
            cs.state:set(esc_key, "1", ESCALATION_DEDUP_TTL)
            events.write("heuristic_escalate", ip, verdict.score, uri)
            cs.metrics:incr("escalations", 1, 0)
        end
    end

    return delta
end

return M
