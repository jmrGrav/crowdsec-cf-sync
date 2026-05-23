--[[
  crowdsec/mitigation.lua — apply verdict to current request

  LEVEL 0 → allow (no action)
  LEVEL 1 → rate limit (leaky bucket; 429 when exceeded)
  LEVEL 2 → tarpit (bounded sleep; 429 after)
  LEVEL 3 → JS challenge hint (429 + header; caller handles redirect)
  LEVEL 4 → CAPTCHA hint (403)
  LEVEL 5 → hard deny: 403 (score < 96) or 444 (score ≥ 96)

  ngx.exit() terminates the request phase immediately.
  All counters are incremented before exit so metrics are accurate.
--]]

local M      = {}
local cs     = require "crowdsec.init"
local tarpit = require "crowdsec.tarpit"

-- Rate-limit bucket: max requests per BURST_WINDOW seconds
-- (separate from the heuristic burst counter — this is per-verdict)
local RL_LIMIT  = 30  -- max requests per window for level-1 IPs
local RL_WINDOW = 60  -- seconds

function M.apply(verdict, ip)
    if not verdict then return end

    local level = verdict.level
    local score = verdict.score

    -- Track per-level hits in metrics
    cs.metrics:incr("level_" .. level .. "_hits", 1, 0)

    -- ── Level 0: allow ────────────────────────────────────────────────────────
    if level <= cs.LEVEL_ALLOW then
        return

    -- ── Level 1: rate limit ───────────────────────────────────────────────────
    elseif level == cs.LEVEL_RATELIMIT then
        local key   = "rl:" .. ip
        local count = cs.cache:incr(key, 1, 0, RL_WINDOW)
        if count and count > RL_LIMIT then
            cs.metrics:incr("ratelimit_drops", 1, 0)
            ngx.header["Retry-After"] = "30"
            ngx.exit(ngx.HTTP_TOO_MANY_REQUESTS)
        end
        -- Under limit: let request through

    -- ── Level 2: tarpit ───────────────────────────────────────────────────────
    elseif level == cs.LEVEL_TARPIT then
        tarpit.sleep(ip)
        cs.metrics:incr("tarpits", 1, 0)
        ngx.header["Retry-After"] = "60"
        ngx.exit(ngx.HTTP_TOO_MANY_REQUESTS)

    -- ── Level 3: JS challenge ─────────────────────────────────────────────────
    elseif level == cs.LEVEL_CHALLENGE then
        cs.metrics:incr("challenges", 1, 0)
        -- Signal to the caller (vhost config) via response header.
        -- Actual challenge delivery (redirect / inline JS) is vhost-specific.
        ngx.header["X-CrowdSec-Action"] = "challenge"
        ngx.header["X-CrowdSec-Score"]  = tostring(score)
        ngx.exit(ngx.HTTP_TOO_MANY_REQUESTS)

    -- ── Level 4: CAPTCHA ──────────────────────────────────────────────────────
    elseif level == cs.LEVEL_CAPTCHA then
        cs.metrics:incr("captchas", 1, 0)
        ngx.var.crowdsec_block_reason = "captcha"
        ngx.exit(ngx.HTTP_FORBIDDEN)

    -- ── Level 5+: hard deny ───────────────────────────────────────────────────
    else
        cs.metrics:incr("denies", 1, 0)
        if score >= 96 then
            -- 444 = silent drop (nginx extension); no response sent
            ngx.exit(444)
        else
            -- Heuristic-sourced denies: label the reason so the ban page and
            -- access log show "heuristic" instead of the map's default "-".
            -- LAPI bans (source="p") keep "-" → shown as "block" on the ban page.
            if verdict.source == "h" then
                ngx.var.crowdsec_block_reason = "heuristic"
            end
            ngx.exit(ngx.HTTP_FORBIDDEN)
        end
    end
end

return M
