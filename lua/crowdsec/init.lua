--[[
  crowdsec/init.lua — constants, shared dict handles, pure helpers
  Loaded once at nginx startup; safe to require from any context.
--]]

local M = {}

-- ── Shared dicts ──────────────────────────────────────────────────────────────
M.cache   = ngx.shared.cscf_verdicts    -- ip/cidr verdicts
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

-- ── Safety thresholds ─────────────────────────────────────────────────────────
-- DEADMAN_SECS: if sync_ts is older than this, bans.json is considered stale.
--   In stale mode, aggressive mitigation (tarpit/challenge) is suspended;
--   only level-5 deny verdicts remain active (fail-open for grey zones).
-- DICT_MIN_FREE: refuse to write new verdicts to the cache dict if free space
--   falls below this threshold, preventing OOM eviction of live entries.
-- BANS_JSON_MAX_BYTES: reject bans.json payloads larger than this before
--   attempting JSON parse (prevents memory spike from corrupted/injected files).
-- EVENTS_MAX_BYTES: refuse to append to events.jsonl beyond this size.
--   Python consumes the file atomically; unbounded growth means Python is down.
-- BANS_STALE_SECS: reject bans.json whose updated_at_epoch is older than this.
--   Protects against replayed or stale files (e.g. filesystem snapshot restores).
-- BANS_FUTURE_SECS: reject bans.json whose updated_at_epoch is this far ahead
--   of wall-clock — clock skew guard.
-- CSCF_VERDICTS_SIZE: declared size of the cscf_verdicts shared dict in bytes.
--   Must match lua_shared_dict cscf_verdicts Nm in crowdsec_shared_dicts.conf.
--   Used only for soft-pressure percentage calculation; not a hard API value.
-- MEM_PRESSURE_PCT: when cscf_verdicts is fuller than this %, suppress new
--   heuristic writes (dict reads and existing verdict lookups still work).
--   Soft layer before DICT_MIN_FREE hard-stop.
M.DEADMAN_SECS        = 120          -- 2 min without sync → stale mode
M.DICT_MIN_FREE       = 2097152      -- 2 MB: hard stop — no new entries below this
M.BANS_JSON_MAX_BYTES = 10485760     -- 10 MB: reject oversized bans.json
M.EVENTS_MAX_BYTES    = 1048576      -- 1 MB: stop appending events.jsonl beyond this
M.BANS_STALE_SECS     = 600          -- 10 min: reject bans.json older than this
M.BANS_FUTURE_SECS    = 300          -- 5 min: reject bans.json with future timestamp
M.CSCF_VERDICTS_SIZE  = 52428800     -- 50 MB: must match lua_shared_dict cscf_verdicts
M.MEM_PRESSURE_PCT    = 90           -- % full: suspend heuristic writes above this

-- ── Mitigation levels ─────────────────────────────────────────────────────────
M.LEVEL_ALLOW     = 0
M.LEVEL_RATELIMIT = 1  -- leaky bucket, 429 when exceeded
M.LEVEL_TARPIT    = 2  -- bounded coroutine sleep then 429
M.LEVEL_CHALLENGE = 3  -- JS challenge redirect (or 429 with hint)
M.LEVEL_CAPTCHA   = 4  -- CAPTCHA redirect (or 403)
M.LEVEL_DENY      = 5  -- 403 (score < 96) or 444 (score >= 96)
M.LEVEL_ESCALATE  = 6  -- reserved; Python daemon handles CF escalation

-- ── Score → level mapping — challenge-first strategy ─────────────────────────
--   0–39  → allow   (legitimate traffic; borderline cases pass through)
--   40–69 → captcha (Turnstile human verification; resolves transparently for real users)
--   70–89 → deny    (403 ban page; confident bot or attacker)
--   90+   → deny    (444 silent drop; high-confidence / recidivist)
--
-- LEVEL_RATELIMIT / LEVEL_TARPIT / LEVEL_CHALLENGE (1–3) are no longer emitted
-- by local heuristics but remain valid for LAPI-pushed verdicts.
-- The 403 vs 444 distinction at LEVEL_DENY is made in mitigation.lua by score threshold.
function M.score_to_level(score)
    if     score >= 90 then return M.LEVEL_DENY    -- hard: 444 silent drop
    elseif score >= 70 then return M.LEVEL_DENY    -- soft: 403 ban page
    elseif score >= 40 then return M.LEVEL_CAPTCHA -- Turnstile challenge
    else                     return M.LEVEL_ALLOW
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
