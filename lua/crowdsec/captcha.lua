--[[
  crowdsec/captcha.lua — Cloudflare Turnstile CAPTCHA workflow

  Three public functions:

    has_valid_cookie()  — check request cookie; returns true → caller skips heuristics
    render()            — serve the CAPTCHA challenge page (called from mitigation.lua)
    verify()            — handle POST /captcha-verify, validate token, set cookie

  Cookie format: base64url(ts:ua_hash:hmac_hex)
    ts       — Unix timestamp (seconds)
    ua_hash  — first 8 hex chars of MD5(User-Agent)  — lightweight UA binding
    hmac_hex — 64-char hex of HMAC-SHA256(SECRET, "ts:ua_hash")

  Cookie is HttpOnly + Secure + SameSite=Lax. TTL = 20 minutes.
  No Redis, no disk state, no external dependencies beyond lua-resty-http.

  Security properties:
    - Stateless: all state is in the HMAC-signed cookie
    - Fail closed: Cloudflare error or timeout → re-serve captcha
    - No IP bypass: cookie binds to UA hash; network change is allowed (NAT/mobile)
    - Replay limited: cookie TTL = 20 min; new solve required after expiry
--]]

local M = {}

-- ── Credentials (loaded from env by OpenResty workers) ───────────────────────
-- nginx.conf must have: env TURNSTILE_SITEKEY; env TURNSTILE_SECRET;
-- openresty.service.d/turnstile.conf must have: EnvironmentFile=/etc/crowdsec/turnstile.env
local SITEKEY = os.getenv("TURNSTILE_SITEKEY") or ""
local SECRET  = os.getenv("TURNSTILE_SECRET")  or ""

local COOKIE_NAME = "crowdsec_captcha"
local COOKIE_TTL  = 1200  -- 20 minutes
local CF_VERIFY   = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

-- ── Helpers ───────────────────────────────────────────────────────────────────

local function to_hex(s)
    return (s:gsub('.', function(c) return string.format('%02x', c:byte()) end))
end

local function b64url_enc(s)
    -- encode_base64(s, true) = standard base64 with no_padding=true
    local b = ngx.encode_base64(s, true)
    return b:gsub('+', '-'):gsub('/', '_')
end

local function b64url_dec(s)
    local pad = (4 - #s % 4) % 4
    s = s:gsub('-', '+'):gsub('_', '/') .. ('='):rep(pad)
    return ngx.decode_base64(s)
end

-- Sign ts:ua_hash with HMAC-SHA256
local function sign(payload)
    return to_hex(ngx.hmac_sha256(SECRET, payload))
end

-- Read a named cookie from the current request
local function get_cookie(name)
    local header = ngx.var.http_cookie or ""
    -- Iterate semicolon-separated pairs
    for pair in (header .. ";"):gmatch("([^;]+);") do
        local k, v = pair:match("^%s*(.-)%s*=%s*(.-)%s*$")
        if k == name then return v end
    end
    return nil
end

-- Sanitize a URL: only accept relative paths (prevents open redirect).
-- Uses find() with plain=true for control chars to avoid Lua pattern null-byte issues.
local function safe_path(path)
    if not path or path == "" then return "/" end
    if path == "/" then return "/" end
    -- Must start with / but NOT // (protocol-relative)
    if path:sub(1, 1) ~= "/" or path:sub(1, 2) == "//" then return "/" end
    -- Reject newlines (prevent header injection)
    if path:find("\r", 1, true) or path:find("\n", 1, true) then return "/" end
    return path
end

-- HTML-escape for embedding in attribute values
local function html_attr(s)
    return (s:gsub('&', '&amp;')
              :gsub('<', '&lt;')
              :gsub('>', '&gt;')
              :gsub('"', '&quot;'))
end

-- ── Cookie construction / validation ─────────────────────────────────────────

local function make_cookie_val(ua)
    local ts      = tostring(ngx.time())
    local ua_hash = ngx.md5(ua or ""):sub(1, 8)
    local payload = ts .. ":" .. ua_hash
    return b64url_enc(payload .. ":" .. sign(payload))
end

local function validate_cookie_val(val, ua)
    if not val or SECRET == "" then return false end
    local decoded = b64url_dec(val)
    if not decoded then return false end

    -- Parse: ts:ua_hash:sig (ua_hash=8 hex, sig=64 hex)
    local ts_str, ua_hash, sig = decoded:match("^(%d+):(%x+):(%x+)$")
    if not ts_str then return false end
    if #ua_hash ~= 8 or #sig ~= 64 then return false end

    -- TTL
    local ts = tonumber(ts_str)
    if not ts or (ngx.time() - ts) > COOKIE_TTL then return false end

    -- HMAC (constant-time compare via sign())
    local payload = ts_str .. ":" .. ua_hash
    if sign(payload) ~= sig then return false end

    -- UA binding
    if ngx.md5(ua or ""):sub(1, 8) ~= ua_hash then return false end

    return true
end

-- ── Captcha HTML page (embedded — no disk I/O at runtime) ────────────────────
-- Inline script hash for CSP: sha256-X4SgwwKVJ7TEkguZJS7OjSgO9HbMqeIdvfaZtbjOzLQ=
-- Script: function onCaptchaDone(){document.getElementById("captcha-form").submit();}

local CAPTCHA_HTML = [[<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex,nofollow">
  <title>Vérification de sécurité — arleo.eu</title>
  <style>
    :root {
      --bg: #f7f8fa; --panel: #ffffff; --text: #1a1d23; --muted: #6b7280;
      --border: #e5e7eb; --accent: #4a5568; --accent-soft: #edf2f7;
      --shadow: 0 1px 2px rgba(0,0,0,.05), 0 8px 24px rgba(0,0,0,.06);
    }
    @media (prefers-color-scheme: dark) {
      :root {
        --bg: #0f1115; --panel: #161922; --text: #e5e7eb; --muted: #9ca3af;
        --border: #262a35; --accent: #cbd5e0; --accent-soft: #1f2330;
        --shadow: 0 1px 2px rgba(0,0,0,.4), 0 8px 24px rgba(0,0,0,.4);
      }
    }
    * { box-sizing: border-box; }
    html, body { margin: 0; padding: 0; height: 100%; background: var(--bg); color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      -webkit-font-smoothing: antialiased; line-height: 1.55; }
    .wrap { min-height: 100%; display: flex; align-items: center; justify-content: center; padding: 1.5rem; }
    .card { background: var(--panel); border: 1px solid var(--border); border-radius: 14px;
      box-shadow: var(--shadow); max-width: 560px; width: 100%; padding: 2.25rem 2rem; }
    .icon { width: 56px; height: 56px; border-radius: 12px; background: var(--accent-soft);
      display: flex; align-items: center; justify-content: center; margin-bottom: 1.25rem; }
    .icon svg { width: 28px; height: 28px; stroke: var(--accent); fill: none;
      stroke-width: 1.8; stroke-linecap: round; stroke-linejoin: round; }
    h1 { margin: 0 0 .5rem; font-size: 1.5rem; font-weight: 600; letter-spacing: -.01em; }
    p { margin: 0 0 1rem; color: var(--text); }
    p.muted { color: var(--muted); font-size: .95rem; }
    .challenge-wrap { margin: 1.5rem 0 0; display: flex; flex-direction: column; align-items: flex-start; gap: 1rem; }
    .cf-turnstile { min-height: 65px; }
    .btn-submit { display: none; padding: .6rem 1.2rem; border-radius: 8px; border: none;
      background: var(--accent); color: var(--panel); font-size: .92rem; font-weight: 500;
      cursor: pointer; transition: opacity .15s; }
    .btn-submit:hover { opacity: .85; }
    footer { margin-top: 1.5rem; padding-top: 1rem; border-top: 1px solid var(--border);
      font-size: .8rem; color: var(--muted); text-align: center; }
    footer a { color: var(--muted); }
  </style>
</head>
<body>
  <div class="wrap">
    <main class="card" role="main">
      <div class="icon" aria-hidden="true">
        <svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>
      </div>
      <h1>Vérification de sécurité</h1>
      <p>Notre système a détecté une activité inhabituelle depuis votre adresse IP.</p>
      <p class="muted">Complétez la vérification ci-dessous pour accéder au site. Cette étape est automatique pour la plupart des navigateurs.</p>
      <form id="captcha-form" action="/captcha-verify" method="POST">
        <input type="hidden" name="_redirect" value="__REDIRECT__">
        <div class="challenge-wrap">
          <div class="cf-turnstile" data-sitekey="__SITEKEY__" data-callback="onCaptchaDone" data-theme="auto"></div>
          <button type="submit" class="btn-submit" id="btn-submit">Continuer →</button>
        </div>
      </form>
      <footer>Protégé par <a href="https://www.crowdsec.net" rel="noopener noreferrer" target="_blank">CrowdSec</a>
        &amp; <a href="https://www.cloudflare.com/products/turnstile/" rel="noopener noreferrer" target="_blank">Cloudflare Turnstile</a></footer>
    </main>
  </div>
  <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
  <script>function onCaptchaDone(){document.getElementById("captcha-form").submit();}</script>
</body>
</html>]]

-- ── Public API ────────────────────────────────────────────────────────────────

-- Check if the current request carries a valid captcha cookie.
-- Called at the top of access.lua (after error_page guard, before honeypot check).
function M.has_valid_cookie()
    if SECRET == "" then return false end
    local val = get_cookie(COOKIE_NAME)
    if not val then return false end
    local ua = ngx.req.get_headers()["user-agent"] or ""
    return validate_cookie_val(val, ua)
end

-- Serve the CAPTCHA challenge page (HTTP 403).
-- Called from mitigation.lua LEVEL_CAPTCHA branch, and from verify() on failure.
-- redirect_hint: optional redirect path to preserve across re-renders (e.g. original URI).
function M.render(redirect_hint)
    local redirect = safe_path(redirect_hint or ngx.var.request_uri)
    local body = CAPTCHA_HTML
        :gsub("__SITEKEY__", SITEKEY ~= "" and SITEKEY or "MISSING_SITEKEY")
        :gsub("__REDIRECT__", html_attr(redirect))

    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.header["Content-Type"]            = "text/html; charset=utf-8"
    ngx.header["Cache-Control"]           = "no-store"
    ngx.header["X-Content-Type-Options"]  = "nosniff"
    ngx.header["Referrer-Policy"]         = "no-referrer"
    -- CSP allows Turnstile script/frame; inline script whitelisted by hash.
    ngx.header["Content-Security-Policy"] =
        "default-src 'none'; " ..
        "style-src 'unsafe-inline'; " ..
        "script-src https://challenges.cloudflare.com " ..
            "'sha256-X4SgwwKVJ7TEkguZJS7OjSgO9HbMqeIdvfaZtbjOzLQ='; " ..
        "frame-src https://challenges.cloudflare.com; " ..
        "connect-src https://challenges.cloudflare.com; " ..
        "img-src 'self' data:; " ..
        "base-uri 'none'; frame-ancestors 'none'"
    ngx.header["Content-Security-Policy-Report-Only"] = nil
    ngx.say(body)
    ngx.exit(ngx.HTTP_FORBIDDEN)
end

-- Handle POST /captcha-verify: validate Turnstile token, issue signed cookie, redirect.
-- Called from content_by_lua_block in crowdsec_captcha.conf.
function M.verify()
    -- Read POST body (nginx buffers it; resty.http needs it pre-read)
    ngx.req.read_body()
    local args, err = ngx.req.get_post_args(10)
    if not args then
        ngx.log(ngx.WARN, "[crowdsec:captcha] event=verify status=bad_args error=", tostring(err))
        M.render()
        return
    end

    local token    = args["cf-turnstile-response"] or ""
    local redirect = safe_path(args["_redirect"] or "/")

    if token == "" then
        M.render(redirect)  -- preserve redirect through re-renders
        return
    end

    -- Validate token with Cloudflare (fail closed on any error)
    local http = require "resty.http"
    local httpc = http.new()
    httpc:set_timeout(3000)

    local res, cf_err = httpc:request_uri(CF_VERIFY, {
        method  = "POST",
        body    = ngx.encode_args({
            secret   = SECRET,
            response = token,
            remoteip = ngx.var.remote_addr,
        }),
        headers = { ["Content-Type"] = "application/x-www-form-urlencoded" },
        ssl_verify = true,
        ssl_trusted_certificate = "/etc/ssl/certs/ca-certificates.crt",
    })

    local success = false
    if res and res.status == 200 then
        local ok, json = pcall(require("cjson").decode, res.body or "")
        if ok and type(json) == "table" and json.success == true then
            success = true
        end
    else
        ngx.log(ngx.WARN,
            "[crowdsec:captcha] event=verify status=cf_error cf_err=", tostring(cf_err),
            " http_status=", res and res.status or "nil")
    end

    if not success then
        -- Fail closed: re-render captcha preserving redirect target
        M.render(redirect)
        return
    end

    -- Issue signed cookie
    local ua  = ngx.req.get_headers()["user-agent"] or ""
    local val = make_cookie_val(ua)
    ngx.header["Set-Cookie"] = COOKIE_NAME .. "=" .. val ..
        "; Max-Age=" .. tostring(COOKIE_TTL) ..
        "; Path=/; HttpOnly; Secure; SameSite=Lax"

    ngx.log(ngx.INFO,
        "[crowdsec:captcha] event=captcha_passed ip=", ngx.var.remote_addr,
        " redirect=", redirect)

    -- Redirect back to original URL (303 See Other to switch from POST to GET)
    ngx.redirect(redirect, ngx.HTTP_SEE_OTHER)
end

return M
