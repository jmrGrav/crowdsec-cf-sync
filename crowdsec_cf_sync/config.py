"""Static configuration for crowdsec-cf-sync.

All values are evaluated at import time from environment variables or hardcoded
defaults. Nothing here changes after the module is loaded.
"""

import os
from pathlib import Path
from typing import Dict, List

# ── Credentials / API tokens ──────────────────────────────────────────────────
CF_API_TOKEN       = os.environ.get("CF_API_TOKEN", "")
CF_ZONE_ID         = os.environ.get("CF_ZONE_ID", "")
CS_API_KEY         = os.environ.get("CS_API_KEY", "")
ABUSEIPDB_KEY      = os.environ.get("ABUSEIPDB_KEY", "")
BETTERSTACK_TOKEN  = os.environ.get("BETTERSTACK_TOKEN", "")
BETTERSTACK_INGEST = os.environ.get("BETTERSTACK_INGEST", "")

# ── Feature flags ─────────────────────────────────────────────────────────────
DRY_RUN           = os.environ.get("CF_DRY_RUN", "").lower() in ("1", "true", "yes")
HEALTH_PORT       = int(os.environ.get("CF_HEALTH_PORT", "8765"))
RECONCILE_SECS    = int(os.environ.get("CF_RECONCILE_SECS", "300"))
CF_MIN_CONFIDENCE = os.environ.get("CF_MIN_CONFIDENCE", "low")
# When =1, sync_cloudflare() skips the push loop (handled by notifier); keeps expiry cleanup
CF_NOTIFIER_ACTIVE = os.environ.get("CF_NOTIFIER_ACTIVE", "").lower() in ("1", "true", "yes")
# When =0, sync_abuseipdb() is disabled (notifier handles AbuseIPDB reporting)
SYNC_ABUSEIPDB = os.environ.get("SYNC_ABUSEIPDB", "1").lower() not in ("0", "false", "no")
CB_THRESHOLD      = int(os.environ.get("CF_CB_THRESHOLD", "5"))
CB_RESET_SECS     = float(os.environ.get("CF_CB_RESET_SECS", "120"))

# ── Lua sync (V3.2+) ──────────────────────────────────────────────────────────
# LUA_ENABLED=0 disables Lua push entirely (daemon still syncs CF only).
LUA_ENABLED    = os.environ.get("LUA_ENABLED", "1").lower() not in ("0", "false", "no")
LUA_SYNC_DIR   = Path(os.environ.get("LUA_SYNC_DIR", "/run/crowdsec-lua"))
LUA_SYNC_FILE  = LUA_SYNC_DIR / "bans.json"
LUA_EVENTS_FILE = LUA_SYNC_DIR / "events.jsonl"

# ── V3.3: auto-heal ───────────────────────────────────────────────────────────
# If the Lua sync_version stops incrementing for LUA_STALE_SECS, trigger an
# OpenResty reload (max once per LUA_HEAL_COOLDOWN_SECS).
LUA_STATUS_URL       = os.environ.get("LUA_STATUS_URL", "http://127.0.0.1:8091/crowdsec-status")
LUA_STALE_SECS       = int(os.environ.get("LUA_STALE_SECS", "120"))
LUA_HEAL_COOLDOWN_SECS = int(os.environ.get("LUA_HEAL_COOLDOWN_SECS", "3600"))

# ── V3.3: CF quota warning thresholds ─────────────────────────────────────────
CF_QUOTA_WARN_PCT  = (70, 85, 95)  # warn at these percentages of CF rule limit

# ── URLs and tags ─────────────────────────────────────────────────────────────
ABUSEIPDB_URL       = "https://api.abuseipdb.com/api/v2/report"
ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
INTERVAL            = 60
NOTE_TAG            = "crowdsec-local-ban"
NOTE_TAG_MODSEC     = "modsec-ban"
NOTE_TAG_CIDR       = "crowdsec-cidr-ban"
LOCAL_ORIGINS       = {"crowdsec", "cscli"}

# ── File paths ────────────────────────────────────────────────────────────────
DECISIONS_LOG       = Path("/var/log/crowdsec/decisions.log")
NGINX_ERROR_LOG     = Path("/var/log/nginx/error.log")
CF_LOG_FILE         = Path("/var/log/crowdsec/cf-sync.log")
ABUSE_STATE         = Path("/var/log/crowdsec/abuseipdb-reported.json")
RECIDIV_STATE       = Path("/var/log/crowdsec/recidivists.json")
MODSEC_STATE        = Path("/var/log/crowdsec/modsec-banned.json")
CIDR_STATE          = Path("/var/log/crowdsec/cidr-banned.json")
CF_WAF_STATE        = Path("/var/log/crowdsec/cf_waf_state.json")
BOUNCER_CHECK_STATE = Path("/var/log/crowdsec/bouncer-abusecheck.json")

# ── Thresholds and durations ──────────────────────────────────────────────────
LOOKBACK_HOURS    = 48
RECIDIV_WINDOW    = 7
CIDR_WINDOW       = 7
MODSEC_SCORE_MIN  = 5
MODSEC_BAN_SECS   = 7200
CIDR_BAN_DURATION = "24h"
CIDR_THRESHOLD    = 2
CF_WAF_POLL_SECS  = 300
CF_WAF_THRESHOLD  = 3
CF_WAF_WINDOW_SECS = 300
BOUNCER_CHECK_TTL = 86400

RECIDIV_ESCALATION = {0: None, 1: "24h"}
RECIDIV_DEFAULT    = "168h"

# ── Scenario → CF service categories mapping ─────────────────────────────────
SCENARIO_CATEGORIES: Dict[str, str] = {
    "http-sensitive-files":    "21,19",
    "http-probing":            "21,19",
    "http-scan":               "21,19",
    "http-bad-user-agent":     "21,19",
    "http-wordpress-scan":     "21,19",
    "http-crawl-non_statics":  "21,19",
    "http-exploit":            "21,19",
    "vpatch-env-access":       "21,19",
    "vpatch-git-config":       "21,19",
    "ssh-bf":                  "22",
    "ssh-slow-bf":             "22",
    "ssh-time-based-bf":       "22",
    "ssh-refused-conn":        "22",
    "ssh-cve":                 "22",
    "mcp-oauth-bruteforce":    "18,21",
    "mcp-oauth-ratelimit":     "21,19",
    "mcp-oauth-scanner":       "21,19",
    "mcp-oauth-bad":           "21,19",
    "default":                 "21,19",
}

_SCENARIO_CONFIDENCE: Dict[str, str] = {
    "ssh-bf":               "high",
    "ssh-slow-bf":          "high",
    "ssh-time-based-bf":    "high",
    "ssh-cve":              "high",
    "http-exploit":         "high",
    "vpatch-env-access":    "high",
    "vpatch-git-config":    "high",
    "mcp-oauth-bruteforce": "high",
    "http-scan":            "medium",
    "http-probing":         "medium",
    "http-sensitive-files": "medium",
    "http-wordpress-scan":  "medium",
    "mcp-oauth-ratelimit":  "medium",
    "mcp-oauth-scanner":    "medium",
    "http-bad-user-agent":  "low",
    "http-crawl-non_statics": "low",
    "mcp-oauth-bad":        "low",
    "ssh-refused-conn":     "low",
    "default":              "medium",
}
_CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}

# ── Protected CIDRs (static list — RFC1918 + Cloudflare ranges) ───────────────
_PROTECTED_CIDRS_STATIC: List[str] = [
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16", "fe80::/10",
    "::1/128",
    "100.64.0.0/10",
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
    "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
]
