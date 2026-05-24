#!/usr/bin/env python3
"""
crowdsec-notifier.py — CrowdSec HTTP notification receiver.

Routes:
  POST /crowdsec/abuseipdb   — Phase 1: report to AbuseIPDB
  POST /crowdsec/cloudflare  — Phase 2: push ban to Cloudflare access rules (event-driven)
  POST /crowdsec/event        — stub: log only

Secrets via EnvironmentFile=/etc/crowdsec/cf-sync.env in systemd unit.
Set NOTIFIER_DRY_RUN=1     to log without POSTing to AbuseIPDB (Phase 1 default).
Set NOTIFIER_CF_DRY_RUN=1  to log without POSTing to Cloudflare (Phase 2 default).
"""
import ipaddress
import json
import logging
import os
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT  = 9999

ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_KEY", "")
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/report"
DRY_RUN       = os.environ.get("NOTIFIER_DRY_RUN", "0") == "1"

CF_API_TOKEN = os.environ.get("CF_API_TOKEN", "")
CF_ZONE_ID   = os.environ.get("CF_ZONE_ID", "")
CF_DRY_RUN   = os.environ.get("NOTIFIER_CF_DRY_RUN", "0") == "1"
CF_API_BASE  = "https://api.cloudflare.com/client/v4"
CF_NOTE_TAG  = "crowdsec-local-ban"
CF_DEDUP_TTL = 120  # seconds — suppress duplicate pushes for same IP

STATE_FILE = Path("/var/log/crowdsec/notifier-state.json")
DEDUP_TTL  = 7 * 86400  # seconds — AbuseIPDB dedup window

# RFC1918, loopback, link-local, CGNAT — never report or block these
_HARDCODED_SKIP = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("100.64.0.0/10"),
]

# Cloudflare proxy/CDN ranges — must never be blocked in CF access rules
_CF_ORIGIN_CIDRS = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
    "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
]


def _build_protected_networks() -> list:
    """RFC1918 + link-local + CGNAT + Cloudflare IPs + own IPs (anti-self-ban)."""
    nets = list(_HARDCODED_SKIP)
    for cidr in _CF_ORIGIN_CIDRS:
        try:
            nets.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            pass
    try:
        result = subprocess.run(
            ["ip", "-j", "addr"], capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            for iface in json.loads(result.stdout) or []:
                for ai in iface.get("addr_info", []):
                    raw = ai.get("local", "")
                    if not raw:
                        continue
                    try:
                        nets.append(ipaddress.ip_network(raw, strict=False))
                    except ValueError:
                        pass
    except Exception:
        pass
    return nets


_protected_networks: list = []


def _is_protected(ip_str: str) -> bool:
    """True if ip_str must never be blocked in Cloudflare (self-ban / CF-origin guard)."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _protected_networks)
    except ValueError:
        return True  # fail-safe: unknown format -> protect


SCENARIO_CATEGORIES: dict[str, list[int]] = {
    "crowdsecurity/http-bf-wordpress_bf":        [21, 18],
    "crowdsecurity/http-bad-user-agents":        [19],
    "crowdsecurity/http-crawl-non_statics":      [19],
    "crowdsecurity/http-path-traversal-probing": [21, 22],
    "crowdsecurity/http-probing":                [19],
    "crowdsecurity/http-sensitive-files":        [21],
    "crowdsecurity/http-xss-probing":            [21],
    "crowdsecurity/http-sqli-probing":           [21],
    "crowdsecurity/http-backdoors-attempts":     [21],
    "crowdsecurity/http-cve-probing":            [21],
    "crowdsecurity/http-wordpress-xml-rpc":      [21],
    "crowdsecurity/ssh-bf":                      [18, 22],
    "crowdsecurity/ssh-slow-bf":                 [18, 22],
    "crowdsecurity/iptables-scan-multi_ports":   [14],
    "LePresidente/http-generic-403-bf":          [21, 18],
}
DEFAULT_CATEGORIES: list[int] = [21]

# -- Skip-list (RFC1918 + CrowdSec allowlist) -- AbuseIPDB only --------------
_skip_networks: list = list(_HARDCODED_SKIP)
_skip_lock = threading.Lock()


def _load_cs_allowlist() -> None:
    """Extend _skip_networks from `cscli allowlists inspect my_allowlist`."""
    global _skip_networks
    try:
        out = subprocess.check_output(
            ["/usr/bin/cscli", "allowlists", "inspect", "my_allowlist", "-o", "json"],
            timeout=10, stderr=subprocess.DEVNULL,
        )
        items = json.loads(out).get("items", [])
        nets = list(_HARDCODED_SKIP)
        for item in items:
            val = item.get("value", "")
            try:
                cidr = val if "/" in val else f"{val}/32"
                nets.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                pass
        with _skip_lock:
            _skip_networks = nets
        logging.info("skip-list: %d entries from CS allowlist", len(items))
    except Exception as e:
        logging.warning("CS allowlist unavailable (using RFC1918 defaults): %s", e)


def should_skip_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    with _skip_lock:
        return any(addr in net for net in _skip_networks)


# -- State (dedup + backoff + counters) ---------------------------------------
_state_lock = threading.Lock()
_state: dict = {
    "dedup": {},
    "dedup_cf": {},
    "backoff_until": 0.0,
    "reported_total": 0,
    "errors_total": 0,
    "cf_blocked_total": 0,
    "cf_errors_total": 0,
}


def _load_state() -> None:
    try:
        _state.update(json.loads(STATE_FILE.read_text()))
    except Exception:
        pass
    # Ensure Phase-2 keys exist when loading an older state file
    _state.setdefault("dedup_cf", {})
    _state.setdefault("cf_blocked_total", 0)
    _state.setdefault("cf_errors_total", 0)


def _save_state() -> None:
    try:
        STATE_FILE.write_text(json.dumps(_state))
    except Exception as e:
        logging.warning("state save: %s", e)


def _prune_dedup() -> None:
    cutoff = time.time() - DEDUP_TTL
    _state["dedup"] = {k: v for k, v in _state["dedup"].items() if v > cutoff}


def _prune_dedup_cf() -> None:
    cutoff = time.time() - CF_DEDUP_TTL
    _state["dedup_cf"] = {k: v for k, v in _state["dedup_cf"].items() if v > cutoff}


# -- AbuseIPDB reporting ------------------------------------------------------
def _report(ip: str, scenario: str, comment: str, categories: list[int]) -> bool:
    if DRY_RUN:
        logging.info("[DRY] ip=%s scenario=%s categories=%s comment=%r",
                     ip, scenario, categories, comment)
        return True
    if not ABUSEIPDB_KEY:
        logging.error("ABUSEIPDB_KEY not set -- report skipped for %s", ip)
        return False
    now = time.time()
    if now < _state["backoff_until"]:
        logging.warning("backoff active %.0fs -- skipping %s", _state["backoff_until"] - now, ip)
        return False
    body = urllib.parse.urlencode({
        "ip": ip,
        "categories": ",".join(str(c) for c in categories),
        "comment": comment[:1024],
    }).encode()
    req = urllib.request.Request(
        ABUSEIPDB_URL, data=body,
        headers={
            "Key": ABUSEIPDB_KEY,
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read())
            score = result.get("data", {}).get("abuseConfidenceScore", "?")
            logging.info("reported ip=%s scenario=%s categories=%s abuseScore=%s",
                         ip, scenario, categories, score)
            _state["reported_total"] = _state.get("reported_total", 0) + 1
            return True
    except urllib.error.HTTPError as e:
        snip = e.read()[:300]
        if e.code == 429:
            logging.warning("AbuseIPDB 429 -- backoff 3600s")
            _state["backoff_until"] = time.time() + 3600
        elif e.code == 422:
            logging.warning("AbuseIPDB 422 (unprocessable) for %s -- not retrying", ip)
            return True  # treat as done; no point retrying
        else:
            logging.error("AbuseIPDB HTTP %d for %s: %s", e.code, ip, snip)
        _state["errors_total"] = _state.get("errors_total", 0) + 1
        return False
    except Exception as ex:
        logging.error("AbuseIPDB request error for %s: %s", ip, ex)
        _state["errors_total"] = _state.get("errors_total", 0) + 1
        return False


def handle_abuseipdb(alerts: list) -> None:
    _prune_dedup()
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        source   = alert.get("source") or {}
        ip       = source.get("ip") or source.get("value", "")
        scenario = alert.get("scenario", "unknown")

        if not ip or should_skip_ip(ip):
            continue
        if source.get("scope", "").lower() != "ip":
            continue

        # Only report locally observed bans (origin=crowdsec, not simulated).
        # Skips community blocklist IPs (origin=CAPI) to avoid spam.
        decisions = alert.get("decisions") or []
        has_local_ban = any(
            d.get("type") == "ban"
            and d.get("origin") == "crowdsec"
            and not d.get("simulated", False)
            for d in decisions
        )
        if not has_local_ban:
            continue

        dedup_key = f"{ip}:{scenario}"
        now = time.time()
        if dedup_key in _state["dedup"]:
            logging.debug("dedup skip ip=%s scenario=%s", ip, scenario)
            continue

        categories = SCENARIO_CATEGORIES.get(scenario, DEFAULT_CATEGORIES)
        cn  = source.get("cn", "")
        asn = source.get("as_name", "")
        comment = f"CrowdSec: {scenario}"
        if cn:
            comment += f" [{cn}]"
        if asn:
            comment += f" ({asn})"

        if _report(ip, scenario, comment, categories):
            _state["dedup"][dedup_key] = now
            _save_state()


# -- Cloudflare event-driven blocking -----------------------------------------
def _cf_block(ip: str) -> bool:
    if CF_DRY_RUN:
        logging.info("[CF-DRY] would block ip=%s", ip)
        return True
    if not CF_API_TOKEN or not CF_ZONE_ID:
        logging.error("CF_API_TOKEN/CF_ZONE_ID not set -- CF block skipped for %s", ip)
        return False
    body = json.dumps({
        "mode": "block",
        "configuration": {"target": "ip", "value": ip},
        "notes": CF_NOTE_TAG,
    }).encode()
    req = urllib.request.Request(
        f"{CF_API_BASE}/zones/{CF_ZONE_ID}/firewall/access_rules/rules",
        data=body,
        headers={
            "Authorization": f"Bearer {CF_API_TOKEN}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read())
            if result.get("success"):
                logging.info("cf_block ok ip=%s", ip)
                _state["cf_blocked_total"] = _state.get("cf_blocked_total", 0) + 1
                return True
            errors = result.get("errors", [])
            logging.error("cf_block failed ip=%s errors=%s", ip, errors)
            _state["cf_errors_total"] = _state.get("cf_errors_total", 0) + 1
            return False
    except urllib.error.HTTPError as e:
        body_snip = e.read()[:300].decode(errors="replace")
        # CF returns 400/409 when the rule already exists -- treat as success
        if e.code in (400, 409) and ("already" in body_snip.lower() or "exists" in body_snip.lower()):
            logging.info("cf_block ip=%s already blocked (ok)", ip)
            _state["cf_blocked_total"] = _state.get("cf_blocked_total", 0) + 1
            return True
        logging.error("cf_block HTTP %d for %s: %s", e.code, ip, body_snip)
        _state["cf_errors_total"] = _state.get("cf_errors_total", 0) + 1
        return False
    except Exception as ex:
        logging.error("cf_block error for %s: %s", ip, ex)
        _state["cf_errors_total"] = _state.get("cf_errors_total", 0) + 1
        return False


def handle_cloudflare(alerts: list) -> None:
    _prune_dedup_cf()
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        source   = alert.get("source") or {}
        ip       = source.get("ip") or source.get("value", "")
        scenario = alert.get("scenario", "unknown")

        if not ip or _is_protected(ip):
            continue
        if source.get("scope", "").lower() != "ip":
            continue

        # Only push locally observed bans (origin=crowdsec, not simulated).
        decisions = alert.get("decisions") or []
        has_local_ban = any(
            d.get("type") == "ban"
            and d.get("origin") == "crowdsec"
            and not d.get("simulated", False)
            for d in decisions
        )
        if not has_local_ban:
            continue

        now = time.time()
        if ip in _state["dedup_cf"]:
            logging.debug("cf dedup skip ip=%s scenario=%s", ip, scenario)
            continue

        if _cf_block(ip):
            _state["dedup_cf"][ip] = now
            _save_state()


# -- HTTP server ---------------------------------------------------------------
class _Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        logging.debug("http " + fmt, *args)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(raw) if raw else []
        except json.JSONDecodeError as e:
            logging.warning("bad JSON on %s: %s", self.path, e)
            self.send_response(400)
            self.end_headers()
            return

        alerts = payload if isinstance(payload, list) else [payload]

        if self.path == "/crowdsec/abuseipdb":
            with _state_lock:
                try:
                    handle_abuseipdb(alerts)
                except Exception as e:
                    logging.error("handle_abuseipdb error: %s", e)
            self.send_response(200)
            self.end_headers()

        elif self.path == "/crowdsec/cloudflare":
            with _state_lock:
                try:
                    handle_cloudflare(alerts)
                except Exception as e:
                    logging.error("handle_cloudflare error: %s", e)
            self.send_response(200)
            self.end_headers()

        elif self.path == "/crowdsec/event":
            logging.info("event stub: %d alert(s)", len(alerts))
            self.send_response(200)
            self.end_headers()

        else:
            self.send_response(404)
            self.end_headers()


def main():
    global _protected_networks
    Path(STATE_FILE.parent).mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[
            logging.FileHandler("/var/log/crowdsec/notifier.log"),
            logging.StreamHandler(),
        ],
    )
    _load_cs_allowlist()
    _protected_networks = _build_protected_networks()
    logging.info("protected-networks: %d ranges (RFC1918 + CF IPs + own)", len(_protected_networks))
    _load_state()
    mode    = "DRY-RUN" if DRY_RUN    else "LIVE"
    cf_mode = "CF-DRY"  if CF_DRY_RUN else "CF-LIVE"
    logging.info("crowdsec-notifier starting [%s][%s] on %s:%d",
                 mode, cf_mode, LISTEN_HOST, LISTEN_PORT)
    if not ABUSEIPDB_KEY and not DRY_RUN:
        logging.warning("ABUSEIPDB_KEY not set -- all AbuseIPDB reports will fail")
    if not CF_API_TOKEN and not CF_DRY_RUN:
        logging.warning("CF_API_TOKEN not set -- all Cloudflare blocks will fail")
    srv = HTTPServer((LISTEN_HOST, LISTEN_PORT), _Handler)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        _save_state()
        logging.info(
            "crowdsec-notifier stopped (reported=%d errors=%d cf_blocked=%d cf_errors=%d)",
            _state.get("reported_total", 0), _state.get("errors_total", 0),
            _state.get("cf_blocked_total", 0), _state.get("cf_errors_total", 0),
        )


if __name__ == "__main__":
    main()
