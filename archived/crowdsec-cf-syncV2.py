#!/usr/bin/env python3
"""
CrowdSec → Cloudflare IP Sync + AbuseIPDB Reporter + Recidivist Escalation
+ ModSecurity → CF Ban immédiat (2h) + Ban /24 automatique — V2

1. Synchronise les bans actifs CrowdSec → Cloudflare IP Access Rules
2. Reporte les nouvelles IPs bannies (48h) → AbuseIPDB
3. Escalade les bans des récidivistes : 1er → CrowdSec gère | 2ème → 24h | 3ème+ → 7j
4. ModSecurity score ≥ 5 → ban CF 2h immédiat + report AbuseIPDB
5. Ban /24 automatique si 2+ IPs distinctes du même /24 en 7j → 24h

Améliorations V2 vs V1 :
- Arrêt gracieux : SIGTERM/SIGINT → threading.Event (sleep interruptible)
- Écritures JSON atomiques : tempfile + os.replace()
- HTTP retry avec backoff exponentiel (urllib, sans dépendances externes)
- RotatingFileHandler : 5 Mo × 3 backups
- Validation IP/CIDR avant tout ajout dans CF
- Validation des tokens requis au démarrage (exit rapide si manquants)
- Récupération sur état JSON corrompu (backup automatique .bak + reset)
- Métriques de cycle (durée en debug log)
- Vérification shutdown entre sous-tâches du cycle
"""

import io
import ipaddress
import json
import logging
import logging.handlers
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# ── Configuration ────────────────────────────────────────────────────────────
CF_API_TOKEN      = os.environ.get("CF_API_TOKEN", "")
CF_ZONE_ID        = os.environ.get("CF_ZONE_ID", "")
CS_API_KEY        = os.environ.get("CS_API_KEY", "")
ABUSEIPDB_KEY     = os.environ.get("ABUSEIPDB_KEY", "")
BETTERSTACK_TOKEN = os.environ.get("BETTERSTACK_TOKEN", "")

ABUSEIPDB_URL      = "https://api.abuseipdb.com/api/v2/report"
ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
BETTERSTACK_INGEST = os.environ.get("BETTERSTACK_INGEST", "")
INTERVAL           = 60
NOTE_TAG           = "crowdsec-local-ban"
NOTE_TAG_MODSEC    = "modsec-ban"
NOTE_TAG_CIDR      = "crowdsec-cidr-ban"
LOCAL_ORIGINS      = {"crowdsec", "cscli"}

DECISIONS_LOG   = Path("/var/log/crowdsec/decisions.log")
NGINX_ERROR_LOG = Path("/var/log/nginx/error.log")
CF_LOG_FILE     = Path("/var/log/crowdsec/cf-sync.log")
ABUSE_STATE     = Path("/var/log/crowdsec/abuseipdb-reported.json")
RECIDIV_STATE   = Path("/var/log/crowdsec/recidivists.json")
MODSEC_STATE    = Path("/var/log/crowdsec/modsec-banned.json")
CIDR_STATE      = Path("/var/log/crowdsec/cidr-banned.json")
BOUNCER_CHECK_STATE = Path("/var/log/crowdsec/bouncer-abusecheck.json")
CF_WAF_STATE    = Path("/var/log/crowdsec/cf_waf_state.json")

LOOKBACK_HOURS     = 48
RECIDIV_WINDOW     = 7     # jours glissants pour récidive IP
CIDR_WINDOW        = 7     # jours glissants pour ban /24
MODSEC_SCORE_MIN   = 5
MODSEC_BAN_SECS    = 7200  # 2h
CIDR_BAN_DURATION  = "24h"
CIDR_THRESHOLD     = 2
CF_WAF_POLL_SECS   = 300
CF_WAF_THRESHOLD   = 3
BOUNCER_CHECK_TTL  = 86400  # check each IP at most once per 24h
CF_WAF_WINDOW_SECS = 300

RECIDIV_ESCALATION = {0: None, 1: "24h"}
RECIDIV_DEFAULT    = "168h"

SCENARIO_CATEGORIES = {
    "http-sensitive-files":   "21,19",
    "http-probing":           "21,19",
    "http-scan":              "21,19",
    "http-bad-user-agent":    "21,19",
    "http-wordpress-scan":    "21,19",
    "http-crawl-non_statics": "21,19",
    "http-exploit":           "21,19",
    "vpatch-env-access":      "21,19",
    "vpatch-git-config":      "21,19",
    "ssh-bf":                 "22",
    "ssh-slow-bf":            "22",
    "ssh-time-based-bf":      "22",
    "ssh-refused-conn":       "22",
    "ssh-cve":                "22",
    "mcp-oauth-bruteforce":   "18,21",
    "mcp-oauth-ratelimit":    "21,19",
    "mcp-oauth-scanner":      "21,19",
    "mcp-oauth-bad":          "21,19",
    "default":                "21,19",
}

# ── Graceful shutdown ────────────────────────────────────────────────────────
_shutdown = threading.Event()


def _handle_signal(signum: int, frame) -> None:
    # log may not be initialised yet if signal fires very early — use stderr
    print(f"[INFO] Signal {signum} reçu — arrêt gracieux en cours…", file=sys.stderr)
    _shutdown.set()


# ── Logging ──────────────────────────────────────────────────────────────────
def _setup_logging() -> logging.Logger:
    logger = logging.getLogger("cf_sync")
    logger.setLevel(logging.INFO)
    logger.propagate = False  # do not forward to root

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    fh = logging.handlers.RotatingFileHandler(
        CF_LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    return logger


log = _setup_logging()


# ── Config validation ────────────────────────────────────────────────────────
def _check_config() -> None:
    missing = [
        name for name, val in [
            ("CF_API_TOKEN",  CF_API_TOKEN),
            ("CF_ZONE_ID",    CF_ZONE_ID),
            ("ABUSEIPDB_KEY", ABUSEIPDB_KEY),
        ]
        if not val
    ]
    if missing:
        sys.exit(f"FATAL: Variables d'environnement manquantes : {', '.join(missing)}")
    if not BETTERSTACK_TOKEN:
        log.warning("BETTERSTACK_TOKEN absent — envoi BetterStack désactivé")
    if not CS_API_KEY:
        log.warning("CS_API_KEY absent — certaines fonctions CrowdSec peuvent échouer")


# ── JSON state helpers ───────────────────────────────────────────────────────
def _parse_dt(dt_str: str) -> datetime:
    """Parse ISO datetime string; returns epoch on error."""
    try:
        return datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
    except Exception:
        return datetime.fromtimestamp(0, tz=timezone.utc)


def _load_json_state(path: Path, default: dict) -> dict:
    """Load JSON with corruption recovery: renames corrupt file to .bak and returns default."""
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("State corrompu %s: %s — reset, backup → .bak", path.name, exc)
        try:
            path.rename(path.with_suffix(".bak"))
        except OSError:
            pass
        return default


def _atomic_write_json(path: Path, data: dict) -> None:
    """Write JSON atomically via a sibling tempfile + os.replace()."""
    tmp_fd, tmp_path = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp_path, path)
    except Exception as exc:
        log.warning("Erreur écriture atomique %s: %s", path.name, exc)
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


# ── IP / CIDR validation ─────────────────────────────────────────────────────
def _is_valid_ip_or_cidr(value: str, target: str = "ip") -> bool:
    """Returns True if value is a valid IP or CIDR before sending to CF."""
    try:
        if target == "ip_range":
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
        return True
    except ValueError:
        log.warning("Valeur invalide ignorée avant envoi CF (target=%s): %r", target, value)
        return False


# ── HTTP helper with retry ───────────────────────────────────────────────────
_RETRYABLE_HTTP = frozenset({429, 500, 502, 503, 504})


def _http_call(
    req: urllib.request.Request,
    timeout: int = 15,
    max_retries: int = 3,
    backoff: float = 1.0,
) -> bytes:
    """
    Execute HTTP request with exponential backoff retry.

    Returns response body bytes on any 2xx success.
    Raises urllib.error.HTTPError for persistent 4xx/5xx (body still readable via e.read()).
    Raises urllib.error.URLError / OSError for network errors.
    Raises RuntimeError if shutdown is requested during a retry wait.
    """
    for attempt in range(max_retries):
        if attempt > 0:
            wait = min(backoff * (2 ** (attempt - 1)), 30.0)
            log.debug("Retry HTTP %d/%d dans %.1fs pour %s",
                      attempt + 1, max_retries, wait, req.full_url)
            if _shutdown.wait(timeout=wait):
                raise RuntimeError("Arrêt gracieux demandé pendant retry HTTP")

        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read()

        except urllib.error.HTTPError as exc:
            body = exc.read()  # consume to release the connection
            if exc.code in _RETRYABLE_HTTP and attempt < max_retries - 1:
                log.debug("HTTP %d retryable (attempt %d/%d) pour %s",
                          exc.code, attempt + 1, max_retries, req.full_url)
                continue
            # Re-raise with body still readable by the caller
            raise urllib.error.HTTPError(
                req.full_url, exc.code, exc.reason, exc.headers, io.BytesIO(body)
            ) from None

        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            if attempt < max_retries - 1:
                log.debug("Erreur réseau '%s' (attempt %d/%d) pour %s",
                          exc, attempt + 1, max_retries, req.full_url)
                continue
            raise

    raise RuntimeError("Exhaustion inattendue de la boucle retry")  # unreachable


# ── Allowlist ────────────────────────────────────────────────────────────────
def get_crowdsec_allowlist() -> Set[str]:
    try:
        result = subprocess.run(
            ["cscli", "allowlists", "inspect", "my_allowlist", "-o", "json"],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode != 0:
            return set()
        data  = json.loads(result.stdout)
        items = data.get("items", []) or []
        return {item.get("value", "") for item in items if item.get("value")}
    except Exception as exc:
        log.warning("Erreur lecture allowlist CrowdSec: %s", exc)
        return set()


def is_allowlisted(ip_str: str, cs_allowlist: Set[str]) -> bool:
    if ip_str in cs_allowlist:
        return True
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        for entry in cs_allowlist:
            try:
                if ip_obj in ipaddress.ip_network(entry, strict=False):
                    return True
            except ValueError:
                pass
    except ValueError:
        pass
    return False


# ── Cloudflare API ───────────────────────────────────────────────────────────
def cf_request(method: str, path: str, data: Optional[dict] = None) -> dict:
    url  = f"https://api.cloudflare.com/client/v4{path}"
    body = json.dumps(data).encode() if data is not None else None
    req  = urllib.request.Request(
        url, data=body, method=method,
        headers={
            "Authorization": f"Bearer {CF_API_TOKEN}",
            "Content-Type":  "application/json",
        },
    )
    try:
        raw    = _http_call(req, timeout=15)
        result = json.loads(raw.decode())
        if not result.get("success"):
            raise RuntimeError(f"CF API error: {result.get('errors')}")
        return result
    except urllib.error.HTTPError as exc:
        body_text = exc.read().decode(errors="replace")
        raise RuntimeError(f"HTTP {exc.code} on {method} {path}: {body_text}") from exc


def get_cf_blocked_ips() -> Dict[str, str]:
    """Returns {ip: rule_id} for all crowdsec-local-ban rules, IPv6 normalised."""
    result = cf_request(
        "GET", f"/zones/{CF_ZONE_ID}/firewall/access_rules/rules?per_page=1000"
    )
    rules: Dict[str, str] = {}
    for rule in result.get("result", []):
        if rule.get("notes") == NOTE_TAG:
            ip = rule.get("configuration", {}).get("value")
            if ip:
                try:
                    ip = str(ipaddress.ip_address(ip))
                except ValueError:
                    pass
                rules[ip] = rule["id"]
    return rules


def get_cf_rules_by_tag(tag: str) -> Dict[str, str]:
    result = cf_request(
        "GET", f"/zones/{CF_ZONE_ID}/firewall/access_rules/rules?per_page=1000"
    )
    rules: Dict[str, str] = {}
    for rule in result.get("result", []):
        if rule.get("notes") == tag:
            val = rule.get("configuration", {}).get("value")
            if val:
                rules[val] = rule["id"]
    return rules


def add_cf_rule(ip: str, tag: str = NOTE_TAG, target: str = "ip") -> bool:
    if not _is_valid_ip_or_cidr(ip, target):
        return False
    try:
        cf_request(
            "POST",
            f"/zones/{CF_ZONE_ID}/firewall/access_rules/rules",
            {"mode": "block", "configuration": {"target": target, "value": ip}, "notes": tag},
        )
        return True
    except Exception as exc:
        log.warning("Impossible d'ajouter %s dans CF [%s]: %s", ip, tag, exc)
        return False


def delete_cf_rule(rule_id: str, ip: str) -> bool:
    try:
        cf_request("DELETE", f"/zones/{CF_ZONE_ID}/firewall/access_rules/rules/{rule_id}")
        return True
    except Exception as exc:
        log.warning("Impossible de supprimer la règle CF pour %s: %s", ip, exc)
        return False


# ── CrowdSec decisions ───────────────────────────────────────────────────────
def _fetch_all_cscli_decisions() -> Optional[List[dict]]:
    """
    Fetch all active decisions (single cscli call, Python-side filtering).
    Returns None on timeout/error (sentinel → skip CF sync).

    NOTE: we intentionally do NOT pass --origin here. cscli --origin X and the
    underlying REST /v1/alerts?origin=X both trigger a 25s+ timeout in CrowdSec
    v1.7.8 due to a go-sqlite3 regression (crowdsecurity/crowdsec#4470, fixed in
    PR #4473 / go-sqlite3 v1.14.32 downgrade, not yet released as of 2026-05-21).
    Workaround: fetch all decisions then filter by origin client-side.
    """
    try:
        result = subprocess.run(
            ["cscli", "decisions", "list", "-o", "json"],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode != 0:
            log.warning(
                "cscli decisions list: returncode=%d stderr=%s",
                result.returncode, (result.stderr or "")[:200],
            )
            return None
        if not result.stdout.strip():
            return []
        data = json.loads(result.stdout)
        if data is None:
            return []
        if not isinstance(data, list):
            log.warning(
                "cscli decisions list: réponse non-liste type=%s", type(data).__name__
            )
            return None
        return data
    except subprocess.TimeoutExpired:
        log.warning("cscli decisions list: timeout 15s — skip sync")
        return None
    except Exception as exc:
        log.warning("cscli decisions list: erreur %s — skip sync", exc)
        return None


def _cscli_bans_for_origin(
    origin: str, all_decisions: Optional[List[dict]]
) -> Optional[Set[str]]:
    if all_decisions is None:
        all_decisions = _fetch_all_cscli_decisions()
    if all_decisions is None:
        return None
    ips: Set[str] = set()
    for alert in all_decisions:
        if not isinstance(alert, dict):
            continue
        for dec in alert.get("decisions") or []:
            if not isinstance(dec, dict):
                continue
            if dec.get("origin", "") != origin:
                continue
            if dec.get("type") != "ban":
                continue
            if dec.get("scope", "").lower() != "ip":
                continue
            value = dec.get("value")
            if value:
                ips.add(value)
    return ips


def get_active_bans() -> Optional[Set[str]]:
    """
    Returns all locally-banned IPs (crowdsec + cscli origins).
    Returns None if cscli failed (caller must skip CF sync).
    """
    all_decisions = _fetch_all_cscli_decisions()
    if all_decisions is None:
        return None
    bans: Set[str] = set()
    for origin in LOCAL_ORIGINS:
        origin_bans = _cscli_bans_for_origin(origin, all_decisions=all_decisions)
        if origin_bans is None:
            return None
        bans |= origin_bans
    return bans


def get_recent_local_bans(hours: int = LOOKBACK_HOURS) -> List[dict]:
    if not DECISIONS_LOG.exists():
        return []

    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    bans: List[dict] = []

    try:
        with DECISIONS_LOG.open(encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    continue

                cs         = d.get("cs", {})
                event_type = cs.get("event_type", "")
                origin     = cs.get("origin", "").lower()

                if event_type == "alert":
                    if cs.get("action") != "banned":
                        continue
                    scenario_alert = cs.get("scenario", "")
                    if "cloudflare-waf" in scenario_alert:
                        continue
                    if scenario_alert.startswith("recidivist-escalation"):
                        continue
                elif event_type == "decision":
                    if origin not in LOCAL_ORIGINS:
                        continue
                    if cs.get("type") != "ban":
                        continue
                    if cs.get("scenario", "").startswith("cloudflare-waf"):
                        continue
                    # FIX: decision events generated by escalate_ban() have scenario
                    # "recidivist-escalation/..." — without this guard they feed back
                    # into sync_recidivists() causing an infinite escalation loop.
                    if cs.get("scenario", "").startswith("recidivist-escalation"):
                        continue
                else:
                    continue

                # FIX: skip CIDR/range bans (e.g. cidr-auto-ban) — AbuseIPDB only
                # accepts single IPs; passing a /24 causes HTTP 422 every cycle.
                ip_val = cs.get("ip", "")
                try:
                    ipaddress.ip_address(ip_val)
                except ValueError:
                    continue

                dt_str = d.get("dt", "")
                try:
                    dt = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
                    if dt < cutoff:
                        continue
                except Exception:
                    continue

                bans.append({
                    "ip":       ip_val,
                    "scenario": cs.get("scenario", "unknown"),
                    "origin":   origin or "crowdsec",
                    "dt":       dt_str,
                    "id":       str(cs.get("id", "")),
                })

    except Exception as exc:
        log.warning("Erreur lecture decisions.log: %s", exc)

    return [b for b in bans if b["ip"]]


# ── Recidivists ──────────────────────────────────────────────────────────────
def load_recidivists() -> dict:
    return _load_json_state(RECIDIV_STATE, {})


def save_recidivists(recidivists: dict) -> None:
    _atomic_write_json(RECIDIV_STATE, recidivists)


def purge_old_recidivists(recidivists: dict) -> dict:
    cutoff = datetime.now(timezone.utc) - timedelta(days=RECIDIV_WINDOW)
    return {
        ip: info for ip, info in recidivists.items()
        if _parse_dt(info.get("last_seen", "")) >= cutoff
    }


def escalate_ban(ip: str, duration: str, scenario: str) -> None:
    try:
        result = subprocess.run(
            [
                "cscli", "decisions", "add",
                "--ip",       ip,
                "--duration", duration,
                "--reason",   f"recidivist-escalation/{scenario}",
                "--type",     "ban",
            ],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            log.info("RÉCIDIVE: %s → ban escaladé %s | scénario: %s", ip, duration, scenario)
        else:
            log.warning("Erreur escalade ban %s: %s", ip, result.stderr.strip())
    except Exception as exc:
        log.warning("Exception escalade ban %s: %s", ip, exc)


def sync_recidivists(recidivists: dict) -> dict:
    recent_bans = get_recent_local_bans(hours=LOOKBACK_HOURS)
    if not recent_bans:
        return recidivists

    seen_ids: Set[str] = set()
    for ban in recent_bans:
        key = f"{ban['ip']}:{ban['id']}"
        if key in seen_ids:
            continue
        seen_ids.add(key)

        ip       = ban["ip"]
        scenario = ban["scenario"]

        if ip == "1.2.3.4":
            continue

        # Belt-and-suspenders: get_recent_local_bans() already filters CIDRs,
        # but guard here too in case state was loaded from a pre-fix run.
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue

        if ip not in recidivists:
            recidivists[ip] = {"count": 1, "last_seen": ban["dt"]}
        else:
            prev_last = recidivists[ip].get("last_seen", "")
            try:
                if _parse_dt(ban["dt"]) <= _parse_dt(prev_last):
                    continue  # same ban or older, skip
            except Exception:
                pass

            count = recidivists[ip]["count"] + 1
            recidivists[ip] = {"count": count, "last_seen": ban["dt"]}

            duration = RECIDIV_ESCALATION.get(count - 1, RECIDIV_DEFAULT)
            if duration:
                escalate_ban(ip, duration, scenario)
                log.info(
                    "RÉCIDIVE: %s | occurrence #%d | durée escaladée: %s",
                    ip, count, duration,
                )

    save_recidivists(recidivists)
    return recidivists


# ── ModSecurity ──────────────────────────────────────────────────────────────
MODSEC_RE = re.compile(
    r"\[client (?P<ip>[\d\.a-fA-F:]+)\] ModSecurity: Access denied.*?"
    r"Total Score: (?P<score>\d+).*?"
    r'\[uri "(?P<uri>[^"]+)"\]',
    re.DOTALL,
)
MODSEC_DATE_RE = re.compile(r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})")
BOUNCER_RE     = re.compile(r"\[Crowdsec\] denied '(?P<ip>[^']+)' with 'ban'")


def get_recent_modsec_events(hours: int = LOOKBACK_HOURS) -> List[dict]:
    if not NGINX_ERROR_LOG.exists():
        return []

    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    events: List[dict] = []

    try:
        with NGINX_ERROR_LOG.open(errors="replace") as f:
            for line in f:
                if "ModSecurity: Access denied" not in line or "Total Score:" not in line:
                    continue

                dt_match = MODSEC_DATE_RE.search(line)
                if not dt_match:
                    continue
                try:
                    dt = datetime.strptime(dt_match.group(1), "%Y/%m/%d %H:%M:%S")
                    dt = dt.replace(tzinfo=timezone.utc)
                    if dt < cutoff:
                        continue
                except Exception:
                    continue

                m = MODSEC_RE.search(line)
                if not m:
                    continue

                score = int(m.group("score"))
                if score < MODSEC_SCORE_MIN:
                    continue

                events.append({
                    "ip":    m.group("ip"),
                    "score": score,
                    "uri":   m.group("uri"),
                    "dt":    dt.isoformat(),
                })
    except Exception as exc:
        log.warning("Erreur lecture nginx error.log: %s", exc)

    return [e for e in events if e["ip"]]


def load_modsec_state() -> dict:
    return _load_json_state(MODSEC_STATE, {})


def save_modsec_state(state: dict) -> None:
    _atomic_write_json(MODSEC_STATE, state)


# ── OpenResty bouncer ────────────────────────────────────────────────────────
def get_recent_bouncer_denials(hours: int = 1) -> List[dict]:
    """Scan nginx error.log for recent OpenResty bouncer denials."""
    if not NGINX_ERROR_LOG.exists():
        return []
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    events: List[dict] = []
    try:
        with NGINX_ERROR_LOG.open(errors="replace") as f:
            for line in f:
                if "[Crowdsec] denied" not in line or "with 'ban'" not in line:
                    continue
                dt_match = MODSEC_DATE_RE.search(line)
                if not dt_match:
                    continue
                try:
                    dt = datetime.strptime(dt_match.group(1), "%Y/%m/%d %H:%M:%S")
                    dt = dt.replace(tzinfo=timezone.utc)
                    if dt < cutoff:
                        continue
                except Exception:
                    continue
                m = BOUNCER_RE.search(line)
                if not m:
                    continue
                req_m  = re.search(r'request: "(?P<method>\w+) (?P<path>\S+)', line)
                host_m = re.search(r'host: "(?P<host>[^"]+)"', line)
                events.append({
                    "ip":     m.group("ip"),
                    "dt":     dt.isoformat(),
                    "method": req_m.group("method") if req_m else "-",
                    "path":   req_m.group("path")   if req_m else "-",
                    "host":   host_m.group("host")  if host_m else "-",
                })
    except Exception as exc:
        log.warning("Erreur lecture bouncer denials nginx error.log: %s", exc)
    return events


def load_bouncer_check_state() -> dict:
    return _load_json_state(BOUNCER_CHECK_STATE, {})


def save_bouncer_check_state(state: dict) -> None:
    _atomic_write_json(BOUNCER_CHECK_STATE, state)


def sync_bouncer_abuseipdb(
    bouncer_check_state: dict, cs_allowlist: Set[str]
) -> dict:
    """Check AbuseIPDB for IPs recently blocked by OpenResty; enrich BetterStack."""
    denials = get_recent_bouncer_denials(hours=1)
    if not denials:
        return bouncer_check_state

    now = datetime.now(timezone.utc)

    # Deduplicate by IP, keep first occurrence for request context
    by_ip: Dict[str, dict] = {}
    for ev in denials:
        if ev["ip"] not in by_ip:
            by_ip[ev["ip"]] = ev

    checked = 0
    for ip, ev in by_ip.items():
        if is_allowlisted(ip, cs_allowlist):
            continue

        last = bouncer_check_state.get(ip, {}).get("checked_at")
        if last:
            try:
                if (now - _parse_dt(last)).total_seconds() < BOUNCER_CHECK_TTL:
                    continue
            except Exception:
                pass

        if _shutdown.is_set():
            break

        data = check_abuseipdb(ip)
        if data is None:
            continue

        score   = data.get("abuseConfidenceScore", 0)
        country = data.get("countryCode", "??")
        isp     = data.get("isp", "?")
        reports = data.get("totalReports", 0)

        log.info(
            "Bouncer AbuseIPDB: %s | score: %d%% | pays: %s | ISP: %s | reports: %d",
            ip, score, country, isp, reports,
        )

        bouncer_check_state[ip] = {"checked_at": now.isoformat(), "score": score}

        send_to_betterstack({
            "message":  f"Bouncer block: {ip} | AbuseIPDB {score}% | {country} | {isp}",
            "platform": "CrowdSec",
            "source":   "openresty-bouncer",
            "cs": {
                "ip":            ip,
                "origin":        "openresty-bouncer",
                "type":          "ban",
                "scenario":      "openresty-bouncer/ban-enforced",
                "abuse_score":   score,
                "country":       country,
                "isp":           isp,
                "total_reports": reports,
                "method":        ev.get("method", "-"),
                "path":          ev.get("path", "-"),
                "host":          ev.get("host", "-"),
            },
            "dt": now.isoformat(),
        })
        checked += 1

    if checked > 0:
        log.info("Bouncer AbuseIPDB: %d IP(s) vérifiée(s) ce cycle", checked)
        save_bouncer_check_state(bouncer_check_state)

    # Purge entries older than 7 days
    cutoff = now - timedelta(days=7)
    bouncer_check_state = {
        k: v for k, v in bouncer_check_state.items()
        if _parse_dt(v.get("checked_at", "")) > cutoff
    }
    return bouncer_check_state


def sync_modsec(
    modsec_state: dict, cs_allowlist: Set[str], reported: dict
) -> Tuple[dict, dict]:
    events = get_recent_modsec_events()
    if not events:
        return modsec_state, reported

    cf_modsec = get_cf_rules_by_tag(NOTE_TAG_MODSEC)
    now       = datetime.now(timezone.utc)
    new_bans  = 0

    # Deduplicate by IP, keep highest score
    by_ip: Dict[str, dict] = {}
    for ev in events:
        ip = ev["ip"]
        if ip not in by_ip or ev["score"] > by_ip[ip]["score"]:
            by_ip[ip] = ev

    for ip, ev in by_ip.items():
        if is_allowlisted(ip, cs_allowlist):
            log.debug("ModSec: %s ignorée (allowlist)", ip)
            continue

        if ip in modsec_state:
            try:
                if (now - _parse_dt(modsec_state[ip]["banned_at"])).total_seconds() < MODSEC_BAN_SECS:
                    continue
            except Exception:
                pass

        if ip not in cf_modsec:
            if add_cf_rule(ip, tag=NOTE_TAG_MODSEC):
                log.info(
                    "ModSec: banni %s dans CF 2h | score: %d | uri: %s",
                    ip, ev["score"], ev["uri"],
                )
                new_bans += 1

        modsec_state[ip] = {"banned_at": now.isoformat(), "score": ev["score"], "uri": ev["uri"]}

        abuse_key = f"modsec:{ip}:{ev['dt'][:10]}"
        if abuse_key not in reported:
            comment = (
                f"ModSecurity block on arleo.eu | "
                f"Anomaly score: {ev['score']} | URI: {ev['uri']}"
            )
            if report_to_abuseipdb_raw(ip, "21", comment, ev["dt"]):
                reported[abuse_key] = now.isoformat()

    if new_bans > 0:
        log.info("ModSec: %d nouvelle(s) IP(s) bannie(s) dans CF", new_bans)
        save_modsec_state(modsec_state)

    # Purge entries older than 3h
    modsec_state = {
        k: v for k, v in modsec_state.items()
        if (now - _parse_dt(v["banned_at"])).total_seconds() < 10800
    }
    return modsec_state, reported


def cleanup_modsec_cf_rules(modsec_state: dict) -> None:
    cf_modsec = get_cf_rules_by_tag(NOTE_TAG_MODSEC)
    now       = datetime.now(timezone.utc)
    for ip, rule_id in cf_modsec.items():
        if ip in modsec_state:
            try:
                if (now - _parse_dt(modsec_state[ip]["banned_at"])).total_seconds() >= MODSEC_BAN_SECS:
                    if delete_cf_rule(rule_id, ip):
                        log.info("ModSec: règle CF expirée supprimée pour %s", ip)
            except Exception:
                pass
        else:
            if delete_cf_rule(rule_id, ip):
                log.info("ModSec: règle CF orpheline supprimée pour %s", ip)


# ── CIDR ban ─────────────────────────────────────────────────────────────────
def load_cidr_state() -> dict:
    return _load_json_state(CIDR_STATE, {})


def save_cidr_state(state: dict) -> None:
    _atomic_write_json(CIDR_STATE, state)


def get_cidr24(ip_str: str) -> Optional[str]:
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.version != 4:
            return None
        return str(ipaddress.ip_network(f"{ip_str}/24", strict=False))
    except ValueError:
        return None


def sync_cidr_bans(cidr_state: dict, cs_allowlist: Set[str]) -> dict:
    recent_bans = get_recent_local_bans(hours=CIDR_WINDOW * 24)
    if not recent_bans:
        return cidr_state

    now = datetime.now(timezone.utc)

    cidr_ips: Dict[str, Set[str]] = {}
    for ban in recent_bans:
        ip = ban["ip"]
        if ip == "1.2.3.4":
            continue
        if is_allowlisted(ip, cs_allowlist):
            continue
        cidr = get_cidr24(ip)
        if not cidr:
            continue
        cidr_ips.setdefault(cidr, set()).add(ip)

    cf_cidr = get_cf_rules_by_tag(NOTE_TAG_CIDR)

    for cidr, ips in cidr_ips.items():
        if len(ips) < CIDR_THRESHOLD:
            continue

        if cidr in cidr_state:
            try:
                if (now - _parse_dt(cidr_state[cidr]["banned_at"])).total_seconds() < 86400:
                    continue
            except Exception:
                pass

        if cidr not in cf_cidr:
            if add_cf_rule(cidr, tag=NOTE_TAG_CIDR, target="ip_range"):
                log.info(
                    "CIDR: banni %s dans CF 24h | %d IPs: %s",
                    cidr, len(ips), ", ".join(sorted(ips)),
                )

        try:
            subprocess.run(
                [
                    "cscli", "decisions", "add",
                    "--range",    cidr,
                    "--duration", CIDR_BAN_DURATION,
                    "--reason",   f"cidr-auto-ban/{len(ips)}-ips",
                    "--type",     "ban",
                ],
                capture_output=True, text=True, timeout=10,
            )
        except Exception as exc:
            log.warning("Erreur ban CIDR CrowdSec %s: %s", cidr, exc)

        cidr_state[cidr] = {"ips": sorted(ips), "banned_at": now.isoformat()}

    save_cidr_state(cidr_state)

    cutoff_ts = time.time() - CIDR_WINDOW * 86400
    cidr_state = {
        k: v for k, v in cidr_state.items()
        if _parse_dt(v["banned_at"]).timestamp() > cutoff_ts
    }
    return cidr_state


# ── AbuseIPDB ────────────────────────────────────────────────────────────────
def load_reported() -> dict:
    return _load_json_state(ABUSE_STATE, {})


def save_reported(reported: dict) -> None:
    _atomic_write_json(ABUSE_STATE, reported)


def get_categories(scenario: str) -> str:
    for key, cats in SCENARIO_CATEGORIES.items():
        if key in scenario.lower():
            return cats
    return SCENARIO_CATEGORIES["default"]


def report_to_abuseipdb_raw(
    ip: str, categories: str, comment: str, timestamp: str
) -> bool:
    data = urllib.parse.urlencode(
        {"ip": ip, "categories": categories, "comment": comment, "timestamp": timestamp}
    ).encode("utf-8")
    req = urllib.request.Request(
        ABUSEIPDB_URL, data=data, method="POST",
        headers={
            "Key":          ABUSEIPDB_KEY,
            "Accept":       "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    try:
        raw    = _http_call(req, timeout=15)
        result = json.loads(raw.decode())
        score  = result.get("data", {}).get("abuseConfidenceScore", "?")
        log.info("AbuseIPDB: reporté %s | score: %s%% | cats: %s", ip, score, categories)
        return True
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        if exc.code == 429:
            log.debug("AbuseIPDB rate limit pour %s", ip)
            return True
        log.warning("Erreur AbuseIPDB %s: HTTP %d — %s", ip, exc.code, body[:300])
        return False
    except Exception as exc:
        log.warning("Erreur AbuseIPDB report %s: %s", ip, exc)
        return False



def check_abuseipdb(ip: str) -> Optional[dict]:
    """GET AbuseIPDB /check for an IP — returns data dict or None on error."""
    url = (
        f"https://api.abuseipdb.com/api/v2/check"
        f"?ipAddress={urllib.parse.quote(ip)}&maxAgeInDays=90"
    )
    req = urllib.request.Request(
        url, method="GET",
        headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
    )
    try:
        raw    = _http_call(req, timeout=15, max_retries=2)
        result = json.loads(raw.decode())
        return result.get("data") or {}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        if exc.code == 429:
            log.debug("AbuseIPDB check rate limit pour %s", ip)
        else:
            log.warning("AbuseIPDB check %s: HTTP %d — %s", ip, exc.code, body[:200])
        return None
    except Exception as exc:
        log.warning("AbuseIPDB check %s: %s", ip, exc)
        return None


def get_nginx_uris_for_ip(ip: str, max_uris: int = 5) -> List[str]:
    uris: List[str] = []
    seen: Set[str]  = set()
    log_files = [
        f for f in Path("/var/log/nginx").glob("*.log")
        if "error" not in f.name and "csp" not in f.name
    ]
    for log_file in log_files:
        if not log_file.exists():
            continue
        try:
            with log_file.open("rb") as f:
                f.seek(0, 2)
                size = f.tell()
                f.seek(max(0, size - 2 * 1024 * 1024))
                chunk = f.read().decode("utf-8", errors="replace")
            for line in reversed(chunk.splitlines()):
                if ip not in line:
                    continue
                m = re.search(r'"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)', line)
                if m:
                    uri = m.group(1)
                    if uri not in seen:
                        seen.add(uri)
                        uris.append(uri)
                        if len(uris) >= max_uris:
                            break
            if len(uris) >= max_uris:
                break
        except Exception:
            pass
    return uris


def report_to_abuseipdb(ip: str, scenario: str, origin: str, timestamp: str) -> bool:
    categories     = get_categories(scenario)
    scenario_short = scenario.split("/")[-1] if "/" in scenario else scenario
    uris           = get_nginx_uris_for_ip(ip)
    uris_str       = ", ".join(uris) if uris else "N/A"
    comment        = (
        f"Detected by CrowdSec on arleo.eu | "
        f"Scenario: {scenario_short} | "
        f"Origin: {origin} | "
        f"URIs: {uris_str}"
    )
    return report_to_abuseipdb_raw(ip, categories, comment, timestamp)


def sync_abuseipdb(reported: dict) -> dict:
    recent_bans = get_recent_local_bans()
    if not recent_bans:
        return reported

    new_reports = 0
    for ban in recent_bans:
        ip       = ban["ip"]
        scenario = ban["scenario"]
        origin   = ban["origin"]
        ban_id   = ban["id"]
        dt       = ban["dt"]
        key      = f"{ip}:{ban_id}"

        if key in reported:
            continue

        if report_to_abuseipdb(ip, scenario, origin, dt):
            reported[key] = datetime.now(timezone.utc).isoformat()
            new_reports += 1

        if _shutdown.wait(timeout=0.5):
            break

    if new_reports > 0:
        log.info("AbuseIPDB: %d nouvelle(s) IP(s) reportée(s)", new_reports)
        save_reported(reported)

    # Purge entries older than 7 days
    cutoff_ts = time.time() - 7 * 86400
    reported  = {
        k: v for k, v in reported.items()
        if _parse_dt(v).timestamp() > cutoff_ts
    }
    return reported


# ── Cloudflare sync ──────────────────────────────────────────────────────────
def sync_cloudflare() -> None:
    active_bans = get_active_bans()
    if active_bans is None:
        log.warning(
            "CF Sync skip — get_active_bans() a échoué (cscli timeout/erreur), "
            "aucune modification CF"
        )
        return

    cf_blocked = get_cf_blocked_ips()
    log.info(
        "CF Sync — CrowdSec: %d bans | Cloudflare: %d règles",
        len(active_bans), len(cf_blocked),
    )

    to_add    = active_bans - set(cf_blocked)
    to_delete = {ip: rid for ip, rid in cf_blocked.items() if ip not in active_bans}

    added = deleted = 0

    for ip in to_add:
        if _shutdown.is_set():
            break
        if add_cf_rule(ip):
            added += 1
            log.info("CF: Ajouté %s", ip)
        time.sleep(0.1)

    for ip, rule_id in to_delete.items():
        if _shutdown.is_set():
            break
        if delete_cf_rule(rule_id, ip):
            deleted += 1
            log.info("CF: Supprimé %s (ban expiré)", ip)
        time.sleep(0.1)

    if added > 0 or deleted > 0:
        log.info("CF Sync terminé — +%d / -%d", added, deleted)


# ── BetterStack ──────────────────────────────────────────────────────────────
def send_to_betterstack(payload: dict) -> bool:
    if not BETTERSTACK_TOKEN:
        return False
    data = json.dumps(payload).encode("utf-8")
    req  = urllib.request.Request(
        BETTERSTACK_INGEST, data=data, method="POST",
        headers={
            "Authorization": f"Bearer {BETTERSTACK_TOKEN}",
            "Content-Type":  "application/json",
        },
    )
    try:
        _http_call(req, timeout=10, max_retries=2)
        return True
    except Exception as exc:
        log.warning("Erreur BetterStack: %s", exc)
        return False


# ── Cloudflare WAF polling ───────────────────────────────────────────────────
def load_cf_waf_state() -> dict:
    return _load_json_state(CF_WAF_STATE, {"last_event_dt": None})


def save_cf_waf_state(state: dict) -> None:
    _atomic_write_json(CF_WAF_STATE, state)


def fetch_cf_waf_events(since: str) -> List[dict]:
    """Poll Cloudflare GraphQL API for WAF events since `since`."""
    query = """{
      viewer {
        zones(filter: {zoneTag: "%s"}) {
          firewallEventsAdaptive(
            filter: {
              datetime_gt: "%s"
              action_in: ["block", "challenge", "managed_challenge", "jschallenge"]
            }
            limit: 1000
            orderBy: [datetime_ASC]
          ) {
            action
            clientIP
            datetime
            clientRequestPath
            clientRequestQuery
          }
        }
      }
    }""" % (CF_ZONE_ID, since)

    data = json.dumps({"query": query}).encode("utf-8")
    req  = urllib.request.Request(
        "https://api.cloudflare.com/client/v4/graphql",
        data=data, method="POST",
        headers={
            "Authorization": f"Bearer {CF_API_TOKEN}",
            "Content-Type":  "application/json",
        },
    )
    raw    = _http_call(req, timeout=20)
    result = json.loads(raw.decode())
    errors = result.get("errors")
    if errors:
        raise RuntimeError(f"CF GraphQL errors: {errors}")
    zones = result.get("data", {}).get("viewer", {}).get("zones", [])
    return zones[0].get("firewallEventsAdaptive", []) if zones else []


def poll_cloudflare_waf(
    waf_state: dict,
    recidivists: dict,
    cs_allowlist: Set[str],
    reported: dict,
) -> Tuple[dict, dict, dict]:
    now     = datetime.now(timezone.utc)
    last_dt = waf_state.get("last_event_dt")
    since   = last_dt if last_dt else (
        now - timedelta(seconds=CF_WAF_WINDOW_SECS)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    try:
        events = fetch_cf_waf_events(since)
    except Exception as exc:
        log.error("CF WAF poll échoué: %s", exc)
        send_to_betterstack({
            "message": f"CF WAF poll error: {exc}",
            "source":  "cloudflare_waf",
            "level":   "error",
            "dt":      now.isoformat(),
        })
        return waf_state, recidivists, reported

    if not events:
        return waf_state, recidivists, reported

    latest_dt = events[-1].get("datetime", "")
    if latest_dt:
        waf_state["last_event_dt"] = latest_dt
        save_cf_waf_state(waf_state)

    window_start = now - timedelta(seconds=CF_WAF_WINDOW_SECS)
    ip_hits: Dict[str, dict] = {}

    for ev in events:
        ev_dt_str = ev.get("datetime", "")
        try:
            ev_dt = datetime.fromisoformat(ev_dt_str.replace("Z", "+00:00"))
        except Exception:
            continue
        if ev_dt < window_start:
            continue

        ip = ev.get("clientIP", "")
        if not ip or is_allowlisted(ip, cs_allowlist):
            continue

        if ip not in ip_hits:
            ip_hits[ip] = {"count": 0, "actions": [], "uris": [], "first_dt": ev_dt_str}
        ip_hits[ip]["count"] += 1
        action = ev.get("action", "")
        if action and action not in ip_hits[ip]["actions"]:
            ip_hits[ip]["actions"].append(action)
        uri = ev.get("clientRequestPath", "")
        if uri and uri not in ip_hits[ip]["uris"]:
            ip_hits[ip]["uris"].append(uri)

    banned_count = 0
    for ip, info in ip_hits.items():
        if info["count"] < CF_WAF_THRESHOLD:
            continue

        rec       = recidivists.get(ip, {})
        rec_count = rec.get("count", 0)
        duration  = RECIDIV_ESCALATION.get(rec_count, RECIDIV_DEFAULT)
        if duration is None:
            duration = "4h"

        uris_str = ", ".join(info["uris"][:3])
        reason   = f"cloudflare-waf/{info['count']}-hits"

        try:
            result = subprocess.run(
                [
                    "cscli", "decisions", "add",
                    "--ip",       ip,
                    "--duration", duration,
                    "--reason",   reason,
                    "--type",     "ban",
                ],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                log.warning("CF WAF: erreur ban %s: %s", ip, result.stderr.strip())
                continue
            log.info(
                "CF WAF: banni %s | hits: %d | durée: %s | URIs: %s",
                ip, info["count"], duration, uris_str,
            )
            banned_count += 1
        except Exception as exc:
            log.warning("CF WAF: exception ban %s: %s", ip, exc)
            continue

        recidivists[ip] = {"count": rec_count + 1, "last_seen": now.isoformat()}

        abuse_key = f"cf-waf:{ip}:{now.strftime('%Y-%m-%d')}"
        if abuse_key not in reported:
            comment = (
                f"Cloudflare WAF block on arleo.eu | "
                f"Hits: {info['count']} in 5min | "
                f"Actions: {', '.join(info['actions'])} | "
                f"URIs: {uris_str}"
            )
            if report_to_abuseipdb_raw(ip, "21,19", comment, info["first_dt"]):
                reported[abuse_key] = now.isoformat()

        send_to_betterstack({
            "dt":       now.isoformat(),
            "host":     socket.gethostname(),
            "platform": "CFWaf",
            "cs": {
                "ip":       ip,
                "hits":     info["count"],
                "action":   ", ".join(info["actions"]),
                "duration": duration,
                "recidive": rec_count + 1,
                "uris":     info["uris"][:5],
                "source":   "cloudflare_waf",
            },
        })

    if banned_count > 0:
        save_recidivists(recidivists)
        save_reported(reported)
        log.info("CF WAF: %d IP(s) bannie(s) ce cycle", banned_count)

    return waf_state, recidivists, reported


# ── Main ─────────────────────────────────────────────────────────────────────
def main() -> None:
    _check_config()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT,  _handle_signal)

    log.info(
        "=== CrowdSec CF Sync V2 + AbuseIPDB + Récidive + ModSec + CIDR Ban "
        "démarré (interval=%ds) ===",
        INTERVAL,
    )

    cs_allowlist = get_crowdsec_allowlist()
    log.info("Allowlist CrowdSec: %d entrées", len(cs_allowlist))

    reported     = load_reported()
    recidivists  = load_recidivists()
    modsec_state = load_modsec_state()
    cidr_state   = load_cidr_state()
    waf_state           = load_cf_waf_state()
    bouncer_check_state = load_bouncer_check_state()
    recidivists         = purge_old_recidivists(recidivists)

    log.info("AbuseIPDB: %d IPs dans l'historique", len(reported))
    log.info("Récidivistes connus: %d IPs", len(recidivists))
    log.info("CIDR bannis: %d blocs", len(cidr_state))
    log.info("Bouncer checks en cache: %d IPs", len(bouncer_check_state))

    log.info("Rattrapage des %dh…", LOOKBACK_HOURS)
    reported     = sync_abuseipdb(reported)
    recidivists  = sync_recidivists(recidivists)
    modsec_state, reported = sync_modsec(modsec_state, cs_allowlist, reported)
    cidr_state   = sync_cidr_bans(cidr_state, cs_allowlist)

    loop_count     = 0
    waf_poll_count = 0

    while not _shutdown.is_set():
        cycle_start = time.monotonic()
        try:
            sync_cloudflare()

            if not _shutdown.is_set():
                reported = sync_abuseipdb(reported)
            if not _shutdown.is_set():
                recidivists = sync_recidivists(recidivists)
            if not _shutdown.is_set():
                modsec_state, reported = sync_modsec(modsec_state, cs_allowlist, reported)
            if not _shutdown.is_set():
                cleanup_modsec_cf_rules(modsec_state)
            if not _shutdown.is_set():
                cidr_state = sync_cidr_bans(cidr_state, cs_allowlist)
            if not _shutdown.is_set():
                bouncer_check_state = sync_bouncer_abuseipdb(
                    bouncer_check_state, cs_allowlist
                )

            recidivists = purge_old_recidivists(recidivists)

            waf_poll_count += 1
            if (
                not _shutdown.is_set()
                and waf_poll_count % (CF_WAF_POLL_SECS // INTERVAL) == 0
            ):
                waf_state, recidivists, reported = poll_cloudflare_waf(
                    waf_state, recidivists, cs_allowlist, reported
                )

            loop_count += 1
            if not _shutdown.is_set() and loop_count % 10 == 0:
                cs_allowlist = get_crowdsec_allowlist()

        except Exception as exc:
            log.error("Erreur sync: %s", exc, exc_info=True)

        elapsed = time.monotonic() - cycle_start
        log.debug("Cycle %d terminé en %.1fs", loop_count, elapsed)

        _shutdown.wait(timeout=max(0.0, INTERVAL - elapsed))

    log.info("=== Arrêt gracieux terminé ===")


if __name__ == "__main__":
    main()
