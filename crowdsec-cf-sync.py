#!/usr/bin/env python3
import os
"""
CrowdSec → Cloudflare IP Sync + AbuseIPDB Reporter + Recidivist Escalation
+ ModSecurity → CF Ban immédiat (2h) + Ban /24 automatique

1. Synchronise les bans actifs CrowdSec → Cloudflare IP Access Rules
2. Reporte les nouvelles IPs bannies (48h) → AbuseIPDB
3. Escalade les bans des récidivistes : 1er → CrowdSec gère | 2ème → 24h | 3ème+ → 7j
4. ModSecurity score ≥ 5 → ban CF 2h immédiat + report AbuseIPDB
5. Ban /24 automatique si 2+ IPs distinctes du même /24 en 7j → 24h

- Tourne toutes les 60 secondes
"""

import ipaddress
import json
import socket
import logging
import re
import subprocess
import time
import urllib.request
import urllib.error
import urllib.parse
from pathlib import Path
from datetime import datetime, timezone, timedelta

# ── Configuration ──────────────────────────────────────────────
CF_API_TOKEN = os.environ.get("CF_API_TOKEN", "")
CF_ZONE_ID = os.environ.get("CF_ZONE_ID", "")
CS_API_KEY = os.environ.get("CS_API_KEY", "")
ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_KEY", "")
ABUSEIPDB_URL   = "https://api.abuseipdb.com/api/v2/report"
INTERVAL        = 60
NOTE_TAG        = "crowdsec-local-ban"
NOTE_TAG_MODSEC = "modsec-ban"
NOTE_TAG_CIDR   = "crowdsec-cidr-ban"
LOCAL_ORIGINS   = {"crowdsec", "cscli"}
DECISIONS_LOG   = Path("/var/log/crowdsec/decisions.log")
NGINX_ERROR_LOG = Path("/var/log/nginx/error.log")
CF_LOG_FILE     = Path("/var/log/crowdsec/cf-sync.log")
ABUSE_STATE     = Path("/var/log/crowdsec/abuseipdb-reported.json")
RECIDIV_STATE   = Path("/var/log/crowdsec/recidivists.json")
MODSEC_STATE    = Path("/var/log/crowdsec/modsec-banned.json")
CIDR_STATE      = Path("/var/log/crowdsec/cidr-banned.json")
LOOKBACK_HOURS  = 48
RECIDIV_WINDOW  = 7    # jours glissants pour récidive IP
CIDR_WINDOW     = 7    # jours glissants pour ban /24
MODSEC_SCORE_MIN    = 5
MODSEC_BAN_SECS     = 7200   # 2h en secondes
CIDR_BAN_DURATION   = "24h"
CIDR_THRESHOLD      = 2

# ── Cloudflare WAF polling ──────────────────────────────────────
BETTERSTACK_TOKEN = os.environ.get("BETTERSTACK_TOKEN", "")
BETTERSTACK_INGEST  = os.environ.get("BETTERSTACK_INGEST", "")
CF_WAF_STATE        = Path("/var/log/crowdsec/cf_waf_state.json")
CF_WAF_POLL_SECS    = 300   # poll toutes les 5 minutes
CF_WAF_THRESHOLD    = 3     # hits minimum pour déclencher un ban
CF_WAF_WINDOW_SECS  = 300   # fenêtre glissante de 5 minutes

# ── Escalade récidive (identique à la version d'hier) ─────────
RECIDIV_ESCALATION = {
    0: None,    # 1er ban → CrowdSec gère (4h par défaut)
    1: "24h",   # 2ème ban → 24h
}
RECIDIV_DEFAULT = "168h"  # 3ème ban et au-delà → 7 jours
# ───────────────────────────────────────────────────────────────

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
    # MCP OAuth proxy scenarios
    "mcp-oauth-bruteforce":   "18,21",   # 18=Brute-Force, 21=Web App Attack
    "mcp-oauth-ratelimit":    "21,19",   # 21=Web App Attack, 19=Bad Web Bot
    "mcp-oauth-scanner":      "21,19",   # 21=Web App Attack, 19=Bad Web Bot
    "mcp-oauth-bad":          "21,19",   # 21=Web App Attack, 19=Bad Web Bot
    "default":                "21,19",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(CF_LOG_FILE),
        logging.StreamHandler()
    ]
)
log = logging.getLogger(__name__)


# ── Allowlist ─────────────────────────────────────────────────

def get_crowdsec_allowlist() -> set:
    """Récupère les IPs/réseaux de la allowlist CrowdSec my_allowlist."""
    try:
        result = subprocess.run(
            ["cscli", "allowlists", "inspect", "my_allowlist", "-o", "json"],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode != 0:
            return set()
        data = json.loads(result.stdout)
        items = data.get("items", []) or []
        return {item.get("value", "") for item in items if item.get("value")}
    except Exception as e:
        log.warning("Erreur lecture allowlist CrowdSec: %s", e)
        return set()


def is_allowlisted(ip_str: str, cs_allowlist: set) -> bool:
    """Retourne True si l'IP est dans la allowlist CrowdSec."""
    if ip_str in cs_allowlist:
        return True
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        for entry in cs_allowlist:
            try:
                net = ipaddress.ip_network(entry, strict=False)
                if ip_obj in net:
                    return True
            except ValueError:
                pass
    except ValueError:
        pass
    return False


# ── Cloudflare API ───────────────────────────────────────────────

def cf_request(method: str, path: str, data=None) -> dict:
    url = f"https://api.cloudflare.com/client/v4{path}"
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(
        url, data=body, method=method,
        headers={
            "Authorization": f"Bearer {CF_API_TOKEN}",
            "Content-Type":  "application/json",
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            result = json.loads(resp.read().decode())
            if not result.get("success"):
                raise RuntimeError(f"CF API error: {result.get('errors')}")
            return result
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        raise RuntimeError(f"HTTP {e.code} on {method} {path}: {body}") from e


def get_cf_blocked_ips() -> dict:
    """Retourne {ip: rule_id} pour toutes les règles crowdsec-local-ban.
    Normalise les IPv6 en forme compressée pour éviter les doublons add/remove."""
    result = cf_request("GET", f"/zones/{CF_ZONE_ID}/firewall/access_rules/rules?per_page=1000")
    rules = {}
    for rule in result.get("result", []):
        if rule.get("notes") == NOTE_TAG:
            ip = rule.get("configuration", {}).get("value")
            if ip:
                try:
                    ip = str(ipaddress.ip_address(ip))  # normalise IPv6 compressé
                except ValueError:
                    pass
                rules[ip] = rule["id"]
    return rules


def get_cf_rules_by_tag(tag: str) -> dict:
    """Retourne {ip/cidr: rule_id} pour un tag donné."""
    result = cf_request("GET", f"/zones/{CF_ZONE_ID}/firewall/access_rules/rules?per_page=1000")
    rules = {}
    for rule in result.get("result", []):
        if rule.get("notes") == tag:
            val = rule.get("configuration", {}).get("value")
            if val:
                rules[val] = rule["id"]
    return rules


def add_cf_rule(ip: str, tag: str = NOTE_TAG, target: str = "ip") -> bool:
    try:
        cf_request("POST", f"/zones/{CF_ZONE_ID}/firewall/access_rules/rules", {
            "mode": "block",
            "configuration": {"target": target, "value": ip},
            "notes": tag
        })
        return True
    except Exception as e:
        log.warning("Impossible d'ajouter %s dans CF [%s]: %s", ip, tag, e)
        return False


def delete_cf_rule(rule_id: str, ip: str) -> bool:
    try:
        cf_request("DELETE", f"/zones/{CF_ZONE_ID}/firewall/access_rules/rules/{rule_id}")
        return True
    except Exception as e:
        log.warning("Impossible de supprimer la règle CF pour %s: %s", ip, e)
        return False


# ── CrowdSec — bans actifs (cscli) ───────────────────────────────
# Fix : l'API REST /v1/decisions pagine sur 1000 et rate les bans cscli.
# On utilise `cscli decisions list --origin X` qui retourne tous les bans
# de l'origin demandé sans limite de pagination.

def _fetch_all_cscli_decisions():
    """
    Récupère TOUTES les décisions actives en une seule requête cscli (~0.3s).
    Evite `--origin X` qui provoque un full-scan SQLite (~110s).
    Retourne None sur timeout/erreur (sentinel).
    """
    try:
        result = subprocess.run(
            ["cscli", "decisions", "list", "-o", "json"],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode != 0:
            log.warning("cscli decisions list: returncode=%d stderr=%s",
                        result.returncode, (result.stderr or "")[:200])
            return None
        if not result.stdout.strip():
            return []
        data = json.loads(result.stdout)
        if data is None:
            return []
        if not isinstance(data, list):
            log.warning("cscli decisions list: réponse non-liste type=%s", type(data).__name__)
            return None
        return data
    except subprocess.TimeoutExpired:
        log.warning("cscli decisions list: timeout 15s — sentinel (skip sync)")
        return None
    except Exception as e:
        log.warning("cscli decisions list: erreur %s — sentinel", e)
        return None


def _cscli_bans_for_origin(origin: str, all_decisions=None):
    """
    Filtre les bans par origin côté Python.
    all_decisions: liste pré-fetchée (Option A) ou None pour fetch à la demande.
    Retourne None si fetch échoue (sentinel).
    Retourne set() vide si fetch OK mais aucun ban pour cette origine.
    """
    if all_decisions is None:
        all_decisions = _fetch_all_cscli_decisions()
    if all_decisions is None:
        return None
    ips = set()
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


def get_active_bans():
    """
    Bans actifs locaux (crowdsec + cscli) — UNE seule requête cscli puis filtrage Python.
    Retourne None si fetch échoue (sentinel: skip sync CF).
    """
    all_decisions = _fetch_all_cscli_decisions()
    if all_decisions is None:
        return None
    bans = set()
    for origin in LOCAL_ORIGINS:
        origin_bans = _cscli_bans_for_origin(origin, all_decisions=all_decisions)
        if origin_bans is None:
            return None
        bans |= origin_bans
    return bans


# ── CrowdSec — bans récents (decisions.log) ──────────────────────

def get_recent_local_bans(hours: int = LOOKBACK_HOURS) -> list:
    """
    Lit decisions.log et retourne les bans locaux des N dernières heures.
    Retourne une liste de dicts avec ip, scenario, origin, dt, id.
    """
    if not DECISIONS_LOG.exists():
        return []

    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    bans = []

    try:
        with DECISIONS_LOG.open() as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    continue

                cs = d.get("cs", {})
                event_type = cs.get("event_type", "")
                origin = cs.get("origin", "").lower()

                # alert = détection CrowdSec locale ; decision = ban cscli escaladé
                if event_type == "alert":
                    if cs.get("action") != "banned":
                        continue
                    scenario_alert = cs.get("scenario", "")
                    # cloudflare-waf alerts déjà reportées par poll_cloudflare_waf
                    if "cloudflare-waf" in scenario_alert:
                        continue
                    # Ignorer nos propres escalades recidivist (elles créent de nouvelles
                    # alertes dans decisions.log → boucle infinie si on les retraite)
                    if scenario_alert.startswith("recidivist-escalation"):
                        continue
                elif event_type == "decision":
                    if origin not in LOCAL_ORIGINS:
                        continue
                    if cs.get("type") != "ban":
                        continue
                    # cloudflare-waf déjà reporté par poll_cloudflare_waf
                    if cs.get("scenario", "").startswith("cloudflare-waf"):
                        continue
                else:
                    continue

                # Filtrer par date
                dt_str = d.get("dt", "")
                try:
                    dt = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
                    if dt < cutoff:
                        continue
                except Exception:
                    continue

                bans.append({
                    "ip":       cs.get("ip", ""),
                    "scenario": cs.get("scenario", "unknown"),
                    "origin":   origin or "crowdsec",
                    "dt":       dt_str,
                    "id":       str(cs.get("id", "")),
                })

    except Exception as e:
        log.warning("Erreur lecture decisions.log: %s", e)

    return [b for b in bans if b["ip"]]


# ── Récidivistes (identique à la version d'hier) ─────────────────

def load_recidivists() -> dict:
    try:
        if RECIDIV_STATE.exists():
            return json.loads(RECIDIV_STATE.read_text())
    except Exception:
        pass
    return {}


def save_recidivists(recidivists: dict):
    try:
        RECIDIV_STATE.write_text(json.dumps(recidivists, indent=2))
    except Exception as e:
        log.warning("Erreur sauvegarde state récidivistes: %s", e)


def purge_old_recidivists(recidivists: dict) -> dict:
    """Supprime les entrées dont le dernier ban date de plus de RECIDIV_WINDOW jours."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=RECIDIV_WINDOW)
    cleaned = {}
    for ip, info in recidivists.items():
        try:
            last = datetime.fromisoformat(info["last_seen"])
            if last >= cutoff:
                cleaned[ip] = info
        except Exception:
            pass
    return cleaned


def escalate_ban(ip: str, duration: str, scenario: str):
    """Force un ban escaladé via cscli."""
    try:
        result = subprocess.run(
            ["cscli", "decisions", "add", "--ip", ip, "--duration", duration,
             "--reason", f"recidivist-escalation/{scenario}", "--type", "ban"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            log.info("RÉCIDIVE: %s → ban escaladé %s | scénario: %s", ip, duration, scenario)
        else:
            log.warning("Erreur escalade ban %s: %s", ip, result.stderr.strip())
    except Exception as e:
        log.warning("Exception escalade ban %s: %s", ip, e)


def sync_recidivists(recidivists: dict) -> dict:
    """
    Pour chaque nouveau ban local :
    - Met à jour le compteur de récidive
    - Si récidiviste → escalade le ban via cscli
    """
    recent_bans = get_recent_local_bans(hours=LOOKBACK_HOURS)
    if not recent_bans:
        return recidivists

    # Dédupliquer par ip:id pour ne pas retraiter les mêmes bans
    seen_ids = set()
    for ban in recent_bans:
        key = f"{ban['ip']}:{ban['id']}"
        if key in seen_ids:
            continue
        seen_ids.add(key)

        ip       = ban["ip"]
        scenario = ban["scenario"]

        # Ignorer les IPs de test
        if ip == "1.2.3.4":
            continue

        if ip not in recidivists:
            # Premier ban connu → initialiser
            recidivists[ip] = {"count": 1, "last_seen": ban["dt"]}
        else:
            prev_last = recidivists[ip].get("last_seen", "")
            # Vérifier que c'est un nouveau ban (plus récent que le dernier connu)
            try:
                dt_ban  = datetime.fromisoformat(ban["dt"].replace("Z", "+00:00"))
                dt_last = datetime.fromisoformat(prev_last.replace("Z", "+00:00"))
                if dt_ban <= dt_last:
                    continue  # même ban ou plus ancien, ignorer
            except Exception:
                pass

            count = recidivists[ip]["count"] + 1
            recidivists[ip] = {"count": count, "last_seen": ban["dt"]}

            # Escalade
            duration = RECIDIV_ESCALATION.get(count - 1, RECIDIV_DEFAULT)
            if duration:
                escalate_ban(ip, duration, scenario)
                log.info("RÉCIDIVE: %s | occurrence #%d | durée escaladée: %s", ip, count, duration)

    save_recidivists(recidivists)
    return recidivists


# ── ModSecurity — lecture error.log ──────────────────────────────

MODSEC_RE = re.compile(
    r'\[client (?P<ip>[\d\.a-fA-F:]+)\] ModSecurity: Access denied.*?'
    r'Total Score: (?P<score>\d+).*?'
    r'\[uri "(?P<uri>[^"]+)"\]',
    re.DOTALL
)
MODSEC_DATE_RE = re.compile(r'(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})')


def get_recent_modsec_events(hours: int = LOOKBACK_HOURS) -> list:
    """Lit nginx/error.log et retourne les événements ModSec score ≥ MODSEC_SCORE_MIN."""
    if not NGINX_ERROR_LOG.exists():
        return []

    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    events = []

    try:
        with NGINX_ERROR_LOG.open(errors="replace") as f:
            for line in f:
                if "ModSecurity: Access denied" not in line:
                    continue
                if "Total Score:" not in line:
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

    except Exception as e:
        log.warning("Erreur lecture nginx error.log: %s", e)

    return [e for e in events if e["ip"]]


def load_modsec_state() -> dict:
    try:
        if MODSEC_STATE.exists():
            return json.loads(MODSEC_STATE.read_text())
    except Exception:
        pass
    return {}


def save_modsec_state(state: dict):
    try:
        MODSEC_STATE.write_text(json.dumps(state, indent=2))
    except Exception as e:
        log.warning("Erreur sauvegarde modsec state: %s", e)


def sync_modsec(modsec_state: dict, cs_allowlist: set, reported: dict) -> tuple:
    """
    Pour chaque événement ModSec récent :
    - Vérifie que l'IP n'est pas dans l'allowlist
    - Ajoute une règle CF modsec-ban (2h) si pas déjà présente
    - Reporte à AbuseIPDB
    """
    events = get_recent_modsec_events()
    if not events:
        return modsec_state, reported

    cf_modsec = get_cf_rules_by_tag(NOTE_TAG_MODSEC)
    now = datetime.now(timezone.utc)
    new_bans = 0

    # Dédupliquer par IP, garder le score le plus élevé
    by_ip = {}
    for ev in events:
        ip = ev["ip"]
        if ip not in by_ip or ev["score"] > by_ip[ip]["score"]:
            by_ip[ip] = ev

    for ip, ev in by_ip.items():
        if is_allowlisted(ip, cs_allowlist):
            log.debug("ModSec: %s ignorée (allowlist)", ip)
            continue

        # Ban encore actif (< 2h) ?
        if ip in modsec_state:
            try:
                banned_at = datetime.fromisoformat(modsec_state[ip]["banned_at"])
                if (now - banned_at).total_seconds() < MODSEC_BAN_SECS:
                    continue
            except Exception:
                pass

        if ip not in cf_modsec:
            if add_cf_rule(ip, tag=NOTE_TAG_MODSEC):
                log.info("ModSec: banni %s dans CF 2h | score: %d | uri: %s",
                         ip, ev["score"], ev["uri"])
                new_bans += 1

        modsec_state[ip] = {
            "banned_at": now.isoformat(),
            "score":     ev["score"],
            "uri":       ev["uri"],
        }

        # Report AbuseIPDB (une fois par IP par jour)
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

    # Purger les entrées > 3h du state modsec
    modsec_state = {
        k: v for k, v in modsec_state.items()
        if (now - datetime.fromisoformat(v["banned_at"])).total_seconds() < 10800
    }

    return modsec_state, reported


def cleanup_modsec_cf_rules(modsec_state: dict):
    """Supprime les règles CF modsec-ban dont le ban 2h est expiré."""
    cf_modsec = get_cf_rules_by_tag(NOTE_TAG_MODSEC)
    now = datetime.now(timezone.utc)
    for ip, rule_id in cf_modsec.items():
        if ip in modsec_state:
            try:
                banned_at = datetime.fromisoformat(modsec_state[ip]["banned_at"])
                if (now - banned_at).total_seconds() >= MODSEC_BAN_SECS:
                    if delete_cf_rule(rule_id, ip):
                        log.info("ModSec: règle CF expirée supprimée pour %s", ip)
            except Exception:
                pass
        else:
            if delete_cf_rule(rule_id, ip):
                log.info("ModSec: règle CF orpheline supprimée pour %s", ip)


# ── Ban /24 automatique ───────────────────────────────────────────

def load_cidr_state() -> dict:
    try:
        if CIDR_STATE.exists():
            return json.loads(CIDR_STATE.read_text())
    except Exception:
        pass
    return {}


def save_cidr_state(state: dict):
    try:
        CIDR_STATE.write_text(json.dumps(state, indent=2))
    except Exception as e:
        log.warning("Erreur sauvegarde cidr state: %s", e)


def get_cidr24(ip_str: str):
    """Retourne le /24 d'une IPv4, None si IPv6 ou invalide."""
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.version != 4:
            return None
        return str(ipaddress.ip_network(f"{ip_str}/24", strict=False))
    except ValueError:
        return None


def sync_cidr_bans(cidr_state: dict, cs_allowlist: set) -> dict:
    """
    Analyse les bans locaux sur 7j et ban le /24 si 2+ IPs distinctes détectées.
    """
    recent_bans = get_recent_local_bans(hours=CIDR_WINDOW * 24)
    if not recent_bans:
        return cidr_state

    now = datetime.now(timezone.utc)

    # Collecter les IPs par /24
    cidr_ips: dict = {}
    for ban in recent_bans:
        ip = ban["ip"]
        if ip == "1.2.3.4":
            continue
        if is_allowlisted(ip, cs_allowlist):
            continue
        cidr = get_cidr24(ip)
        if not cidr:
            continue
        if cidr not in cidr_ips:
            cidr_ips[cidr] = set()
        cidr_ips[cidr].add(ip)

    cf_cidr = get_cf_rules_by_tag(NOTE_TAG_CIDR)

    for cidr, ips in cidr_ips.items():
        if len(ips) < CIDR_THRESHOLD:
            continue

        # Ban encore actif (< 24h) ?
        if cidr in cidr_state:
            try:
                banned_at = datetime.fromisoformat(cidr_state[cidr]["banned_at"])
                if (now - banned_at).total_seconds() < 86400:
                    continue
            except Exception:
                pass

        # Ban CF
        if cidr not in cf_cidr:
            if add_cf_rule(cidr, tag=NOTE_TAG_CIDR, target="ip_range"):
                log.info("CIDR: banni %s dans CF 24h | %d IPs: %s",
                         cidr, len(ips), ", ".join(sorted(ips)))

        # Ban CrowdSec
        try:
            subprocess.run(
                ["cscli", "decisions", "add", "--range", cidr,
                 "--duration", CIDR_BAN_DURATION,
                 "--reason", f"cidr-auto-ban/{len(ips)}-ips", "--type", "ban"],
                capture_output=True, text=True, timeout=10
            )
        except Exception as e:
            log.warning("Erreur ban CIDR CrowdSec %s: %s", cidr, e)

        cidr_state[cidr] = {
            "ips":       sorted(ips),
            "banned_at": now.isoformat(),
        }

    save_cidr_state(cidr_state)

    # Purger les entrées > 7 jours
    cidr_state = {
        k: v for k, v in cidr_state.items()
        if datetime.fromisoformat(v["banned_at"]).timestamp() > (time.time() - CIDR_WINDOW * 86400)
    }

    return cidr_state


# ── AbuseIPDB ─────────────────────────────────────────────────────

def load_reported() -> dict:
    try:
        if ABUSE_STATE.exists():
            return json.loads(ABUSE_STATE.read_text())
    except Exception:
        pass
    return {}


def save_reported(reported: dict):
    try:
        ABUSE_STATE.write_text(json.dumps(reported, indent=2))
    except Exception as e:
        log.warning("Erreur sauvegarde state AbuseIPDB: %s", e)


def get_categories(scenario: str) -> str:
    for key, cats in SCENARIO_CATEGORIES.items():
        if key in scenario.lower():
            return cats
    return SCENARIO_CATEGORIES["default"]


def report_to_abuseipdb_raw(ip: str, categories: str, comment: str,
                             timestamp: str) -> bool:
    """Report brut vers AbuseIPDB avec catégories et commentaire fournis."""
    data = urllib.parse.urlencode({
        "ip":         ip,
        "categories": categories,
        "comment":    comment,
        "timestamp":  timestamp,
    }).encode("utf-8")

    req = urllib.request.Request(
        ABUSEIPDB_URL, data=data, method="POST",
        headers={
            "Key":          ABUSEIPDB_KEY,
            "Accept":       "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            result = json.loads(resp.read().decode())
            score = result.get("data", {}).get("abuseConfidenceScore", "?")
            log.info("AbuseIPDB: reporté %s | score: %s%% | cats: %s",
                     ip, score, categories)
            return True
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        if e.code == 429:
            log.debug("AbuseIPDB rate limit pour %s", ip)
            return True
        log.warning("Erreur AbuseIPDB %s: HTTP %d — %s", ip, e.code, body[:300])
        return False
    except Exception as e:
        log.warning("Erreur AbuseIPDB report %s: %s", ip, e)
        return False


def get_nginx_uris_for_ip(ip: str, max_uris: int = 5) -> list:
    """Cherche les dernières URIs tentées par cette IP dans les access.log nginx."""
    uris = []
    seen = set()
    log_files = list(Path("/var/log/nginx").glob("*.log"))
    log_files = [f for f in log_files if "error" not in f.name and "csp" not in f.name]
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


def report_to_abuseipdb(ip: str, scenario: str, origin: str,
                         timestamp: str) -> bool:
    categories = get_categories(scenario)
    # Extraire le nom court du scénario (ignorer les préfixes recidivist-escalation/)
    scenario_short = scenario.split("/")[-1] if "/" in scenario else scenario
    uris = get_nginx_uris_for_ip(ip)
    uris_str = ", ".join(uris) if uris else "N/A"
    comment = (
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

        time.sleep(0.5)

    if new_reports > 0:
        log.info("AbuseIPDB: %d nouvelle(s) IP(s) reportée(s)", new_reports)
        save_reported(reported)

    # Nettoyer les entrées > 7 jours
    cutoff_ts = time.time() - (7 * 86400)
    reported = {
        k: v for k, v in reported.items()
        if datetime.fromisoformat(v).timestamp() > cutoff_ts
    }

    return reported


# ── Cloudflare Sync ───────────────────────────────────────────────

def sync_cloudflare():
    active_bans = get_active_bans()
    if active_bans is None:
        log.warning("CF Sync skip — get_active_bans() a échoué (cscli timeout/erreur), aucune modification CF")
        return
    cf_blocked  = get_cf_blocked_ips()

    log.info("CF Sync — CrowdSec: %d bans | Cloudflare: %d règles",
             len(active_bans), len(cf_blocked))

    to_add    = active_bans - set(cf_blocked.keys())
    to_delete = {ip: rid for ip, rid in cf_blocked.items() if ip not in active_bans}

    added = deleted = 0

    for ip in to_add:
        if add_cf_rule(ip):
            added += 1
            log.info("CF: Ajouté %s", ip)
        time.sleep(0.1)

    for ip, rule_id in to_delete.items():
        if delete_cf_rule(rule_id, ip):
            deleted += 1
            log.info("CF: Supprimé %s (ban expiré)", ip)
        time.sleep(0.1)

    if added > 0 or deleted > 0:
        log.info("CF Sync terminé — +%d / -%d", added, deleted)



# ── BetterStack ───────────────────────────────────────────────────

def send_to_betterstack(payload: dict) -> bool:
    """Envoie un événement structuré vers BetterStack Logs (source crowdsec-decisions)."""
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        BETTERSTACK_INGEST, data=data, method="POST",
        headers={
            "Authorization": f"Bearer {BETTERSTACK_TOKEN}",
            "Content-Type":  "application/json",
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status in (200, 202)
    except Exception as e:
        log.warning("Erreur BetterStack: %s", e)
        return False


# ── Cloudflare WAF polling ────────────────────────────────────────

def load_cf_waf_state() -> dict:
    try:
        if CF_WAF_STATE.exists():
            return json.loads(CF_WAF_STATE.read_text())
    except Exception:
        pass
    return {"last_event_dt": None}


def save_cf_waf_state(state: dict):
    try:
        CF_WAF_STATE.write_text(json.dumps(state, indent=2))
    except Exception as e:
        log.warning("Erreur sauvegarde cf_waf_state: %s", e)


def fetch_cf_waf_events(since: str) -> list:
    """Interroge l'API GraphQL Cloudflare pour les événements WAF depuis `since`."""
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
    req = urllib.request.Request(
        "https://api.cloudflare.com/client/v4/graphql",
        data=data, method="POST",
        headers={
            "Authorization": f"Bearer {CF_API_TOKEN}",
            "Content-Type":  "application/json",
        }
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        result = json.loads(resp.read().decode())
    errors = result.get("errors")
    if errors:
        raise RuntimeError(f"CF GraphQL errors: {errors}")
    zones = result.get("data", {}).get("viewer", {}).get("zones", [])
    if not zones:
        return []
    return zones[0].get("firewallEventsAdaptive", [])


def poll_cloudflare_waf(
    waf_state: dict,
    recidivists: dict,
    cs_allowlist: set,
    reported: dict,
) -> tuple:
    """
    Poll les événements WAF Cloudflare, détecte les IPs avec CF_WAF_THRESHOLD+
    hits dans la fenêtre glissante et les banne via CrowdSec avec escalade récidive.
    """
    now = datetime.now(timezone.utc)

    last_dt = waf_state.get("last_event_dt")
    if last_dt:
        since = last_dt
    else:
        since = (now - timedelta(seconds=CF_WAF_WINDOW_SECS)).strftime("%Y-%m-%dT%H:%M:%SZ")

    try:
        events = fetch_cf_waf_events(since)
    except Exception as e:
        log.error("CF WAF poll échoué: %s", e)
        send_to_betterstack({
            "message": f"CF WAF poll error: {e}",
            "source":  "cloudflare_waf",
            "level":   "error",
            "dt":      now.isoformat(),
        })
        return waf_state, recidivists, reported

    if not events:
        return waf_state, recidivists, reported

    # Mettre à jour last_event_dt avec le plus récent
    latest_dt = events[-1].get("datetime", "")
    if latest_dt:
        waf_state["last_event_dt"] = latest_dt
        save_cf_waf_state(waf_state)

    # Grouper par IP dans la fenêtre glissante
    window_start = now - timedelta(seconds=CF_WAF_WINDOW_SECS)
    ip_hits: dict = {}

    for ev in events:
        ev_dt_str = ev.get("datetime", "")
        try:
            ev_dt = datetime.fromisoformat(ev_dt_str.replace("Z", "+00:00"))
        except Exception:
            continue
        if ev_dt < window_start:
            continue

        ip = ev.get("clientIP", "")
        if not ip:
            continue
        if is_allowlisted(ip, cs_allowlist):
            continue

        if ip not in ip_hits:
            ip_hits[ip] = {"count": 0, "actions": [], "uris": [], "first_dt": ev_dt_str}
        ip_hits[ip]["count"] += 1
        action = ev.get("action", "")
        if action not in ip_hits[ip]["actions"]:
            ip_hits[ip]["actions"].append(action)
        uri = ev.get("clientRequestPath", "")
        if uri and uri not in ip_hits[ip]["uris"]:
            ip_hits[ip]["uris"].append(uri)

    banned_count = 0
    for ip, info in ip_hits.items():
        if info["count"] < CF_WAF_THRESHOLD:
            continue

        # Durée via logique de récidive existante
        rec = recidivists.get(ip, {})
        rec_count = rec.get("count", 0)
        duration = RECIDIV_ESCALATION.get(rec_count, RECIDIV_DEFAULT)
        if duration is None:
            duration = "4h"

        uris_str = ", ".join(info["uris"][:3])
        reason = f"cloudflare-waf/{info['count']}-hits"

        try:
            result = subprocess.run(
                ["cscli", "decisions", "add", "--ip", ip,
                 "--duration", duration, "--reason", reason, "--type", "ban"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                log.warning("CF WAF: erreur ban %s: %s", ip, result.stderr.strip())
                continue
            log.info("CF WAF: banni %s | hits: %d | durée: %s | URIs: %s",
                     ip, info["count"], duration, uris_str)
            banned_count += 1
        except Exception as e:
            log.warning("CF WAF: exception ban %s: %s", ip, e)
            continue

        # Mise à jour récidivistes
        recidivists[ip] = {
            "count":     rec_count + 1,
            "last_seen": now.isoformat(),
        }

        # AbuseIPDB (une fois par IP par jour)
        abuse_key = f"cf-waf:{ip}:{now.strftime('%Y-%m-%d')}"
        if abuse_key not in reported:
            cats = "21,19"
            comment = (
                f"Cloudflare WAF block on arleo.eu | "
                f"Hits: {info['count']} in 5min | "
                f"Actions: {', '.join(info['actions'])} | "
                f"URIs: {uris_str}"
            )
            if report_to_abuseipdb_raw(ip, cats, comment, info["first_dt"]):
                reported[abuse_key] = now.isoformat()

        # BetterStack
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


# ── Main ─────────────────────────────────────────────────────────

def main():
    log.info(
        "=== CrowdSec CF Sync + AbuseIPDB + Récidive + ModSec + CIDR Ban "
        "démarré (interval=%ds) ===", INTERVAL
    )

    # Charger la allowlist CrowdSec au démarrage
    cs_allowlist = get_crowdsec_allowlist()
    log.info("Allowlist CrowdSec: %d entrées", len(cs_allowlist))

    reported     = load_reported()
    recidivists  = load_recidivists()
    modsec_state = load_modsec_state()
    cidr_state   = load_cidr_state()
    waf_state    = load_cf_waf_state()
    recidivists  = purge_old_recidivists(recidivists)

    log.info("AbuseIPDB: %d IPs dans l'historique", len(reported))
    log.info("Récidivistes connus: %d IPs", len(recidivists))
    log.info("CIDR bannis: %d blocs", len(cidr_state))

    # Rattrapage initial des 48h au démarrage
    log.info("Rattrapage des %dh...", LOOKBACK_HOURS)
    reported    = sync_abuseipdb(reported)
    recidivists = sync_recidivists(recidivists)
    modsec_state, reported = sync_modsec(modsec_state, cs_allowlist, reported)
    cidr_state  = sync_cidr_bans(cidr_state, cs_allowlist)

    loop_count = 0
    waf_poll_count = 0

    while True:
        try:
            sync_cloudflare()
            reported     = sync_abuseipdb(reported)
            recidivists  = sync_recidivists(recidivists)
            modsec_state, reported = sync_modsec(modsec_state, cs_allowlist, reported)
            cleanup_modsec_cf_rules(modsec_state)
            cidr_state   = sync_cidr_bans(cidr_state, cs_allowlist)
            recidivists  = purge_old_recidivists(recidivists)

            # Poll Cloudflare WAF toutes les 5 minutes
            waf_poll_count += 1
            if waf_poll_count % (CF_WAF_POLL_SECS // INTERVAL) == 0:
                waf_state, recidivists, reported = poll_cloudflare_waf(
                    waf_state, recidivists, cs_allowlist, reported
                )

            # Rafraîchir la allowlist CrowdSec toutes les 10 minutes
            loop_count += 1
            if loop_count % 10 == 0:
                cs_allowlist = get_crowdsec_allowlist()

        except Exception as e:
            log.error("Erreur sync: %s", e, exc_info=True)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
