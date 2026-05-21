#!/usr/bin/env python3
"""
CrowdSec → Cloudflare IP Sync — V3

Improvements over V2:
  - Anti-self-ban: immutable protected ranges (RFC1918, Cloudflare, Tailscale, self)
  - Circuit breaker: graceful degradation when CF/CrowdSec APIs are down
  - DRY_RUN / shadow mode: CF_DRY_RUN=1 simulates without applying
  - Health + Prometheus metrics: HTTP endpoint on 127.0.0.1:CF_HEALTH_PORT
  - WAL: append-only journal of every CF operation intent
  - SIGHUP hot reload: reload allowlist + config without restart
  - sd_notify watchdog: native systemd integration (WatchdogSec)
  - Adaptive mitigation: route by scenario confidence (low→local, high→CF)
  - Rule collapsing: ipaddress.collapse_addresses() before CF batch
  - Drift detection: reconciliation compares CF state vs local, alerts BetterStack

All V2 features preserved:
  - Graceful shutdown (SIGTERM/SIGINT)
  - Atomic JSON writes (tempfile + os.replace)
  - HTTP retry with exponential backoff
  - RotatingFileHandler (5 MB × 3)
  - IP/CIDR validation before CF calls
  - Config validation at startup
  - JSON state corruption recovery
  - Recidivist escalation
  - ModSecurity CF ban (2h) + AbuseIPDB
  - Auto /24 CIDR block
  - Cloudflare WAF polling
  - OpenResty bouncer AbuseIPDB check
"""

import http.server
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

# ── Configuration ─────────────────────────────────────────────────────────────
CF_API_TOKEN      = os.environ.get("CF_API_TOKEN", "")
CF_ZONE_ID        = os.environ.get("CF_ZONE_ID", "")
CS_API_KEY        = os.environ.get("CS_API_KEY", "")
ABUSEIPDB_KEY     = os.environ.get("ABUSEIPDB_KEY", "")
BETTERSTACK_TOKEN = os.environ.get("BETTERSTACK_TOKEN", "")
BETTERSTACK_INGEST = os.environ.get("BETTERSTACK_INGEST", "")

# V3 — new env vars
DRY_RUN          = os.environ.get("CF_DRY_RUN", "").lower() in ("1", "true", "yes")
HEALTH_PORT      = int(os.environ.get("CF_HEALTH_PORT", "8765"))
RECONCILE_SECS   = int(os.environ.get("CF_RECONCILE_SECS", "300"))
CF_MIN_CONFIDENCE = os.environ.get("CF_MIN_CONFIDENCE", "low")   # low | medium | high
CB_THRESHOLD     = int(os.environ.get("CF_CB_THRESHOLD", "5"))    # circuit breaker failures
CB_RESET_SECS    = float(os.environ.get("CF_CB_RESET_SECS", "120"))

ABUSEIPDB_URL      = "https://api.abuseipdb.com/api/v2/report"
ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
INTERVAL           = 60
NOTE_TAG           = "crowdsec-local-ban"
NOTE_TAG_MODSEC    = "modsec-ban"
NOTE_TAG_CIDR      = "crowdsec-cidr-ban"
LOCAL_ORIGINS      = {"crowdsec", "cscli"}

DECISIONS_LOG       = Path("/var/log/crowdsec/decisions.log")
NGINX_ERROR_LOG     = Path("/var/log/nginx/error.log")
CF_LOG_FILE         = Path("/var/log/crowdsec/cf-sync.log")
WAL_FILE            = Path("/var/log/crowdsec/cf-sync-wal.jsonl")
ABUSE_STATE         = Path("/var/log/crowdsec/abuseipdb-reported.json")
RECIDIV_STATE       = Path("/var/log/crowdsec/recidivists.json")
MODSEC_STATE        = Path("/var/log/crowdsec/modsec-banned.json")
CIDR_STATE          = Path("/var/log/crowdsec/cidr-banned.json")
CF_WAF_STATE        = Path("/var/log/crowdsec/cf_waf_state.json")
BOUNCER_CHECK_STATE = Path("/var/log/crowdsec/bouncer-abusecheck.json")

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

SCENARIO_CATEGORIES: Dict[str, str] = {
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

# Confidence levels — determines whether a scenario syncs to Cloudflare
# low  = local CrowdSec only (skip CF unless CF_MIN_CONFIDENCE=low)
# medium = CF block (default threshold)
# high = CF block + prioritize AbuseIPDB + CIDR consideration
_SCENARIO_CONFIDENCE: Dict[str, str] = {
    "ssh-bf":              "high",
    "ssh-slow-bf":         "high",
    "ssh-time-based-bf":   "high",
    "ssh-cve":             "high",
    "http-exploit":        "high",
    "vpatch-env-access":   "high",
    "vpatch-git-config":   "high",
    "mcp-oauth-bruteforce":"high",
    "http-scan":           "medium",
    "http-probing":        "medium",
    "http-sensitive-files":"medium",
    "http-wordpress-scan": "medium",
    "mcp-oauth-ratelimit": "medium",
    "mcp-oauth-scanner":   "medium",
    "http-bad-user-agent": "low",
    "http-crawl-non_statics":"low",
    "mcp-oauth-bad":       "low",
    "ssh-refused-conn":    "low",
    "default":             "medium",
}
_CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}

# Protected ranges — never ban these IPs regardless of CrowdSec decisions
_PROTECTED_CIDRS_STATIC: List[str] = [
    # RFC1918
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    # Loopback
    "127.0.0.0/8",
    # Link-local
    "169.254.0.0/16", "fe80::/10",
    # Loopback IPv6
    "::1/128",
    # Tailscale CGNAT
    "100.64.0.0/10",
    # Cloudflare anycast IPv4
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    # Cloudflare anycast IPv6
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
    "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
]

# ── Graceful shutdown + hot reload ────────────────────────────────────────────
_shutdown  = threading.Event()
_reload    = threading.Event()   # SIGHUP sets this


def _handle_signal(signum: int, frame) -> None:
    if signum == signal.SIGHUP:
        print("[INFO] SIGHUP reçu — hot reload en attente", file=sys.stderr)
        _reload.set()
    else:
        print(f"[INFO] Signal {signum} reçu — arrêt gracieux en cours…", file=sys.stderr)
        _shutdown.set()


# ── Logging ───────────────────────────────────────────────────────────────────
def _setup_logging() -> logging.Logger:
    logger = logging.getLogger("cf_sync")
    logger.setLevel(logging.INFO)
    logger.propagate = False
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


# ── Metrics ───────────────────────────────────────────────────────────────────
class _Metrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: Dict[str, int] = {
            "cycle_count":            0,
            "cf_api_calls":           0,
            "cf_api_errors":          0,
            "cf_rules_added":         0,
            "cf_rules_removed":       0,
            "decisions_processed":    0,
            "abuseipdb_reports":      0,
            "abuseipdb_checks":       0,
            "recidivists_escalated":  0,
            "drift_detected":         0,
            "circuit_breaker_trips":  0,
            "protected_range_blocks": 0,
            "dry_run_skips":          0,
            "wal_entries":            0,
            "reconcile_runs":         0,
            "collapsed_rules":        0,
        }
        self._gauges: Dict[str, str] = {
            "last_sync_ts":   "",
            "mode":           "dry_run" if DRY_RUN else "normal",
            "uptime_start":   datetime.now(timezone.utc).isoformat(),
        }

    def inc(self, key: str, n: int = 1) -> None:
        with self._lock:
            self._counters[key] = self._counters.get(key, 0) + n

    def set_gauge(self, key: str, val: str) -> None:
        with self._lock:
            self._gauges[key] = val

    def snapshot(self) -> dict:
        with self._lock:
            return {**self._counters, **self._gauges}


metrics = _Metrics()


# ── Circuit breaker ───────────────────────────────────────────────────────────
class CircuitBreaker:
    def __init__(self, name: str, threshold: int = CB_THRESHOLD,
                 reset_secs: float = CB_RESET_SECS) -> None:
        self._name      = name
        self._threshold = threshold
        self._reset     = reset_secs
        self._failures  = 0
        self._opened_at: Optional[float] = None
        self._lock      = threading.Lock()

    @property
    def is_open(self) -> bool:
        with self._lock:
            if self._opened_at is None:
                return False
            if time.monotonic() - self._opened_at > self._reset:
                # Half-open: allow one trial
                log.info("Circuit breaker [%s] half-open — test autorisé", self._name)
                self._opened_at = None
                self._failures  = 0
                return False
            return True

    def ok(self) -> None:
        with self._lock:
            if self._opened_at is not None:
                log.info("Circuit breaker [%s] FERMÉ (succès)", self._name)
                metrics.inc("circuit_breaker_trips")
            self._failures  = 0
            self._opened_at = None

    def fail(self) -> None:
        with self._lock:
            self._failures += 1
            if self._failures >= self._threshold and self._opened_at is None:
                self._opened_at = time.monotonic()
                log.warning(
                    "Circuit breaker [%s] OUVERT après %d échecs — pause %ds",
                    self._name, self._failures, int(self._reset),
                )
                metrics.inc("circuit_breaker_trips")


_cb_cf  = CircuitBreaker("cloudflare")
_cb_cs  = CircuitBreaker("crowdsec")
_cb_abu = CircuitBreaker("abuseipdb")


# ── Config validation ─────────────────────────────────────────────────────────
def _check_config() -> None:
    missing = [
        name for name, val in [
            ("CF_API_TOKEN",  CF_API_TOKEN),
            ("CF_ZONE_ID",    CF_ZONE_ID),
            ("ABUSEIPDB_KEY", ABUSEIPDB_KEY),
        ] if not val
    ]
    if missing:
        sys.exit(f"FATAL: Variables d'environnement manquantes : {', '.join(missing)}")
    if not BETTERSTACK_TOKEN:
        log.warning("BETTERSTACK_TOKEN absent — envoi BetterStack désactivé")
    if not CS_API_KEY:
        log.warning("CS_API_KEY absent — certaines fonctions CrowdSec peuvent échouer")
    if CF_MIN_CONFIDENCE not in _CONFIDENCE_RANK:
        sys.exit(f"FATAL: CF_MIN_CONFIDENCE invalide: {CF_MIN_CONFIDENCE!r} (low|medium|high)")
    if DRY_RUN:
        log.warning("=== MODE DRY RUN ACTIVÉ — aucune modification CF/AbuseIPDB ne sera appliquée ===")


# ── JSON state helpers ────────────────────────────────────────────────────────
def _parse_dt(dt_str: str) -> datetime:
    try:
        return datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
    except Exception:
        return datetime.fromtimestamp(0, tz=timezone.utc)


def _load_json_state(path: Path, default: dict) -> dict:
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


# ── WAL (write-ahead log) ─────────────────────────────────────────────────────
def _wal_log(action: str, target: str, tag: str = "", dry_run: bool = False) -> None:
    """Append a CF operation intent to the WAL before execution."""
    entry = {
        "ts":      datetime.now(timezone.utc).isoformat(),
        "action":  action,    # "add" | "remove" | "reconcile"
        "target":  target,
        "tag":     tag,
        "dry_run": dry_run,
    }
    try:
        with WAL_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
        metrics.inc("wal_entries")
    except Exception as exc:
        log.debug("WAL write failed: %s", exc)


def _wal_trim(max_lines: int = 10_000) -> None:
    """Keep WAL bounded — trim oldest lines when it exceeds max_lines."""
    if not WAL_FILE.exists():
        return
    try:
        lines = WAL_FILE.read_text(encoding="utf-8").splitlines(keepends=True)
        if len(lines) > max_lines:
            keep = lines[-max_lines:]
            tmp_fd, tmp_path = tempfile.mkstemp(dir=WAL_FILE.parent, suffix=".tmp")
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
                f.writelines(keep)
            os.replace(tmp_path, WAL_FILE)
    except Exception as exc:
        log.debug("WAL trim failed: %s", exc)


# ── Protected ranges (anti-self-ban) ─────────────────────────────────────────
_protected_networks: List[ipaddress._BaseNetwork] = []


def _build_protected_networks() -> List[ipaddress._BaseNetwork]:
    nets: List[ipaddress._BaseNetwork] = []
    for cidr in _PROTECTED_CIDRS_STATIC:
        try:
            nets.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            log.warning("Protected CIDR invalide ignoré: %s", cidr)
    # Auto-detect own IPs
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            raw_ip = info[4][0]
            try:
                nets.append(ipaddress.ip_network(raw_ip, strict=False))
            except ValueError:
                pass
    except Exception:
        pass
    return nets


def is_protected(ip_str: str) -> bool:
    """Return True if ip_str falls in a protected range — must NEVER be sent to CF."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        for net in _protected_networks:
            if ip_obj in net:
                return True
    except ValueError:
        pass
    return False


# ── IP / CIDR validation ──────────────────────────────────────────────────────
def _is_valid_ip_or_cidr(value: str, target: str = "ip") -> bool:
    try:
        if target == "ip_range":
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
        return True
    except ValueError:
        log.warning("Valeur invalide ignorée (target=%s): %r", target, value)
        return False


# ── Adaptive mitigation ───────────────────────────────────────────────────────
def _scenario_confidence(scenario: str) -> str:
    key = scenario.split("/")[-1] if "/" in scenario else scenario
    return _SCENARIO_CONFIDENCE.get(key, _SCENARIO_CONFIDENCE["default"])


def _should_sync_to_cf(scenario: str) -> bool:
    """Return True if scenario confidence meets CF_MIN_CONFIDENCE threshold."""
    conf = _scenario_confidence(scenario)
    return _CONFIDENCE_RANK.get(conf, 1) >= _CONFIDENCE_RANK.get(CF_MIN_CONFIDENCE, 0)


# ── HTTP helper with retry ────────────────────────────────────────────────────
_RETRYABLE_HTTP = frozenset({429, 500, 502, 503, 504})


def _http_call(
    req: urllib.request.Request,
    timeout: int = 15,
    max_retries: int = 3,
    backoff: float = 1.0,
) -> bytes:
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
            body = exc.read()
            if exc.code in _RETRYABLE_HTTP and attempt < max_retries - 1:
                continue
            raise urllib.error.HTTPError(
                req.full_url, exc.code, exc.reason, exc.headers, io.BytesIO(body)
            ) from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            if attempt < max_retries - 1:
                continue
            raise
    raise RuntimeError("Exhaustion inattendue de la boucle retry")


# ── sd_notify watchdog ────────────────────────────────────────────────────────
def _sd_notify(state: str) -> None:
    """Send a notification to systemd via NOTIFY_SOCKET (if set)."""
    sock_path = os.environ.get("NOTIFY_SOCKET", "")
    if not sock_path:
        return
    try:
        family = socket.AF_UNIX
        addr   = sock_path
        if sock_path.startswith("@"):
            addr = "\0" + sock_path[1:]
        with socket.socket(family, socket.SOCK_DGRAM) as s:
            s.connect(addr)
            s.sendall(state.encode())
    except Exception as exc:
        log.debug("sd_notify failed: %s", exc)


# ── Health + Prometheus metrics HTTP server ───────────────────────────────────
def _build_health(
    cs_allowlist_size: int = 0,
    recidivists_size: int = 0,
    cidr_size: int = 0,
) -> dict:
    m = metrics.snapshot()
    mode = "dry_run" if DRY_RUN else (
        "degraded" if (_cb_cf.is_open or _cb_cs.is_open) else "healthy"
    )
    return {
        "status":              mode,
        "mode":                mode,
        "cloudflare_cb":       "open" if _cb_cf.is_open else "closed",
        "crowdsec_cb":         "open" if _cb_cs.is_open else "closed",
        "abuseipdb_cb":        "open" if _cb_abu.is_open else "closed",
        "last_sync":           m.get("last_sync_ts", ""),
        "uptime_start":        m.get("uptime_start", ""),
        "cycle_count":         m.get("cycle_count", 0),
        "cf_rules_added":      m.get("cf_rules_added", 0),
        "cf_rules_removed":    m.get("cf_rules_removed", 0),
        "cf_api_errors":       m.get("cf_api_errors", 0),
        "drift_detected":      m.get("drift_detected", 0),
        "allowlist_size":      cs_allowlist_size,
        "recidivists":         recidivists_size,
        "cidr_blocks":         cidr_size,
        "dry_run":             DRY_RUN,
        "cf_min_confidence":   CF_MIN_CONFIDENCE,
    }


def _build_prometheus(snap: Optional[dict] = None) -> str:
    s = snap or metrics.snapshot()
    lines = [
        "# HELP crowdsec_cf_sync_cycles_total Total sync cycles run",
        "# TYPE crowdsec_cf_sync_cycles_total counter",
        f"crowdsec_cf_sync_cycles_total {s.get('cycle_count', 0)}",
        "# HELP crowdsec_cf_sync_cf_api_calls_total Total Cloudflare API calls",
        "# TYPE crowdsec_cf_sync_cf_api_calls_total counter",
        f"crowdsec_cf_sync_cf_api_calls_total {s.get('cf_api_calls', 0)}",
        "# HELP crowdsec_cf_sync_cf_api_errors_total Total Cloudflare API errors",
        "# TYPE crowdsec_cf_sync_cf_api_errors_total counter",
        f"crowdsec_cf_sync_cf_api_errors_total {s.get('cf_api_errors', 0)}",
        "# HELP crowdsec_cf_sync_rules_added_total CF rules added",
        "# TYPE crowdsec_cf_sync_rules_added_total counter",
        f"crowdsec_cf_sync_rules_added_total {s.get('cf_rules_added', 0)}",
        "# HELP crowdsec_cf_sync_rules_removed_total CF rules removed",
        "# TYPE crowdsec_cf_sync_rules_removed_total counter",
        f"crowdsec_cf_sync_rules_removed_total {s.get('cf_rules_removed', 0)}",
        "# HELP crowdsec_cf_sync_drift_detected_total Reconciliation drift events",
        "# TYPE crowdsec_cf_sync_drift_detected_total counter",
        f"crowdsec_cf_sync_drift_detected_total {s.get('drift_detected', 0)}",
        "# HELP crowdsec_cf_sync_circuit_breaker_trips_total Circuit breaker trip count",
        "# TYPE crowdsec_cf_sync_circuit_breaker_trips_total counter",
        f"crowdsec_cf_sync_circuit_breaker_trips_total {s.get('circuit_breaker_trips', 0)}",
        "# HELP crowdsec_cf_sync_protected_blocks_total Blocked self-ban attempts",
        "# TYPE crowdsec_cf_sync_protected_blocks_total counter",
        f"crowdsec_cf_sync_protected_blocks_total {s.get('protected_range_blocks', 0)}",
        "# HELP crowdsec_cf_sync_abuseipdb_reports_total AbuseIPDB reports sent",
        "# TYPE crowdsec_cf_sync_abuseipdb_reports_total counter",
        f"crowdsec_cf_sync_abuseipdb_reports_total {s.get('abuseipdb_reports', 0)}",
        "# HELP crowdsec_cf_sync_dry_run 1 if dry-run mode is active",
        "# TYPE crowdsec_cf_sync_dry_run gauge",
        f"crowdsec_cf_sync_dry_run {1 if DRY_RUN else 0}",
        "# HELP crowdsec_cf_sync_wal_entries_total WAL entries written",
        "# TYPE crowdsec_cf_sync_wal_entries_total counter",
        f"crowdsec_cf_sync_wal_entries_total {s.get('wal_entries', 0)}",
        "",
    ]
    return "\n".join(lines)


# shared state for health endpoint (updated each cycle)
_health_state: dict = {}
_health_lock  = threading.Lock()


def _start_health_server() -> Optional[http.server.HTTPServer]:
    if not HEALTH_PORT:
        return None

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/health":
                with _health_lock:
                    data = dict(_health_state)
                code = 200 if data.get("status") == "healthy" else 503
                body = json.dumps(data, indent=2).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)
            elif self.path == "/metrics":
                body = _build_prometheus(metrics.snapshot()).encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; version=0.0.4")
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, fmt: str, *args: object) -> None:
            pass  # silence access logs

    try:
        srv = http.server.HTTPServer(("127.0.0.1", HEALTH_PORT), _Handler)
        t   = threading.Thread(target=srv.serve_forever, daemon=True, name="health-srv")
        t.start()
        log.info("Health:   http://127.0.0.1:%d/health", HEALTH_PORT)
        log.info("Metrics:  http://127.0.0.1:%d/metrics", HEALTH_PORT)
        return srv
    except OSError as exc:
        log.warning("Health server ne peut pas démarrer sur port %d: %s", HEALTH_PORT, exc)
        return None


# ── Allowlist ─────────────────────────────────────────────────────────────────
def get_crowdsec_allowlist() -> Set[str]:
    if _cb_cs.is_open:
        log.debug("Circuit breaker CrowdSec ouvert — allowlist skip")
        return set()
    try:
        result = subprocess.run(
            ["cscli", "allowlists", "inspect", "my_allowlist", "-o", "json"],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode != 0:
            _cb_cs.fail()
            return set()
        data  = json.loads(result.stdout)
        items = data.get("items", []) or []
        _cb_cs.ok()
        return {item.get("value", "") for item in items if item.get("value")}
    except Exception as exc:
        log.warning("Erreur lecture allowlist CrowdSec: %s", exc)
        _cb_cs.fail()
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


# ── Cloudflare API ────────────────────────────────────────────────────────────
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
    metrics.inc("cf_api_calls")
    try:
        raw    = _http_call(req, timeout=15)
        result = json.loads(raw.decode())
        if not result.get("success"):
            raise RuntimeError(f"CF API error: {result.get('errors')}")
        _cb_cf.ok()
        return result
    except urllib.error.HTTPError as exc:
        body_text = exc.read().decode(errors="replace")
        metrics.inc("cf_api_errors")
        _cb_cf.fail()
        raise RuntimeError(f"HTTP {exc.code} on {method} {path}: {body_text}") from exc
    except Exception as exc:
        metrics.inc("cf_api_errors")
        _cb_cf.fail()
        raise


def get_cf_blocked_ips() -> Dict[str, str]:
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

    # Anti-self-ban: block if protected range
    if target == "ip" and is_protected(ip):
        log.warning("PROTECTED RANGE — refus d'ajouter %s dans CF (anti-self-ban)", ip)
        metrics.inc("protected_range_blocks")
        send_to_betterstack({
            "message":  f"PROTECTED RANGE BLOCK: tentative de ban de {ip} bloquée",
            "platform": "CrowdSec",
            "source":   "anti-self-ban",
            "dt":       datetime.now(timezone.utc).isoformat(),
        })
        return False

    _wal_log("add", ip, tag=tag, dry_run=DRY_RUN)

    if DRY_RUN:
        log.info("[DRY RUN] CF add %s [%s]", ip, tag)
        metrics.inc("dry_run_skips")
        metrics.inc("cf_rules_added")
        return True

    if _cb_cf.is_open:
        log.warning("Circuit breaker CF ouvert — skip add %s", ip)
        return False

    try:
        cf_request("POST", f"/zones/{CF_ZONE_ID}/firewall/access_rules/rules", {
            "mode":          "block",
            "configuration": {"target": target, "value": ip},
            "notes":         tag,
        })
        metrics.inc("cf_rules_added")
        return True
    except Exception as exc:
        log.warning("Impossible d'ajouter %s dans CF [%s]: %s", ip, tag, exc)
        return False


def delete_cf_rule(rule_id: str, ip: str) -> bool:
    _wal_log("remove", ip, dry_run=DRY_RUN)

    if DRY_RUN:
        log.info("[DRY RUN] CF remove %s (rule %s)", ip, rule_id)
        metrics.inc("dry_run_skips")
        metrics.inc("cf_rules_removed")
        return True

    if _cb_cf.is_open:
        log.warning("Circuit breaker CF ouvert — skip delete %s", ip)
        return False

    try:
        cf_request("DELETE", f"/zones/{CF_ZONE_ID}/firewall/access_rules/rules/{rule_id}")
        metrics.inc("cf_rules_removed")
        return True
    except Exception as exc:
        log.warning("Impossible de supprimer la règle CF pour %s: %s", ip, exc)
        return False


# ── Rule collapsing ───────────────────────────────────────────────────────────
def collapse_ips(ips: Set[str]) -> List[str]:
    """
    Collapse a set of individual IPs into the minimal list of IPs + CIDRs
    using ipaddress.collapse_addresses(). Returns strings ready for CF.
    """
    v4: List[ipaddress.IPv4Address] = []
    v6: List[ipaddress.IPv6Address] = []
    raw_pass: List[str] = []

    for ip in ips:
        try:
            obj = ipaddress.ip_address(ip)
            if obj.version == 4:
                v4.append(obj)
            else:
                v6.append(obj)
        except ValueError:
            raw_pass.append(ip)

    collapsed: List[str] = list(raw_pass)
    for net in ipaddress.collapse_addresses(v4):  # type: ignore[arg-type]
        collapsed.append(str(net) if net.prefixlen < 32 else str(net.network_address))
    for net in ipaddress.collapse_addresses(v6):  # type: ignore[arg-type]
        collapsed.append(str(net) if net.prefixlen < 128 else str(net.network_address))

    if len(collapsed) < len(ips):
        saved = len(ips) - len(collapsed)
        log.info("Rule collapsing: %d IPs → %d entrées (%d règles économisées)",
                 len(ips), len(collapsed), saved)
        metrics.inc("collapsed_rules", saved)

    return collapsed


# ── CrowdSec — active bans ────────────────────────────────────────────────────
def _fetch_all_cscli_decisions() -> Optional[list]:
    """
    Fetch ALL active decisions — no --origin flag.
    NOTE: cscli --origin X causes a 25s+ SQLite timeout in CrowdSec ≤ 1.7.8
    (crowdsecurity/crowdsec#4470, fixed in PR #4473). Workaround: fetch all,
    filter client-side.
    """
    if _cb_cs.is_open:
        log.warning("Circuit breaker CrowdSec ouvert — skip fetch decisions")
        return None
    try:
        result = subprocess.run(
            ["cscli", "decisions", "list", "-o", "json"],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode != 0:
            log.warning("cscli decisions list: returncode=%d stderr=%s",
                        result.returncode, (result.stderr or "")[:200])
            _cb_cs.fail()
            return None
        if not result.stdout.strip():
            _cb_cs.ok()
            return []
        data = json.loads(result.stdout)
        if data is None:
            _cb_cs.ok()
            return []
        if not isinstance(data, list):
            log.warning("cscli decisions list: réponse non-liste type=%s", type(data).__name__)
            _cb_cs.fail()
            return None
        _cb_cs.ok()
        return data
    except subprocess.TimeoutExpired:
        log.warning("cscli decisions list: timeout 15s — sentinel (skip sync)")
        _cb_cs.fail()
        return None
    except Exception as exc:
        log.warning("cscli decisions list: erreur %s — sentinel", exc)
        _cb_cs.fail()
        return None


def _cscli_bans_for_origin(
    origin: str, all_decisions: Optional[list] = None
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


# ── CrowdSec — recent bans from decisions.log ─────────────────────────────────
def get_recent_local_bans(hours: int = LOOKBACK_HOURS) -> List[dict]:
    if not DECISIONS_LOG.exists():
        return []

    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    bans: List[dict] = []

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
                    if cs.get("scenario", "").startswith("recidivist-escalation"):
                        continue
                else:
                    continue

                dt_str = d.get("dt", "")
                try:
                    dt = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
                    if dt < cutoff:
                        continue
                except Exception:
                    continue

                ip_val = cs.get("ip", "")
                try:
                    ipaddress.ip_address(ip_val)
                except ValueError:
                    continue  # skip CIDR entries

                bans.append({
                    "ip":       ip_val,
                    "scenario": cs.get("scenario", "unknown"),
                    "origin":   origin or "crowdsec",
                    "dt":       dt_str,
                    "id":       str(cs.get("id", "")),
                })
                metrics.inc("decisions_processed")

    except Exception as exc:
        log.warning("Erreur lecture decisions.log: %s", exc)

    return [b for b in bans if b["ip"]]


# ── Recidivists ───────────────────────────────────────────────────────────────
def load_recidivists() -> dict:
    return _load_json_state(RECIDIV_STATE, {})


def save_recidivists(recidivists: dict) -> None:
    _atomic_write_json(RECIDIV_STATE, recidivists)


def load_reported() -> dict:
    return _load_json_state(ABUSE_STATE, {})


def save_reported(reported: dict) -> None:
    _atomic_write_json(ABUSE_STATE, reported)


def purge_old_recidivists(recidivists: dict) -> dict:
    cutoff = datetime.now(timezone.utc) - timedelta(days=RECIDIV_WINDOW)
    purged = {
        ip: info for ip, info in recidivists.items()
        if not ip.startswith("_") and _parse_dt(info.get("last_seen", "")) >= cutoff
    }
    # Preserve internal cursor key
    if "_cursor" in recidivists:
        purged["_cursor"] = recidivists["_cursor"]
    return purged


def escalate_ban(ip: str, duration: str, scenario: str) -> None:
    comment = f"Recidivist escalation | scenario: {scenario}"
    try:
        subprocess.run(
            ["cscli", "decisions", "add", "--ip", ip, "--duration", duration,
             "--type", "ban", "--reason", comment],
            capture_output=True, text=True, timeout=15, check=True,
        )
        metrics.inc("recidivists_escalated")
    except Exception as exc:
        log.warning("Erreur escalade recidivist %s: %s", ip, exc)


def sync_recidivists(recidivists: dict) -> dict:
    recent_bans = get_recent_local_bans()
    if not recent_bans:
        return recidivists

    # Cursor prevents re-processing the same ban events across cycles.
    # Only bans strictly newer than the cursor are counted; cursor advances
    # to the highest ban timestamp seen this call.
    # First run (no cursor): initialize to now so we don't retroactively re-count
    # bans that a prior daemon instance (V2) already processed.
    cursor_str = recidivists.get("_cursor", "")
    if cursor_str:
        try:
            cursor_dt = _parse_dt(cursor_str)
        except Exception:
            cursor_dt = datetime.now(timezone.utc)
    else:
        cursor_dt = datetime.now(timezone.utc)

    new_cursor_dt = cursor_dt
    changed = False

    for ban in recent_bans:
        # Skip bans at or before the last-processed cursor
        try:
            ban_dt = _parse_dt(ban["dt"])
        except Exception:
            continue
        if ban_dt <= cursor_dt:
            continue

        ip       = ban["ip"]
        scenario = ban["scenario"]

        if ip == "1.2.3.4":
            continue
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        if scenario.startswith("recidivist-escalation"):
            continue

        if ip not in recidivists:
            recidivists[ip] = {"count": 0, "last_seen": ban["dt"]}

        try:
            last = _parse_dt(recidivists[ip].get("last_seen", ""))
            if (datetime.now(timezone.utc) - last).days > RECIDIV_WINDOW:
                recidivists[ip] = {"count": 0, "last_seen": ban["dt"]}
        except Exception:
            pass

        count = recidivists[ip]["count"] + 1
        recidivists[ip] = {"count": count, "last_seen": ban["dt"]}
        changed = True

        if ban_dt > new_cursor_dt:
            new_cursor_dt = ban_dt

        duration = RECIDIV_ESCALATION.get(count - 1, RECIDIV_DEFAULT)
        if duration:
            escalate_ban(ip, duration, scenario)
            log.info("RÉCIDIVE: %s | occurrence #%d | durée escaladée: %s",
                     ip, count, duration)

    if new_cursor_dt > cursor_dt:
        recidivists["_cursor"] = new_cursor_dt.isoformat()

    if changed or new_cursor_dt > cursor_dt:
        save_recidivists(recidivists)
    return recidivists


# ── ModSecurity ───────────────────────────────────────────────────────────────
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


def sync_modsec(
    modsec_state: dict, cs_allowlist: Set[str], reported: dict
) -> Tuple[dict, dict]:
    events = get_recent_modsec_events()
    if not events:
        return modsec_state, reported

    cf_modsec = get_cf_rules_by_tag(NOTE_TAG_MODSEC)
    now       = datetime.now(timezone.utc)
    new_bans  = 0

    by_ip: Dict[str, dict] = {}
    for ev in events:
        ip = ev["ip"]
        if ip not in by_ip or ev["score"] > by_ip[ip]["score"]:
            by_ip[ip] = ev

    for ip, ev in by_ip.items():
        if is_allowlisted(ip, cs_allowlist) or is_protected(ip):
            log.debug("ModSec: %s ignorée (allowlist/protected)", ip)
            continue
        if ip in modsec_state:
            try:
                if (now - _parse_dt(modsec_state[ip]["banned_at"])).total_seconds() < MODSEC_BAN_SECS:
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


# ── OpenResty bouncer ─────────────────────────────────────────────────────────
def get_recent_bouncer_denials(hours: int = 1) -> List[dict]:
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
    denials = get_recent_bouncer_denials(hours=1)
    if not denials:
        return bouncer_check_state

    now = datetime.now(timezone.utc)

    by_ip: Dict[str, dict] = {}
    for ev in denials:
        if ev["ip"] not in by_ip:
            by_ip[ev["ip"]] = ev

    checked = 0
    for ip, ev in by_ip.items():
        if is_allowlisted(ip, cs_allowlist) or is_protected(ip):
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

    cutoff = now - timedelta(days=7)
    bouncer_check_state = {
        k: v for k, v in bouncer_check_state.items()
        if _parse_dt(v.get("checked_at", "")) > cutoff
    }
    return bouncer_check_state


# ── CIDR ban ──────────────────────────────────────────────────────────────────
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
        if is_allowlisted(ip, cs_allowlist) or is_protected(ip):
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
            continue
        if cidr in cf_cidr:
            cidr_state[cidr] = {"banned_at": now.isoformat(), "ip_count": len(ips)}
            continue
        if add_cf_rule(cidr, tag=NOTE_TAG_CIDR, target="ip_range"):
            log.info("CIDR: banni %s dans CF (%d IPs distinctes)", cidr, len(ips))
            try:
                subprocess.run(
                    ["cscli", "decisions", "add", "--range", cidr,
                     "--duration", CIDR_BAN_DURATION, "--type", "ban",
                     "--reason", f"auto-cidr-ban: {len(ips)} IPs from {cidr}"],
                    capture_output=True, text=True, timeout=15,
                )
            except Exception as exc:
                log.warning("CIDR: erreur ajout CrowdSec pour %s: %s", cidr, exc)
            cidr_state[cidr] = {"banned_at": now.isoformat(), "ip_count": len(ips)}
            save_cidr_state(cidr_state)

    # Expire old CIDR bans
    expiry = timedelta(hours=24)
    expired = [
        cidr for cidr, info in cidr_state.items()
        if (now - _parse_dt(info.get("banned_at", ""))).total_seconds() >= expiry.total_seconds()
    ]
    for cidr in expired:
        rule_id = cf_cidr.get(cidr)
        if rule_id:
            delete_cf_rule(rule_id, cidr)
            log.info("CIDR: ban expiré supprimé pour %s", cidr)
        del cidr_state[cidr]

    if expired:
        save_cidr_state(cidr_state)

    return cidr_state


# ── AbuseIPDB ─────────────────────────────────────────────────────────────────
def report_to_abuseipdb_raw(
    ip: str, categories: str, comment: str, timestamp: str
) -> bool:
    if _cb_abu.is_open:
        log.debug("Circuit breaker AbuseIPDB ouvert — skip report %s", ip)
        return False
    if DRY_RUN:
        log.info("[DRY RUN] AbuseIPDB report %s | cats: %s", ip, categories)
        metrics.inc("dry_run_skips")
        return True

    data = urllib.parse.urlencode({
        "ip": ip, "categories": categories,
        "comment": comment, "timestamp": timestamp,
    }).encode("utf-8")
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
        metrics.inc("abuseipdb_reports")
        _cb_abu.ok()
        return True
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        if exc.code == 429:
            log.debug("AbuseIPDB rate limit pour %s", ip)
            _cb_abu.fail()
            return True
        log.warning("Erreur AbuseIPDB %s: HTTP %d — %s", ip, exc.code, body[:300])
        _cb_abu.fail()
        return False
    except Exception as exc:
        log.warning("Erreur AbuseIPDB report %s: %s", ip, exc)
        _cb_abu.fail()
        return False


def check_abuseipdb(ip: str) -> Optional[dict]:
    if _cb_abu.is_open:
        log.debug("Circuit breaker AbuseIPDB ouvert — skip check %s", ip)
        return None
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
        metrics.inc("abuseipdb_checks")
        _cb_abu.ok()
        return result.get("data") or {}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        if exc.code == 429:
            log.debug("AbuseIPDB check rate limit pour %s", ip)
            _cb_abu.fail()
        else:
            log.warning("AbuseIPDB check %s: HTTP %d — %s", ip, exc.code, body[:200])
            _cb_abu.fail()
        return None
    except Exception as exc:
        log.warning("AbuseIPDB check %s: %s", ip, exc)
        _cb_abu.fail()
        return None


def get_categories(scenario: str) -> str:
    for key, cats in SCENARIO_CATEGORIES.items():
        if key in scenario:
            return cats
    return SCENARIO_CATEGORIES["default"]


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
        f"Scenario: {scenario_short} | Origin: {origin} | URIs: {uris_str}"
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

    cutoff_ts = time.time() - 7 * 86400
    reported  = {
        k: v for k, v in reported.items()
        if _parse_dt(v).timestamp() > cutoff_ts
    }
    return reported


# ── BetterStack ───────────────────────────────────────────────────────────────
def send_to_betterstack(payload: dict) -> bool:
    if not BETTERSTACK_TOKEN or not BETTERSTACK_INGEST:
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


# ── Cloudflare sync ───────────────────────────────────────────────────────────
def sync_cloudflare(cs_allowlist: Set[str]) -> None:
    """Sync active CrowdSec bans → Cloudflare, with adaptive mitigation + rule collapsing."""
    if _cb_cf.is_open:
        log.warning("Circuit breaker CF ouvert — sync_cloudflare ignoré (degraded mode)")
        metrics.set_gauge("mode", "degraded")
        return

    active_bans = get_active_bans()
    if active_bans is None:
        log.warning(
            "CF Sync skip — get_active_bans() a échoué (cscli timeout/erreur), "
            "aucune modification CF"
        )
        return

    # Adaptive mitigation: filter bans by confidence
    if CF_MIN_CONFIDENCE != "low":
        recent = get_recent_local_bans()
        scenario_map = {ban["ip"]: ban["scenario"] for ban in recent}
        filtered_bans: Set[str] = set()
        for ip in active_bans:
            scenario = scenario_map.get(ip, "default")
            if _should_sync_to_cf(scenario):
                filtered_bans.add(ip)
            else:
                log.debug("Adaptive mitigation: %s skipped (confidence=%s < %s)",
                          ip, _scenario_confidence(scenario), CF_MIN_CONFIDENCE)
        active_bans = filtered_bans

    # Normalize IPs and apply allowlist / protected range filters
    clean_bans: Set[str] = set()
    for ip in active_bans:
        try:
            norm = str(ipaddress.ip_address(ip))
        except ValueError:
            norm = ip
        if not is_allowlisted(norm, cs_allowlist) and not is_protected(norm):
            clean_bans.add(norm)

    cf_blocked = get_cf_blocked_ips()
    log.info(
        "CF Sync — CrowdSec: %d bans | Cloudflare: %d règles",
        len(clean_bans), len(cf_blocked),
    )

    to_add    = clean_bans - set(cf_blocked)
    to_delete = {ip: rid for ip, rid in cf_blocked.items() if ip not in clean_bans}

    # Collapse IPs to CIDRs before adding (saves CF rules quota)
    to_add_collapsed = set(collapse_ips(to_add))

    added = deleted = 0

    for ip in to_add_collapsed:
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

    metrics.set_gauge("last_sync_ts", datetime.now(timezone.utc).isoformat())
    metrics.set_gauge("mode", "dry_run" if DRY_RUN else "normal")


# ── Reconciliation (drift detection) ─────────────────────────────────────────
def reconcile_state(cs_allowlist: Set[str]) -> int:
    """
    Full reconciliation: compare CF actual state vs CrowdSec active bans.
    Returns number of drifted rules corrected (or detected in DRY_RUN mode).
    """
    _wal_log("reconcile", "full", dry_run=DRY_RUN)
    metrics.inc("reconcile_runs")

    active_bans = get_active_bans()
    if active_bans is None:
        log.warning("Reconciliation: get_active_bans() échoué — skip")
        return 0

    cf_blocked = get_cf_blocked_ips()
    drift_add    = active_bans - set(cf_blocked)
    drift_remove = {ip for ip in cf_blocked if ip not in active_bans}

    drift_count = len(drift_add) + len(drift_remove)

    if drift_count == 0:
        log.debug("Reconciliation: pas de drift détecté")
        return 0

    log.warning(
        "DRIFT DÉTECTÉ: %d règles à ajouter, %d à supprimer",
        len(drift_add), len(drift_remove),
    )
    metrics.inc("drift_detected", drift_count)

    if BETTERSTACK_TOKEN and BETTERSTACK_INGEST:
        send_to_betterstack({
            "message":      f"CF drift detected: +{len(drift_add)} / -{len(drift_remove)}",
            "source":       "reconciliation",
            "platform":     "CrowdSec",
            "drift_add":    list(drift_add)[:20],
            "drift_remove": list(drift_remove)[:20],
            "dry_run":      DRY_RUN,
            "dt":           datetime.now(timezone.utc).isoformat(),
        })

    corrected = 0
    for ip in drift_add:
        if is_allowlisted(ip, cs_allowlist) or is_protected(ip):
            continue
        if add_cf_rule(ip):
            log.info("Reconciliation: ajouté %s (manquant dans CF)", ip)
            corrected += 1
        if _shutdown.is_set():
            break

    for ip, rule_id in {ip: cf_blocked[ip] for ip in drift_remove}.items():
        if delete_cf_rule(rule_id, ip):
            log.info("Reconciliation: supprimé %s (fantôme dans CF)", ip)
            corrected += 1
        if _shutdown.is_set():
            break

    return corrected


# ── Cloudflare WAF polling ────────────────────────────────────────────────────
def load_cf_waf_state() -> dict:
    return _load_json_state(CF_WAF_STATE, {"last_event_dt": None})


def save_cf_waf_state(state: dict) -> None:
    _atomic_write_json(CF_WAF_STATE, state)


def fetch_cf_waf_events(since: str) -> list:
    query = """
    {
      viewer {
        zones(filter: { zoneTag: "%s" }) {
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
    if _cb_cf.is_open:
        log.debug("Circuit breaker CF ouvert — WAF poll ignoré")
        return waf_state, recidivists, reported

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
        if not ip or is_allowlisted(ip, cs_allowlist) or is_protected(ip):
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

        if duration:
            try:
                uris_str = ", ".join(info["uris"][:3]) or "N/A"
                subprocess.run(
                    ["cscli", "decisions", "add", "--ip", ip,
                     "--duration", duration, "--type", "ban",
                     "--reason",
                     f"cloudflare-waf: {info['count']} hits | actions: {info['actions']} | URIs: {uris_str}"],
                    capture_output=True, text=True, timeout=15,
                )
                recidivists[ip] = {
                    "count":     rec_count + 1,
                    "last_seen": info["first_dt"],
                }
                save_recidivists(recidivists)

                abuse_key = f"waf:{ip}:{info['first_dt'][:10]}"
                if abuse_key not in reported:
                    comment = (
                        f"Cloudflare WAF: {info['count']} hits in {CF_WAF_WINDOW_SECS}s | "
                        f"actions: {info['actions']} | URIs: {uris_str}"
                    )
                    if report_to_abuseipdb_raw(ip, "21,19", comment, info["first_dt"]):
                        reported[abuse_key] = now.isoformat()
                        save_reported(reported)

                send_to_betterstack({
                    "message":    f"CF WAF ban: {ip} | {info['count']} hits | {info['actions']}",
                    "source":     "cloudflare_waf",
                    "platform":   "CrowdSec",
                    "cs": {
                        "ip":       ip,
                        "origin":   "cloudflare-waf",
                        "hits":     info["count"],
                        "actions":  info["actions"],
                        "uris":     info["uris"][:5],
                        "duration": duration,
                    },
                    "dt": now.isoformat(),
                })
                log.info("CF WAF: banni %s (%d hits, durée %s)", ip, info["count"], duration)
                banned_count += 1
            except Exception as exc:
                log.warning("CF WAF: erreur ban %s: %s", ip, exc)

    if banned_count > 0:
        save_reported(reported)
        log.info("CF WAF: %d IP(s) bannie(s) ce cycle", banned_count)

    return waf_state, recidivists, reported


# ── Main ──────────────────────────────────────────────────────────────────────
def main() -> None:
    _check_config()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT,  _handle_signal)
    signal.signal(signal.SIGHUP,  _handle_signal)

    # Build protected ranges
    global _protected_networks
    _protected_networks = _build_protected_networks()
    log.info("Protected ranges: %d réseaux chargés", len(_protected_networks))

    log.info(
        "=== CrowdSec CF Sync V3 démarré (interval=%ds | dry_run=%s | "
        "confidence=%s | health_port=%s) ===",
        INTERVAL, DRY_RUN, CF_MIN_CONFIDENCE,
        HEALTH_PORT if HEALTH_PORT else "disabled",
    )

    # Start health/metrics HTTP server
    _start_health_server()

    # Load state
    cs_allowlist        = get_crowdsec_allowlist()
    reported            = load_reported()
    recidivists         = load_recidivists()
    modsec_state        = load_modsec_state()
    cidr_state          = load_cidr_state()
    waf_state           = load_cf_waf_state()
    bouncer_check_state = load_bouncer_check_state()
    recidivists         = purge_old_recidivists(recidivists)

    log.info("Allowlist CrowdSec: %d entrées", len(cs_allowlist))
    log.info("AbuseIPDB: %d IPs dans l'historique", len(reported))
    log.info("Récidivistes connus: %d IPs", len(recidivists))
    log.info("CIDR bannis: %d blocs", len(cidr_state))
    log.info("Bouncer checks en cache: %d IPs", len(bouncer_check_state))

    # Initial catchup
    log.info("Rattrapage des %dh…", LOOKBACK_HOURS)
    reported     = sync_abuseipdb(reported)
    recidivists  = sync_recidivists(recidivists)
    modsec_state, reported = sync_modsec(modsec_state, cs_allowlist, reported)
    cidr_state   = sync_cidr_bans(cidr_state, cs_allowlist)

    # Notify systemd we're ready
    _sd_notify("READY=1\nSTATUS=Running\n")

    loop_count       = 0
    waf_poll_count   = 0
    reconcile_count  = 0
    last_reconcile   = time.monotonic()

    # Trim WAL on startup
    _wal_trim()

    while not _shutdown.is_set():
        cycle_start = time.monotonic()

        # Hot reload if SIGHUP received
        if _reload.is_set():
            _reload.clear()
            log.info("Hot reload: rechargement allowlist + protected ranges")
            cs_allowlist = get_crowdsec_allowlist()
            _protected_networks = _build_protected_networks()
            log.info("Hot reload terminé — allowlist: %d entrées, protected: %d nets",
                     len(cs_allowlist), len(_protected_networks))

        try:
            sync_cloudflare(cs_allowlist)

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
                bouncer_check_state = sync_bouncer_abuseipdb(bouncer_check_state, cs_allowlist)

            recidivists = purge_old_recidivists(recidivists)

            # WAF poll (every CF_WAF_POLL_SECS)
            waf_poll_count += 1
            if (
                not _shutdown.is_set()
                and waf_poll_count % max(1, CF_WAF_POLL_SECS // INTERVAL) == 0
            ):
                waf_state, recidivists, reported = poll_cloudflare_waf(
                    waf_state, recidivists, cs_allowlist, reported
                )

            # Periodic reconciliation (every RECONCILE_SECS)
            if (
                not _shutdown.is_set()
                and (time.monotonic() - last_reconcile) >= RECONCILE_SECS
            ):
                corrected = reconcile_state(cs_allowlist)
                if corrected:
                    log.info("Reconciliation: %d règle(s) corrigée(s)", corrected)
                last_reconcile = time.monotonic()
                reconcile_count += 1
                _wal_trim()

            # Refresh allowlist every 10 cycles
            loop_count += 1
            if not _shutdown.is_set() and loop_count % 10 == 0:
                cs_allowlist = get_crowdsec_allowlist()

            metrics.inc("cycle_count")

        except Exception as exc:
            log.error("Erreur sync: %s", exc, exc_info=True)

        elapsed = time.monotonic() - cycle_start
        log.debug("Cycle %d terminé en %.1fs", loop_count, elapsed)

        # Update health state
        with _health_lock:
            _health_state.update(_build_health(
                cs_allowlist_size=len(cs_allowlist),
                recidivists_size=len(recidivists),
                cidr_size=len(cidr_state),
            ))

        # Watchdog heartbeat
        _sd_notify(f"WATCHDOG=1\nSTATUS=Cycle {loop_count} OK\n")

        _shutdown.wait(timeout=max(0.0, INTERVAL - elapsed))

    log.info("=== Arrêt gracieux terminé (cycles: %d, réconciliations: %d) ===",
             loop_count, reconcile_count)
    _sd_notify("STOPPING=1\n")


if __name__ == "__main__":
    main()
