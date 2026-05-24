#!/usr/bin/env python3
"""
CrowdSec → Cloudflare IP Sync — V4

Improvements over V3:
  - fsync WAL + atomic writes: write-ahead log is now truly crash-durable
  - State versioning: all state files wrapped in {version, sha256, state} envelope
  - Snapshot checksum: sha256 detects silent disk corruption on every load
  - CIDR-aware reconciliation: drift_add excludes IPs already covered by /24 CIDR blocks
  - Single CF API call per reconciliation (was 3 in V3)
  - Jitter in HTTP retry: prevents thundering herd on 429 storms
  - CF quota awareness: warning at 800/1000 rules
  - Boot degraded mode: CF unreachable at startup → degraded (no rule wipe), auto-recover
  - Protected IPs via `ip -j addr` (reliable) with fallback to socket
  - _fetch_cf_rules() / _parse_cf_rules_by_tag() helpers to cache CF API reads

Architecture note — source of truth:
  Cloudflare API = canonical state.
  Local state files = acceleration cache + replay aid.
  reconcile_state() is the final arbiter, not the WAL.
  The WAL is an append-only audit trail, not a distributed transaction log.

All V3 features preserved:
  - Anti-self-ban (protected ranges)
  - Circuit breakers (CF, CrowdSec, AbuseIPDB)
  - DRY_RUN / shadow mode
  - Health + Prometheus metrics HTTP endpoint
  - SIGHUP hot reload
  - sd_notify watchdog
  - Adaptive mitigation (CF_MIN_CONFIDENCE)
  - Rule collapsing
  - Recidivist cursor (no double-counting across restarts)
  - Graceful shutdown, atomic JSON writes, HTTP retry, RotatingFileHandler
  - Recidivist escalation, ModSec CF ban, auto /24 CIDR block
  - Cloudflare WAF polling, OpenResty bouncer AbuseIPDB check
"""

import hashlib
import http.server
import io
import ipaddress
import json
import logging
import logging.handlers
import os
import random
import re
import shutil
import signal
import socket
import subprocess
import zlib
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

from crowdsec_cf_sync.models import (
    LocalBan, RecidivistEntry, ModsecEvent, ModsecStateEntry,
    CidrStateEntry, BouncerDenial, BouncerCheckEntry, WalEntry, LuaBanEntry,
)
from crowdsec_cf_sync.state_store import (
    STATE_VERSION, StateStore,
    _load_json_state, _atomic_write_json,
)
import crowdsec_cf_sync.wal as _wal_mod
from crowdsec_cf_sync.wal import (
    WAL_FILE,
    _init_wal_seq, _wal_log, _wal_trim,
    cmd_wal_inspect, cmd_wal_replay, cmd_wal_compact,
)
from crowdsec_cf_sync.config import (
    CF_API_TOKEN, CF_ZONE_ID, CS_API_KEY, ABUSEIPDB_KEY,
    BETTERSTACK_TOKEN, BETTERSTACK_INGEST,
    DRY_RUN, HEALTH_PORT, RECONCILE_SECS, CF_MIN_CONFIDENCE,
    CF_NOTIFIER_ACTIVE, SYNC_ABUSEIPDB, CB_THRESHOLD, CB_RESET_SECS,
    LUA_ENABLED, LUA_SYNC_DIR, LUA_SYNC_FILE, LUA_EVENTS_FILE,
    LUA_STATUS_URL, LUA_STALE_SECS, LUA_HEAL_COOLDOWN_SECS,
    CF_QUOTA_WARN_PCT,
    ABUSEIPDB_URL, ABUSEIPDB_CHECK_URL, INTERVAL,
    NOTE_TAG, NOTE_TAG_MODSEC, NOTE_TAG_CIDR, LOCAL_ORIGINS,
    DECISIONS_LOG, NGINX_ERROR_LOG, CF_LOG_FILE,
    ABUSE_STATE, RECIDIV_STATE, MODSEC_STATE, CIDR_STATE,
    CF_WAF_STATE, BOUNCER_CHECK_STATE,
    LOOKBACK_HOURS, RECIDIV_WINDOW, CIDR_WINDOW,
    MODSEC_SCORE_MIN, MODSEC_BAN_SECS, CIDR_BAN_DURATION, CIDR_THRESHOLD,
    CF_WAF_POLL_SECS, CF_WAF_THRESHOLD, CF_WAF_WINDOW_SECS, BOUNCER_CHECK_TTL,
    RECIDIV_ESCALATION, RECIDIV_DEFAULT,
    SCENARIO_CATEGORIES, _SCENARIO_CONFIDENCE, _CONFIDENCE_RANK,
    _PROTECTED_CIDRS_STATIC,
)

# ── Module-level state ────────────────────────────────────────────────────────

class Supervisor:
    """Container for runtime-mutable daemon state (replaces module-level globals).

    Attributes are added incrementally per phase. Module-level aliases below
    keep existing call-sites unchanged during the transition.
    """
    def __init__(self) -> None:
        self._shutdown        = threading.Event()
        self._reload          = threading.Event()
        self._boot_healthy    = False  # True after first successful CF API probe
        self._degraded_reason = ""    # non-empty when in degraded mode
        # Lua auto-heal state
        self._lua_sync_version: int = 0
        self._lua_last_known_version: int = 0
        self._lua_last_version_change_ts: float = 0.0
        self._lua_last_heal_ts: float = 0.0
        # Populated at startup, rebuilt on SIGHUP
        self._protected_networks: List[ipaddress._BaseNetwork] = []
        # Health endpoint state — shared with HTTP handler thread
        self._health_state: dict = {}
        self._health_lock = threading.Lock()


_sup = Supervisor()

# Module-level aliases — existing call-sites need no changes during the transition.
# threading.Event, Lock, list, dict aliases share the same object (mutations
# visible through both names). bool/str/int/float aliases are initial copies;
# at each global rebind site _sup.* is kept in sync explicitly (Phase 9.4).
_shutdown                 = _sup._shutdown
_reload                   = _sup._reload
_boot_healthy             = _sup._boot_healthy
_degraded_reason          = _sup._degraded_reason
_lua_sync_version         = _sup._lua_sync_version
_lua_last_known_version   = _sup._lua_last_known_version
_lua_last_version_change_ts = _sup._lua_last_version_change_ts
_lua_last_heal_ts         = _sup._lua_last_heal_ts
_protected_networks       = _sup._protected_networks
_health_state             = _sup._health_state
_health_lock              = _sup._health_lock


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


def slog(component: str, event: str, level: int = logging.INFO, **kwargs) -> None:
    """Emit a structured log line: component=X event=Y key=val ...

    Format mirrors what the Lua layer emits so log aggregators see consistent
    key=value pairs from both sides of the Python↔Lua boundary.
    """
    parts = [f"component={component}", f"event={event}"]
    parts.extend(f"{k}={v}" for k, v in kwargs.items())
    log.log(level, " ".join(parts))


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
            "cf_quota_warnings":      0,
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
            "lua_syncs":              0,
            "lua_sync_errors":        0,
            "lua_escalations":        0,
        }
        self._gauges: Dict[str, str] = {
            "last_sync_ts": "",
            "cf_rule_count": "0",
            "mode":         "dry_run" if DRY_RUN else "normal",
            "uptime_start": datetime.now(timezone.utc).isoformat(),
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


_sup._cb_cf  = CircuitBreaker("cloudflare")
_sup._cb_cs  = CircuitBreaker("crowdsec")
_sup._cb_abu = CircuitBreaker("abuseipdb")

# Phase-9.2 aliases — CircuitBreaker objects are shared (mutations visible through
# both names); module-level aliases preserve all existing call-sites.
_cb_cf  = _sup._cb_cf
_cb_cs  = _sup._cb_cs
_cb_abu = _sup._cb_abu


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
        log.warning("=== MODE DRY RUN ACTIVÉ — aucune modification CF/AbuseIPDB ===")


# ── JSON state helpers ────────────────────────────────────────────────────────
def _parse_dt(dt_str: str) -> datetime:
    try:
        return datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
    except Exception:
        return datetime.fromtimestamp(0, tz=timezone.utc)


# Per-domain singletons. Getters resolve module-level constants dynamically
# so tests can redirect paths via setattr without re-wiring the stores.
_RECIDIV_STORE  = StateStore(lambda: RECIDIV_STATE)
_REPORTED_STORE = StateStore(lambda: ABUSE_STATE)
_MODSEC_STORE   = StateStore(lambda: MODSEC_STATE)
_CIDR_STORE     = StateStore(lambda: CIDR_STATE)
_CF_WAF_STORE   = StateStore(lambda: CF_WAF_STATE, default={"last_event_dt": None})
_BOUNCER_STORE  = StateStore(lambda: BOUNCER_CHECK_STATE)


# ── Protected ranges (anti-self-ban) ─────────────────────────────────────────
def _build_protected_networks() -> List[ipaddress._BaseNetwork]:
    nets: List[ipaddress._BaseNetwork] = []
    for cidr in _PROTECTED_CIDRS_STATIC:
        try:
            nets.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            log.warning("Protected CIDR invalide ignoré: %s", cidr)

    # Auto-detect own IPs via `ip -j addr` (reliable across all interface types)
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
    except Exception as exc:
        log.warning("ip -j addr failed, fallback socket.getaddrinfo: %s", exc)
        try:
            for info in socket.getaddrinfo(socket.gethostname(), None):
                raw_ip = info[4][0]
                try:
                    nets.append(ipaddress.ip_network(raw_ip, strict=False))
                except ValueError:
                    pass
        except Exception:
            pass

    return nets


def is_protected(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return any(ip_obj in net for net in _protected_networks)
    except ValueError:
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
    conf = _scenario_confidence(scenario)
    return _CONFIDENCE_RANK.get(conf, 1) >= _CONFIDENCE_RANK.get(CF_MIN_CONFIDENCE, 0)


# ── HTTP helper with retry + jitter ──────────────────────────────────────────
_RETRYABLE_HTTP = frozenset({429, 500, 502, 503, 504})


def _http_call(
    req: urllib.request.Request,
    timeout: int = 15,
    max_retries: int = 3,
    backoff: float = 1.0,
) -> bytes:
    for attempt in range(max_retries):
        if attempt > 0:
            base_wait = min(backoff * (2 ** (attempt - 1)), 30.0)
            # Jitter prevents thundering herd when multiple retries are synchronized
            wait = base_wait + random.uniform(0, base_wait * 0.3)
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
        except (urllib.error.URLError, TimeoutError, OSError):
            if attempt < max_retries - 1:
                continue
            raise
    raise RuntimeError("Exhaustion inattendue de la boucle retry")


# ── sd_notify watchdog ────────────────────────────────────────────────────────
def _sd_notify(state: str) -> None:
    sock_path = os.environ.get("NOTIFY_SOCKET", "")
    if not sock_path:
        return
    try:
        addr = "\0" + sock_path[1:] if sock_path.startswith("@") else sock_path
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
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
    cb_open = _cb_cf.is_open or _cb_cs.is_open
    if DRY_RUN:
        mode = "dry_run"
    elif not _boot_healthy or _degraded_reason:
        mode = "degraded"
    elif cb_open:
        mode = "degraded"
    else:
        mode = "healthy"

    result: dict = {
        "status":            mode,
        "mode":              mode,
        "cloudflare_cb":     "open" if _cb_cf.is_open  else "closed",
        "crowdsec_cb":       "open" if _cb_cs.is_open  else "closed",
        "abuseipdb_cb":      "open" if _cb_abu.is_open else "closed",
        "last_sync":         m.get("last_sync_ts", ""),
        "uptime_start":      m.get("uptime_start", ""),
        "cycle_count":       m.get("cycle_count", 0),
        "cf_rules_added":    m.get("cf_rules_added", 0),
        "cf_rules_removed":  m.get("cf_rules_removed", 0),
        "cf_api_errors":     m.get("cf_api_errors", 0),
        "cf_quota_warnings": m.get("cf_quota_warnings", 0),
        "drift_detected":    m.get("drift_detected", 0),
        "allowlist_size":    cs_allowlist_size,
        "recidivists":       recidivists_size,
        "cidr_blocks":       cidr_size,
        "dry_run":           DRY_RUN,
        "cf_min_confidence": CF_MIN_CONFIDENCE,
        "state_version":     STATE_VERSION,
    }
    if _degraded_reason:
        result["degraded_reason"] = _degraded_reason
    return result


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
        "# HELP crowdsec_cf_sync_cf_quota_warnings_total Times CF quota ≥800/1000",
        "# TYPE crowdsec_cf_sync_cf_quota_warnings_total counter",
        f"crowdsec_cf_sync_cf_quota_warnings_total {s.get('cf_quota_warnings', 0)}",
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
        "# HELP crowdsec_cf_sync_wal_entries_total WAL entries written",
        "# TYPE crowdsec_cf_sync_wal_entries_total counter",
        f"crowdsec_cf_sync_wal_entries_total {s.get('wal_entries', 0)}",
        "# HELP crowdsec_cf_sync_cf_rule_count Current Cloudflare access rules managed by CrowdSec",
        "# TYPE crowdsec_cf_sync_cf_rule_count gauge",
        f"crowdsec_cf_sync_cf_rule_count {s.get('cf_rule_count', 0)}",
        "# HELP crowdsec_cf_sync_dry_run 1 if dry-run mode is active",
        "# TYPE crowdsec_cf_sync_dry_run gauge",
        f"crowdsec_cf_sync_dry_run {1 if DRY_RUN else 0}",
        "",
    ]
    return "\n".join(lines)


def _start_health_server() -> Optional[http.server.HTTPServer]:
    if not HEALTH_PORT:
        return None

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/health":
                with _health_lock:
                    data = dict(_health_state)
                code = 200 if data.get("status") in ("healthy", "dry_run") else 503
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
            pass

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
        log.warning("CF HTTP %d %s: %s", exc.code, method, body_text[:300])
        metrics.inc("cf_api_errors")
        _cb_cf.fail()
        raise
    except Exception as exc:
        log.warning("CF request %s %s: %s", method, path, exc)
        metrics.inc("cf_api_errors")
        _cb_cf.fail()
        raise


def _fetch_cf_rules() -> List[dict]:
    """Fetch all CF access rules for this zone. Raises if circuit breaker is open."""
    if _cb_cf.is_open:
        raise RuntimeError("Circuit breaker CF ouvert — fetch impossible")
    result = cf_request(
        "GET", f"/zones/{CF_ZONE_ID}/firewall/access_rules/rules?per_page=1000"
    )
    raw   = result.get("result", [])
    count = len(raw)
    cf_limit = 1000
    pct = (count / cf_limit) * 100
    for threshold in CF_QUOTA_WARN_PCT:
        if pct >= threshold:
            slog("cf_quota", "warning",
                 level=logging.WARNING,
                 rules=count,
                 limit=cf_limit,
                 pct=f"{pct:.0f}")
            metrics.inc("cf_quota_warnings")
            break
    return raw


def _parse_cf_rules_by_tag(rules: List[dict], tag: str) -> Dict[str, str]:
    """Extract {value: rule_id} from a cached CF rule list, filtered by exact notes tag."""
    result: Dict[str, str] = {}
    for rule in rules:
        if rule.get("notes") == tag:
            val = rule.get("configuration", {}).get("value")
            if val:
                result[val] = rule["id"]
    return result


def get_cf_blocked_ips(rules: Optional[List[dict]] = None) -> Dict[str, str]:
    """Return {ip: rule_id} for crowdsec-local-ban rules. Fetches CF if rules not provided."""
    if rules is None:
        rules = _fetch_cf_rules()
    raw = _parse_cf_rules_by_tag(rules, NOTE_TAG)
    normalized: Dict[str, str] = {}
    for val, rid in raw.items():
        try:
            normalized[str(ipaddress.ip_address(val))] = rid
        except ValueError:
            normalized[val] = rid
    return normalized


def get_cf_rules_by_tag(tag: str, rules: Optional[List[dict]] = None) -> Dict[str, str]:
    """Return {value: rule_id} for rules with the given tag. Fetches CF if rules not provided."""
    if rules is None:
        rules = _fetch_cf_rules()
    return _parse_cf_rules_by_tag(rules, tag)


def add_cf_rule(ip: str, tag: str = NOTE_TAG, target: str = "ip") -> bool:
    if not _is_valid_ip_or_cidr(ip, target):
        return False
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
    v4: List[ipaddress.IPv4Address] = []
    v6: List[ipaddress.IPv6Address] = []
    raw_pass: List[str] = []
    for ip in ips:
        try:
            obj = ipaddress.ip_address(ip)
            (v4 if obj.version == 4 else v6).append(obj)
        except ValueError:
            raw_pass.append(ip)
    collapsed: List[str] = list(raw_pass)
    for net in ipaddress.collapse_addresses(v4):   # type: ignore[arg-type]
        collapsed.append(str(net) if net.prefixlen < 32 else str(net.network_address))
    for net in ipaddress.collapse_addresses(v6):   # type: ignore[arg-type]
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
    Fetch ALL active decisions without --origin (workaround for CrowdSec #4470:
    cscli --origin X causes 25s+ SQLite timeout in v1.7.8).
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
        log.warning("cscli decisions list: timeout 15s — skip sync")
        _cb_cs.fail()
        return None
    except Exception as exc:
        log.warning("cscli decisions list: erreur %s", exc)
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
def get_recent_local_bans(hours: int = LOOKBACK_HOURS) -> List[LocalBan]:
    if not DECISIONS_LOG.exists():
        return []
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    bans: List[LocalBan] = []
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
                    continue
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
    return _RECIDIV_STORE.load()


def save_recidivists(recidivists: dict) -> None:
    _RECIDIV_STORE.save(recidivists)


def load_reported() -> dict:
    return _REPORTED_STORE.load()


def save_reported(reported: dict) -> None:
    _REPORTED_STORE.save(reported)


def purge_old_recidivists(recidivists: dict) -> dict:
    cutoff = datetime.now(timezone.utc) - timedelta(days=RECIDIV_WINDOW)
    purged = {
        ip: info for ip, info in recidivists.items()
        if not ip.startswith("_") and _parse_dt(info.get("last_seen", "")) >= cutoff
    }
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

    # Cursor prevents re-processing the same ban events across cycles/restarts.
    # Initialized to now on first V4 run so we don't retroactively re-count
    # bans that a prior daemon instance already processed.
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


def get_recent_modsec_events(hours: int = LOOKBACK_HOURS) -> List[ModsecEvent]:
    if not NGINX_ERROR_LOG.exists():
        return []
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    events: List[ModsecEvent] = []
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
    return _MODSEC_STORE.load()


def save_modsec_state(state: dict) -> None:
    _MODSEC_STORE.save(state)


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
def get_recent_bouncer_denials(hours: int = 1) -> List[BouncerDenial]:
    if not NGINX_ERROR_LOG.exists():
        return []
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    events: List[BouncerDenial] = []
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
        log.warning("Erreur lecture bouncer denials: %s", exc)
    return events


def load_bouncer_check_state() -> dict:
    return _BOUNCER_STORE.load()


def save_bouncer_check_state(state: dict) -> None:
    _BOUNCER_STORE.save(state)


def sync_bouncer_abuseipdb(
    bouncer_check_state: dict, cs_allowlist: Set[str]
) -> dict:
    denials = get_recent_bouncer_denials(hours=1)
    if not denials:
        return bouncer_check_state

    now    = datetime.now(timezone.utc)
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
    return _CIDR_STORE.load()


def save_cidr_state(state: dict) -> None:
    _CIDR_STORE.save(state)


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

    expiry  = timedelta(hours=24)
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
    if not SYNC_ABUSEIPDB:
        return reported
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
    """Sync active CrowdSec bans → Cloudflare. Single CF API call via _fetch_cf_rules()."""
    if _cb_cf.is_open:
        log.warning("Circuit breaker CF ouvert — sync_cloudflare ignoré (degraded mode)")
        metrics.set_gauge("mode", "degraded")
        return

    active_bans = get_active_bans()
    if active_bans is None:
        log.warning("CF Sync skip — get_active_bans() échoué (cscli timeout/erreur)")
        return

    # Adaptive mitigation: filter by scenario confidence
    if CF_MIN_CONFIDENCE != "low":
        recent       = get_recent_local_bans()
        scenario_map = {ban["ip"]: ban["scenario"] for ban in recent}
        active_bans  = {
            ip for ip in active_bans
            if _should_sync_to_cf(scenario_map.get(ip, "default"))
        }

    # Normalize + allowlist/protected filter
    clean_bans: Set[str] = set()
    for ip in active_bans:
        try:
            norm = str(ipaddress.ip_address(ip))
        except ValueError:
            norm = ip
        if not is_allowlisted(norm, cs_allowlist) and not is_protected(norm):
            clean_bans.add(norm)

    # Single CF API call — reuse for diff
    try:
        all_rules = _fetch_cf_rules()
    except Exception as exc:
        log.warning("CF Sync: impossible de lire règles CF — %s", exc)
        return
    cf_blocked = get_cf_blocked_ips(rules=all_rules)
    metrics.set_gauge("cf_rule_count", str(len(cf_blocked)))

    log.info("CF Sync — CrowdSec: %d bans | Cloudflare: %d règles",
             len(clean_bans), len(cf_blocked))

    to_add    = clean_bans - set(cf_blocked)
    to_delete = {ip: rid for ip, rid in cf_blocked.items() if ip not in clean_bans}

    to_add_collapsed = set(collapse_ips(to_add))

    added = deleted = 0
    if CF_NOTIFIER_ACTIVE:
        log.info("CF Sync: notifier actif -- push deleguee (%d IPs ignorees)", len(to_add_collapsed))
    else:
        for ip in to_add_collapsed:
            if _shutdown.is_set():
                break
            if add_cf_rule(ip):
                added += 1
                log.info("CF: Ajoute %s", ip)
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


# ── Reconciliation (CIDR-aware drift detection) ───────────────────────────────
def reconcile_state(cs_allowlist: Set[str]) -> int:
    """
    Full reconciliation: compare CF actual state vs CrowdSec active bans.

    Key improvements over V3:
    - Single CF API call (was 3 separate calls in V3)
    - CIDR-aware: drift_add excludes IPs already covered by a /24 CIDR block in CF,
      preventing spurious 'missing' detections for IPs blocked at subnet level
    - drift_remove only targets crowdsec-local-ban tag; ModSec + CIDR tags managed
      by their own sync functions (no cross-tag interference)

    Source of truth: Cloudflare API.
    Local state = cache. Reconciliation = final arbiter.
    """
    _wal_log("reconcile", "full", dry_run=DRY_RUN)
    metrics.inc("reconcile_runs")

    if _cb_cf.is_open:
        log.warning("Reconciliation: circuit breaker CF ouvert — skip")
        return 0

    # Single CF API call — share across all tag lookups
    try:
        all_cf_rules = _fetch_cf_rules()
    except Exception as exc:
        log.warning("Reconciliation: impossible de lire règles CF: %s — skip", exc)
        return 0

    cf_local  = get_cf_blocked_ips(rules=all_cf_rules)             # crowdsec-local-ban
    cf_cidr   = get_cf_rules_by_tag(NOTE_TAG_CIDR,   rules=all_cf_rules)
    cf_modsec = get_cf_rules_by_tag(NOTE_TAG_MODSEC,  rules=all_cf_rules)

    # Build CIDR network objects for IP coverage check
    cidr_nets: List[ipaddress._BaseNetwork] = []
    for cidr_str in cf_cidr:
        try:
            cidr_nets.append(ipaddress.ip_network(cidr_str, strict=False))
        except ValueError:
            pass

    # All individual IPs under any crowdsec tag
    all_cf_ips: Set[str] = set(cf_local) | set(cf_modsec)

    def _ip_in_cf(ip: str) -> bool:
        """True if ip has an individual CF rule OR falls inside a CF CIDR block."""
        if ip in all_cf_ips:
            return True
        try:
            ip_obj = ipaddress.ip_address(ip)
            return any(ip_obj in net for net in cidr_nets)
        except ValueError:
            return False

    active_bans = get_active_bans()
    if active_bans is None:
        log.warning("Reconciliation: get_active_bans() échoué — skip")
        return 0

    # drift_add: in CrowdSec but not covered by any CF crowdsec rule (including CIDR)
    drift_add: Set[str] = {
        ip for ip in active_bans
        if not _ip_in_cf(ip)
        and not is_allowlisted(ip, cs_allowlist)
        and not is_protected(ip)
    }

    # drift_remove: crowdsec-local-ban rules that are no longer active in CS
    # Intentionally scoped to our tag only — don't interfere with ModSec/CIDR management
    drift_remove: Dict[str, str] = {
        ip: rid for ip, rid in cf_local.items()
        if ip not in active_bans
    }

    drift_count = len(drift_add) + len(drift_remove)
    if drift_count == 0:
        log.debug("Reconciliation: pas de drift détecté")
        return 0

    log.warning(
        "DRIFT DÉTECTÉ: %d règle(s) à ajouter, %d à supprimer",
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
        if add_cf_rule(ip):
            log.info("Reconciliation: ajouté %s (manquant dans CF)", ip)
            corrected += 1
        if _shutdown.is_set():
            break

    for ip, rule_id in drift_remove.items():
        if delete_cf_rule(rule_id, ip):
            log.info("Reconciliation: supprimé %s (fantôme dans CF)", ip)
            corrected += 1
        if _shutdown.is_set():
            break

    return corrected


# ── Cloudflare WAF polling ────────────────────────────────────────────────────
def load_cf_waf_state() -> dict:
    return _CF_WAF_STORE.load()


def save_cf_waf_state(state: dict) -> None:
    _CF_WAF_STORE.save(state)


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

    now      = datetime.now(timezone.utc)
    since    = waf_state.get("last_event_dt") or (
        now - timedelta(seconds=CF_WAF_WINDOW_SECS)
    ).isoformat()

    try:
        events = fetch_cf_waf_events(since)
    except Exception as exc:
        log.warning("CF WAF poll: erreur %s", exc)
        return waf_state, recidivists, reported

    if not events:
        return waf_state, recidivists, reported

    waf_state["last_event_dt"] = events[-1]["datetime"]
    save_cf_waf_state(waf_state)

    window_start = now - timedelta(seconds=CF_WAF_WINDOW_SECS)
    ip_hits: Dict[str, dict] = {}
    for ev in events:
        ip = ev.get("clientIP")
        if not ip:
            continue
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        if is_allowlisted(ip, cs_allowlist) or is_protected(ip):
            continue
        if ip not in ip_hits:
            ip_hits[ip] = {
                "count":    0,
                "actions":  set(),
                "uris":     [],
                "first_dt": ev["datetime"],
            }
        ip_hits[ip]["count"] += 1
        ip_hits[ip]["actions"].add(ev.get("action", ""))
        uri = ev.get("clientRequestPath", "")
        if uri and len(ip_hits[ip]["uris"]) < 5:
            ip_hits[ip]["uris"].append(uri)

    banned_count = 0
    for ip, info in ip_hits.items():
        if info["count"] < CF_WAF_THRESHOLD:
            continue
        try:
            ev_dt = _parse_dt(info["first_dt"])
            if ev_dt < window_start:
                continue
        except Exception:
            continue

        try:
            info["actions"] = list(info["actions"])
            uris_str = ", ".join(info["uris"]) if info["uris"] else "N/A"
            duration = "168h" if ip in recidivists else "24h"

            if ip not in recidivists:
                recidivists[ip] = {"count": 1, "last_seen": info["first_dt"]}
            else:
                recidivists[ip] = {
                    "count":     recidivists[ip]["count"] + 1,
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
                "message":  f"CF WAF ban: {ip} | {info['count']} hits | {info['actions']}",
                "source":   "cloudflare_waf",
                "platform": "CrowdSec",
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


# ── Lua state sync (V3.2) ──────────────────────────────────────────────────────

def push_lua_state(
    active_bans: Set[str],
    cidr_state: dict,
    modsec_state: dict,
    recidivists: dict,
) -> None:
    """Push current ban state to /run/crowdsec-lua/bans.json for OpenResty pickup.

    This is the Python→Lua IPC path. OpenResty polls the file every 5s via
    ngx.timer.every() and loads verdicts into shared dict. Per-request lookup
    is then pure shared dict read — zero network or file I/O.

    Lua performs an entry_count integrity check; if Python crashes mid-write,
    the partial file is rejected and Lua keeps the previous good state.
    """
    global _lua_sync_version
    if not LUA_ENABLED:
        return
    try:
        LUA_SYNC_DIR.mkdir(parents=True, exist_ok=True)

        _sup._lua_sync_version += 1
        _lua_sync_version = _sup._lua_sync_version

        bans: Dict[str, LuaBanEntry] = {}

        # Active CrowdSec bans: score reflects recidivism
        for ip in active_bans:
            rec = recidivists.get(ip, {})
            count = rec.get("count", 0)
            # Base score 70; +10 per recidivist occurrence above 1, capped at 100
            score = min(100, 70 + max(0, count - 1) * 10)
            bans[ip] = {"score": score, "level": 5, "ttl": 3600, "reason": "crowdsec-ban"}

        # ModSec bans: 2h TTL, medium-high score
        for ip in modsec_state:
            if ip not in bans:
                bans[ip] = {"score": 80, "level": 5, "ttl": MODSEC_BAN_SECS, "reason": "modsec-ban"}

        # CIDR bans
        cidrs: Dict[str, LuaBanEntry] = {}
        for cidr in cidr_state:
            cidrs[cidr] = {"score": 100, "level": 5, "ttl": 86400, "reason": "crowdsec-cidr"}

        # Build payload without crc32 first, then compute and inject
        now_utc = datetime.now(timezone.utc)
        m = metrics.snapshot()
        payload: dict = {
            "version":           _lua_sync_version,
            "updated_at":        now_utc.isoformat(),
            "updated_at_epoch":  int(now_utc.timestamp()),
            "entry_count":       len(bans) + len(cidrs),
            "writer_pid":        os.getpid(),
            "writer_hostname":   socket.gethostname(),
            "bans":              bans,
            "cidrs":             cidrs,
            # Python daemon operational counters — Lua reads these and stores in
            # crowdsec_metrics dict, making them visible at /crowdsec-status and
            # /crowdsec-metrics without requiring a separate call to port 8765.
            "meta": {
                "cycle_count":     m.get("cycle_count", 0),
                "cf_api_errors":   m.get("cf_api_errors", 0),
                "wal_entries":     m.get("wal_entries", 0),
                "lua_sync_errors": m.get("lua_sync_errors", 0),
                "degraded":        not _boot_healthy or bool(_degraded_reason),
            },
        }
        # Compute crc32 of the payload-so-far for integrity verification
        pre_content = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()
        payload["payload_crc32"] = zlib.crc32(pre_content) & 0xFFFFFFFF

        content = json.dumps(payload, indent=2, ensure_ascii=False).encode()
        tmp_fd, tmp_path = tempfile.mkstemp(dir=LUA_SYNC_DIR, suffix=".tmp")
        os.fchmod(tmp_fd, 0o644)  # www-data (OpenResty) must be able to read this
        try:
            with os.fdopen(tmp_fd, "wb") as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, LUA_SYNC_FILE)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

        metrics.inc("lua_syncs")
        slog("lua_sync", "push",
             version=_lua_sync_version,
             bans=len(bans),
             cidrs=len(cidrs),
             bytes=len(content),
             status="ok")
    except Exception as exc:
        metrics.inc("lua_sync_errors")
        log.warning("Lua push échoué (non-fatal): %s", exc)


def read_lua_events() -> List[dict]:
    """Consume escalation events written by OpenResty Lua layer.

    Uses atomic rename (events.jsonl → events.jsonl.processing) to avoid
    the read-and-truncate race where Lua appends while Python truncates.
    Lua automatically creates a new events.jsonl after the rename.
    """
    if not LUA_ENABLED or not LUA_EVENTS_FILE.exists():
        return []
    proc_file = LUA_EVENTS_FILE.with_suffix(".processing")
    try:
        LUA_EVENTS_FILE.rename(proc_file)
    except (FileNotFoundError, OSError):
        return []
    events_out: List[dict] = []
    try:
        with proc_file.open(encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    events_out.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    finally:
        try:
            proc_file.unlink()
        except OSError:
            pass
    if events_out:
        log.info("Lua events: %d événement(s) reçu(s)", len(events_out))
        metrics.inc("lua_escalations", len(events_out))
    return events_out


def process_lua_events(
    events_in: List[dict],
    reported: dict,
    cs_allowlist: Set[str],
) -> dict:
    """Process escalation events from OpenResty Lua layer.

    Current handling:
      honeypot_hit        → report to AbuseIPDB if not already reported
      heuristic_escalate  → log + optionally report to AbuseIPDB

    Future: push to CrowdSec LAPI via `cscli decisions add`.
    Python daemon remains the single orchestration authority.
    """
    if not events_in:
        return reported

    for ev in events_in:
        ev_type = ev.get("type", "")
        ip      = ev.get("ip", "")
        score   = ev.get("score", 0)
        detail  = ev.get("detail", "")

        if not ip or is_allowlisted(ip, cs_allowlist) or is_protected(ip):
            continue

        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue

        if ev_type == "honeypot_hit":
            log.warning("Honeypot hit from %s (path=%s) — score=%d", ip, detail, score)
            if ip not in reported:
                cats = "21,19"
                comment = f"Honeypot path access: {detail}"
                report_to_abuseipdb(ip, cats, comment, reported)

        elif ev_type == "heuristic_escalate":
            log.info("Lua heuristic escalation: %s score=%d detail=%s", ip, score, detail)
            # Only report once per IP per session
            if ip not in reported and score >= 90:
                cats = "21,19"
                comment = f"Lua heuristic score {score}: {detail}"
                report_to_abuseipdb(ip, cats, comment, reported)

    return reported


# ── Auto-heal ─────────────────────────────────────────────────────────────────

def _query_lua_status() -> Optional[dict]:
    """Query the local /crowdsec-status endpoint. Returns parsed JSON or None."""
    try:
        req = urllib.request.Request(LUA_STATUS_URL, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return None


def check_lua_autoheal() -> None:
    """Monitor Lua sync_version. If frozen, reload OpenResty (rate-limited)."""
    global _lua_last_known_version, _lua_last_version_change_ts, _lua_last_heal_ts

    status = _query_lua_status()
    if status is None:
        slog("autoheal", "status_unreachable", level=logging.WARNING,
             url=LUA_STATUS_URL)
        return

    version = status.get("sync", {}).get("version", 0)
    now = time.monotonic()

    if version != _lua_last_known_version:
        _sup._lua_last_known_version = version
        _lua_last_known_version = version
        _sup._lua_last_version_change_ts = now
        _lua_last_version_change_ts = now
        return  # version is moving, all good

    # Version has not changed — check if it's been frozen too long
    if _lua_last_version_change_ts == 0.0:
        _sup._lua_last_version_change_ts = now
        _lua_last_version_change_ts = now
        return

    frozen_secs = now - _lua_last_version_change_ts
    if frozen_secs < LUA_STALE_SECS:
        return  # not yet stale

    # Version is frozen — check cooldown before healing
    if now - _lua_last_heal_ts < LUA_HEAL_COOLDOWN_SECS:
        slog("autoheal", "cooldown_active", level=logging.WARNING,
             frozen_secs=round(frozen_secs),
             cooldown_remaining=round(LUA_HEAL_COOLDOWN_SECS - (now - _lua_last_heal_ts)))
        return

    # Trigger reload
    slog("autoheal", "trigger_reload", level=logging.WARNING,
         reason="sync_version_frozen",
         frozen_secs=round(frozen_secs),
         sync_version=version)
    try:
        result = subprocess.run(
            ["systemctl", "reload", "openresty"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            _sup._lua_last_heal_ts = now
            _lua_last_heal_ts = now
            _sup._lua_last_version_change_ts = now  # reset frozen clock
            _lua_last_version_change_ts = now
            slog("autoheal", "reload_ok", status="success")
            metrics.inc("lua_autoheal_reloads")
        else:
            slog("autoheal", "reload_failed", level=logging.ERROR,
                 stderr=result.stderr.strip())
    except Exception as exc:
        slog("autoheal", "reload_error", level=logging.ERROR, error=str(exc))


# ── Doctor ────────────────────────────────────────────────────────────────────

def cmd_doctor() -> int:
    """System health audit. Returns exit code: 0=healthy, 1=degraded, 2=broken."""
    print("=== crowdsec-cf-sync doctor ===\n")
    ok_count = 0; warn_count = 0; fail_count = 0
    hostname = socket.gethostname()

    def chk_ok(label: str, detail: str = "") -> None:
        nonlocal ok_count
        ok_count += 1
        print(f"  \033[32m[OK]\033[0m    {label}" + (f" — {detail}" if detail else ""))

    def chk_warn(label: str, detail: str = "") -> None:
        nonlocal warn_count
        warn_count += 1
        print(f"  \033[33m[WARN]\033[0m  {label}" + (f" — {detail}" if detail else ""))

    def chk_fail(label: str, detail: str = "") -> None:
        nonlocal fail_count
        fail_count += 1
        print(f"  \033[31m[FAIL]\033[0m  {label}" + (f" — {detail}" if detail else ""))

    print(f"Host: {hostname}\n")

    # ── Python daemon ──────────────────────────────────────────────────────────
    print("── Python daemon ────────────────────────────────────────────────────")
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "crowdsec-cf-sync"],
            capture_output=True, text=True, timeout=5,
        )
        if result.stdout.strip() == "active":
            chk_ok("Daemon active", "crowdsec-cf-sync.service")
        else:
            chk_fail("Daemon not active", result.stdout.strip())
    except Exception as e:
        chk_fail("Cannot query systemd", str(e))

    # WAL
    if WAL_FILE.exists():
        wal_size = WAL_FILE.stat().st_size
        chk_ok("WAL file exists", f"{WAL_FILE} ({wal_size:,} bytes)")
    else:
        chk_warn("WAL file missing", str(WAL_FILE))

    # State files
    for state_file in (RECIDIV_STATE, MODSEC_STATE, CIDR_STATE):
        if state_file.exists():
            chk_ok(f"State file: {state_file.name}")
        else:
            chk_warn(f"State file missing: {state_file.name}", "will be created on first run")

    # ── Cloudflare ────────────────────────────────────────────────────────────
    print("\n── Cloudflare ───────────────────────────────────────────────────────")
    if not CF_API_TOKEN or not CF_ZONE_ID:
        chk_fail("CF credentials missing", "CF_API_TOKEN or CF_ZONE_ID not set")
    else:
        try:
            cf_rules = _fetch_cf_rules()
            n = len(cf_rules)
            chk_ok("CF API reachable", f"{n} active rules")
            # Quota check
            limit = 1000  # typical CF free limit
            pct = (n / limit) * 100
            if pct >= 95:
                chk_fail(f"CF quota critical: {n}/{limit} rules ({pct:.0f}%)")
            elif pct >= 85:
                chk_warn(f"CF quota high: {n}/{limit} rules ({pct:.0f}%)")
            elif pct >= 70:
                chk_warn(f"CF quota elevated: {n}/{limit} rules ({pct:.0f}%)")
            else:
                chk_ok(f"CF quota OK: {n}/{limit} rules ({pct:.0f}%)")
        except Exception as e:
            chk_fail("CF API unreachable", str(e))

    # ── CrowdSec LAPI ─────────────────────────────────────────────────────────
    print("\n── CrowdSec LAPI ────────────────────────────────────────────────────")
    if not CS_API_KEY:
        chk_warn("CS_API_KEY not set", "CrowdSec integration disabled")
    else:
        try:
            result = subprocess.run(
                ["cscli", "lapi", "status"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                chk_ok("CrowdSec LAPI reachable")
            else:
                chk_fail("CrowdSec LAPI error", (result.stderr or result.stdout).strip()[:80])
        except FileNotFoundError:
            chk_warn("cscli not found in PATH")
        except Exception as e:
            chk_fail("CrowdSec check failed", str(e))

    # ── Lua layer ─────────────────────────────────────────────────────────────
    print("\n── Lua layer ────────────────────────────────────────────────────────")
    if not LUA_ENABLED:
        chk_warn("Lua layer disabled", "LUA_ENABLED=0")
    else:
        lua_status = _query_lua_status()
        if lua_status is None:
            chk_fail("Lua status endpoint unreachable", LUA_STATUS_URL)
        else:
            chk_ok("Lua status endpoint reachable", LUA_STATUS_URL)

            sync_version = lua_status.get("sync", {}).get("version", 0)
            sync_ts      = lua_status.get("sync", {}).get("ts", 0)
            entries      = lua_status.get("sync", {}).get("entries", 0)
            lua_syncs    = lua_status.get("counters", {}).get("lua_syncs", 0)

            if sync_version and sync_version > 0:
                chk_ok(f"Lua sync active", f"version={sync_version} entries={entries}")
            else:
                chk_fail("Lua sync_version=0", "bans.json not yet loaded by Lua")

            if sync_ts:
                age = int(time.time()) - sync_ts
                if age < 120:
                    chk_ok(f"Lua sync recent", f"{age}s ago")
                elif age < 300:
                    chk_warn(f"Lua sync aging", f"{age}s ago (threshold 120s)")
                else:
                    chk_fail(f"Lua sync stale", f"{age}s ago — deadman mode active")

            # Dict memory
            dh = lua_status.get("dict_health", {})
            for dict_name, free_bytes in dh.items():
                free_mb = free_bytes / (1024 * 1024)
                if free_mb < 2:
                    chk_fail(f"Dict low: {dict_name}", f"{free_mb:.1f} MB free")
                elif free_mb < 10:
                    chk_warn(f"Dict tight: {dict_name}", f"{free_mb:.1f} MB free")
                else:
                    chk_ok(f"Dict healthy: {dict_name}", f"{free_mb:.1f} MB free")

    # ── Permissions ───────────────────────────────────────────────────────────
    print("\n── Permissions ──────────────────────────────────────────────────────")
    sync_dir = LUA_SYNC_DIR
    if sync_dir.exists():
        chk_ok(f"Sync dir exists", str(sync_dir))
        bans_json = sync_dir / "bans.json"
        if bans_json.exists():
            mode = oct(bans_json.stat().st_mode)[-3:]
            if mode == "644":
                chk_ok("bans.json mode 644")
            else:
                chk_fail(f"bans.json mode {mode}", "expected 644 (OpenResty needs read)")
        else:
            chk_warn("bans.json not yet created")

        events_jsonl = sync_dir / "events.jsonl"
        if events_jsonl.exists():
            mode = oct(events_jsonl.stat().st_mode)[-3:]
            chk_ok(f"events.jsonl mode {mode}")
        else:
            chk_warn("events.jsonl not yet created")
    else:
        chk_fail(f"Sync dir missing: {sync_dir}", "run install-v3.sh")

    # ── nginx/OpenResty config ────────────────────────────────────────────────
    print("\n── nginx/OpenResty ──────────────────────────────────────────────────")
    nginx_bin = "openresty" if shutil.which("openresty") else "nginx"
    try:
        result = subprocess.run(
            [nginx_bin, "-t"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            chk_ok("nginx config syntax OK")
        else:
            chk_fail("nginx config has errors", result.stderr.strip()[:120])
    except Exception as e:
        chk_fail("Cannot run nginx -t", str(e))

    # Check crowdsec_cf_sync_generated.conf is loaded
    try:
        result = subprocess.run(
            [nginx_bin, "-T"],
            capture_output=True, text=True, timeout=10,
        )
        dump = result.stdout
        if "crowdsec_cf_sync_generated.conf" in dump or "cscf_verdicts" in dump:
            chk_ok("crowdsec_cf_sync_generated.conf loaded")
        else:
            chk_warn("crowdsec_cf_sync_generated.conf not detected in active config",
                     "run install-v3.sh")
        if "cscf_verdicts" in dump:
            chk_ok("lua_shared_dict cscf_verdicts declared")
        else:
            chk_warn("lua_shared_dict cscf_verdicts not found in active config")
    except Exception:
        pass

    # ── Summary ───────────────────────────────────────────────────────────────
    total = ok_count + warn_count + fail_count
    print(f"\n── Summary ({total} checks) ───────────────────────────────────────────")
    if fail_count == 0 and warn_count == 0:
        print("\033[32m\033[1mSTATUS: HEALTHY\033[0m")
        return 0
    elif fail_count == 0:
        print(f"\033[33m\033[1mSTATUS: DEGRADED\033[0m  ({ok_count} ok, {warn_count} warnings, 0 failures)")
        return 1
    else:
        print(f"\033[31m\033[1mSTATUS: BROKEN\033[0m   ({ok_count} ok, {warn_count} warnings, {fail_count} failures)")
        return 2


def _run_reconciliation_if_due(
    cs_allowlist: List[str],
    last_reconcile: float,
    reconcile_count: int,
) -> tuple:
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
    return (last_reconcile, reconcile_count)


def _run_waf_poll_if_due(
    waf_poll_count: int,
    waf_state: dict,
    recidivists: dict,
    cs_allowlist: List[str],
    reported: dict,
) -> tuple:
    waf_poll_count += 1
    if (
        not _shutdown.is_set()
        and waf_poll_count % max(1, CF_WAF_POLL_SECS // INTERVAL) == 0
    ):
        waf_state, recidivists, reported = poll_cloudflare_waf(
            waf_state, recidivists, cs_allowlist, reported
        )
    return (waf_poll_count, waf_state, recidivists, reported)


def _sync_lua_state(cidr_state: dict, modsec_state: dict, recidivists: dict) -> None:
    if LUA_ENABLED and not _shutdown.is_set():
        _active = get_active_bans()
        if _active is not None:
            push_lua_state(_active, cidr_state, modsec_state, recidivists)
        # Auto-heal: check if Lua sync timer is alive
        check_lua_autoheal()


def _sync_crowdsec_sources(
    reported: dict,
    recidivists: dict,
    modsec_state: dict,
    cidr_state: dict,
    bouncer_check_state: dict,
    cs_allowlist: List[str],
) -> tuple:
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
    return (reported, recidivists, modsec_state, cidr_state, bouncer_check_state)


def _ingest_lua_events(reported: dict, cs_allowlist: List[str]) -> dict:
    # Atomic rename avoids read-truncate race with Lua append.
    if LUA_ENABLED and not _shutdown.is_set():
        lua_events = read_lua_events()
        if lua_events:
            reported = process_lua_events(lua_events, reported, cs_allowlist)
    return reported


def _try_recover_degraded(cycle_start: float) -> bool:
    """Returns True if the cycle should be skipped (CF still unreachable)."""
    global _boot_healthy, _degraded_reason
    if _boot_healthy:
        return False
    try:
        _fetch_cf_rules()
        _sup._boot_healthy = True
        _boot_healthy    = True
        _sup._degraded_reason = ""
        _degraded_reason = ""
        log.info("CF rétabli — sortie du mode dégradé")
        return False
    except Exception:
        log.warning("Mode dégradé: CF toujours inaccessible, sync CF ignoré ce cycle")
        _sd_notify(f"WATCHDOG=1\nSTATUS=Degraded: {_degraded_reason}\n")
        elapsed   = time.monotonic() - cycle_start
        remaining = max(0.0, INTERVAL - elapsed)
        _shutdown.wait(timeout=remaining)
        return True


def _startup_daemon() -> tuple:
    global _boot_healthy, _degraded_reason, _protected_networks

    _check_config()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT,  _handle_signal)
    signal.signal(signal.SIGHUP,  _handle_signal)

    _protected_networks = _build_protected_networks()
    _sup._protected_networks = _protected_networks
    log.info("Protected ranges: %d réseaux chargés", len(_protected_networks))

    log.info(
        "=== CrowdSec CF Sync V3.6.0 démarré (interval=%ds | dry_run=%s | "
        "confidence=%s | health_port=%s | state_version=%d | lua=%s) ===",
        INTERVAL, DRY_RUN, CF_MIN_CONFIDENCE,
        HEALTH_PORT if HEALTH_PORT else "disabled",
        STATE_VERSION,
        "enabled" if LUA_ENABLED else "disabled",
    )

    _start_health_server()

    # Initialize WAL sequence from existing WAL, trim on startup
    _wal_mod._wal_seq = _init_wal_seq()
    log.info("WAL: %d entrées existantes (prochain id: %d)", _wal_mod._wal_seq, _wal_mod._wal_seq + 1)
    _wal_trim()

    # Probe CF connectivity at boot.
    # On failure: enter degraded mode — do NOT wipe CF rules with stale local state.
    # Cloudflare is the source of truth; we must be able to read it before modifying it.
    try:
        _fetch_cf_rules()
        _sup._boot_healthy = True
        _boot_healthy = True
        log.info("Boot: CF accessible — démarrage normal")
    except Exception as exc:
        _degraded_reason = f"CF inaccessible au démarrage: {exc}"
        _sup._degraded_reason = _degraded_reason
        log.error("DEGRADED BOOT: %s", _degraded_reason)
        log.warning(
            "Daemon en mode dégradé — aucune modification CF "
            "tant que CF reste inaccessible"
        )

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
    log.info("Récidivistes connus: %d IPs",
             len([k for k in recidivists if not k.startswith("_")]))
    log.info("CIDR bannis: %d blocs", len(cidr_state))
    log.info("Bouncer checks en cache: %d IPs", len(bouncer_check_state))

    # Initial catchup (log-based operations — safe regardless of CF reachability)
    log.info("Rattrapage des %dh…", LOOKBACK_HOURS)
    reported     = sync_abuseipdb(reported)
    recidivists  = sync_recidivists(recidivists)
    modsec_state, reported = sync_modsec(modsec_state, cs_allowlist, reported)
    cidr_state   = sync_cidr_bans(cidr_state, cs_allowlist)

    # READY=1 sent unconditionally — STATUS communicates boot health to systemd
    status_msg = "Degraded" if not _boot_healthy else "Running"
    _sd_notify(f"READY=1\nSTATUS={status_msg}\n")

    return (cs_allowlist, reported, recidivists, modsec_state, cidr_state, waf_state, bouncer_check_state)


def _handle_reload_if_needed(cs_allowlist: List[str]) -> List[str]:
    global _protected_networks
    if not _reload.is_set():
        return cs_allowlist
    _reload.clear()
    log.info("Hot reload: rechargement allowlist + protected ranges")
    cs_allowlist = get_crowdsec_allowlist()
    _protected_networks = _build_protected_networks()
    _sup._protected_networks = _protected_networks
    log.info("Hot reload terminé — allowlist: %d entrées, protected: %d nets",
             len(cs_allowlist), len(_protected_networks))
    return cs_allowlist


# ── Main ──────────────────────────────────────────────────────────────────────
def main() -> None:
    (
        cs_allowlist, reported, recidivists,
        modsec_state, cidr_state, waf_state,
        bouncer_check_state,
    ) = _startup_daemon()

    loop_count      = 0
    waf_poll_count  = 0
    reconcile_count = 0
    last_reconcile  = time.monotonic()

    while not _shutdown.is_set():
        cycle_start = time.monotonic()

        # Hot reload on SIGHUP
        cs_allowlist = _handle_reload_if_needed(cs_allowlist)

        # Auto-recover from degraded boot once CF is reachable
        if _try_recover_degraded(cycle_start):
            continue

        try:
            # ── Lua event ingestion (start of cycle) ──────────────────────────
            reported = _ingest_lua_events(reported, cs_allowlist)

            (
                reported, recidivists, modsec_state, cidr_state, bouncer_check_state,
            ) = _sync_crowdsec_sources(
                reported, recidivists, modsec_state, cidr_state, bouncer_check_state,
                cs_allowlist,
            )

            # ── Lua state push (after all local state is up to date) ──────────
            _sync_lua_state(cidr_state, modsec_state, recidivists)

            # WAF poll (every CF_WAF_POLL_SECS)
            waf_poll_count, waf_state, recidivists, reported = _run_waf_poll_if_due(
                waf_poll_count, waf_state, recidivists, cs_allowlist, reported
            )

            # Periodic reconciliation
            last_reconcile, reconcile_count = _run_reconciliation_if_due(
                cs_allowlist, last_reconcile, reconcile_count
            )

            # Refresh allowlist every 10 cycles
            loop_count += 1
            if not _shutdown.is_set() and loop_count % 10 == 0:
                cs_allowlist = get_crowdsec_allowlist()

            metrics.inc("cycle_count")

        except Exception as exc:
            log.error("Erreur sync: %s", exc, exc_info=True)

        elapsed = time.monotonic() - cycle_start
        log.debug("Cycle %d terminé en %.1fs", loop_count, elapsed)

        # Update health endpoint state
        with _health_lock:
            _health_state.update(
                _build_health(
                    cs_allowlist_size=len(cs_allowlist),
                    recidivists_size=len([k for k in recidivists if not k.startswith("_")]),
                    cidr_size=len(cidr_state),
                )
            )

        _sd_notify(f"WATCHDOG=1\nSTATUS=Cycle {loop_count} OK\n")

        remaining = max(0.0, INTERVAL - elapsed)
        _shutdown.wait(timeout=remaining)

    _sd_notify("STOPPING=1\n")
    log.info(
        "=== Arrêt gracieux terminé (cycles: %d, réconciliations: %d) ===",
        loop_count, reconcile_count,
    )


def run():
    # ── Subcommand dispatch ────────────────────────────────────────────────────
    # Usage examples are built at runtime from sys.argv[0] so renames of the
    # executable don't silently drift away from the doc.
    _prog = Path(sys.argv[0]).name or "crowdsec-cf-sync"
    _USAGE = "\n".join((
        f"  {_prog}                            — run daemon (default)",
        f"  {_prog} doctor                     — system health audit",
        f"  {_prog} wal inspect                — inspect WAL",
        f"  {_prog} wal replay                 — dry-run WAL replay",
        f"  {_prog} wal replay --execute       — execute WAL replay",
        f"  {_prog} wal compact                — compact WAL to net state",
    ))
    args = sys.argv[1:]
    if args and args[0] in ("-h", "--help", "help"):
        print("Usage:")
        print(_USAGE)
        sys.exit(0)
    if args and args[0] == "doctor":
        sys.exit(cmd_doctor())
    elif args and args[0] == "wal":
        sub = args[1] if len(args) > 1 else ""
        if sub == "inspect":
            cmd_wal_inspect()
        elif sub == "replay":
            cmd_wal_replay(dry_run="--execute" not in args)
        elif sub == "compact":
            cmd_wal_compact()
        else:
            print(f"Usage: {_prog} wal <inspect|replay|compact>")
            sys.exit(1)
    else:
        main()


if __name__ == "__main__":
    run()
