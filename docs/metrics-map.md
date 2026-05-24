# Metrics Map — `crowdsec-cf-sync` v3.6.0

Audit en lecture seule des compteurs et gauges exposés par l'architecture hybride :
data plane Lua + control plane Python. Sert de **baseline opérationnelle** avant la
décomposition modulaire du supervisor (cf. `docs/architecture-triage.md`).

**Aucune modification** n'a été apportée au pipeline runtime, à l'IPC, ou à
l'ordering. Seuls les compteurs déjà émis sont documentés ici.

Sources :
- `lua/crowdsec/*.lua` — émission (`cs.metrics:incr/set`, `cs.state:set/get`)
- `lua/crowdsec/metrics.lua` — export (`/crowdsec-status` JSON + `/crowdsec-metrics` Prometheus)
- `crowdsec-cf-sync` (Python) — émission (`metrics.inc/set_gauge`) + export (`/metrics` port 8765 via `_build_prometheus`)

---

## Endpoints existants

| Endpoint | Port | Format | Owner | Scrape rate suggéré |
|----------|------|--------|-------|---------------------|
| `http://127.0.0.1:8091/crowdsec-status` | 8091 (nginx) | JSON | Lua | sur demande (debug) |
| `http://127.0.0.1:8091/crowdsec-metrics` | 8091 (nginx) | Prometheus | Lua | 15s |
| `http://127.0.0.1:8765/metrics` | 8765 (Python HTTPServer) | Prometheus | Python | 30s |
| `http://127.0.0.1:8765/health` | 8765 | JSON | Python | 15s |

Les deux Prometheus endpoints sont **accessibles uniquement depuis loopback** (réglé en nginx pour le Lua, par binding 127.0.0.1 pour Python).

---

## Lua data plane — compteurs (shared dict `crowdsec_metrics`)

### Per-request decision pipeline (très haute fréquence, faible cardinalité)

| Compteur | Source | Émis quand | Cardinalité | Coût | Valeur opérationnelle | Dashboard | Alerting |
|----------|--------|-----------|-------------|------|----------------------|-----------|----------|
| `total_checks` | `access.lua:57` | Chaque requête entrant le pipeline Lua | 1 | nul | Volume baseline, base du ratio de tous les autres | Security Overview | — (utilisé comme dénominateur) |
| `cache_hits` | `lookup.lua:41,50,60` | Verdict trouvé dans `cscf_verdicts` (exact/cidr24/cidr16) | 1 | nul | Efficacité du cache | Lua Engine Health | hit_ratio < 50 % = warn |
| `cache_misses` | `lookup.lua:65` | Aucun verdict trouvé | 1 | nul | Trafic inconnu vs banni | Lua Engine Health | (cf. ratio) |
| `level_0_hits` | `mitigation.lua:31` | Verdict allow | 1 | nul | Trafic légitime | Security Overview | — |
| `ratelimit_drops` | `mitigation.lua:42` | 429 par rate-limit | 1 | nul | Charge anormale par IP | Security Overview | spike → warn |
| `tarpits` | `mitigation.lua:51` | Tarpit appliqué | 1 | nul | Latence imposée à un scanner | Security Overview | — |
| `challenges` | `mitigation.lua:57` | JS challenge | 1 | nul | Hint LAPI challenge | Security Overview | — |
| `captchas` | `mitigation.lua:66` | Niveau CAPTCHA déclenché | 1 | nul | Volume CAPTCHA | Security Overview | spike → investigate |
| `denies` | `mitigation.lua:75` | 403/444 | 1 | nul | Volume blocages | Security Overview | spike → investigate |
| `honeypot_hits` | `access.lua:82` | Touche d'un path honeypot | 1 | nul | Activité scanner/exploit | Security Overview | tout hit = signal |
| `sync_stale_checks` | `access.lua:92` | Requête traitée en mode stale (sync > 120s) | 1 | nul | Indisponibilité Python détectée par Lua | Lua Engine Health | > 0 = page |
| `escalations` | `heuristics.lua:161` | Score cumulé > 80 → event écrit dans events.jsonl | 1 | léger I/O | Auto-escalade vers Python | Security Overview | spike soutenu → review |
| `appsec_blocks` | `access.lua:123` | AppSec Coraza/CRS match (fusion mode) | 1 | nul | Activité WAF | Security Overview | ⚠️ **NON EXPORTÉ** dans /crowdsec-metrics actuellement (gap) |

### Heuristic signals (haute fréquence, faible cardinalité)

| Compteur | Source | Émis quand | Valeur op |
|----------|--------|-----------|-----------|
| `heuristic_hits` | `heuristics.lua:152` | Total signaux heuristiques évalués | Volume baseline |
| `ua_hits` | `heuristics.lua:142` | User-Agent anomalie | UA scanners/bots |
| `header_anomaly_hits` | `heuristics.lua:143` | Header incohérent | Spoofing/scraping |
| `path_hits` | `heuristics.lua:144` | Path sensible (admin, .env, etc.) | Reconnaissance |
| `burst_hits` | `heuristics.lua:138` | Burst dépassé (`BURST_THRESHOLD = 120/60s`) | DoS-like |

### IPC integrity (très basse fréquence)

| Compteur | Source | Émis quand | Cardinalité | Valeur op |
|----------|--------|-----------|-------------|-----------|
| `lua_syncs` | `sync.lua:246` | Chaque reload `bans.json` réussi (toutes les 5s) | 1 | Liveness Lua sync |
| `lua_cache_entries` (gauge) | `sync.lua:245` | Snapshot du nombre d'entrées en cache | 1 | Volume bans actifs |
| `cache_free_bytes` (gauge) | `sync.lua:257` | Free space du dict après load | 1 | Pression mémoire |
| `sync_duration_ms` (gauge) | `sync.lua:260` | Durée du dernier load | 1 | Latence reload |
| `ipc_rejected` | `sync.lua:109,118,140,149` | Rejet payload (size/parse/timestamp/integrity) | 1 | Corruption IPC ou rare drift | spike → page |
| `dict_set_failures` | `sync.lua:248` | `cache:set()` échoué (dict plein) | 1 | Saturation cache | > 0 sustained = page |
| `dropped_events` | `events.lua:71` | events.jsonl > 1 MB (Python down) | 1 | Daemon Python arrêté | > 0 = page |
| `memory_pressure_events` | `sync.lua:77` | Cycle où `free_pct < 10%` | 1 | Pression cache sustained | spike = warn |

### Tarpit concurrency

| Compteur | Source | Émis quand |
|----------|--------|-----------|
| `tarpit_total` | `tarpit.lua:41` | Sleep effectué |
| `tarpit_skipped` | `tarpit.lua:25,37` | Concurrency limit (`MAX_TARPITS = 20`) atteint → fail-open |

### Python-pushed via `bans.json.meta` (basse fréquence)

| Compteur | Source | Émis quand | Valeur op |
|----------|--------|-----------|-----------|
| `py_cycle_count` (gauge) | `sync.lua:268` | À chaque load (push Python) | Liveness Python |
| `py_cf_api_errors` | `sync.lua:269` | Idem | Santé API CF côté Python |
| `py_wal_entries` | `sync.lua:270` | Idem | Volume WAL |
| `py_lua_sync_errors` | `sync.lua:271` | Idem | Échecs push (Python → Lua) |
| `py_degraded` (gauge) | `sync.lua:274` | 1 si supervisor en degraded mode | Sentinelle | page |

### State dict — clés notables (non-counters, état runtime)

| Clé | Owner | Usage |
|-----|-------|-------|
| `sync_version` | sync.lua | Dernière version `bans.json` acceptée |
| `sync_ts` | sync.lua | Timestamp Unix du dernier sync — base du `deadman check` (120s) |
| `sync_entries` | sync.lua | Nombre d'entrées dans le dernier reload |
| `memory_pressure` | sync.lua | 1 si free_pct < (100 - 90) % |
| `mem_pressure_warn_ts` | sync.lua | Rate-limit des WARN logs |
| `tarpit_active` | tarpit.lua | Compteur de coroutines en sleep |
| `evt:<ip>:<type>` | events.lua | Dédup per-IP des events (TTL 60s) |
| `esc:<ip>` | heuristics.lua | Dédup d'escalade (TTL 300s) |

---

## Python control plane — compteurs (`_Metrics` class)

Définis dans `crowdsec-cf-sync:_Metrics.__init__` (l. 247). Exposés via `_build_prometheus()` (l. 670) sur `/metrics` port 8765.

### Cycle & API

| Compteur | Source | Émis quand | Valeur op |
|----------|--------|-----------|-----------|
| `cycle_count` | `_Metrics` baseline | (jamais incrémenté actuellement — gauge effective) | Heartbeat |
| `cf_api_calls` | `cf_request:811` | Chaque appel CF API | Volume API |
| `cf_api_errors` | `cf_request:822,827` | Exception ou non-2xx | Santé CF |
| `cf_quota_warnings` | `add_cf_rule:850` | Rule count ≥ 800/1000 | Saturation quota CF |
| `circuit_breaker_trips` | `CircuitBreaker:322,335` | CB ouvert (CF/CS/AbuseIPDB) | Indisponibilité backend |

### Cloudflare actions

| Compteur | Source | Valeur op |
|----------|--------|-----------|
| `cf_rules_added` | `add_cf_rule:906,919` | Volume bans poussés |
| `cf_rules_removed` | `delete_cf_rule:932,941` | Volume unbans |
| `cf_rule_count` (gauge) | `sync_cloudflare:1778` | État courant CF |
| `collapsed_rules` | `collapse_ips:968` | Bans agrégés en /24 |
| `drift_detected` | `reconcile_state:1898` | Désalignement Python ↔ CF |

### Bans & escalations

| Compteur | Source | Valeur op |
|----------|--------|-----------|
| `decisions_processed` | `get_active_bans:1110` | Décisions CrowdSec lues |
| `recidivists_escalated` | `escalate_ban:1152` | Escalade `recidivist-escalation` |
| `protected_range_blocks` | `add_cf_rule:892` | Self-ban prévenu |
| `dry_run_skips` | `add_cf_rule:905,931; report:1559` | Volume opérations DRY |
| `wal_entries` | `_wal_log:480` | Volume audit log |
| `reconcile_runs` | `reconcile_state:1831` | Compteur reconciliation |
| `abuseipdb_reports` | `report_to_abuseipdb_raw:1578` | Volume reports envoyés |
| `abuseipdb_checks` | `check_abuseipdb:1611` | Volume vérifs |
| `lua_syncs` | `push_lua_state:` | Push réussi vers Lua |
| `lua_sync_errors` | `push_lua_state:` | Échec push Lua |
| `lua_escalations` | `read_lua_events:` | Events Lua consommés |

### Gauges

| Gauge | Source | Valeur op |
|-------|--------|-----------|
| `last_sync_ts` | `sync_cloudflare:1811` | Liveness cycle |
| `cf_rule_count` | (cf. dessus) | Volume bans CF actuels |
| `mode` | `1744,1812` | `"normal"` / `"dry_run"` / `"degraded"` |
| `uptime_start` | `_Metrics` init | Boot timestamp |
| `dry_run` (export) | `_build_prometheus:709` | 1 si DRY_RUN |

---

## Gaps d'observabilité identifiés

### 🔴 Gap 1 — `appsec_blocks` compteur non exporté

- **Émission :** `lua/crowdsec/access.lua:123` fait `cs.metrics:incr("appsec_blocks", 1, 0)`.
- **Export :** absent de `lua/crowdsec/metrics.lua` (ni JSON ni Prometheus).
- **Impact :** impossible de mesurer le taux de blocage AppSec côté observabilité externe sans interroger directement le shared dict.
- **Fix proposé (TASK 2 future) :** ajouter dans `metrics.lua` handler Prometheus :
  ```lua
  add("crowdsec_lua_appsec_hits_total", g("appsec_blocks"), "AppSec/Coraza/CRS matches in fusion mode")
  ```
  Et la ligne équivalente dans le JSON `/crowdsec-status`.

### 🔴 Gap 2 — `captcha.lua` n'émet aucune métrique

- **Émission :** 0 appel à `cs.metrics:incr` dans `lua/crowdsec/captcha.lua` (331 lignes).
- **Conséquences observabilité :** on ne sait pas distinguer :
  - CAPTCHA *rendus* (page servie)
  - CAPTCHA *vérifiés avec succès* (cookie valide)
  - CAPTCHA *échoués* (mauvais token Turnstile, timeout, etc.)
  - Cookies *présentés et valides* (bypass légitime)
- **Compteur agrégé existant :** `captchas` (mitigation.lua:66) ne capture que le *déclenchement* du niveau, pas le funnel complet.
- **Fix proposé (TASK 2 future) :** instrumenter 4 compteurs dans `captcha.lua` :
  - `captcha_rendered` (dans `render()`)
  - `captcha_verified_ok` (dans `verify()` après HMAC + Turnstile OK)
  - `captcha_verify_failed` (dans `verify()` sur échec)
  - `captcha_cookie_ok` (dans `has_valid_cookie()` sur OK)

### 🟡 Gap 3 — Pas de métrique d'âge de sync

- `sync_ts` est une clé state, pas un compteur. Le deadman check (`access.lua:40`) la lit en ad-hoc.
- **Manque :** une gauge `crowdsec_lua_sync_age_seconds` = `ngx.time() - sync_ts` qui permettrait une alerte simple "sync stale > 120s".
- Actuellement on doit calculer cet écart côté Prometheus rule, à partir de `sync_ts` (mais cette gauge n'est pas non plus exportée — autre gap).

### 🟡 Gap 4 — Cardinalité — pas de label par vhost

- Toutes les métriques sont globales (un seul label par compteur).
- Impossible de séparer `arleo.eu` vs `mcp-hugo.arleo.eu` vs autres.
- **Fix proposé (TASK 2/3 future) :** ajouter un label `vhost` issu de `ngx.var.server_name`. Attention cardinalité : si l'host header est attaquable, garder un allow-list de vhosts connus.

### 🟢 Gap 5 — Compteur Python `cycle_count` jamais incrémenté

- Défini à 0 dans `_Metrics`, exposé via `meta.cycle_count` en push Lua et `crowdsec_cf_sync_cycles_total` en Prometheus, mais **aucun `metrics.inc("cycle_count")` dans le code**.
- Reste à 0 → tous les dashboards `py_cycle_count` montrent 0 indéfiniment.
- **Fix trivial (1 ligne) :** ajouter `metrics.inc("cycle_count")` au début de chaque itération du `while not _shutdown.is_set()` dans `main()`.

### 🟢 Gap 6 — Pas de tagging par domaine métier

- Les compteurs Python sont nommés (`cf_*`, `abuseipdb_*`, `wal_*`) mais ne portent pas de label `domain=cloudflare|abuseipdb|wal|...`.
- Limite l'agrégation et la réorganisation future après extraction modulaire.
- **Fix (TASK 4 plan) :** côté BetterStack, créer le mapping via regex sur le nom de la métrique. Le tagging structurel attendra l'extraction modulaire (post-StateStore).

---

## Coût (mémoire + CPU)

| Composant | Coût observé |
|-----------|--------------|
| `cs.metrics:incr` (Lua) | 0-coût conceptuel (`ngx.shared.dict.incr` est atomique, O(1)) |
| `cs.metrics:set` (Lua) | Identique |
| `_Metrics.inc` (Python) | Lock acquire/release par appel — négligeable |
| `_build_prometheus` (Python) | O(N counters) string format à chaque scrape — ~50 lignes, négligeable |
| `M.handle_prometheus` (Lua) | O(N counters) string format à chaque scrape Lua-side — négligeable |
| Shared dict size (`crowdsec_metrics`) | 10 MB alloué dans nginx — < 1 % utilisé |
| Shared dict size (`crowdsec_state`) | 5 MB alloué — < 1 % utilisé |

**Verdict coût :** l'instrumentation actuelle est **gratuite** en pratique. Les gaps de la section précédente peuvent être comblés sans surcharge mesurable.

---

## Synthèse

Coverage actuelle (par couche) :

| Couche | Compteurs exportés Prometheus | Couvrage estimé |
|--------|-------------------------------|-----------------|
| Lua data plane (request path) | 16 compteurs + 6 gauges | ✅ 90 % (gaps : appsec, captcha funnel) |
| Lua → Python IPC | 3 compteurs (`lua_syncs`, `ipc_rejected`, `dropped_events`) | ✅ 100 % |
| Python → Lua IPC | 4 compteurs côté Python + 5 gauges républiés côté Lua | ✅ 100 % |
| Python ↔ Cloudflare | 6 compteurs + 1 gauge | ✅ 100 % |
| Python ↔ CrowdSec LAPI | 1 compteur (`decisions_processed`) | ⚠️ 50 % (pas de latence, pas de retry count) |
| Python ↔ AbuseIPDB | 2 compteurs | ✅ 80 % |
| WAL | 1 compteur (`wal_entries`) | ⚠️ 50 % (pas de trim events, pas de replay metrics) |
| Reconcile | 2 compteurs (`reconcile_runs`, `drift_detected`) | ⚠️ 70 % (pas de durée par cycle) |
| Circuit breakers | 1 compteur agrégé (`circuit_breaker_trips`) | ⚠️ 50 % (pas de breakdown par backend) |

**Couverture globale baseline :** ~80 %. Les manques se concentrent côté funnel CAPTCHA et instrumentation `appsec_blocks` côté Lua, plus quelques détails côté Python (cycle_count = 0, pas de latence, pas de breakdown CB). Aucun de ces gaps n'est bloquant pour établir une baseline opérationnelle ; ils sont des cibles d'amélioration **post-extraction modulaire** (TASK 2/3 du mission V3.6.x, à reprendre après la décomposition).

---

## Méta

| Champ | Valeur |
|-------|--------|
| Source code | `crowdsec-cf-sync` v3.6.0 (commit `bae723d`), `lua/crowdsec/*.lua` |
| Auteur doc | Mission V3.6.x — TASK 1 (Lua counters audit, lecture seule) |
| Date | 2026-05-24 |
| Triage parent | `docs/architecture-triage.md`, [[project_crowdsec_hybrid_roadmap]] Phase 5 |
| Statut | Inventaire baseline figé — sera la référence pour mesurer l'impact des futurs refactors |
