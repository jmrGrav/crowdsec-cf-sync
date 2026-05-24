# BetterStack Observability Recommendations

Recommandations dashboards / alertes / SLO pour la stack hybride `crowdsec-cf-sync`,
conçues pour rester valides **après** la décomposition modulaire du supervisor.

**Principe directeur :** instrumentation minimale mais structurée. Pas de hooks
ajoutés ad-hoc ; on consomme uniquement les compteurs existants documentés dans
`docs/metrics-map.md`. Tagging par domaine est préparé via regex sur les noms de
métriques pour pouvoir migrer vers de vrais labels Prometheus une fois l'extraction
modulaire faite.

---

## Sources à scraper

Deux endpoints Prometheus à connecter à BetterStack via Vector (ou prometheus_remote_write) :

| Endpoint | Interval | Tags BetterStack à appliquer |
|----------|----------|------------------------------|
| `http://127.0.0.1:8091/crowdsec-metrics` | 15s | `layer=data_plane`, `runtime=lua`, `host=$HOSTNAME` |
| `http://127.0.0.1:8765/metrics` | 30s | `layer=control_plane`, `runtime=python`, `host=$HOSTNAME` |

Vector example (snippet, à intégrer dans `vector.yaml` existant — secrets toujours via env) :

```yaml
sources:
  crowdsec_lua_metrics:
    type: prometheus_scrape
    endpoints: ["http://127.0.0.1:8091/crowdsec-metrics"]
    scrape_interval_secs: 15
  crowdsec_py_metrics:
    type: prometheus_scrape
    endpoints: ["http://127.0.0.1:8765/metrics"]
    scrape_interval_secs: 30

transforms:
  tag_lua:
    type: remap
    inputs: [crowdsec_lua_metrics]
    source: |
      .tags.layer = "data_plane"
      .tags.runtime = "lua"
  tag_py:
    type: remap
    inputs: [crowdsec_py_metrics]
    source: |
      .tags.layer = "control_plane"
      .tags.runtime = "python"
```

**⚠️ Aucun secret dans les configs commitées.** `BETTERSTACK_TOKEN` reste exclusivement en env.

---

## Tagging strategy — préparation future modular

Les métriques actuelles n'ont pas de label `domain=`. On le dérive par **regex sur le nom**
côté BetterStack/Vector, pour que les dashboards restent stables quand l'extraction
modulaire introduira de vrais labels :

| Pattern de nom | Tag dérivé | Domaine futur (post-refactor) |
|----------------|------------|-------------------------------|
| `crowdsec_cf_sync_cf_*` | `domain=cloudflare` | `cloudflare.py` |
| `crowdsec_cf_sync_wal_*` | `domain=wal` | `wal.py` |
| `crowdsec_cf_sync_abuseipdb_*` | `domain=abuseipdb` | `abuseipdb.py` |
| `crowdsec_cf_sync_reconcile_*` / `_drift_*` | `domain=reconcile` | `reconciliation.py` |
| `crowdsec_cf_sync_recidivists_*` | `domain=recidiv` | `recidiv.py` |
| `crowdsec_cf_sync_circuit_breaker_*` | `domain=circuit_breaker` | `circuit_breaker.py` |
| `crowdsec_cf_sync_decisions_*` | `domain=crowdsec_lapi` | `crowdsec_lapi.py` |
| `crowdsec_cf_sync_protected_*` | `domain=safety` | `protected.py` |
| `crowdsec_lua_cache_*` | `domain=lua_cache` | (data plane, hors refactor Python) |
| `crowdsec_lua_ipc_*` / `_sync_*` / `_dropped_events_*` | `domain=lua_ipc` | `lua_ipc.py` |
| `crowdsec_lua_appsec_*` | `domain=appsec` | (data plane) |
| `crowdsec_lua_captcha*` / `_challenges_*` | `domain=mitigation` | (data plane) |
| `crowdsec_py_*` (côté Lua, republié) | `domain=python_bridge` | (cross-plane) |

Mapping additionnel par **stage** (pour pipeline-aware dashboards futurs) :

| Stage | Métriques |
|-------|-----------|
| `input` | `total_checks`, `cache_hits`, `cache_misses` |
| `decide` | `heuristic_hits`, `ua_hits`, `header_anomaly_hits`, `path_hits`, `burst_hits`, `appsec_blocks` |
| `mitigate` | `level_0_hits`, `ratelimit_drops`, `tarpits`, `challenges`, `captchas`, `denies` |
| `persist` | `wal_entries`, `cf_rules_added`, `cf_rules_removed` |
| `escalate` | `escalations`, `recidivists_escalated`, `abuseipdb_reports` |
| `reconcile` | `reconcile_runs`, `drift_detected`, `lua_syncs` |
| `health` | `circuit_breaker_trips`, `cf_quota_warnings`, `memory_pressure_events`, `ipc_rejected`, `dict_set_failures`, `dropped_events`, `py_degraded` |

---

## Dashboards recommandés (6)

### Dashboard 1 — Security Overview

**Audience :** vue temps réel des décisions du data plane.

**Panels :**
1. **Decision funnel** (stacked area, last 1h, `rate()` over 5m) :
   - `crowdsec_lua_total_checks_total`
   - décomposé par : `level_0_hits` (allows), `tarpits`, `challenges`, `captchas`, `ratelimit_drops`, `denies`
2. **Decision ratios** (gauge avec seuils) :
   - `denies / total_checks` (warn > 1 %, page > 10 %)
   - `captchas / total_checks` (warn > 0.5 %)
3. **Honeypot hits** (counter delta) : tout hit = signal scanner ; rate par heure
4. **AppSec hits** : ⚠️ **bloqué tant que Gap 1 (`appsec_blocks` export) pas corrigé**
5. **Top attacking IPs** (table) : nécessite cardinalité par IP côté log Vector, pas via Prometheus
6. **Cloudflare bans actifs** (gauge) : `crowdsec_cf_sync_cf_rule_count` — surveiller approche du quota
7. **Quota CF approchant** : `crowdsec_cf_sync_cf_quota_warnings_total` rate ; toute valeur = warn

### Dashboard 2 — Lua Engine Health

**Audience :** SRE / oncall sur la stack.

**Panels :**
1. **Sync liveness** :
   - `crowdsec_py_cycle_count` delta (rate per 5m doit être > 0)
   - `crowdsec_lua_syncs_total` rate (doit être ~12/min — un cycle = 5s)
2. **Sync stale events** (counter) : `crowdsec_lua_sync_stale_checks_total` ; > 0 = Python down ou désynchronisé
3. **Memory pressure** (gauge) : `crowdsec_lua_memory_pressure_active` — 0/1 ; toute valeur = 1 = warn
4. **Cache hit ratio** (gauge dérivé) : `cache_hits / (cache_hits + cache_misses)`
5. **Cache entries** (gauge) : `crowdsec_lua_cache_entries`
6. **Cache free bytes** (gauge avec seuils) : `crowdsec_lua_cache_free_bytes` — < 5 MB = warn, < 2 MB = page (correspond `DICT_MIN_FREE`)
7. **Sync duration** (gauge) : `crowdsec_lua_sync_duration_ms` — > 200 ms = warn
8. **IPC integrity** (counter) :
   - `crowdsec_lua_ipc_rejected_total` rate
   - `crowdsec_lua_dict_set_failures` rate
9. **Dropped events** : `crowdsec_lua_dropped_events_total` — > 0 sustained = Python arrêté

### Dashboard 3 — Cloudflare

**Audience :** ops + observation impact externe.

**Panels :**
1. **CF API call rate** : `crowdsec_cf_sync_cf_api_calls_total` rate
2. **CF API error rate** : `crowdsec_cf_sync_cf_api_errors_total` rate ; et **error ratio** vs total calls (page > 5 %)
3. **Rules added/removed** (counter) : breakdown over 1h
4. **Active CF rules** : `crowdsec_cf_sync_cf_rule_count` — proche 800/1000 = warn (quota défini ligne 124)
5. **Reconcile cycles** : `crowdsec_cf_sync_reconcile_runs_total` rate (doit être ~12/h — un reconcile = 300s)
6. **Drift detected** : `crowdsec_cf_sync_drift_detected_total` rate ; spike sustained = bug Python ou notifier en panne
7. **Circuit breaker CF** : `crowdsec_cf_sync_circuit_breaker_trips_total` — toute valeur (idéalement breakdown par backend, voir Gap 6 dans metrics-map)
8. **Mode** (gauge text) : `crowdsec_cf_sync_dry_run` (1 = dry-run, 0 = normal) ; `mode="degraded"` côté JSON = page

### Dashboard 4 — AbuseIPDB

**Audience :** observation du reporting externe (volume + dédup).

**Panels :**
1. **Reports sent** : `crowdsec_cf_sync_abuseipdb_reports_total` rate per day
2. **Checks performed** : `crowdsec_cf_sync_abuseipdb_checks_total` rate per day
3. **DRY_RUN status** : `crowdsec_cf_sync_dry_run` = 1 → AbuseIPDB n'envoie pas (Phase 4 du hybrid roadmap)
4. **Skipped via dedup** : nécessite instrumentation supplémentaire — actuellement on ne mesure pas le ratio "tenté mais déjà reported"

### Dashboard 5 — WAL & Reconcile

**Audience :** debug + post-mortem.

**Panels :**
1. **WAL entries growth** : `crowdsec_cf_sync_wal_entries_total` rate ; tendance flat ou modérée attendue
2. **WAL size** (gauge custom) : `du /var/log/crowdsec/cf-sync-wal.jsonl` exposée via node_exporter ou Vector file source
3. **Reconcile drift events** : déjà dans Dashboard 3, dupliqué ici pour vue WAL-centric
4. **Recidivists escalated** : `crowdsec_cf_sync_recidivists_escalated_total` rate ; spike = vague d'attaque récurrente
5. **Collapsed rules** : `crowdsec_cf_sync_collapsed_rules_total` ; volume bans agrégés en /24 — efficacité du collapsing

### Dashboard 6 — Heuristics breakdown

**Audience :** tuning des règles heuristiques.

**Panels :**
1. **Heuristic signals stacked** :
   - `crowdsec_lua_ua_hits_total`
   - `crowdsec_lua_header_anomaly_hits_total`
   - `crowdsec_lua_path_hits_total`
   - `crowdsec_lua_burst_hits_total`
2. **Escalation rate** : `crowdsec_lua_escalations_total` rate ; corrélation avec les heuristic signals indique le seuil opérationnel
3. **Tarpit usage** : `crowdsec_lua_tarpit_total` rate + `crowdsec_lua_tarpit_skipped_total` rate ; skipped > 0 = saturation `MAX_TARPITS=20`

---

## Alerting recommandé (catégories)

### 🔴 Page (intervention immédiate)

| Condition | Source | Pourquoi |
|-----------|--------|----------|
| `py_degraded == 1 for 1m` | Lua republished metric | Supervisor en mode dégradé (CF inaccessible) |
| `sync_stale_checks > 0 for 5m` | Lua | Daemon Python down ou figé, data plane fonctionne en stale |
| `dropped_events > 0 for 5m` | Lua | Python arrêté, events.jsonl > 1 MB |
| `cache_free_bytes < 2_097_152 for 10m` | Lua | Saturation cache (`DICT_MIN_FREE`) — pas de nouveaux bans |
| `cf_api_errors / cf_api_calls > 0.1 for 10m` | Python | Indisponibilité Cloudflare, fallback à reconcile uniquement |
| `circuit_breaker_trips delta > 0 in 5m` | Python | Backend ouvert (CF/CS/AbuseIPDB) |
| `cf_rule_count > 950` | Python | Approche du quota 1000 |

### 🟡 Warn (investigation différée)

| Condition | Source | Pourquoi |
|-----------|--------|----------|
| `memory_pressure_active == 1 for 30m` | Lua | Pression mémoire soutenue |
| `cache_hit_ratio < 0.50 for 1h` | Lua dérivé | Cache inefficace ou afflux d'IPs inconnues |
| `ipc_rejected delta > 5 in 1h` | Lua | Drift Python ↔ Lua ou corruption IPC |
| `dict_set_failures delta > 0 in 1h` | Lua | Saturation du dict pendant écriture |
| `denies / total_checks > 0.05 for 30m` | Lua dérivé | Vague d'attaque ou faux positifs |
| `drift_detected delta > 10 in 1h` | Python | Reconcile fait beaucoup de corrections — notifier en panne ? |
| `cf_quota_warnings delta > 0 in 1h` | Python | Approche du quota CF |

### 🟢 Info (visibilité dashboard, pas d'alerte)

- `total_checks rate` — observation volume
- `recidivists_escalated rate` — observation vague récurrente
- `appsec_blocks rate` (une fois Gap 1 corrigé) — observation activité WAF

---

## SLO candidats

| SLO | Cible | Window | Justification |
|-----|-------|--------|---------------|
| **SLO-1** : pas de stale mode | `sync_stale_checks == 0` | 99.9 % du temps mensuel | Le data plane doit toujours avoir un Python vivant |
| **SLO-2** : sync Python en temps | `rate(crowdsec_lua_syncs_total) >= 6/min` (~50% de la fréquence nominale 12/min) | 99 % du temps | Latence acceptable |
| **SLO-3** : Cloudflare API success | `cf_api_errors / cf_api_calls < 5 %` | 99 % du temps | Disponibilité externe |
| **SLO-4** : cache pas saturé | `cache_free_bytes > 2 MB` | 99 % du temps | Garantit l'acceptation de nouveaux bans |
| **SLO-5** : pas de degraded mode | `py_degraded == 0` | 99.9 % du temps | Boot CF OK |

Mesurés via BetterStack Uptime/SLO sur les Prometheus queries correspondantes.

---

## Retention strategy

| Type métrique | Retention recommandée | Rationale |
|---------------|----------------------|-----------|
| Compteurs request-path (`total_checks`, `cache_*`, `level_*_hits`) | 30 jours raw + 1 an 5min downsample | Trend analysis |
| Compteurs IPC integrity (`ipc_rejected`, `dropped_events`) | 90 jours raw | Forensics post-incident |
| Compteurs Cloudflare (`cf_*`) | 90 jours raw | Audit modifications externes |
| Compteurs WAL (`wal_entries`) | 1 an downsample | Cohérent avec `cf-sync-wal.jsonl` audit trail |
| Gauges state (`cf_rule_count`, `cache_entries`) | 30 jours raw | Suffit aux dashboards courants |
| Mode/health gauges | 1 an raw | Faible volume, valeur post-mortem élevée |

---

## Incident views

Pré-configurer dans BetterStack 3 vues filtrées :

1. **"CF outage"** — toutes les métriques avec `domain=cloudflare` + `circuit_breaker_trips`, fenêtre last 1h.
2. **"Lua data plane saturation"** — `memory_pressure_active`, `cache_free_bytes`, `dict_set_failures`, `ipc_rejected`, fenêtre last 30m.
3. **"Python supervisor down"** — `sync_stale_checks`, `dropped_events`, `py_cycle_count` rate, fenêtre last 30m.

Liens directs depuis chaque alerte vers la vue correspondante.

---

## Métriques anticipées pour le refactor modulaire

Une fois l'extraction modulaire faite (post-StateStore + post-config.py), réintroduire :

| Compteur | Source future | Label de différenciation |
|----------|---------------|--------------------------|
| `crowdsec_supervisor_stage_duration_seconds` | `pipeline.py` | `stage={ingest_lua, sync_crowdsec, sync_cloudflare, sync_abuseipdb, sync_modsec, ...}` |
| `crowdsec_supervisor_stage_errors_total` | `pipeline.py` | `stage=...` + `error_class=...` |
| `crowdsec_state_store_ops_total` | `state_store.py` | `op={load, save}` + `domain={recidiv, abuse, modsec, cidr, waf, bouncer}` |
| `crowdsec_state_store_corruption_total` | `state_store.py` | `domain=...` + `reason={sha_mismatch, json_decode, wrong_type, ...}` |
| `crowdsec_wal_replay_duration_seconds` | `wal.py` | (histogramme) |
| `crowdsec_circuit_breaker_state` | `circuit_breaker.py` | `backend={cloudflare, crowdsec, abuseipdb}` + `state={closed, open, half_open}` |

Ces métriques ne sont **pas** à instrumenter maintenant ; elles servent de cible pour
guider la signature des futurs modules. Le mapping regex actuel les remplacera
naturellement quand elles arriveront.

---

## Anti-recommandations (à NE PAS faire)

| Tentation | Pourquoi pas |
|-----------|-------------|
| Ajouter des `log.info(...)` partout dans la boucle Python | Coût I/O, bruit dans journald, surveille des choses qui ne sont pas alertables. Mieux : compteurs. |
| Instrumenter `captcha.lua` maintenant (Gap 2) | Modifie le data plane ; reporté à TASK 2 post-extraction. Le triage doc l'interdit. |
| Ajouter un label `vhost` Lua-side maintenant | Cardinalité explosive si attaquée par Host header forgé. Attendre. |
| Streamer chaque request dans BetterStack | Coût ingestion énorme. On veut des agrégats, pas du raw. |
| Exporter `evt:*` / `esc:*` keys d'état comme métriques | Cardinalité par IP infinie. C'est de l'état interne, pas une métrique. |
| Ajouter de nouveaux env vars pour toggle métriques | Augmente la dette config.py qu'on cherche à réduire. |

---

## Méta

| Champ | Valeur |
|-------|--------|
| Source code | `crowdsec-cf-sync` v3.6.0 + `lua/crowdsec/*.lua` |
| Référence inventaire | `docs/metrics-map.md` |
| Auteur doc | Mission V3.6.x — TASK 4 (BetterStack recommendations) |
| Date | 2026-05-24 |
| Statut | Recommandations figées — implementation Vector/BetterStack à la discrétion de l'utilisateur |
| Prochain refactor déclenchant maj | Extraction `pipeline.py` + `state_store.py` (introduira de vrais labels) |
