# Architecture Triage — Brooks-Lint Audit 2026-05-24

Triage des findings de l'audit architectural Brooks-Lint sur `crowdsec-cf-sync` v3.6.0.
Décision prise après audit : pas de `--fix` automatique, refactor incrémental documenté,
golden tests avant toute extraction de StateStore.

**Score initial :** 62/100 (1 Critical + 4 Warning + 3 Suggestion).
**Score cible court terme :** inchangé — la dette est acceptée, l'objectif est de réduire
le **risque de régression** plutôt que le score.

---

## Vue d'ensemble du plan de refactor

L'ordre d'exécution validé est :

1. **Documenter** invariants, formats d'état, contrats IPC
2. **Tester** : golden tests + snapshots + crash scenarios
3. **Extraire** modules par domaine (StateStore d'abord, puis WAL, etc.)
4. **Orchestrer** : Supervisor classe + Pipeline explicite

**Interdit :** big bang rewrite, refactor mécanique sans golden tests, changements de
schéma d'état sans migration explicite.

---

## Findings

### F1 — Cognitive Overload : Supervisor monolithique (2913 L, 80 funcs, 10 domaines)

| Champ | Valeur |
|-------|--------|
| Severity | 🔴 Critical |
| Decision | **Accepted — Deferred** |
| Target phase | Phases 1→5 (Safe Extraction → Supervisor) |
| Dependencies | F3 (StateStore), F7 (Models), golden tests |
| Risk if rushed | Très élevé — refactor sans tests d'état = corruption WAL/recidiv/CIDR, drift checksum, replay incohérent |
| Risk if deferred | Faible court terme (1 owner), modéré moyen terme (onboarding/extensibilité) |

**Rationale :** la dette est réelle mais le système est stateful et critique. Le découpage
par domaine est la bonne direction, mais il doit suivre l'extraction des fondations
(StateStore, WAL, Models) — pas l'inverse.

**Avant de toucher :**
- `docs/state-format.md` rédigé (envelope, checksum, versioning, atomic write semantics)
- Golden tests sur load/save roundtrip + crash-during-write + invalid checksum + replay
- `docs/ipc-schema.md` figé pour `bans.json` / `events.jsonl`

---

### F2 — Change Propagation : Divergent Change + globales mutables partagées

| Champ | Valeur |
|-------|--------|
| Severity | 🟡 Warning |
| Decision | **Accepted — Deferred** |
| Target phase | Phase 5 (Supervisor class) |
| Dependencies | F1 (résolu par F1 indirectement) |
| Risk if rushed | Élevé — transformer `_cb_cf`/`_cb_cs`/`_cb_abu`/`_shutdown`/`_reload`/`_wal_seq`/`_boot_healthy`/`_degraded_reason`/`_protected_networks`/`_health_lock` en attributs `Supervisor` change la sémantique des handlers SIGHUP/SIGTERM si fait sans soin |
| Risk if deferred | Faible (les globales sont stables, peu de contributeurs concurrents) |

**Rationale :** les globales mutables sont un symptôme du fichier unique. Disparaît
naturellement quand on extrait les domaines et qu'on introduit une classe `Supervisor`
qui les détient.

**Avant de toucher :**
- F1 phases 1→4 complétées (modules extraits, signal handling intact)
- Tests intégration confirmés sur SIGHUP hot reload + SIGTERM graceful shutdown + degraded mode

---

### F3 — Knowledge Duplication : load_X/save_X boilerplate (×6 paires)

| Champ | Valeur |
|-------|--------|
| Severity | 🟡 Warning |
| Decision | **Accepted — Deferred (explicitly NOT mechanical)** |
| Target phase | Phase 2 (StateStore) — APRÈS docs + golden tests |
| Dependencies | `docs/state-format.md`, golden tests, F7 (Models) |
| Risk if rushed | **TRÈS ÉLEVÉ** — touche directement persistence/atomic writes/state recovery/checksum/versioning/WAL-adjacent logic. Régressions silencieuses possibles : corruption d'état, drift de format, problème checksum, recovery WAL cassé, replay incohérent |
| Risk if deferred | Faible — duplication stable, ajouter un nouveau domaine d'état coûte 4 lignes |

**Rationale :** finding *en apparence* mécanique mais dangereux. Les `load_X/save_X`
encapsulent les invariants de persistence du daemon. Un refactor sans capture préalable
des comportements actuels = bombe à retardement.

**Étapes obligatoires avant de toucher :**
1. Snapshot des 6 états en prod (`recidivists.json`, `abuseipdb-reported.json`,
   `modsec-banned.json`, `cidr-banned.json`, `cf_waf_state.json`, `bouncer-abusecheck.json`)
2. Golden tests : load/save roundtrip, crash during write, partial write, invalid
   checksum, invalid version, concurrent write safety, replay after restart
3. Migration explicite documentée si l'envelope change

**Interdiction explicite :** `--fix` automatique Brooks-Lint sur ce finding.

---

### F4 — Dependency Disorder : Schémas IPC implicites (Python ↔ Lua)

| Champ | Valeur |
|-------|--------|
| Severity | 🟡 Warning |
| Decision | **Accepted — Deferred** |
| Target phase | Phase 7 (IPC Contract) |
| Dependencies | F3 (StateStore — partage le pattern d'envelope) |
| Risk if rushed | Modéré — changer le format `bans.json`/`events.jsonl` casse l'IPC entre Python et Lua. Doit être versionné explicitement. |
| Risk if deferred | Modéré — couplage silencieux, mais protégé par `test-lua-integration.sh` |

**Rationale :** créer une source de vérité unique (`docs/ipc-schema.md` ou
`schemas/*.schema.json`) avant tout changement de format. Le test d'intégration valide
ensuite la conformité.

**Avant de toucher :**
- Documenter le format actuel exact dans `docs/ipc-schema.md`
- Si JSON Schema : ajouter validation dans `scripts/test-lua-integration.sh`
- Tagger une version de schéma (séparée de `STATE_VERSION` Python)

---

### F5 — Accidental Complexity : Tactical Programming debt

| Champ | Valeur |
|-------|--------|
| Severity | 🟡 Warning |
| Decision | **Accepted — Resolved indirectly** |
| Target phase | Phase 6 (Pipeline) — résolu par construction |
| Dependencies | F1 phases 1→5 complétées |
| Risk if rushed | Faible — c'est un finding "lecture-seule" sur la structure, pas un risque actif |
| Risk if deferred | Faible court terme, élevé long terme (chaque feature paie la dette) |

**Rationale :** le pipeline explicite (liste `stages = [ingest_lua, sync_crowdsec, ...]`)
remplace les `if not _shutdown.is_set()` répétés. Disparaît automatiquement avec F1.

---

### F6 — Cognitive Overload : Fonctions `main()` et `cmd_doctor()` > 200L

| Champ | Valeur |
|-------|--------|
| Severity | 🟢 Suggestion |
| Decision | **Accepted — Deferred** |
| Target phase | Phase 5 (Supervisor) |
| Dependencies | F1 phases 1→4 |
| Risk if rushed | Modéré — `main()` contient bootstrap + hot reload + degraded mode + loop. Découper sans tests = risque sur l'ordre des opérations boot. |
| Risk if deferred | Faible |

**Rationale :** `main()` se découpe naturellement en `_bootstrap()`, `_load_initial_state()`,
`_run_cycle(state)`, `_handle_shutdown()` quand la classe `Supervisor` existe. `cmd_doctor()`
devient une liste de `DoctorCheck` objets.

---

### F7 — Domain Model Distortion : Schémas anémiques (dict magiques)

| Champ | Valeur |
|-------|--------|
| Severity | 🟢 Suggestion |
| Decision | **Accepted — Scheduled early** |
| Target phase | Phase 3 (Models) — prérequis de F3 |
| Dependencies | `docs/state-format.md` (invariants documentés) |
| Risk if rushed | Faible — `dataclass`/`TypedDict` sont purs (pas de runtime change si la sérialisation JSON est préservée) |
| Risk if deferred | Faible court terme, mais bloque F3 (StateStore propre demande des types) |

**Rationale :** type-only change avec sérialisation préservée = sûr et utile.
Améliore la refactorabilité de F3 et F1.

**Modèles minimum :** `Ban`, `Recidivist`, `ModsecEvent`, `CidrBlock`, `WafDecision`.

---

### F8 — Knowledge Duplication : Drift CLI exemples (`crowdsec-cf-syncV3.py`)

| Champ | Valeur |
|-------|--------|
| Severity | 🟢 Suggestion |
| Decision | **✅ RESOLVED** |
| Target phase | Done — 2026-05-24 |
| Dependencies | — |
| Patch | `if __name__ == "__main__":` block — exemples convertis en f-strings runtime via `Path(sys.argv[0]).name`, ajout handler `-h`/`--help`/`help` |

**Rationale :** déjà corrigé dans le source GitHub par commit `bae723d` (rename
`crowdsec-cf-syncV3.py` → `crowdsec-cf-sync`). Patch additionnel pour éliminer le risque
de drift futur en cas de nouveau rename : `_prog = Path(sys.argv[0]).name`.

**Reste à faire :** redéployer le binaire prod (`/usr/local/bin/crowdsec-cf-sync` est
antérieur au commit `bae723d` + au patch `--help`).

---

## Roadmap d'exécution

Ordre **non négociable** :

```
1. ✅ F8 — Patch CLI drift + --help (DONE 2026-05-24)
2. ✅ docs/state-format.md — invariants persistence (DONE 2026-05-24)
3. ✅ docs/ipc-schema.md — contrat Python↔Lua (DONE 2026-05-24)
4. ✅ Golden tests state files (54 tests) (DONE 2026-05-24)
5. ✅ Golden tests WAL (32 tests) (DONE 2026-05-24)
5b. ✅ Prod-pattern fixtures + corruption variants (+18 tests) (DONE 2026-05-24)
6. ✅ F3 — StateStore (extraction load_X/save_X) in-file class (DONE 2026-05-24, branch refactor/state-store-extraction)
7. ✅ F7 — Models (dataclass/TypedDict, sérialisation préservée) (DONE 2026-05-24, commit 3f152c0)
8. ✅ F1 phases 1-4 — Safe Extraction (state_store.py + wal.py + models.py + config.py — true package layout) (DONE 2026-05-25, branch refactor/package-extraction)
9. ✅ F1 phase 5 + F2 + F6 — Supervisor class (phases 9.1–9.4: globals→attrs, CB, lua/health/protected, _sup.* sync) (DONE 2026-05-25)
10. ✅ F1 phase 6 + F5 — Pipeline explicite (8 extractions: _startup_daemon, _handle_reload_if_needed, _try_recover_degraded, _ingest_lua_events, _sync_crowdsec_sources, _sync_lua_state, _run_waf_poll_if_due, _run_reconciliation_if_due, _update_health_state) (DONE 2026-05-25)
11. ⏳ F4 — IPC Contract formalisé (JSON Schema files)
```

**Tests :** `scripts/test-python.sh` (stdlib unittest, hermétiques, ~0.5s pour 104 tests).
Couverture actuelle : envelope, atomic write, checksum, V3 backward compat, 6 domain
load/save, .bak policy, mutation safety, WAL init/log/trim/replay/inspect, malformed
line tolerance, restart-cross monotonic ids.

Aucune étape ne démarre tant que la précédente n'est pas verte (tests + revue).

---

## Méta

| Champ | Valeur |
|-------|--------|
| Audit source | Brooks-Lint Architecture Audit, 2026-05-24 |
| Audited version | v3.6.0 (commit `bae723d`) |
| Reviewer | jmrGrav |
| Next review | Après extraction StateStore (F3) — réévaluer score & redécouper findings restants |
