# IPC Schema — Python ↔ Lua

Source de vérité unique du contrat IPC entre le control plane Python (`crowdsec-cf-sync`)
et le data plane Lua (`/etc/openresty/lua/crowdsec/`). Tout changement de schéma doit être
versionné via le champ `version` et synchronisé des deux côtés simultanément.

Source code références :
- Python writer  : `crowdsec-cf-sync` → `push_lua_state()` (l. 2094)
- Python reader  : `crowdsec-cf-sync` → `read_lua_events()` / `process_lua_events()` (l. 2192/2228)
- Lua reader     : `lua/crowdsec/sync.lua`
- Lua writer     : `lua/crowdsec/events.lua`
- Lua constants  : `lua/crowdsec/init.lua`

---

## Vue d'ensemble

| Direction | Fichier | Format | Mode write | Mode read |
|-----------|---------|--------|------------|-----------|
| Python → Lua | `/run/crowdsec-lua/bans.json` | JSON (un seul objet) | `mkstemp` + `fsync` + `os.replace` (atomic full-file) | `io.open("r")` + `cjson.decode` (polling 5s) |
| Lua → Python | `/run/crowdsec-lua/events.jsonl` | JSONL (une entry par ligne) | `io.open("a")` + write (atomic per-line) | `rename → .processing` + read + unlink |

**Répertoire IPC :** `/run/crowdsec-lua/` — tmpfs, créé par systemd (`RuntimeDirectory=crowdsec-lua` dans `crowdsec-cf-sync.service`). Permissions : `drwxrwxr-x root:www-data 750`.

**Versioning :** chaque fichier porte un champ `version` (entier monotone côté Python ; pas de champ côté events.jsonl par entry — l'évolution se fait via le type).

---

## Direction Python → Lua : `bans.json`

### Sample prod (2026-05-24)

```json
{
  "version": 558,
  "updated_at": "2026-05-24T10:31:38.710499+00:00",
  "updated_at_epoch": 1779618698,
  "entry_count": 3,
  "writer_pid": 2738499,
  "writer_hostname": "NUC8i3BEH",
  "bans": {
    "160.79.106.123": {
      "score": 80,
      "level": 5,
      "ttl": 7200,
      "reason": "modsec-ban"
    }
  },
  "cidrs": {},
  "meta": {
    "cycle_count": 557,
    "cf_api_errors": 0,
    "wal_entries": 94,
    "lua_sync_errors": 0,
    "degraded": false
  },
  "payload_crc32": 2309249997
}
```

### Schéma normatif

| Champ | Type | Obligatoire | Description |
|-------|------|-------------|-------------|
| `version` | int ≥ 1 | ✅ | Compteur monotone incrémenté à chaque push. **Lua rejette si `version <= last_version` (replay/stale).** Persisté entre redémarrages Python via `_lua_sync_version` global (TODO : actuellement reset au boot Python). |
| `updated_at` | string ISO-8601 UTC | ✅ | Timestamp de l'écriture côté Python (info humaine). |
| `updated_at_epoch` | int (Unix seconds) | ✅ | Même timestamp en Unix epoch. **Utilisé par Lua pour la validation age/future.** |
| `entry_count` | int ≥ 0 | ✅ | `len(bans) + len(cidrs)`. **Lua vérifie au load : mismatch = truncation suspectée → rejet.** |
| `writer_pid` | int | ✅ | PID Python writer (debug). |
| `writer_hostname` | string | ✅ | `socket.gethostname()` (debug). |
| `bans` | object `{ip: BanEntry}` | ✅ (peut être `{}`) | Bans individuels par IP exacte. |
| `cidrs` | object `{cidr: CidrEntry}` | ✅ (peut être `{}`) | Bans par bloc CIDR. |
| `meta` | object `MetaCounters` | ✅ | Compteurs opérationnels Python (Lua les republie en metrics). |
| `payload_crc32` | int 0..2³²−1 | ✅ | CRC32 du JSON canonique sans `payload_crc32` lui-même. Calcul : `zlib.crc32(json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()) & 0xFFFFFFFF`. **Pas vérifié par Lua au 2026-05-24** — réservé future validation, déjà émis pour défense en profondeur. |

### Sous-schéma `BanEntry`

```json
{ "score": 80, "level": 5, "ttl": 7200, "reason": "modsec-ban" }
```

| Champ | Type | Contrainte | Default si absent |
|-------|------|------------|-------------------|
| `score` | int | 0..100000 (clampé par Lua) | 100 |
| `level` | int | 0..5 (`LEVEL_DENY`, clampé par Lua) | `score_to_level(score)` |
| `ttl` | int (seconds) | 1..604800 (1s à 7 jours, clampé par Lua) | 3600 |
| `reason` | string | Tag descriptif. Valeurs connues : `"crowdsec-ban"`, `"modsec-ban"`, `"crowdsec-cidr"`. | — (ignoré par Lua, info debug) |

**Comportement Lua :**
- Entrée dont `info` n'est pas une table → skip silencieux (continue boucle).
- Pas de downgrade : si l'IP a déjà un verdict dans `cscf_verdicts` avec un `level` supérieur (escaladée par heuristique locale), le push ne l'écrase pas.
- Stocké comme string `"<level>:<score>:p"` dans le shared dict (le `:p` marque l'origine Python).

### Sous-schéma `CidrEntry`

```json
{ "score": 100, "level": 5, "ttl": 86400 }
```

| Champ | Type | Contrainte | Default si absent |
|-------|------|------------|-------------------|
| `score` | int | 0..100000 (clampé) | 100 |
| `level` | int | 0..5 (clampé) | 5 |
| `ttl` | int (seconds) | 1..2592000 (1s à 30 jours, clampé) | 86400 |
| `reason` | string optionnel | (présent côté Python actuellement, ignoré par Lua) | — |

**Clés acceptées :**
- CIDR /24 (e.g. `"1.2.3.0/24"`) → stocké sous `cidr24:1.2.3` dans le shared dict.
- CIDR /16 (e.g. `"1.2.0.0/16"`) → stocké sous `cidr16:1.2`.
- Autres masks → ignorés silencieusement par Lua (`prefix24`/`prefix16` retournent nil).

### Sous-schéma `MetaCounters`

```json
{
  "cycle_count":     557,
  "cf_api_errors":   0,
  "wal_entries":     94,
  "lua_sync_errors": 0,
  "degraded":        false
}
```

| Champ | Type | Lua metric output |
|-------|------|-------------------|
| `cycle_count` | int | `py_cycle_count` |
| `cf_api_errors` | int | `py_cf_api_errors` |
| `wal_entries` | int | `py_wal_entries` |
| `lua_sync_errors` | int | `py_lua_sync_errors` |
| `degraded` | bool | `py_degraded` (sérialisé 1/0 pour Prometheus) |

Tous optionnels — si absent, le metric correspondant n'est pas mis à jour.

### Encodage et permissions

- **JSON encode :** `json.dumps(payload, indent=2, ensure_ascii=False).encode()` (UTF-8).
- **CRC32 encode (pour `payload_crc32`) :** `json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()` — canonique, **sans `indent`** et **avec `sort_keys`**. Différent de l'encode final.
- **File mode :** `0o644` (`os.fchmod` après `mkstemp`). www-data (OpenResty) doit lire.
- **Owner :** root (Python tourne en root).

### Atomicité Python writer

1. `LUA_SYNC_DIR.mkdir(parents=True, exist_ok=True)` — idempotent.
2. `tempfile.mkstemp(dir=LUA_SYNC_DIR, suffix=".tmp")` — même tmpfs (rename atomique).
3. `os.fchmod(tmp_fd, 0o644)` — droits avant l'ouverture en write.
4. `write` → `flush` → `os.fsync()` — durabilité.
5. `os.replace(tmp_path, LUA_SYNC_FILE)` — rename atomique.
6. En cas d'exception : `os.unlink(tmp_path)` + re-raise.

### Validation Lua au load (`sync.lua`)

Ordre de validation **non négociable** (chaque étape doit pouvoir rejeter sans toucher le shared dict) :

1. **Dict saturation pré-load** — si `cache:free_space() < DICT_MIN_FREE (2 MB)` → skip + log WARN.
2. **Memory pressure flag** — set `state["memory_pressure"]` à 1 si `free_pct < (100 - MEM_PRESSURE_PCT)`.
3. **File open** — absent = normal au boot (Python pas encore écrit).
4. **Empty content** — silencieux.
5. **Payload size guard** — `#content > BANS_JSON_MAX_BYTES (10 MB)` → reject + `metrics.ipc_rejected++`.
6. **JSON parse** — fail = reject + `metrics.ipc_rejected++`.
7. **Version monotonic** — `tonumber(data.version) <= last_version` → silent skip (replay ou stale).
8. **Age guard** — `(ngx.time() - updated_at_epoch) > BANS_STALE_SECS (600s)` → reject + `metrics.ipc_rejected++`.
9. **Future guard** — `(updated_at_epoch - ngx.time()) > BANS_FUTURE_SECS (300s)` → reject + `metrics.ipc_rejected++`.
10. **Type check `bans` / `cidrs`** — non-table et non-nil → reject (pas de metric increment).
11. **Entry count integrity** — `count(bans) + count(cidrs) != entry_count` → reject (truncation suspectée).
12. **Per-entry validation** — chaque ban/cidr dont `info` n'est pas une table → skip silencieux.

### Frontière de confiance

Le fichier `bans.json` est traité par Lua comme **données non fiables** : tous les champs sont validés en type, bornés en valeur (clamping), et l'intégrité est vérifiée via `entry_count`. Le `payload_crc32` est émis par Python mais **pas encore vérifié côté Lua** — disponible pour défense en profondeur future.

---

## Direction Lua → Python : `events.jsonl`

### Sample (simulé — fichier absent en prod 2026-05-24, aucune escalation récente)

```jsonl
{"ts":1779618700.123,"type":"honeypot_hit","ip":"1.2.3.4","score":100,"detail":"/wp-login.php","worker":0}
{"ts":1779618701.456,"type":"heuristic_escalate","ip":"5.6.7.8","score":95,"detail":"burst+ua_suspect","worker":2}
```

### Schéma normatif (par ligne JSON)

| Champ | Type | Obligatoire | Description |
|-------|------|-------------|-------------|
| `ts` | float (Unix epoch, fractional) | ✅ | `ngx.now()` — résolution microseconde. Pas obligatoire côté Python (ignoré). |
| `type` | string | ✅ | Type d'event. Valeurs connues : `"honeypot_hit"`, `"heuristic_escalate"`. |
| `ip` | string | ✅ | IP source (validé par Python via `ipaddress.ip_address`). |
| `score` | int | ✅ | Score Lua au moment de l'event (0..100+). |
| `detail` | string | ✅ (peut être `""`) | Contexte (path, raison heuristique). |
| `worker` | int | ✅ | `ngx.worker.id()` — debug. |

### Types d'événements (`ev.type`)

#### `honeypot_hit`
- Émis par : `lua/crowdsec/heuristics.lua` quand une IP touche un path honeypot.
- `detail` = path de la requête.
- Action Python : report à AbuseIPDB (catégories `21,19`) si IP pas déjà dans `reported`.

#### `heuristic_escalate`
- Émis par : `lua/crowdsec/heuristics.lua` quand le score cumulé dépasse `ESCALATION_THRESHOLD = 80`.
- `detail` = string descriptive du déclencheur (`"burst+ua_suspect"`, etc.).
- Action Python : log INFO ; report AbuseIPDB **uniquement si `score >= 90` ET pas déjà reported**.

### Types réservés / futurs

Tout futur `type` doit :
1. Être ajouté à `process_lua_events()` côté Python (sinon silencieusement ignoré).
2. Documenté ici avec son `detail` schéma et l'action attendue.
3. Émis avec le même schéma de ligne (pas de nouveau champ obligatoire sans bump versionning fichier).

### Atomicité Lua writer

- `io.open(EVENTS_FILE, "a")` — append POSIX atomique pour writes < `PIPE_BUF` (4096 bytes). Une entry fait ~150 bytes : safe.
- Écriture déférée via `ngx.timer.at(0, ...)` — le request handler n'est jamais bloqué par I/O.
- **Pas de fsync** — perte tolérée en cas de crash (les events sont best-effort, l'IP sera re-bannie au prochain hit).

### Anti-flood Lua

- Clé `evt:<ip>:<type>` dans `crowdsec_state` shared dict avec TTL = `EVENT_COOLDOWN_SECS = 60`.
- Si la clé existe : event silencieusement droppé.
- Réservation **avant** le write asynchrone pour éviter race entre workers.

### Size guard Lua

- Avant chaque append : `io.open(EVENTS_FILE, "r")` + `seek("end")` pour mesurer la taille.
- Si `current_size > EVENTS_MAX_BYTES (1 MB)` → event droppé, `metrics.dropped_events++`, log WARN.
- **Lua ne tronque JAMAIS** : c'est Python qui possède le cycle de vie du fichier (rename → .processing → unlink).
- En opération normale Python draine toutes les 60s donc ce guard ne se déclenche que si Python est arrêté.

### Atomicité Python reader (`read_lua_events`)

1. Si `LUA_EVENTS_FILE` absent → return `[]`.
2. `LUA_EVENTS_FILE.rename(events.jsonl.processing)` — atomique POSIX, Lua re-créera `events.jsonl` au prochain append.
3. Lecture ligne par ligne du `.processing`, parsing `json.loads` (lignes invalides silencieusement skippées).
4. `proc_file.unlink()` dans le `finally`.

**Invariant :** entre le `rename` et le `unlink`, Lua peut continuer à appender sur un nouveau `events.jsonl` sans interférer avec la lecture. Pas de read-while-truncate race.

---

## Versioning et compatibilité

### Politique de bump

| Type de changement | Action requise |
|--------------------|----------------|
| Nouveau champ optionnel dans `bans.json` (toléré par Lua) | Aucun bump. Documenter ici. |
| Nouveau champ obligatoire | **Bump majeur** : nouveau schéma `version_v2`, code Lua dual-read pendant fenêtre de migration, Python écrit l'ancien format en parallèle pendant N cycles. |
| Nouveau type d'event Lua → Python | Aucun bump. Ajouter le handler dans `process_lua_events()`. Émis events de type inconnu = ignorés silencieusement (forward compatible). |
| Changement de sémantique d'un champ existant (e.g. unité de TTL) | **Bump majeur obligatoire** + migration coordonnée. |
| Suppression d'un champ | **Bump majeur**, retirer la lecture Lua APRÈS confirmation que Python ne l'émet plus. |

### Compatibilité actuelle (au 2026-05-24)

- Python writer V3.6.0 → Lua reader V3.5+ : ✅ compatible.
- Lua envoie `payload_crc32` mais Lua reader ne le vérifie pas — pas un problème.
- Tous les champs `meta` sont optionnels côté Lua (chaque champ vérifié individuellement) — Python peut en ajouter sans risque.

---

## TODO — JSON Schema files

Pour la Phase 7 du triage doc (`F4 — IPC Contract formalisé`), produire :

```
schemas/
  bans.schema.json        — JSON Schema draft-07 pour bans.json
  events.schema.json      — JSON Schema (par ligne) pour events.jsonl
```

Validation à intégrer dans :
- `scripts/test-lua-integration.sh` : valider qu'un write Python conforme passe le parsing Lua.
- Pre-commit hook (optionnel) : valider les samples de tests dans `examples/`.

Pas encore créés au 2026-05-24 — la spec prose ci-dessus reste la source de vérité jusqu'à la Phase 7.

---

## Constantes critiques (référence rapide)

| Constante | Côté | Valeur | Rôle |
|-----------|------|--------|------|
| `SYNC_INTERVAL` | Lua | 5s | Période de poll de `bans.json` |
| `BANS_STALE_SECS` | Lua | 600s | Rejet si `bans.json` plus vieux que ça |
| `BANS_FUTURE_SECS` | Lua | 300s | Rejet si timestamp dans le futur |
| `BANS_JSON_MAX_BYTES` | Lua | 10 MB | Rejet pre-parse si trop gros |
| `EVENTS_MAX_BYTES` | Lua | 1 MB | Drop events si fichier au-dessus |
| `EVENT_COOLDOWN_SECS` | Lua | 60s | Anti-flood per-(ip, type) |
| `DICT_MIN_FREE` | Lua | 2 MB | Skip load si shared dict saturé |
| `MEM_PRESSURE_PCT` | Lua | 90 % | Seuil pour suspendre writes heuristiques |
| `LEVEL_DENY` | Lua | 5 | Niveau max accepté pour bans/cidrs |
| `MODSEC_BAN_SECS` | Python | 7200s | TTL des bans ModSec dans `bans.json` |
| `INTERVAL` | Python | 60s | Période du cycle Python (write `bans.json`) |
| `STATE_VERSION` | Python | 1 | Version envelope des fichiers d'état (≠ `version` de bans.json) |

⚠️ **`bans.json.version` est un compteur de cycles** (++ à chaque push, persistant pendant la session Python), **pas** une version de schéma. Le numéro 558 dans le sample = 558ème push depuis le dernier boot Python.

---

## Méta

| Champ | Valeur |
|-------|--------|
| Source code | `crowdsec-cf-sync` v3.6.0 (commit `bae723d`), `lua/crowdsec/*.lua` |
| Auteur doc | Brooks-Lint refactor — étape 3 (préparation IPC Contract) |
| Date | 2026-05-24 |
| Triage parent | `docs/architecture-triage.md` F4 (Dependency Disorder — schémas IPC implicites) |
| Statut | Spec figée — toute modification de format requiert édition coordonnée Python + Lua + ce document |
