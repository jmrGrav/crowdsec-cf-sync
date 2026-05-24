# State File Format — `crowdsec-cf-sync`

Specification figée des invariants de persistence du supervisor. Toute extraction
StateStore (cf. `docs/architecture-triage.md`, finding F3) doit préserver ces
invariants à l'octet près. Tout changement implique une migration explicite + bump
de `STATE_VERSION`.

Source : `crowdsec-cf-sync` v3.6.0, fonctions `_load_json_state` (l. 381) et
`_atomic_write_json` (l. 423).

---

## Vue d'ensemble

| Fichier | Domaine | Format actuel | Envelope V4 ? | Retention |
|---------|---------|---------------|---------------|-----------|
| `/var/log/crowdsec/recidivists.json` | Récidivistes (compteur per-IP) | dict | ✅ | `RECIDIV_WINDOW = 7 jours` |
| `/var/log/crowdsec/abuseipdb-reported.json` | Dédup envois AbuseIPDB | dict | ✅ | géré par caller (clés composites) |
| `/var/log/crowdsec/modsec-banned.json` | Bans ModSec → CF | dict | ⚠️ mix V3/V4 (migrate-on-save) | `MODSEC_BAN_SECS = 2h` (cleanup 3h) |
| `/var/log/crowdsec/cidr-banned.json` | Bans CIDR /24 agrégés | dict | ✅ | `CIDR_WINDOW = 7 jours` |
| `/var/log/crowdsec/cf_waf_state.json` | Curseur poll WAF Cloudflare | dict | ✅ | `last_event_dt` glissant |
| `/var/log/crowdsec/bouncer-abusecheck.json` | Cache vérifs AbuseIPDB du bouncer | dict | ✅ (créé à la 1ʳᵉ écriture) | `BOUNCER_CHECK_TTL = 24h` (cleanup 7 jours) |
| `/var/log/crowdsec/cf-sync-wal.jsonl` | WAL append-only des actions CF | JSONL | N/A (pas d'envelope) | trim à 10 000 lignes |

`STATE_VERSION = 1` au 2026-05-24. À bumper UNIQUEMENT si le format change de façon
non rétrocompatible.

---

## Envelope V4 — invariants

Tous les fichiers d'état (sauf WAL) sont écrits dans cette enveloppe :

```json
{
  "version": 1,
  "updated_at": "2026-05-24T07:33:39.026246+00:00",
  "sha256": "262e4a1986f09b2caddd1c9c4106e740d1bd31624dff6e645abecd73961bdfdd",
  "state": { ... }
}
```

### Invariants normatifs

1. **Clés obligatoires :** `version` (int), `updated_at` (ISO-8601 UTC), `sha256` (hex 64 chars), `state` (object).
2. **Checksum sur le canonical JSON du seul `state`** :
   ```python
   hashlib.sha256(
       json.dumps(state, sort_keys=True, ensure_ascii=False).encode()
   ).hexdigest()
   ```
   - `sort_keys=True` — non négociable, le moindre ordre différent invalide le checksum.
   - `ensure_ascii=False` — non négociable, les non-ASCII passent en UTF-8 brut.
3. **Enrobage write** : `indent=2`, `ensure_ascii=False`, encodé UTF-8 (note : `indent` ne fait PAS partie du calcul du checksum).
4. **`updated_at`** : `datetime.now(timezone.utc).isoformat()`. Pas suffixé `Z`, garde l'offset `+00:00`.
5. **Le checksum protège uniquement `state`** : la corruption de `version`/`updated_at`/`sha256` lui-même n'est pas auto-détectée — mais une mauvaise valeur de `sha256` au load → reset+backup.

### Comportement load

```
file absent     → return default (no log)
JSON parse fail → log warning + _rename_bak (→ .bak) + return default
state pas dict  → log warning + _rename_bak + return default
sha256 mismatch → log warning + _rename_bak + return default
sha256 absent   → accepté (envelope partielle) — pas de validation
version absent  → traité comme V3 flat (cf. ci-dessous)
type inattendu  → log warning + _rename_bak + return default
```

### Backward compatibility — V3 flat format

Avant V4, les fichiers étaient écrits comme `dict` plat sans envelope :

```json
{
  "160.79.106.123": {
    "banned_at": "2026-04-06T20:45:14.827023+00:00",
    "score": 8,
    "uri": "/oauth-mcp/mcp"
  }
}
```

Règles :
- Au load : si `version` absent ET `data` est un dict → accepté tel quel (interprété comme `state`).
- Au save : ré-écrit dans l'enveloppe V4 (migrate-on-save).
- **Aucun checksum** pour les V3 lus → pas de protection corruption rétroactive.
- **Aucune migration explicite** : la première écriture après un load V3 produit un V4. **Si jamais aucun save n'est déclenché, le fichier reste V3 indéfiniment.**

> ⚠️ Au 2026-05-24, `modsec-banned.json` est encore en V3 sur prod (aucun ban ModSec récent → pas de save). Comportement attendu et inoffensif, mais à connaître pour les golden tests.

---

## Atomic write semantics

Implémenté par `_atomic_write_json` (l. 423) :

1. `tempfile.mkstemp(dir=path.parent, suffix=".tmp")` — fichier temp dans le **même répertoire** (rename atomique cross-FS impossible).
2. `f.write(content)` → `f.flush()` → `os.fsync(f.fileno())` — durabilité avant rename.
3. `os.replace(tmp_path, path)` — rename atomique POSIX.
4. En cas d'exception : `os.unlink(tmp_path)` pour nettoyer.

### Invariants

- **Pas de write partiel observable** : `os.replace` est atomique au niveau du syscall.
- **Le fichier final est toujours valide** (fsync avant rename garantit la durabilité).
- **Le `.tmp` peut survivre** si crash entre `write` et `replace` → cleanup au prochain démarrage non implémenté actuellement. Risque mineur : encombre `/var/log/crowdsec/`.
- **Pas de lock** : si deux processus écrivent simultanément, le dernier `replace` gagne. Le supervisor est mono-process (systemd `Type=simple`) — non concerné.

### Recovery semantics

| Scénario crash | Conséquence |
|----------------|-------------|
| Crash avant `write` | Aucun changement disque |
| Crash pendant `write` (avant `fsync`) | `.tmp` partiel, fichier final intact |
| Crash après `fsync`, avant `replace` | `.tmp` complet et valide, fichier final intact |
| Crash après `replace` | Nouveau fichier en place, `.tmp` déjà supprimé |

Conclusion : **le fichier final est TOUJOURS dans un état valide V4 (ou absent au boot initial)**. Un `.tmp` orphelin ne corrompt rien — il est ignoré au load.

---

## State files — détail par domaine

### 1. `recidivists.json` — Récidivistes

**Domaine :** compteur de bans répétés par IP, source de l'escalade `recidivist-escalation`.

**Shape `state` :**

```json
{
  "_cursor": "2026-05-24T07:33:39.000000+00:00",
  "192.175.111.252": {
    "count": 127,
    "last_seen": "2026-05-17T09:37:43Z"
  }
}
```

**Invariants :**
- Clés `^_` (underscore prefix) = méta (actuellement `_cursor` uniquement).
- Toutes les autres clés = IPv4 ou IPv6 valides (validé par `ipaddress.ip_address()`).
- `count` : int ≥ 1.
- `last_seen` : ISO-8601 UTC (peut être suffixé `Z` ou `+00:00` selon source — `_parse_dt` normalise).
- `_cursor` : dernier `ban.dt` traité, prévient re-comptage cross-restart.

**Lifecycle :**
- Reset compteur si `last_seen` > `RECIDIV_WINDOW = 7` jours.
- `purge_old_recidivists()` retire les entrées dont `last_seen` est antérieur au cutoff, garde `_cursor`.
- Save uniquement si `changed=True` (un nouveau ban dépasse cursor).

### 2. `abuseipdb-reported.json` — Dédup AbuseIPDB

**Domaine :** empêche les doubles envois à AbuseIPDB.

**Shape `state` :**

```json
{
  "91.90.123.179:10485512": "2026-05-17T01:06:08.767584+00:00",
  "modsec:160.79.106.123:2026-04-06": "2026-04-06T20:45:15.000000+00:00",
  "cf-waf:34.128.101.121:2026-05-17": "2026-05-17T02:46:10.686539+00:00",
  "waf:198.51.100.99:2026-04-09": "2026-04-09T21:31:15.000000+00:00"
}
```

**Invariants :**
- Clé = string composite, format dépend du caller :
  - `<ip>:<crowdsec_decision_id>` — `sync_abuseipdb` (origine CrowdSec)
  - `modsec:<ip>:<YYYY-MM-DD>` — `sync_modsec`
  - `waf:<ip>:<YYYY-MM-DD>` — `poll_cloudflare_waf` (legacy)
  - `cf-waf:<ip>:<YYYY-MM-DD>` — `poll_cloudflare_waf` (V3+)
- Valeur = timestamp ISO-8601 UTC d'envoi.
- **Aucune retention automatique** — le dict grossit indéfiniment. À surveiller (mémoire + I/O à chaque save).

### 3. `modsec-banned.json` — Bans ModSec

**Domaine :** IPs bannies pour anomaly score ModSec/Coraza.

**Shape `state` :**

```json
{
  "160.79.106.123": {
    "banned_at": "2026-04-06T20:45:14.827023+00:00",
    "score": 8,
    "uri": "/oauth-mcp/mcp"
  }
}
```

**Invariants :**
- Clé = IPv4 ou IPv6 valide.
- `banned_at` : ISO-8601 UTC.
- `score` : int (anomaly score ModSec/Coraza).
- `uri` : string (path complet de la requête déclenchante).

**Lifecycle :**
- Re-ban suppressed pendant `MODSEC_BAN_SECS = 7200s` (2h).
- Cleanup à chaque `sync_modsec` : entrées avec `banned_at` > 10800s (3h) sont retirées.
- Save uniquement si `new_bans > 0`.

**Format actuel sur prod (2026-05-24) :** V3 flat (pas d'envelope) — sera migré V4 au prochain ban ModSec.

### 4. `cidr-banned.json` — Bans CIDR /24

**Domaine :** blocs /24 bannis en agrégat suite à plusieurs IPs offensives.

**Shape `state` :**

```json
{
  "1.2.3.0/24": {
    "first_seen": "2026-05-20T10:00:00+00:00",
    "ip_count": 5,
    "scenarios": ["crowdsecurity/http-probing", "crowdsecurity/http-bf"]
  }
}
```

**Invariants :**
- Clé = CIDR /24 canonique (`ipaddress.ip_network(.../24, strict=False)`).
- IPv4 uniquement (la fonction `get_cidr24` filtre `ip.version != 4`).
- `first_seen` : ISO-8601 UTC.
- `ip_count` : int ≥ 1.
- `scenarios` : list[str], dédupliquée.

**Lifecycle :**
- Fenêtre d'agrégation : `CIDR_WINDOW * 24 = 168` heures.
- Cleanup : entrées dont `first_seen` est antérieur au cutoff.

### 5. `cf_waf_state.json` — Curseur WAF Cloudflare

**Domaine :** dernier événement Cloudflare WAF traité + buffer pending.

**Shape `state` (default à l'init) :**

```json
{
  "last_event_dt": null
}
```

**Shape `state` après poll :**

```json
{
  "last_processed": "2026-04-09T21:29:42Z",
  "pending_events": [
    {
      "ip": "198.51.100.99",
      "datetime": "2026-04-09T21:31:12Z",
      "action": "managed_challenge",
      "path": "/shell.php",
      "method": "GET"
    }
  ],
  "last_event_dt": "2026-04-09T21:31:12Z"
}
```

**Invariants :**
- `last_event_dt` : ISO-8601 ou `null` (jamais absent).
- `pending_events` : list de dicts avec keys fixes `ip`, `datetime`, `action`, `path`, `method`.
- `action` ∈ `{"block", "challenge", "managed_challenge", "jschallenge"}`.

### 6. `bouncer-abusecheck.json` — Cache AbuseIPDB du bouncer

**Domaine :** dédoublonnage des vérifs AbuseIPDB déclenchées par denials du bouncer.

**Shape `state` :**

```json
{
  "1.2.3.4": {
    "checked_at": "2026-05-23T12:00:00+00:00",
    "score": 87,
    "country": "RU",
    "isp": "Foo Telecom",
    "total_reports": 142,
    "method": "POST",
    "path": "/wp-login.php",
    "host": "arleo.eu"
  }
}
```

**Invariants :**
- Clé = IPv4 ou IPv6 valide.
- `checked_at` : ISO-8601 UTC.
- `score` : int 0..100.
- Autres champs : strings (ou `"-"` si absent dans l'event source).

**Lifecycle :**
- Skip si `checked_at` < `BOUNCER_CHECK_TTL = 86400s` (24h).
- Cleanup à 7 jours.
- Fichier peut être absent en prod tant qu'aucun denial bouncer n'a déclenché de check (cas observé 2026-05-24).

### 7. `cf-sync-wal.jsonl` — Write-Ahead Log

**Domaine :** trace append-only de toutes les intentions d'opération CF.

**Format :** JSONL (une entry JSON complète par ligne, `\n` séparateur).

**Shape par ligne :**

```json
{"id": 572, "op": "reconcile", "target": "full", "tag": "", "ts": "2026-05-24T10:23:39.045424+00:00", "attempt": 1, "dry_run": false}
```

**Invariants :**
- `id` : int monotone croissant. **Persisté à travers les restarts** via `_init_wal_seq()` qui compte les lignes existantes.
- `op` ∈ `{"add", "remove", "reconcile"}`.
- `target` : IP, CIDR, ou `"full"` pour reconcile.
- `tag` : tag de règle CF (`crowdsec-local-ban`, `modsec-ban`, `crowdsec-cidr-ban`) ou `""`.
- `ts` : ISO-8601 UTC.
- `attempt` : int ≥ 1 (tentative N de l'opération en cas de retry).
- `dry_run` : bool.

**Atomicité :**
- `open("a")` + `write()` + `flush()` + `fsync()` — chaque ligne est crash-durable avant retour.
- Append POSIX = atomique pour writes < PIPE_BUF (4096 bytes). Une entry WAL fait ~150 bytes : safe.

**Trim :**
- À chaque boot (`_wal_trim` dans `main()`), si > `max_lines = 10_000`, garde les 10 000 dernières et écrit le résultat via `mkstemp → fsync → replace`.
- **Aucune compaction par contenu** : le trim est purement quantitatif.

**Replay :**
- `cmd_wal_replay()` lit le WAL et applique les `add`/`remove` non confirmés contre l'état CF actuel.
- Idempotent par construction (ré-essayer un `add` déjà appliqué = no-op CF).

---

## Recovery — invariants au boot

`main()` charge les 6 fichiers dans cet ordre :

```python
cs_allowlist        = get_crowdsec_allowlist()
reported            = load_reported()
recidivists         = load_recidivists()
modsec_state        = load_modsec_state()
cidr_state          = load_cidr_state()
waf_state           = load_cf_waf_state()
bouncer_check_state = load_bouncer_check_state()
recidivists         = purge_old_recidivists(recidivists)
```

Invariants au boot :

1. **Aucun reset destructif sans backup** : tout fichier corrompu est renommé `.bak` avant fallback au default.
2. **Boot dégradé si CF inaccessible** : `_fetch_cf_rules()` au boot ; échec → mode dégradé, **AUCUNE écriture CF** tant que pas rétabli. Le fichier d'état CF (s'il existe) reste source de vérité.
3. **WAL n'est pas autoritaire** : `reconcile_state()` arbitre via CF API directement. Le WAL est audit trail + aide replay, pas distributed transaction log.
4. **`STATE_VERSION = 1` strictement** : un fichier avec `version: 2` au load → traité comme V3 flat (no version match), accepté tel quel. **À surveiller en cas de bump futur** — la migration doit être explicite.

---

## Contraintes pour le futur StateStore (F3)

Lors de l'extraction :

| Contrainte | Vérification |
|------------|--------------|
| Format binaire identique au save | Diff `sha256` du fichier avant/après |
| Migrate V3→V4 au save préservé | Golden test : write d'un load V3 → V4 envelope avec checksum valide |
| `os.replace` atomique préservé | Golden test : kill -9 entre write et fsync → fichier final intact |
| `.bak` créé sur corruption | Golden test : injecter sha256 invalide → `.bak` existe + default retourné |
| `_cursor` recidivists non purgé | Golden test : purge_old_recidivists conserve `_cursor` |
| WAL `id` monotone cross-restart | Golden test : restart simulé → `_init_wal_seq()` retourne count exact |
| WAL trim n'altère pas l'ordre | Golden test : trim 11 000 → 10 000 lignes, 10 000 dernières dans le même ordre |
| Boot dégradé n'écrit pas | Golden test : `_fetch_cf_rules` mock fail → save_X() jamais appelé pendant le cycle |

Tout helper StateStore qui ne passe pas ces golden tests **NE DOIT PAS** remplacer le code actuel.

---

## Politique de migration

Bumper `STATE_VERSION` UNIQUEMENT si :

1. Changement de schéma `state` non-rétrocompatible (nouveau champ obligatoire, type changé, clé renommée).
2. Code de migration dédié écrit ET testé.
3. `_load_json_state` étendu pour détecter et migrer.
4. Documentation `docs/state-format.md` mise à jour avec section dédiée à la nouvelle version.

Changements rétrocompatibles (nouveau champ optionnel, nouvelle valeur d'enum) :
- **Ne bumpent pas la version.**
- Doivent être tolérés au load (clé absente → default ou skip).
- Doivent être documentés ici.

---

## Méta

| Champ | Valeur |
|-------|--------|
| Source code | `crowdsec-cf-sync` v3.6.0 (commit `bae723d`) |
| Auteur doc | Brooks-Lint refactor — étape 2 (préparation StateStore) |
| Date | 2026-05-24 |
| Triage parent | `docs/architecture-triage.md` F3 (Knowledge Duplication) |
| Statut | Spec figée — toute extraction StateStore doit s'y conformer |
