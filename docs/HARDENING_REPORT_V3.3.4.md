# Hardening Report — V3.3.4 Pre-Release

**Date:** 2026-05-23  
**Scope:** crowdsec-cf-sync V3.3.x on NUC (OpenResty 1.29.2.4 / LuaJIT 2.1)  
**Status:** ✅ Ready for release validation — awaiting human sign-off

---

## 1. Architecture actuelle

```
Internet → Cloudflare (CDN/WAF) → OpenResty (NUC)
                                        │
                                ┌───────▼───────────────────────┐
                                │  HTTP level (init_by_lua_block) │
                                │   cs.Allow() — bouncer officiel │
                                │   sets $crowdsec_block_reason   │
                                └───────┬───────────────────────┘
                                        │ (if bouncer allows → continue)
                                ┌───────▼───────────────────────┐
                                │  Server level (access_by_lua)  │
                                │   crowdsec.access.check()      │
                                │   1. crowdsec_error_page guard  │
                                │   2. honeypot check             │
                                │   3. deadman / staleness        │
                                │   4. lookup.get_verdict(ip)     │
                                │   5. heuristics.score_request() │
                                │   6. mitigation.apply()         │
                                └───────┬───────────────────────┘
                                        │
                          ┌─────────────▼──────────────────────────┐
                          │ mitigation.apply(verdict, ip)           │
                          │  LEVEL_ALLOW   → pass through          │
                          │  LEVEL_RATELIMIT → 429 (leaky bucket)  │
                          │  LEVEL_TARPIT  → sleep + 429           │
                          │  LEVEL_CHALLENGE → 429 + header        │
                          │  LEVEL_CAPTCHA  → 403                  │
                          │  LEVEL_DENY score<96 → cs_reason=      │
                          │               "heuristic" + 403        │
                          │  LEVEL_DENY score≥96 → 444 (silent)   │
                          └─────────────────────────────────────────┘
```

**IPC Python ↔ Lua:**
```
Python daemon (crowdsec-cf-sync)
  ↓ writes /run/crowdsec-lua/bans.json  (every 60s, version-stamped)
Lua sync.lua (init_worker_by_lua_block timer)
  ↓ reads bans.json → cscf_verdicts shared dict
  ↓ writes /run/crowdsec-lua/events.jsonl
Python daemon reads events.jsonl → escalates to CrowdSec LAPI / Cloudflare
```

---

## 2. Flow exact — error_page 403

```
Request arrives
    │
    ▼
access_by_lua (crowdsec.access.check)
    │  ← if $crowdsec_error_page == "1": return immediately (loop guard)
    │
    ├─ LAPI/heuristic DENY, score<96 → ngx.exit(403)
    │       │
    │       ▼
    │   nginx error_page 403 → internal redirect /crowdsec-ban-page
    │       │
    │       ▼
    │   access_by_lua runs again for internal subrequest
    │       │  $crowdsec_error_page == "1" → return (NO re-scoring, NO metrics)
    │       ▼
    │   content_by_lua_block (crowdsec_ban_page.conf)
    │       → reads ban.template_str (upvalue, zero I/O)
    │       → substitutes __REF__, __TS__, __REASON__, __IP__
    │       → reads $crowdsec_block_reason (map var, overridden by mitigation.lua)
    │       → ngx.say(html) → 403 response with ban.html
    │
    ├─ Bouncer ban (AppSec/LAPI) → ban.lua.apply() writes body THEN ngx.exit(403)
    │   → error_page NOT triggered (body already set)
    │   → ban.html rendered directly by ban.lua
    │
    ├─ nginx deny all → 403 → error_page → /crowdsec-ban-page → ban.html
    │
    └─ DENY score≥96 → ngx.exit(444) — TCP close, error_page NOT triggered
```

**Key invariant:** The `internal` keyword on `/crowdsec-ban-page` makes it unreachable from the internet. The `$crowdsec_error_page` variable is set only in the rewrite phase of that internal location; external requests cannot set it. The guard in `access.lua` checks for `"1"` (string) — nginx variables default to `""`.

---

## 3. Flow exact — skip_heuristics (/ping)

```nginx
location = /ping {
    set $crowdsec_skip_heuristics 1;   # rewrite phase
    ...
}
```

```lua
-- access.lua
local skip_heuristics = ngx.var.crowdsec_skip_heuristics == "1"

if not skip_heuristics and heuristics.is_honeypot(uri) then ... end   -- 1. honeypot
-- 2. deadman: always runs
-- 3. lookup LAPI verdicts: always runs (source="p" bans still enforced)
if not stale and not mem_pressure and not skip_heuristics then         -- 4. heuristics
    heuristics.score_request(...)
end
if verdict and verdict.level > cs.LEVEL_ALLOW then
    if skip_heuristics and verdict.source == "h" then return end       -- no heuristic-only enforce
    mitigation.apply(verdict, ip)
end
```

**What skip_heuristics bypasses:** honeypot check, UA scoring, header scoring, path scoring, burst scoring, heuristic-only denial.  
**What skip_heuristics does NOT bypass:** LAPI-pushed bans (source="p"), AppSec bans (from bouncer at HTTP level).

---

## 4. cs_reason flow

```
$crowdsec_block_reason is a nginx map variable (always evaluates to "-")

override path 1: bouncer (cs.Allow() level) sets it to "appsec" or "bouncer"
override path 2: mitigation.apply() for source="h", score<96:
    ngx.var.crowdsec_block_reason = "heuristic"
    → logged as cs_reason=heuristic in access log
    → read by /crowdsec-ban-page: "Motif: heuristic" on ban page

remaining "-" cases → mapped to "block" in crowdsec_ban_page.conf
```

---

## 5. Lua path — clarification définitive

`/etc/openresty` est un **symlink système** vers `/usr/local/openresty/nginx/conf`.  
Il n'y a qu'**un seul répertoire physique** de modules Lua :

```
/usr/local/openresty/nginx/conf/lua/crowdsec/   ← répertoire physique
/etc/openresty/lua/crowdsec/                    ← alias via symlink système
```

Les deux chemins pointent vers les **mêmes fichiers** (pas de duplication, pas de risque de divergence). Le `lua_package_path` référence `/etc/openresty/lua/?.lua`, ce qui résout vers le chemin physique.

**Action requise :** aucune. La documentation antérieure mentionnant "dual path" ou "mirroring manuel" était erronée sur ce système. **Ne pas créer de symlink supplémentaire** (crée une boucle circulaire comme découvert lors de cette session).

---

## 6. Fixes appliqués dans cette session (V3.3.x → V3.3.4)

### Fix 1 — /ping bypass heuristique

**Fichier :** `nginx/sites-enabled/www.arleo.eu`  
**Changement :** `set $crowdsec_skip_heuristics 1;` dans la location `/ping`  
**Impact :** 0 faux positif sur les sondes BetterStack, LAPI bans toujours appliqués

### Fix 2 — Ban page universelle (error_page 403)

**Fichier créé :** `snippets/crowdsec_ban_page.conf`  
**Fichier modifié :** `lua/crowdsec/access.lua` (guard boucle `crowdsec_error_page`)  
**Fichier modifié :** `nginx/sites-enabled/www.arleo.eu` (include ban_page.conf)  
**Impact :** ban.html servi pour TOUS les 403 (heuristiques, nginx deny, AppSec)

### Fix 3 — Vector : origine CAPI + crowdsec engine

**Fichier :** `/etc/vector/vector.yaml`  
**Changement :** filtre étendu à `cscli || crowdsec || CAPI`  
**Impact :** décisions CAPI (100 entrées) et crowdsec engine (12 entrées) maintenant visibles dans BetterStack

### Fix 4 — cs_reason=heuristic

**Fichier :** `lua/crowdsec/mitigation.lua`  
**Changement :** `ngx.var.crowdsec_block_reason = "heuristic"` avant `ngx.exit(403)` pour `verdict.source == "h"`  
**Impact :** access log et ban page montrent "heuristic" au lieu de "-"

### Fix 5 — heuristics.lua patterns (cette session)

**Fichier :** `lua/crowdsec/heuristics.lua`  
**Bug :** 4 patterns `path:find("%.env", 1, true)` utilisaient le flag `true` (plain string) avec des patterns Lua (`%`-escaped) → recherchaient `%.env` littéral (avec `%`) → 0 correspondances en pratique  
**Fix :** retrait du flag `true` sur les 4 lignes concernées  
**Lignes corrigées :**
```lua
-- AVANT (cassé)
if path:find("%.env",    1, true) then return 60 end  -- cherchait "%.env" littéral
if path:find("%.git",    1, true) then return 40 end
if path:find("wp%-admin",1, true) then return 20 end
if path:find("%.php~",   1, true) then return 40 end

-- APRÈS (correct)
if path:find("%.env",    1) then return 60 end  -- Lua pattern: "%.env" = ".env"
if path:find("%.git",    1) then return 40 end  -- "%.git" = ".git"
if path:find("wp%-admin",1) then return 20 end  -- "wp%-admin" = "wp-admin"
if path:find("%.php~",   1) then return 40 end  -- "%.php~" = ".php~"
```

**Impact :** les chemins comme `/backup/.env`, `/.git/HEAD`, `/wp-admin/options.php`, `/backup.php~` sont maintenant correctement scorés (ancienne valeur : 0 pour tous).

---

## 7. Tableau de scoring — heuristics.lua

Résultats de la suite de tests (`scripts/regression-test.sh` section G), 25/25 :

| URI | Score attendu | Source | Résultat |
|-----|--------------|--------|---------|
| `/.env` | 60 | exact PATH_SCORES | ✅ |
| `/backup/.env` | 60 | substring `.env` | ✅ (était 0 avant fix) |
| `/backup/.env.bak` | 60 | substring `.env` | ✅ (était 0 avant fix) |
| `/.git` | 40 | exact PATH_SCORES | ✅ |
| `/.git/HEAD` | 40 | substring `.git` | ✅ (était 0 avant fix) |
| `/api/.git/config` | 40 | substring `.git` | ✅ (était 0 avant fix) |
| `/wp-login.php` | 25 | exact PATH_SCORES | ✅ |
| `/wp-admin` | 20 | exact PATH_SCORES | ✅ |
| `/wp-admin/options.php` | 20 | substring `wp-admin` | ✅ (était 0 avant fix) |
| `/not-wp-admin/foo` | 20 | substring `wp-admin` | ✅ (était 0 avant fix) |
| `/phpunit/tests/` | 60 | substring `phpunit` | ✅ |
| `/vendor/phpunit/src/test.php` | 60 | substring `phpunit` | ✅ |
| `/phpmyadmin/index.php` | 20 | substring `phpmyadmin` | ✅ |
| `/admin` | 10 | exact PATH_SCORES | ✅ |
| `/config.php` | 50 | exact PATH_SCORES | ✅ |
| `/shell` | 60 | exact PATH_SCORES | ✅ |
| `/cmd` | 50 | exact PATH_SCORES | ✅ |
| `/backup.php~` | 40 | substring `.php~` | ✅ (était 0 avant fix) |
| `/admin.php~` | 40 | substring `.php~` | ✅ (était 0 avant fix) |
| `/etc/passwd` | 50 | substring `passwd` | ✅ |
| `/shadow` | 50 | substring `shadow` | ✅ |
| `/` | 0 | no match | ✅ |
| `/api/v1/users` | 0 | no match | ✅ |
| `/robots.txt` | 0 | no match | ✅ |
| `/blog/post?page=2` | 0 | query string stripped | ✅ |

---

## 8. Tests de non-régression

**Suite :** `scripts/regression-test.sh` — 31 tests, exit 0 si tous passent.

| Section | Tests | Résultat |
|---------|-------|---------|
| A. /ping bypass | 6 (métriques, status, log) | ✅ 6/6 |
| B. Honeypot ban page | 4 (status, taille, contenu, no loop) | ✅ 4/4 |
| C. Heuristic ban page | 4 (status, taille, cs_reason, contenu) | ✅ 4/4 |
| D. Silent drop score≥96 | 1 (curl 000) | ✅ 1/1 |
| E. nginx deny ban page | 2 (status, taille) | ✅ 2/2 |
| F. Ban page headers | 6 (CSP, Cache-Control, Content-Type, etc.) | ✅ 6/6 |
| G. heuristics path scoring | 1 (25 cases Lua) | ✅ 25/25 |
| H. Vector | 2 (validate, running) | ✅ 2/2 |
| I. Shared dict / IPC | 2 (counters, sync freshness) | ✅ 2/2 |
| J. Monitoring endpoints | 3 (status JSON, metrics, WAN isolation) | ✅ 3/3 |

**Exécution :**
```bash
sudo -u jm -E bash scripts/regression-test.sh
```

---

## 9. Résultats de performance

**Conditions :** OpenResty 4 workers, 1 vhost actif, NUC local (localhost 127.0.0.1)

| Scénario | Requêtes | Temps total | Moy/req | dict change | Erreurs Lua |
|----------|----------|-------------|---------|-------------|-------------|
| Ban page (nginx deny → error_page) | 300 | 11.6s | 38ms | 0 octets | 0 |
| Normal path (access.lua, no score) | 300 | 13.4s | 44ms | 0 octets | 0 |
| 10 requêtes concurrentes ban page | 10 | 282ms | 28ms | 0 octets | 0 |

**Mémoire après 600 requêtes :**
- `cache_free_bytes` : 52 113 408 → 52 113 408 (**stable, zéro leak**)
- `pressure_active` : false tout au long
- Workers RSS : 17–22 MB (4 workers) — stable

**Note :** le latency overhead est principalement TLS (loopback). En production derrière Cloudflare, le délai TLS est absent côté nginx (terminaison CF + HTTP interne).

---

## 10. Audit des locations spéciales

| Location | Mécanisme | access.lua ? | error_page ? | Risque |
|----------|-----------|:------------:|:------------:|--------|
| `= /ping` | auth_basic + alias | ✅ (skip_heuristics=1) | ✅ (mais skip guard) | ✅ Correct |
| `^~ /api/mcp` | return 444 | ✅ (heuristic scoring) | ✗ (444 ne trigger pas) | ✅ Correct |
| `= /csp-report` | content_by_lua → 204 | ✅ | ✗ (204, pas 403) | ✅ Correct |
| `= /nginx_status` | allow LAN / deny all | ✅ (scoring si LAN) | ✅ (deny → ban.html) | ✅ Correct |
| `^~ /.well-known/` | deny all | ✅ | ✅ ban.html | ✅ Correct |
| `= /.well-known/security.txt` | alias | ✅ | ✅ si 403 | ✅ Correct |
| `~ /\.ht` | deny all | ✅ | ✅ ban.html | ✅ Correct |
| `~ /\.git` | deny all | ✅ (git path scores +40) | ✅ ban.html | ✅ Correct |
| `= /crowdsec-ban-page` | internal, content_by_lua | ✅ (guard exit si error_page=1) | ✗ (content handler) | ✅ Correct |

**Bypass involontaire :** aucun trouvé. Les locations `internal` ne sont pas accessibles depuis l'extérieur (nginx les rejette avec 404 pour les requêtes directes).

**Interaction AppSec + error_page :** AppSec écrit le corps HTML avant `ngx.exit(403)`. Quand le corps est déjà écrit, nginx ne déclenche pas `error_page`. Comportement correct et voulu.

---

## 11. Ce qui N'A PAS été modifié — et pourquoi

| Élément | Raison |
|---------|--------|
| **LEVEL_CAPTCHA (level 4) cs_reason** | Aucun hit en production. Fix demandé était "MINIMAL" — limité à LEVEL_DENY. Dette technique légère. |
| **score_ua BAD_UA loop (`lc:find(frag, 1, true)`)** | Ces strings n'ont pas de caractères spéciaux Lua → `true` et sans `true` sont équivalents. Pas de bug ici. |
| **score≥96 → exit(444) sans cs_reason** | Intentionnel : 444 ne génère pas de corps, pas de ban page, pas de log entry. Pas de raison à afficher. |
| **sync.lua : goto continue_bans** | Valide LuaJIT (OpenResty). Le `luac` 5.1 système le rejette (false positive). Ne pas modifier. |
| **Dual path documentation** | La documentation `runtime-layout.md` mentionne "mirroring" — doit être mise à jour (voir section 5). |
| **lua_package_path** | Déjà correct, pointe vers `/etc/openresty/lua/?.lua`. Aucun changement nécessaire. |
| **install-v3.sh / setup-lua.sh** | Corrects pour ce système. Le setup-lua.sh ne copie qu'une fois (vers `/etc/openresty/lua/crowdsec/`). |

---

## 12. Risques restants

| Risque | Niveau | Mitigation |
|--------|--------|-----------|
| LEVEL_CAPTCHA sans cs_reason | Négligeable | Aucun hit actuel |
| `luac` 5.1 rejette sync.lua (goto) | Cosmétique | Utiliser `openresty -t` pour valider, pas `luac` |
| Documentation "dual path" obsolète | Faible | Mettre à jour runtime-layout.md (section 5) |
| PATH_SCORES `["/.env"]` = dead code | Cosmétique | Honeypot check est prioritaire, l'entrée n'est jamais atteinte pour `/.env` exact |

---

## 13. Dette technique restante

1. **`runtime-layout.md`** : supprimer la mention "On dual-path installs, files are mirrored" pour ce système. Documenter que `/etc/openresty` est un symlink vers `/usr/local/openresty/nginx/conf`.

2. **`LEVEL_CAPTCHA` cs_reason** : ajouter `ngx.var.crowdsec_block_reason = "captcha"` avant `ngx.exit(ngx.HTTP_FORBIDDEN)` dans le branch captcha de `mitigation.lua` — une ligne, zéro risque.

3. **`PATH_SCORES["/.env"] = 60`** : dead code (honeypot check est prioritaire). Peut être retiré pour clarté, mais sans impact fonctionnel.

4. **Validation `luac`** dans `release-v3.sh` : ajouter une note ou remplacer `luac -p` par `openresty -t` pour éviter les faux positifs sur `goto`.

---

## 14. Checksums des fichiers modifiés

| Fichier | MD5 déployé | Note |
|---------|-------------|------|
| `/etc/openresty/lua/crowdsec/access.lua` | `42fa642f9f4919cd8b3ad43664842613` | Guard boucle error_page + skip_heuristics |
| `/etc/openresty/lua/crowdsec/heuristics.lua` | `88fd07a53c397893959c63ea6b9aef48` | Fix 4 patterns cassés |
| `/etc/openresty/lua/crowdsec/mitigation.lua` | `912eb675f010a87b6642d3870b46a81b` | cs_reason=heuristic |
| `/usr/local/openresty/nginx/conf/snippets/crowdsec_ban_page.conf` | `78420c718b202b4e77eb817faebfc751` | Nouveau fichier |
| `/etc/nginx/sites-enabled/www.arleo.eu` | — | skip_heuristics /ping + include ban_page.conf |
| `/etc/vector/vector.yaml` | — | Filtre origin étendu |

Tous les fichiers Lua du repo (`/tmp/crowdsec-cf-sync/lua/crowdsec/`) sont en synchronisation avec le déploiement (checksums vérifiés).

---

## 15. Check-list pré-release

- [x] `python3 -m py_compile crowdsec-cf-sync` — syntax OK
- [x] `openresty -t` — config OK
- [x] `sudo -u jm -E bash scripts/regression-test.sh` — **31/31 PASS**
- [x] `vector validate /etc/vector/vector.yaml` — OK
- [x] `curl http://127.0.0.1:8091/crowdsec-status` — JSON valide, sync frais
- [x] Performance : 600 requêtes, 0 memory leak, 0 erreur Lua
- [x] Checksums repo = checksums déployés (9 fichiers Lua)
- [ ] **Tag GPG signé** : `sudo -u jm -E bash scripts/release-v3.sh 3.3.4`
- [ ] **Validation humaine finale** : vérifier WAN réel, accès BetterStack, logs Vector

---

*Rapport généré le 2026-05-23 — session hardening post-V3.3.3.*
