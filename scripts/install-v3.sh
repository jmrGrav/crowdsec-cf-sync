#!/bin/bash
# install-v3.sh — CrowdSec-CF-Sync V3 installer
#
# Auto-detects the environment before touching anything.
# Never supposes a path, a user, or a directive.
# Every decision is preceded by a real verification.
#
# Modes:
#   --audit      Show conflicts and what would be done, make no changes
#   --dry-run    Same as --audit (alias)
#   --yes        Skip interactive confirmation (for automation)
#   --rollback   Restore most recent backup (or specify timestamp)
#
# Usage:
#   sudo bash scripts/install-v3.sh          # detect + confirm + install
#   sudo bash scripts/install-v3.sh --audit  # inspect only
#   sudo bash scripts/install-v3.sh --yes    # non-interactive install
#   sudo bash scripts/install-v3.sh --rollback 20260522_061000

set -euo pipefail
IFS=$'\n\t'

# ── Constants ──────────────────────────────────────────────────────────────────
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BACKUP_BASE="/var/backups/crowdsec-cf-sync"
INSTALL_LOG="/var/log/crowdsec/crowdsec-cf-sync-install.log"
LUA_SYNC_DIR="/run/crowdsec-lua"
VERSION="3.3.0"

# ── Argument parsing ───────────────────────────────────────────────────────────
MODE="install"          # install | audit | rollback
YES=false
ROLLBACK_TS=""

for arg in "$@"; do
    case "$arg" in
        --audit|--dry-run) MODE="audit" ;;
        --yes|-y)          YES=true ;;
        --rollback)        MODE="rollback" ;;
        --rollback=*)      MODE="rollback"; ROLLBACK_TS="${arg#--rollback=}" ;;
        *)
            if [ "$MODE" = "rollback" ] && [ -z "$ROLLBACK_TS" ]; then
                ROLLBACK_TS="$arg"
            fi
            ;;
    esac
done

# ── Colours ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YLW='\033[1;33m'; GRN='\033[0;32m'
BLU='\033[0;34m'; CYN='\033[0;36m'; RST='\033[0m'; BLD='\033[1m'

info()  { echo -e "${BLU}[INFO]${RST}  $*"; }
ok()    { echo -e "${GRN}[OK]${RST}    $*"; }
warn()  { echo -e "${YLW}[WARN]${RST}  $*"; }
err()   { echo -e "${RED}[ERROR]${RST} $*" >&2; }
hdr()   { echo -e "\n${BLD}${CYN}── $* ──${RST}"; }
die()   { err "$*"; exit 1; }

log_to_file() {
    mkdir -p "$(dirname "$INSTALL_LOG")" 2>/dev/null || true
    echo "[$(date -u +%FT%TZ)] $*" >> "$INSTALL_LOG" 2>/dev/null || true
}

# ── Rollback ───────────────────────────────────────────────────────────────────
do_rollback() {
    hdr "Rollback"
    if [ -z "$ROLLBACK_TS" ]; then
        # Use most recent backup
        ROLLBACK_TS=$(ls -1 "$BACKUP_BASE" 2>/dev/null | sort -r | head -1)
        [ -z "$ROLLBACK_TS" ] && die "No backups found in $BACKUP_BASE"
    fi
    local backup_dir="$BACKUP_BASE/$ROLLBACK_TS"
    [ -d "$backup_dir" ] || die "Backup not found: $backup_dir"

    info "Restoring from: $backup_dir"
    if [ -f "$backup_dir/MANIFEST.txt" ]; then
        echo; cat "$backup_dir/MANIFEST.txt"; echo
    fi

    # Restore each file listed in manifest
    while IFS= read -r line; do
        local hash file
        hash=$(echo "$line" | awk '{print $1}')
        file=$(echo "$line" | awk '{print $2}')
        [ -z "$file" ] && continue
        [ ! -f "$backup_dir/$(basename "$file")" ] && continue
        cp "$backup_dir/$(basename "$file")" "$file"
        ok "Restored: $file"
    done < <(grep -v "^#\|^Backup\|^Hostname\|^Generated\|^$" "$backup_dir/MANIFEST.txt" 2>/dev/null || true)

    info "Reloading nginx..."
    if "$NGINX_BIN" -t 2>/dev/null; then
        systemctl reload "$NGINX_SERVICE" && ok "Reload OK"
    else
        warn "Config test failed after rollback — manual intervention required"
    fi
    log_to_file "ROLLBACK completed from $ROLLBACK_TS"
}

# ── Detection ──────────────────────────────────────────────────────────────────
detect_environment() {
    hdr "Environment detection"

    # ── nginx binary ──────────────────────────────────────────────────────────
    if command -v openresty >/dev/null 2>&1; then
        NGINX_BIN="openresty"
        NGINX_SERVICE="openresty"
    elif command -v nginx >/dev/null 2>&1; then
        NGINX_BIN="nginx"
        NGINX_SERVICE="nginx"
    else
        die "Neither 'openresty' nor 'nginx' found in PATH"
    fi
    ok "nginx binary: $NGINX_BIN (service: $NGINX_SERVICE)"

    # ── Main config file (follow the binary's -t output) ─────────────────────
    NGINX_MAIN_CONF=$(sudo "$NGINX_BIN" -t 2>&1 | grep "configuration file" | awk '{print $NF}' | head -1)
    [ -z "$NGINX_MAIN_CONF" ] && NGINX_MAIN_CONF="/usr/local/openresty/nginx/conf/nginx.conf"
    NGINX_CONF_DIR=$(dirname "$NGINX_MAIN_CONF")
    ok "Main config: $NGINX_MAIN_CONF"

    # ── Full compiled config dump — the ground truth ──────────────────────────
    NGINX_DUMP=$(sudo "$NGINX_BIN" -T 2>/dev/null) || {
        warn "nginx -T failed — attempting with explicit conf"
        NGINX_DUMP=$(sudo "$NGINX_BIN" -T -c "$NGINX_MAIN_CONF" 2>/dev/null) || NGINX_DUMP=""
    }

    # ── Detect conf.d directory from actual includes ──────────────────────────
    CONF_D_DIR=$(echo "$NGINX_DUMP" | grep -o 'include [^;]*conf\.d/\*' | head -1 | \
        sed 's/include //; s|/\*.*||' | xargs realpath 2>/dev/null || true)
    if [ -z "$CONF_D_DIR" ]; then
        # Fallback: common paths, verify existence
        for candidate in \
            /etc/openresty/conf.d \
            /etc/nginx/conf.d \
            /usr/local/openresty/nginx/conf/conf.d
        do
            if [ -d "$candidate" ]; then
                CONF_D_DIR=$(realpath "$candidate")
                break
            fi
        done
    fi
    [ -z "$CONF_D_DIR" ] && die "Cannot detect conf.d directory"
    ok "conf.d: $CONF_D_DIR"

    # ── Detect snippets directory ─────────────────────────────────────────────
    for candidate in /etc/nginx/snippets /etc/openresty/snippets; do
        if [ -d "$candidate" ]; then
            SNIPPETS_DIR="$candidate"
            break
        fi
    done
    SNIPPETS_DIR="${SNIPPETS_DIR:-/etc/nginx/snippets}"
    ok "Snippets dir: $SNIPPETS_DIR"

    # ── Detect nginx runtime user ─────────────────────────────────────────────
    NGINX_USER=$(echo "$NGINX_DUMP" | grep -m1 '^user ' | awk '{print $2}' | tr -d ';' || true)
    if [ -z "$NGINX_USER" ]; then
        # Try the binary's compiled-in default
        NGINX_USER=$(sudo "$NGINX_BIN" -V 2>&1 | grep -o 'user=[^[:space:]]*' | cut -d= -f2 || true)
        NGINX_USER="${NGINX_USER:-www-data}"
    fi
    ok "nginx user: $NGINX_USER"

    # ── Detect Lua module directory ───────────────────────────────────────────
    LUA_MODULE_DIR=""
    for candidate in \
        /etc/openresty/lua \
        /etc/nginx/lua \
        /usr/local/openresty/lua
    do
        if [ -d "$candidate" ]; then
            LUA_MODULE_DIR="$candidate"
            break
        fi
    done
    # If none exist yet, use the conventional path for this system
    LUA_MODULE_DIR="${LUA_MODULE_DIR:-/etc/openresty/lua}"
    ok "Lua modules: $LUA_MODULE_DIR"

    # ── Detect official CrowdSec OpenResty bouncer ────────────────────────────
    OFFICIAL_BOUNCER_CONF=""
    for candidate in \
        "$CONF_D_DIR/crowdsec_openresty.conf" \
        "/etc/nginx/conf.d/crowdsec_openresty.conf" \
        "/etc/openresty/conf.d/crowdsec_openresty.conf"
    do
        if [ -f "$candidate" ]; then
            OFFICIAL_BOUNCER_CONF=$(realpath "$candidate")
            break
        fi
    done

    if [ -n "$OFFICIAL_BOUNCER_CONF" ]; then
        ok "Official CrowdSec bouncer: $OFFICIAL_BOUNCER_CONF"
        HAS_OFFICIAL_BOUNCER=true
    else
        info "No official CrowdSec OpenResty bouncer detected (standalone mode)"
        HAS_OFFICIAL_BOUNCER=false
    fi

    # ── Detect existing Lua singleton directives (from compiled dump) ─────────
    HAS_LUA_PACKAGE_PATH=false
    HAS_INIT_BY_LUA=false
    HAS_INIT_WORKER_BY_LUA=false
    HAS_ACCESS_BY_LUA=false

    echo "$NGINX_DUMP" | grep -q '^[[:space:]]*lua_package_path'      && HAS_LUA_PACKAGE_PATH=true
    echo "$NGINX_DUMP" | grep -q '^[[:space:]]*init_by_lua_block'     && HAS_INIT_BY_LUA=true
    echo "$NGINX_DUMP" | grep -q '^[[:space:]]*init_worker_by_lua'    && HAS_INIT_WORKER_BY_LUA=true
    echo "$NGINX_DUMP" | grep -q '^[[:space:]]*access_by_lua_block'   && HAS_ACCESS_BY_LUA=true

    info "Existing Lua directives: package_path=$HAS_LUA_PACKAGE_PATH init_by_lua=$HAS_INIT_BY_LUA init_worker=$HAS_INIT_WORKER_BY_LUA access_by_lua=$HAS_ACCESS_BY_LUA"

    # ── Detect existing shared dicts (name → size) ────────────────────────────
    mapfile -t EXISTING_DICT_NAMES < <(
        echo "$NGINX_DUMP" | grep -o 'lua_shared_dict [^[:space:]]*' | awk '{print $2}' | sort -u
    )
    info "Existing lua_shared_dicts: ${EXISTING_DICT_NAMES[*]:-none}"

    # ── Detect our previously generated conf ──────────────────────────────────
    GENERATED_CONF="$CONF_D_DIR/crowdsec_cf_sync_generated.conf"
    HAS_GENERATED_CONF=false
    [ -f "$GENERATED_CONF" ] && HAS_GENERATED_CONF=true

    # ── Detect systemd unit ───────────────────────────────────────────────────
    SYSTEMD_UNIT="/etc/systemd/system/crowdsec-cf-sync.service"
    HAS_SYSTEMD=false
    [ -f "$SYSTEMD_UNIT" ] && HAS_SYSTEMD=true
}

# ── Audit ──────────────────────────────────────────────────────────────────────
do_audit() {
    hdr "Audit — conflicts and planned actions"
    local issues=0

    # Dict collisions
    for dict in cscf_verdicts crowdsec_metrics crowdsec_state; do
        if printf '%s\n' "${EXISTING_DICT_NAMES[@]}" | grep -qx "$dict"; then
            ok "lua_shared_dict $dict: already declared"
        else
            info "lua_shared_dict $dict: will be added to generated conf"
        fi
    done
    # Collision with official bouncer dict name
    if printf '%s\n' "${EXISTING_DICT_NAMES[@]}" | grep -qx "crowdsec_cache"; then
        ok "crowdsec_cache dict detected (official bouncer) — our dict is named 'cscf_verdicts' (no collision)"
    fi

    # Lua singleton directives
    echo
    if $HAS_INIT_BY_LUA && $HAS_OFFICIAL_BOUNCER; then
        warn "CONFLICT: init_by_lua_block exists in official bouncer conf"
        info "  → Will inject our requires into $OFFICIAL_BOUNCER_CONF (backup first)"
        info "  → crowdsec_cf_sync_generated.conf will NOT declare init_by_lua_block"
        ((issues++)) || true
    elif $HAS_INIT_BY_LUA && ! $HAS_OFFICIAL_BOUNCER; then
        warn "init_by_lua_block already exists but no official bouncer detected"
        info "  → Will NOT add another one — check your config manually"
        ((issues++)) || true
    else
        info "init_by_lua_block: will be added to generated conf (standalone)"
    fi

    if $HAS_LUA_PACKAGE_PATH && $HAS_OFFICIAL_BOUNCER; then
        warn "CONFLICT: lua_package_path exists in official bouncer"
        info "  → Will extend it with $LUA_MODULE_DIR/?.lua (idempotent)"
        ((issues++)) || true
    fi

    if $HAS_ACCESS_BY_LUA; then
        warn "access_by_lua_block detected at http{} level"
        info "  → crowdsec_access.conf is a per-vhost snippet only — goes to $SNIPPETS_DIR"
        info "  → Will NOT auto-include it (avoids http-level conflict)"
        ((issues++)) || true
    fi

    # Permissions
    echo
    if [ -f "$LUA_SYNC_DIR/bans.json" ]; then
        local perms
        perms=$(stat -c '%a' "$LUA_SYNC_DIR/bans.json" 2>/dev/null || echo "?")
        if [ "$perms" = "644" ]; then
            ok "bans.json permissions: $perms (OK — readable by $NGINX_USER)"
        else
            warn "bans.json permissions: $perms (expected 644 — $NGINX_USER may not read it)"
            ((issues++)) || true
        fi
    else
        info "bans.json: not yet created (Python daemon writes it on first cycle)"
    fi

    if [ -f "$LUA_SYNC_DIR/events.jsonl" ]; then
        local owner
        owner=$(stat -c '%U:%G' "$LUA_SYNC_DIR/events.jsonl" 2>/dev/null || echo "?")
        info "events.jsonl owner: $owner"
    fi

    # Existing generated conf
    echo
    if $HAS_GENERATED_CONF; then
        info "Previously generated conf found: $GENERATED_CONF"
        info "  → Will regenerate (backup created first)"
    else
        info "Generated conf: will create $GENERATED_CONF"
    fi

    # Systemd
    echo
    if $HAS_SYSTEMD; then
        ok "Systemd unit: $SYSTEMD_UNIT (exists)"
    else
        info "Systemd unit: will be installed from $REPO_DIR/systemd/crowdsec-cf-sync.service"
    fi

    # Snippet vhost status
    echo
    local vhost_count missing_count
    vhost_count=0; missing_count=0
    for vhost in /etc/nginx/sites-enabled/*; do
        [ -f "$vhost" ] || continue
        ((vhost_count++)) || true
        if ! grep -q "crowdsec_access" "$vhost" 2>/dev/null; then
            info "Vhost missing crowdsec_access include: $(basename "$vhost")"
            ((missing_count++)) || true
        fi
    done
    if [ "$missing_count" -gt 0 ]; then
        warn "$missing_count/$vhost_count vhosts missing 'include $SNIPPETS_DIR/crowdsec_access.conf;'"
        info "  → Install will NOT auto-add this (use --add-vhosts to activate per-request protection)"
    else
        ok "All $vhost_count vhosts include crowdsec_access snippet"
    fi

    echo
    if [ "$issues" -gt 0 ]; then
        warn "Detected $issues conflict(s) — all are handled automatically"
    else
        ok "No blocking conflicts detected"
    fi
    info "Total: $issues items require merging/patching"
}

# ── Backup ─────────────────────────────────────────────────────────────────────
do_backup() {
    local ts
    ts=$(date +%Y%m%d_%H%M%S)
    BACKUP_DIR="$BACKUP_BASE/$ts"
    mkdir -p "$BACKUP_DIR"

    local manifest="$BACKUP_DIR/MANIFEST.txt"
    {
        echo "# crowdsec-cf-sync installation backup"
        echo "# Backup-TS: $ts"
        echo "# Hostname: $(hostname)"
        echo "# Generated-by: install-v3.sh $VERSION"
        echo "# nginx-bin: $NGINX_BIN"
        echo "# official-bouncer: ${OFFICIAL_BOUNCER_CONF:-none}"
        echo ""
    } > "$manifest"

    local backed=0
    _backup_file() {
        local f="$1"
        [ -f "$f" ] || return 0
        cp "$f" "$BACKUP_DIR/$(basename "$f")"
        sha256sum "$f" >> "$manifest"
        ((backed++)) || true
        info "Backed up: $f"
    }

    _backup_file "$GENERATED_CONF"
    _backup_file "${OFFICIAL_BOUNCER_CONF:-}"
    _backup_file "$CONF_D_DIR/crowdsec_shared_dicts.conf"
    _backup_file "$CONF_D_DIR/crowdsec_init.conf"
    _backup_file "$SYSTEMD_UNIT"

    ok "Backup created: $BACKUP_DIR ($backed file(s))"
    log_to_file "BACKUP created at $BACKUP_DIR"

    # Keep last 10 backups only
    local count
    count=$(ls -1 "$BACKUP_BASE" | wc -l)
    if [ "$count" -gt 10 ]; then
        ls -1 "$BACKUP_BASE" | sort | head -n $((count - 10)) | \
            while read -r old; do rm -rf "$BACKUP_BASE/$old"; done
        info "Pruned old backups (kept 10)"
    fi
}

# ── Generate conf ──────────────────────────────────────────────────────────────
generate_conf() {
    hdr "Generating $GENERATED_CONF"

    # Build header
    local gen_ts gen_hostname
    gen_ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    gen_hostname=$(hostname)

    # Detect which dicts are NOT yet declared (skip if already present from bouncer)
    local declare_verdicts=true declare_metrics=true declare_state=true
    printf '%s\n' "${EXISTING_DICT_NAMES[@]}" | grep -qx "cscf_verdicts"     && declare_verdicts=false
    printf '%s\n' "${EXISTING_DICT_NAMES[@]}" | grep -qx "crowdsec_metrics"  && declare_metrics=false
    printf '%s\n' "${EXISTING_DICT_NAMES[@]}" | grep -qx "crowdsec_state"    && declare_state=false

    {
        cat <<HEADER
# crowdsec_cf_sync_generated.conf
# GENERATED — do not edit manually. Regenerate with: scripts/install-v3.sh
# Generated: ${gen_ts}
# Hostname:  ${gen_hostname}
# Installer: install-v3.sh ${VERSION}
# Mode:      $( $HAS_OFFICIAL_BOUNCER && echo "coexistence (official bouncer present)" || echo "standalone" )
#
# This file is safe to include in the nginx http {} block.
# Only lua_shared_dict declarations appear here — no singleton directives
# (lua_package_path / init_by_lua_block / init_worker_by_lua_block) that
# would conflict with the official CrowdSec OpenResty bouncer.

HEADER

        echo "# ── Shared dict declarations ──────────────────────────────────────────────────"
        $declare_verdicts && echo "lua_shared_dict cscf_verdicts    50m;  # per-IP and per-CIDR verdicts"
        $declare_metrics  && echo "lua_shared_dict crowdsec_metrics 10m;  # atomic counters, Prometheus export"
        $declare_state    && echo "lua_shared_dict crowdsec_state    5m;  # sync metadata, tarpit semaphore"

        if ! $declare_verdicts || ! $declare_metrics || ! $declare_state; then
            echo ""
            echo "# NOTE: Some dicts were already declared elsewhere (skipped above):"
            ! $declare_verdicts && echo "#   cscf_verdicts    — already in loaded config"
            ! $declare_metrics  && echo "#   crowdsec_metrics — already in loaded config"
            ! $declare_state    && echo "#   crowdsec_state   — already in loaded config"
        fi

        if ! $HAS_OFFICIAL_BOUNCER; then
            cat <<STANDALONE

# ── Standalone mode: no official CrowdSec bouncer present ─────────────────────
# Declaring singleton Lua directives here. If you later install the official
# bouncer, re-run install-v3.sh — it will merge these into the bouncer conf
# and remove them from this file.

lua_package_path "${LUA_MODULE_DIR}/?.lua;;";

init_by_lua_block {
    -- CrowdSec custom Lua layer (crowdsec-cf-sync ${VERSION})
    local ok, err = pcall(function()
        require "crowdsec.init"
        require "crowdsec.lookup"
        require "crowdsec.heuristics"
        require "crowdsec.mitigation"
        require "crowdsec.tarpit"
        require "crowdsec.sync"
        require "crowdsec.events"
        require "crowdsec.access"
        require "crowdsec.metrics"
    end)
    if not ok then
        ngx.log(ngx.ERR, "[crowdsec-cf-sync] init failed (fail-open): ", err)
    end
}

init_worker_by_lua_block {
    local ok, err = pcall(function()
        require("crowdsec.sync").start()
    end)
    if not ok then
        ngx.log(ngx.ERR, "[crowdsec-cf-sync] worker init failed: ", err)
    end
}
STANDALONE
        else
            cat <<BOUNCER_NOTE

# ── Coexistence mode: official CrowdSec bouncer present ───────────────────────
# The following directives were merged into: ${OFFICIAL_BOUNCER_CONF}
#   - lua_package_path (extended, not replaced)
#   - init_by_lua_block (our requires appended)
#   - init_worker_by_lua_block (crowdsec.sync.start() appended)
# See install log: ${INSTALL_LOG}
BOUNCER_NOTE
        fi
    } > "$GENERATED_CONF"

    chmod 644 "$GENERATED_CONF"
    ok "Generated: $GENERATED_CONF"
}

# ── Merge into official bouncer conf ───────────────────────────────────────────
merge_official_bouncer() {
    [ "$HAS_OFFICIAL_BOUNCER" = "true" ] || return 0
    hdr "Merging into official bouncer: $OFFICIAL_BOUNCER_CONF"

    python3 - "$OFFICIAL_BOUNCER_CONF" "$LUA_MODULE_DIR" "$VERSION" <<'PYEOF'
import re, sys, textwrap

conf_path    = sys.argv[1]
lua_mod_dir  = sys.argv[2]
version      = sys.argv[3]

with open(conf_path) as f:
    conf = f.read()

changed = False

# ── 1. lua_package_path: extend if our path is missing ────────────────────────
our_path = f"{lua_mod_dir}/?.lua"
if our_path not in conf:
    conf = re.sub(
        r"(lua_package_path\s+')([^']*)(;;'\s*;)",
        lambda m: m.group(1) + m.group(2).rstrip(';') + f";{our_path};;" + m.group(3)[2:],
        conf, count=1
    )
    # Simpler fallback pattern (no trailing ;; in value)
    if our_path not in conf:
        conf = re.sub(
            r"(lua_package_path\s+')(.*?)(';)",
            lambda m: m.group(1) + m.group(2).rstrip(';') + f";{our_path};;" + "';",
            conf, count=1
        )
    changed = True
    print(f"  → lua_package_path extended with {our_path}")
else:
    print(f"  → lua_package_path already contains our path (skip)")

# ── 2. init_by_lua_block: append our requires ─────────────────────────────────
INIT_MARKER = "crowdsec-cf-sync init"
if INIT_MARKER not in conf:
    INIT_INJECT = textwrap.dedent(f"""\
        -- crowdsec-cf-sync {version} — fail-open init
        local _cs_ok, _cs_err = pcall(function()
            require "crowdsec.init"
            require "crowdsec.lookup"
            require "crowdsec.heuristics"
            require "crowdsec.mitigation"
            require "crowdsec.tarpit"
            require "crowdsec.sync"
            require "crowdsec.events"
            require "crowdsec.access"
            require "crowdsec.metrics"
        end)
        if not _cs_ok then
            ngx.log(ngx.ERR, "[crowdsec-cf-sync] init failed (fail-open): ", _cs_err)
        end""")
    conf = re.sub(
        r'(init_by_lua_block\s*\{)(.*?)(\n\})',
        lambda m: (m.group(1) + m.group(2).rstrip()
                   + '\n\n    -- ' + INIT_MARKER + '\n'
                   + textwrap.indent(INIT_INJECT, '    ')
                   + m.group(3)),
        conf, count=1, flags=re.DOTALL
    )
    changed = True
    print("  → init_by_lua_block: our requires appended")
else:
    print("  → init_by_lua_block already contains our code (skip)")

# ── 3. init_worker_by_lua_block: append sync.start() ─────────────────────────
WORKER_MARKER = "crowdsec-cf-sync sync"
if WORKER_MARKER not in conf:
    WORKER_INJECT = textwrap.dedent(f"""\
        -- crowdsec-cf-sync {version}
        local _cw_ok, _cw_err = pcall(function()
            require("crowdsec.sync").start()
        end)
        if not _cw_ok then
            ngx.log(ngx.ERR, "[crowdsec-cf-sync] worker init failed: ", _cw_err)
        end""")
    conf = re.sub(
        r'(init_worker_by_lua_block\s*\{)(.*?)(\n\})',
        lambda m: (m.group(1) + m.group(2).rstrip()
                   + '\n\n    -- ' + WORKER_MARKER + '\n'
                   + textwrap.indent(WORKER_INJECT, '    ')
                   + m.group(3)),
        conf, count=1, flags=re.DOTALL
    )
    changed = True
    print("  → init_worker_by_lua_block: sync.start() appended")
else:
    print("  → init_worker_by_lua_block already contains our code (skip)")

if changed:
    with open(conf_path, 'w') as f:
        f.write(conf)
    print(f"  → Wrote patched config: {conf_path}")
else:
    print("  → No changes needed to official bouncer conf")
PYEOF
}

# ── Install Lua modules ────────────────────────────────────────────────────────
install_lua_modules() {
    hdr "Installing Lua modules → $LUA_MODULE_DIR/crowdsec/"
    mkdir -p "$LUA_MODULE_DIR/crowdsec"
    cp -v "$REPO_DIR/lua/crowdsec/"*.lua "$LUA_MODULE_DIR/crowdsec/"
    chmod 644 "$LUA_MODULE_DIR/crowdsec/"*.lua
    ok "Lua modules installed"
}

# ── Install snippets ───────────────────────────────────────────────────────────
install_snippets() {
    hdr "Installing per-vhost snippets → $SNIPPETS_DIR/"
    mkdir -p "$SNIPPETS_DIR"
    cp -v "$REPO_DIR/nginx/crowdsec_access.conf" "$SNIPPETS_DIR/"
    cp -v "$REPO_DIR/nginx/crowdsec_status.conf" "$SNIPPETS_DIR/"
    chmod 644 "$SNIPPETS_DIR/crowdsec_access.conf" "$SNIPPETS_DIR/crowdsec_status.conf"
    ok "Snippets installed (NOT auto-included in vhosts)"
    info "To protect a vhost, add:"
    info "  include $SNIPPETS_DIR/crowdsec_access.conf;"
}

# ── Setup sync directory ───────────────────────────────────────────────────────
setup_sync_dir() {
    hdr "Sync directory: $LUA_SYNC_DIR"
    mkdir -p "$LUA_SYNC_DIR"
    chown root:"$NGINX_USER" "$LUA_SYNC_DIR"
    chmod 775 "$LUA_SYNC_DIR"
    touch "$LUA_SYNC_DIR/events.jsonl"
    chown root:"$NGINX_USER" "$LUA_SYNC_DIR/events.jsonl"
    chmod 664 "$LUA_SYNC_DIR/events.jsonl"
    ok "Sync dir configured (owner root:$NGINX_USER mode 775)"
}

# ── Install systemd unit ───────────────────────────────────────────────────────
install_systemd() {
    local unit_src="$REPO_DIR/systemd/crowdsec-cf-sync.service"
    [ -f "$unit_src" ] || { warn "Systemd unit not found: $unit_src (skip)"; return; }
    hdr "Systemd service"
    cp -v "$unit_src" "$SYSTEMD_UNIT"
    systemctl daemon-reload
    systemctl enable crowdsec-cf-sync 2>/dev/null || true
    systemctl restart crowdsec-cf-sync
    ok "Service installed and started"
}

# ── Verify nginx config ────────────────────────────────────────────────────────
verify_nginx_config() {
    hdr "Nginx config test"
    if sudo "$NGINX_BIN" -t 2>&1; then
        ok "Config syntax OK"
    else
        err "Config test FAILED — rolling back"
        do_rollback
        die "Installation aborted: nginx config invalid after changes"
    fi
}

# ── Real post-install verification ────────────────────────────────────────────
verify_installation() {
    hdr "Post-install verification"

    # 1. Reload nginx
    info "Reloading $NGINX_SERVICE..."
    systemctl reload "$NGINX_SERVICE"
    sleep 2

    local status_url="http://127.0.0.1:8091/crowdsec-status"
    local ok_count=0 fail_count=0

    # 2. Endpoint reachable
    info "Checking $status_url ..."
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" "$status_url" --max-time 5 2>/dev/null || echo "000")
    if [ "$http_code" = "200" ]; then
        ok "Endpoint /crowdsec-status: HTTP $http_code"
        ((ok_count++)) || true
    else
        warn "Endpoint /crowdsec-status: HTTP $http_code (may need nginx_status_internal.conf)"
        ((fail_count++)) || true
    fi

    # 3. Parse metrics from endpoint
    if [ "$http_code" = "200" ]; then
        local lua_syncs sync_version
        lua_syncs=$(curl -s "$status_url" | python3 -c \
            "import sys,json; d=json.load(sys.stdin); print(d['counters'].get('lua_syncs',0))" 2>/dev/null || echo "?")
        sync_version=$(curl -s "$status_url" | python3 -c \
            "import sys,json; d=json.load(sys.stdin); print(d['sync'].get('version',0))" 2>/dev/null || echo "?")
        info "Lua metrics: lua_syncs=$lua_syncs  sync_version=$sync_version"

        if [ "$sync_version" != "?" ] && [ "$sync_version" != "0" ]; then
            ok "Lua sync timer active (sync_version=$sync_version)"
            ((ok_count++)) || true
        else
            warn "sync_version=$sync_version — Python daemon may not be running yet"
            ((fail_count++)) || true
        fi
    fi

    # 4. bans.json readable by nginx user
    if [ -f "$LUA_SYNC_DIR/bans.json" ]; then
        local perm
        perm=$(stat -c '%a' "$LUA_SYNC_DIR/bans.json")
        if sudo -u "$NGINX_USER" test -r "$LUA_SYNC_DIR/bans.json" 2>/dev/null; then
            ok "bans.json readable by $NGINX_USER (mode $perm)"
            ((ok_count++)) || true
        else
            warn "bans.json NOT readable by $NGINX_USER (mode $perm)"
            warn "Fix: chmod 644 $LUA_SYNC_DIR/bans.json"
            ((fail_count++)) || true
        fi
    else
        info "bans.json not yet created — will appear after first Python daemon cycle"
    fi

    # 5. Lua module files present
    local missing_modules=0
    for mod in init lookup sync access heuristics mitigation tarpit events metrics; do
        if [ ! -f "$LUA_MODULE_DIR/crowdsec/$mod.lua" ]; then
            warn "Missing Lua module: $LUA_MODULE_DIR/crowdsec/$mod.lua"
            ((missing_modules++)) || true
        fi
    done
    if [ "$missing_modules" -eq 0 ]; then
        ok "All 9 Lua modules present in $LUA_MODULE_DIR/crowdsec/"
        ((ok_count++)) || true
    else
        ((fail_count++)) || true
    fi

    # 6. Python daemon running
    if systemctl is-active --quiet crowdsec-cf-sync 2>/dev/null; then
        ok "Python daemon: active"
        ((ok_count++)) || true
    else
        warn "Python daemon: not active (start with: systemctl start crowdsec-cf-sync)"
        ((fail_count++)) || true
    fi

    echo
    if [ "$fail_count" -eq 0 ]; then
        echo -e "${GRN}${BLD}STATUS: HEALTHY${RST} ($ok_count checks passed)"
    elif [ "$ok_count" -gt "$fail_count" ]; then
        echo -e "${YLW}${BLD}STATUS: DEGRADED${RST} ($ok_count OK, $fail_count warnings)"
    else
        echo -e "${RED}${BLD}STATUS: BROKEN${RST} ($ok_count OK, $fail_count failures)"
    fi

    log_to_file "INSTALL verified: ok=$ok_count fail=$fail_count"
}

# ── Main ───────────────────────────────────────────────────────────────────────
main() {
    [ "$(id -u)" -eq 0 ] || die "Must be run as root"

    echo -e "${BLD}${CYN}=== CrowdSec-CF-Sync Installer ${VERSION} ===${RST}"
    log_to_file "=== install-v3.sh $VERSION started (mode=$MODE) ==="

    # Declare globals used across functions
    declare -g NGINX_BIN NGINX_SERVICE NGINX_MAIN_CONF NGINX_CONF_DIR NGINX_DUMP
    declare -g CONF_D_DIR SNIPPETS_DIR NGINX_USER LUA_MODULE_DIR
    declare -g OFFICIAL_BOUNCER_CONF HAS_OFFICIAL_BOUNCER GENERATED_CONF HAS_GENERATED_CONF
    declare -g HAS_LUA_PACKAGE_PATH HAS_INIT_BY_LUA HAS_INIT_WORKER_BY_LUA HAS_ACCESS_BY_LUA
    declare -ga EXISTING_DICT_NAMES
    declare -g HAS_SYSTEMD BACKUP_DIR

    detect_environment

    if [ "$MODE" = "rollback" ]; then
        do_rollback
        exit 0
    fi

    do_audit

    if [ "$MODE" = "audit" ]; then
        echo
        info "Audit complete. Run without --audit to install."
        exit 0
    fi

    # Interactive confirmation
    if ! $YES; then
        echo
        echo -e "${YLW}The installer will now:${RST}"
        echo "  1. Back up all files it will modify"
        echo "  2. Generate $GENERATED_CONF"
        $HAS_OFFICIAL_BOUNCER && echo "  3. Extend $OFFICIAL_BOUNCER_CONF (lua_package_path + init blocks)"
        echo "  4. Install Lua modules to $LUA_MODULE_DIR/crowdsec/"
        echo "  5. Install snippets to $SNIPPETS_DIR/"
        echo "  6. Configure sync directory $LUA_SYNC_DIR"
        echo "  7. Install/restart systemd service"
        echo "  8. Verify installation"
        echo
        read -r -p "Proceed? [y/N] " confirm
        [[ "$confirm" =~ ^[Yy]$ ]] || { info "Aborted."; exit 0; }
    fi

    do_backup
    generate_conf
    merge_official_bouncer
    install_lua_modules
    install_snippets
    setup_sync_dir
    install_systemd
    verify_nginx_config
    verify_installation

    echo
    ok "Installation complete. Backup at: $BACKUP_DIR"
    info "To rollback: sudo bash scripts/install-v3.sh --rollback"
    log_to_file "=== install-v3.sh complete ==="
}

main "$@"
