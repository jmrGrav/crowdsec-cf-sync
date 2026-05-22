#!/bin/bash
# setup-lua.sh — One-time setup for CrowdSec OpenResty Lua layer (V3.2)
# Run as root on the NUC.
set -euo pipefail

LUA_SYNC_DIR="/run/crowdsec-lua"
LUA_MODULE_DIR="/etc/openresty/lua"
NGINX_CONF_DIR="/etc/openresty/conf.d"
NGINX_SNIPPETS_DIR="/etc/nginx/snippets"
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "=== CrowdSec Lua layer setup ==="

# ── 1. Shared sync directory ──────────────────────────────────────────────────
echo "[1/5] Creating sync dir: $LUA_SYNC_DIR"
mkdir -p "$LUA_SYNC_DIR"
# Python daemon (root) writes bans.json; OpenResty (www-data) writes events.jsonl
chown root:www-data "$LUA_SYNC_DIR"
chmod 775 "$LUA_SYNC_DIR"
# Pre-create events file writable by OpenResty
touch "$LUA_SYNC_DIR/events.jsonl"
chown root:www-data "$LUA_SYNC_DIR/events.jsonl"
chmod 664 "$LUA_SYNC_DIR/events.jsonl"

# ── 2. Lua module directory ────────────────────────────────────────────────────
echo "[2/5] Installing Lua modules to $LUA_MODULE_DIR/crowdsec/"
mkdir -p "$LUA_MODULE_DIR/crowdsec"
cp -v "$REPO_DIR/lua/crowdsec/"*.lua "$LUA_MODULE_DIR/crowdsec/"
chmod 644 "$LUA_MODULE_DIR/crowdsec/"*.lua

# ── 3. OpenResty config snippets ──────────────────────────────────────────────
echo "[3/5] Installing nginx conf snippets..."

# HTTP-level config (shared dict declarations + init blocks) → conf.d/
mkdir -p "$NGINX_CONF_DIR"
cp -v "$REPO_DIR/nginx/crowdsec_shared_dicts.conf" "$NGINX_CONF_DIR/"
cp -v "$REPO_DIR/nginx/crowdsec_init.conf"         "$NGINX_CONF_DIR/"
chmod 644 "$NGINX_CONF_DIR/crowdsec_shared_dicts.conf" \
          "$NGINX_CONF_DIR/crowdsec_init.conf"

# Per-vhost snippets (access_by_lua_block, status locations) → snippets/
# These MUST NOT land in conf.d/ — auto-including them at the http {} level
# creates duplicate init_by_lua_block / access_by_lua_block conflicts with
# the official CrowdSec OpenResty bouncer.
mkdir -p "$NGINX_SNIPPETS_DIR"
cp -v "$REPO_DIR/nginx/crowdsec_access.conf" "$NGINX_SNIPPETS_DIR/"
cp -v "$REPO_DIR/nginx/crowdsec_status.conf" "$NGINX_SNIPPETS_DIR/"
chmod 644 "$NGINX_SNIPPETS_DIR/crowdsec_access.conf" \
          "$NGINX_SNIPPETS_DIR/crowdsec_status.conf"

# ── 4. Handle conflicts with official CrowdSec OpenResty bouncer ───────────────
# The official bouncer (crowdsec_openresty.conf) declares:
#   - lua_package_path        (duplicate → extend in-place)
#   - init_by_lua_block       (duplicate → merge our requires into it)
#   - init_worker_by_lua_block (duplicate → merge our sync.start() into it)
# When the official bouncer is present our crowdsec_init.conf must NOT
# re-declare those directives.
OFFICIAL_CONF="$NGINX_CONF_DIR/crowdsec_openresty.conf"
OUR_INIT_CONF="$NGINX_CONF_DIR/crowdsec_init.conf"
OUR_LUA_PATH="/etc/openresty/lua/?.lua"

if [ -f "$OFFICIAL_CONF" ]; then
    echo "[4a] Official CrowdSec bouncer detected — merging our config into it"

    # ── lua_package_path ──
    if ! grep -q "$OUR_LUA_PATH" "$OFFICIAL_CONF"; then
        sed -i "s|lua_package_path '\(.*\);;';|lua_package_path '\1;$OUR_LUA_PATH;;';|" \
            "$OFFICIAL_CONF"
        echo "  → lua_package_path extended in $OFFICIAL_CONF"
    else
        echo "  → lua_package_path already contains our path (no change)"
    fi

    # ── init_by_lua_block / init_worker_by_lua_block ──
    # Inject our module preloads into the official bouncer's init blocks,
    # then strip those directives from our crowdsec_init.conf to prevent
    # nginx "duplicate directive" errors.
    python3 - "$OFFICIAL_CONF" "$OUR_INIT_CONF" <<'PYEOF'
import re, sys

official_path = sys.argv[1]
our_path      = sys.argv[2]

with open(official_path) as f:
    official = f.read()
with open(our_path) as f:
    our = f.read()

# ── 1. Inject into official init_by_lua_block (idempotent) ──
INIT_INJECT = """\
    -- CrowdSec custom Lua layer (crowdsec-cf-sync)
    require "crowdsec.init"
    require "crowdsec.lookup"
    require "crowdsec.heuristics"
    require "crowdsec.mitigation"
    require "crowdsec.tarpit"
    require "crowdsec.sync"
    require "crowdsec.events"
    require "crowdsec.access"
    require "crowdsec.metrics"\
"""
if 'require "crowdsec.init"' not in official:
    # Append before the first closing } of init_by_lua_block
    official = re.sub(
        r'(init_by_lua_block\s*\{)(.*?)(\})',
        lambda m: m.group(1) + m.group(2).rstrip() + '\n' + INIT_INJECT + '\n' + m.group(3),
        official, count=1, flags=re.DOTALL
    )
    print("  → init_by_lua_block extended in", official_path)
else:
    print("  → init_by_lua_block already contains our requires (no change)")

# ── 2. Inject into official init_worker_by_lua_block (idempotent) ──
WORKER_INJECT = """\
    -- Start CrowdSec Lua sync timer
    require("crowdsec.sync").start()\
"""
if 'crowdsec.sync' not in official:
    official = re.sub(
        r'(init_worker_by_lua_block\s*\{)(.*?)(\})',
        lambda m: m.group(1) + m.group(2).rstrip() + '\n' + WORKER_INJECT + '\n' + m.group(3),
        official, count=1, flags=re.DOTALL
    )
    print("  → init_worker_by_lua_block extended in", official_path)
else:
    print("  → init_worker_by_lua_block already contains our sync (no change)")

with open(official_path, 'w') as f:
    f.write(official)

# ── 3. Strip duplicate directives from our crowdsec_init.conf ──
stripped = re.sub(r'\ninit_by_lua_block\s*\{.*?\}', '', our, flags=re.DOTALL)
stripped = re.sub(r'\ninit_worker_by_lua_block\s*\{.*?\}', '', stripped, flags=re.DOTALL)
if stripped != our:
    with open(our_path, 'w') as f:
        f.write(stripped)
    print("  → Duplicate init blocks removed from", our_path)
else:
    print("  → crowdsec_init.conf already stripped (no change)")
PYEOF

else
    echo "[4a] No official bouncer found — using crowdsec_init.conf as-is"
fi

# ── 4b. Verify OpenResty syntax ───────────────────────────────────────────────
echo "[4b] Testing OpenResty configuration..."
openresty -t && echo "  → Config OK"

# ── 5. Systemd service update ─────────────────────────────────────────────────
echo "[5/5] Updating systemd service unit..."
cp -v "$REPO_DIR/systemd/crowdsec-cf-sync.service" \
      /etc/systemd/system/crowdsec-cf-sync.service
systemctl daemon-reload
systemctl restart crowdsec-cf-sync
systemctl status crowdsec-cf-sync --no-pager -l

echo ""
echo "=== Setup complete ==="
echo "  Sync dir:       $LUA_SYNC_DIR"
echo "  Lua modules:    $LUA_MODULE_DIR/crowdsec/"
echo "  HTTP-level:     $NGINX_CONF_DIR/crowdsec_shared_dicts.conf"
echo "                  $NGINX_CONF_DIR/crowdsec_init.conf"
echo "  Snippets:       $NGINX_SNIPPETS_DIR/crowdsec_access.conf"
echo "                  $NGINX_SNIPPETS_DIR/crowdsec_status.conf"
echo "  bans.json:      written by Python daemon each cycle (60s)"
echo "  events.jsonl:   written by OpenResty, read by Python each cycle"
echo ""
echo "Next steps:"
echo "  1. Add to each vhost you want protected:"
echo "       include $NGINX_SNIPPETS_DIR/crowdsec_access.conf;"
echo "  2. (Optional) Add to your 127.0.0.1 status server block:"
echo "       include $NGINX_SNIPPETS_DIR/crowdsec_status.conf;"
echo "  3. Reload OpenResty:"
echo "       systemctl reload openresty"
