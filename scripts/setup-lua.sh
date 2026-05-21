#!/bin/bash
# setup-lua.sh — One-time setup for CrowdSec OpenResty Lua layer (V3.2)
# Run as root on the NUC.
set -euo pipefail

LUA_SYNC_DIR="/run/crowdsec-lua"
LUA_MODULE_DIR="/etc/openresty/lua"
NGINX_CONF_DIR="/etc/openresty/conf.d"
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
echo "[3/5] Installing nginx conf snippets to $NGINX_CONF_DIR/"
mkdir -p "$NGINX_CONF_DIR"
cp -v "$REPO_DIR/nginx/crowdsec_shared_dicts.conf" "$NGINX_CONF_DIR/"
cp -v "$REPO_DIR/nginx/crowdsec_init.conf"         "$NGINX_CONF_DIR/"
cp -v "$REPO_DIR/nginx/crowdsec_access.conf"       "$NGINX_CONF_DIR/"
cp -v "$REPO_DIR/nginx/crowdsec_status.conf"       "$NGINX_CONF_DIR/"
chmod 644 "$NGINX_CONF_DIR/crowdsec_"*.conf

# ── 4. Verify OpenResty syntax ────────────────────────────────────────────────
echo "[4/5] Testing OpenResty configuration..."
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
echo "  bans.json:      written by Python daemon each cycle (60s)"
echo "  events.jsonl:   written by OpenResty, read by Python each cycle"
echo ""
echo "Next: include crowdsec_shared_dicts.conf and crowdsec_init.conf in your"
echo "      http {} block, then add crowdsec_access.conf to each vhost."
echo "      Then: systemctl reload openresty"
