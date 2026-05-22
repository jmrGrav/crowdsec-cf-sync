#!/bin/bash
# rollback-v3.sh — Restore a crowdsec-cf-sync installation backup
#
# Usage:
#   sudo bash scripts/rollback-v3.sh               # list available backups
#   sudo bash scripts/rollback-v3.sh 20260522_0610  # restore specific timestamp
#   sudo bash scripts/rollback-v3.sh --latest       # restore most recent backup

set -euo pipefail

BACKUP_BASE="/var/backups/crowdsec-cf-sync"
INSTALL_LOG="/var/log/crowdsec/crowdsec-cf-sync-install.log"

RED='\033[0;31m'; YLW='\033[1;33m'; GRN='\033[0;32m'; BLU='\033[0;34m'; RST='\033[0m'; BLD='\033[1m'
ok()   { echo -e "${GRN}[OK]${RST}    $*"; }
info() { echo -e "${BLU}[INFO]${RST}  $*"; }
warn() { echo -e "${YLW}[WARN]${RST}  $*"; }
die()  { echo -e "${RED}[ERROR]${RST} $*" >&2; exit 1; }

log_to_file() {
    mkdir -p "$(dirname "$INSTALL_LOG")" 2>/dev/null || true
    echo "[$(date -u +%FT%TZ)] $*" >> "$INSTALL_LOG" 2>/dev/null || true
}

[ "$(id -u)" -eq 0 ] || die "Must be run as root"
[ -d "$BACKUP_BASE" ] || die "No backup directory: $BACKUP_BASE"

# ── List mode ──────────────────────────────────────────────────────────────────
if [ $# -eq 0 ]; then
    echo -e "${BLD}Available backups:${RST}"
    local_count=0
    for d in $(ls -1r "$BACKUP_BASE" 2>/dev/null); do
        manifest="$BACKUP_BASE/$d/MANIFEST.txt"
        if [ -d "$BACKUP_BASE/$d" ]; then
            info "$d"
            if [ -f "$manifest" ]; then
                grep "^# " "$manifest" | head -4 | sed 's/^# /    /'
            fi
            ((local_count++)) || true
        fi
    done
    [ "$local_count" -eq 0 ] && warn "No backups found"
    echo
    echo "Usage: sudo bash scripts/rollback-v3.sh <timestamp>"
    exit 0
fi

# ── Select backup ──────────────────────────────────────────────────────────────
TARGET="$1"
if [ "$TARGET" = "--latest" ]; then
    TARGET=$(ls -1 "$BACKUP_BASE" 2>/dev/null | sort -r | head -1)
    [ -z "$TARGET" ] && die "No backups found"
fi

BACKUP_DIR="$BACKUP_BASE/$TARGET"
[ -d "$BACKUP_DIR" ] || die "Backup not found: $BACKUP_DIR"

echo -e "${BLD}Restoring from: $BACKUP_DIR${RST}"
if [ -f "$BACKUP_DIR/MANIFEST.txt" ]; then
    echo; cat "$BACKUP_DIR/MANIFEST.txt"; echo
fi

# ── Restore files ──────────────────────────────────────────────────────────────
restored=0; failed=0

while IFS= read -r line; do
    # Lines look like: "sha256hash  /full/path/to/file"
    [[ "$line" =~ ^[0-9a-f]{64}[[:space:]] ]] || continue
    orig_path=$(echo "$line" | awk '{print $2}')
    bname=$(basename "$orig_path")
    src="$BACKUP_DIR/$bname"

    if [ ! -f "$src" ]; then
        warn "Backup file not found: $src (skip)"
        ((failed++)) || true
        continue
    fi

    # Verify checksum of backup copy
    expected_hash=$(echo "$line" | awk '{print $1}')
    actual_hash=$(sha256sum "$src" | awk '{print $1}')
    if [ "$actual_hash" != "$expected_hash" ]; then
        warn "Checksum mismatch for $bname — backup may be corrupted (restoring anyway)"
    fi

    cp "$src" "$orig_path"
    chmod 644 "$orig_path"
    ok "Restored: $orig_path"
    ((restored++)) || true

done < "$BACKUP_DIR/MANIFEST.txt"

info "Restored $restored file(s), $failed skipped"

# ── Detect nginx binary ────────────────────────────────────────────────────────
if command -v openresty >/dev/null 2>&1; then
    NGINX_BIN="openresty"; NGINX_SERVICE="openresty"
else
    NGINX_BIN="nginx"; NGINX_SERVICE="nginx"
fi

# ── Verify and reload ─────────────────────────────────────────────────────────
echo
if sudo "$NGINX_BIN" -t 2>&1; then
    ok "Config syntax OK after rollback"
    systemctl reload "$NGINX_SERVICE" && ok "Service reloaded"
else
    warn "Config test FAILED after rollback — inspect manually:"
    warn "  sudo $NGINX_BIN -T | grep -A5 'crowdsec'"
fi

log_to_file "ROLLBACK to $TARGET: restored=$restored failed=$failed"
echo
ok "Rollback complete"
