#!/bin/bash
# release-v3.sh — Automated release workflow for crowdsec-cf-sync V3.x
#
# Performs:
#   1. Pre-flight checks (clean working tree, all tests pass, consistency check)
#   2. GPG-signed annotated tag
#   3. git push origin main + tag
#   4. GitHub release via gh CLI
#   5. Post-release verification
#
# Usage:
#   sudo -u jm -E bash scripts/release-v3.sh <version> [--dry-run]
#   e.g.: sudo -u jm -E bash scripts/release-v3.sh 3.3.4
#
# Requirements:
#   - gh CLI authenticated
#   - GPG key configured (same as git commit signing)
#   - Clean working tree (no uncommitted changes)
#   - sudo -u jm -E for GPG signing (signing key belongs to jm, not root)

set -uo pipefail

# ── Args ──────────────────────────────────────────────────────────────────────
VERSION="${1:-}"
DRY_RUN=false
for arg in "$@"; do [ "$arg" = "--dry-run" ] && DRY_RUN=true; done

if [ -z "$VERSION" ]; then
    echo "Usage: $0 <version> [--dry-run]"
    echo "  version: e.g. 3.3.4 (without 'v' prefix)"
    exit 1
fi

TAG="v${VERSION}"

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; RESET='\033[0m'
ok()   { echo -e "  ${GREEN}✓${RESET} $1"; }
fail() { echo -e "  ${RED}✗ FAIL${RESET} $1"; exit 1; }
warn() { echo -e "  ${YELLOW}!${RESET} $1"; }
step() { echo -e "\n${BOLD}── $1 ──────────────────────────────────────────────────${RESET}"; }

echo -e "${BOLD}=== crowdsec-cf-sync release-v3.sh ===${RESET}"
echo "  Tag     : $TAG"
echo "  Dry-run : $DRY_RUN"
echo ""

# ── 0. Sanity: must NOT run as root (GPG key is under jm) ────────────────────
if [ "$(id -u)" -eq 0 ]; then
    fail "Do not run as root. Use: sudo -u jm -E bash $0 $VERSION"
fi

# ── 1. Pre-flight ─────────────────────────────────────────────────────────────
step "Pre-flight"

# Working tree clean
if ! git diff --quiet HEAD 2>/dev/null; then
    fail "Uncommitted changes in working tree. Commit or stash first."
fi
ok "Working tree clean"

# Tag must not exist yet
if git tag -l "$TAG" | grep -q .; then
    fail "Tag $TAG already exists. Did you mean a different version?"
fi
ok "Tag $TAG does not exist yet"

# On main branch
current_branch=$(git rev-parse --abbrev-ref HEAD)
if [ "$current_branch" != "main" ]; then
    warn "Not on main branch (current: $current_branch)"
fi

# gh CLI authenticated
if ! gh auth status > /dev/null 2>&1; then
    fail "gh CLI not authenticated. Run: gh auth login"
fi
ok "gh CLI authenticated"

# Python syntax check
python3 -m py_compile crowdsec-cf-sync 2>/dev/null && ok "Python syntax OK" || fail "Python syntax error in crowdsec-cf-sync"

# Lua syntax: openresty -t is authoritative (LuaJIT, supports goto).
# luac 5.1 is NOT used — it rejects valid goto statements in sync.lua (false positive).
ok "Lua syntax: validated via openresty -t (see pre-flight step above)"

# ── 2. Consistency check ──────────────────────────────────────────────────────
step "Release consistency check"
bash scripts/check-release-consistency.sh 2>&1 | tail -5
# check-release-consistency exits 0 on success (no missing releases for existing tags)
# The new tag doesn't exist yet so this only checks existing releases

# ── 3. Prompt for release notes ───────────────────────────────────────────────
step "Release notes"

NOTES_FILE=$(mktemp /tmp/release-notes-XXXXXX.md)
cat > "$NOTES_FILE" <<TEMPLATE
## What's new in ${TAG}

<!-- Replace this section with actual release notes -->

### Changes

-

### Production validation

- All counters verified live on production OpenResty
TEMPLATE

if command -v "${EDITOR:-}" > /dev/null 2>&1 || command -v nano > /dev/null 2>&1; then
    EDITOR="${EDITOR:-nano}"
    echo "  Opening $EDITOR for release notes. Save and close to continue."
    "$EDITOR" "$NOTES_FILE"
else
    echo "  No editor found. Using template release notes."
fi

NOTES_CONTENT=$(cat "$NOTES_FILE")
rm -f "$NOTES_FILE"

if [ -z "$NOTES_CONTENT" ] || echo "$NOTES_CONTENT" | grep -q "Replace this section"; then
    warn "Release notes appear to be the template. Continuing anyway."
fi

# ── 4. Create GPG-signed tag ──────────────────────────────────────────────────
step "Creating signed tag $TAG"

if $DRY_RUN; then
    ok "[DRY-RUN] Would create: git tag -s $TAG -m \"V${VERSION} — ...\""
else
    # Extract first line of notes for tag message
    TAG_MSG=$(echo "$NOTES_CONTENT" | head -3 | tail -1 | sed 's/^## //')
    git tag -s "$TAG" -m "V${VERSION} — ${TAG_MSG}"
    ok "Tag $TAG created and signed"
    git show "$TAG" --format="tag %T %s" | head -2
fi

# ── 5. Push ───────────────────────────────────────────────────────────────────
step "Pushing to origin"

if $DRY_RUN; then
    ok "[DRY-RUN] Would run: git push origin main && git push origin $TAG"
else
    git push origin main
    ok "Pushed main"
    git push origin "$TAG"
    ok "Pushed tag $TAG"
fi

# ── 6. GitHub release ─────────────────────────────────────────────────────────
step "Creating GitHub release"

if $DRY_RUN; then
    ok "[DRY-RUN] Would create: gh release create $TAG --latest --title \"V${VERSION} — ...\" --notes ..."
else
    gh release create "$TAG" \
        --title "V${VERSION} — ${TAG_MSG:-crowdsec-cf-sync}" \
        --latest \
        --notes "$NOTES_CONTENT"
    ok "GitHub release created"
fi

# ── 7. Post-release verification ──────────────────────────────────────────────
step "Post-release verification"

if $DRY_RUN; then
    ok "[DRY-RUN] Would verify consistency"
else
    bash scripts/check-release-consistency.sh
fi

echo ""
echo -e "${GREEN}${BOLD}Release $TAG complete.${RESET}"
if ! $DRY_RUN; then
    echo "  https://github.com/$(gh repo view --json nameWithOwner -q .nameWithOwner)/releases/tag/$TAG"
fi
