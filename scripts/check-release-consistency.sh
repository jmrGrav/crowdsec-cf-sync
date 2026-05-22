#!/bin/bash
# check-release-consistency.sh — verify git tags match GitHub releases
#
# Checks:
#   1. Every vX.Y.Z tag has a matching GitHub release
#   2. Every GitHub release has a matching signed tag
#   3. All tags point to commits reachable from main
#   4. The "Latest" release is the highest semver
#   5. Tags are GPG-signed
#
# Usage: bash scripts/check-release-consistency.sh
# Requires: gh CLI authenticated, git

set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RESET='\033[0m'
ERRORS=0; WARNS=0; TOTAL=0

pass()  { TOTAL=$((TOTAL+1)); echo -e "  ${GREEN}OK${RESET}    $1"; }
fail()  { TOTAL=$((TOTAL+1)); ERRORS=$((ERRORS+1)); echo -e "  ${RED}FAIL${RESET}  $1"; }
warn()  { TOTAL=$((TOTAL+1)); WARNS=$((WARNS+1));   echo -e "  ${YELLOW}WARN${RESET}  $1"; }

echo "=== check-release-consistency.sh ==="
echo ""

# ── Fetch data ────────────────────────────────────────────────────────────────
GIT_TAGS=$(git tag -l 'v*.*.*' | sort -V)
if [ -z "$GIT_TAGS" ]; then
    fail "No git tags found matching v*.*.*"
    exit 1
fi

GH_RELEASES=$(gh release list --limit 50 --json tagName,isLatest,isDraft,isPrerelease \
    2>/dev/null | python3 -c "
import json, sys
data = json.load(sys.stdin)
for r in data:
    print(r['tagName'], 'latest' if r['isLatest'] else '-', 'draft' if r['isDraft'] else '-')
")
if [ -z "$GH_RELEASES" ]; then
    fail "Cannot fetch GitHub releases (gh not authenticated or no releases)"
    exit 1
fi

GH_TAG_LIST=$(echo "$GH_RELEASES" | awk '{print $1}')
LATEST_TAG=$(echo "$GH_RELEASES" | awk '$2=="latest" {print $1}')

echo "Git tags  : $(echo "$GIT_TAGS" | tr '\n' ' ')"
echo "GH latest : $LATEST_TAG"
echo ""

# ── Check 1: every git tag has a GH release ──────────────────────────────────
echo "── Every git tag has a GitHub release ──────────────────────────────────"
while IFS= read -r tag; do
    if echo "$GH_TAG_LIST" | grep -qx "$tag"; then
        pass "$tag → GitHub release exists"
    else
        fail "$tag → NO GitHub release"
    fi
done <<< "$GIT_TAGS"

# ── Check 2: every GH release has a git tag ──────────────────────────────────
echo ""
echo "── Every GitHub release has a git tag ──────────────────────────────────"
while IFS= read -r gh_tag; do
    if echo "$GIT_TAGS" | grep -qx "$gh_tag"; then
        pass "$gh_tag → git tag exists"
    else
        fail "$gh_tag → git tag MISSING"
    fi
done <<< "$GH_TAG_LIST"

# ── Check 3: all tags reachable from main ────────────────────────────────────
echo ""
echo "── All tags reachable from main ─────────────────────────────────────────"
MAIN_COMMITS=$(git log main --format="%H" 2>/dev/null)
while IFS= read -r tag; do
    tag_commit=$(git rev-parse "${tag}^{}" 2>/dev/null)
    if echo "$MAIN_COMMITS" | grep -qx "$tag_commit"; then
        pass "$tag → reachable from main (${tag_commit:0:8})"
    else
        fail "$tag → NOT reachable from main (${tag_commit:0:8})"
    fi
done <<< "$GIT_TAGS"

# ── Check 4: Latest is the highest semver ────────────────────────────────────
echo ""
echo "── Latest release is highest semver ────────────────────────────────────"
HIGHEST=$(echo "$GIT_TAGS" | sort -V | tail -1)
if [ "$LATEST_TAG" = "$HIGHEST" ]; then
    pass "Latest=$LATEST_TAG is the highest tag ($HIGHEST)"
else
    fail "Latest=$LATEST_TAG but highest tag is $HIGHEST"
fi

# ── Check 5: tags are GPG-signed ─────────────────────────────────────────────
echo ""
echo "── Tags are GPG-signed ──────────────────────────────────────────────────"
while IFS= read -r tag; do
    tag_type=$(git cat-file -t "$tag" 2>/dev/null)
    if [ "$tag_type" = "tag" ]; then
        # Annotated tag — check for GPG signature
        if git tag -v "$tag" 2>&1 | grep -q "gpg:"; then
            pass "$tag → signed"
        else
            warn "$tag → annotated but no GPG signature detected"
        fi
    else
        fail "$tag → lightweight tag (not annotated, not signed)"
    fi
done <<< "$GIT_TAGS"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════════════════════"
echo " Results: $((TOTAL - ERRORS - WARNS))/${TOTAL} OK  ($WARNS warnings, $ERRORS failures)"
[ "$ERRORS" -gt 0 ] && echo -e " ${RED}${ERRORS} check(s) FAILED${RESET}"
[ "$WARNS" -gt 0  ] && echo -e " ${YELLOW}${WARNS} warning(s)${RESET}"
echo "════════════════════════════════════════════════════════════════════════"

[ "$ERRORS" -gt 0 ] && exit 1
exit 0
