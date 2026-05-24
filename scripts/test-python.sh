#!/bin/bash
# test-python.sh — Run the supervisor's Python golden tests.
#
# Stdlib unittest only — no pytest, no external dependencies.
# Tests are hermetic (tempdir per test), deterministic, offline.
#
# Usage:
#   scripts/test-python.sh           # quiet mode (dots)
#   scripts/test-python.sh -v        # verbose (test names + invariant docstrings)
#   scripts/test-python.sh test_state_roundtrip  # single module

set -euo pipefail
cd "$(dirname "$0")/.."

if [ $# -eq 0 ]; then
    exec python3 -m unittest discover tests/
elif [ "$1" = "-v" ] || [ "$1" = "--verbose" ]; then
    exec python3 -m unittest discover -v tests/
else
    # Run a specific test module (e.g. test_state_roundtrip)
    exec python3 -m unittest "tests.$1"
fi
