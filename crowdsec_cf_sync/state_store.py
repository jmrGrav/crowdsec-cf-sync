"""Persistence helpers and StateStore for crowdsec-cf-sync state files.

_load_json_state / _atomic_write_json implement the V4 envelope contract
(version, sha256 checksum, atomic write via mkstemp + fsync + os.replace).
See docs/state-format.md for the normative spec.
"""

import hashlib
import json
import logging
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("cf_sync")

STATE_VERSION = 1  # bumped when state format changes


def _rename_bak(path: Path) -> None:
    try:
        bak = path.with_suffix(".bak")
        path.rename(bak)
        log.info("State backup: %s → %s", path.name, bak.name)
    except OSError:
        pass


def _load_json_state(path: Path, default: dict) -> dict:
    if not path.exists():
        return dict(default)
    try:
        raw  = path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (json.JSONDecodeError, OSError, UnicodeDecodeError) as exc:
        log.warning("State corrompu %s: %s — reset + backup", path.name, exc)
        _rename_bak(path)
        return dict(default)

    # V4 versioned envelope: {"version": N, "sha256": "...", "state": {...}}
    if isinstance(data, dict) and "version" in data:
        state = data.get("state")
        if not isinstance(state, dict):
            log.warning("State %s: champ 'state' invalide — reset + backup", path.name)
            _rename_bak(path)
            return dict(default)
        stored_sha = data.get("sha256", "")
        if stored_sha:
            actual_sha = hashlib.sha256(
                json.dumps(state, sort_keys=True, ensure_ascii=False).encode()
            ).hexdigest()
            if actual_sha != stored_sha:
                log.warning(
                    "State %s: checksum invalide (stocké=%s… calculé=%s…) — "
                    "corruption détectée, reset + backup",
                    path.name, stored_sha[:12], actual_sha[:12],
                )
                _rename_bak(path)
                return dict(default)
        return state

    # V3 flat format (no version key) — accepted, migrated to V4 envelope on next save
    if isinstance(data, dict):
        return data

    log.warning("State %s: type inattendu %s — reset", path.name, type(data).__name__)
    _rename_bak(path)
    return dict(default)


def _atomic_write_json(path: Path, data: dict) -> None:
    # Compute checksum over state dict (canonical JSON, sorted keys)
    state_canonical = json.dumps(data, sort_keys=True, ensure_ascii=False)
    checksum = hashlib.sha256(state_canonical.encode()).hexdigest()
    envelope = {
        "version":    STATE_VERSION,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "sha256":     checksum,
        "state":      data,
    }
    content = json.dumps(envelope, indent=2, ensure_ascii=False).encode()
    tmp_fd, tmp_path = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(tmp_fd, "wb") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())   # durable before rename
        os.replace(tmp_path, path)
    except Exception as exc:
        log.warning("Erreur écriture atomique %s: %s", path.name, exc)
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


# ── StateStore — per-domain envelope wrapper ─────────────────────────────────
# One instance per state file. Path is resolved via a getter so module-level
# constants can be hot-swapped (tests). default is the value returned on
# absent-file load — copied per call so caller mutations cannot leak back.
# All invariants (V4 envelope, sha256 canonical, .bak on corruption,
# atomic write, V3 backward compat) live in _load_json_state / _atomic_write_json
# above; this class is a thin per-path binding to consolidate the 12
# previous load_X / save_X wrappers.
# See docs/state-format.md for the normative contract.

class StateStore:
    def __init__(self, path_getter, default=None) -> None:
        self._get_path = path_getter
        self._default  = default if default is not None else {}

    def load(self) -> dict:
        return _load_json_state(self._get_path(), self._default)

    def save(self, data: dict) -> None:
        _atomic_write_json(self._get_path(), data)
