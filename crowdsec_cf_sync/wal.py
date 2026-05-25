"""WAL (write-ahead log) subsystem for crowdsec-cf-sync.

Append-only, crash-durable audit log of every intended CF operation.
Cloudflare API is the source of truth; the WAL is an audit trail, not
a distributed transaction log.
"""

import json
import logging
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from crowdsec_cf_sync.models import WalEntry

log = logging.getLogger("cf_sync")

WAL_FILE: Path = Path("/var/log/crowdsec/cf-sync-wal.jsonl")

# Optional callback set by main.py after import: lambda: metrics.inc("wal_entries")
# Using a callback avoids a circular import (wal → main → wal).
_on_wal_write = None
_wal_seq: int = 0


def _init_wal_seq() -> int:
    """Return current WAL line count so IDs continue across restarts."""
    if not WAL_FILE.exists():
        return 0
    try:
        with WAL_FILE.open(encoding="utf-8", errors="ignore") as f:
            return sum(1 for _ in f)
    except Exception:
        return 0


def _wal_log(op: str, target: str, tag: str = "", dry_run: bool = False,
             attempt: int = 1) -> None:
    """Append a CF operation intent to the WAL with fsync before returning."""
    global _wal_seq
    _wal_seq += 1
    entry: WalEntry = {
        "id":      _wal_seq,
        "op":      op,       # "add" | "remove" | "reconcile"
        "target":  target,
        "tag":     tag,
        "ts":      datetime.now(timezone.utc).isoformat(),
        "attempt": attempt,
        "dry_run": dry_run,
    }
    try:
        with WAL_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
            f.flush()
            os.fsync(f.fileno())   # crash-durable WAL entry
        if _on_wal_write is not None:
            _on_wal_write()
    except Exception as exc:
        log.debug("WAL write failed: %s", exc)


def _wal_trim(max_lines: int = 10_000) -> None:
    if not WAL_FILE.exists():
        return
    try:
        lines = WAL_FILE.read_text(encoding="utf-8").splitlines(keepends=True)
        if len(lines) > max_lines:
            keep = lines[-max_lines:]
            tmp_fd, tmp_path = tempfile.mkstemp(dir=WAL_FILE.parent, suffix=".tmp")
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
                f.writelines(keep)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, WAL_FILE)
            log.info("WAL: compacté %d → %d lignes", len(lines), len(keep))
    except Exception as exc:
        log.debug("WAL trim failed: %s", exc)


def cmd_wal_inspect() -> None:
    """Print a human-readable summary of the WAL."""
    if not WAL_FILE.exists():
        print(f"WAL file not found: {WAL_FILE}")
        return
    entries = []
    errors = 0
    with WAL_FILE.open(encoding="utf-8", errors="ignore") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                errors += 1
                print(f"  [line {i}] INVALID JSON: {line[:80]}")

    print(f"WAL: {WAL_FILE}")
    print(f"  Total entries: {len(entries)}, parse errors: {errors}")
    if not entries:
        return

    by_op: Dict[str, int] = {}
    targets: set = set()
    for e in entries:
        op = e.get("op", "?")
        by_op[op] = by_op.get(op, 0) + 1
        if "target" in e:
            targets.add(e["target"])

    print(f"  Unique targets: {len(targets)}")
    print(f"  Operations:")
    for op, count in sorted(by_op.items(), key=lambda x: -x[1]):
        print(f"    {op}: {count}")

    first_ts = entries[0].get("ts", "?")
    last_ts  = entries[-1].get("ts", "?")
    print(f"  Time range: {first_ts} → {last_ts}")
    print(f"  Last 5 entries:")
    for e in entries[-5:]:
        print(f"    {json.dumps(e)}")


def cmd_wal_replay(dry_run: bool = True) -> None:
    """Re-apply WAL entries (add/remove CF rules) from the WAL log.

    Use dry_run=True (default) to preview; pass --execute to actually apply.
    """
    if not WAL_FILE.exists():
        print(f"WAL file not found: {WAL_FILE}")
        return

    adds: List[str] = []
    removes: List[str] = []
    with WAL_FILE.open(encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            op     = e.get("op", "")
            target = e.get("target", "")
            if not target or op == "reconcile":
                continue
            if op == "add":
                adds.append(target)
            elif op == "remove":
                removes.append(target)

    # Net state: last op per target wins
    net: Dict[str, str] = {}
    with WAL_FILE.open(encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
                target = e.get("target", "")
                op     = e.get("op", "")
                if target and op != "reconcile":
                    net[target] = op
            except json.JSONDecodeError:
                continue

    to_add    = [t for t, op in net.items() if op == "add"]
    to_remove = [t for t, op in net.items() if op == "remove"]

    print(f"WAL replay {'(DRY RUN)' if dry_run else '(EXECUTE)'}:")
    print(f"  Net state: {len(to_add)} to add, {len(to_remove)} to remove")
    for t in to_add[:20]:
        print(f"  + {t}")
    for t in to_remove[:20]:
        print(f"  - {t}")
    if not dry_run:
        print("  Execute not yet implemented — use the main daemon loop instead.")


def cmd_wal_compact() -> None:
    """Collapse WAL to net state: one entry per IP, removes cancelling pairs."""
    if not WAL_FILE.exists():
        print(f"WAL file not found: {WAL_FILE}")
        return

    entries = []
    with WAL_FILE.open(encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                pass

    before = len(entries)
    # Keep only the last entry per target
    net: Dict[str, dict] = {}
    for e in entries:
        target = e.get("target", "")
        if target:
            net[target] = e

    compacted = list(net.values())
    after = len(compacted)

    print(f"WAL compact: {before} → {after} entries (removed {before - after} duplicates)")

    bak = WAL_FILE.with_suffix(".jsonl.bak")
    WAL_FILE.rename(bak)
    with WAL_FILE.open("w", encoding="utf-8") as f:
        for e in compacted:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")
    print(f"  Backup: {bak}")
    print(f"  Compacted WAL: {WAL_FILE}")
