"""Golden tests — WAL replay determinism and primitives.

The WAL is an append-only, crash-durable audit log of every intended CF
operation. It is NOT authoritative (Cloudflare API is source of truth) but it
MUST preserve order and entry integrity across crashes.

Invariants verified:
  - _init_wal_seq() returns 0 when file absent
  - _init_wal_seq() returns exact line count when file present
  - _wal_log() entry has all 7 required fields (id, op, target, tag, ts, attempt, dry_run)
  - _wal_log() entry is valid JSON
  - _wal_log() increments id strictly monotonically in-process
  - Simulated restart: next _wal_log() after _init_wal_seq() yields next id
  - Order preserved across appends (newest is last line)
  - cmd_wal_replay(dry_run=True) is deterministic on a given WAL state
  - cmd_wal_replay does NOT mutate the WAL (read-only)

Stdlib-only. Hermetic. No CF API calls.
"""

import io
import json
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _supervisor import load_supervisor

sup = load_supervisor()
import crowdsec_cf_sync.wal as _wal_mod


class _WalBase(unittest.TestCase):
    """Shared setup: tmp dir + WAL_FILE swap that auto-restores."""

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp(prefix="brooks-wal-"))
        self.wal_path = self.tmpdir / "wal.jsonl"
        self._original_wal = _wal_mod.WAL_FILE
        self._original_seq = _wal_mod._wal_seq
        _wal_mod.WAL_FILE = self.wal_path
        _wal_mod._wal_seq = 0

    def tearDown(self):
        _wal_mod.WAL_FILE = self._original_wal
        _wal_mod._wal_seq = self._original_seq
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _read_entries(self):
        entries = []
        if not self.wal_path.exists():
            return entries
        for line in self.wal_path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            entries.append(json.loads(line))
        return entries


# ── _init_wal_seq ───────────────────────────────────────────────────────────

class InitWalSeqTests(_WalBase):
    def test_invariant_absent_file_returns_zero(self):
        self.assertEqual(sup._init_wal_seq(), 0)

    def test_invariant_empty_file_returns_zero(self):
        self.wal_path.touch()
        self.assertEqual(sup._init_wal_seq(), 0)

    def test_invariant_returns_exact_line_count(self):
        self.wal_path.write_text("line1\nline2\nline3\n")
        self.assertEqual(sup._init_wal_seq(), 3)

    def test_invariant_counts_lines_without_trailing_newline(self):
        self.wal_path.write_text("line1\nline2\nline3")
        # File has 3 lines (last unterminated still counts)
        self.assertEqual(sup._init_wal_seq(), 3)


# ── _wal_log ────────────────────────────────────────────────────────────────

class WalLogStructureTests(_WalBase):
    def test_invariant_entry_has_all_required_fields(self):
        sup._wal_log("add", "1.2.3.4", tag="crowdsec-local-ban")
        entries = self._read_entries()
        self.assertEqual(len(entries), 1)
        for field in ("id", "op", "target", "tag", "ts", "attempt", "dry_run"):
            self.assertIn(field, entries[0], f"WAL entry MUST include '{field}'")

    def test_invariant_entry_is_valid_json(self):
        sup._wal_log("remove", "5.6.7.8")
        # _read_entries() would have raised on invalid JSON
        entries = self._read_entries()
        self.assertEqual(len(entries), 1)

    def test_invariant_fields_have_expected_types(self):
        sup._wal_log("add", "1.2.3.4", tag="crowdsec-local-ban", dry_run=True, attempt=2)
        entry = self._read_entries()[0]
        self.assertIsInstance(entry["id"], int)
        self.assertEqual(entry["op"], "add")
        self.assertEqual(entry["target"], "1.2.3.4")
        self.assertEqual(entry["tag"], "crowdsec-local-ban")
        self.assertIsInstance(entry["ts"], str)
        self.assertEqual(entry["attempt"], 2)
        self.assertIs(entry["dry_run"], True)

    def test_invariant_defaults_applied(self):
        sup._wal_log("add", "1.2.3.4")
        entry = self._read_entries()[0]
        self.assertEqual(entry["tag"], "")
        self.assertEqual(entry["attempt"], 1)
        self.assertIs(entry["dry_run"], False)


# ── ID monotonicity ─────────────────────────────────────────────────────────

class WalIdMonotonicityTests(_WalBase):
    def test_invariant_id_strictly_increases_in_process(self):
        for i in range(5):
            sup._wal_log("add", f"10.0.0.{i}")
        ids = [e["id"] for e in self._read_entries()]
        self.assertEqual(ids, [1, 2, 3, 4, 5], "WAL ids MUST be strictly monotonic")

    def test_invariant_id_continues_across_simulated_restart(self):
        """Critical crash-recovery invariant: ids do NOT collide after restart."""
        # Simulate first daemon instance writing 3 entries
        for i in range(3):
            sup._wal_log("add", f"10.0.0.{i}")
        first_session_ids = [e["id"] for e in self._read_entries()]
        self.assertEqual(first_session_ids, [1, 2, 3])

        # Simulate restart: _wal_seq reset, _init_wal_seq() re-reads file
        _wal_mod._wal_seq = sup._init_wal_seq()
        self.assertEqual(_wal_mod._wal_seq, 3, "init_wal_seq MUST recover exact prior count")

        # Second instance appends two more entries
        for i in range(3, 5):
            sup._wal_log("add", f"10.0.0.{i}")
        all_ids = [e["id"] for e in self._read_entries()]
        self.assertEqual(all_ids, [1, 2, 3, 4, 5],
                         "Post-restart ids MUST continue from where prior session ended")


# ── Order preservation ─────────────────────────────────────────────────────

class WalOrderTests(_WalBase):
    def test_invariant_append_order_preserved(self):
        targets = ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"]
        for t in targets:
            sup._wal_log("add", t)
        observed = [e["target"] for e in self._read_entries()]
        self.assertEqual(observed, targets, "WAL MUST preserve append order")

    def test_invariant_mixed_ops_preserve_order(self):
        sup._wal_log("add", "1.1.1.1")
        sup._wal_log("remove", "2.2.2.2")
        sup._wal_log("reconcile", "full")
        sup._wal_log("add", "3.3.3.3")
        entries = self._read_entries()
        self.assertEqual(
            [(e["op"], e["target"]) for e in entries],
            [("add", "1.1.1.1"), ("remove", "2.2.2.2"),
             ("reconcile", "full"), ("add", "3.3.3.3")],
        )


# ── cmd_wal_replay determinism ──────────────────────────────────────────────

class WalReplayDeterminismTests(_WalBase):
    """cmd_wal_replay(dry_run=True) is pure: same WAL state → same output."""

    def _capture_replay(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            sup.cmd_wal_replay(dry_run=True)
        return buf.getvalue()

    def test_invariant_replay_handles_absent_wal(self):
        # No file → graceful "not found" message, no exception
        output = self._capture_replay()
        self.assertIn("not found", output.lower())

    def test_invariant_replay_handles_empty_wal(self):
        self.wal_path.touch()
        output = self._capture_replay()
        # Should produce a "0 to add, 0 to remove" summary
        self.assertIn("Net state", output)

    def test_invariant_replay_is_deterministic(self):
        """Same input → same output. Two consecutive runs MUST produce same text."""
        for i in range(3):
            sup._wal_log("add", f"10.0.0.{i}")
        first = self._capture_replay()
        second = self._capture_replay()
        self.assertEqual(first, second, "Replay output MUST be deterministic")

    def test_invariant_replay_does_not_mutate_wal(self):
        """Replay is read-only: WAL contents and size MUST be unchanged."""
        for i in range(3):
            sup._wal_log("add", f"10.0.0.{i}")
        before_content = self.wal_path.read_bytes()
        before_mtime = self.wal_path.stat().st_mtime_ns
        self._capture_replay()
        self.assertEqual(self.wal_path.read_bytes(), before_content,
                         "Replay MUST NOT mutate WAL bytes")
        # mtime check is informational — some FS round to second; bytes is the strong check

    def test_invariant_replay_robust_to_malformed_lines(self):
        """cmd_wal_replay MUST skip malformed JSON lines, not crash."""
        sup._wal_log("add", "1.1.1.1")
        # Append a malformed line directly
        with self.wal_path.open("a") as f:
            f.write("not valid json\n")
        sup._wal_log("add", "2.2.2.2")
        # Should not raise
        output = self._capture_replay()
        self.assertIn("Net state", output)


# ── cmd_wal_inspect basic execution ─────────────────────────────────────────

class WalInspectTests(_WalBase):
    def _capture_inspect(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            sup.cmd_wal_inspect()
        return buf.getvalue()

    def test_invariant_inspect_handles_absent_wal(self):
        output = self._capture_inspect()
        self.assertIn("not found", output.lower())

    def test_invariant_inspect_reports_entry_count(self):
        for i in range(5):
            sup._wal_log("add", f"10.0.0.{i}")
        output = self._capture_inspect()
        self.assertIn("Total entries: 5", output)

    def test_invariant_inspect_robust_to_malformed_lines(self):
        sup._wal_log("add", "1.1.1.1")
        with self.wal_path.open("a") as f:
            f.write("garbage line\n")
        sup._wal_log("add", "2.2.2.2")
        output = self._capture_inspect()
        self.assertIn("Total entries: 2", output, "Valid entries counted")
        self.assertIn("parse errors: 1", output, "Malformed lines reported")


if __name__ == "__main__":
    unittest.main()
