"""Golden tests — corruption handling invariants.

Each test captures one explicit recovery invariant. The supervisor's contract
is: on any corruption, the broken file is renamed to `.bak` (auditable) and the
caller gets the documented default (operation continues, no crash, no data loss
that wasn't already present).

Invariants verified:
  - Empty file        → .bak + default
  - Invalid JSON      → .bak + default
  - Top-level not dict (list/scalar) → .bak + default
  - V4 envelope missing 'state' field → .bak + default
  - V4 envelope with non-dict 'state' → .bak + default
  - V4 envelope with sha256 mismatch  → .bak + default
  - V4 envelope with sha256 absent    → accepted (envelope partial, no validation)
  - Absent file       → default (NO .bak)
  - Default returned is COPIED (mutations don't leak across calls)
  - .bak naming: <name>.bak (overwrites prior .bak)

Stdlib-only. Hermetic. Tempdir per test.
"""

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _supervisor import load_supervisor

sup = load_supervisor()


class _CorruptionBase(unittest.TestCase):
    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp(prefix="brooks-corrupt-"))
        self.path = self.tmpdir / "state.json"
        self.bak = self.tmpdir / "state.bak"
        self.default = {"_default_marker": True, "n": 0}

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _load(self):
        # Pass a fresh copy of default so we can assert the returned value
        # equals it but is a SEPARATE object (mutation safety).
        return sup._load_json_state(self.path, self.default)


# ── Absent file ─────────────────────────────────────────────────────────────

class AbsentFileTests(_CorruptionBase):
    def test_invariant_absent_file_returns_default(self):
        result = self._load()
        self.assertEqual(result, self.default)

    def test_invariant_absent_file_does_not_create_bak(self):
        self._load()
        self.assertFalse(
            self.bak.exists(),
            "Absent file MUST NOT trigger .bak creation",
        )

    def test_invariant_default_is_copied(self):
        """Mutating the returned dict MUST NOT affect the default arg."""
        result = self._load()
        result["mutated_by_caller"] = True
        self.assertNotIn(
            "mutated_by_caller", self.default,
            "Caller mutation MUST NOT leak into the default arg",
        )


# ── Invalid JSON / unparseable ───────────────────────────────────────────────

class InvalidJsonTests(_CorruptionBase):
    def test_invariant_empty_file_triggers_recovery(self):
        self.path.write_text("")
        result = self._load()
        self.assertEqual(result, self.default)
        self.assertTrue(self.bak.exists(), "Empty file MUST create .bak")
        self.assertFalse(self.path.exists(), "Original MUST be renamed")

    def test_invariant_malformed_json_triggers_recovery(self):
        self.path.write_text("{ not valid json")
        result = self._load()
        self.assertEqual(result, self.default)
        self.assertTrue(self.bak.exists())
        self.assertFalse(self.path.exists())

    def test_invariant_invalid_utf8_triggers_recovery(self):
        self.path.write_bytes(b"\xff\xfe\xfa\xfb")  # not valid UTF-8 prefix
        result = self._load()
        self.assertEqual(result, self.default)
        self.assertTrue(self.bak.exists())


# ── Wrong top-level type ─────────────────────────────────────────────────────

class WrongTopLevelTypeTests(_CorruptionBase):
    def test_invariant_top_level_list_triggers_recovery(self):
        self.path.write_text(json.dumps([1, 2, 3]))
        result = self._load()
        self.assertEqual(result, self.default)
        self.assertTrue(self.bak.exists())

    def test_invariant_top_level_string_triggers_recovery(self):
        self.path.write_text(json.dumps("just a string"))
        result = self._load()
        self.assertEqual(result, self.default)
        self.assertTrue(self.bak.exists())

    def test_invariant_top_level_null_triggers_recovery(self):
        self.path.write_text(json.dumps(None))
        result = self._load()
        self.assertEqual(result, self.default)
        self.assertTrue(self.bak.exists())


# ── V4 envelope: structural corruption ───────────────────────────────────────

class V4StructuralCorruptionTests(_CorruptionBase):
    def test_invariant_missing_state_field_triggers_recovery(self):
        """Envelope with version key but no state field → .bak + default."""
        self.path.write_text(json.dumps({
            "version": 1,
            "updated_at": "2026-05-22T00:00:00+00:00",
            "sha256": "abc",
            # 'state' deliberately absent
        }))
        result = self._load()
        self.assertEqual(result, self.default)
        self.assertTrue(self.bak.exists())

    def test_invariant_state_is_list_triggers_recovery(self):
        """Envelope with 'state' that is a list (not dict) → .bak + default."""
        self.path.write_text(json.dumps({
            "version": 1,
            "state": [1, 2, 3],
        }))
        result = self._load()
        self.assertEqual(result, self.default)
        self.assertTrue(self.bak.exists())

    def test_invariant_state_is_string_triggers_recovery(self):
        self.path.write_text(json.dumps({
            "version": 1,
            "state": "not a dict",
        }))
        result = self._load()
        self.assertEqual(result, self.default)
        self.assertTrue(self.bak.exists())

    def test_invariant_state_is_null_triggers_recovery(self):
        self.path.write_text(json.dumps({
            "version": 1,
            "state": None,
        }))
        result = self._load()
        self.assertEqual(result, self.default)
        self.assertTrue(self.bak.exists())


# ── V4 envelope: checksum validation ────────────────────────────────────────

class V4ChecksumTests(_CorruptionBase):
    def test_invariant_sha256_mismatch_triggers_recovery(self):
        """Valid envelope but tampered sha256 → .bak + default."""
        # Build a valid envelope then flip the sha
        sup._atomic_write_json(self.path, {"key": "value"})
        envelope = json.loads(self.path.read_text())
        envelope["sha256"] = "0" * 64  # wrong
        self.path.write_text(json.dumps(envelope))
        result = self._load()
        self.assertEqual(result, self.default)
        self.assertTrue(self.bak.exists())

    def test_invariant_sha256_mismatch_after_state_tamper_triggers_recovery(self):
        """Tampering 'state' after sha256 was computed → recovery."""
        sup._atomic_write_json(self.path, {"key": "original"})
        envelope = json.loads(self.path.read_text())
        envelope["state"]["key"] = "tampered"  # state changed, sha256 not updated
        self.path.write_text(json.dumps(envelope))
        result = self._load()
        self.assertEqual(result, self.default)
        self.assertTrue(self.bak.exists())

    def test_invariant_sha256_absent_accepted(self):
        """Envelope without sha256 field MUST be accepted (no validation)."""
        self.path.write_text(json.dumps({
            "version": 1,
            "state": {"key": "value"},
            # 'sha256' deliberately absent
        }))
        result = self._load()
        self.assertEqual(result, {"key": "value"})
        self.assertFalse(self.bak.exists())

    def test_invariant_sha256_empty_string_accepted(self):
        """Envelope with sha256='' MUST be accepted (skip validation)."""
        self.path.write_text(json.dumps({
            "version": 1,
            "sha256": "",
            "state": {"key": "value"},
        }))
        result = self._load()
        self.assertEqual(result, {"key": "value"})
        self.assertFalse(self.bak.exists())


# ── .bak overwrite policy ────────────────────────────────────────────────────

class BakOverwriteTests(_CorruptionBase):
    def test_invariant_bak_is_overwritten_by_subsequent_corruption(self):
        """A second corruption MUST overwrite the previous .bak."""
        # First corruption
        self.path.write_text("first corrupt")
        self._load()
        first_bak_content = self.bak.read_text()
        self.assertEqual(first_bak_content, "first corrupt")

        # Second corruption
        self.path.write_text("second corrupt")
        self._load()
        second_bak_content = self.bak.read_text()
        self.assertEqual(
            second_bak_content, "second corrupt",
            "Subsequent corruption MUST overwrite .bak",
        )


if __name__ == "__main__":
    unittest.main()
