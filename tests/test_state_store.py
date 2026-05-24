"""Golden tests — envelope mechanics and atomic write guarantees.

These tests lock the contract of the future StateStore extraction (F3) at
the primitive level. They exercise `_load_json_state` / `_atomic_write_json`
and the envelope format directly, independent of any specific domain.

Invariants verified:
  - V4 envelope structure: {version, updated_at, sha256, state}
  - sha256 computed on canonical(sorted_keys, ensure_ascii=False) of state
  - sha256 covers ONLY the state field (envelope metadata mutation not detected)
  - JSON output uses indent=2 (human-readable)
  - ensure_ascii=False preserves UTF-8 literals
  - Atomic write: no .tmp file remains on success
  - Atomic write: empty input dict is valid and roundtrips
  - Re-saving same state produces the same sha256 (deterministic checksum)
  - Re-saving same state produces a different `updated_at` (timestamp moves)
  - STATE_VERSION matches the envelope's version field

Stdlib-only. Hermetic. Tempdir per test.
"""

import hashlib
import json
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _supervisor import load_supervisor

sup = load_supervisor()


class _EnvelopeBase(unittest.TestCase):
    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp(prefix="brooks-envelope-"))
        self.path = self.tmpdir / "state.json"

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)


# ── Envelope structure ──────────────────────────────────────────────────────

class EnvelopeStructureTests(_EnvelopeBase):
    def test_invariant_envelope_has_required_fields(self):
        sup._atomic_write_json(self.path, {"k": "v"})
        raw = json.loads(self.path.read_text())
        for field in ("version", "updated_at", "sha256", "state"):
            self.assertIn(field, raw, f"Envelope MUST include '{field}'")

    def test_invariant_version_matches_state_version_constant(self):
        sup._atomic_write_json(self.path, {})
        raw = json.loads(self.path.read_text())
        self.assertEqual(
            raw["version"], sup.STATE_VERSION,
            "envelope.version MUST equal STATE_VERSION at write time",
        )

    def test_invariant_state_field_equals_input(self):
        payload = {"alpha": 1, "beta": [1, 2, 3], "gamma": {"nested": True}}
        sup._atomic_write_json(self.path, payload)
        raw = json.loads(self.path.read_text())
        self.assertEqual(raw["state"], payload)

    def test_invariant_updated_at_is_iso8601_utc(self):
        sup._atomic_write_json(self.path, {})
        raw = json.loads(self.path.read_text())
        # ISO 8601 UTC has either +00:00 or Z; supervisor uses +00:00
        self.assertTrue(
            raw["updated_at"].endswith("+00:00"),
            f"updated_at MUST be UTC ISO-8601 with +00:00 suffix, got: {raw['updated_at']}",
        )

    def test_invariant_output_is_human_readable_indent(self):
        sup._atomic_write_json(self.path, {"k": "v"})
        text = self.path.read_text(encoding="utf-8")
        self.assertIn("\n", text, "output MUST be multi-line (indent=2)")
        self.assertIn('  "', text, "output MUST use 2-space indentation")


# ── Checksum invariants ─────────────────────────────────────────────────────

class ChecksumTests(_EnvelopeBase):
    def test_invariant_sha256_computed_on_canonical_state(self):
        """sha256 MUST equal sha256(json.dumps(state, sort_keys=True, ensure_ascii=False))."""
        payload = {"zebra": 1, "alpha": 2, "monkey": 3}  # deliberately unsorted
        sup._atomic_write_json(self.path, payload)
        raw = json.loads(self.path.read_text())
        expected = hashlib.sha256(
            json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()
        ).hexdigest()
        self.assertEqual(raw["sha256"], expected)

    def test_invariant_sha256_is_64_hex_chars(self):
        sup._atomic_write_json(self.path, {"k": "v"})
        raw = json.loads(self.path.read_text())
        self.assertEqual(len(raw["sha256"]), 64)
        # All hex
        int(raw["sha256"], 16)  # raises if not hex

    def test_invariant_same_state_same_sha256(self):
        """Two writes of identical state MUST produce identical sha256."""
        payload = {"k": "v"}
        sup._atomic_write_json(self.path, payload)
        first_sha = json.loads(self.path.read_text())["sha256"]
        # Wait at least 1µs so updated_at differs (but sha256 must not)
        time.sleep(0.001)
        sup._atomic_write_json(self.path, payload)
        second_sha = json.loads(self.path.read_text())["sha256"]
        self.assertEqual(
            first_sha, second_sha,
            "sha256 MUST be deterministic on the state, independent of timestamp",
        )

    def test_invariant_updated_at_changes_between_writes(self):
        """Two writes MUST produce different updated_at (no caching)."""
        payload = {"k": "v"}
        sup._atomic_write_json(self.path, payload)
        first_ts = json.loads(self.path.read_text())["updated_at"]
        time.sleep(0.001)
        sup._atomic_write_json(self.path, payload)
        second_ts = json.loads(self.path.read_text())["updated_at"]
        self.assertNotEqual(first_ts, second_ts)

    def test_invariant_sha256_changes_when_state_changes(self):
        sup._atomic_write_json(self.path, {"k": "v1"})
        sha_v1 = json.loads(self.path.read_text())["sha256"]
        sup._atomic_write_json(self.path, {"k": "v2"})
        sha_v2 = json.loads(self.path.read_text())["sha256"]
        self.assertNotEqual(sha_v1, sha_v2)


# ── UTF-8 / unicode ─────────────────────────────────────────────────────────

class UnicodeTests(_EnvelopeBase):
    def test_invariant_unicode_preserved_in_state(self):
        payload = {"name": "Café Étoilé", "ru": "Привет", "ja": "こんにちは"}
        sup._atomic_write_json(self.path, payload)
        # Raw file MUST contain literal UTF-8 chars (ensure_ascii=False)
        text = self.path.read_text(encoding="utf-8")
        self.assertIn("Café", text)
        self.assertIn("Привет", text)
        self.assertIn("こんにちは", text)
        # Roundtrip equality
        loaded = sup._load_json_state(self.path, {})
        self.assertEqual(loaded, payload)

    def test_invariant_unicode_in_keys_preserved(self):
        payload = {"clé_utf8": "value"}
        sup._atomic_write_json(self.path, payload)
        loaded = sup._load_json_state(self.path, {})
        self.assertEqual(loaded, payload)


# ── Atomic write ────────────────────────────────────────────────────────────

class AtomicWriteTests(_EnvelopeBase):
    def test_invariant_no_tmp_left_after_success(self):
        sup._atomic_write_json(self.path, {"k": "v"})
        tmps = list(self.tmpdir.glob("*.tmp"))
        self.assertEqual(
            tmps, [],
            f"No .tmp file MUST remain after successful write; found: {tmps}",
        )

    def test_invariant_empty_dict_is_valid_input(self):
        sup._atomic_write_json(self.path, {})
        raw = json.loads(self.path.read_text())
        self.assertEqual(raw["state"], {})

    def test_invariant_overwrite_replaces_prior_content(self):
        sup._atomic_write_json(self.path, {"version_1": True})
        sup._atomic_write_json(self.path, {"version_2": True})
        loaded = sup._load_json_state(self.path, {})
        self.assertEqual(loaded, {"version_2": True})
        self.assertNotIn("version_1", loaded)

    def test_invariant_previous_file_intact_when_write_fails(self):
        """If atomic write raises, the previously committed file MUST remain valid.

        Simulate failure by making the target directory un-writable AFTER the
        first successful write. The second write will fail at mkstemp; the
        first file must remain on disk and remain loadable.
        """
        sup._atomic_write_json(self.path, {"committed": True})
        first_content = self.path.read_bytes()

        # Make dir read-only so mkstemp fails
        import os
        original_mode = self.tmpdir.stat().st_mode
        try:
            os.chmod(self.tmpdir, 0o555)
            with self.assertRaises((OSError, PermissionError)):
                sup._atomic_write_json(self.path, {"should_fail": True})
        finally:
            os.chmod(self.tmpdir, original_mode)

        # File must be intact
        self.assertEqual(self.path.read_bytes(), first_content)
        loaded = sup._load_json_state(self.path, {})
        self.assertEqual(loaded, {"committed": True})


# ── Save / Load roundtrip at primitive level ────────────────────────────────

class PrimitiveRoundtripTests(_EnvelopeBase):
    def test_invariant_save_then_load_returns_state(self):
        payload = {"k1": "v1", "k2": [1, 2, 3], "k3": {"nested": True}}
        sup._atomic_write_json(self.path, payload)
        loaded = sup._load_json_state(self.path, {})
        self.assertEqual(loaded, payload)

    def test_invariant_save_load_save_is_idempotent_at_state_level(self):
        """save(load(save(X))) state-equals save(X)."""
        payload = {"k": "v", "nested": {"a": 1, "b": 2}}
        sup._atomic_write_json(self.path, payload)
        sha_1 = json.loads(self.path.read_text())["sha256"]

        loaded_1 = sup._load_json_state(self.path, {})
        sup._atomic_write_json(self.path, loaded_1)
        sha_2 = json.loads(self.path.read_text())["sha256"]

        loaded_2 = sup._load_json_state(self.path, {})
        self.assertEqual(loaded_1, loaded_2)
        self.assertEqual(sha_1, sha_2)


if __name__ == "__main__":
    unittest.main()
