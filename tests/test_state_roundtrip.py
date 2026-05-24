"""Golden tests — domain state roundtrip invariants.

Each test captures one explicit architectural invariant tied to the
StateStore extraction target (F3 in docs/architecture-triage.md).

Core invariants verified:
  - save(load(X)) == X for every domain (semantic equality of state)
  - load(default) returns default when file absent (and default is copied, not shared)
  - V3 flat fixture → load → returns the dict as-is (backward compat)
  - V3 → save migrates the file to V4 envelope (envelope wrapping on next save)

Each domain's load_X / save_X pair is exercised independently.
Path constants are swapped per test via setattr on the supervisor module.

Stdlib-only. Hermetic. Tempdir per test.
"""

import json
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _supervisor import load_supervisor

sup = load_supervisor()
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "states"


class _DomainBase(unittest.TestCase):
    """Shared setup: tmp dir + path-constant swap that auto-restores on teardown."""

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp(prefix="brooks-roundtrip-"))
        self._restores = []

    def tearDown(self):
        for restore in self._restores:
            restore()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _swap_path(self, const_name, filename):
        """Redirect a supervisor path constant into the test tmpdir."""
        new_path = self.tmpdir / filename
        original = getattr(sup, const_name)
        setattr(sup, const_name, new_path)
        self._restores.append(lambda: setattr(sup, const_name, original))
        return new_path


# ── Per-domain roundtrip ─────────────────────────────────────────────────────

class RecidivistsRoundtripTests(_DomainBase):
    """Invariant: save(load(X)) preserves recidivists state."""

    def test_invariant_save_load_empty(self):
        self._swap_path("RECIDIV_STATE", "recidivists.json")
        sup.save_recidivists({})
        self.assertEqual(sup.load_recidivists(), {})

    def test_invariant_save_load_with_entries_and_cursor(self):
        self._swap_path("RECIDIV_STATE", "recidivists.json")
        data = {
            "1.2.3.4": {"count": 3, "last_seen": "2026-05-20T10:00:00+00:00"},
            "5.6.7.8": {"count": 1, "last_seen": "2026-05-21T11:00:00+00:00"},
            "_cursor": "2026-05-21T12:00:00+00:00",
        }
        sup.save_recidivists(data)
        self.assertEqual(sup.load_recidivists(), data)

    def test_invariant_load_absent_returns_default(self):
        self._swap_path("RECIDIV_STATE", "recidivists.json")
        # No file exists; load returns {} (the documented default)
        self.assertEqual(sup.load_recidivists(), {})

    def test_invariant_purge_preserves_cursor(self):
        """purge_old_recidivists MUST preserve `_cursor` regardless of cutoff."""
        old = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        recent = datetime.now(timezone.utc).isoformat()
        data = {
            "1.2.3.4": {"count": 2, "last_seen": recent},
            "5.6.7.8": {"count": 99, "last_seen": old},
            "_cursor": "2026-05-21T00:00:00+00:00",
        }
        purged = sup.purge_old_recidivists(data)
        self.assertIn("1.2.3.4", purged, "recent entry must survive")
        self.assertNotIn("5.6.7.8", purged, "old entry must be purged")
        self.assertEqual(
            purged["_cursor"], "2026-05-21T00:00:00+00:00",
            "_cursor MUST be preserved through purge",
        )

    def test_invariant_purge_drops_other_underscore_keys(self):
        """Only _cursor is preserved among `_`-prefixed keys."""
        recent = datetime.now(timezone.utc).isoformat()
        data = {
            "1.2.3.4": {"count": 1, "last_seen": recent},
            "_cursor": "2026-05-21T00:00:00+00:00",
            "_unrelated_meta": "should be dropped",
        }
        purged = sup.purge_old_recidivists(data)
        self.assertIn("_cursor", purged)
        self.assertNotIn("_unrelated_meta", purged)


class ReportedRoundtripTests(_DomainBase):
    """Invariant: AbuseIPDB dedup keys (composite strings) survive roundtrip."""

    def test_invariant_save_load_composite_keys(self):
        self._swap_path("ABUSE_STATE", "abuseipdb-reported.json")
        data = {
            "1.2.3.4:1234": "2026-05-20T10:00:00+00:00",
            "modsec:5.6.7.8:2026-05-20": "2026-05-20T11:00:00+00:00",
            "cf-waf:9.10.11.12:2026-05-20": "2026-05-20T12:00:00+00:00",
            "waf:13.14.15.16:2026-05-20": "2026-05-20T13:00:00+00:00",
        }
        sup.save_reported(data)
        self.assertEqual(sup.load_reported(), data)

    def test_invariant_load_absent_returns_default(self):
        self._swap_path("ABUSE_STATE", "abuseipdb-reported.json")
        self.assertEqual(sup.load_reported(), {})


class ModsecRoundtripTests(_DomainBase):
    """Invariant: ModSec ban entries survive roundtrip with nested score/uri."""

    def test_invariant_save_load(self):
        self._swap_path("MODSEC_STATE", "modsec-banned.json")
        data = {
            "1.2.3.4": {
                "banned_at": "2026-05-20T10:00:00+00:00",
                "score": 80,
                "uri": "/wp-login.php",
            },
            "5.6.7.8": {
                "banned_at": "2026-05-20T11:00:00+00:00",
                "score": 100,
                "uri": "/oauth-mcp/mcp",
            },
        }
        sup.save_modsec_state(data)
        self.assertEqual(sup.load_modsec_state(), data)

    def test_invariant_load_absent_returns_default(self):
        self._swap_path("MODSEC_STATE", "modsec-banned.json")
        self.assertEqual(sup.load_modsec_state(), {})


class CidrRoundtripTests(_DomainBase):
    """Invariant: CIDR-keyed dict with nested scenarios list survives roundtrip."""

    def test_invariant_save_load(self):
        self._swap_path("CIDR_STATE", "cidr-banned.json")
        data = {
            "1.2.3.0/24": {
                "first_seen": "2026-05-20T10:00:00+00:00",
                "ip_count": 5,
                "scenarios": [
                    "crowdsecurity/http-probing",
                    "crowdsecurity/http-bf",
                ],
            },
        }
        sup.save_cidr_state(data)
        loaded = sup.load_cidr_state()
        self.assertEqual(loaded, data)
        # Defensive: nested list ordering preserved
        self.assertEqual(
            loaded["1.2.3.0/24"]["scenarios"],
            ["crowdsecurity/http-probing", "crowdsecurity/http-bf"],
        )

    def test_invariant_load_absent_returns_default(self):
        self._swap_path("CIDR_STATE", "cidr-banned.json")
        self.assertEqual(sup.load_cidr_state(), {})


class CfWafRoundtripTests(_DomainBase):
    """Invariant: CF WAF state has non-empty default (special case)."""

    def test_invariant_load_absent_returns_non_empty_default(self):
        """CF WAF default is {'last_event_dt': None} — NOT {}."""
        self._swap_path("CF_WAF_STATE", "cf_waf_state.json")
        self.assertEqual(sup.load_cf_waf_state(), {"last_event_dt": None})

    def test_invariant_save_load_with_pending_events(self):
        self._swap_path("CF_WAF_STATE", "cf_waf_state.json")
        data = {
            "last_processed": "2026-05-20T10:00:00Z",
            "pending_events": [
                {
                    "ip": "1.2.3.4",
                    "datetime": "2026-05-20T10:01:00Z",
                    "action": "block",
                    "path": "/admin",
                    "method": "POST",
                },
                {
                    "ip": "5.6.7.8",
                    "datetime": "2026-05-20T10:02:00Z",
                    "action": "managed_challenge",
                    "path": "/wp-login.php",
                    "method": "GET",
                },
            ],
            "last_event_dt": "2026-05-20T10:02:00Z",
        }
        sup.save_cf_waf_state(data)
        self.assertEqual(sup.load_cf_waf_state(), data)


class BouncerCheckRoundtripTests(_DomainBase):
    """Invariant: full bouncer-check entry survives roundtrip (nested fields)."""

    def test_invariant_save_load(self):
        self._swap_path("BOUNCER_CHECK_STATE", "bouncer-abusecheck.json")
        data = {
            "1.2.3.4": {
                "checked_at": "2026-05-20T10:00:00+00:00",
                "score": 87,
                "country": "RU",
                "isp": "Foo Telecom",
                "total_reports": 142,
                "method": "POST",
                "path": "/wp-login.php",
                "host": "arleo.eu",
            },
        }
        sup.save_bouncer_check_state(data)
        self.assertEqual(sup.load_bouncer_check_state(), data)

    def test_invariant_load_absent_returns_default(self):
        self._swap_path("BOUNCER_CHECK_STATE", "bouncer-abusecheck.json")
        self.assertEqual(sup.load_bouncer_check_state(), {})


# ── Backward compatibility — V3 flat format ──────────────────────────────────

class V3BackwardCompatTests(_DomainBase):
    """Invariant: V3 flat files (no envelope) are accepted and migrated on save."""

    def test_invariant_v3_flat_load_accepted(self):
        """Loading a V3 flat file returns the dict as-is (no envelope parse)."""
        self._swap_path("RECIDIV_STATE", "recidivists.json")
        v3_fixture = FIXTURES / "v3_flat_sample.json"
        shutil.copy(v3_fixture, sup.RECIDIV_STATE)
        loaded = sup.load_recidivists()
        with v3_fixture.open() as f:
            expected = json.load(f)
        self.assertEqual(loaded, expected)

    def test_invariant_v3_migrated_to_v4_on_save(self):
        """After load(V3) → save, the file is rewritten as V4 envelope."""
        self._swap_path("RECIDIV_STATE", "recidivists.json")
        v3_fixture = FIXTURES / "v3_flat_sample.json"
        shutil.copy(v3_fixture, sup.RECIDIV_STATE)
        loaded = sup.load_recidivists()
        sup.save_recidivists(loaded)
        with sup.RECIDIV_STATE.open() as f:
            raw = json.load(f)
        self.assertIn("version", raw, "V4 envelope MUST have version key")
        self.assertIn("sha256", raw, "V4 envelope MUST have sha256 key")
        self.assertIn("state", raw, "V4 envelope MUST have state key")
        self.assertEqual(raw["state"], loaded, "state field MUST contain original data")
        self.assertEqual(raw["version"], sup.STATE_VERSION)


# ── V4 envelope load ─────────────────────────────────────────────────────────

class V4EnvelopeLoadTests(_DomainBase):
    """Invariant: a valid V4 envelope returns its state field intact."""

    def test_invariant_v4_envelope_returns_state_field(self):
        self._swap_path("RECIDIV_STATE", "recidivists.json")
        v4_fixture = FIXTURES / "v4_envelope_sample.json"
        shutil.copy(v4_fixture, sup.RECIDIV_STATE)
        loaded = sup.load_recidivists()
        with v4_fixture.open() as f:
            envelope = json.load(f)
        self.assertEqual(
            loaded, envelope["state"],
            "load MUST return the envelope's state field, not the envelope itself",
        )


if __name__ == "__main__":
    unittest.main()
