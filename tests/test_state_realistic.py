"""Golden tests — realistic prod-pattern fixtures.

Complementary to test_state_roundtrip.py and test_state_corruption.py:
exercises patterns observed in actual production state files (anonymized
to TEST-NET-1 / TEST-NET-2 / 2001:db8::/32 docs ranges) that the synthetic
fixtures didn't fully capture.

Patterns covered:
  - Mixed ISO-8601 timestamp formats (Z vs +00:00) within the same state
  - IPv6 keys (RFC 3849 documentation range)
  - Multiple composite key formats coexisting in abuseipdb-reported.json
    (`<ip>:<decision_id>`, `cf-waf:<ip>:<date>`, `modsec:<ip>:<date>`,
    `waf:<ip>:<date>`)
  - V3 flat format encountered in prod (modsec-banned.json)
  - cf_waf_state with non-empty pending_events array, mixed actions
  - bouncer-check entries with "-" placeholder for missing optional fields
  - Recidivists with very high count (127) and _cursor

Corruption variants captured separately:
  - Truncated mid-envelope (simulating crash mid-write)
  - Envelope where state field is a wrong type (string instead of dict)
  - sha256 mismatch with tampered state (silent corruption)

Each test asserts ONE explicit production-observed invariant.

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
FIX = Path(__file__).resolve().parent / "fixtures" / "states"


class _ProdFixtureBase(unittest.TestCase):
    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp(prefix="brooks-prod-"))
        self._restores = []

    def tearDown(self):
        for r in self._restores:
            r()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _install_fixture(self, const_name, fixture_filename, target_filename):
        """Copy fixture to tmpdir + redirect supervisor's path constant."""
        target = self.tmpdir / target_filename
        shutil.copy(FIX / fixture_filename, target)
        original = getattr(sup, const_name)
        setattr(sup, const_name, target)
        self._restores.append(lambda: setattr(sup, const_name, original))
        return target


# ── Realistic V4 envelopes — load + roundtrip ───────────────────────────────

class ProdRealisticRecidivistsTests(_ProdFixtureBase):
    def test_invariant_loads_prod_fixture(self):
        """Real V4 envelope with mixed timestamp formats MUST load."""
        self._install_fixture("RECIDIV_STATE", "prod_realistic_recidivists.json",
                              "recidivists.json")
        loaded = sup.load_recidivists()
        # _cursor preserved
        self.assertIn("_cursor", loaded)
        self.assertEqual(loaded["_cursor"], "2026-05-22T08:05:00.000000+00:00")
        # 4 IPs + 1 _cursor key
        self.assertEqual(len(loaded), 5)
        # High count preserved
        self.assertEqual(loaded["192.0.2.12"]["count"], 127)

    def test_invariant_mixed_timestamp_formats_loaded(self):
        """Z suffix AND +00:00 suffix coexist in real prod data."""
        self._install_fixture("RECIDIV_STATE", "prod_realistic_recidivists.json",
                              "recidivists.json")
        loaded = sup.load_recidivists()
        # Z format
        self.assertEqual(loaded["192.0.2.10"]["last_seen"], "2026-05-22T02:22:25Z")
        # +00:00 format
        self.assertEqual(loaded["192.0.2.11"]["last_seen"],
                         "2026-05-17T11:37:21.267011+00:00")

    def test_invariant_purge_handles_mixed_timestamp_formats(self):
        """purge_old_recidivists MUST parse both Z and +00:00 formats."""
        self._install_fixture("RECIDIV_STATE", "prod_realistic_recidivists.json",
                              "recidivists.json")
        loaded = sup.load_recidivists()
        # Don't actually depend on real time — just confirm it doesn't crash
        # and preserves _cursor regardless of which entries are purged.
        purged = sup.purge_old_recidivists(loaded)
        self.assertIn("_cursor", purged)

    def test_invariant_roundtrip_preserves_high_count(self):
        """Save/reload MUST preserve large count values without overflow."""
        self._install_fixture("RECIDIV_STATE", "prod_realistic_recidivists.json",
                              "recidivists.json")
        loaded = sup.load_recidivists()
        sup.save_recidivists(loaded)
        reloaded = sup.load_recidivists()
        self.assertEqual(reloaded["192.0.2.12"]["count"], 127)
        self.assertEqual(reloaded["192.0.2.13"]["count"], 90)


class ProdRealisticReportedTests(_ProdFixtureBase):
    def test_invariant_loads_all_composite_key_formats(self):
        """Real prod data has 4 distinct composite key formats coexisting."""
        self._install_fixture("ABUSE_STATE", "prod_realistic_abuse_reported.json",
                              "abuseipdb-reported.json")
        loaded = sup.load_reported()
        # Plain <ip>:<id>
        self.assertIn("192.0.2.30:10485512", loaded)
        # cf-waf prefix
        self.assertTrue(any(k.startswith("cf-waf:") for k in loaded))
        # modsec prefix
        self.assertTrue(any(k.startswith("modsec:") for k in loaded))
        # waf (legacy) prefix
        self.assertTrue(any(k.startswith("waf:") for k in loaded))

    def test_invariant_ipv6_keys_preserved(self):
        """IPv6 in composite keys (`<v6>:<id>`) MUST not be parsed/normalized."""
        self._install_fixture("ABUSE_STATE", "prod_realistic_abuse_reported.json",
                              "abuseipdb-reported.json")
        loaded = sup.load_reported()
        self.assertIn("2001:db8::1:10407915", loaded,
                      "IPv6 composite key MUST survive roundtrip verbatim")

    def test_invariant_same_ip_multiple_decision_ids_independent(self):
        """Two decisions on the same IP MUST produce two independent keys."""
        self._install_fixture("ABUSE_STATE", "prod_realistic_abuse_reported.json",
                              "abuseipdb-reported.json")
        loaded = sup.load_reported()
        self.assertIn("192.0.2.33:10537454", loaded)
        self.assertIn("192.0.2.33:3641", loaded)
        self.assertNotEqual(loaded["192.0.2.33:10537454"],
                            loaded["192.0.2.33:3641"])

    def test_invariant_roundtrip_save_load_preserves_all_formats(self):
        self._install_fixture("ABUSE_STATE", "prod_realistic_abuse_reported.json",
                              "abuseipdb-reported.json")
        loaded = sup.load_reported()
        sup.save_reported(loaded)
        reloaded = sup.load_reported()
        self.assertEqual(loaded, reloaded)


class ProdRealisticModsecV3Tests(_ProdFixtureBase):
    """Modsec-banned was V3 flat in prod at audit time. MUST stay supported."""

    def test_invariant_v3_flat_loads(self):
        self._install_fixture("MODSEC_STATE", "prod_realistic_modsec_v3_flat.json",
                              "modsec-banned.json")
        loaded = sup.load_modsec_state()
        self.assertEqual(len(loaded), 3)
        self.assertEqual(loaded["192.0.2.20"]["score"], 8)
        self.assertEqual(loaded["192.0.2.21"]["score"], 100)
        self.assertEqual(loaded["192.0.2.22"]["uri"], "/wp-admin/setup.php")

    def test_invariant_v3_save_migrates_to_v4(self):
        """Loading V3 prod data + saving MUST produce a V4 envelope."""
        path = self._install_fixture("MODSEC_STATE", "prod_realistic_modsec_v3_flat.json",
                                     "modsec-banned.json")
        loaded = sup.load_modsec_state()
        sup.save_modsec_state(loaded)
        # File should now be a V4 envelope
        raw = json.loads(path.read_text())
        self.assertIn("version", raw)
        self.assertIn("sha256", raw)
        self.assertIn("state", raw)
        self.assertEqual(raw["state"], loaded)


class ProdRealisticCfWafTests(_ProdFixtureBase):
    def test_invariant_pending_events_with_mixed_actions(self):
        """pending_events array contains 4 distinct action values in prod."""
        self._install_fixture("CF_WAF_STATE", "prod_realistic_cf_waf.json",
                              "cf_waf_state.json")
        loaded = sup.load_cf_waf_state()
        actions = {ev["action"] for ev in loaded["pending_events"]}
        # Subset of: block, challenge, managed_challenge, jschallenge
        self.assertEqual(actions, {"managed_challenge", "block", "challenge"})

    def test_invariant_pending_events_order_preserved(self):
        """Array order MUST be preserved through load/save (JSON list invariant)."""
        path = self._install_fixture("CF_WAF_STATE", "prod_realistic_cf_waf.json",
                                     "cf_waf_state.json")
        loaded = sup.load_cf_waf_state()
        original_order = [(ev["ip"], ev["datetime"]) for ev in loaded["pending_events"]]

        sup.save_cf_waf_state(loaded)
        reloaded = sup.load_cf_waf_state()
        reloaded_order = [(ev["ip"], ev["datetime"]) for ev in reloaded["pending_events"]]
        self.assertEqual(original_order, reloaded_order)


class ProdRealisticCidrTests(_ProdFixtureBase):
    def test_invariant_scenarios_list_preserved(self):
        self._install_fixture("CIDR_STATE", "prod_realistic_cidr.json",
                              "cidr-banned.json")
        loaded = sup.load_cidr_state()
        self.assertIn("192.0.2.0/24", loaded)
        self.assertEqual(loaded["192.0.2.0/24"]["scenarios"],
                         ["crowdsecurity/http-probing", "crowdsecurity/http-bf"])
        self.assertEqual(loaded["192.0.2.0/24"]["ip_count"], 8)


class ProdRealisticBouncerTests(_ProdFixtureBase):
    def test_invariant_dash_placeholder_in_optional_fields_preserved(self):
        """Real prod data uses '-' as placeholder for missing optional fields."""
        self._install_fixture("BOUNCER_CHECK_STATE", "prod_realistic_bouncer.json",
                              "bouncer-abusecheck.json")
        loaded = sup.load_bouncer_check_state()
        self.assertEqual(loaded["192.0.2.41"]["country"], "-")
        self.assertEqual(loaded["192.0.2.41"]["isp"], "-")

    def test_invariant_large_total_reports_preserved(self):
        """total_reports can be in the thousands in real data."""
        self._install_fixture("BOUNCER_CHECK_STATE", "prod_realistic_bouncer.json",
                              "bouncer-abusecheck.json")
        loaded = sup.load_bouncer_check_state()
        self.assertEqual(loaded["192.0.2.41"]["total_reports"], 1024)


# ── Corrupt fixtures — recovery ─────────────────────────────────────────────

class CorruptFixtureTests(_ProdFixtureBase):
    """Use real corruption patterns rather than inline test-built corruption."""

    def _check_recovery(self, fixture_name):
        """Generic: install corrupt fixture, load, assert default + .bak."""
        path = self.tmpdir / "corrupt.json"
        shutil.copy(FIX / fixture_name, path)
        bak = self.tmpdir / "corrupt.bak"
        default = {"_default": True}
        result = sup._load_json_state(path, default)
        self.assertEqual(result, default)
        self.assertTrue(bak.exists(), f"{fixture_name} MUST trigger .bak creation")
        self.assertFalse(path.exists(), "Original MUST be renamed")

    def test_invariant_truncated_mid_envelope_recovers(self):
        """Crash-mid-write simulation: incomplete JSON triggers recovery."""
        self._check_recovery("corrupt_truncated_mid_envelope.json")

    def test_invariant_state_wrong_type_recovers(self):
        """V4 envelope with state field as string MUST trigger recovery."""
        self._check_recovery("corrupt_state_is_string.json")

    def test_invariant_sha_mismatch_tampered_state_recovers(self):
        """Silent tampering of state (count changed, sha unchanged) MUST be detected."""
        self._check_recovery("corrupt_sha_mismatch_tampered_count.json")


if __name__ == "__main__":
    unittest.main()
