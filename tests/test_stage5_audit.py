"""Network-free Nyx16 Stage 5 audit tests; never touches USB or Apple TSS."""
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import stage5_audit as stage5


def fixture_stage4():
    return {
        "experiment": "NYX16_STAGE4_IPHONE11",
        "status": "METADATA_MATCH_ONLY",
        "device_mode": "NORMAL", "connected_device": "iPhone 11",
        "target": dict(stage5.EXPECTED),
        "checks": {key: "MATCH" for key in stage5.REQUIRED_STAGE4_CHECKS},
        "apple_signing": "NOT_CHECKED",
        "sep_baseband_cross_version_compatibility": "UNKNOWN",
        "unsigned_downgrade": "NOT_DEMONSTRATED",
        "device_modified": False,
        "installed_baseband_version": "8.00.00",
        "compared_manifest_digest_statuses": {
            "MANIFEST_DIGEST_FIELDS_DIFFER": 24,
            "DIGEST_FIELDS_INSUFFICIENT": 4,
        },
    }


def fixture_snapshot():
    return {
        "evidence_type": "THIRD_PARTY_PUBLIC_CATALOG_SNAPSHOT",
        "device": "iPhone12,1",
        "current_version": "27.2",
        "current_build": "24B119",
        "target_version": "26.1",
        "target_build": "23B85",
        "observed_date": "2026-11-09",
        "current_catalog_status": "SIGNED",
        "target_catalog_status": "UNSIGNED",
        "source_urls": [
            "https://ipsw.me/download/iPhone12%2C1/24B119/",
            "https://ipsw.me/download/iPhone12%2C1/23B85/",
        ],
    }


class Stage5Tests(unittest.TestCase):
    def evaluate(self, stage4=None, snapshot=None):
        return stage5.assess(
            fixture_stage4() if stage4 is None else stage4,
            fixture_snapshot() if snapshot is None else snapshot,
            hashlib.sha256(b"fixture").hexdigest(),
        )

    def test_reproducible_no_go_for_iphone11(self):
        out = self.evaluate()
        self.assertEqual(out["decision"], "NO_GO_UNSIGNED_TARGET")
        self.assertTrue(out["stage4_prerequisites_passed"])
        self.assertEqual(out["signing_evidence"]["target_status_as_reported"], "UNSIGNED")
        self.assertEqual(out["signing_evidence"]["personalized_restore_authorization"], "NOT_CHECKED")
        self.assertEqual(out["sep_cross_version_compatibility"], "UNKNOWN")
        self.assertEqual(out["baseband_cross_version_compatibility"], "UNKNOWN")
        self.assertEqual(out["unsigned_downgrade"], "NOT_DEMONSTRATED")
        self.assertFalse(out["device_modified"])

    def test_missing_one_of_thirteen_checks_stops(self):
        inp = fixture_stage4()
        inp["checks"]["device_board"] = "MISMATCH"
        out = self.evaluate(stage4=inp)
        self.assertEqual(out["decision"], "NO_GO_INSUFFICIENT_OR_INVALID_EVIDENCE")
        self.assertTrue(any("device_board" in issue for issue in out["stage4_issues"]))

    def test_wrong_product_stops(self):
        inp = fixture_stage4()
        inp["target"]["product_type"] = "iPhone13,2"
        self.assertEqual(self.evaluate(stage4=inp)["decision"], "NO_GO_INSUFFICIENT_OR_INVALID_EVIDENCE")

    def test_wrong_build_stops(self):
        inp = fixture_stage4()
        inp["target"]["target_build"] = "23Z999"
        self.assertEqual(self.evaluate(stage4=inp)["decision"], "NO_GO_INSUFFICIENT_OR_INVALID_EVIDENCE")

    def test_fake_signing_claim_stops(self):
        inp = fixture_stage4()
        inp["apple_signing"] = "SIGNED"
        self.assertEqual(self.evaluate(stage4=inp)["decision"], "NO_GO_INSUFFICIENT_OR_INVALID_EVIDENCE")

    def test_stage4_claims_downgrade_supported_stops(self):
        inp = fixture_stage4()
        inp["unsigned_downgrade"] = "SUPPORTED"
        self.assertEqual(self.evaluate(stage4=inp)["decision"], "NO_GO_INSUFFICIENT_OR_INVALID_EVIDENCE")

    def test_signed_catalog_does_not_authorize_restore(self):
        snap = fixture_snapshot()
        snap["target_catalog_status"] = "SIGNED"
        out = self.evaluate(snapshot=snap)
        self.assertEqual(out["decision"], "HOLD_UNVERIFIED_ELIGIBILITY")
        self.assertEqual(out["signing_evidence"]["personalized_restore_authorization"], "NOT_CHECKED")

    def test_incorrect_snapshot_device_stops(self):
        snap = fixture_snapshot()
        snap["device"] = "iPhone13,2"
        self.assertEqual(self.evaluate(snapshot=snap)["decision"], "NO_GO_INSUFFICIENT_OR_INVALID_EVIDENCE")

    def test_invalid_snapshot_source_stops(self):
        snap = fixture_snapshot()
        snap["source_urls"] = ["http://evil.test/not-ipsw"]
        self.assertEqual(self.evaluate(snapshot=snap)["decision"], "NO_GO_INSUFFICIENT_OR_INVALID_EVIDENCE")

    def test_stale_snapshot_is_labeled(self):
        out = self.evaluate()
        self.assertIn("catalog_stale_over_7_days", out["signing_evidence"])

    def test_invalid_manifest_count_stops(self):
        inp = fixture_stage4()
        inp["compared_manifest_digest_statuses"]["MANIFEST_DIGEST_FIELDS_DIFFER"] = -9
        self.assertEqual(self.evaluate(stage4=inp)["decision"], "NO_GO_INSUFFICIENT_OR_INVALID_EVIDENCE")

    def test_report_markdown_is_clear_about_limits(self):
        report = self.evaluate()
        markdown = stage5.render_markdown(report)
        self.assertIn("NO_GO_UNSIGNED_TARGET", markdown)
        self.assertIn("NOT DEMONSTRATED", markdown)
        self.assertIn("NOT CHECKED", markdown)
        self.assertIn("SEP and baseband cross-version compatibility", markdown)

    def test_load_json_rejects_non_object(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "test.json"
            p.write_text("[]")
            with self.assertRaises(stage5.AuditError):
                stage5.load_json(p)

    def test_load_json_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            original = Path(tmp) / "original.json"
            original.write_text("{}")
            alias = Path(tmp) / "alias.json"
            alias.symlink_to(original)
            with self.assertRaises(stage5.AuditError):
                stage5.load_json(alias)

    def test_cli_writes_report_from_local_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stage4_file = root / "stage4.json"
            snap_file = root / "catalog.json"
            output = root / "output"
            stage4_file.write_text(json.dumps(fixture_stage4()))
            snap_file.write_text(json.dumps(fixture_snapshot()))
            with patch("builtins.print"):
                exit_code = stage5.main([
                    "--stage4", str(stage4_file),
                    "--catalog", str(snap_file),
                    "--out", str(output),
                ])
            self.assertEqual(exit_code, 0)
            report = json.loads((output / "stage5_feasibility.json").read_text())
            self.assertEqual(report["decision"], "NO_GO_UNSIGNED_TARGET")
            self.assertTrue((output / "STAGE5_FEASIBILITY.md").is_file())


if __name__ == "__main__":
    unittest.main()
