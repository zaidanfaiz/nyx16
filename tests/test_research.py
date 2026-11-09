"""Regression tests for reproducible report generation, using only synthetic plists."""
import csv
import json
import plistlib
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from nyx16.research import EvidenceError, build_reports, manifest_rows, read_plist

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / "evidence" / "secure_boot_sources.json"


class ResearchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "manifests"
        self.root.mkdir()
        self.out = Path(self.tmp.name) / "reports"
        self.manifest = {
            "ProductVersion": "17.0",
            "ProductBuildVersion": "21A329",
            "SupportedProductTypes": ["iPhone13,2", "iPhone13,3"],
            "BuildIdentities": [{"Info": {"DeviceClass": "d53gap"}}],
        }

    def save(self):
        path = self.root / "sample.plist"
        path.write_bytes(plistlib.dumps(self.manifest))
        return path

    def test_empty_reports_are_explicitly_inconclusive(self):
        result = build_reports(self.root, SOURCES, self.out)
        self.assertEqual(result["manifest_count"], 0)
        self.assertEqual(result["unsigned_downgrade"], "NOT_DEMONSTRATED")
        self.assertIn("No real BuildManifest", (self.out / "RESEARCH_SUMMARY.md").read_text())
        self.assertEqual(len(list(csv.DictReader((self.out / "soc_research_matrix.csv").open()))), 6)

    def test_a17_pro_reported_as_research_only(self):
        result = build_reports(self.root, SOURCES, self.out)
        self.assertIn("A17 Pro", result["soc_families"])
        self.assertEqual(result["apple_signing_status"], "NOT_CHECKED")

    def test_manifest_generates_identity_row_without_guessing_pairing(self):
        self.save()
        result = build_reports(self.root, SOURCES, self.out)
        self.assertEqual(result["manifest_count"], 1)
        self.assertEqual(result["build_identity_rows"], 1)
        rows = list(csv.DictReader((self.out / "firmware_manifest_matrix.csv").open()))
        self.assertEqual(rows[0]["product_board_pairing"], "NOT_ESTABLISHED")
        self.assertEqual(rows[0]["identity_board"], "d53gap")
        self.assertEqual(rows[0]["apple_signing"], "NOT_CHECKED")

    def test_pairing_only_when_declared_within_identity(self):
        self.manifest["BuildIdentities"][0]["Info"]["ProductType"] = "iPhone13,2"
        self.save()
        _, rows = manifest_rows(self.root)
        self.assertEqual(rows[0]["product_board_pairing"], "DECLARED_IN_IDENTITY")

    def test_invalid_plist_rejected(self):
        (self.root / "bad.plist").write_bytes(b"not a plist")
        with self.assertRaises(EvidenceError):
            manifest_rows(self.root)

    def test_missing_build_identities_rejected(self):
        del self.manifest["BuildIdentities"]
        self.save()
        with self.assertRaises(EvidenceError):
            manifest_rows(self.root)

    def test_large_manifest_rejected(self):
        (self.root / "large.plist").write_bytes(b"x" * (10 * 1024 * 1024 + 1))
        with self.assertRaises(EvidenceError):
            manifest_rows(self.root)

    def test_source_evidence_report_has_citations(self):
        build_reports(self.root, SOURCES, self.out)
        doc = (self.out / "secure_boot_evidence.md").read_text()
        self.assertIn("https://support.apple.com/", doc)
        self.assertIn("NOT_PERFORMED", doc)

    def test_summary_json_records_hash(self):
        self.save()
        build_reports(self.root, SOURCES, self.out)
        report = json.loads((self.out / "research_summary.json").read_text())
        self.assertEqual(len(report["input_inventory"][0]["sha256"]), 64)

    def test_reject_symlink(self):
        link = self.root / "symlink.plist"
        link.symlink_to(Path(__file__))
        with self.assertRaises(EvidenceError):
            manifest_rows(self.root)


if __name__ == "__main__":
    unittest.main()
