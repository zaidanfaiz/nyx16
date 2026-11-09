"""J4C comparison invariants: source provenance, limitations and deterministic reports."""
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from j4c_webkit_patch_compare import (
    DEFAULT_MANIFEST, EvidenceError, compare_patches, load_manifest, main,
    render_markdown,
)


class FixedWebKitPatchComparisonTests(unittest.TestCase):
    def test_four_real_fixed_issues_are_source_grounded(self):
        manifest = load_manifest()
        self.assertEqual({c["bug_id"] for c in manifest["cases"]},
                         {"304140", "289523", "297624", "308713"})
        for case in manifest["cases"]:
            with self.subTest(case=case["bug_id"]):
                self.assertTrue(case["fixed_date"] <= manifest["research_cutoff"])
                self.assertGreaterEqual(len(case["evidence_urls"]), 2)
                self.assertIn("https://commits.webkit.org/" + case["upstream_revision"],
                              case["evidence_urls"])
                self.assertTrue(case["scope_caveat"])

    def test_outputs_are_descriptive_not_exploitation_claims(self):
        manifest = load_manifest()
        report = compare_patches(manifest)
        markdown = render_markdown(manifest, report)
        self.assertEqual(report["public_fixed_upstream_issues_documented"], 4)
        self.assertEqual(len(report["issue_classes"]), 4)
        self.assertEqual(report["ios_27_2_vulnerability"], "NOT_ESTABLISHED")
        self.assertFalse(report["actual_webkit_or_iphone_execution"])
        self.assertFalse(report["jailbreak_demonstrated"])
        self.assertIn("NOT DEMONSTRATED", markdown)
        for case in manifest["cases"]:
            self.assertIn(case["bug_id"], markdown)
            self.assertIn(case["scope_caveat"], markdown)

    def test_invalid_bug_identifier_cannot_silently_pass(self):
        manifest = load_manifest()
        broken = copy.deepcopy(manifest)
        broken["cases"][1]["bug_id"] = broken["cases"][0]["bug_id"]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "invalid.json"
            path.write_text(json.dumps(broken), encoding="utf-8")
            with self.assertRaises(EvidenceError):
                load_manifest(path)

    def test_missing_evidence_or_incorrect_fix_date_rejected(self):
        manifest = load_manifest()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "invalid.json"
            for variant in ("missing_bug_url", "future_fix", "bad_claim"):
                broken = copy.deepcopy(manifest)
                if variant == "missing_bug_url":
                    broken["cases"][0]["evidence_urls"] = ["https://example.com"]
                elif variant == "future_fix":
                    broken["cases"][0]["fixed_date"] = "2099-01-01"
                else:
                    broken["finding"] = "IOS_EXPLOIT_DEMONSTRATED"
                path.write_text(json.dumps(broken), encoding="utf-8")
                with self.subTest(variant=variant), self.assertRaises(EvidenceError):
                    load_manifest(path)

    def test_cli_writes_two_reproducible_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            json_out = Path(tmp) / "comparison.json"
            md_out = Path(tmp) / "comparison.md"
            args = ["--manifest", str(DEFAULT_MANIFEST),
                    "--json-out", str(json_out), "--md-out", str(md_out)]
            self.assertEqual(main(args), 0)
            before = (json_out.read_bytes(), md_out.read_bytes())
            self.assertEqual(main(args), 0)
            self.assertEqual(before, (json_out.read_bytes(), md_out.read_bytes()))
            report = json.loads(json_out.read_text(encoding="utf-8"))
            self.assertEqual(report["finding"], "DOCUMENTARY_PATCH_COMPARISON_ONLY")


if __name__ == "__main__":
    unittest.main()
