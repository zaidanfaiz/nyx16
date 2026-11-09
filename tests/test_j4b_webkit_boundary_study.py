"""J4B boundary regression tests. Does not import or run WebKit code."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from j4b_webkit_boundary_study import (
    SIGNED_C_INT_MAX, LengthBoundaryError, checked_signed_api_length,
    main, run_study
)


class J4BWebKitPatchStudyTests(unittest.TestCase):
    def test_near_the_signed_int_boundary(self):
        for value in (0, 1, SIGNED_C_INT_MAX - 1, SIGNED_C_INT_MAX):
            with self.subTest(value=value):
                self.assertEqual(checked_signed_api_length(value), value)
        for value in (-1, SIGNED_C_INT_MAX + 1, 2**32 - 1, 2**64 - 1):
            with self.subTest(value=value):
                with self.assertRaises(LengthBoundaryError):
                    checked_signed_api_length(value)

    def test_rejects_implicit_coercion(self):
        for value in (True, False, 2.5, "1", None, b"1"):
            with self.subTest(value=repr(value)):
                with self.assertRaises(LengthBoundaryError):
                    checked_signed_api_length(value)

    def test_matrix_matches_expected_and_does_not_claim_cve(self):
        result = run_study()
        self.assertEqual(result["total_cases"], 9)
        self.assertEqual(result["passed_cases"], 9)
        self.assertEqual(result["failed_cases"], 0)
        self.assertEqual(result["finding"], "PATCH_MECHANISM_MODELED_ONLY")
        self.assertFalse(result["actual_webkit_binaries_executed"])
        self.assertFalse(result["libxml2_executed"])
        self.assertFalse(result["crafted_web_content_generated"])
        self.assertFalse(result["iphone_contacted"])
        self.assertFalse(result["jailbreak_demonstrated"])
        self.assertEqual(result["ios_27_2_vulnerable"], "NOT_ESTABLISHED")
        self.assertEqual(result["public_upstream_bug"], "304140")
        self.assertNotIn("CVE-", json.dumps(result))

    def test_cli_produces_machine_readable_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "j4b.json"
            self.assertEqual(main(["--out", str(destination)]), 0)
            report = json.loads(destination.read_text(encoding="utf-8"))
            self.assertEqual(report["failed_cases"], 0)
            self.assertEqual(len(report["boundary_cases"]), 9)


if __name__ == "__main__":
    unittest.main()
