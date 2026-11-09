"""Synthetic, network-free regression tests for version comparison."""
import plistlib
import tempfile
import unittest
from pathlib import Path
from sys import path

path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from nyx16.compare import (
    ComparisonError, category, compare, component_comparison, write_report
)


def make_manifest(version, build, *, digest=b"old", sep=True, board="N104AP",
                  variant="Customer Erase Install (IPSW)"):
    components = {
        "iBSS": {"Digest": b"ibss", "Info": {"Path": "Firmware/dfu/iBSS.img4"}},
        "BasebandFirmware": {"Digest": b"baseband", "Info": {"Path": "Firmware/baseband.bbfw"}},
        "KernelCache": {"Digest": b"kernel", "Info": {"Path": "kernelcache.release"}},
    }
    if sep:
        components["SEP"] = {"Digest": digest, "Info": {"Path": "Firmware/sep-firmware.img4"}}
    return {
        "ProductVersion": version,
        "ProductBuildVersion": build,
        "SupportedProductTypes": ["iPhone12,1"],
        "BuildIdentities": [
            {"Info": {"DeviceClass": board, "Variant": variant}, "Manifest": components}
        ],
    }


class ComparisonTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.current = root / "current.plist"
        self.target = root / "target.plist"
        self.out = root / "out"
        self.current.write_bytes(plistlib.dumps(make_manifest("27.2", "24B119")))
        self.target.write_bytes(plistlib.dumps(make_manifest("26.1", "23B85")))

    def test_component_categories(self):
        self.assertEqual(category("SEP"), "SEP")
        self.assertEqual(category("BasebandFirmware"), "Baseband")
        self.assertEqual(category("iBSS"), "iBSS")
        self.assertEqual(category("KernelCache"), "KernelCache")
        self.assertIsNone(category("RestoreLogo"))

    def test_detects_change_without_claiming_compatibility(self):
        report = compare(self.current, self.target, board="n104ap")
        rows = {r["component_category"]: r for r in report["rows"]}
        self.assertEqual(rows["SEP"]["metadata_comparison"], "MANIFEST_DIGEST_FIELDS_MATCH")
        self.assertEqual(rows["Baseband"]["metadata_comparison"], "MANIFEST_DIGEST_FIELDS_MATCH")
        self.assertEqual(report["sep_cross_version_compatibility"], "UNKNOWN")
        self.assertEqual(report["unsigned_downgrade"], "NOT_DEMONSTRATED")
        self.assertEqual(report["apple_signing"], "NOT_CHECKED")
        self.assertEqual(report["current_board_identity_count"], 1)
        self.assertEqual(report["target_board_identity_count"], 1)

    def test_detects_changed_sep_field(self):
        self.target.write_bytes(plistlib.dumps(
            make_manifest("26.1", "23B85", digest=b"different")
        ))
        result = compare(self.current, self.target, board="N104AP")
        row = next(x for x in result["rows"] if x["component_category"] == "SEP")
        self.assertEqual(row["metadata_comparison"], "MANIFEST_DIGEST_FIELDS_DIFFER")
        self.assertEqual(row["restore_compatibility"], "UNKNOWN")

    def test_declared_component_missing(self):
        self.target.write_bytes(plistlib.dumps(
            make_manifest("26.1", "23B85", sep=False)
        ))
        report = compare(self.current, self.target, board="N104AP")
        sep = next(x for x in report["rows"] if x["component_category"] == "SEP")
        self.assertEqual(sep["metadata_comparison"], "DECLARATION_DIFFERS")

    def test_no_manifest_entry_in_either_is_inconclusive(self):
        result = compare(self.current, self.target, board="N104AP")
        row = next(x for x in result["rows"] if x["component_category"] == "iBoot")
        self.assertEqual(row["metadata_comparison"], "NOT_DECLARED_IN_EITHER_MANIFEST")

    def test_fails_closed_on_other_product(self):
        data = make_manifest("26.1", "23B85")
        data["SupportedProductTypes"] = ["iPhone13,2"]
        self.target.write_bytes(plistlib.dumps(data))
        with self.assertRaisesRegex(ComparisonError, "ProductType"):
            compare(self.current, self.target, board="N104AP")

    def test_fails_on_mismatched_build(self):
        data = make_manifest("26.1", "23B85")
        data["ProductBuildVersion"] = "999999"
        self.target.write_bytes(plistlib.dumps(data))
        with self.assertRaisesRegex(ComparisonError, "version/build"):
            compare(self.current, self.target, board="N104AP")

    def test_fails_on_wrong_board(self):
        with self.assertRaisesRegex(ComparisonError, "No matching board"):
            compare(self.current, self.target, board="D53gAP")

    def test_identity_variants_not_paired_by_array_index(self):
        different = make_manifest("26.1", "23B85", variant="Customer Update Install (IPSW)")
        self.target.write_bytes(plistlib.dumps(different))
        report = compare(self.current, self.target, board="N104AP")
        self.assertEqual(len(report["rows"]), 14)
        self.assertTrue(all(
            x["metadata_comparison"] == "IDENTITY_MISSING_OR_AMBIGUOUS"
            for x in report["rows"]
        ))

    def test_missing_digest_field_cannot_prove_match(self):
        self.assertEqual(component_comparison(
            {"SEP": {"digest_record": "NOT_DECLARED"}},
            {"SEP": {"digest_record": "NOT_DECLARED"}}
        ), "DIGEST_FIELDS_INSUFFICIENT")

    def test_write_reports(self):
        result = compare(self.current, self.target, board="N104AP")
        write_report(result, self.out)
        self.assertTrue((self.out / "iphone11_firmware_comparison.json").is_file())
        self.assertTrue((self.out / "iphone11_component_metadata_matrix.csv").is_file())
        text = (self.out / "IPHONE11_COMPARISON_SUMMARY.md").read_text()
        self.assertIn("NOT_DEMONSTRATED", text)
        self.assertIn("iOS 27.2", text)


if __name__ == "__main__":
    unittest.main()
