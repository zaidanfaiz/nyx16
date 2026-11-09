"""Offline tests: real ZIP central directory parsing over fake HTTP byte ranges."""
import io
import json
import plistlib
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from ipsw_inventory import InventoryError, inventory_preset, compare_inventories


def fixture_ipsw(version, build, *, suffix="", omit_path=False, repeated=False):
    names = {
        "iBSS": f"Firmware/dfu/iBSS.n104{suffix}.im4p",
        "iBEC": f"Firmware/dfu/iBEC.n104{suffix}.im4p",
        "SEP": f"Firmware/all_flash/sep-firmware.n104{suffix}.im4p",
        "BasebandFirmware": f"Firmware/baseband{suffix}.bbfw",
        "KernelCache": f"kernelcache.release.n104{suffix}",
    }
    components = {
        k: {"Info": ({} if omit_path and k == "SEP" else {"Path": v}), "Digest": b"test" + k.encode()}
        for k, v in names.items()
    }
    raw_manifest = plistlib.dumps({
        "ProductVersion": version, "ProductBuildVersion": build,
        "SupportedProductTypes": ["iPhone12,1"],
        "BuildIdentities": [
            {"Info": {"DeviceClass": "n104ap", "Variant": "Customer Erase Install (IPSW)"},
             "Manifest": components}
        ],
    })
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as zipf:
        zipf.writestr("BuildManifest.plist", raw_manifest)
        for path in names.values():
            zipf.writestr(path, b"test firmware placeholder" * 3)
        if repeated:
            zipf.writestr(names["iBSS"], b"duplicate")
        zipf.writestr("large-unrelated.bin", b"1" * 2_000_000)
    return output.getvalue(), raw_manifest


class FakeFetcher:
    def __init__(self, content):
        self.content = content
        self.calls = []

    def __call__(self, url, start, end):
        self.calls.append((start, end))
        return self.content[start:end+1], len(self.content)


class IPSWInventoryTests(unittest.TestCase):
    def do_inventory(self, preset, suffix="", omit_path=False, repeated=False):
        version, build = ("27.2", "24B119") if "27.2" in preset else ("26.1", "23B85")
        raw, manifest = fixture_ipsw(version, build, suffix=suffix, omit_path=omit_path, repeated=repeated)
        with tempfile.TemporaryDirectory() as d:
            manifest_file = Path(d) / "BuildManifest.plist"
            manifest_file.write_bytes(manifest)
            fetched = FakeFetcher(raw)
            result = inventory_preset(preset, expected_manifest=manifest_file, fetcher=fetched)
            return result, fetched, raw

    def test_only_directory_and_manifest_are_read(self):
        result, fetched, raw = self.do_inventory("iphone11-ios27.2")
        self.assertEqual(result["ios_version"], "27.2")
        self.assertEqual(result["board"], "N104AP")
        self.assertFalse(result["firmware_binary_content_read"])
        self.assertFalse(result["full_ipsw_hash_verified"])
        self.assertLess(result["http_bytes_transferred"], len(raw))
        self.assertEqual(result["archive_zip_entries"], 7)
        self.assertEqual(len(result["records"]), 5)
        self.assertTrue(all(r["path_status"] == "PATH_IN_ARCHIVE_INDEX" for r in result["records"]))
        self.assertEqual(result["apple_signing"], "NOT_CHECKED")

    def test_missing_manifest_path_is_explicit(self):
        result, _, _ = self.do_inventory("iphone11-ios26.1", omit_path=True)
        row = next(r for r in result["records"] if r["component_key"] == "SEP")
        self.assertEqual(row["path_status"], "PATH_NOT_DECLARED")
        self.assertIsNone(row["uncompressed_bytes"])

    def test_duplicate_archive_member_is_ambiguous(self):
        result, _, _ = self.do_inventory("iphone11-ios26.1", repeated=True)
        row = next(r for r in result["records"] if r["component_key"] == "iBSS")
        self.assertEqual(row["path_status"], "AMBIGUOUS_DUPLICATE_ARCHIVE_PATH")

    def test_comparison_detects_path_changes_and_safe_states(self):
        newer, _, _ = self.do_inventory("iphone11-ios27.2")
        older, _, _ = self.do_inventory("iphone11-ios26.1", suffix=".old")
        report = compare_inventories(newer, older)
        self.assertEqual(report["comparison_counts"]["COMPONENT_PATH_DIFFERS"], 5)
        self.assertFalse(report["firmware_binaries_downloaded"])
        self.assertEqual(report["sep_baseband_compatibility"], "UNKNOWN")
        self.assertEqual(report["unsigned_downgrade"], "NOT_DEMONSTRATED")

    def test_matching_entry_metadata_does_not_claim_matching_binary(self):
        newer, _, _ = self.do_inventory("iphone11-ios27.2")
        older, _, _ = self.do_inventory("iphone11-ios26.1")
        report = compare_inventories(newer, older)
        self.assertEqual(report["comparison_counts"]["ZIP_ENTRY_METADATA_MATCH_NOT_BINARY_VERIFIED"], 5)

    def test_comparison_detects_missing_path(self):
        newer, _, _ = self.do_inventory("iphone11-ios27.2")
        older, _, _ = self.do_inventory("iphone11-ios26.1", omit_path=True)
        report = compare_inventories(newer, older)
        self.assertEqual(report["comparison_counts"]["ZIP_PATH_NOT_VERIFIED_IN_BOTH"], 1)

    def test_invalid_version_rejected(self):
        raw, _ = fixture_ipsw("99.1", "24B119")
        with self.assertRaisesRegex(ValueError, "version/build"):
            inventory_preset("iphone11-ios27.2", fetcher=FakeFetcher(raw))

    def test_wrong_or_changed_local_manifest_rejected(self):
        raw, _ = fixture_ipsw("27.2", "24B119")
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "wrong.plist"
            path.write_bytes(b"not a matching manifest")
            with self.assertRaisesRegex(InventoryError, "differs"):
                inventory_preset("iphone11-ios27.2", expected_manifest=path, fetcher=FakeFetcher(raw))

    def test_forged_comparison_source_rejected(self):
        newer, _, _ = self.do_inventory("iphone11-ios27.2")
        older, _, _ = self.do_inventory("iphone11-ios26.1")
        older["ios_version"] = "27.2"
        with self.assertRaisesRegex(InventoryError, "provenance"):
            compare_inventories(newer, older)

    def test_only_iPhone11_presets_accepted(self):
        with self.assertRaisesRegex(InventoryError, "iPhone 11"):
            inventory_preset("iphone12-ios26.1")


if __name__ == "__main__":
    unittest.main()
