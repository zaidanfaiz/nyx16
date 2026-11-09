"""Synthetic tests; no real iPhone connection, USB, or live signing calls."""
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import mac_verify

HASH_CURRENT = "8de323d663b8fcb69b7bc852be5a43cecfe5a3235577c81fcd4c56cba62289b2"
HASH_TARGET = "c32b39f91ac8c835e1e8dbe776b21421ad36ff1650f67a624371c0ed25f4500d"


def fixtures():
    target = mac_verify.EXPECTED
    comparison = {
        **target,
        "current_manifest_sha256": HASH_CURRENT,
        "target_manifest_sha256": HASH_TARGET,
        "apple_signing": "NOT_CHECKED",
        "sep_cross_version_compatibility": "UNKNOWN",
        "baseband_cross_version_compatibility": "UNKNOWN",
        "unsigned_downgrade": "NOT_DEMONSTRATED",
        "comparisons": {"MANIFEST_DIGEST_FIELDS_DIFFER": 24, "DIGEST_FIELDS_INSUFFICIENT": 4},
    }
    current = {
        "manifest_sha256": HASH_CURRENT, "ios_version": "27.2", "build_version": "24B119",
        "product_type_checked": "iPhone12,1",
        "source_url": "https://updates.cdn-apple.com/current.ipsw",
    }
    older = {
        "manifest_sha256": HASH_TARGET, "ios_version": "26.1", "build_version": "23B85",
        "product_type_checked": "iPhone12,1",
        "source_url": "https://updates.cdn-apple.com/target.ipsw",
    }
    return dict(zip(mac_verify.REQUIRED, (comparison, current, older)))


def device():
    return {
        "mode": "NORMAL",
        "observed": {"ProductType": "iPhone12,1", "HardwareModel": "N104AP",
                     "ProductVersion": "27.2", "BuildVersion": "24B119",
                     "BasebandVersion": "8.00.00"},
        "device_identification": {"device": "iPhone 11"},
    }


class MacVerifyTests(unittest.TestCase):
    def test_matching_report_and_real_identity_is_metadata_only(self):
        result = mac_verify.compare_artifact_to_device(fixtures(), device())
        self.assertEqual(result["status"], "METADATA_MATCH_ONLY")
        self.assertEqual(result["unsigned_downgrade"], "NOT_DEMONSTRATED")
        self.assertFalse(result["device_modified"])
        self.assertEqual(result["installed_baseband_version"], "8.00.00")

    def test_wrong_phone_model_stops(self):
        d = device()
        d["observed"]["ProductType"] = "iPhone13,2"
        self.assertEqual(mac_verify.compare_artifact_to_device(fixtures(), d)["status"], "MISMATCH_STOP")

    def test_wrong_installed_version_stops(self):
        d = device()
        d["observed"]["ProductVersion"] = "26.1"
        self.assertEqual(mac_verify.compare_artifact_to_device(fixtures(), d)["status"], "MISMATCH_STOP")

    def test_missing_usb_access_is_inconclusive(self):
        d = device()
        d["mode"] = "USB_VISIBLE_NOT_PAIRED"
        self.assertEqual(
            mac_verify.compare_artifact_to_device(fixtures(), d)["status"],
            "INCONCLUSIVE_DEVICE_ACCESS",
        )

    def test_swapped_sources_stops(self):
        records = fixtures()
        records[mac_verify.REQUIRED[1]], records[mac_verify.REQUIRED[2]] = (
            records[mac_verify.REQUIRED[2]], records[mac_verify.REQUIRED[1]]
        )
        self.assertEqual(
            mac_verify.compare_artifact_to_device(records, device())["status"], "MISMATCH_STOP"
        )

    def test_source_not_on_apple_cdn_stops(self):
        records = fixtures()
        records["current_ipsw_source.json"]["source_url"] = "https://not-apple.example/firmware.ipsw"
        self.assertEqual(
            mac_verify.compare_artifact_to_device(records, device())["status"], "MISMATCH_STOP"
        )

    def test_false_downgrade_claim_stops(self):
        records = fixtures()
        records["iphone11_firmware_comparison.json"]["unsigned_downgrade"] = "SUPPORTED"
        self.assertEqual(
            mac_verify.compare_artifact_to_device(records, device())["status"], "MISMATCH_STOP"
        )

    def test_extracted_folder_works_without_rezipping(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "nyx16-iphone11-27_2-vs-26_1-3"
            root.mkdir()
            for name, value in fixtures().items():
                (root / name).write_text(json.dumps(value), encoding="utf-8")
            loaded = mac_verify.read_artifact(root)
            self.assertEqual(loaded["iphone11_firmware_comparison.json"]["target_ios"], "26.1")

    def test_zip_works(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "nyx16-iphone11-27_2-vs-26_1-2.zip"
            with zipfile.ZipFile(path, "w") as z:
                for name, value in fixtures().items():
                    z.writestr(name, json.dumps(value))
            loaded = mac_verify.read_artifact(path)
            self.assertEqual(loaded["current_ipsw_source.json"]["build_version"], "24B119")

    def test_autodetect_latest_download(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            path = root / "nyx16-iphone11-27_2-vs-26_1-3"
            path.mkdir()
            self.assertEqual(mac_verify.locate_artifact(downloads=d), path)

    def test_reject_oversized_member(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "bad.zip"
            with zipfile.ZipFile(path, "w") as z:
                z.writestr("iphone11_firmware_comparison.json", "X" * (2 * 1024 * 1024 + 1))
            with self.assertRaises(mac_verify.VerificationError):
                mac_verify.read_artifact(path)

    def test_missing_report(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(mac_verify.VerificationError):
                mac_verify.locate_artifact(downloads=d)

    def test_probe_called_only_after_artifact_read(self):
        with tempfile.TemporaryDirectory() as d:
            with patch("mac_verify.probe") as fake:
                status = mac_verify.main(["--report", str(Path(d) / "missing.zip")])
                self.assertEqual(status, 1)
                fake.assert_not_called()


if __name__ == "__main__":
    unittest.main()
