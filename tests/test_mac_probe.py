"""Mac probe tests: all hardware inputs are simulated; no device needed."""
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import mac_probe
from device_profiles import identify_product, identify_recovery


class MacProbeTests(unittest.TestCase):
    def test_version_comparison(self):
        for current, target, expected in [
            ("27.0", "26.1", "TARGET_OLDER_THAN_INSTALLED"),
            ("26.1", "26.1", "SAME_IOS_VERSION"),
            ("26.0", "26.1", "TARGET_NEWER_THAN_INSTALLED"),
            ("invalid", "26.1", "UNKNOWN"),
        ]:
            self.assertEqual(mac_probe.compare_versions(current, target), expected)

    def test_families_across_iphone_11_to_14(self):
        for product, family, model in [
            ("iPhone12,1", "A13", "iPhone 11"),
            ("iPhone13,2", "A14", "iPhone 12"),
            ("iPhone14,5", "A15", "iPhone 13"),
            ("iPhone14,7", "A15", "iPhone 14"),
            ("iPhone15,2", "A16", "iPhone 14 Pro"),
            ("iPhone15,4", "A16", "iPhone 15"),
            ("iPhone16,1", "A17 Pro", "iPhone 15 Pro"),
            ("iPhone16,2", "A17 Pro", "iPhone 15 Pro Max"),
        ]:
            result = identify_product(product)
            self.assertEqual((result["chip_family"], result["device"]), (family, model))

    def test_a17_pro_board(self):
        self.assertEqual(identify_product("iPhone16,1", "D83AP")["board_match"], "MATCH")
        self.assertEqual(identify_product("iPhone16,2", "D84AP")["board_match"], "MATCH")
        self.assertEqual(identify_product("iPhone16,1", "D84AP")["board_match"], "MISMATCH")
        self.assertEqual(identify_recovery("0x8130"), "A17 Pro")

    def test_iphone11_board(self):
        self.assertEqual(identify_product("iPhone12,1", "N104AP")["board_match"], "MATCH")
        self.assertEqual(identify_product("iPhone12,1", "D53gAP")["board_match"], "MISMATCH")
        self.assertEqual(identify_product("iPhone12,1")["board_match"], "UNKNOWN")

    def test_unknown_model_is_unknown_not_fake_match(self):
        self.assertEqual(identify_product("iPhone99,99")["status"], "UNKNOWN")

    def test_recovery_cpid_only_identifies_family(self):
        self.assertEqual(identify_recovery("0x8030"), "A13")
        self.assertEqual(identify_recovery("0x8101"), "A14")
        self.assertEqual(identify_recovery("0x8120"), "A16")
        self.assertEqual(identify_recovery("bad"), "UNKNOWN")

    def test_recovery_redacts_sensitive_fields(self):
        raw = "MODE: DFU\nCPID: 0x8030\nECID: sensitive\nNONC: secret\nSERIAL: hidden\nMODEL: n104ap"
        self.assertEqual(mac_probe.parse_recovery(raw), {
            "mode": "DFU", "cpid": "0x8030", "model": "n104ap"
        })

    @patch("mac_probe.platform.system", return_value="Darwin")
    @patch("mac_probe.shutil.which", return_value="/opt/local/bin/tool")
    def test_iphone11_normal_auto_identification_redacts_udid(self, which, system):
        def execute(args):
            if args[:2] == ["idevice_id", "-l"]:
                return "SECRET_UDID"
            return {
                "ProductType": "iPhone12,1",
                "ProductVersion": "27.0",
                "BuildVersion": "24A123",
                "HardwareModel": "N104AP",
                "BasebandVersion": "mock-baseband",
            }.get(args[-1])
        with patch("mac_probe.run_command", side_effect=execute):
            report = mac_probe.probe()
        self.assertEqual(report["mode"], "NORMAL")
        self.assertEqual(report["device_identification"]["device"], "iPhone 11")
        self.assertEqual(report["device_identification"]["chip_family"], "A13")
        self.assertEqual(report["device_identification"]["board_match"], "MATCH")
        self.assertEqual(report["version_relationship"], "NOT_REQUESTED")
        self.assertIsNone(report["target_ios_version"])
        self.assertEqual(report["research_objective"], "FULL_JAILBREAK_A12_A17")
        self.assertEqual(report["jailbreak_status"], "NOT_DEMONSTRATED")
        self.assertEqual(report["privileged_device_file_access"], "NOT_DEMONSTRATED")
        self.assertEqual(report["dfu_code_execution"], "NOT_DEMONSTRATED")

        self.assertNotIn("SECRET_UDID", json.dumps(report))
        self.assertFalse(report["device_modified"])

    @patch("mac_probe.platform.system", return_value="Darwin")
    @patch("mac_probe.shutil.which", return_value="/opt/local/bin/tool")
    def test_legacy_version_comparison_is_opt_in(self, which, system):
        def execute(args):
            if args[:2] == ["idevice_id", "-l"]:
                return "REDACTED"
            return {
                "ProductType": "iPhone12,1", "ProductVersion": "27.2",
                "HardwareModel": "N104AP",
            }.get(args[-1])
        with patch("mac_probe.run_command", side_effect=execute):
            report = mac_probe.probe(target_ios="26.1")
        self.assertEqual(report["version_relationship"], "TARGET_OLDER_THAN_INSTALLED")
        self.assertEqual(report["jailbreak_status"], "NOT_DEMONSTRATED")

    @patch("mac_probe.platform.system", return_value="Darwin")
    @patch("mac_probe.shutil.which", return_value="/opt/local/bin/tool")
    def test_iphone14_pro_a16_normal(self, which, system):
        def execute(args):
            if args[:2] == ["idevice_id", "-l"]:
                return "SECRET_UDID"
            return {
                "ProductType": "iPhone15,2", "ProductVersion": "26.1",
                "BuildVersion": "23B85", "HardwareModel": "D73AP",
            }.get(args[-1])
        with patch("mac_probe.run_command", side_effect=execute):
            report = mac_probe.probe()
        self.assertEqual(report["device_identification"]["device"], "iPhone 14 Pro")
        self.assertEqual(report["device_identification"]["chip_family"], "A16")

    @patch("mac_probe.platform.system", return_value="Darwin")
    @patch("mac_probe.shutil.which", return_value="/opt/local/bin/tool")
    def test_multiple_devices_not_selected(self, which, system):
        with patch("mac_probe.run_command", return_value="UDID_A\nUDID_B"):
            report = mac_probe.probe()
        self.assertEqual(report["mode"], "MULTIPLE_DEVICES")

    @patch("mac_probe.platform.system", return_value="Darwin")
    @patch("mac_probe.shutil.which", return_value="/opt/local/bin/tool")
    def test_unpaired_device_does_not_try_to_pair(self, which, system):
        calls = []
        def execute(args):
            calls.append(args)
            return "SECRET_UDID" if args[:2] == ["idevice_id", "-l"] else None
        with patch("mac_probe.run_command", side_effect=execute):
            report = mac_probe.probe()
        self.assertEqual(report["mode"], "USB_VISIBLE_NOT_PAIRED")
        self.assertTrue(all(cmd[0] in ("idevice_id", "ideviceinfo") for cmd in calls))

    @patch("mac_probe.platform.system", return_value="Darwin")
    @patch("mac_probe.shutil.which", return_value="/opt/local/bin/tool")
    def test_recovery_mode_without_device_model_guess(self, which, system):
        def execute(args):
            return "MODE: Recovery\nCPID: 0x8030\nECID: HIDDEN" if args[0] == "irecovery" else ""
        with patch("mac_probe.run_command", side_effect=execute):
            report = mac_probe.probe()
        self.assertEqual(report["mode"], "RECOVERY_OR_DFU")
        self.assertEqual(report["device_identification"]["chip_family"], "A13")
        self.assertEqual(report["device_identification"]["device"], "UNKNOWN")
        self.assertNotIn("HIDDEN", json.dumps(report))

    def report_zip(self, folder):
        path = Path(folder) / "artifact.zip"
        sha = "0123456789abcdef" * 4
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("research_summary.json", json.dumps({
                "manifest_count": 1,
                "input_inventory": [{
                    "sha256": sha, "ios_version": "26.1", "build_version": "23B85",
                    "supported_product_types": ["iPhone13,2", "iPhone13,3"],
                }],
            }))
            archive.writestr("ipsw_http_source.json", json.dumps({
                "manifest_sha256": sha, "ios_version": "26.1", "build_version": "23B85",
                "product_type_checked": "iPhone13,2",
            }))
        return path

    def test_iphone11_rejects_iphone12_manifest(self):
        with tempfile.TemporaryDirectory() as folder:
            path = self.report_zip(folder)
            result = mac_probe.read_report_archive(path, product_type="iPhone12,1")
            self.assertTrue(result["report_metadata_consistent"])
            self.assertEqual(result["report_device_applicability"], "MISMATCH")

    def test_iphone12_accepts_iphone12_manifest(self):
        with tempfile.TemporaryDirectory() as folder:
            result = mac_probe.read_report_archive(self.report_zip(folder), product_type="iPhone13,2")
            self.assertEqual(result["report_device_applicability"], "MATCH")

    def test_report_does_not_claim_validity_without_source_integrity(self):
        with tempfile.TemporaryDirectory() as folder:
            path = self.report_zip(folder)
            # Tamper source manifest hash in the archived JSON without changing inventory.
            with zipfile.ZipFile(path, "a") as archive:
                archive.writestr("ipsw_http_source.json", '{"manifest_sha256":"BAD"}')
            with self.assertRaises(ValueError):
                mac_probe.read_report_archive(path, product_type="iPhone13,2")

    @patch("mac_probe.platform.system", return_value="Linux")
    def test_mac_requirement(self, system):
        with patch("mac_probe.run_command") as command:
            report = mac_probe.probe()
        self.assertEqual(report["mode"], "NOT_DETECTED")
        command.assert_not_called()


if __name__ == "__main__":
    unittest.main()
