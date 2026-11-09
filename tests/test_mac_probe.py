"""Synthetic regression tests for read-only macOS connected iPhone inspection."""
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import mac_probe


class MacProbeTests(unittest.TestCase):
    def test_version_comparison(self):
        self.assertEqual(mac_probe.compare_versions("27.0", "26.1"), "TARGET_OLDER_THAN_INSTALLED")
        self.assertEqual(mac_probe.compare_versions("26.1", "26.1"), "SAME_IOS_VERSION")
        self.assertEqual(mac_probe.compare_versions("26.0", "26.1"), "TARGET_NEWER_THAN_INSTALLED")
        self.assertEqual(mac_probe.compare_versions("invalid", "26.1"), "UNKNOWN")

    def test_recovery_metadata_drops_sensitive_fields(self):
        raw = "MODE: DFU\nCPID: 0x8101\nECID: 111122223333\nNONC: secret\nSRTG: secret\nMODEL: d53gap"
        self.assertEqual(mac_probe.parse_recovery(raw), {
            "mode": "DFU", "cpid": "0x8101", "model": "d53gap"
        })

    @patch("mac_probe.platform.system", return_value="Darwin")
    @patch("mac_probe.shutil.which", return_value="/opt/local/bin/tool")
    def test_normal_mode_redacts_identifiers(self, which, system):
        def execute(args):
            if args[:2] == ["idevice_id", "-l"]:
                return "SENSITIVE_DEVICE_UDID"
            lookup = {
                "ProductType": "iPhone13,2", "ProductVersion": "27.0",
                "BuildVersion": "24A123", "HardwareModel": "D53gAP",
            }
            return lookup.get(args[-1])
        with patch("mac_probe.run_command", side_effect=execute):
            report = mac_probe.probe()
        self.assertEqual(report["mode"], "NORMAL")
        self.assertEqual(report["model_match"], "MATCH")
        self.assertEqual(report["board_match"], "MATCH")
        self.assertEqual(report["version_relationship"], "TARGET_OLDER_THAN_INSTALLED")
        self.assertNotIn("SENSITIVE_DEVICE_UDID", json.dumps(report))
        self.assertFalse(report["device_modified"])

    @patch("mac_probe.platform.system", return_value="Darwin")
    @patch("mac_probe.shutil.which", return_value="/opt/local/bin/tool")
    def test_multiple_devices_not_selected(self, which, system):
        with patch("mac_probe.run_command", return_value="UDID_A\nUDID_B"):
            report = mac_probe.probe()
        self.assertEqual(report["mode"], "MULTIPLE_DEVICES")
        self.assertEqual(report["observed"], {})

    @patch("mac_probe.platform.system", return_value="Darwin")
    @patch("mac_probe.shutil.which", return_value="/opt/local/bin/tool")
    def test_unpaired_device_not_interrogated(self, which, system):
        calls = []
        def execute(args):
            calls.append(args)
            return "SENSITIVE_UDID" if args[:2] == ["idevice_id", "-l"] else None
        with patch("mac_probe.run_command", side_effect=execute):
            report = mac_probe.probe()
        self.assertEqual(report["mode"], "USB_VISIBLE_NOT_PAIRED")
        self.assertTrue(all(cmd[0] in ("idevice_id", "ideviceinfo") for cmd in calls))

    @patch("mac_probe.platform.system", return_value="Darwin")
    @patch("mac_probe.shutil.which", return_value="/opt/local/bin/tool")
    def test_recovery_mode_whitelist(self, which, system):
        def execute(args):
            return "MODE: Recovery\nCPID: 0x8101\nECID: TOP_SECRET" if args[0] == "irecovery" else ""
        with patch("mac_probe.run_command", side_effect=execute):
            report = mac_probe.probe()
        self.assertEqual(report["mode"], "RECOVERY_OR_DFU")
        self.assertNotIn("TOP_SECRET", json.dumps(report))

    def test_report_zip_comparison(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.zip"
            target = mac_probe.TARGET
            with zipfile.ZipFile(path, "w") as z:
                z.writestr("research_summary.json", json.dumps({"manifest_count": 1}))
                z.writestr("ipsw_http_source.json", json.dumps({
                    "manifest_sha256": target["manifest_sha256"],
                    "ios_version": target["target_ios"],
                    "build_version": target["target_build"],
                    "product_type_checked": target["product_type"],
                    "source_kind": "APPLE_CDN_IPSW_HTTP_RANGE",
                }))
            result = mac_probe.read_report_archive(path)
            self.assertTrue(result["report_valid_for_preset"])

    def test_report_zip_inconsistent_rejected_as_match(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.zip"
            with zipfile.ZipFile(path, "w") as z:
                z.writestr("research_summary.json", '{"manifest_count":1}')
                z.writestr("ipsw_http_source.json", '{"ios_version":"27.0"}')
            self.assertFalse(mac_probe.read_report_archive(path)["report_valid_for_preset"])

    @patch("mac_probe.platform.system", return_value="Linux")
    def test_wrong_host_no_device_calls(self, system):
        with patch("mac_probe.run_command") as execute:
            report = mac_probe.probe()
        self.assertEqual(report["mode"], "NOT_DETECTED")
        execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()
