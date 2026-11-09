"""Offline J2 entitlement parser regression tests; no Xcode or iPhone required."""
import json
import plistlib
import sys
import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from inspect_lab_entitlements import EntitlementsError, inspect_signed_app


class J2EntitlementTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.app = Path(self.tmp.name) / "Nyx16Lab.app"
        self.app.mkdir()

    def signed(self, values, returncode=0):
        plist = plistlib.dumps(values)
        def runner(cmd, **kwargs):
            self.assertEqual(cmd[:4], ["/usr/bin/codesign", "-d", "--entitlements", ":-"])
            self.assertEqual(cmd[-1], str(self.app))
            self.assertTrue(kwargs["capture_output"])
            self.assertFalse(kwargs["check"])
            return CompletedProcess(cmd, returncode, stdout=plist, stderr=b"")
        return runner

    def test_allowlisted_summary_redacts_all_identifier_values(self):
        raw = {
            "get-task-allow": True,
            "application-identifier": "SECRET_TEAM.com.nyx16.test",
            "com.apple.developer.team-identifier": "SECRET_TEAM",
            "com.apple.security.application-groups": ["SECRET_GROUP_1", "SECRET_GROUP_2"],
            "com.apple.developer.associated-domains": ["example.com"],
            "com.apple.security.network.client": True,
        }
        result = inspect_signed_app(self.app, runner=self.signed(raw))
        serialized = json.dumps(result)
        self.assertEqual(result["get_task_allow"], "TRUE")
        self.assertEqual(result["app_group_count"], 2)
        self.assertEqual(result["associated_domain_count"], 1)
        self.assertEqual(result["entitlement_key_count"], 6)
        self.assertEqual(result["application_identifier"], "PRESENT_REDACTED")
        self.assertFalse(result["complete_entitlements_exported"])
        self.assertFalse(result["code_signature_validated"])
        self.assertFalse(result["device_inspected"])
        self.assertNotIn("SECRET_TEAM", serialized)
        self.assertNotIn("SECRET_GROUP", serialized)
        self.assertNotIn("example.com", serialized)

    def test_missing_entitlements_not_assumed_false(self):
        result = inspect_signed_app(self.app, runner=self.signed({}))
        self.assertEqual(result["get_task_allow"], "NOT_PRESENT_OR_NOT_BOOLEAN")
        self.assertIsNone(result["app_group_count"])
        self.assertEqual(result["jailbreak_status"], "NOT_DEMONSTRATED")

    def test_unsigned_or_invalid_binary_is_inconclusive(self):
        with self.assertRaisesRegex(EntitlementsError, "development signing"):
            inspect_signed_app(self.app, runner=self.signed({}, returncode=1))

    def test_bad_plist_rejected(self):
        def runner(cmd, **kwargs):
            return CompletedProcess(cmd, 0, stdout=b"not a plist", stderr=b"")
        with self.assertRaisesRegex(EntitlementsError, "parse"):
            inspect_signed_app(self.app, runner=runner)

    def test_wrong_path_rejected(self):
        with self.assertRaisesRegex(EntitlementsError, "existing signed"):
            inspect_signed_app(Path(self.tmp.name) / "missing.app", runner=self.signed({}))


if __name__ == "__main__":
    unittest.main()
