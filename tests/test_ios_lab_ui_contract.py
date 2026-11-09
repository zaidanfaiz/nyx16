"""Static regression checks for the Nyx16 iPhone UI contract, not iOS runtime tests."""
import json
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP_DIR = ROOT / "ios" / "Nyx16Lab" / "Nyx16Lab"
SWIFT = APP_DIR / "Nyx16LabApp.swift"
PBX = ROOT / "ios" / "Nyx16Lab" / "Nyx16Lab.xcodeproj" / "project.pbxproj"
ICON_DIR = APP_DIR / "Assets.xcassets" / "AppIcon.appiconset"


class IOSLabUIContractTests(unittest.TestCase):
    def test_single_unified_runner_for_j1_to_j3(self):
        code = SWIFT.read_text(encoding="utf-8")
        self.assertIn("func runAllDiagnostics()", code)
        self.assertIn("let finished = [runJ1(), runJ2(), runJ3()]", code)
        self.assertIn("model.runAllDiagnostics()", code)
        self.assertIn('"runFullDiagnostics"', code)
        self.assertNotIn("Run Sandbox Test", code)
        self.assertNotIn("Run J2 Diagnostics", code)
        self.assertNotIn('"runJ2Diagnostics"', code)
        self.assertNotIn('"runSandboxTest"', code)

    def test_j3_never_claims_arbitrary_execution_or_kernel_access(self):
        code = SWIFT.read_text(encoding="utf-8")
        self.assertIn("JAILBREAK: NOT DEMONSTRATED", code)
        self.assertIn("SIGNATURE BYPASS: NOT TESTED", code)
        self.assertIn("Arbitrary code execution", code)
        self.assertIn("NOT TESTED", code)
        self.assertIn("CryptoKit", code)
        self.assertIn("Bundle.main.executableURL", code)
        self.assertNotIn("irecovery -", code)

    def test_copy_and_share_of_single_combined_report(self):
        code = SWIFT.read_text(encoding="utf-8")
        self.assertIn("UIPasteboard.general.string = reportText", code)
        self.assertIn("ShareLink(item: model.reportText)", code)
        self.assertIn("hasReport", code)

    def test_app_icon_is_1024_png_and_catalog_registered(self):
        manifest = json.loads((ICON_DIR / "Contents.json").read_text(encoding="utf-8"))
        images = manifest["images"]
        self.assertEqual(len(images), 1)
        self.assertEqual(images[0]["size"], "1024x1024")
        self.assertEqual(images[0]["platform"], "ios")
        icon = ICON_DIR / images[0]["filename"]
        with icon.open("rb") as fp:
            header = fp.read(24)
        self.assertEqual(header[:8], b"\x89PNG\r\n\x1a\n")
        self.assertEqual(header[12:16], b"IHDR")
        self.assertEqual(struct.unpack(">II", header[16:24]), (1024, 1024))
        pbx = PBX.read_text(encoding="utf-8")
        self.assertIn("ASSETCATALOG_COMPILER_APPICON_NAME = AppIcon;", pbx)
        self.assertIn("Assets.xcassets in Resources", pbx)


if __name__ == "__main__":
    unittest.main()
