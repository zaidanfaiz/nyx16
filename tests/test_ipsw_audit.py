"""Synthetic IPSW ZIP tests: no hardware required."""
import plistlib
import tempfile
import unittest
import zipfile
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from nyx16.audit import IPSWError, inspect_ipsw
from nyx16.chips import CHIPS, list_chips

class IPSWAuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ipsw = Path(self.tmp.name) / "sample.ipsw"
        self.manifest = {
            "ProductVersion": "17.0",
            "ProductBuildVersion": "21A329",
            "SupportedProductTypes": ["iPhone13,2"],
            "BuildIdentities": [{"Info": {"DeviceClass": "d53gap"}}],
        }

    def write_ipsw(self, *, manifest=True, content=None):
        with zipfile.ZipFile(self.ipsw, "w") as archive:
            if manifest:
                archive.writestr("BuildManifest.plist", content if content is not None else plistlib.dumps(self.manifest))

    def test_matching_identifiers(self):
        self.write_ipsw()
        data = inspect_ipsw(self.ipsw, product_type="IPHONE13,2", board="D53GAP")
        self.assertEqual(data["metadata_result"], "matched")
        self.assertEqual(data["apple_signing_status"], "NOT_CHECKED")
        self.assertEqual(data["downgrade_feasibility"], "UNDETERMINED")

    def test_mismatching_product(self):
        self.write_ipsw()
        data = inspect_ipsw(self.ipsw, product_type="iPhone12,1", board="d53gap")
        self.assertEqual(data["metadata_result"], "mismatched")

    def test_mismatching_board(self):
        self.write_ipsw()
        data = inspect_ipsw(self.ipsw, product_type="iPhone13,2", board="unknown")
        self.assertEqual(data["board_result"], "mismatched")

    def test_unknown_when_no_identifiers(self):
        self.write_ipsw()
        data = inspect_ipsw(self.ipsw)
        self.assertEqual(data["metadata_result"], "unknown")

    def test_unknown_when_product_list_missing(self):
        del self.manifest["SupportedProductTypes"]
        self.write_ipsw()
        data = inspect_ipsw(self.ipsw, product_type="iPhone13,2", board="d53gap")
        self.assertEqual(data["metadata_result"], "unknown")

    def test_reject_missing_manifest(self):
        self.write_ipsw(manifest=False)
        with self.assertRaises(IPSWError): inspect_ipsw(self.ipsw)

    def test_reject_corrupted_plist(self):
        self.write_ipsw(content=b"invalid")
        with self.assertRaises(IPSWError): inspect_ipsw(self.ipsw)

    def test_reject_oversized_manifest(self):
        self.write_ipsw(content=b"x" * (10 * 1024 * 1024 + 1))
        with self.assertRaises(IPSWError): inspect_ipsw(self.ipsw)

    def test_reject_invalid_build_identities(self):
        self.manifest["BuildIdentities"] = "oops"
        self.write_ipsw()
        with self.assertRaises(IPSWError): inspect_ipsw(self.ipsw)

    def test_reject_missing_file(self):
        with self.assertRaises(IPSWError): inspect_ipsw(self.ipsw)

    def test_chip_ids(self):
        self.assertEqual([c.cpid for c in CHIPS], [0x8020,0x8030,0x8101,0x8110,0x8120])
        self.assertEqual(list_chips()[-1]["family"], "A16")

if __name__ == "__main__": unittest.main()
