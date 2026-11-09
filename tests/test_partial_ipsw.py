"""Network-free unit tests of the virtual HTTP Range reader and IPSW metadata extractor."""
import io
import plistlib
import sys
import unittest
import warnings
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from partial_ipsw import (
    APPLE_IPSW_26_1_IPHONE12, PRESETS, MAX_MANIFEST, RangeError,
    RemoteIPSW, extract_manifest, validate_url,
)


def sample_apple_ipsw(*, version="26.1", product="iPhone13,2", build="23B85",
                      omit_manifest=False, duplicate_manifest=False,
                      extra_size=3 * 1024 * 1024):
    raw = io.BytesIO()
    manifest = plistlib.dumps({
        "ProductVersion": version,
        "ProductBuildVersion": build,
        "SupportedProductTypes": [product, "iPhone13,3"],
        "BuildIdentities": [{"Info": {"DeviceClass": "D53gAP"}}],
    })
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(raw, "w") as zipf:
            if not omit_manifest:
                zipf.writestr("BuildManifest.plist", manifest, compress_type=zipfile.ZIP_DEFLATED)
                if duplicate_manifest:
                    zipf.writestr("BuildManifest.plist", manifest)
            zipf.writestr("large-opaque-data.bin", b"z" * extra_size, compress_type=zipfile.ZIP_STORED)
    return raw.getvalue()


class FakeFetcher:
    def __init__(self, data):
        self.data = data
        self.calls = []

    def __call__(self, url, start, end):
        self.calls.append((start, end))
        return self.data[start:end + 1], len(self.data)


class PartialIPSWTests(unittest.TestCase):
    def test_iphone11_preset_is_separate_from_iphone12(self):
        i11 = PRESETS["iphone11-ios26.1"]
        i12 = PRESETS["iphone12-ios26.1"]
        self.assertEqual(i11["product_type"], "iPhone12,1")
        self.assertEqual(i11["chip"], "A13")
        self.assertEqual(i11["ios_version"], "26.1")
        self.assertEqual(i11["build_version"], "23B85")
        self.assertNotEqual(i11["url"], i12["url"])
        self.assertNotEqual(i11["published_ipsw_sha256"], i12["published_ipsw_sha256"])
        validate_url(i11["url"])


    def test_partial_ranges_extract_manifest_without_downloading_entire_archive(self):
        fake = FakeFetcher(sample_apple_ipsw(extra_size=5 * 1024 * 1024))
        data, meta = extract_manifest(
            APPLE_IPSW_26_1_IPHONE12,
            product_type="iPhone13,2", ios_version="26.1", build_version="23B85",
            fetcher=fake,
        )
        self.assertEqual(plistlib.loads(data)["ProductVersion"], "26.1")
        self.assertLess(meta["http_bytes_transferred"], len(fake.data))
        self.assertGreater(meta["http_range_requests"], 1)
        self.assertFalse(meta["full_ipsw_sha256_verified"])
        self.assertEqual(meta["apple_signing_status"], "NOT_CHECKED")
        self.assertEqual(meta["unsigned_downgrade"], "NOT_DEMONSTRATED")

    def test_wrong_product_fails_closed(self):
        fake = FakeFetcher(sample_apple_ipsw(product="iPhone12,1"))
        with self.assertRaisesRegex(RangeError, "does not declare"):
            extract_manifest(APPLE_IPSW_26_1_IPHONE12,
                             product_type="iPhone13,2", fetcher=fake)

    def test_wrong_version_fails_closed(self):
        fake = FakeFetcher(sample_apple_ipsw(version="27.0"))
        with self.assertRaisesRegex(RangeError, "ProductVersion mismatch"):
            extract_manifest(APPLE_IPSW_26_1_IPHONE12, ios_version="26.1", fetcher=fake)

    def test_wrong_build_fails_closed(self):
        fake = FakeFetcher(sample_apple_ipsw(build="99Z999"))
        with self.assertRaisesRegex(RangeError, "ProductBuildVersion mismatch"):
            extract_manifest(APPLE_IPSW_26_1_IPHONE12, build_version="23B85", fetcher=fake)

    def test_missing_manifest_rejected(self):
        fake = FakeFetcher(sample_apple_ipsw(omit_manifest=True))
        with self.assertRaisesRegex(RangeError, "exactly one"):
            extract_manifest(APPLE_IPSW_26_1_IPHONE12, fetcher=fake)

    def test_duplicate_manifest_rejected(self):
        fake = FakeFetcher(sample_apple_ipsw(duplicate_manifest=True))
        with self.assertRaisesRegex(RangeError, "exactly one"):
            extract_manifest(APPLE_IPSW_26_1_IPHONE12, fetcher=fake)

    def test_reject_other_hosts(self):
        for url in [
            "https://evil.example/firmware.ipsw",
            "http://updates.cdn-apple.com/firmware.ipsw",
            "https://updates.cdn-apple.com.evil.example/firmware.ipsw",
            "https://updates.cdn-apple.com/firmware.ipsw?token=secret",
            "https://example:pass@updates.cdn-apple.com/firmware.ipsw",
        ]:
            with self.subTest(url=url), self.assertRaises(RangeError):
                validate_url(url)

    def test_virtual_seek_read_and_cache(self):
        fake = FakeFetcher(sample_apple_ipsw(extra_size=2 * 1024 * 1024))
        with RemoteIPSW(APPLE_IPSW_26_1_IPHONE12, fetcher=fake) as reader:
            self.assertEqual(reader.seek(-100, io.SEEK_END), len(fake.data) - 100)
            self.assertEqual(reader.read(100), fake.data[-100:])
            self.assertEqual(reader.read(), b"")
            self.assertEqual(reader.seek(0), 0)
            self.assertEqual(reader.read(64), fake.data[:64])
            self.assertEqual(reader.seek(0), 0)
            self.assertEqual(reader.read(64), fake.data[:64])

    def test_unbounded_read_is_refused(self):
        fake = FakeFetcher(sample_apple_ipsw(extra_size=65 * 1024 * 1024))
        with RemoteIPSW(APPLE_IPSW_26_1_IPHONE12, fetcher=fake) as reader:
            with self.assertRaisesRegex(RangeError, "Oversized"):
                reader.read()

    def test_changed_remote_size_rejected(self):
        fake = FakeFetcher(sample_apple_ipsw())
        def changed(url, start, end):
            payload, total = fake(url, start, end)
            return payload, total if start == 0 and end == 0 else total + 1
        with RemoteIPSW(APPLE_IPSW_26_1_IPHONE12, fetcher=changed) as reader:
            with self.assertRaisesRegex(RangeError, "changed"):
                reader.read(1024)


if __name__ == "__main__":
    unittest.main()
