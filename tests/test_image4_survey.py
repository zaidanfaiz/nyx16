"""Offline synthetic IM4P ZIP fixtures. No external network, device or exploit."""
from __future__ import annotations
import hashlib
import io
import plistlib
import sys
import unittest
import warnings
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from image4_survey import (
    COMPONENT_LIMIT, Image4Error, compare_surveys, inspect_preset,
    parse_image4_container,
)


def der(tag, payload):
    size = len(payload)
    if size < 128:
        length = bytes([size])
    else:
        digits = size.to_bytes((size.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(digits)]) + digits
    return bytes([tag]) + length + payload


def ia5(text):
    return der(0x16, text.encode("ascii"))


def sample_im4p(component, version):
    typ = "ibot" if component == "iBoot" else "sepi"
    return der(0x30, ia5("IM4P") + ia5(typ)
               + ia5(f"{component}-{version}") + der(0x04, b"fakepayload" * 40))


def fixture(version, build, *, malformed=False, omit_sep=False, duplicate=False):
    files = {
        "Firmware/all_flash/iBoot.n104.RELEASE.im4p": sample_im4p("iBoot", version),
        "Firmware/all_flash/sep-firmware.n104.RELEASE.im4p":
            sample_im4p("SEP", version) if not malformed else b"not DER",
    }
    identities = {
        "Info": {
            "DeviceClass": "N104AP",
            "Variant": "Customer Erase Install (IPSW)",
            "RestoreBehavior": "Erase",
        },
        "Manifest": {
            "iBoot": {"Info": {"Path": "Firmware/all_flash/iBoot.n104.RELEASE.im4p"}, "Digest": b"a"},
            "SEP": {"Info": {"Path": "Firmware/all_flash/sep-firmware.n104.RELEASE.im4p"}, "Digest": b"b"},
        },
    }
    manifest = plistlib.dumps({
        "ProductVersion": version,
        "ProductBuildVersion": build,
        "SupportedProductTypes": ["iPhone12,1"],
        "BuildIdentities": [identities],
    })
    out = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(out, "w") as z:
            z.writestr("BuildManifest.plist", manifest, compress_type=zipfile.ZIP_DEFLATED)
            for name, blob in files.items():
                if not omit_sep or "sep-firmware" not in name:
                    z.writestr(name, blob, compress_type=zipfile.ZIP_DEFLATED)
                    if duplicate and "iBoot" in name:
                        z.writestr(name, blob)
            z.writestr("unused.bin", b"x" * 2_000_000, compress_type=zipfile.ZIP_STORED)
    return out.getvalue()


class FakeFetcher:
    def __init__(self, data):
        self.data = data
        self.calls = []
    def __call__(self, url, start, end):
        self.calls.append((start, end))
        return self.data[start:end + 1], len(self.data)


class Image4SurveyTests(unittest.TestCase):
    def test_der_header_parses_expected_fields(self):
        raw = sample_im4p("iBoot", "27.2")
        result = parse_image4_container(raw)
        self.assertEqual(result["outer_magic"], "IM4P")
        self.assertEqual(result["type_code"], "ibot")
        self.assertEqual(result["description"], "iBoot-27.2")
        self.assertEqual(result["payload_octets_declared"], 40 * len(b"fakepayload"))
        self.assertFalse(result["signature_verified"])

    def test_compression_sequence_and_keybag_candidate_are_metadata_only(self):
        compression = der(0x30, der(0x02, b"\\x01") + der(0x02, b"\\x00\\x20\\x00"))
        keybag = der(0x04, b"not-a-real-keybag")
        raw = der(0x30, ia5("IM4P") + ia5("ibot") + ia5("iBoot-test")
                  + der(0x04, b"bvx2" + b"x" * 100)
                  + keybag + compression)
        info = parse_image4_container(raw)
        self.assertEqual(info["payload_prefix_hint"], "LZFSE_BVX2_SIGNATURE_ONLY")
        self.assertEqual(info["compression_record"]["status"], "DECLARED_IN_DER")
        self.assertEqual(info["compression_record"]["algorithm_label"], "LZFSE")
        self.assertEqual(info["compression_record"]["declared_uncompressed_bytes"], 8192)
        self.assertEqual(info["optional_der_tag_sequence"], ["0x04", "0x30"])
        self.assertTrue(info["keybag_candidate_present"])
        self.assertEqual(info["encryption_status"], "NOT_DETERMINED")
        self.assertFalse(info["decryption_performed"])
        self.assertFalse(info["crypto_key_material_exported"])

    def test_lzss_signature_is_hint_not_a_decompression(self):
        raw = der(0x30, ia5("IM4P") + ia5("sepi") + ia5("SEP")
                  + der(0x04, b"complzss" + b"encoded-payload"))
        result = parse_image4_container(raw)
        self.assertEqual(result["payload_prefix_hint"], "LZSS_SIGNATURE_ONLY")
        self.assertEqual(result["compression_record"]["status"], "NOT_DECLARED")
        self.assertFalse(result["decompression_performed"])
        self.assertEqual(result["encryption_status"], "NOT_DETERMINED")

    def test_unknown_compression_id_is_not_named(self):
        record = der(0x30, der(0x02, b"\\x09") + der(0x02, b"\\x01"))
        raw = der(0x30, ia5("IM4P") + ia5("ibot") + ia5("x")
                  + der(0x04, b"opaque") + record)
        info = parse_image4_container(raw)
        self.assertEqual(info["compression_record"]["status"], "DECLARED_IN_DER")
        self.assertEqual(info["compression_record"]["algorithm_label"], "UNKNOWN_ALGORITHM")

    def test_malformed_optional_der_rejected(self):
        raw = der(0x30, ia5("IM4P") + ia5("ibot") + ia5("x")
                  + der(0x04, b"payload") + b"\\x04\\x82\\x01")
        with self.assertRaises(Image4Error):
            parse_image4_container(raw)

    def test_no_keybag_does_not_claim_unencrypted(self):
        data = parse_image4_container(sample_im4p("iBoot", "27.2"))
        self.assertFalse(data["keybag_candidate_present"])
        self.assertEqual(data["encryption_status"], "NOT_DETERMINED")
        self.assertFalse(data["decompression_performed"])

    def test_long_opaque_sep_description_is_valid_metadata(self):
        blob = der(0x30, ia5("IM4P") + ia5("sepi")
                   + der(0x16, b"SEP" + bytes([1]) * 1243)
                   + der(0x04, b"payload"))
        record = parse_image4_container(blob)
        self.assertEqual(record["type_code"], "sepi")
        self.assertEqual(record["description"], "OPAQUE_IA5STRING")
        self.assertEqual(record["description_octets"], 1246)
        self.assertEqual(len(record["description_sha256"]), 64)
        self.assertFalse(record["description_printable"])
        self.assertEqual(record["structure_parse_status"], "SHALLOW_DER_ENVELOPE_VALID")

    def test_long_printable_sep_description_is_redacted(self):
        blob = der(0x30, ia5("IM4P") + ia5("sepi")
                   + der(0x16, b"a" * 1246)
                   + der(0x04, b"payload"))
        result = parse_image4_container(blob)
        self.assertEqual(result["description"], "OPAQUE_IA5STRING")
        self.assertTrue(result["description_printable"])
        self.assertFalse(result["description_exported_as_text"])
        self.assertEqual(result["description_octets"], 1246)

    def test_img4_wrapper_parses_without_manifest(self):
        inner = sample_im4p("SEP", "26.1")
        outer = der(0x30, ia5("IMG4") + inner)
        result = parse_image4_container(outer)
        self.assertEqual(result["outer_magic"], "IMG4")
        self.assertEqual(result["type_code"], "sepi")

    def test_rejects_indefinite_der(self):
        with self.assertRaisesRegex(Image4Error, "Indefinite"):
            parse_image4_container(b"\x30\x80\x16\x04IM4P\x00\x00")

    def test_rejects_nonminimal_der(self):
        with self.assertRaisesRegex(Image4Error, "Nonminimal"):
            parse_image4_container(b"\x30\x81\x07\x16\x04IM4P\x00")

    def test_rejects_truncated_der(self):
        with self.assertRaises(Image4Error):
            parse_image4_container(b"\x30\x82\x00\xFF\x16\x04IM4P")

    def test_rejects_oversized(self):
        with self.assertRaisesRegex(Image4Error, "size limit"):
            parse_image4_container(b"x" * (COMPONENT_LIMIT + 1))

    def test_reads_only_components_and_manifest_from_remote_zip(self):
        sample = fixture("27.2", "24B119")
        fetcher = FakeFetcher(sample)
        result = inspect_preset("iphone11-ios27.2", fetcher=fetcher)
        self.assertEqual(result["ios_version"], "27.2")
        self.assertEqual(len(result["components"]), 2)
        self.assertTrue(all(x["structure_parse_status"] == "SHALLOW_DER_ENVELOPE_VALID"
                            for x in result["components"]))
        self.assertTrue(all(x["type_code_matches_expected"] for x in result["components"]))
        self.assertLess(result["http_range_bytes_transferred"], len(sample))
        self.assertFalse(result["full_ipsw_downloaded"])
        self.assertFalse(result["firmware_files_written_to_disk"])

    def test_version_comparison_hashes_differ(self):
        cur = inspect_preset("iphone11-ios27.2", fetcher=FakeFetcher(fixture("27.2", "24B119")))
        old = inspect_preset("iphone11-ios26.1", fetcher=FakeFetcher(fixture("26.1", "23B85")))
        cmp = compare_surveys(cur, old)
        self.assertEqual(len(cmp["rows"]), 2)
        self.assertEqual({x["comparison"] for x in cmp["rows"]}, {"FILE_SHA256_DIFFERS"})
        self.assertEqual(cmp["unsigned_downgrade"], "NOT_DEMONSTRATED")

    def test_unknown_header_is_reported_not_claimed_valid(self):
        out = inspect_preset("iphone11-ios27.2",
                             fetcher=FakeFetcher(fixture("27.2", "24B119", malformed=True)))
        sep = next(x for x in out["components"] if x["component"] == "SEP")
        self.assertEqual(sep["structure_parse_status"], "UNRECOGNIZED_OR_MALFORMED_DER")
        self.assertIsNone(sep["type_code_matches_expected"])

    def test_missing_component_rejected(self):
        with self.assertRaisesRegex(Image4Error, "missing/ambiguous"):
            inspect_preset("iphone11-ios27.2",
                           fetcher=FakeFetcher(fixture("27.2", "24B119", omit_sep=True)))

    def test_duplicate_component_rejected(self):
        with self.assertRaisesRegex(Image4Error, "missing/ambiguous"):
            inspect_preset("iphone11-ios27.2",
                           fetcher=FakeFetcher(fixture("27.2", "24B119", duplicate=True)))

    def test_preset_restricted(self):
        with self.assertRaisesRegex(Image4Error, "iPhone 11"):
            inspect_preset("iphone12-ios26.1")

    def test_false_claims_rejected_in_comparison(self):
        cur = inspect_preset("iphone11-ios27.2", fetcher=FakeFetcher(fixture("27.2", "24B119")))
        old = inspect_preset("iphone11-ios26.1", fetcher=FakeFetcher(fixture("26.1", "23B85")))
        cur["signature_verified"] = True
        with self.assertRaisesRegex(Image4Error, "provenance"):
            compare_surveys(cur, old)


if __name__ == "__main__":
    unittest.main()
