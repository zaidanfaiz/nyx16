"""Inspect bounded iPhone 11 IM4P containers without decryption or boot operations.

Fetches two explicitly chosen Apple IPSW ZIP members (iBoot and SEP) through
HTTP Range; performs strict, shallow ASN.1 DER header parsing. Firmware is never
written to disk, executed, patched, signed, or sent to a device.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import plistlib
import sys
import zipfile
from pathlib import Path

from partial_ipsw import PRESETS, RangeError, RemoteIPSW, MAX_MANIFEST
from ipsw_inventory import BOARD, PRODUCT, InventoryError
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from nyx16.compare import assert_subject, identities_for_board

COMPONENT_LIMIT = 10 * 1024 * 1024
COMPONENTS = ("iBoot", "SEP")
VARIANT = ("Customer Erase Install (IPSW)", "Erase")
EXPECTED_TYPES = {"iBoot": "ibot", "SEP": "sepi"}


class Image4Error(ValueError):
    """Unsupported or malformed DER envelope, not a claim about bootability."""


def tlv(data, offset, end):
    if offset >= end:
        raise Image4Error("Truncated ASN.1 field")
    tag = data[offset]
    at = offset + 1
    if at >= end:
        raise Image4Error("Truncated DER length")
    first = data[at]
    at += 1
    if first == 0x80:
        raise Image4Error("Indefinite BER length is not DER")
    if first < 0x80:
        length = first
    else:
        count = first & 0x7f
        if not 1 <= count <= 4 or at + count > end:
            raise Image4Error("Unsupported or truncated long-form DER length")
        if data[at] == 0 or (count == 1 and data[at] < 0x80):
            raise Image4Error("Nonminimal DER length")
        length = int.from_bytes(data[at:at + count], "big")
        at += count
    if at + length > end:
        raise Image4Error("DER value exceeds supplied container")
    return tag, at, at + length, at + length


def text_field(data, offset, bound, max_bytes=192):
    tag, begin, end, after = tlv(data, offset, bound)
    if tag != 0x16 or end - begin > max_bytes:
        raise Image4Error(f"Expected bounded IA5String at offset {offset} (tag=0x{tag:02x}; size={end-begin}; max={max_bytes})")
    raw = data[begin:end]
    if any(c > 0x7f or c < 0x20 for c in raw):
        raise Image4Error("Non-printable IA5String")
    return raw.decode("ascii"), after


def description_field(data, offset, bound):
    """Descriptions can contain long opaque Apple metadata; do not decode it as text."""
    tag, begin, end, after = tlv(data, offset, bound)
    if tag != 0x16 or end - begin > 4096:
        raise Image4Error(
            f"Unsupported IM4P description field (tag=0x{tag:02x}, size={end-begin})"
        )
    raw = data[begin:end]
    plain = all(0x20 <= c < 0x7f for c in raw)
    return {
        "description": raw.decode("ascii") if plain else "OPAQUE_IA5STRING",
        "description_octets": len(raw),
        "description_sha256": hashlib.sha256(raw).hexdigest(),
        "description_printable": plain,
    }, after


def parse_image4_container(data):
    """Read DER envelope and payload LENGTH only, never parse its contents."""
    if not isinstance(data, bytes) or not 1 <= len(data) <= COMPONENT_LIMIT:
        raise Image4Error("Input exceeds container size limit")
    tag, begin, end, after = tlv(data, 0, len(data))
    if tag != 0x30:
        raise Image4Error("Outer object is not ASN.1 SEQUENCE")
    magic, at = text_field(data, begin, end, 8)
    outer_magic = magic
    if magic == "IMG4":
        inner_tag, inner_begin, inner_end, after_inner = tlv(data, at, end)
        if inner_tag != 0x30:
            raise Image4Error("IMG4 does not contain a SEQUENCE payload")
        magic, at = text_field(data, inner_begin, inner_end, 8)
        bound = inner_end
        if after_inner > end:
            raise Image4Error("Nested IMG4 payload exceeds parent")
    else:
        bound = end
    if magic != "IM4P":
        raise Image4Error("Expected IM4P payload magic")
    payload_type, at = text_field(data, at, bound, 16)
    description_metadata, at = description_field(data, at, bound)
    tag, start, payload_end, at = tlv(data, at, bound)
    if tag != 0x04:
        raise Image4Error("IM4P payload field is not OCTET STRING")
    return {
        "outer_magic": outer_magic,
        "type_code": payload_type,
        **description_metadata,
        "payload_octets_declared": payload_end - start,
        "optional_der_fields_present": at < bound,
        "trailing_bytes_after_der": len(data) - after,
        "structure_parse_status": "SHALLOW_DER_ENVELOPE_VALID",
        "signature_verified": False,
        "payload_decrypted": False,
        "payload_executed": False,
    }


def inspect_preset(preset_name, fetcher=None):
    if preset_name not in ("iphone11-ios27.2", "iphone11-ios26.1"):
        raise Image4Error("Only defined iPhone 11 presets are supported")
    preset = PRESETS[preset_name]
    remote = RemoteIPSW(preset["url"], fetcher=fetcher)
    try:
        with zipfile.ZipFile(remote) as archive:
            candidates = [x for x in archive.infolist() if x.filename == "BuildManifest.plist"]
            if len(candidates) != 1 or not 0 < candidates[0].file_size <= MAX_MANIFEST:
                raise Image4Error("Missing or too-large BuildManifest")
            manifest_bytes = archive.read(candidates[0])
            manifest = plistlib.loads(manifest_bytes)
            assert_subject(manifest, PRODUCT, preset["ios_version"], preset["build_version"])
            identities = identities_for_board(manifest, BOARD)
            if len(identities.get(VARIANT, [])) != 1:
                raise Image4Error("Expected exactly one N104AP customer erase identity")
            component_map = identities[VARIANT][0].get("Manifest")
            if not isinstance(component_map, dict):
                raise Image4Error("Missing component manifest dictionary")
            indexed = archive.infolist()
            results = []
            for name in COMPONENTS:
                record = component_map.get(name, {})
                info = record.get("Info") if isinstance(record, dict) else {}
                path = info.get("Path") if isinstance(info, dict) else None
                if not isinstance(path, str) or not path.endswith(".im4p") or len(path) > 1024:
                    raise Image4Error(f"Missing/invalid {name} IM4P path")
                matches = [entry for entry in indexed if entry.filename == path and not entry.is_dir()]
                if len(matches) != 1:
                    raise Image4Error(f"{name} ZIP path missing/ambiguous")
                member = matches[0]
                if not 0 < member.file_size <= COMPONENT_LIMIT or not 0 < member.compress_size <= COMPONENT_LIMIT:
                    raise Image4Error(f"{name} exceeds bounded 10 MiB member limit")
                # Archive.open verifies the ZIP CRC on full read; do not persist raw bytes.
                with archive.open(member) as fp:
                    blob = fp.read(COMPONENT_LIMIT + 1)
                if len(blob) != member.file_size:
                    raise Image4Error(f"{name} archive member length mismatch")
                digest = hashlib.sha256(blob).hexdigest()
                try:
                    result = parse_image4_container(blob)
                except Image4Error as exc:
                    result = {
                        "structure_parse_status": "UNRECOGNIZED_OR_MALFORMED_DER",
                        "parse_error": str(exc),
                        "signature_verified": False,
                        "payload_decrypted": False,
                        "payload_executed": False,
                    }
                result.update({
                    "component": name,
                    "manifest_path": path,
                    "uncompressed_bytes": len(blob),
                    "sha256_of_compressed_or_wrapped_component_file": digest,
                    "zip_crc32_verified_by_reader": True,
                    "expected_type_code": EXPECTED_TYPES[name],
                    "type_code_matches_expected": (
                        result.get("type_code") == EXPECTED_TYPES[name]
                        if "type_code" in result else None
                    ),
                })
                results.append(result)
        return {
            "experiment": "NYX16_IM4P_STATIC_HEADER_SURVEY",
            "preset": preset_name,
            "product_type": PRODUCT,
            "board": BOARD,
            "ios_version": preset["ios_version"],
            "build_version": preset["build_version"],
            "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "http_range_bytes_transferred": remote.transferred,
            "http_range_requests": remote.requests,
            "component_file_contents_read_for_shallow_parsing": True,
            "full_ipsw_downloaded": False,
            "firmware_files_written_to_disk": False,
            "signature_verified": False,
            "sep_cross_version_compatibility": "UNKNOWN",
            "unsigned_downgrade": "NOT_DEMONSTRATED",
            "components": results,
        }
    except (RangeError, InventoryError, zipfile.BadZipFile, EOFError,
            OSError, plistlib.InvalidFileException) as exc:
        raise Image4Error(f"Cannot inspect IPSW safely: {exc}") from exc
    finally:
        remote.close()


def compare_surveys(current, target):
    if (current.get("preset") != "iphone11-ios27.2"
            or target.get("preset") != "iphone11-ios26.1"):
        raise Image4Error("Unexpected version pair")
    for obj, preset in ((current, "iphone11-ios27.2"), (target, "iphone11-ios26.1")):
        expected = PRESETS[preset]
        if (obj.get("product_type") != PRODUCT or obj.get("board") != BOARD or
                obj.get("ios_version") != expected["ios_version"] or
                obj.get("build_version") != expected["build_version"] or
                obj.get("full_ipsw_downloaded") is not False or
                obj.get("signature_verified") is not False):
            raise Image4Error("Firmware survey provenance mismatch")
        if not isinstance(obj.get("components"), list) or len(obj["components"]) != 2:
            raise Image4Error("Incomplete firmware component survey")
    present = {}
    for obj in (current, target):
        components = {}
        for item in obj["components"]:
            key = item.get("component")
            if key not in COMPONENTS or key in components:
                raise Image4Error("Missing/duplicate component identity")
            components[key] = item
        if set(components) != set(COMPONENTS):
            raise Image4Error("Incomplete component list")
        present[obj["preset"]] = components
    rows = []
    for component in COMPONENTS:
        a = present["iphone11-ios27.2"][component]
        b = present["iphone11-ios26.1"][component]
        a_status = a.get("structure_parse_status")
        b_status = b.get("structure_parse_status")
        if a_status != "SHALLOW_DER_ENVELOPE_VALID" or b_status != "SHALLOW_DER_ENVELOPE_VALID":
            status = "PARSE_INCOMPLETE"
        elif a.get("type_code") != b.get("type_code"):
            status = "IM4P_TYPE_CODE_DIFFERS"
        elif a.get("sha256_of_compressed_or_wrapped_component_file") == b.get("sha256_of_compressed_or_wrapped_component_file"):
            status = "FILE_SHA256_MATCH_NOT_SIGNATURE_PROOF"
        else:
            status = "FILE_SHA256_DIFFERS"
        rows.append({
            "component": component,
            "current_header_status": a_status,
            "target_header_status": b_status,
            "current_image4_type": a.get("type_code", "UNKNOWN"),
            "target_image4_type": b.get("type_code", "UNKNOWN"),
            "current_description": a.get("description", "UNKNOWN"),
            "target_description": b.get("description", "UNKNOWN"),
            "current_file_sha256": a.get("sha256_of_compressed_or_wrapped_component_file"),
            "target_file_sha256": b.get("sha256_of_compressed_or_wrapped_component_file"),
            "comparison": status,
            "binary_boot_compatibility": "UNKNOWN",
        })
    return {
        "experiment": "NYX16_IM4P_HEADER_VERSION_COMPARISON",
        "product_type": PRODUCT,
        "board": BOARD,
        "rows": rows,
        "apple_signature_verified": False,
        "sep_cross_version_compatibility": "UNKNOWN",
        "baseband_cross_version_compatibility": "UNKNOWN",
        "unsigned_downgrade": "NOT_DEMONSTRATED",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Inspect iPhone 11 IM4P headers safely from Apple IPSWs")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--preset", choices=("iphone11-ios27.2", "iphone11-ios26.1"))
    group.add_argument("--compare", nargs=2, metavar=("CURRENT", "TARGET"))
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    try:
        if args.preset:
            result = inspect_preset(args.preset)
        else:
            src = [json.loads(Path(x).read_text(encoding="utf-8")) for x in args.compare]
            result = compare_surveys(*src)
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({k: v for k, v in result.items()
                          if k not in ("components", "rows")}, indent=2))
    except (Image4Error, ValueError, OSError) as exc:
        parser.exit(1, f"Nyx16 Image4 survey error: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
