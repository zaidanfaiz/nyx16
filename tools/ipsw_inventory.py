"""Nyx16: bounded Apple IPSW central-directory inventory (read-only).

Uses the existing HTTPS Range guard; reads ONLY ZIP directory metadata and
BuildManifest.plist. Never downloads, decrypts, or executes firmware components.
ZIP sizes and names are untrusted metadata, not validated firmware content.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import plistlib
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from nyx16.compare import category, identities_for_board, assert_subject
from partial_ipsw import PRESETS, RemoteIPSW, RangeError, MAX_MANIFEST

MAX_ZIP_ENTRIES = 100000
BOARD = "N104AP"
PRODUCT = "iPhone12,1"


class InventoryError(ValueError):
    pass


def _check_manifest_zip(archive):
    candidates = [info for info in archive.infolist() if info.filename == "BuildManifest.plist"]
    if len(candidates) != 1 or candidates[0].is_dir():
        raise InventoryError("Expected exactly one root BuildManifest.plist")
    if not 0 < candidates[0].file_size <= MAX_MANIFEST:
        raise InventoryError("Root BuildManifest exceeds 10 MiB limit")
    try:
        with archive.open(candidates[0]) as stream:
            content = stream.read(MAX_MANIFEST + 1)
        if len(content) != candidates[0].file_size:
            raise InventoryError("Manifest length mismatch")
        obj = plistlib.loads(content)
    except (OSError, RuntimeError, zipfile.BadZipFile, plistlib.InvalidFileException,
            ValueError, TypeError, OverflowError) as exc:
        raise InventoryError(f"Cannot read BuildManifest: {exc}") from exc
    if not isinstance(obj, dict) or not isinstance(obj.get("BuildIdentities"), list):
        raise InventoryError("Invalid manifest identity list")
    return obj, hashlib.sha256(content).hexdigest()


def _index_entries(infos):
    entries = defaultdict(list)
    for info in infos:
        if not info.is_dir():
            entries[info.filename].append(info)
    return entries


def _describe_path(entries, path):
    if not isinstance(path, str) or not path or len(path) > 1024:
        return "PATH_NOT_DECLARED", None
    found = entries.get(path, [])
    if len(found) == 0:
        return "PATH_NOT_IN_ARCHIVE_INDEX", None
    if len(found) > 1:
        return "AMBIGUOUS_DUPLICATE_ARCHIVE_PATH", None
    return "PATH_IN_ARCHIVE_INDEX", found[0]


def inventory_preset(preset_name, *, expected_manifest=None, fetcher=None):
    if preset_name not in ("iphone11-ios27.2", "iphone11-ios26.1"):
        raise InventoryError("Only iPhone 11 firmware presets are permitted")
    preset = PRESETS[preset_name]
    source = RemoteIPSW(preset["url"], fetcher=fetcher)
    try:
        try:
            with zipfile.ZipFile(source) as archive:
                infos = archive.infolist()
                if not 1 <= len(infos) <= MAX_ZIP_ENTRIES:
                    raise InventoryError("ZIP entry count outside approved bounds")
                manifest, manifest_sha = _check_manifest_zip(archive)
                assert_subject(manifest, PRODUCT, preset["ios_version"], preset["build_version"])
                if expected_manifest is not None and hashlib.sha256(
                        Path(expected_manifest).read_bytes()).hexdigest() != manifest_sha:
                    raise InventoryError("Archive manifest differs from validated comparison input")
                identities = identities_for_board(manifest, BOARD)
                if not identities:
                    raise InventoryError("No BuildIdentity for N104AP")
                entries = _index_entries(infos)
                records = []
                for (variant, behavior), matches in sorted(identities.items()):
                    # Keep an ambiguity marker rather than silently choosing by list index.
                    if len(matches) != 1:
                        records.append({
                            "identity_variant": variant, "restore_behavior": behavior,
                            "component_category": "UNRESOLVED",
                            "component_key": "UNRESOLVED",
                            "manifest_path": None, "path_status": "AMBIGUOUS_BUILD_IDENTITY",
                            "compressed_bytes": None, "uncompressed_bytes": None,
                            "zip_compression": None, "manifest_digest_present": None,
                        })
                        continue
                    components = matches[0].get("Manifest", {})
                    if not isinstance(components, dict):
                        raise InventoryError("BuildIdentity missing component dictionary")
                    for key, metadata in sorted(components.items()):
                        cat = category(key) if isinstance(key, str) else None
                        if cat is None:
                            continue
                        if not isinstance(metadata, dict):
                            metadata = {}
                        info = metadata.get("Info")
                        path = info.get("Path") if isinstance(info, dict) else None
                        status, matched = _describe_path(entries, path)
                        digest = metadata.get("Digest")
                        records.append({
                            "identity_variant": variant, "restore_behavior": behavior,
                            "component_category": cat, "component_key": key,
                            "manifest_path": path if isinstance(path, str) and len(path) <= 1024 else None,
                            "path_status": status,
                            "compressed_bytes": matched.compress_size if matched else None,
                            "uncompressed_bytes": matched.file_size if matched else None,
                            "zip_compression": matched.compress_type if matched else None,
                            "manifest_digest_present": isinstance(digest, bytes),
                        })
        except (zipfile.BadZipFile, EOFError, RuntimeError, OSError, RangeError) as exc:
            raise InventoryError(f"Remote IPSW cannot be indexed safely: {exc}") from exc
        return {
            "type": "NYX16_IPSW_ARCHIVE_INDEX",
            "preset": preset_name,
            "product_type": PRODUCT,
            "board": BOARD,
            "ios_version": preset["ios_version"],
            "build_version": preset["build_version"],
            "manifest_sha256": manifest_sha,
            "archive_zip_entries": len(infos),
            "ipsw_total_bytes_from_http": source.size,
            "http_range_requests": source.requests,
            "http_bytes_transferred": source.transferred,
            "scope": "ZIP_DIRECTORY_AND_BUILDMANIFEST_ONLY",
            "firmware_binary_content_read": False,
            "full_ipsw_hash_verified": False,
            "apple_signing": "NOT_CHECKED",
            "sep_baseband_compatibility": "UNKNOWN",
            "unsigned_downgrade": "NOT_DEMONSTRATED",
            "records": records,
        }
    finally:
        source.close()


def compare_inventories(current, target):
    if current.get("type") != "NYX16_IPSW_ARCHIVE_INDEX" or target.get("type") != "NYX16_IPSW_ARCHIVE_INDEX":
        raise InventoryError("Not Nyx16 IPSW archive index data")
    for item, preset in ((current, "iphone11-ios27.2"), (target, "iphone11-ios26.1")):
        expected = PRESETS[preset]
        for field, value in (
            ("preset", preset), ("board", BOARD), ("product_type", PRODUCT),
            ("ios_version", expected["ios_version"]), ("build_version", expected["build_version"]),
            ("scope", "ZIP_DIRECTORY_AND_BUILDMANIFEST_ONLY"),
        ):
            if item.get(field) != value:
                raise InventoryError(f"Archive provenance mismatch: {preset} {field}")
        if not item.get("manifest_sha256") or item.get("firmware_binary_content_read") is not False:
            raise InventoryError("Missing manifest provenance or unsafe archive read claim")

    def by_identity(data):
        grouped = defaultdict(list)
        for r in data.get("records", []):
            if not isinstance(r, dict):
                raise InventoryError("Invalid component record")
            key = (r.get("identity_variant"), r.get("restore_behavior"), r.get("component_key"))
            grouped[key].append(r)
        return grouped

    left = by_identity(current)
    right = by_identity(target)
    rows = []
    for signature in sorted(set(left) | set(right)):
        a, b = left.get(signature, []), right.get(signature, [])
        if len(a) != 1 or len(b) != 1:
            status = "MISSING_OR_AMBIGUOUS_COMPONENT_IDENTITY"
        elif a[0]["path_status"] != "PATH_IN_ARCHIVE_INDEX" or b[0]["path_status"] != "PATH_IN_ARCHIVE_INDEX":
            status = "ZIP_PATH_NOT_VERIFIED_IN_BOTH"
        elif a[0]["manifest_path"] != b[0]["manifest_path"]:
            status = "COMPONENT_PATH_DIFFERS"
        elif (a[0]["compressed_bytes"], a[0]["uncompressed_bytes"], a[0]["zip_compression"]) != (
                b[0]["compressed_bytes"], b[0]["uncompressed_bytes"], b[0]["zip_compression"]):
            status = "ZIP_ENTRY_SIZES_OR_METHOD_DIFFER"
        else:
            status = "ZIP_ENTRY_METADATA_MATCH_NOT_BINARY_VERIFIED"
        rows.append({
            "variant": signature[0], "restore_behavior": signature[1], "component_key": signature[2],
            "category": a[0].get("component_category") if a else b[0].get("component_category"),
            "current_path": a[0].get("manifest_path") if a else None,
            "target_path": b[0].get("manifest_path") if b else None,
            "current_size_bytes": a[0].get("uncompressed_bytes") if a else None,
            "target_size_bytes": b[0].get("uncompressed_bytes") if b else None,
            "current_path_status": a[0].get("path_status") if a else "MISSING",
            "target_path_status": b[0].get("path_status") if b else "MISSING",
            "comparison": status,
            "binary_compatibility": "UNKNOWN",
        })
    return {
        "analysis": "IPSW_ZIP_CENTRAL_DIRECTORY_METADATA",
        "current_manifest_sha256": current["manifest_sha256"],
        "target_manifest_sha256": target["manifest_sha256"],
        "current_zip_entries": current["archive_zip_entries"],
        "target_zip_entries": target["archive_zip_entries"],
        "current_range_bytes": current["http_bytes_transferred"],
        "target_range_bytes": target["http_bytes_transferred"],
        "comparison_counts": dict(Counter(r["comparison"] for r in rows)),
        "rows": rows,
        "firmware_binaries_downloaded": False,
        "sep_baseband_compatibility": "UNKNOWN",
        "apple_signing": "NOT_CHECKED",
        "unsigned_downgrade": "NOT_DEMONSTRATED",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read-only IPSW archive component inventory")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--preset", choices=("iphone11-ios27.2", "iphone11-ios26.1"))
    mode.add_argument("--compare", nargs=2, metavar=("CURRENT_JSON", "TARGET_JSON"))
    parser.add_argument("--expected-manifest", help="Previously verified local BuildManifest.plist")
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    try:
        if args.preset:
            result = inventory_preset(args.preset, expected_manifest=args.expected_manifest)
        else:
            c, t = (json.loads(Path(p).read_text(encoding="utf-8")) for p in args.compare)
            result = compare_inventories(c, t)
        output = Path(args.out)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        if args.compare:
            with output.with_suffix(".csv").open("w", newline="", encoding="utf-8") as f:
                fields = list(result["rows"][0]) if result["rows"] else (
                    "variant", "restore_behavior", "component_key", "category", "comparison")
                writer = csv.DictWriter(f, fieldnames=fields)
                writer.writeheader()
                writer.writerows(result["rows"])
        print(json.dumps({k: v for k, v in result.items() if k not in ("records", "rows")}, indent=2))
    except (InventoryError, OSError, ValueError, json.JSONDecodeError) as exc:
        parser.exit(1, f"IPSW archive inventory error: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
