"""Nyx16 Stage 4: match an Actions comparison artifact to a local iPhone (read-only).

Supports both an extracted Actions artifact folder and its original ZIP.
Never alters the device, contacts signing services, or processes private IDs.
"""
from __future__ import annotations

import argparse
import json
import sys
import zipfile
from pathlib import Path
from urllib.parse import urlsplit

from mac_probe import probe

EXPECTED = {
    "product_type": "iPhone12,1",
    "board": "N104AP",
    "current_ios": "27.2",
    "current_build": "24B119",
    "target_ios": "26.1",
    "target_build": "23B85",
}
REQUIRED = (
    "iphone11_firmware_comparison.json",
    "current_ipsw_source.json",
    "target_ipsw_source.json",
)
MAX_MEMBER = 2 * 1024 * 1024


class VerificationError(ValueError):
    pass


def locate_artifact(path=None, downloads=None):
    """Find report ZIP or extracted folder; never create or mutate it."""
    if path:
        candidate = Path(path).expanduser()
        if not candidate.is_file() and not candidate.is_dir():
            raise VerificationError(f"Report not found: {candidate}")
        return candidate
    root = Path(downloads).expanduser() if downloads else Path.home() / "Downloads"
    if not root.is_dir():
        raise VerificationError("Downloads directory does not exist; use --report")
    candidates = [
        p for p in root.glob("nyx16-iphone11-27_2-vs-26_1-*")
        if p.is_dir() or (p.is_file() and p.suffix.lower() == ".zip")
    ]
    if not candidates:
        raise VerificationError("No iPhone 11 comparison artifact in Downloads. Download from GitHub Actions.")
    return max(candidates, key=lambda p: (p.stat().st_mtime, p.name))


def _decode(raw: bytes, name: str):
    if not 0 < len(raw) <= MAX_MEMBER:
        raise VerificationError(f"Invalid report file size: {name}")
    try:
        result = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"Invalid JSON in {name}") from exc
    if not isinstance(result, dict):
        raise VerificationError(f"Report member must be JSON object: {name}")
    return result


def read_artifact(path):
    """Read three small known JSON members, never extract arbitrary ZIP entries."""
    p = Path(path)
    records = {}
    if p.is_dir():
        root = p.resolve()
        for name in REQUIRED:
            entry = p / name
            if (not entry.is_file() or entry.is_symlink() or
                    not entry.resolve().is_relative_to(root) or
                    not 0 < entry.stat().st_size <= MAX_MEMBER):
                raise VerificationError(f"Missing or oversized member: {name}")
            records[name] = _decode(entry.read_bytes(), name)
    else:
        try:
            with zipfile.ZipFile(p) as archive:
                for name in REQUIRED:
                    entries = [e for e in archive.infolist() if e.filename == name]
                    if len(entries) != 1 or not 0 < entries[0].file_size <= MAX_MEMBER:
                        raise VerificationError(f"Missing, duplicate, or oversized member: {name}")
                    with archive.open(entries[0]) as fp:
                        records[name] = _decode(fp.read(MAX_MEMBER + 1), name)
        except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
            raise VerificationError(f"Cannot read Actions report ZIP: {exc}") from exc
    return records


def compare_artifact_to_device(records, device):
    """All checks compare metadata; a PASS is never a restore authorization."""
    cmp = records[REQUIRED[0]]
    current = records[REQUIRED[1]]
    target = records[REQUIRED[2]]
    checks = {}
    for k, expected in EXPECTED.items():
        actual = cmp.get(k)
        checks["report_" + k] = (
            "MATCH" if isinstance(actual, str) and actual.casefold() == expected.casefold()
            else "MISMATCH"
        )
    checks["current_manifest_provenance"] = (
        "MATCH" if isinstance(current.get("manifest_sha256"), str)
        and len(current["manifest_sha256"]) == 64
        and cmp.get("current_manifest_sha256") == current["manifest_sha256"]
        and current.get("ios_version") == EXPECTED["current_ios"]
        and current.get("build_version") == EXPECTED["current_build"]
        and current.get("product_type_checked") == EXPECTED["product_type"]
        and urlsplit(current.get("source_url", "")).hostname == "updates.cdn-apple.com"
        else "MISMATCH"
    )
    checks["target_manifest_provenance"] = (
        "MATCH" if isinstance(target.get("manifest_sha256"), str)
        and len(target["manifest_sha256"]) == 64
        and cmp.get("target_manifest_sha256") == target["manifest_sha256"]
        and target.get("ios_version") == EXPECTED["target_ios"]
        and target.get("build_version") == EXPECTED["target_build"]
        and target.get("product_type_checked") == EXPECTED["product_type"]
        and urlsplit(target.get("source_url", "")).hostname == "updates.cdn-apple.com"
        else "MISMATCH"
    )
    checks["report_not_restore_claim"] = (
        "MATCH" if cmp.get("apple_signing") == "NOT_CHECKED"
        and cmp.get("sep_cross_version_compatibility") == "UNKNOWN"
        and cmp.get("baseband_cross_version_compatibility") == "UNKNOWN"
        and cmp.get("unsigned_downgrade") == "NOT_DEMONSTRATED"
        else "MISMATCH"
    )
    observed = device.get("observed", {})
    if device.get("mode") != "NORMAL":
        for key in ("device_product", "device_board", "device_installed_ios", "device_installed_build"):
            checks[key] = "NOT_AVAILABLE"
    else:
        for label, observed_key, expected_key in (
            ("device_product", "ProductType", "product_type"),
            ("device_board", "HardwareModel", "board"),
            ("device_installed_ios", "ProductVersion", "current_ios"),
            ("device_installed_build", "BuildVersion", "current_build"),
        ):
            value = observed.get(observed_key)
            checks[label] = (
                "MATCH" if isinstance(value, str)
                and value.casefold() == EXPECTED[expected_key].casefold()
                else "MISMATCH" if value is not None else "NOT_AVAILABLE"
            )
    if "MISMATCH" in checks.values():
        status = "MISMATCH_STOP"
    elif "NOT_AVAILABLE" in checks.values():
        status = "INCONCLUSIVE_DEVICE_ACCESS"
    else:
        status = "METADATA_MATCH_ONLY"
    return {
        "experiment": "NYX16_STAGE4_IPHONE11",
        "status": status,
        "checks": checks,
        "device_mode": device.get("mode", "NOT_DETECTED"),
        "connected_device": device.get("device_identification", {}).get("device", "UNKNOWN"),
        "installed_baseband_version": observed.get("BasebandVersion", "UNKNOWN"),
        "target": EXPECTED,
        "compared_manifest_digest_statuses": cmp.get("comparisons", {}),
        "apple_signing": "NOT_CHECKED",
        "sep_baseband_cross_version_compatibility": "UNKNOWN",
        "unsigned_downgrade": "NOT_DEMONSTRATED",
        "device_modified": False,
        "notice": (
            "Only internally compares a downloaded report to read-only USB device metadata. "
            "No firmware cryptographic verification, signing authorization, SEP compatibility, "
            "bootability, or downgrade is established."
        ),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Nyx16 Stage 4: macOS read-only artifact/device matching")
    parser.add_argument("--report", help="Actions artifact ZIP or extracted directory; auto-detect if omitted")
    parser.add_argument("--output", help="Optional sanitized JSON output file")
    args = parser.parse_args(argv)
    try:
        path = locate_artifact(args.report)
        records = read_artifact(path)
        device = probe(target_ios="26.1")
        report = compare_artifact_to_device(records, device)
        report["artifact_location"] = str(path)
    except (OSError, VerificationError) as exc:
        report = {
            "experiment": "NYX16_STAGE4_IPHONE11", "status": "NOT_COMPLETED",
            "error": str(exc), "device_modified": False,
            "unsigned_downgrade": "NOT_DEMONSTRATED",
        }
    text = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        Path(args.output).expanduser().write_text(text, encoding="utf-8")
    print(text, end="")
    return 0 if report["status"] == "METADATA_MATCH_ONLY" else 1


if __name__ == "__main__":
    sys.exit(main())
