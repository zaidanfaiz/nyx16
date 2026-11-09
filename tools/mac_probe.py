"""Nyx16 macOS USB identification (read-only), supporting A12–A16 iPhones.

No device restore, pairing change, Activation Lock access, exploit, or signing
server interaction. UDID / ECID / serial / nonces are intentionally excluded.
"""
from __future__ import annotations

import argparse
import json
import platform
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

from device_profiles import identify_product, identify_recovery

INFO_KEYS = ("ProductType", "ProductVersion", "BuildVersion", "HardwareModel", "BasebandVersion")
SAFE_RECOVERY_KEYS = ("MODE", "CPID", "BDID", "MODEL")


def run_command(command):
    try:
        proc = subprocess.run(command, capture_output=True, text=True,
                              timeout=12, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return proc.stdout.strip() if proc.returncode == 0 else None


def compare_versions(current, target):
    def parts(s):
        if not isinstance(s, str) or not re.fullmatch(r"\d+(?:\.\d+){0,2}", s):
            return None
        return tuple(map(int, s.split(".")))
    left, right = parts(current), parts(target)
    if left is None or right is None:
        return "UNKNOWN"
    n = max(len(left), len(right))
    left += (0,) * (n - len(left))
    right += (0,) * (n - len(right))
    return ("TARGET_OLDER_THAN_INSTALLED" if left > right
            else "TARGET_NEWER_THAN_INSTALLED" if left < right
            else "SAME_IOS_VERSION")


def parse_recovery(text):
    """Restrict recovery output to a small allowlist; strip all sensitive fields."""
    values = {}
    for line in (text or "").splitlines():
        if ":" not in line:
            continue
        key, val = (item.strip() for item in line.split(":", 1))
        if key.upper() in SAFE_RECOVERY_KEYS and len(val) < 80:
            values[key.lower()] = val
    return values


def read_report_archive(filename, product_type=None):
    """Verify internal report provenance and its applicability to this device.

    Do not infer restore eligibility. Never extract ZIP members.
    """
    path = Path(filename).expanduser()
    if not path.is_file():
        raise ValueError("Research report ZIP does not exist")
    members = {}
    with zipfile.ZipFile(path) as archive:
        for name in ("research_summary.json", "ipsw_http_source.json"):
            matching = [info for info in archive.infolist() if info.filename == name]
            if len(matching) != 1 or not 0 < matching[0].file_size <= 128 * 1024:
                raise ValueError(f"Missing or invalid research report member: {name}")
            with archive.open(matching[0]) as stream:
                raw = stream.read(128 * 1024 + 1)
            if len(raw) > 128 * 1024:
                raise ValueError(f"Oversized research report member: {name}")
            members[name] = json.loads(raw)
    summary = members["research_summary.json"]
    source = members["ipsw_http_source.json"]
    if not isinstance(summary, dict) or not isinstance(source, dict):
        raise ValueError("Research report JSON must be objects")
    inventory = summary.get("input_inventory")
    manifest_sha = source.get("manifest_sha256")
    consistent = (
        isinstance(inventory, list) and len(inventory) == 1
        and isinstance(inventory[0], dict)
        and inventory[0].get("sha256") == manifest_sha
        and inventory[0].get("ios_version") == source.get("ios_version")
        and inventory[0].get("build_version") == source.get("build_version")
        and summary.get("manifest_count") == 1
    )
    declared = inventory[0].get("supported_product_types", []) if consistent else []
    device_applicability = "UNKNOWN"
    if product_type and consistent and isinstance(declared, list) and declared:
        device_applicability = (
            "MATCH" if product_type.casefold() in
            [p.casefold() for p in declared if isinstance(p, str)]
            else "MISMATCH"
        )
    return {
        "report_metadata_consistent": bool(consistent),
        "report_device_applicability": device_applicability,
        "report_declared_products": declared if isinstance(declared, list) else [],
        "report_ios_version": source.get("ios_version", "UNKNOWN"),
        "report_build": source.get("build_version", "UNKNOWN"),
        "manifest_sha256": manifest_sha or "UNKNOWN",
        "note": "Firmware manifest metadata only. No Apple signing, SEP or restore eligibility checked.",
    }


def probe(target_ios="26.1"):
    result = {
        "tool": "nyx16-mac-probe",
        "execution_host": platform.system(),
        "mode": "NOT_DETECTED",
        "usb_device_count": 0,
        "observed": {},
        "device_identification": {
            "status": "UNKNOWN", "device": "UNKNOWN", "chip_family": "UNKNOWN",
        },
        "target_ios_version": target_ios,
        "version_relationship": "UNKNOWN",
        "apple_signing_status": "NOT_CHECKED",
        "sep_baseband_compatibility": "UNKNOWN",
        "unsigned_downgrade": "NOT_DEMONSTRATED",
        "device_modified": False,
    }
    if result["execution_host"] != "Darwin":
        result["note"] = "Connect the iPhone to a Mac and run the probe locally."
        return result
    if not shutil.which("idevice_id") or not shutil.which("ideviceinfo"):
        result["note"] = "MacPorts libimobiledevice is missing."
        return result

    udids = run_command(["idevice_id", "-l"])
    devices = [s for s in (udids or "").splitlines() if s.strip()]
    result["usb_device_count"] = len(devices)
    if len(devices) > 1:
        result["mode"] = "MULTIPLE_DEVICES"
        result["note"] = "Disconnect other iOS devices; selection was refused."
        return result
    if len(devices) == 1:
        # Use the UDID internally only; never record or print it.
        udid = devices[0]
        observed = {}
        for key in INFO_KEYS:
            value = run_command(["ideviceinfo", "-u", udid, "-k", key])
            if value and len(value) <= 128:
                observed[key] = value
        if not observed:
            result["mode"] = "USB_VISIBLE_NOT_PAIRED"
            result["note"] = "Unlock the device and choose Trust This Computer when possible."
            return result
        result["mode"] = "NORMAL"
        result["observed"] = observed
        result["device_identification"] = identify_product(
            observed.get("ProductType"), observed.get("HardwareModel")
        )
        result["version_relationship"] = compare_versions(observed.get("ProductVersion"), target_ios)
        result["note"] = "Hardware identification only; no unsigned firmware restore was attempted."
        return result
    if shutil.which("irecovery"):
        rec = parse_recovery(run_command(["irecovery", "-q"]))
        if rec:
            result["mode"] = "RECOVERY_OR_DFU"
            result["observed"] = rec
            result["device_identification"] = {
                "status": "CHIP_ONLY",
                "device": "UNKNOWN",
                "chip_family": identify_recovery(rec.get("cpid")),
            }
            result["note"] = "Recovery/DFU CPID identifies a chip family only, not a model."
            return result
    result["note"] = "No accessible iOS device; check cable, pairing, or Recovery mode."
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description="Nyx16 read-only macOS iPhone A12-A16 probe")
    parser.add_argument("--target-ios", default="26.1", help="Reference version for comparison, not a restore request")
    parser.add_argument("--report-zip", help="Optional Nyx16 GitHub Actions report ZIP")
    parser.add_argument("--output", help="Optional local JSON file with no serial, UDID, ECID or nonce")
    args = parser.parse_args(argv)
    if not re.fullmatch(r"\d+(?:\.\d+){0,2}", args.target_ios):
        parser.error("--target-ios must be an iOS version such as 26.1")
    result = probe(target_ios=args.target_ios)
    if args.report_zip:
        product_type = result.get("observed", {}).get("ProductType")
        try:
            report = read_report_archive(args.report_zip, product_type=product_type)
            result["nyx16_actions_report"] = report
            if report["report_device_applicability"] == "MISMATCH":
                result["warning"] = (
                    "This report is for a different iPhone model. "
                    "Do not treat its manifest as compatible with the connected device."
                )
        except (ValueError, OSError, zipfile.BadZipFile,
                json.JSONDecodeError, UnicodeDecodeError) as exc:
            result["nyx16_actions_report"] = {"error": str(exc)}
    text = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        Path(args.output).expanduser().write_text(text, encoding="utf-8")
    print(text, end="")
    return 0 if result["mode"] in ("NORMAL", "RECOVERY_OR_DFU") else 1


if __name__ == "__main__":
    sys.exit(main())
