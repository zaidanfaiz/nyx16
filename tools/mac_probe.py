"""Nyx16 macOS first hardware probe: USB device identity, read-only.

No flashing, pairing mutation, device unlock, activation manipulation, or
communication with Apple's signing service. Device identifiers are never saved.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import platform
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

TARGET = {
    "device": "iPhone 12",
    "product_type": "iPhone13,2",
    "chip_family": "A14",
    "target_ios": "26.1",
    "target_build": "23B85",
    "target_boards": ["d53gap", "d53pap"],
    "manifest_sha256": "b756fdf237c0bd7893e280447947b6b385b36b3e8eaae372980edc3c2c054774",
}
INFO_KEYS = ("ProductType", "ProductVersion", "BuildVersion", "HardwareModel")
SAFE_RECOVERY_KEYS = ("MODE", "CPID", "BDID", "MODEL")


def run_command(command):
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=12, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def compare_versions(current, target):
    def parts(s):
        if not isinstance(s, str) or not re.fullmatch(r"\d+(?:\.\d+){0,2}", s):
            return None
        return tuple(map(int, s.split(".")))
    left, right = parts(current), parts(target)
    if left is None or right is None:
        return "UNKNOWN"
    n = max(len(left), len(right))
    left, right = left + (0,) * (n - len(left)), right + (0,) * (n - len(right))
    if left > right:
        return "TARGET_OLDER_THAN_INSTALLED"
    if left < right:
        return "TARGET_NEWER_THAN_INSTALLED"
    return "SAME_IOS_VERSION"


def parse_recovery(text):
    """Whitelisted diagnostic metadata only; discard ECID, serial and nonces."""
    output = {}
    if not text:
        return output
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().upper()
        if key in SAFE_RECOVERY_KEYS and len(value.strip()) <= 80:
            output[key.lower()] = value.strip()
    return output


def read_report_archive(filename):
    """Optionally compare a local Nyx16 Actions report; never extract ZIP files."""
    path = Path(filename).expanduser()
    if not path.is_file():
        raise ValueError("Report ZIP not found")
    with zipfile.ZipFile(path) as archive:
        required = ("research_summary.json", "ipsw_http_source.json")
        records = {}
        for name in required:
            matching = [entry for entry in archive.infolist() if entry.filename == name]
            if len(matching) != 1 or matching[0].file_size > 128 * 1024:
                raise ValueError(f"Missing or oversized report member: {name}")
            with archive.open(matching[0]) as fp:
                raw = fp.read(128 * 1024 + 1)
            if len(raw) > 128 * 1024:
                raise ValueError("Oversized report member")
            records[name] = json.loads(raw)
    summary, source = records["research_summary.json"], records["ipsw_http_source.json"]
    if not isinstance(summary, dict) or not isinstance(source, dict):
        raise ValueError("Invalid report document")
    valid = (
        source.get("manifest_sha256") == TARGET["manifest_sha256"]
        and source.get("ios_version") == TARGET["target_ios"]
        and source.get("build_version") == TARGET["target_build"]
        and source.get("product_type_checked") == TARGET["product_type"]
        and summary.get("manifest_count") == 1
    )
    return {
        "report_valid_for_preset": valid,
        "manifest_sha256": source.get("manifest_sha256", "UNKNOWN"),
        "source_kind": source.get("source_kind", "UNKNOWN"),
        "note": "Checks report metadata consistency; not Apple signing or a complete IPSW hash.",
    }


def probe():
    result = {
        "tool": "nyx16-mac-probe",
        "execution_host": platform.system(),
        "mode": "NOT_DETECTED",
        "usb_device_count": 0,
        "target": TARGET,
        "observed": {},
        "model_match": "UNKNOWN",
        "board_match": "UNKNOWN",
        "version_relationship": "UNKNOWN",
        "apple_signing_status": "NOT_CHECKED",
        "sep_baseband_compatibility": "UNKNOWN",
        "unsigned_downgrade": "NOT_DEMONSTRATED",
        "device_modified": False,
    }
    if result["execution_host"] != "Darwin":
        result["note"] = "Run on macOS with the iPhone attached over USB."
        return result
    if not shutil.which("idevice_id") or not shutil.which("ideviceinfo"):
        result["note"] = "Install MacPorts libimobiledevice and retry."
        return result
    udids = run_command(["idevice_id", "-l"])
    devices = [s for s in (udids or "").splitlines() if s.strip()]
    result["usb_device_count"] = len(devices)
    if len(devices) > 1:
        result["mode"] = "MULTIPLE_DEVICES"
        result["note"] = "Disconnect other iOS devices; no device was selected."
        return result
    if len(devices) == 1:
        udid = devices[0].strip()
        observed = {}
        for key in INFO_KEYS:
            value = run_command(["ideviceinfo", "-u", udid, "-k", key])
            if value and len(value) < 128:
                observed[key] = value
        if not observed:
            result["mode"] = "USB_VISIBLE_NOT_PAIRED"
            result["note"] = "Unlock iPhone and tap Trust This Computer; no pairing changes were attempted."
            return result
        result["mode"] = "NORMAL"
        result["observed"] = observed
        model = observed.get("ProductType")
        result["model_match"] = (
            "MATCH" if model == TARGET["product_type"] else "MISMATCH"
            if model else "UNKNOWN"
        )
        board = observed.get("HardwareModel")
        result["board_match"] = (
            "MATCH" if board.casefold() in TARGET["target_boards"] else "MISMATCH"
            if board else "UNKNOWN"
        )
        result["version_relationship"] = compare_versions(
            observed.get("ProductVersion"), TARGET["target_ios"]
        )
        if result["model_match"] != "MATCH":
            result["note"] = "The connected iPhone is not the intended iPhone 12 target; stop."
        else:
            result["note"] = "Read-only identity comparison only; this does not authorize firmware restore."
        return result

    # If the device isn't in normal mode, optionally identify DFU / Recovery.
    if shutil.which("irecovery"):
        observed = parse_recovery(run_command(["irecovery", "-q"]))
        if observed:
            result["mode"] = "RECOVERY_OR_DFU"
            result["observed"] = observed
            result["note"] = "Recovery diagnostics only; no attempt to modify firmware."
            return result
    result["note"] = "No accessible device. Check USB cable, trust prompt, or recovery connection."
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description="Nyx16 read-only iPhone 12 macOS USB diagnostics")
    parser.add_argument("--report-zip", help="Optional local GitHub Actions report ZIP for source comparison")
    parser.add_argument("--output", help="Optional local JSON report; no serial/UDID/ECID is recorded")
    args = parser.parse_args(argv)
    result = probe()
    if args.report_zip:
        try:
            result["nyx16_actions_report"] = read_report_archive(args.report_zip)
        except (ValueError, OSError, zipfile.BadZipFile, json.JSONDecodeError) as exc:
            result["nyx16_actions_report"] = {"error": str(exc)}
    output = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        Path(args.output).expanduser().write_text(output, encoding="utf-8")
    print(output, end="")
    return 0 if result["mode"] in ("NORMAL", "RECOVERY_OR_DFU") else 1


if __name__ == "__main__":
    sys.exit(main())
