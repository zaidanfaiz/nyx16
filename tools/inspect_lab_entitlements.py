"""Inspect ONLY selected entitlements of a locally signed Nyx16Lab .app.

Uses Apple's codesign on macOS, never reads any device data or prints signing
identifiers, team IDs, certificate details, device identifiers, or raw plist.
An unsigned CI simulator build intentionally has no entitlements to inspect.
"""
from __future__ import annotations

import argparse
import json
import plistlib
import subprocess
import sys
from pathlib import Path


class EntitlementsError(ValueError):
    pass


def _status_of_boolean(data: dict, key: str):
    value = data.get(key)
    if value is True:
        return "TRUE"
    if value is False:
        return "FALSE"
    return "NOT_PRESENT_OR_NOT_BOOLEAN"


def _redacted_presence(data: dict, key: str):
    value = data.get(key)
    return "PRESENT_REDACTED" if isinstance(value, str) and value else "NOT_PRESENT"


def _redacted_count(data: dict, key: str):
    value = data.get(key)
    return len(value) if isinstance(value, list) else None


def inspect_signed_app(app_path: str | Path, *, runner=subprocess.run):
    path = Path(app_path).expanduser()
    if not path.is_dir() or path.suffix != ".app":
        raise EntitlementsError("Expected an existing signed .app bundle directory")
    try:
        result = runner(
            ["/usr/bin/codesign", "-d", "--entitlements", ":-", str(path)],
            capture_output=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise EntitlementsError("codesign could not inspect the local .app") from exc
    if result.returncode != 0:
        raise EntitlementsError("codesign did not return entitlements; verify development signing")
    if not 1 <= len(result.stdout) <= 1024 * 1024:
        raise EntitlementsError("Missing or oversized entitlement plist")
    try:
        entitlements = plistlib.loads(result.stdout)
    except (ValueError, TypeError, plistlib.InvalidFileException) as exc:
        raise EntitlementsError("Could not parse returned entitlements") from exc
    if not isinstance(entitlements, dict):
        raise EntitlementsError("Entitlement plist is not a dictionary")

    return {
        "tool": "nyx16-local-entitlements",
        "source": "LOCAL_SIGNED_APP_CODESIGN",
        "bundle_name": path.name,
        "get_task_allow": _status_of_boolean(entitlements, "get-task-allow"),
        "application_identifier": _redacted_presence(entitlements, "application-identifier"),
        "team_identifier": _redacted_presence(entitlements, "com.apple.developer.team-identifier"),
        "app_group_count": _redacted_count(entitlements, "com.apple.security.application-groups"),
        "associated_domain_count": _redacted_count(entitlements, "com.apple.developer.associated-domains"),
        "entitlement_key_count": len(entitlements),
        "complete_entitlements_exported": False,
        "device_inspected": False,
        "code_signature_validated": False,
        "jailbreak_status": "NOT_DEMONSTRATED",
        "note": "Local signed app entitlements only; cannot prove installed device entitlements or elevated privileges.",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read redacted entitlement facts from a signed local Nyx16Lab .app")
    parser.add_argument("--app", required=True, help="Path to locally signed Nyx16Lab.app")
    args = parser.parse_args(argv)
    try:
        report = inspect_signed_app(args.app)
    except EntitlementsError as exc:
        print(f"Nyx16 entitlement inspection: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
