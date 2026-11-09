"""Nyx16 Stage 5: conservative, OFFLINE downgrade feasibility audit.

Consumes a sanitized Stage 4 report and a date-stamped third-party signing
snapshot. No device commands, TSS requests, Apple account access or firmware
operations. This is a research decision, not a restoration tool.
"""
from __future__ import annotations

import argparse
from datetime import date
import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit

EXPECTED = {
    "product_type": "iPhone12,1", "board": "N104AP",
    "current_ios": "27.2", "current_build": "24B119",
    "target_ios": "26.1", "target_build": "23B85",
}
REQUIRED_STAGE4_CHECKS = (
    "report_product_type", "report_board",
    "report_current_ios", "report_current_build",
    "report_target_ios", "report_target_build",
    "current_manifest_provenance", "target_manifest_provenance",
    "report_not_restore_claim", "device_product", "device_board",
    "device_installed_ios", "device_installed_build",
)
MAX_JSON_BYTES = 1024 * 1024


class AuditError(ValueError):
    pass


def load_json(path):
    p = Path(path).expanduser()
    if not p.is_file() or p.is_symlink() or not 0 < p.stat().st_size <= MAX_JSON_BYTES:
        raise AuditError(f"Input missing, symlinked or larger than 1 MiB: {p}")
    raw = p.read_bytes()
    try:
        result = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise AuditError(f"Invalid JSON: {p}") from exc
    if not isinstance(result, dict):
        raise AuditError("Input JSON must be an object")
    return result, hashlib.sha256(raw).hexdigest()


def inspect_stage4(report):
    issues = []
    if report.get("experiment") != "NYX16_STAGE4_IPHONE11":
        issues.append("Unexpected experiment type")
    if report.get("status") != "METADATA_MATCH_ONLY":
        issues.append("Stage 4 was not confirmed as a metadata-only match")
    if report.get("mode", report.get("device_mode")) != "NORMAL":
        issues.append("No normal-mode USB identity evidence")
    if report.get("connected_device") != "iPhone 11":
        issues.append("Device model is not iPhone 11")
    values = report.get("target")
    if not isinstance(values, dict):
        values = {}
    for key, expected in EXPECTED.items():
        if not isinstance(values.get(key), str) or values[key].casefold() != expected.casefold():
            issues.append(f"Stage 4 target mismatch: {key}")
    checks = report.get("checks")
    if not isinstance(checks, dict):
        checks = {}
    for key in REQUIRED_STAGE4_CHECKS:
        if checks.get(key) != "MATCH":
            issues.append(f"Unverified prerequisite: {key}")
    if report.get("apple_signing") != "NOT_CHECKED":
        issues.append("Signing status misrepresented as independently checked")
    if report.get("sep_baseband_cross_version_compatibility") != "UNKNOWN":
        issues.append("SEP/baseband compatibility claim is not supported")
    if report.get("unsigned_downgrade") != "NOT_DEMONSTRATED":
        issues.append("Unsigned downgrade claim is not supported")
    if report.get("device_modified") is not False:
        issues.append("Stage 4 is not attested read-only")
    counts = report.get("compared_manifest_digest_statuses")
    if not isinstance(counts, dict):
        issues.append("Manifest comparison evidence unavailable")
        counts = {}
    for key in ("DIGEST_FIELDS_INSUFFICIENT", "MANIFEST_DIGEST_FIELDS_DIFFER"):
        value = counts.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            issues.append(f"Invalid manifest comparison count: {key}")
    return issues, {k: counts.get(k) for k in (
        "DIGEST_FIELDS_INSUFFICIENT", "MANIFEST_DIGEST_FIELDS_DIFFER"
    )}, report.get("installed_baseband_version", "UNKNOWN")


def inspect_signing_snapshot(data):
    issues = []
    if data.get("evidence_type") != "THIRD_PARTY_PUBLIC_CATALOG_SNAPSHOT":
        issues.append("Signing evidence is not a labeled catalog snapshot")
    if data.get("device") != EXPECTED["product_type"]:
        issues.append("Signing snapshot device mismatch")
    if data.get("current_version") != EXPECTED["current_ios"] or data.get("current_build") != EXPECTED["current_build"]:
        issues.append("Signing snapshot current build mismatch")
    if data.get("target_version") != EXPECTED["target_ios"] or data.get("target_build") != EXPECTED["target_build"]:
        issues.append("Signing snapshot target build mismatch")
    for key in ("current_catalog_status", "target_catalog_status"):
        if data.get(key) not in ("SIGNED", "UNSIGNED", "UNKNOWN"):
            issues.append(f"Invalid signing catalog state: {key}")
    observed = data.get("observed_date")
    try:
        checked_day = date.fromisoformat(observed) if isinstance(observed, str) else None
    except ValueError:
        checked_day = None
    if not checked_day or checked_day > date.today():
        issues.append("Snapshot observation date missing, invalid, or in the future")
    sources = data.get("source_urls")
    if not isinstance(sources, list) or len(sources) < 1 or any(
        not isinstance(url, str) or urlsplit(url).hostname != "ipsw.me"
        or urlsplit(url).scheme != "https" for url in sources
    ):
        issues.append("Source must reference HTTPS ipsw.me catalog")
    return issues, checked_day


def assess(stage4, snapshot, stage4_digest):
    stage4_issues, counts, baseband = inspect_stage4(stage4)
    catalog_issues, date_observed = inspect_signing_snapshot(snapshot)
    all_issues = stage4_issues + catalog_issues
    if all_issues:
        status = "NO_GO_INSUFFICIENT_OR_INVALID_EVIDENCE"
        decision = "Do not attempt restore: submitted evidence is incomplete or contradictory"
    elif snapshot.get("target_catalog_status") == "UNSIGNED":
        status = "NO_GO_UNSIGNED_TARGET"
        decision = "No routine Finder / idevicerestore restore route for the target IPSW"
    else:
        status = "HOLD_UNVERIFIED_ELIGIBILITY"
        decision = "No authorization to restore established by a third-party catalog"
    age_days = (date.today() - date_observed).days if date_observed else None
    catalog_stale = age_days is None or age_days > 7
    return {
        "experiment": "NYX16_STAGE5_IPHONE11_FEASIBILITY",
        "audit_type": "OFFLINE_EVIDENCE_REVIEW",
        "decision": status,
        "decision_reason": decision,
        "device": EXPECTED,
        "stage4_evidence_sha256": stage4_digest,
        "stage4_prerequisites_passed": not stage4_issues,
        "stage4_issues": stage4_issues,
        "catalog_issues": catalog_issues,
        "manifest_digest_field_comparisons": counts,
        "current_baseband_reported": baseband,
        "signing_evidence": {
            "type": "THIRD_PARTY_CATALOG_NOT_APPLE_TSS",
            "observed_date": snapshot.get("observed_date"),
            "catalog_age_days": age_days,
            "catalog_stale_over_7_days": catalog_stale,
            "current_status_as_reported": snapshot.get("current_catalog_status"),
            "target_status_as_reported": snapshot.get("target_catalog_status"),
            "source_urls": snapshot.get("source_urls", []),
            "personalized_restore_authorization": "NOT_CHECKED",
        },
        "sep_cross_version_compatibility": "UNKNOWN",
        "baseband_cross_version_compatibility": "UNKNOWN",
        "iboot_cross_version_bootability": "UNKNOWN",
        "saved_shsh_or_apnonce_eligibility": "NOT_CHECKED",
        "unsigned_downgrade": "NOT_DEMONSTRATED",
        "device_modified": False,
        "risk_review": [
            "A restore can erase device data; an existing backup and its recoverability need independent validation.",
            "A backup created on a newer iOS version may not restore on an older iOS version.",
            "Activation Lock and device ownership verification are separate from firmware metadata.",
            "SEP/baseband manifest field differences do not prove executable firmware compatibility.",
            "Unexpected restore errors may require recovery to a currently authorized iOS version.",
        ],
        "safe_next_step": (
            "Archive this audit and verify a recoverable backup. Do not issue restore/flash "
            "commands for unsigned iOS 26.1; revisit only when independent, "
            "model-specific authorization evidence becomes available."
        ),
    }


def render_markdown(result):
    lines = [
        "# Nyx16 — Stage 5 downgrade feasibility audit",
        "",
        f"**Decision: {result['decision']}**",
        "",
        f"- Device: iPhone 11 (`{EXPECTED['product_type']}`, A13, board `{EXPECTED['board']}`)",
        f"- Installed iOS: **{EXPECTED['current_ios']} ({EXPECTED['current_build']})**",
        f"- Target iOS: **{EXPECTED['target_ios']} ({EXPECTED['target_build']})**",
        "- Source: user-supplied Stage 4 macOS JSON, checked against third-party signing catalog snapshot",
        f"- Stage 4 prerequisites: **{'PASS' if result['stage4_prerequisites_passed'] else 'FAILED'}**",
        "",
        "## Evidence and limitations",
        "",
        f"- Reported installed baseband: **{result['current_baseband_reported']}**",
        f"- Manifest digest fields differing: **{result['manifest_digest_field_comparisons'].get('MANIFEST_DIGEST_FIELDS_DIFFER', 'UNKNOWN')}**",
        f"- Manifest digest fields insufficient: **{result['manifest_digest_field_comparisons'].get('DIGEST_FIELDS_INSUFFICIENT', 'UNKNOWN')}**",
        f"- Catalog current firmware: **{result['signing_evidence']['current_status_as_reported']}**",
        f"- Catalog target firmware: **{result['signing_evidence']['target_status_as_reported']}**",
        f"- Catalog observed: **{result['signing_evidence']['observed_date']}**; stale over 7 days: **{result['signing_evidence']['catalog_stale_over_7_days']}**",
        "- Apple personalized signing / TSS authorization: **NOT CHECKED**",
        "- SEP and baseband cross-version compatibility: **UNKNOWN**",
        "- iBoot bootability across versions: **UNKNOWN**",
        "- Unsigned downgrade: **NOT DEMONSTRATED**",
        "",
        "## Decision",
        "",
        result["decision_reason"] + ".",
        "",
        "## Risk review",
        "",
    ]
    lines.extend(f"- {item}" for item in result["risk_review"])
    if result["stage4_issues"] or result["catalog_issues"]:
        lines += ["", "## Evidence issues", ""]
        lines.extend(f"- {item}" for item in (
            result["stage4_issues"] + result["catalog_issues"]
        ))
    lines += [
        "", "## Next step", "",
        result["safe_next_step"], "",
        "## Sources", "",
    ]
    lines.extend(f"- {url}" for url in result["signing_evidence"]["source_urls"])
    lines += [
        "- https://support.apple.com/guide/security/", "",
        "**Research only. This report cannot authorize, perform or recommend an unsigned restore.**",
        "",
    ]
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Nyx16 Stage 5 offline downgrade feasibility audit")
    parser.add_argument("--stage4", default=str(Path.home() / "Desktop" / "nyx16-stage4.json"))
    parser.add_argument("--catalog", default="evidence/iphone11_signing_snapshot_2026-11-09.json")
    parser.add_argument("--out", default=str(Path.home() / "Desktop" / "Nyx16-Stage5"))
    args = parser.parse_args(argv)
    try:
        stage4, digest = load_json(args.stage4)
        snapshot, _ = load_json(args.catalog)
        output = assess(stage4, snapshot, digest)
        dest = Path(args.out).expanduser()
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "stage5_feasibility.json").write_text(
            json.dumps(output, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            encoding="utf-8")
        (dest / "STAGE5_FEASIBILITY.md").write_text(render_markdown(output), encoding="utf-8")
        print(json.dumps({
            "decision": output["decision"],
            "stage4_prerequisites_passed": output["stage4_prerequisites_passed"],
            "target_catalog_status": output["signing_evidence"]["target_status_as_reported"],
            "apple_signing": "NOT_CHECKED",
            "sep_baseband_compatibility": "UNKNOWN",
            "unsigned_downgrade": "NOT_DEMONSTRATED",
            "output": str(dest),
        }, indent=2))
    except (AuditError, OSError) as exc:
        parser.exit(1, f"Stage 5 audit error: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
