"""Evidence-grounded, read-only IPSW manifest research reports.

A BuildManifest declares metadata; it never establishes signing or restore eligibility.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import plistlib
from datetime import date
from pathlib import Path

from .chips import list_chips

MAX_MANIFEST_SIZE = 10 * 1024 * 1024
MAX_MANIFESTS = 64
MAX_IDENTITIES = 512
FIELDS = [
    "source_file", "manifest_sha256", "ios_version", "build_version",
    "supported_product_types", "identity_index", "identity_board",
    "identity_product_type", "product_board_pairing",
    "apple_signing", "sep_compatibility", "baseband_compatibility",
    "unsigned_downgrade",
]


class EvidenceError(ValueError):
    """The evidence file is invalid or would exceed inspection limits."""


def _safe_text(value):
    return value.strip()[:128] if isinstance(value, str) else ""


def _text_list(value):
    if not isinstance(value, list):
        return []
    return sorted({_safe_text(v) for v in value if _safe_text(v)})


def read_plist(path: Path, root: Path):
    if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
        raise EvidenceError(f"Symlink or out-of-root evidence rejected: {path}")
    size = path.stat().st_size
    if not 0 < size <= MAX_MANIFEST_SIZE:
        raise EvidenceError(f"Manifest must be 1 byte to 10 MiB: {path}")
    raw = path.read_bytes()
    try:
        data = plistlib.loads(raw)
    except (ValueError, TypeError, OverflowError, plistlib.InvalidFileException) as exc:
        raise EvidenceError(f"Cannot parse plist {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise EvidenceError(f"Expected plist dictionary: {path}")
    identities = data.get("BuildIdentities")
    if not isinstance(identities, list) or len(identities) > MAX_IDENTITIES:
        raise EvidenceError(f"BuildIdentities must be a list with <=512 entries: {path}")
    if any(not isinstance(item, dict) for item in identities):
        raise EvidenceError(f"BuildIdentities contains a non-dictionary: {path}")
    products = data.get("SupportedProductTypes")
    if products is not None and not isinstance(products, list):
        raise EvidenceError(f"SupportedProductTypes must be an array: {path}")
    return data, hashlib.sha256(raw).hexdigest()


def manifest_rows(root: Path):
    if not root.is_dir():
        raise EvidenceError(f"Manifest directory missing: {root}")
    paths = sorted(root.rglob("*.plist"))
    if len(paths) > MAX_MANIFESTS:
        raise EvidenceError(f"Too many manifest files (limit {MAX_MANIFESTS})")
    rows = []
    manifest_inventory = []
    for path in paths:
        info, digest = read_plist(path, root)
        supported = _text_list(info.get("SupportedProductTypes"))
        ios = _safe_text(info.get("ProductVersion"))
        build = _safe_text(info.get("ProductBuildVersion"))
        source = path.relative_to(root).as_posix()
        ids = info["BuildIdentities"]
        manifest_inventory.append({
            "file": source,
            "sha256": digest,
            "ios_version": ios or None,
            "build_version": build or None,
            "supported_product_types": supported,
            "build_identities": len(ids),
        })
        for n, identity in enumerate(ids):
            metadata = identity.get("Info")
            metadata = metadata if isinstance(metadata, dict) else {}
            board = _safe_text(metadata.get("DeviceClass"))
            # A top-level list of products does NOT establish individual
            # product/board pairings for a BuildIdentity.
            identity_product = _safe_text(metadata.get("ProductType"))
            rows.append({
                "source_file": source,
                "manifest_sha256": digest,
                "ios_version": ios,
                "build_version": build,
                "supported_product_types": ";".join(supported),
                "identity_index": n,
                "identity_board": board,
                "identity_product_type": identity_product,
                "product_board_pairing": "DECLARED_IN_IDENTITY" if board and identity_product else "NOT_ESTABLISHED",
                "apple_signing": "NOT_CHECKED",
                "sep_compatibility": "UNKNOWN",
                "baseband_compatibility": "UNKNOWN",
                "unsigned_downgrade": "NOT_DEMONSTRATED",
            })
    return manifest_inventory, rows


def validate_sources(path: Path):
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("claims"), list):
        raise EvidenceError("Secure Boot evidence must have a claims list")
    seen = set()
    for claim in data["claims"]:
        if not isinstance(claim, dict) or not all(
            isinstance(claim.get(k), str) and claim[k].strip()
            for k in ("id", "scope", "statement", "source", "type")
        ):
            raise EvidenceError("Claim missing a required field")
        if claim["id"] in seen or not claim["source"].startswith("https://support.apple.com/"):
            raise EvidenceError("Duplicate claim or source is not official Apple documentation")
        seen.add(claim["id"])
    return data


def write_csv(path: Path, fields, rows):
    with path.open("w", encoding="utf-8", newline="") as fp:
        writer = csv.DictWriter(fp, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def build_reports(manifest_dir, evidence_file, output_dir):
    root = Path(manifest_dir)
    evidence = validate_sources(Path(evidence_file))
    manifests, rows = manifest_rows(root)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    write_csv(out / "firmware_manifest_matrix.csv", FIELDS, rows)

    chips = [{
        "family": chip["family"], "silicon": chip["silicon"],
        "cpid": chip["cpid_hex"], "manifest_coverage": "NOT_MAPPED",
        "apple_signing": "NOT_CHECKED", "unsigned_downgrade": "NOT_DEMONSTRATED",
    } for chip in list_chips()]
    write_csv(out / "soc_research_matrix.csv",
              ["family", "silicon", "cpid", "manifest_coverage",
               "apple_signing", "unsigned_downgrade"], chips)

    evidence_lines = [
        "# Apple Secure Boot: documented constraints",
        "",
        "Evidence type: **vendor documentation**, not a hardware exploit demonstration.",
        "",
    ]
    for c in evidence["claims"]:
        evidence_lines += [
            f"## {c['id']}",
            f"- Scope: {c['scope']}",
            f"- Statement: {c['statement']}",
            f"- Source: {c['source']}",
            f"- Evidence type: {c['type']}",
            "- Device experiment: NOT_PERFORMED",
            "",
        ]
    evidence_lines += [
        "## Unverified questions",
        "",
        "APNonce / signing eligibility, per-version SEP and baseband compatibility,",
        "bootability, and unsigned downgrade feasibility require separate evidence.",
        "This report does not test them.",
        "",
    ]
    (out / "secure_boot_evidence.md").write_text("\n".join(evidence_lines), encoding="utf-8")
    summary = {
        "project": "Nyx16",
        "mode": "OFFLINE_READ_ONLY",
        "manifest_count": len(manifests),
        "build_identity_rows": len(rows),
        "soc_families": [c["family"] for c in chips],
        "official_documentation_claims": len(evidence["claims"]),
        "apple_signing_status": "NOT_CHECKED",
        "sep_compatibility": "UNKNOWN",
        "baseband_compatibility": "UNKNOWN",
        "unsigned_downgrade": "NOT_DEMONSTRATED",
        "input_inventory": manifests,
    }
    (out / "research_summary.json").write_text(
        json.dumps(summary, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    summary_md = [
        "# Nyx16 GitHub Actions research report",
        "",
        f"- Manifest files analyzed: **{len(manifests)}**",
        f"- Build identities recorded: **{len(rows)}**",
        f"- SoC families in baseline matrix: **{len(chips)} (A12–A16)**",
        f"- Vendor-documentation claims: **{len(evidence['claims'])}**",
        "- Apple signing: **NOT CHECKED**",
        "- SEP / baseband compatibility: **UNKNOWN**",
        "- Unsigned downgrade: **NOT DEMONSTRATED**",
        "",
    ]
    if not manifests:
        summary_md += [
            "> No real BuildManifest.plist evidence was supplied.",
            "> Matrices are baseline research tables, not device-specific compatibility results.",
            "",
        ]
    summary_md += [
        "See the downloaded artifact for the CSV matrices, manifest hashes,",
        "and source-linked Secure Boot evidence. No firmware is flashed or executed.",
        "",
    ]
    (out / "RESEARCH_SUMMARY.md").write_text("\n".join(summary_md), encoding="utf-8")
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description="Nyx16 offline metadata and Secure Boot evidence matrix")
    parser.add_argument("--manifests", default="evidence/manifests")
    parser.add_argument("--evidence", default="evidence/secure_boot_sources.json")
    parser.add_argument("--out", default="reports")
    args = parser.parse_args(argv)
    try:
        summary = build_reports(args.manifests, args.evidence, args.out)
    except (EvidenceError, OSError, json.JSONDecodeError) as exc:
        parser.exit(status=1, message=f"Nyx16 research error: {exc}\n")
    print(json.dumps({k: v for k, v in summary.items() if k != "input_inventory"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
