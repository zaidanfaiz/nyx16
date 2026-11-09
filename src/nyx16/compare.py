"""Nyx16: comparison of declared IPSW manifest fields (NOT restore compatibility).

No device access, TSS calls, SHA/SP or firmware-binary extraction. Components
are compared using the metadata present within BuildManifest only.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import plistlib
from collections import Counter
from pathlib import Path

MAX_SIZE = 10 * 1024 * 1024
CATEGORIES = ("iBoot", "iBSS", "iBEC", "LLB", "SEP", "Baseband", "KernelCache")
FIELDS = (
    "board", "identity_variant", "component_category",
    "current_manifest_keys", "target_manifest_keys",
    "current_digest_fields", "target_digest_fields",
    "metadata_comparison", "restore_compatibility",
)


class ComparisonError(ValueError):
    pass


def read_manifest(path: str):
    p = Path(path)
    if not p.is_file() or not 0 < p.stat().st_size <= MAX_SIZE:
        raise ComparisonError(f"Manifest missing or larger than 10 MiB: {path}")
    data = p.read_bytes()
    try:
        m = plistlib.loads(data)
    except (ValueError, TypeError, OverflowError, plistlib.InvalidFileException) as exc:
        raise ComparisonError(f"Invalid plist: {path}") from exc
    if not isinstance(m, dict) or not isinstance(m.get("BuildIdentities"), list):
        raise ComparisonError(f"BuildManifest requires an identity list: {path}")
    return m, hashlib.sha256(data).hexdigest()


def assert_subject(m, product, ios_version, build):
    products = m.get("SupportedProductTypes")
    if not isinstance(products, list) or product.casefold() not in [
            item.casefold() for item in products if isinstance(item, str)]:
        raise ComparisonError(f"Manifest does not list target ProductType: {product}")
    if m.get("ProductVersion") != ios_version or m.get("ProductBuildVersion") != build:
        raise ComparisonError(f"Manifest version/build doesn't match expected {ios_version} {build}")


def category(name):
    n = name.lower()
    if "baseband" in n:
        return "Baseband"
    if "kernelcache" in n or "kernelcache" in n.replace("-", ""):
        return "KernelCache"
    if n.startswith("sep") or n.endswith("sep") or "sepfirmware" in n:
        return "SEP"
    for key in ("iboot", "ibss", "ibec", "llb"):
        if key in n:
            return {"iboot": "iBoot", "ibss": "iBSS", "ibec": "iBEC", "llb": "LLB"}[key]
    return None


def component_fields(manifest_component):
    if not isinstance(manifest_component, dict):
        return {"digest_record": "UNKNOWN", "path_declared": False}
    digest = manifest_component.get("Digest")
    if isinstance(digest, bytes):
        # This fingerprints the *manifest's digest field*, not the binary
        # and not a validated cryptographic image hash.
        fp = hashlib.sha256(digest).hexdigest()
    else:
        fp = "NOT_DECLARED"
    info = manifest_component.get("Info")
    path = info.get("Path") if isinstance(info, dict) else None
    return {"digest_record": fp, "path_declared": isinstance(path, str) and bool(path)}


def identities_for_board(m, board):
    selected = {}
    for identity in m["BuildIdentities"]:
        if not isinstance(identity, dict):
            raise ComparisonError("Malformed build identity")
        info = identity.get("Info")
        if not isinstance(info, dict):
            continue
        device_class = info.get("DeviceClass")
        if not isinstance(device_class, str) or device_class.casefold() != board.casefold():
            continue
        # Identity index ordering can change between firmware builds; never pair by index.
        variant = str(info.get("Variant", "UNSPECIFIED"))
        behavior = str(info.get("RestoreBehavior", "UNSPECIFIED"))
        key = (variant, behavior)
        selected.setdefault(key, []).append(identity)
    return selected


def summarize_components(identity):
    manifest = identity.get("Manifest", {})
    if not isinstance(manifest, dict):
        return {}
    components = {cat: {} for cat in CATEGORIES}
    for name, metadata in manifest.items():
        if not isinstance(name, str):
            continue
        cat = category(name)
        if cat:
            components[cat][name] = component_fields(metadata)
    return {cat: value for cat, value in components.items() if value}


def component_comparison(left, right):
    if not left and not right:
        return "NOT_DECLARED_IN_EITHER_MANIFEST"
    if not left or not right:
        return "DECLARATION_DIFFERS"
    if set(left) != set(right):
        return "COMPONENT_KEY_SET_DIFFERS"
    a = {k: v["digest_record"] for k, v in left.items()}
    b = {k: v["digest_record"] for k, v in right.items()}
    if any(v == "NOT_DECLARED" or v == "UNKNOWN" for v in list(a.values()) + list(b.values())):
        return "DIGEST_FIELDS_INSUFFICIENT"
    return "MANIFEST_DIGEST_FIELDS_MATCH" if a == b else "MANIFEST_DIGEST_FIELDS_DIFFER"


def compare(current, target, board, product="iPhone12,1",
            current_version="27.2", current_build="24B119",
            target_version="26.1", target_build="23B85"):
    m_current, sha_current = read_manifest(current)
    m_target, sha_target = read_manifest(target)
    assert_subject(m_current, product, current_version, current_build)
    assert_subject(m_target, product, target_version, target_build)
    current_ids = identities_for_board(m_current, board)
    target_ids = identities_for_board(m_target, board)
    if not current_ids or not target_ids:
        raise ComparisonError(f"No matching board identity for {board} in both manifests")

    rows = []
    signatures = sorted(set(current_ids) | set(target_ids))
    for sig in signatures:
        c_entries = current_ids.get(sig, [])
        t_entries = target_ids.get(sig, [])
        if len(c_entries) != 1 or len(t_entries) != 1:
            for cat in CATEGORIES:
                rows.append({
                    "board": board,
                    "identity_variant": " / ".join(sig),
                    "component_category": cat,
                    "current_manifest_keys": "",
                    "target_manifest_keys": "",
                    "current_digest_fields": "",
                    "target_digest_fields": "",
                    "metadata_comparison": "IDENTITY_MISSING_OR_AMBIGUOUS",
                    "restore_compatibility": "UNKNOWN",
                })
            continue
        comps_c = summarize_components(c_entries[0])
        comps_t = summarize_components(t_entries[0])
        for cat in CATEGORIES:
            a, b = comps_c.get(cat, {}), comps_t.get(cat, {})
            rows.append({
                "board": board,
                "identity_variant": " / ".join(sig),
                "component_category": cat,
                "current_manifest_keys": ";".join(sorted(a)),
                "target_manifest_keys": ";".join(sorted(b)),
                "current_digest_fields": ";".join(
                    f"{k}:{a[k]['digest_record']}" for k in sorted(a)
                ),
                "target_digest_fields": ";".join(
                    f"{k}:{b[k]['digest_record']}" for k in sorted(b)
                ),
                "metadata_comparison": component_comparison(a, b),
                "restore_compatibility": "UNKNOWN",
            })
    counts = dict(Counter(row["metadata_comparison"] for row in rows))
    report = {
        "project": "Nyx16", "analysis": "READ_ONLY_BUILD_MANIFEST_FIELD_COMPARISON",
        "product_type": product, "board": board,
        "current_ios": current_version, "current_build": current_build,
        "target_ios": target_version, "target_build": target_build,
        "current_manifest_sha256": sha_current, "target_manifest_sha256": sha_target,
        "current_board_identity_count": sum(map(len, current_ids.values())),
        "target_board_identity_count": sum(map(len, target_ids.values())),
        "comparisons": counts, "rows": rows,
        "apple_signing": "NOT_CHECKED",
        "sep_cross_version_compatibility": "UNKNOWN",
        "baseband_cross_version_compatibility": "UNKNOWN",
        "unsigned_downgrade": "NOT_DEMONSTRATED",
        "warning": (
            "A matching manifest digest field does not verify the firmware binary, "
            "SEP/baseband compatibility, or Apple restore authorization."
        ),
    }
    return report


def write_report(data, outdir):
    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "iphone11_firmware_comparison.json").write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with (out / "iphone11_component_metadata_matrix.csv").open(
        "w", encoding="utf-8", newline=""
    ) as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(data["rows"])
    lines = [
        "# Nyx16 iPhone 11 A13 firmware metadata comparison",
        "",
        f"- Device: **{data['product_type']}** / board **{data['board']}**",
        f"- Installed-version reference: **iOS {data['current_ios']} ({data['current_build']})**",
        f"- Target: **iOS {data['target_ios']} ({data['target_build']})**",
        f"- Identity records for board: current **{data['current_board_identity_count']}**, "
        f"target **{data['target_board_identity_count']}**",
        f"- Component category comparisons: **{len(data['rows'])}**",
        "",
        "## Findings (metadata only)",
        "",
    ]
    for status, count in sorted(data["comparisons"].items()):
        lines.append(f"- {status}: **{count}**")
    lines += [
        "",
        "## Critical limitations",
        "",
        "- **Apple signing:** NOT_CHECKED by Nyx16",
        "- **SEP version compatibility:** UNKNOWN",
        "- **Baseband version compatibility:** UNKNOWN",
        "- **Unsigned downgrade:** NOT_DEMONSTRATED",
        "",
        "**This comparison never accesses a connected iPhone, sends restore commands, "
        "or reads SEP/baseband firmware binaries.**",
        "",
        "Component entries refer to manifest metadata fields only. A changed field "
        "does not establish a vulnerability; unchanged fields do not prove bootability.",
        "",
    ]
    (out / "IPHONE11_COMPARISON_SUMMARY.md").write_text(
        "\n".join(lines), encoding="utf-8"
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description="Compare two Apple IPSW BuildManifest.plist files")
    parser.add_argument("--current", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--board", default="N104AP")
    parser.add_argument("--product", default="iPhone12,1")
    parser.add_argument("--out", default="reports")
    args = parser.parse_args(argv)
    try:
        report = compare(args.current, args.target, board=args.board, product=args.product)
        write_report(report, args.out)
    except (ComparisonError, OSError, ValueError) as exc:
        parser.exit(1, f"Nyx16 comparison failed: {exc}\n")
    print(json.dumps({k: v for k, v in report.items() if k != "rows"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
