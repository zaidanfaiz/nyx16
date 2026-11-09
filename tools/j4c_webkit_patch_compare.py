"""J4C: compare verified, ALREADY-FIXED WebKit patches from a local evidence manifest.

Offline documentary analysis only. Does not fetch, compile, execute or fuzz
WebKit; no iPhone or Apple infrastructure is contacted. Claims are intentionally
limited to the source descriptions and reviewed upstream commit messages.
"""
from __future__ import annotations

import argparse
import collections
import json
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "research" / "webkit_fixed_patch_cases.json"


class EvidenceError(ValueError):
    pass


def load_manifest(path: Path = DEFAULT_MANIFEST) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceError("Cannot read or parse WebKit fixed-patch manifest") from exc
    if data.get("schema_version") != 1:
        raise EvidenceError("Unsupported manifest schema")
    if data.get("finding") != "DOCUMENTARY_PATCH_COMPARISON_ONLY":
        raise EvidenceError("Manifest must not claim exploit or vulnerable-device findings")
    if not isinstance(data.get("cases"), list) or not data["cases"]:
        raise EvidenceError("Expected at least one documented fixed WebKit case")

    ids: set[str] = set()
    cutoff = date.fromisoformat(data["research_cutoff"])
    needed = ("bug_id", "title", "component", "reported_date", "fixed_date",
              "upstream_revision", "commit_short", "class", "root_cause",
              "documented_fix", "source_paths", "evidence_urls", "scope_caveat")
    for case in data["cases"]:
        if not isinstance(case, dict) or not all(case.get(k) for k in needed):
            raise EvidenceError("Case is missing required source-backed fields")
        number = case["bug_id"]
        if not isinstance(number, str) or not number.isdigit() or number in ids:
            raise EvidenceError("Case bug IDs must be unique decimal strings")
        ids.add(number)
        start = date.fromisoformat(case["reported_date"])
        resolved = date.fromisoformat(case["fixed_date"])
        if not start <= resolved <= cutoff:
            raise EvidenceError("Case reported/fixed dates do not fit research cutoff")
        if not case["upstream_revision"].endswith("@main"):
            raise EvidenceError("Case is missing a canonical fixed upstream main revision")
        urls = case["evidence_urls"]
        if not isinstance(urls, list) or not all(isinstance(x, str) for x in urls):
            raise EvidenceError("Case evidence URLs malformed")
        if ("https://bugs.webkit.org/show_bug.cgi?id=" + number) not in urls:
            raise EvidenceError("No primary WebKit Bugzilla source link")
        if ("https://commits.webkit.org/" + case["upstream_revision"]) not in urls:
            raise EvidenceError("No matching upstream fixed commit link")
        if not isinstance(case["source_paths"], list) or not all(
            isinstance(x, str) and x.startswith("Source/") for x in case["source_paths"]
        ):
            raise EvidenceError("Source paths must be WebKit Source/ paths")
    return data


def compare_patches(data: dict) -> dict:
    cases = data["cases"]
    classes = collections.Counter(case["class"] for case in cases)
    dates = sorted(case["fixed_date"] for case in cases)
    return {
        "study": "NYX16_J4C_WEBKIT_FIXED_PATCH_COMPARISON",
        "research_cutoff": data["research_cutoff"],
        "public_fixed_upstream_issues_documented": len(cases),
        "issues": [
            {"bug_id": c["bug_id"], "fixed_date": c["fixed_date"],
             "component": c["component"], "class": c["class"],
             "upstream_revision": c["upstream_revision"]}
            for c in cases
        ],
        "issue_classes": dict(sorted(classes.items())),
        "earliest_fixed_date": dates[0],
        "latest_fixed_date": dates[-1],
        "commonality": [
            "Size-sensitive operations need representable ranges at type/API boundaries.",
            "Bounds-check arithmetic must itself be overflow-safe.",
            "System architecture matters: a documented 32-bit issue cannot automatically be projected onto an A13 64-bit iPhone."
        ],
        "actual_webkit_or_iphone_execution": False,
        "ios_27_2_vulnerability": "NOT_ESTABLISHED",
        "kernel_access": "NOT_TESTED",
        "jailbreak_demonstrated": False,
        "finding": "DOCUMENTARY_PATCH_COMPARISON_ONLY",
    }


def _cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def render_markdown(data: dict, summary: dict) -> str:
    lines = [
        "# Nyx16 J4C — Comparison of fixed WebKit patch mechanisms",
        "",
        "**Evidence:** WebKit Bugzilla reports and reviewed upstream commits. "
        "**No WebKit binary, iPhone, jailbreak or exploit was tested.**",
        "",
        "| Bug | Fixed upstream | Area | Documented defect | Documented correction |",
        "| --- | --- | --- | --- | --- |",
    ]
    for case in data["cases"]:
        bug = case["bug_id"]
        lines.append(
            f"| [#{bug}](https://bugs.webkit.org/show_bug.cgi?id={bug}) "
            f"| {_cell(case['fixed_date'])} "
            f"| {_cell(case['component'])} "
            f"| {_cell(case['root_cause'])} "
            f"| {_cell(case['documented_fix'])} |"
        )
    lines.extend([
        "",
        "## Source-specific applicability limits",
        "",
    ])
    for case in data["cases"]:
        lines.append(
            f"- **#{case['bug_id']}** ([fixed commit]"
            f"(https://commits.webkit.org/{case['upstream_revision']})): "
            f"{case['scope_caveat']}"
        )
    lines.extend([
        "",
        "## Cross-case observations (research synthesis, not quoted upstream)",
        "",
    ])
    for item in summary["commonality"]:
        lines.append("- " + item)
    lines.extend([
        "",
        "## Unsupported claims",
        "",
        "- Any of these bugs is present in the user's iOS 27.2 build: **NOT ESTABLISHED**.",
        "- Impact on Apple A13 privilege boundaries: **NOT TESTED**.",
        "- Live iPhone WebKit, Safari or kernel tests: **NOT RUN**.",
        "- Exploit, sandbox escape or jailbreak: **NOT DEMONSTRATED**.",
        "",
        "Research next step: source-review the full fixed diffs, map affected build "
        "configurations and write a responsible, non-exploit regression plan. "
        "Do not infer vulnerable iOS build mappings from upstream main revisions.",
        "",
    ])
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Nyx16 J4C: offline fixed-WebKit patch comparison")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--json-out", type=Path, default=Path("reports/j4c_webkit_patches.json"))
    parser.add_argument("--md-out", type=Path, default=Path("reports/j4c_webkit_patches.md"))
    args = parser.parse_args(argv)
    try:
        source = load_manifest(args.manifest)
    except (EvidenceError, ValueError) as exc:
        parser.error(str(exc))
    report = compare_patches(source)
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.md_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.md_out.write_text(render_markdown(source, report), encoding="utf-8")
    print(json.dumps({
        "documented_fixed_issues": report["public_fixed_upstream_issues_documented"],
        "issue_classes": report["issue_classes"],
        "finding": report["finding"],
        "ios_27_2_vulnerability": report["ios_27_2_vulnerability"],
        "json_output": str(args.json_out),
        "markdown_output": str(args.md_out),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
