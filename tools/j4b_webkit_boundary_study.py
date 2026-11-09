"""J4B: regression study of a fixed PUBLIC WebKit length-boundary bug class.

Reference: WebKit bug 304140, fixed in WebKit main commit 66bfd48 (2026-01-07).
This does NOT execute WebKit, libxml2, browser content, iOS, or an exploit.

The purpose is to demonstrate why unsigned host-buffer sizes must be checked
BEFORE passing them to an interface with a signed 32-bit length parameter.
No large allocations are performed; all test values are logical lengths.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

SIGNED_C_INT_MAX = (1 << 31) - 1

FIXED_WEBKIT_BUG = "304140"
FIXED_WEBKIT_COMMIT = "66bfd48c94bf04db92322e41ea8b78d64b1c775e"
FIXED_WEBKIT_URL = "https://bugs.webkit.org/show_bug.cgi?id=304140"
COMMIT_URL = (
    "https://github.com/WebKit/WebKit/commit/"
    + FIXED_WEBKIT_COMMIT
)


class LengthBoundaryError(ValueError):
    """A logical length does not fit a signed 32-bit API boundary."""


def checked_signed_api_length(logical_length: int) -> int:
    """Validate the conceptual integer before conversion; never allocate memory.

    A boolean is disallowed even though bool inherits int in Python.
    This models a defensive precondition, not actual WebKit source code.
    """
    if type(logical_length) is not int:
        raise LengthBoundaryError("length must be an integer, not a boolean or coercible value")
    if logical_length < 0:
        raise LengthBoundaryError("negative logical length")
    if logical_length > SIGNED_C_INT_MAX:
        raise LengthBoundaryError("length does not fit signed 32-bit API")
    return logical_length


def regression_matrix() -> list[dict]:
    """Boundary-value analysis; cases intentionally include *logical* huge sizes."""
    cases = [
        ("negative", -1, False),
        ("zero", 0, True),
        ("one", 1, True),
        ("ordinary", 65535, True),
        ("int_max_minus_one", SIGNED_C_INT_MAX - 1, True),
        ("int_max", SIGNED_C_INT_MAX, True),
        ("int_max_plus_one", SIGNED_C_INT_MAX + 1, False),
        ("uint32_max", (1 << 32) - 1, False),
        ("uint64_max", (1 << 64) - 1, False),
    ]
    rows = []
    for name, n, should_accept in cases:
        try:
            checked_signed_api_length(n)
            accepted = True
        except LengthBoundaryError:
            accepted = False
        rows.append({
            "name": name,
            "logical_length": str(n),
            "expected": "ACCEPT" if should_accept else "REJECT",
            "observed": "ACCEPT" if accepted else "REJECT",
            "result": "PASS" if accepted == should_accept else "FAIL",
        })
    return rows


def run_study() -> dict:
    rows = regression_matrix()
    passed = sum(row["result"] == "PASS" for row in rows)
    return {
        "experiment": "NYX16_J4B_WEBKIT_PATCH_MECHANISM_STUDY",
        "public_upstream_bug": FIXED_WEBKIT_BUG,
        "public_upstream_commit": FIXED_WEBKIT_COMMIT,
        "sources": [FIXED_WEBKIT_URL, COMMIT_URL],
        "bug_class": "SIGNED_32BIT_ARGUMENT_RANGE_CHECK",
        "scope": "LOCAL_OWNED_REFERENCE_MODEL_ONLY",
        "total_cases": len(rows),
        "passed_cases": passed,
        "failed_cases": len(rows) - passed,
        "boundary_cases": rows,
        "actual_webkit_binaries_executed": False,
        "libxml2_executed": False,
        "crafted_web_content_generated": False,
        "iphone_contacted": False,
        "ios_27_2_vulnerable": "NOT_ESTABLISHED",
        "jailbreak_demonstrated": False,
        "finding": "PATCH_MECHANISM_MODELED_ONLY" if passed == len(rows)
                   else "OWN_MODEL_REGRESSION_FOUND",
        "note": (
            "WebKit bug 304140 documents a 2026-01-07 repair using INT_MAX "
            "checks before libxml2 calls. This is an independent minimal "
            "boundary model, not a reproduction of WebKit code or a CVE exploit."
        ),
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="J4B: study a fixed public WebKit int-length boundary (offline)"
    )
    parser.add_argument(
        "--out", type=Path, default=Path("reports/j4b_webkit_boundary.json")
    )
    args = parser.parse_args(argv)
    report = run_study()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "experiment": report["experiment"],
        "public_upstream_bug": report["public_upstream_bug"],
        "total_cases": report["total_cases"],
        "passed_cases": report["passed_cases"],
        "failed_cases": report["failed_cases"],
        "finding": report["finding"],
        "actual_webkit_binaries_executed": False,
        "ios_27_2_vulnerable": "NOT_ESTABLISHED",
    }, indent=2))
    return 0 if report["failed_cases"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
