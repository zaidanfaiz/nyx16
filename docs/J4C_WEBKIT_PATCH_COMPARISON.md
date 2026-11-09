# J4C — Comparative study of four already-fixed WebKit patches

**Method:** compare primary WebKit Bugzilla reports with the corresponding reviewed upstream commit messages. The reproducible source manifest is in [`research/webkit_fixed_patch_cases.json`](../research/webkit_fixed_patch_cases.json). The tool generates a source-linked **documentary** report; it does **not** execute WebKit, Safari or any iPhone code.

**Device context:** earlier user-run J1, J2 and J3 normal-app checks passed on an iPhone 11 (A13) running iOS 27.2 with UID/EUID 501. Those results do not prove any of the historical bugs applies to the device.

## Primary-source comparison

| WebKit issue | Fixed upstream | Affected area | Root-cause category | What the upstream fix does |
| --- | --- | --- | --- | --- |
| [304140](https://bugs.webkit.org/show_bug.cgi?id=304140) | [305255@main](https://commits.webkit.org/305255@main), Jan 7 2026 | WebCore XML/XSLT + GStreamer PlayReady path | Signed length boundary | Adds `INT_MAX` size-range checks at three `libxml2` integration points |
| [289523](https://bugs.webkit.org/show_bug.cgi?id=289523) | [292355@main](https://commits.webkit.org/292355@main), Mar 19 2025 | JavaScriptCore / WebAssembly arrays | 32-bit allocation multiplication | Detects and propagates a potentially wrapped array size calculation when `size_t` is 32 bits |
| [297624](https://bugs.webkit.org/show_bug.cgi?id=297624) | [298946@main](https://commits.webkit.org/298946@main), Aug 20 2025 | SVG convolution filter | Geometry area calculation | Uses `IntSize::unclampedArea()` in size validation to avoid an overflowing product |
| [308713](https://bugs.webkit.org/show_bug.cgi?id=308713) | [308649@main](https://commits.webkit.org/308649@main), Mar 4 2026 | IndexedDB key deserialization | Bounds-check multiplication | Makes the validation of a string key's required bytes non-overflowing before allocation |

Commit-level evidence from reviewed upstream code changes:
- [304140 full commit](https://github.com/WebKit/WebKit/commit/66bfd48c94bf04db92322e41ea8b78d64b1c775e)
- [289523 full commit](https://commits.webkit.org/292355@main)
- [297624 full commit](https://commits.webkit.org/298946@main)
- [308713 full commit](https://commits.webkit.org/308649@main)

## Findings: separate upstream evidence from Nyx16 inference

**Observed in the upstream descriptions:**
1. **Boundary narrowing** — 304140 checks whether sizes are representable by an API that accepts a narrower signed type.
2. **Multiplication for allocation** — 289523 catches size arithmetic that may wrap on a 32-bit `size_t` build.
3. **Geometry product** — 297624 moves to an area calculation explicitly intended to avoid overflow.
4. **Validation math** — 308713 addresses a size calculation that could wrap inside the condition intended to prevent an oversized operation.

**Nyx16 synthesis (not a verbatim upstream claim):** Two groups stand out. First, checks must occur **before type conversion or allocation** (304140, 289523). Second, the **check's own arithmetic must be safe** (297624, 308713). A correct outer comparison is not a protection if its size expression has already overflowed. This is a general C/C++ engineering lesson, not evidence of a new iOS weakness.

**Crucial platform limitations:**
- 289523 expressly discusses a **32-bit** `size_t` condition, so the original stated problem cannot automatically be applied to a **64-bit A13** iPhone.
- 297624's Bugzilla report includes a debug-build assertion. That is **not** proof of code execution or a viable security exploit.
- 308713's bug report discusses resource exhaustion, and its upstream commit promises a non-overflowing bounds check. This does **not** establish a shipped iOS build was vulnerable.
- 304140 includes a **GStreamer-specific** path. Upstream WebKit mainline does not equal Apple's shipped mobile configuration or version.

**No CVE, Apple Security Content mapping, Safari version, iOS 27.2 vulnerability, sandbox escape or kernel privilege has been proven by these four reports.**

## Run on Mac

```bash
cd ~/Development/nyx16
git pull --ff-only
python3 -m unittest discover -s tests -p 'test_j4c_webkit_patch_compare.py' -v
python3 tools/j4c_webkit_patch_compare.py \
  --json-out reports/j4c_webkit_patches.json \
  --md-out reports/j4c_webkit_patches.md
```

Outputs:
- `reports/j4c_webkit_patches.json`: source-linked case identifiers, fixed dates, category counts and unsupported-claim statements
- `reports/j4c_webkit_patches.md`: readable side-by-side comparison with issue and commit URLs
- GitHub Actions artifact `j4c-webkit-fixed-patch-comparison`

The report script verifies unique issue IDs, dates, primary links and that it is labeled **DOCUMENTARY_PATCH_COMPARISON_ONLY**. It does not invent test results about running WebKit.

## Next concrete research decision

Choose one **already-fixed** pattern for a code-review-only mapping: where are narrowing boundaries documented, where does arithmetic occur before a guard, and which build configurations are actually in scope? Verify a patch against original upstream source and branch history, and record the applicability of the fix separately from any claims about iOS 27.2.

If an independent novel Apple security issue is discovered in authorized research, follow responsible reporting and Apple's security research guidance. Do not turn patch comparisons into an automated exploit chain or a targeting workflow.

## Outcome

**J4C documentary comparison completed only when primary sources and reproducible reports are checked.** The original Nyx16 J4 research gate requiring proof of a privilege boundary crossing remains unmet. Nyx16Lab keeps its one `Run Full Diagnostics` button; there is no new on-device action.
