# J4B — WebKit public-patch case study: checked integer-length boundaries

**Research type:** public fixed upstream bug review + independent regression model.
**No WebKit binary, iPhone, Safari, kernel, malicious HTML, or privileged path is executed.**

## Primary sources and patch identity

WebKit Bugzilla **304140**, *"[WebContent] Fix Integer Underflow in xmlReadMemory"*, was reported on **13 December 2025** and marked **RESOLVED FIXED** on **7 January 2026**. It is an upstream WebKit issue, classified by Bugzilla as *Normal* severity. The reviewed commit on the upstream main branch is **66bfd48c94bf04db92322e41ea8b78d64b1c775e** (WebKit 305255@main), author Zak Ridouh, dated 7 January 2026.

- [WebKit Bugzilla 304140 — upstream state](https://bugs.webkit.org/show_bug.cgi?id=304140)
- [Upstream commit 66bfd48c94bf — source changes](https://github.com/WebKit/WebKit/commit/66bfd48c94bf04db92322e41ea8b78d64b1c775e)
- [WebKit commit notification with review explanation](https://www.mail-archive.com/webkit-changes@lists.webkit.org/msg241531.html)
- [WebKitGLib 2.50 branch backport, 12 January 2026](https://www.mail-archive.com/webkit-changes@lists.webkit.org/msg241736.html)

According to the **upstream commit description**, the fix introduces explicit bounds checks using **INT_MAX** before passing lengths to libxml2. The upstream change touched three paths:

| Upstream path | Context according to upstream commit |
| --- | --- |
| Source/WebCore/xml/parser/XMLDocumentParserLibxml2.cpp | XML document parsing |
| Source/WebCore/xml/XSLTProcessorLibxslt.cpp | XSLT document loading |
| Source/WebCore/Modules/encryptedmedia/InitDataRegistry.cpp | PlayReady initialization data parsing (GStreamer path) |

**Scope caution:** this bug and commit notice do not establish that the user's **iOS 27.2** build is vulnerable or that the fix is associated with a particular CVE. Do **not** invent a CVE, claim an Apple mobile-release mapping, or equate WebKitGLib with iOS WebKit.

## Mechanism: arithmetic contract, not an exploit

A C API accepting a **signed 32-bit integer length** can represent nonnegative logical lengths from 0 through **2,147,483,647**. When a producer stores lengths using a larger or unsigned integer type, the consumer must validate the range **before** converting to the narrower signed type.

This general lesson follows the upstream commit explanation. It is not a claim that actual memory corruption is reproducible on any Apple platform.

The Nyx16 example rejects negative, non-integer, and greater-than-INT_MAX logical lengths. It does **not** allocate large buffers: even its 64-bit boundary tests handle integers only.

## Reproduce the nine-case regression matrix

Run on the Mac, without connecting an iPhone:

    cd ~/Development/nyx16
    python3 -m unittest discover -s tests -p 'test_j4b_webkit_boundary_study.py' -v
    python3 tools/j4b_webkit_boundary_study.py --out reports/j4b_webkit_boundary.json

The cases are -1, 0, 1, 65535, INT_MAX-1, INT_MAX, INT_MAX+1, UINT32_MAX, and UINT64_MAX. Values greater than INT_MAX or below zero should be rejected; remaining nonnegative signed-int values accepted. Non-integer rejection has separate unit tests.

The JSON report contains the **expected and observed** decision for each case. Successful result: **PATCH_MECHANISM_MODELED_ONLY**, not EXPLOIT_FIXED or IOS_VULNERABILITY_FOUND. CI publishes an artifact with integer cases and public source links.

## What can be concluded?

| Evidence | Supported conclusion |
| --- | --- |
| Bugzilla state RESOLVED FIXED | Specific upstream issue was fixed by 7 January 2026 |
| Commit description includes INT_MAX checks | Integer argument validation was part of correction |
| Nyx16 nine-case model passes | Our own validation correctly handles the signed-32-bit range |
| iOS 27.2 J1–J3 passes on iPhone 11 | Ordinary signed-app functionality |
| iOS 27.2 vulnerability or kernel privilege | **NOT ESTABLISHED** |
| J4 jailbreak exploit or sandbox escape | **NOT DEMONSTRATED** |

## Next research question

Compare this **documented upstream check** with other *already patched* length-boundary issues. Distinguish common defensive patterns from device-specific exploitation claims. No additional Run button is needed in Nyx16Lab: this study is offline.

This is a fixed-bug learning milestone, **not** completion of the original roadmap J4 privilege-crossing gate.
