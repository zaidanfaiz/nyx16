# J4 — Vulnerability research foundation: owned parser robustness

**Scope:** A bounded, deterministic test harness for the `NX16` toy frame format **authored by Nyx16**. It does **not** target iOS, Apple system parsers, WebKit, kernel interfaces, or other people's devices. There is currently **no discovered iOS vulnerability or jailbreak exploit**.

J1–J3 have already run on the owned iPhone 11 (A13, iOS 27.2). The result showed ordinary application UID 501 and no elevated privilege, with J1, J2 and J3 baseline checks passing. Repeating those tests does not move us closer to a jailbreak.

## Experiment

The reference format is `NX16 | version 1 | uint16 length | payload (max 128 bytes) | CRC32`. The experiment produces valid seeds, makes bounded, deterministic mutations, and checks the sample decoder's behavior. Expected malformed frames raise a documented `FrameError`. Unexpected Python exceptions or broken roundtrips are recorded as **local parser failures**, not iOS security vulnerabilities.

The harness:
- Uses only pure Python standard library, runs offline, and never contacts a phone or a remote system
- Caps case count at 10,000 and frame length, and uses a supplied random seed
- Checks valid-message roundtrips, malformed-size rejection, checksum rejection and mutations
- Produces machine-readable `reports/j4_owned_parser.json` including counts, seed and up to eight reproducible failure identifiers (hashes, not arbitrary private inputs)
- Fails the process on unexpected exceptions or invalid valid-message roundtrips
- Runs a CI job that uploads the report as an artifact

## Run on Mac

```bash
cd ~/Development/nyx16
git pull --ff-only
python3 -m unittest discover -s tests -p 'test_j4_parser_lab.py' -v
python3 tools/j4_parser_lab.py --seed 1627 --cases 1500 --out reports/j4_owned_parser.json
```

Check `unexpected_failures` and `valid_reference_roundtrip_failures`. If either is nonzero, investigate as a **Nyx16-owned software defect**. A zero-result run is expected for the reference decoder and is not evidence that iOS is secure.

## What this does and does not achieve

| Claim | Status |
| --- | --- |
| Reproducible malformed-input experiment infrastructure | IMPLEMENTED |
| Deterministic local regression tests | IMPLEMENTED |
| Sample parser crash or correctness issue | ONLY IF OBSERVED; none presumed |
| iPhone 11 vulnerability | **NOT TESTED** |
| iOS sandbox escape or kernel exploit | **NOT TESTED** |
| Full A12–A17 jailbreak | **NOT DEMONSTRATED** |

**Do not turn this sample harness into a blind automated attack against iOS system parsers or network services.** Novel Apple security issues require scoped research, real reproduction evidence, and responsible disclosure.

## Future research decisions

Use public Apple security advisories to select specific **already disclosed and fixed** vulnerability classes for architectural study, separating knowledge about mitigation from the existence of a usable exploit on iOS 27.2. Only claim progress toward a vulnerability when tested findings support that exact claim. For iOS internals research that needs privileged capabilities, Apple's **Security Research Device** program provides authorized special-purpose research hardware, subject to eligibility and program dates.

References:
- [Apple Security Research Device](https://security.apple.com/research-device)
- [Apple Security Bounty Guidelines](https://security.apple.com/bounty/guidelines)
- [LLVM libFuzzer concepts](https://llvm.org/docs/LibFuzzer.html) (background methodology; the current Nyx16 harness is pure Python and is **not** libFuzzer)
