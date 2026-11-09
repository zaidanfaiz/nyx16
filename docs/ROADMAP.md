# Nyx16 Roadmap — A12–A17 jailbreak research

## Project mission

Investigate the feasibility of a **full, usable iOS jailbreak** on Apple A12 through A17 Pro devices, beginning with an authorized iPhone 11 (A13) running iOS 27.2. **Do not make an unsigned downgrade a dependency.** The mission is aspirational: as of this roadmap, **Nyx16 has not demonstrated a jailbreak or found a working exploit chain**.

A jailbreak is version-specific. Evidence for one model/build must never be generalized to other versions or chip families.

## Evidence gates

| Gate | Objective | Required evidence | Current status |
| --- | --- | --- | --- |
| J0 | Identify physical device and installed OS | Model/board/chip, iOS/build, normal/Recovery/DFU transport observations | **Observed on one A13 iPhone 11** |
| J1 | Establish repeatable device lab and recovery method | Consent/ownership, test log, state transition, minimal sanitized metadata | **Partially done** |
| J2 | Characterize current security boundary, mitigations and candidate vulnerability classes | Version-specific public documentation and reproducible observations | **Not demonstrated** |
| J3 | Demonstrate limited sandboxed execution on the owned device | Independent, instrumented evidence and a clean recovery path | **Not demonstrated** |
| J4 | Demonstrate a privilege boundary crossing, if independently discovered and authorized | Repeatable, scoped validation, failure analysis, disclosure review | **Not demonstrated** |
| J5 | Demonstrate privileges required for a usable jailbreak environment | Separation of userland, kernel, sandbox and code-signing requirements; tests | **Not demonstrated** |
| J6 | Package a tested jailbreak with version-specific compatibility and rollback | Test matrices, reproducible release checks, unambiguous limitations | **Not demonstrated** |

Gates describe requirements, not a promised exploit chain or a command recipe.

## Observed on-device baseline and current J4 activity (9 Nov 2026)

The operator reported all three Nyx16Lab checks as PASS on the physical **iPhone 11 (A13) / iOS 27.2**, with **UID/EUID 501/501**. J1 established app-owned file operations, J2 recorded app-owned directory access and Data Protection attribute behavior, and J3 recognized only the app's own ARM64 Mach-O header and a deterministic compiled code self-test. These observations **do not** satisfy J4's privilege-boundary-crossing gate.

**J4 investigation infrastructure started:** the offline, seeded [owned-parser robustness harness](J4_RESEARCH.md) is available for learning to reproduce malformed-input failures. It targets only Nyx16's own reference parser; **an iOS vulnerability, a sandbox escape and a kernel exploit are not demonstrated**. No new J4 button was added to the iPhone app.

## Workstreams

### A. Device-first research (highest priority)
- Keep **iPhone 11 / A13 / N104AP / iOS 27.2** as the first test reference.
- Support normal, Recovery and DFU *identification* with sanitized logs, not bootrom execution claims.
- Research which filesystem interfaces are accessible in a **non-jailbroken** device, without mislabeling app containers as system/root access.
- Track supported vs unsupported kernel/security observations per OS build and device.
- Record ordinary device recoverability and negative results; do not use blind restore/flash steps.

### B. Version-specific iOS security research
- Document boundaries: AMFI/code signing, sandbox, kernel hardening, protected filesystem, boot chain and SEP.
- Track independently corroborated public findings with relevant versions and mitigation state.
- Develop isolated/offline tests and structured observations before any device behavior is described as exploitable.
- Handle any novel finding responsibly, without publishing a weaponizable chain or targeting third-party devices.

### C. A12–A17 hardware coverage
- A12–A16 registry is an identification baseline, **not jailbreak support**.
- Add A17 Pro: iPhone 15 Pro (`iPhone16,1` / `D83AP`) and iPhone 15 Pro Max (`iPhone16,2` / `D84AP`), CPID `0x8130`.
- Require board/build specific validation; any missing chip/model/version remains **UNKNOWN**, not assumed compatible.

### D. Legacy firmware knowledge (lower priority)
- Preserve read-only iOS 27.2 vs 26.1 IPSW/Image4 analysis for architectural context.
- Do not keep restarting downgrade feasibility audits as if they advance the jailbreak gate.
- No unsigned restore mechanism is claimed or bundled.

## Completion criteria

A claim such as **"full jailbreak supported"** requires a repeatable authorized-device demonstration, clearly defined achieved privileges, compatible version/build list, failure modes, documented recovery route and third-party reproducibility. Rootless vs rootful, tethered vs untethered, and persistence must be explicitly identified.

**Current headline: "Jailbreak research — no exploit demonstrated."**

Reference: [device lab](DEVICE_LAB.md), [security research scope](JAILBREAK_RESEARCH.md), [safety](SECURITY_SCOPE.md).
