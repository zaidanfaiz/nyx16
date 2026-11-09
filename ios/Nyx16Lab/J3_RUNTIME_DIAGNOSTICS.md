# Nyx16Lab J3 — Own-app runtime integrity baseline

## Goal

The first J3 iteration measures **ordinary signed-app execution** on an owned iPhone 11 A13 running iOS 27.2, building on J1/J2 screenshots. It is not a jailbreak, arbitrary code execution, sandbox escape, exploit primitive, signing bypass, or kernel privilege validation.

## Unified one-tap flow

Nyx16Lab now presents a **single** `Run Full Diagnostics` action. This performs, in order:

| Stage | What is actually measured | What is NOT established |
| --- | --- | --- |
| J1 — Sandbox Baseline | Own Documents directory, temporary file write/read/delete | Any protected filesystem access |
| J2 — Security Boundaries | Own Documents/Library/Caches/tmp readability, temporary own-file Data Protection attribute/readback/cleanup | Entitlement bypass, protection behavior while device locked |
| J3 — Runtime Integrity | Reads **8 bytes only** from **its own app executable**, checks ARM64 Mach-O magic/CPU type; computes SHA-256 known-answer test `abc` | Apple code-signature verification, arbitrary code execution, AMFI/PPL bypass, kernel privilege |

### Understand J3 carefully

A `J3 PASS` means **the normal installed app ran its own compiled code and recognized its own ARM64 Mach-O header**. Since the user already launched Nyx16Lab, this is an instrumented execution baseline, **not evidence that an exploit exists**.

The app deliberately does not attempt to inspect or modify protected OS paths, other apps' containers, signing policy, kernel state or DFU. The code-signing entitlement snapshot remains a *separate Mac-side local .app analysis* using `tools/inspect_lab_entitlements.py`.

### Visual identity

- Original Nyx16 **N16 orbital emblem** appears at the top of the app.
- Matching 1024px Home Screen icon is included in the Xcode AppIcon asset catalog.
- Editable vector mark: [`branding/nyx16-mark.svg`](../../branding/nyx16-mark.svg).
- Navy/cyan dark interface with three status cards and **one Run Full Diagnostics button**. Stage cards expand to show their data and do not trigger more tests.

### Copy the report to your Mac

After a run, tap **Copy Report**, then paste via `⌘V` on the Mac using Universal Clipboard (same Apple Account, Handoff, Wi-Fi and Bluetooth). **AirDrop / Share** is an alternative. The text includes J1, J2 and J3 in one self-contained report. No report is automatically uploaded.

## On-device trial

```bash
cd ~/Development/nyx16
git pull --ff-only
open ios/Nyx16Lab/Nyx16Lab.xcodeproj
```

Choose the paired iPhone and press `⌘R` in Xcode. In the updated app, tap **Run Full Diagnostics** once, then **Copy Report**. Send the resulting report, **not** device identifiers or signing credentials.

Only the actual on-device results can verify that J3 works on iOS 27.2; CI simulator builds alone do not verify that.

## Evidence and safety

`INCONCLUSIVE` means a normal API did not supply the expected evidence and should not be upgraded to a security claim. `JAILBREAK: NOT DEMONSTRATED` stays true unless independently reproducible privileged capability is established with device/build-specific proof.

Related: [J2 diagnostics](J2_SECURITY_DIAGNOSTICS.md), [Jailbreak research](../../docs/JAILBREAK_RESEARCH.md), [Apple Bundle](https://developer.apple.com/documentation/foundation/bundle), [Apple CryptoKit](https://developer.apple.com/documentation/cryptokit/).
