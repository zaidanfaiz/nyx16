# Nyx16Lab — iPhone device research app

**Current app: v0.3 · Unified J1–J3 diagnostics.**

Nyx16Lab is a signed SwiftUI app for research baselines on owned/authorized iPhones, starting with the iPhone 11 (A13) on iOS 27.2. It currently does **not** implement or demonstrate a jailbreak, kernel exploit, unsigned code execution, or privileged filesystem access.

## What's new

- New original **Nyx16 N16 orbit logo** and matching branded **Home Screen icon**, navy/cyan visual style.
- **Exactly one run button:** `Run Full Diagnostics` executes J1, J2 and J3 in sequence, then shows collapsible result cards.
- J1 checks normal write/read/cleanup within the app's own Documents directory.
- J2 checks its **own** directory readability and a temporary file's Data Protection attribute.
- J3 reads the first **eight bytes only** of the app's own executable to check ARM64 Mach-O header and executes a known SHA-256 self-test. **No privileged execution is tested.**
- After one full run, **Copy Report** and **AirDrop / Share** export a combined J1–J3 report. No report is uploaded automatically.

See [J3 test interpretation and limits](J3_RUNTIME_DIAGNOSTICS.md) and [J2 details](J2_SECURITY_DIAGNOSTICS.md).

## Build / install on your iPhone

Requirements: macOS, Xcode with a supported target, installed iPhone development signing identity, a paired iPhone with Developer Mode as needed.

```bash
cd ~/Development/nyx16
git pull --ff-only
open ios/Nyx16Lab/Nyx16Lab.xcodeproj
```

In Xcode choose the `Nyx16Lab` target, **Signing & Capabilities**, pick your Apple development Team, and select the paired iPhone as the target. Press `⌘R` to install and run the updated app. Keep the same Bundle ID and development Team to update an already installed app in place.

To compile the project without device signing:

```bash
xcodebuild -project ios/Nyx16Lab/Nyx16Lab.xcodeproj \
  -scheme Nyx16Lab -configuration Debug \
  -destination 'generic/platform=iOS Simulator' \
  -derivedDataPath /tmp/nyx16lab-build CODE_SIGNING_ALLOWED=NO build
```

A simulator build is not proof of iOS 27.2 hardware compatibility or a jailbreak.

## Transfer data to Mac

Run all diagnostics once, then select **Copy Report**. Universal Clipboard needs both devices on the same Apple Account with Wi-Fi, Bluetooth and Handoff enabled. Paste on Mac with `⌘V`. If accounts differ, tap **AirDrop / Share** instead.

The reports deliberately omit ECID, UDID, serial numbers, pairing records, filesystem paths and personal data. Do not copy raw device pairing logs or sensitive sign-in information.

## Interpretation

| Status | Meaning |
| --- | --- |
| J1 PASS | Read/write/delete within app's own sandbox |
| J2 PASS | App-local directory / file attribute checks succeeded |
| J3 PASS | Normal compiled app runs and its own ARM64 executable header is recognizable |
| INCONCLUSIVE | Expected local evidence unavailable; investigate without guessing |
| JAILBREAK NOT DEMONSTRATED | No privilege bypass, kernel exploit or full jailbreak has been tested |

Nyx16's goal remains full jailbreak **research** on A12–A17 Pro, but J1–J3 are instrumented baseline measurements, not a newly found vulnerability.
