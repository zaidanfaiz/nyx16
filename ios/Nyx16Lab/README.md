# Nyx16Lab — physical iPhone sandbox baseline

**Purpose:** Build a normal, signed SwiftUI application and test **its own container** on an authorized iPhone. This is the first on-device development baseline for Nyx16's A12–A17 jailbreak research program.

It is not a jailbreak, sandbox escape, exploit trigger, kernel primitive, custom DFU image, or protected filesystem inspector. It uses no network access, private APIs, elevated entitlements, or background data collection.

## Requirements

- macOS with Xcode (operator tested Xcode **26.3**, build `17C529`)
- A physical iPhone accessible in Xcode, trusted and unlocked
- Developer Mode enabled on the device when Xcode asks for it
- A personal/team Apple Development signing identity selected in Xcode

**Device compatibility caution:** the current test iPhone runs **iOS 27.2**; Xcode 26.3 might not have the matching device support needed for deployment/debugging. Passing a simulator build does **not** prove physical iOS 27.2 deployment. Verify in Xcode's Devices and Simulators window or `xcrun devicectl list devices`; do not downgrade or restore the phone to address a developer-support mismatch.

## Step 1 — Verify Xcode sees the iPhone

```bash
cd ~/Development/nyx16
git pull --ff-only
export PATH="/opt/local/bin:$PATH"
xcodebuild -list -project ios/Nyx16Lab/Nyx16Lab.xcodeproj
xcrun devicectl list devices
```

If the phone is listed but unavailable, check the reported reason in Xcode → Window → Devices and Simulators; developer tools and OS version support may be prerequisites.

## Step 2 — Build without device signing

This checks the project and Swift compilation against the installed iOS Simulator SDK. It makes **no modifications to the iPhone**.

```bash
xcodebuild \
  -project ios/Nyx16Lab/Nyx16Lab.xcodeproj \
  -scheme Nyx16Lab \
  -configuration Debug \
  -destination 'generic/platform=iOS Simulator' \
  -derivedDataPath /tmp/nyx16lab-build \
  CODE_SIGNING_ALLOWED=NO build
```

The build may use a newer/different SDK than the phone runs; do not infer physical device support.

## Step 3 — Install through Xcode, after eligibility is confirmed

1. Open `ios/Nyx16Lab/Nyx16Lab.xcodeproj` in Xcode.
2. Select the `Nyx16Lab` target → **Signing & Capabilities** → enable Automatically manage signing, select **your** personal/team Apple account and, if needed, change the bundle identifier to one unique to your team.
3. Select the **connected iPhone** as the run destination. Follow Xcode's on-device prompt to enable Developer Mode, if needed (Settings → Privacy & Security → Developer Mode; may need restart).
4. Press **Run** once the destination is available and signing is valid. Do not force DFU/Recovery or restore the device.
5. In the app, tap **Run Sandbox Test**. The report contains OS version, app bundle, UID/eUID and a temporary **own Documents** write/read/delete check.
6. Share only the report's non-identifying result lines, not any pairing records, UDIDs/ECIDs, device management details or unrelated user data.

## Interpretation

| Output | What it demonstrates |
| --- | --- |
| `Own sandbox file write/read: PASS` | Normal signed app can read/write its own container |
| `Temporary test file cleanup: PASS` | The app removed only its own probe file |
| `Process UID` and `Effective UID` | A basic process identity observation, not proof of elevated privilege |
| `JAILBREAK: NOT DEMONSTRATED` | No jailbreak test or exploit has occurred |
| Xcode simulator build succeeds | Swift project compiles with the selected SDK; does not establish hardware compatibility |
| App fails to launch on iOS 27.2 | Could be signing, Developer Mode, pairing or device-support mismatch; not a jailbreak finding |

**No system files are read or modified.** If a test fails, preserve the Xcode error and stop; do not attempt unsigned firmware booting as a workaround.

For the evidence policy see [Device Lab](../../docs/DEVICE_LAB.md) and [Jailbreak Research](../../docs/JAILBREAK_RESEARCH.md).
