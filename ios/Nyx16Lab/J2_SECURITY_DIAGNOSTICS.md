# J2 — On-device iOS security diagnostics (Nyx16Lab)

## Goal and status

**Goal:** characterize boundaries of a **normal, signed app** on the operator's iPhone 11 (A13, iOS 27.2), following the successful J1 app-container read/write/delete test. J2 must distinguish ordinary app behavior from privileged execution.

J2 adds a **Run J2 Diagnostics** button to the existing SwiftUI app. The app uses only public iOS APIs; it does **not** attempt to cross the app sandbox, test arbitrary system paths or run a kernel/DFU payload.

## Device test: inside the app

1. Update Nyx16, then rebuild/reinstall the **Nyx16Lab** target through Xcode as an Apple-development-signed app on the same iPhone.
2. Tap **Run J2 Diagnostics**.
3. Record the labels, not any private file paths:
   - \`APP CONTAINER DIRECTORY INVENTORY\`: \`Documents\`, \`Library\`, \`Caches\`, \`tmp\`, with whether they exist and are readable.
   - \`CODE SIGNING ENTITLEMENTS\`: \`NOT PERFORMED\` on device (see Mac steps below).
   - \`FILE DATA PROTECTION\`: current protected-data availability, a temporary own-file protection attribute check (\`COMPLETE_UNTIL_FIRST_AUTHENTICATION\`), readback and cleanup.
   - \`PROTECTED SYSTEM PATHS: NOT ACCESSED\`, \`SANDBOX ESCAPE: NOT TESTED\`, \`KERNEL PRIVILEGE: NOT TESTED\`, \`JAILBREAK: NOT DEMONSTRATED\`.

The diagnostics **never** attempt to read or write protected system paths, other apps' containers or user data outside the Nyx16Lab sandbox. The temporary test file is created only inside Nyx16Lab's own Documents directory and removed afterward. The test will **skip** rather than overwrite a file with the same test name.

A \`Protection attribute: MATCH\` means the own test file reported the requested Apple Data Protection attribute. It is **not** a cryptographic audit or proof of effective at-rest encryption or behavior while locked. The app intentionally does not lock the device or try to trigger protection failures.

## Mac test: inspect entitlements from the signed application

Do this **only after successfully building a signed iPhone app** in Xcode. The simulator artifact created by GitHub CI has code signing disabled and is unsuitable.

In Xcode, find the built \`Nyx16Lab.app\` product (e.g., Product → Show Build Folder in Finder). Then:

\`\`\`bash
cd ~/Development/nyx16
python3 tools/inspect_lab_entitlements.py --app "/ABSOLUTE/PATH/TO/Nyx16Lab.app"
\`\`\`

The macOS tool invokes \`/usr/bin/codesign -d --entitlements :-\` to inspect **that local signed app only**. Its output deliberately redacts actual \`application-identifier\`, team ID, app group names and associated-domain values; it shows only presence/counts and the \`get-task-allow\` boolean if available. A blank/missing entitlement is \`NOT_PRESENT_OR_NOT_BOOLEAN\`, **not** automatically false. The tool does not verify the whole code signature, inspect the installed iPhone binary or extract protected on-device content.

**Do not upload raw codesign output**: it can include account/team identifiers. Share only the redacted output of this tool.

## What to expect

| Observation | Interpretation |
| --- | --- |
| Documents/Library/Caches/tmp readable | Normal app-owned container access |
| \`get_task_allow = TRUE\` in a development build | Debug entitlement in a signed local app; **not** sandbox escape or kernel privilege |
| \`get_task_allow = NOT_PRESENT_OR_NOT_BOOLEAN\` | Unavailable/absent value, not enough information to infer signing failure |
| Protection attribute MATCH | App successfully requested and read a protection level on its own temporary file |
| Cleanup PASS | Temporary own-file removed; no system modification |
| JAILBREAK NOT DEMONSTRATED | No exploit or elevated privilege evidence collected |

## Sources

- [Apple: Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [Apple: FileProtectionType.completeUntilFirstUserAuthentication](https://developer.apple.com/documentation/foundation/fileprotectiontype/completeuntilfirstuserauthentication)
- [OWASP MASTG: iOS File System APIs](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0091/)

This is an *observation baseline* in the [Nyx16 security research plan](../../docs/JAILBREAK_RESEARCH.md), not an exploit milestone.
