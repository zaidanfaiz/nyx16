# Nyx16 Device Lab — authorized iPhone testing

## Scope

This workflow records **non-destructive device observations**, primarily for the current iPhone 11 A13 lab. It does not extract protected root files, edit the sealed system volume, patch iBoot or run a DFU payload. **Physical access and DFU mode are not proof of an exploit.**

A stock, paired iPhone exposes limited services (model/build and permitted data). Reading or changing protected system files is **not normally available** through `ideviceinfo`, `idevicepair` or DFU transport alone. A device-specific, proven privilege breakthrough would be necessary before claiming otherwise.

## Evidence baseline already obtained

| Property | Observed result |
| --- | --- |
| iPhone model | iPhone 11, `iPhone12,1` |
| Board | `N104AP` |
| A13 CPID | `0x8030` |
| Board ID | `0x04` |
| Installed OS | iOS 27.2, build `24B119` |
| Normal mode | Supported; paired and activated |
| Recovery USB | Observed |
| DFU USB | Observed |
| Arbitrary kernel execution | **NOT DEMONSTRATED** |
| System filesystem write | **NOT DEMONSTRATED** |
| Jailbreak | **NOT DEMONSTRATED** |

## Read-only local commands

With a trusted iPhone connected to macOS and libimobiledevice available:

```bash
export PATH="/opt/local/bin:$PATH"
cd ~/Development/nyx16
python3 tools/mac_probe.py
```

When already in Recovery/DFU, `irecovery -m` reports USB mode. Running `irecovery -q` can expose unique device identifiers, so do **not** publish its full output. These commands only observe a state; they do not change boot policy.

### What to measure next (without an exploit payload)

- Precise device/build combinations and normal/Recovery/DFU identification reliability.
- The difference between app-container and protected filesystem access on non-jailbroken iOS.
- Baseline logs and public security feature documentation matched to the installed iOS build.
- Recovery reproducibility, observed errors and where a service refuses a privileged request.

The prior iOS 26.1 downgrade evaluation is archived, not a prerequisite to these observations. Do not run blind flash, destructive root volume edits, arbitrary DFU uploads, or third-party bypass tools during baseline measurements.

## Evidence hygiene

Never upload raw `irecovery -q` output, pairing records, serial/ECID/UDID, APNonce, activation credentials or personal files. Record only sanitized observations with time, device family, build, action category and outcome. For any future write-capable device tests, define the affected scope and a documented recovery method before running them.

## Status criteria

`OBSERVED` describes a measurable property; `REPRODUCED` requires repeating it; `JAILBREAK_VERIFIED` requires independently verified on-device privilege and usable jailbreak environment. Failure or missing access is a valid finding.


## J2: application sandbox and Data Protection measurements

Following the J1 iPhone 11 app-container PASS, the Nyx16Lab app has a **Run J2 Diagnostics** button, which lists availability/readability of directories inside its own sandbox and checks the protection attribute of a temporary own-file before deleting it. The signed app's entitlements can be inspected on macOS using a redacted CLI report; the installed device's code signature is not directly inspected.

See [on-device J2 diagnostics](../ios/Nyx16Lab/J2_SECURITY_DIAGNOSTICS.md). J2 does **not** attempt root privilege, protected file access, exploit payloads or DFU operations.
