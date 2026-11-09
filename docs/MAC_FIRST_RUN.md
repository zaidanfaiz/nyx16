# Nyx16 First Mac Hardware Probe — iPhone 12 (A14)

This phase is **read-only**: inspect a physically connected iPhone over USB, compare against a previously collected Apple iOS 26.1 firmware manifest, and stop. **No restore, signing bypass, DFU exploit, jailbreak, or iOS downgrade operation occurs.**

## 1. Prepare the Mac (macOS 15+, MacPorts)

Connect the iPhone 12 via a data-capable Lightning cable. If it is in normal mode, unlock it and choose **Trust This Computer** on the iPhone.

Install diagnostic tools using the official MacPorts ports:

```bash
sudo port install libimobiledevice libirecovery
export PATH="/opt/local/bin:$PATH"
```

References:
- https://ports.macports.org/port/libimobiledevice/
- https://ports.macports.org/port/libirecovery/

If these ports are already installed, MacPorts will detect that. `ideviceinfo` reads a paired device's information; `irecovery -q` is only used for metadata query when a normal-mode device is not visible.

## 2. Run Nyx16 locally

```bash
mkdir -p ~/Development
cd ~/Development
git clone https://github.com/zaidanfaiz/nyx16.git
cd nyx16
python3 tools/mac_probe.py
```

If the repo was previously cloned:

```bash
cd ~/Development/nyx16
git pull --ff-only
python3 tools/mac_probe.py
```

Optional: Compare the macOS probe against a locally downloaded GitHub Actions ZIP artifact (do **not** upload private device details):

```bash
python3 tools/mac_probe.py --report-zip ~/Downloads/nyx16-research-reports-5.zip
```

Optionally save a **sanitized** JSON file locally:

```bash
python3 tools/mac_probe.py --output ~/Desktop/nyx16-mac-probe.json
```

Do not post raw `idevice_id -l`, `ideviceinfo`, or `irecovery -q` outputs, as they may contain persistent device identifiers. The Nyx16 script emits only allowlisted information.

## 3. Read the result

- `mode=NORMAL`: device is recognized and paired over USB; product, iOS version, build and board can be compared.
- `mode=USB_VISIBLE_NOT_PAIRED`: unlock and trust the connected iPhone; nothing is changed.
- `mode=RECOVERY_OR_DFU`: iBoot diagnostic query only; **no commands are sent to modify the device**.
- `mode=MULTIPLE_DEVICES`: disconnect other iPhones; script refuses to guess which to inspect.
- `mode=NOT_DETECTED`: review the USB cable and tool installation.

Expected iPhone 12 target values from the iOS 26.1 manifest:
- ProductType: `iPhone13,2`
- Target iOS: `26.1` / build `23B85`
- Manifest boards observed: `d53gap`, `d53pap`
- Manifest SHA256: `b756fdf237c0bd7893e280447947b6b385b36b3e8eaae372980edc3c2c054774`

`version_relationship=TARGET_OLDER_THAN_INSTALLED` means this would be a downgrade request, **not** that the phone can be downgraded.

`apple_signing_status=NOT_CHECKED`, `sep_baseband_compatibility=UNKNOWN`, and `unsigned_downgrade=NOT_DEMONSTRATED` remain unchanged regardless of USB probe success.

## 4. Scope

This step can confirm physical device model and currently installed firmware. It cannot verify the device's ability to boot older firmware or defeat Apple's restore authorization. Connecting an iPhone to a Mac alone does not change Secure Boot or the A14 hardware trust chain.

**If the iPhone is in Activation Lock or MDM enrollment, this script does not change it.**
