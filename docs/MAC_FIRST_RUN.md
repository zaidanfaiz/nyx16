# Nyx16 macOS Experiment 1 — A12–A16 iPhone Auto-Detection

**Actual hardware for this experiment: iPhone 11 (A13, iPhone12,1).**
The same read-only macOS probe supports device identity lookup for iPhone XR/XS, 11, 12, 13, 14 and their variants.

No jailbreak, Activation Lock modification, iBoot patch, flash, restore, unsigned downgrade, or signing bypass occurs.

## 1. Connect and prepare the Mac

Connect one iPhone by Lightning/USB cable. In normal mode, unlock it and choose **Trust This Computer** if requested. If the device is at Activation Lock, do not try to bypass it; the available normal-mode identity data may be limited.

On the Mac, with MacPorts already installed:

```bash
export PATH="/opt/local/bin:$PATH"
sudo port install libimobiledevice libirecovery
```

Reference tools: [MacPorts libimobiledevice](https://ports.macports.org/port/libimobiledevice/) and [MacPorts libirecovery](https://ports.macports.org/port/libirecovery/).

## 2. Clone or update and run the read-only probe

For a fresh clone:

```bash
mkdir -p ~/Development
cd ~/Development
git clone https://github.com/zaidanfaiz/nyx16.git
cd nyx16
python3 tools/mac_probe.py --target-ios 26.1
```

For an existing clone:

```bash
cd ~/Development/nyx16
git pull --ff-only
python3 tools/mac_probe.py --target-ios 26.1
```

The script does **not** require specifying the iPhone model. It detects `ProductType` and uses the device profile database automatically:
- iPhone 11 = `iPhone12,1` / A13 / `N104AP`
- iPhone 12 = `iPhone13,2` / A14 / `D53gAP`
- iPhone 13 = `iPhone14,5` / A15 / `D17AP`
- iPhone 14 = `iPhone14,7` / A15 / `D27AP`
- iPhone 14 Pro = `iPhone15,2` / A16 / `D73AP`

This is a read-only hardware registry, **not** a list of proven exploitable devices.

If a device is only in Recovery/DFU, Nyx16 attempts `irecovery -q` and may identify only the A-series **chip family**, not the exact iPhone model.

## 3. Firmware reports: do not mix different models

To compare with a GitHub Actions report already downloaded to the Mac:

```bash
python3 tools/mac_probe.py \
  --target-ios 26.1 \
  --report-zip "$HOME/Downloads/nyx16-research-reports-5.zip"
```

If that ZIP is for **iPhone 12**, but the Mac detects **iPhone 11**, Nyx16 returns `report_device_applicability=MISMATCH`. That is expected, and prevents wrongly claiming compatibility.

To collect the correct iPhone 11 metadata report, open [Actions → Nyx16 Firmware Research](https://github.com/zaidanfaiz/nyx16/actions/workflows/research.yml) and choose **Run workflow → iphone11-ios26.1**. It reads only `BuildManifest.plist` from the Apple-hosted firmware using HTTP byte ranges, without downloading the whole IPSW. Download that new artifact and pass it with `--report-zip` if desired.

## 4. Interpreting results

- `mode=NORMAL`: connected and paired, ProductType, OS version, build, board and possibly baseband are read.
- `mode=USB_VISIBLE_NOT_PAIRED`: device visible but not accessible with current pairing, no state changes.
- `mode=RECOVERY_OR_DFU`: limited safe metadata query; no exploit is attempted.
- `mode=MULTIPLE_DEVICES`: selection refused to avoid reporting the wrong iPhone.
- `version_relationship=TARGET_OLDER_THAN_INSTALLED`: describes only version ordering, not restore ability.

All reports retain `apple_signing_status=NOT_CHECKED`, `sep_baseband_compatibility=UNKNOWN`, `unsigned_downgrade=NOT_DEMONSTRATED`, and `device_modified=false`.

Nyx16 avoids saving or printing UDID, ECID, serial, and nonce. Share only the sanitized output of `tools/mac_probe.py`, not raw `ideviceinfo` or `irecovery` logs.
