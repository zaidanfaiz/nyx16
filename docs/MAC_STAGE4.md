# Nyx16 Stage 4 — Validate GitHub Actions comparison against a connected iPhone 11

**Goal:** confirm the previously generated iOS 27.2 (24B119) vs iOS 26.1 (23B85) BuildManifest metadata comparison is applicable to a physically attached iPhone 11 (iPhone12,1, N104AP). This is an observation-only stage.

## On the Mac

Keep one iPhone 11 connected via USB and trusted in normal mode. Use the existing Nyx16 clone:

```bash
export PATH="/opt/local/bin:$PATH"
cd ~/Development/nyx16
git pull --ff-only
python3 tools/mac_verify.py
```

The script automatically searches `~/Downloads` for the most recently modified **nyx16-iphone11-27_2-vs-26_1-*** artifact. It accepts the artifact ZIP **or the extracted directory**. You do not have to re-zip it.

If the file was downloaded to another location:

```bash
python3 tools/mac_verify.py --report "$HOME/Downloads/nyx16-iphone11-27_2-vs-26_1-1"
```

Or use the ZIP path (when applicable):

```bash
python3 tools/mac_verify.py --report "$HOME/Downloads/nyx16-iphone11-27_2-vs-26_1-1.zip"
```

Download the artifact from [the GitHub Actions comparison run](https://github.com/zaidanfaiz/nyx16/actions/workflows/iphone11-compare.yml). It contains:
- `iphone11_firmware_comparison.json`
- `current_ipsw_source.json`
- `target_ipsw_source.json`

## Interpret results

| Status | Meaning |
| --- | --- |
| `METADATA_MATCH_ONLY` | Model, board, installed version/build and source manifest report fields agree. **No restore feasibility is established** |
| `MISMATCH_STOP` | Wrong device, wrong iOS/build, differing source hashes or misleading report claim |
| `INCONCLUSIVE_DEVICE_ACCESS` | Connected phone cannot supply the required normal-mode identity |
| `NOT_COMPLETED` | Artifact path or JSON couldn't be read |

The script displays the current baseband version when available; it **does not** compare baseband/SEP binaries or test cross-version compatibility.

For reproducibility, you may add `--output "$HOME/Desktop/nyx16-stage4.json"`; the tool does not retain UDID, serial number, ECID, pairing records or nonces.

## Scope

Nyx16 currently does not implement an A13 unsigned downgrade. GitHub Actions and local probes cannot defeat Apple signing requirements. **Do not flash, restore, or erase the iPhone based on a metadata match**. Device authorization, data preservation, SEP and baseband version compatibility remain separate unresolved questions.

Source: [Apple software update security](https://support.apple.com/en-ca/guide/security/secf683e0b36/web).
