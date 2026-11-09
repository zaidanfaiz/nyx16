# Experiment #3: iPhone 11 A13 — iOS 27.2 versus iOS 26.1

Run the comparison **entirely within GitHub Actions**: [Nyx16 iPhone 11 27.2 vs 26.1](https://github.com/zaidanfaiz/nyx16/actions/workflows/iphone11-compare.yml).

Select **Run workflow** on branch **main**. No connected iPhone or macOS computer is required for this phase. The two IPSWs are never downloaded in full.

## Verified model and build references

| Kind | Device | Version | Build | Source |
| --- | --- | --- | --- | --- |
| Current | iPhone 11 / iPhone12,1 / A13 / N104AP | 27.2 | 24B119 | https://ipsw.me/download/iPhone12%2C1/24B119/ |
| Target | iPhone 11 / iPhone12,1 / A13 / N104AP | 26.1 | 23B85 | https://ipsw.me/download/iPhone12%2C1/23B85/ |

The project records *published* full-file checksums for provenance, but does **not verify whole-IPSW checksums** because it transfers only partial ZIP ranges. GitHub Actions validates model, version, and build in each BuildManifest before comparing them.

## What is compared

Nyx16 reads metadata entries of all `BuildIdentities` with `DeviceClass=N104AP`. It groups identities using **Variant** and **RestoreBehavior**; an ambiguous or missing identity is reported as such rather than being matched by list index.

For each identity, it examines manifest key presence and available `Digest` fields in categories:
- iBoot, iBSS, iBEC, LLB
- SEP
- Baseband
- KernelCache

The tool fingerprints the manifest's *Digest field*, **not** the actual firmware binary. A digest-field match does not imply binaries are interchangeable or signatures valid.

## Downloadable artifact

After the GitHub Actions job succeeds, download the ZIP artifact `nyx16-iphone11-27_2-vs-26_1-N` containing:

- `iphone11_firmware_comparison.json` — structured metadata comparison
- `iphone11_component_metadata_matrix.csv` — per-identity/component status
- `IPHONE11_COMPARISON_SUMMARY.md` — also appears in Actions Summary
- `current_ipsw_source.json` and `target_ipsw_source.json` — provenance, manifest SHA256 and network transfer sizes

It does **not** upload complete IPSWs, firmware component binaries, or raw BuildManifest files.

## Hard limits

Apple authorization: **NOT_CHECKED**; SEP and baseband cross-version compatibility: **UNKNOWN**; unsigned downgrade: **NOT_DEMONSTRATED**. This workflow cannot restore, patch, jailbreak, exploit Secure Boot, or modify any connected device.

Apple's signed software update system is documented at https://support.apple.com/en-ca/guide/security/secf683e0b36/web.

For the user's original Mac experiment, the recognized device was `iPhone12,1` with board `N104AP`, iOS 27.2 and baseband 8.00.00. Those details do **not** establish SEP/baseband downgrade compatibility. Do not run firmware restore commands based on this report.
