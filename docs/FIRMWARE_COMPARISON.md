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


## New archive-index experiment (read-only)

The `tools/ipsw_inventory.py` utility now checks the **real IPSW ZIP central directory** for paths referenced by iPhone 11 (`N104AP`) iBoot, iBSS, iBEC, LLB, SEP, Baseband and KernelCache BuildManifest component entries.

The tool:
- Queries official Apple CDN IPSWs over strict HTTP 206 byte ranges and reads **only the root BuildManifest and ZIP central-directory metadata**.
- Verifies the root manifest's SHA256 against the separately fetched manifest used in the existing iOS 27.2 vs 26.1 comparison.
- For each relevant build identity, records component category, exact manifest-declared ZIP path, whether that path exists exactly, and **ZIP-declared** compressed/uncompressed byte sizes and compression method.
- Compares corresponding component entries across the two IPSW versions conservatively. Missing paths and ambiguous identities are explicitly marked.
- Does **not** download firmware-component binary payloads, hash component binaries, test bootability, perform TSS requests, or contact an iPhone.

This adds the following files to the normal GitHub Actions comparison artifact:

| File | Contents |
| --- | --- |
| `ios27_2_archive_inventory.json` | Current firmware ZIP directory metadata |
| `ios26_1_archive_inventory.json` | Target firmware ZIP directory metadata |
| `iphone11_ipsw_archive_comparison.json` | Matched component paths and archive size comparisons |
| `iphone11_ipsw_archive_comparison.csv` | Tabular comparison by identity and component |

### Interpret carefully

The presence of a file path and its size in a ZIP directory is a **metadata observation only**. It does not prove the referenced binary's signature, authenticity, exploitability, cross-version compatibility, or availability for unsigned restore. `ZIP_ENTRY_METADATA_MATCH_NOT_BINARY_VERIFIED` must never be interpreted as compatible or identical firmware. When paths are missing, the program reports `ZIP_PATH_NOT_VERIFIED_IN_BOTH`, not a firmware failure.

The project already proved the connected iPhone 11 `CPID=0x8030`, `BDID=0x04`, `MODEL=n104ap` was reachable in Recovery and DFU, and returned to normal iOS 27.2. That hardware evidence is **separate** from the remote IPSW archive inventory.


## Experiment: shallow static Image4 / IM4P header survey

The [comparison workflow](https://github.com/zaidanfaiz/nyx16/actions/workflows/iphone11-compare.yml) additionally performs bounded static inspection of the **iBoot** and **SEP** `.im4p` components for **iPhone 11 N104AP**, iOS 27.2 and iOS 26.1.

- Uses only the official Apple CDN URLs already validated against each `BuildManifest.plist`.
- Restricts selection to the **Customer Erase Install (IPSW)** identity with `DeviceClass=N104AP` and matching expected version/build.
- Reads **only two component files per IPSW** via guarded HTTP byte ranges, each capped at **10 MiB compressed and uncompressed**.
- Parses the top-level ASN.1 DER SEQUENCE, `IM4P`/optional `IMG4` envelope magic, four-character image type, description, OCTET STRING **declared length**, and optional-field presence. It does **not** parse or decrypt the payload OCTET STRING.
- Computes SHA256 over the complete ZIP member bytes read in memory and verifies ZIP member CRC via the standard Python ZIP reader. **This is not an Apple signature validation or a hardware boot verification.**
- Does not save firmware components, remove signatures, decrypt firmware, issue device commands, flash, or attempt restore.

The workflow artifact adds:
- `ios27_2_image4_headers.json`
- `ios26_1_image4_headers.json`
- `iphone11_image4_header_comparison.json`

Status vocabulary: `SHALLOW_DER_ENVELOPE_VALID`, `UNRECOGNIZED_OR_MALFORMED_DER`, `FILE_SHA256_DIFFERS`, `FILE_SHA256_MATCH_NOT_SIGNATURE_PROOF`, `IM4P_TYPE_CODE_DIFFERS`, and `PARSE_INCOMPLETE`. These labels report **static format observations**, not exploitability, downgrade viability, SEP compatibility, or any guarantee of binary execution.

Format reference: [The iPhone Wiki — IMG4 file format](https://www.theiphonewiki.com/wiki/IMG4_File_Format) and [ReverseEngineering.wiki IMG4](https://reverseengineering.wiki/index.php/Format:IMG4).

**SEP description nuance:** An Apple SEP IM4P can use a long (1,246-byte) IA5String for opaque description metadata. Nyx16 records its size, SHA256 and whether it is printable; it deliberately does not interpret or export embedded data. Older 192-byte description limits incorrectly rejected these files, and have been corrected.

Connected iPhone mode tests remain separate: the physical iPhone 11 showed `CPID=0x8030` and `BDID=0x04` in Recovery and DFU before returning to normal iOS 27.2. No payload was ever sent to the phone.
