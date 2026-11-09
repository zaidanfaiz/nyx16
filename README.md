# Nyx16

**Apple A12–A16 IPSW metadata and Secure Boot research in GitHub Actions**

> **Research only, v0.3.0.** Nyx16 is not a demonstrated exploit. It does not bypass Apple signing, jailbreak, restore, downgrade, or alter an iPhone.

Nyx16 is independent of checkm9 and ipwndfu. GitHub Actions now supports direct Apple CDN IPSW URLs using **bounded HTTP Range requests**, downloading only the ZIP directory and `BuildManifest.plist` needed for read-only research. No local tools or full IPSW download required.

## One-click preset: iPhone 11 / iOS 26.1

Open **[Actions → Nyx16 Firmware Research](../../actions/workflows/research.yml)**, select **Run workflow**, and keep `firmware_target=iphone11-ios26.1` (default). Leave URLs blank, start the run, then download the `nyx16-research-reports` artifact.

The default preset uses the Apple CDN IPSW for **iPhone 11 (`iPhone12,1`), A13, iOS 26.1 build `23B85`**, cross-referenced against the [IPSW catalog](https://ipsw.me/download/iPhone12%2C1/23B85/). Choose `iphone12-ios26.1` to inspect iPhone 12 firmware instead. The catalog currently lists the firmware as **unsigned**. Nyx16 does not contact Apple's signing service or assert that unsigned installation is possible.

Custom firmware modes support an Apple CDN `.ipsw` URL or a raw public GitHub-hosted `BuildManifest.plist`; `baseline` makes a report without downloading firmware. The repository also executes the iPhone 11 preset on relevant CI pushes and pull requests. macOS device inspection supports iPhone 11, 12, 13, 14, and their variants through automatic ProductType detection; see [macOS first-run instructions](docs/MAC_FIRST_RUN.md).

The HTTP Range client requires exact HTTP 206 responses and limits all transfers to **64 MiB**, preventing accidental download of the full 9.5 GB iPhone 11 IPSW. If a server does not support ranges, the workflow stops with an error. Only the manifest is saved into an ephemeral runner; firmware binaries are neither extracted nor published.

## Downloadable reports

| File | Meaning |
| --- | --- |
| `firmware_manifest_matrix.csv` | Build identity, product, board and OS metadata declared in BuildManifest |
| `soc_research_matrix.csv` | Baseline A12–A16 SoC inventory, not downgrade compatibility |
| `secure_boot_evidence.md` | Source-linked Apple Secure Boot design claims |
| `research_summary.json` | Manifest inventory and SHA256 |
| `ipsw_http_source.json` | Partial-transfer provenance and hash limits (when IPSW mode is used) |
| `RESEARCH_SUMMARY.md` | Human-readable GitHub Actions Summary |

### Current research families

| SoC | Silicon | CPID | Status |
| --- | --- | --- | --- |
| A12 | T8020 | 0x8020 | Metadata research |
| A13 | T8030 | 0x8030 | Metadata research |
| A14 | T8101 | 0x8101 | Metadata research |
| A15 | T8110 | 0x8110 | Metadata research |
| A16 | T8120 | 0x8120 | Metadata research |

Source: [Asahi Linux SoC codenames](https://asahilinux.org/docs/hw/soc/soc-codenames/).

**A BuildManifest match is not proof of device restore authorization, valid SHSH, bootability, SEP compatibility, or baseband compatibility.** A manifest for iPhone 12 cannot be assumed to apply to iPhone 11. Signing remains `NOT_CHECKED`; unsigned downgrade remains `NOT_DEMONSTRATED`.

See [Actions usage](docs/ACTIONS_USAGE.md), [research roadmap](docs/ROADMAP.md), and [security scope](docs/SECURITY_SCOPE.md).

## Reproduce tests (optional)

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## License

MIT, copyright 2026 Nyx16 contributors.


## macOS Stage 4 — verify the iPhone 11 comparison artifact

With your iPhone 11 attached to the Mac, download the [iOS 27.2 vs 26.1 comparison artifact](https://github.com/zaidanfaiz/nyx16/actions/workflows/iphone11-compare.yml) into Downloads. Then run:

```bash
cd ~/Development/nyx16
git pull --ff-only
python3 tools/mac_verify.py
```

This recognizes the downloaded ZIP **or an extracted folder** automatically, and cross-checks the artifact fields with USB-reported device model, board, and installed version. Even a pass means **metadata match only**, never unsigned restore permission. See [Mac Stage 4 guide](docs/MAC_STAGE4.md).


## Stage 5 — iPhone 11 downgrade feasibility audit (offline)

After successful Stage 4 metadata matching, generate a **conservative, read-only** audit from `~/Desktop/nyx16-stage4.json`:

```bash
cd ~/Development/nyx16
git pull --ff-only
python3 tools/stage5_audit.py
```

Results are written to `~/Desktop/Nyx16-Stage5/` as JSON and Markdown. The saved signing snapshot is a **date-stamped external catalog observation**, not a live Apple TSS authorization. There is deliberately no `GO` restore decision in this audit. See [Stage 5 instructions](docs/MAC_STAGE5.md).
