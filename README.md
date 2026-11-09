# Nyx16

**Apple A12–A16 IPSW metadata and Secure Boot research in GitHub Actions**

> **Research only, v0.3.0.** Nyx16 is not a demonstrated exploit. It does not bypass Apple signing, jailbreak, restore, downgrade, or alter an iPhone.

Nyx16 is independent of checkm9 and ipwndfu. GitHub Actions now supports direct Apple CDN IPSW URLs using **bounded HTTP Range requests**, downloading only the ZIP directory and `BuildManifest.plist` needed for read-only research. No local tools or full IPSW download required.

## One-click preset: iPhone 12 / iOS 26.1

Open **[Actions → Nyx16 Firmware Research](../../actions/workflows/research.yml)**, select **Run workflow**, and keep `firmware_target=iphone12-ios26.1` (default). Leave URLs blank, start the run, then download the `nyx16-research-reports` artifact.

The preset uses the official Apple CDN IPSW for **iPhone 12 (`iPhone13,2`), A14, iOS 26.1 build `23B85`**, cross-referenced against the [IPSW catalog](https://ipsw.me/download/iPhone13%2C2/23B85/). The catalog currently lists the firmware as **unsigned**. Nyx16 does not contact Apple's signing service or assert that unsigned installation is possible.

Custom firmware modes support an Apple CDN `.ipsw` URL or a raw public GitHub-hosted `BuildManifest.plist`; `baseline` makes a report without downloading firmware. The repository also executes the preset on relevant CI pushes and pull requests.

The HTTP Range client requires exact HTTP 206 responses and limits all transfers to **64 MiB**, preventing accidental download of the full 10.1 GB IPSW. If a server does not support ranges, the workflow stops with an error. Only the manifest is saved into an ephemeral runner; firmware binaries are neither extracted nor published.

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

**A BuildManifest match is not proof of device restore authorization, valid SHSH, bootability, SEP compatibility, or baseband compatibility.** Signing remains `NOT_CHECKED`; unsigned downgrade remains `NOT_DEMONSTRATED`.

See [Actions usage](docs/ACTIONS_USAGE.md), [research roadmap](docs/ROADMAP.md), and [security scope](docs/SECURITY_SCOPE.md).

## Reproduce tests (optional)

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## License

MIT, copyright 2026 Nyx16 contributors.
