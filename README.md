# Nyx16

**Apple A12–A16 firmware metadata and Secure Boot research, automated in GitHub Actions**

> **Research only, v0.2.0.** Nyx16 is not a demonstrated exploit. It does not bypass Apple signing, jailbreak, restore, downgrade, or alter an iPhone.

Nyx16 is independent of checkm9 and ipwndfu. Our CI reports what is **documented**, what is **declared by firmware metadata**, and what remains **unverified**.

## Run entirely through GitHub Actions

1. Open **[Actions → Nyx16 Firmware Research](../../actions/workflows/research.yml)**.
2. Select **Run workflow** (branch: `main`).
3. Optionally enter a publicly accessible **raw GitHub URL to a `BuildManifest.plist`** in `manifest_url`. Leave blank to build the baseline research report from committed evidence.
4. Open the completed run; read the **Summary** and download the **nyx16-research-reports-...** artifact (retained 21 days).

This workflow also runs automatically on changes to research code, evidence, or documentation in `main`, and on relevant pull requests. No laptop, iPhone connection, complete IPSW upload, or external package installation is needed to run the research pipeline.

**The URL input accepts a single raw `BuildManifest.plist` hosted on `raw.githubusercontent.com` or `gist.githubusercontent.com`.** It does not accept full multi-GB IPSW archive URLs. The input is analyzed in the ephemeral Actions runner and is not added to the repository.

### Downloadable reports

| File | What it proves |
| --- | --- |
| `firmware_manifest_matrix.csv` | Metadata explicitly declared in supplied BuildManifest identities; no inferred board/product pairing |
| `soc_research_matrix.csv` | Baseline A12–A16 chip registry; research coverage not exploit support |
| `secure_boot_evidence.md` | Vendor-documented constraints with references to Apple security documentation |
| `research_summary.json` | Manifest inventory and SHA256 hashes with limitation flags |
| `RESEARCH_SUMMARY.md` | Summary visible directly in GitHub Actions |

When no real manifest is provided, the reports explicitly state **no firmware evidence supplied**. A chip appearing in the baseline table does not mean a downgrade is feasible.

## Research families

| SoC | Silicon | CPID | Status |
| --- | --- | --- | --- |
| A12 | T8020 | 0x8020 | Research only |
| A13 | T8030 | 0x8030 | Research only |
| A14 | T8101 | 0x8101 | Research only |
| A15 | T8110 | 0x8110 | Research only |
| A16 | T8120 | 0x8120 | Research only |

Source: [Asahi Linux SoC codenames](https://asahilinux.org/docs/hw/soc/soc-codenames/).

## Scope and evidence

A `BuildManifest.plist` declares product types, build identities, board details, and version metadata. It **does not establish** that Apple still signs a build or that a specific device can boot it. Apple documents a personalized software authorization system and independent Secure Enclave verification.

Every automated report keeps:
- Apple signing: `NOT_CHECKED`
- SEP and baseband compatibility: `UNKNOWN`
- Unsigned downgrade: `NOT_DEMONSTRATED`

See [Actions usage](docs/ACTIONS_USAGE.md), [Roadmap](docs/ROADMAP.md), [Security scope](docs/SECURITY_SCOPE.md), and [Contributing](CONTRIBUTING.md).

## Local developer commands (optional)

Automated analysis runs in GitHub Actions; maintainers may also reproduce checks locally using Python 3.10+:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m nyx16.research --manifests evidence/manifests --out reports
```

The existing `nyx16 inspect` command can inspect a local IPSW's root BuildManifest, without extracting or modifying firmware. It is separate from the GitHub-hosted research workflow.

## License

MIT, copyright 2026 Nyx16 contributors.
