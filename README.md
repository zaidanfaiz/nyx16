# Nyx16

**Offline A12–A16 iOS firmware analysis and secure-boot research**

> **Research / pre-exploit (v0.1.0).** Nyx16 is a research codename, not a demonstrated exploit. It cannot bypass Apple signing, downgrade unsigned firmware, jailbreak, or alter an iPhone.

Nyx16 is an independent project, not a fork of checkm9 or ipwndfu. Its first milestone is a deterministic, local, read-only IPSW metadata inspector.

## Research families

| SoC | Silicon | CPID | Status |
| --- | --- | --- | --- |
| A12 | T8020 | 0x8020 | Metadata research only |
| A13 | T8030 | 0x8030 | Metadata research only |
| A14 | T8101 | 0x8101 | Metadata research only |
| A15 | T8110 | 0x8110 | Metadata research only |
| A16 | T8120 | 0x8120 | Metadata research only |

Source: [Asahi Linux SoC codenames](https://asahilinux.org/docs/hw/soc/soc-codenames/).

## Quick start

Python 3.10+; standard library only.

```bash
PYTHONPATH=src python3 -m nyx16 chips
PYTHONPATH=src python3 -m nyx16 inspect /path/to/firmware.ipsw --product-type iPhone13,2
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

The inspector reads only the root `BuildManifest.plist` from an IPSW ZIP. It **never extracts, uploads, flashes, patches, or executes** firmware contents. Validate the provenance of firmware independently.

## Understanding the report

- `matched`: supplied identifier appears in declared manifest metadata.
- `mismatched`: supplied identifier is absent from explicitly provided metadata.
- `unknown`: insufficient information to compare.
- `apple_signing_status`: always `NOT_CHECKED`.
- `downgrade_feasibility`: always `UNDETERMINED`.

**A metadata match does not prove signing, restore eligibility, or SEP/baseband compatibility.** No unsigned downgrade is claimed.

See [Roadmap](docs/ROADMAP.md), [Security Scope](docs/SECURITY_SCOPE.md), and [Contributing](CONTRIBUTING.md).

## License

MIT, copyright 2026 Nyx16 contributors.
