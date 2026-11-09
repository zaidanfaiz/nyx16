# Nyx16

**Apple A12–A17 iPhone jailbreak research — device-first, evidence-driven**

> **Project goal: research and eventually demonstrate a full jailbreak for supported A12–A17 iPhones.**
> **Current reality: no jailbreak, kernel exploit, privileged filesystem access, or boot-chain bypass is implemented or demonstrated by Nyx16.** Model detection and DFU access are not jailbreak capabilities.

Nyx16 is moving from its original *unsigned iOS downgrade / IPSW metadata* hypothesis to **research toward a full jailbreak on the installed iOS version**. **Downgrading is no longer a prerequisite or primary objective.** The old IPSW comparison tools remain available as historical firmware research.

## What "full jailbreak" means here

The desired end state is a **reproducible, independently verified jailbreak on an owned/authorized device**, potentially including the ability to run privileged code and a usable jailbreak environment under iOS security constraints. The required research areas include:

- iOS application sandbox and code-signing boundaries
- Kernel privilege and security mitigations
- Userland-to-kernel and persistence constraints, if applicable
- iBoot/DFU and boot-chain behavior as *independent* research tracks
- Device/version-specific compatibility and safe recovery

**Rootless is not the same as partial jailbreak.** A successful jailbreak need not make the sealed/system volume writable. Persistent ("untethered") operation is a separate research goal; Nyx16 does not claim it is possible. Any actual exploit chain requires evidence and testing before the term *jailbreak supported* is used.

## Target platforms

| Chip family | Representative iPhones | Status |
| --- | --- | --- |
| A12 | XR, XS, XS Max | Research target; device identification |
| A13 | 11 series, SE (2020) | **Primary physical research device: iPhone 11** |
| A14 | 12 series | Research target; device identification |
| A15 | 13 series, 14/14 Plus, SE (2022) | Research target; device identification |
| A16 | 14 Pro series, 15/15 Plus (model coverage varies) | Research target; device identification |
| A17 Pro | 15 Pro, 15 Pro Max | **New research target; identification only** |

A17 Pro chip references: [Apple iPhone 15 Pro specs](https://support.apple.com/id-id/111829); [iPhone 15 Pro hardware identifiers](https://ipsw.me/iPhone16%2C1/info/).

Targeting a chip family is **not** claiming an available exploit, jailbreak compatibility, or support for every iOS version. Each build needs its own device-specific evidence.

## First physical test device

- **iPhone 11** (`iPhone12,1`, board `N104AP`, A13, CPID `0x8030`, BDID `0x04`)
- **Installed iOS:** 27.2 (build `24B119`) at time of testing
- **Observed modes:** normal, Recovery, DFU; returned to normal mode, activated
- **Pairing:** verified with Mac
- **Exploit status:** **none demonstrated**
- **Device filesystem modification:** **none demonstrated**

The above records were obtained by operator-run USB queries on the physical device. Being able to enter DFU or read Apple-hosted firmware is **not** proof of bootrom code execution, access to protected iOS files, or a jailbreak.

See [device lab](docs/DEVICE_LAB.md) for non-destructive measurements and [jailbreak research plan](docs/JAILBREAK_RESEARCH.md) for measurable success criteria.

## Research workflow

1. **Identify the actual device and OS build.** Separate USB/DFU access from privileged access; record minimal sanitized metadata.
2. **Establish a repeatable device lab.** Record baselines and recovery outcomes on owned hardware, including tests that fail.
3. **Map public security boundaries and candidate research questions.** Evaluate evidence by chip, model, board, iOS build and mitigation, without inferring an exploit from a firmware hash difference.
4. **Validate any future capability independently.** Distinguish file access, code execution, privileged execution, kernel capability and full jailbreak operation. Never claim a jailbreak based on an unverified log.
5. **Document responsible disclosure, compatibility and limitations** before release.

The repository currently supports **read-only firmware/USB research and diagnostics**, not an exploit or on-device filesystem patcher. No DFU payloads or arbitrary filesystem modification commands are provided.

## Nyx16Lab — on-device research dashboard

[Nyx16Lab](ios/Nyx16Lab/README.md) is an iPhone app for non-privileged J1–J3 lab observations, tested on an iPhone 11 running iOS 27.2. The current app has a **single Run Full Diagnostics button** that performs:

- **J1:** app-owned sandbox file write/read/cleanup
- **J2:** app-owned directory inventory and Data Protection attribute test
- **J3:** recognized ARM64 Mach-O header of the **app's own executable** and deterministic SHA-256 self-test

The updated navy/cyan dashboard has an **original Nyx16 N16 logo and 1024px Home Screen icon**, three expandable result cards, and Copy Report / AirDrop sharing of the combined report.

These are **normal signed-app baseline checks**, not a kernel exploit, jailbreak, sandbox escape or proof of code-signing bypass. The operator has now reported **J1, J2 and J3 PASS on the physical iPhone 11 (iOS 27.2)**; each reflects stock-app functionality, not privileged execution.

[App setup](ios/Nyx16Lab/README.md) · [J3 scope](ios/Nyx16Lab/J3_RUNTIME_DIAGNOSTICS.md) · [Brand vector](branding/nyx16-mark.svg)

## J4 — Reproducible vulnerability research setup

Nyx16 now has an **offline parser robustness harness** at [`tools/j4_parser_lab.py`](tools/j4_parser_lab.py). Unlike J1–J3, it does not create a new app button: it tests **a small binary parser written by the project itself**, with bounded, reproducible malformed inputs. Each run produces evidence JSON and unexpected behavior must be reproduced with the same seed. [J4 guide](docs/J4_RESEARCH.md).

```bash
python3 tools/j4_parser_lab.py --seed 1627 --cases 1500 --out reports/j4_owned_parser.json
```

This tool does **not** scan iOS, fuzz Apple parsers, exploit a kernel, or make the iPhone jailbroken. Its purpose is to establish a reliable local experiment workflow before interpreting any claimed vulnerability.

## Running existing diagnostic tools on a Mac

With an iPhone connected and trusted in normal mode:

```bash
export PATH="/opt/local/bin:$PATH"
cd ~/Development/nyx16
git pull --ff-only
python3 tools/mac_probe.py
```

The Mac probe now defaults to **jailbreak research identification** and reports `jailbreak_status=NOT_DEMONSTRATED`. The old `--target-ios 26.1` option remains available only to reproduce prior firmware comparisons; it is **not a prerequisite** for this jailbreak objective.

If the phone is in Recovery or DFU, `irecovery -m` can identify its USB mode. DFU is **not** an exploit. Do not use `irecovery` payload/boot commands, Finder Restore or unsigned flashes as "discovery tests."

For the existing local firmware tool:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## Historical firmware research (preserved)

Nyx16 retains read-only Apple CDN HTTP Range and BuildManifest inspection, iOS 27.2 versus iOS 26.1 comparisons, Image4/iBoot/SEP structure and compression metadata studies. These are **supporting research** only; they have not produced a working downgrade or jailbreak.

- [Firmware comparison archive](docs/FIRMWARE_COMPARISON.md)
- [Original downgrade feasibility notes](docs/MAC_STAGE5.md)
- [GitHub Actions firmware reports](../../actions/workflows/iphone11-compare.yml)

## Roadmap and responsible scope

- [Roadmap to a verifiable full jailbreak](docs/ROADMAP.md)
- [Research design, privilege gates and evidence policy](docs/JAILBREAK_RESEARCH.md)
- [On-device measurement and recovery](docs/DEVICE_LAB.md)
- [Security scope and disclosure](docs/SECURITY_SCOPE.md)

**No Activation Lock/MDM bypass, third-party device intrusion, kernel exploit chain, Apple signature bypass, or jailbreak binary is supplied.** Never upload UDIDs, ECIDs, serial numbers, pairing records, personal device data, nonces or proprietary firmware images as public research evidence.

## License

MIT. Copyright 2026 Nyx16 contributors.


