# Nyx16 Security Scope and Evidence Policy

## Mission

Nyx16 researches the conditions for a future **full jailbreak on A12–A17 Pro iPhones**, prioritizing an **owned/authorized A13 iPhone 11 running iOS 27.2**. The project does **not** currently contain a jailbreak or privilege-escalation exploit. Prior iOS 26.1 downgrade work is retained as a separate historical reference.

## Present, implemented capabilities

- Read-only local and GitHub Actions firmware metadata inspection.
- Bounded Apple CDN IPSW BuildManifest, ZIP directory, and static Image4 parsing.
- Minimal normal/Recovery/DFU USB device model, board, iOS version/build identification where services permit.
- Tests against offline synthetic fixtures and CI.
- **A17 Pro identification coverage**, which is not exploit support.

## Not implemented or demonstrated

- iOS kernel execution, privilege escalation or a complete exploit chain.
- Defeat of AMFI, sandbox, KTRR/PPL, PAC or other security controls.
- Root filesystem modifications or privileged access to protected device files.
- A working tethered/untethered, rootless/rootful jailbreak.
- BootROM/DFU exploit or unsigned payload booting.
- Apple TSS/signing bypass, SEP compromise, unsigned restore, Activation Lock/MDM bypass.
- Any compromise of third-party devices.

## Research evidence levels

| Status | Meaning |
| --- | --- |
| `TARGET` | Intended chip/model/build research scope, **not compatibility** |
| `OBSERVED` | Hardware or format property observed through bounded, authorized testing |
| `REPRODUCED` | Repeatable behavior under documented, scoped lab conditions |
| `PRIVILEGE_DEMONSTRATED` | Independently verified execution capability; not yet "full jailbreak" |
| `JAILBREAK_VERIFIED` | End-to-end environment works on the stated specific build/device |
| `UNKNOWN` | No reliable evidence either way |
| `NOT_DEMONSTRATED` | No validated outcome; should never appear as proof |

## Authorized device handling

- Only test personally owned or explicitly authorized devices.
- Do not collect, commit or publish UDIDs, serials, ECIDs, pairing records, APNonces or user data.
- DFU is a communication state; **its availability is not a vulnerability**.
- Stock iOS app-container access is **not** system/root filesystem access.
- Use a documented local recovery plan before changes to boot state or firmware.
- Do not publish live exploit payloads, credential-access tooling, target-selection automation or unauthorized bypass instructions.
- Prefer responsible disclosure if a real flaw is discovered.

**Interpretation policy:** a parsed IM4P field, matching firmware hash, working USB pairing, or a recovery-mode command cannot be upgraded into a jailbreak claim. Gate-specific evidence is required.
