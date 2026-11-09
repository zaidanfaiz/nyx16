# Nyx16 — Full Jailbreak Research Program (A12–A17)

## Hypothesis and goal

**Hypothesis:** a future, version-specific vulnerability may enable a usable jailbreak on some A12–A17 Pro iPhones without first downgrading iOS. This is a research goal, **not evidence of such a vulnerability**.

Primary physical reference: **iPhone 11 / A13 / N104AP / iOS 27.2 (24B119)**.

Full jailbreak is defined by observed **end-to-end capabilities** on a precisely scoped device/build rather than a vague "root" claim. A *semi-jailbreak* can provide limited tweaks but may not cross all boundaries needed for privileged execution. "Full" does not necessarily require a writable sealed system volume; rootless jailbreaks deliberately work without that.

## Security boundaries to investigate

| Boundary | What evidence would distinguish research from implementation? |
| --- | --- |
| Stock app sandbox | Explicitly observed app permissions and contained file visibility |
| Code signing / AMFI | Reproducible, authorized execution capability assessment |
| Userland to kernel | Independent demonstration of the exact claimed privilege level |
| Kernel protections | A build-specific description of protection state and mitigations |
| Trust and boot chain | DFU/recovery **transport** observations, kept separate from execution |
| Jailbreak environment | Verified functionality, stability, compatibility and uninstall/recovery |

Do not infer one boundary from another. Access to an app container does not imply kernel access; DFU detection does not imply unsigned execution.

## Current device evidence

An operator tested an owned iPhone 11 in Normal, Recovery and DFU modes, showing the following non-sensitive fields:
- ProductType `iPhone12,1`
- HardwareModel `N104AP`
- A13 CPID `0x8030`, BDID `0x04`
- iOS `27.2`, build `24B119`
- Returned from DFU to normal iOS; paired and activated

Those measurements establish transport and identification only. **They do not constitute a vulnerability, jailbreak, root access, filesystem write, or downgrade.**

## How to evaluate future findings

- Maintain exact model, board, SoC, OS version and build association.
- Distinguish first-hand authorized observation from conjecture and third-party reports.
- Favor offline fixtures and static analysis for early confidence testing.
- Require independently repeatable on-device evidence before upgrading a capability claim.
- Keep failure modes, recovery outcomes and unresolved questions in the report.
- Seek appropriate disclosure handling for a novel security flaw.
- Do not treat compatibility with a published vulnerability as proof of exploitability without evidence.

## Research deliverables

1. Sanitary device observation record with no secrets or identifying serial numbers.
2. Build-specific security-mitigation map with public citations.
3. Offline tests plus evidence review criteria for potential findings.
4. Reproducibility and stability criteria for a future authorized-device jailbreak, if discovered.
5. Unambiguous supported-device/build matrix, never blanket A12–A17 support based on one device.

Legacy IPSW/Image4 tools are available in [firmware comparison](FIRMWARE_COMPARISON.md), but downgrade is no longer the primary objective. Read [security scope](SECURITY_SCOPE.md) before extending the device workflow.
