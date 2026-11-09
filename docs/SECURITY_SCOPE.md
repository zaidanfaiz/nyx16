# Nyx16 security scope and evidence policy

## Implemented
- Read-only inspection of local IPSW root `BuildManifest.plist` and offline standalone manifest analysis
- Hosted GitHub Actions reports with CSV matrices, evidence citations, and input SHA256 hashes
- Public raw GitHub-hosted plist as optional runner-only input; no full IPSW download
- Strict caps: 10 MiB per manifest, at most 64 manifest files, at most 512 BuildIdentities per file
- Rejects evidence symlinks, malformed files, oversized inputs, and non-GitHub-hosted URL destinations

## Not performed
- No DFU, BootROM exploitation, unsigned restore, firmware flashing, or device modifications
- No Apple TSS / authorization server requests, SHSH/APTicket checks, or APNonce compatibility tests
- No SEP or baseband version-compatibility predictions
- No bypass of Activation Lock or unauthorized device access

## Evidentiary meaning
- `DECLARED_IN_IDENTITY` means a board and product are both explicitly listed in a single manifest identity. It is not a boot guarantee.
- `NOT_ESTABLISHED` means a pair is not explicitly documented within one identity; a top-level `SupportedProductTypes` list is not sufficient to infer its pairing with each board.
- `NOT_CHECKED`, `UNKNOWN`, and `NOT_DEMONSTRATED` are deliberately inconclusive, not test failures or evidence of compatibility.
- Vendor documentation establishes stated design constraints, not any vulnerability or exploit feasibility.

## Safety and disclosure
Do not publish device-specific identifiers, activation credentials, pairing records, blobs containing user secrets, or proprietary firmware images. Conduct hardware research only on owned or explicitly authorized equipment, with a recovery plan. Use independent evidence before claiming a vulnerability, bypass, or downgrade.
