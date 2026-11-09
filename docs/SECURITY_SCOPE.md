# Research scope, limitations, and security

## Current capabilities
- Reads root IPSW `BuildManifest.plist` locally from a ZIP
- Reports device product types and board configurations declared in metadata
- Flags simple mismatches and marks inconclusive comparisons unknown
- Lists publicly documented Apple A12–A16 silicon identifiers

## Not supported
- Apple TSS signing checks, cryptographic signature or SHSH/APTicket verification
- APNonce compatibility, SEP/baseband cross-version compatibility
- DFU access, BootROM exploitation, firmware restore or downgrade
- Activation Lock bypass or unauthorized device access

## Security posture
Operations are offline and read-only. No archive entries are extracted. The manifest is capped at 10 MiB in size. Test fixtures are synthetic. Third-party firmware should be treated as untrusted until provenance and hashes are independently verified.

## Evidence standard
Future vulnerability claims must state exact hardware, SoC, firmware, observed results, risks, provenance, disclosure context, and independent reproduction. Nyx16 is not currently a demonstrated exploit.
