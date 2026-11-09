# Nyx16 Experiment #5 — Offline feasibility audit (iPhone 11, 27.2 → 26.1)

This stage consumes the **sanitized Mac Stage 4 JSON** and a *date-stamped third-party firmware-signing catalog snapshot* to produce a conservative decision. **It does not run Apple TSS requests, USB commands, restore tools, DFU operations, patches, or signing bypass.**

## On macOS

Your Stage 4 output was saved as `~/Desktop/nyx16-stage4.json`. Keep that file unchanged.

```bash
cd ~/Development/nyx16
git pull --ff-only
python3 tools/stage5_audit.py
```

The script prints the decision and writes two new files under `~/Desktop/Nyx16-Stage5/`:

- `stage5_feasibility.json`: structured evidence, device matching, uncertainty, and decision
- `STAGE5_FEASIBILITY.md`: readable audit with references and risk review

For custom paths:

```bash
python3 tools/stage5_audit.py \
  --stage4 "$HOME/Desktop/nyx16-stage4.json" \
  --catalog evidence/iphone11_signing_snapshot_2026-11-09.json \
  --out "$HOME/Desktop/Nyx16-Stage5"
```

No original file is modified. The Stage 4 input is hashed for provenance.

## Evidence this stage actually possesses

- USB normal-mode `iPhone12,1`, board `N104AP`, iOS `27.2` / `24B119`, A13
- Target `26.1` / `23B85` BuildManifest metadata, with 13/13 Stage 4 metadata checks matching
- 24 manifest digest-field comparisons differ, 4 lack sufficient metadata (these are **not exploits**)
- Current modem baseband version as read from the attached device: `8.00.00`
- As of **2026-11-09**, [IPSW Downloads iPhone 11 catalog](https://ipsw.me/iPhone12%2C1/) reports iOS 26.1 **unsigned** and iOS 27.2 **signed**

Catalog evidence is not an Apple-generated personalized restore authorization. When the cached snapshot is over seven days old, the script identifies it as stale; it does not perform a silent signing lookup or pretend the catalog is live.

## Decision states

| Decision | Interpretation |
| --- | --- |
| `NO_GO_UNSIGNED_TARGET` | Metadata is valid, but the catalog lists target as unsigned; routine restore is not available |
| `NO_GO_INSUFFICIENT_OR_INVALID_EVIDENCE` | Prerequisite reports, device identifiers, or provenance disagree |
| `HOLD_UNVERIFIED_ELIGIBILITY` | Even if a catalog claims signed, personalized authorization and cross-version compatibility remain unverified |

There is deliberately **no `GO` state** in Stage 5, because these inputs cannot authorize installation.

## Risks and outstanding checks

1. Signing policy: Apple personalized restore authorization was **NOT CHECKED** by Nyx16; do not confuse a public catalog with Apple TSS.
2. SEP: Manifest digest fields may differ between versions, but cross-version compatibility is still **UNKNOWN**.
3. Baseband: The installed baseband version alone does not establish whether target firmware would support it; compatibility is **UNKNOWN**.
4. Backups and recovery: A firmware restore can erase local data. A backup from newer iOS may not be restorable to older iOS, and an unsupported restore may leave the user needing a currently signed version.
5. Activation Lock: Separate from firmware metadata. This script does not modify Activation Lock, MDM, owner identity, or device activation.

Sources:
- [Apple Platform Security](https://support.apple.com/guide/security/)
- [IPSW Downloads: iPhone 11 current catalog](https://ipsw.me/iPhone12%2C1/)
- [IPSW Downloads: iPhone 11 iOS 26.1](https://ipsw.me/download/iPhone12%2C1/23B85/)
- [IPSW Downloads: iPhone 11 iOS 27.2](https://ipsw.me/download/iPhone12%2C1/24B119/)

**No-go is an evidence-based restriction on restore attempts, not a statement that a new exploit is impossible.** Revisit when a demonstrable, independently verified, device-specific authorization or supported upgrade path exists.
