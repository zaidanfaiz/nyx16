# Nyx16 research roadmap

## M0 — Independent foundation (completed)
- Independent A12–A16 CPID database and offline IPSW metadata inspection
- No checkm9 dependencies; no device modifications
- Synthetic tests, read-only GitHub Actions CI

## M1 — Evidence-grounded GitHub Actions reporting (implemented)
- Automatic and manually dispatched pipeline
- Public GitHub-hosted BuildManifest URL as optional ephemeral input
- SHA256 manifest inventory and declared identity metadata matrix
- A12–A16 SoC research baseline with no implied compatibility
- Official Apple Secure Boot references in downloadable Markdown report
- CI validation for malformed, oversized, and linked manifest inputs

## M2 — Research quality improvements (proposed)
- More explicit confidence tiers for each evidence claim
- Optional offline manifest-to-manifest comparison with version-aware records
- Regression tests for real, redacted public BuildManifest examples with provenance
- Documented per-version signing sources, clearly separated from signing assertions

## M3 — Evidence-dependent research (not started)
- Authorization, SEP, and baseband constraints documented with sources
- Independent reproduction on owned / authorized devices only
- No declaration of exploit capability without a verifiable demonstration

**No activation bypass, unsigned firmware flashing, signing defeat, or full downgrade method is provided.**
