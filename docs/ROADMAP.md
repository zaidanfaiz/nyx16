# Nyx16 research roadmap

### M0 — v0.1.0 foundation
- Independent codebase and branding, no checkm9 dependencies
- A12–A16 CPID registry with public-source attribution
- Offline BuildManifest inspection and JSON output
- Guardrails: no extraction, restore, device modification, or signing assertions
- Synthetic unit tests and GitHub Actions CI

### M1 — Validation
- Additional synthetic test vectors and edge-case fuzzing
- Explicit input provenance and hash record
- Evidence confidence levels for compatibility conclusions
- Documentation of IPSW component relationships (SEP, baseband, iBoot)

### M2 — Research
- Source-cited matrix of documented limitations by SoC, model, and firmware
- Distinguish BootROM, iBoot, SEP, and restore authorization research
- Record independently reproduced findings on owned or authorized devices

### M3 — Evidence-dependent future work
- Responsible vulnerability research and disclosure, when applicable
- Do not advertise unsigned downgrade support without validated end-to-end results

**No functionality for bypassing activation, defeating signing, or flashing unsigned images is included.**
