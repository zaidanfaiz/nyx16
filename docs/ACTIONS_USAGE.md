# Using Nyx16 with GitHub Actions

## 1. Run a baseline report

Open [Nyx16 Firmware Research workflow](../.github/workflows/research.yml) from the repository **Actions** tab, click **Run workflow**, and choose branch `main`. Leave `manifest_url` blank.

This produces:
- `soc_research_matrix.csv` with A12–A16 research families
- `firmware_manifest_matrix.csv`, usually header-only until real manifest evidence is supplied
- `secure_boot_evidence.md` with cited Apple security design constraints
- `research_summary.json` and `RESEARCH_SUMMARY.md` with explicit confidence limits

## 2. Analyze a public BuildManifest.plist

Use the same workflow and enter the **public raw GitHub** URL of one `BuildManifest.plist` in `manifest_url`. Supported hosts:
- `https://raw.githubusercontent.com/...`
- `https://gist.githubusercontent.com/...`

This URL must point directly to a plist, **not** a GitHub HTML page and **not** to a full IPSW (multi-GB ZIP). Only the plist is downloaded into the temporary runner, capped at 10 MiB. An encrypted, private, or malformed manifest will fail with an error.

Alternatively commit non-sensitive public plist inputs to `evidence/manifests/`. Every push that changes evidence triggers a new GitHub Actions report automatically.

## 3. Read results

Open the run and inspect the **Summary**. Download the `nyx16-research-reports-N` artifact from its **Artifacts** section. Reports remain available for 21 days.

The records distinguish these states:
- `DECLARED_IN_IDENTITY` — both ProductType and DeviceClass appear inside one BuildIdentity.
- `NOT_ESTABLISHED` — no such explicit pairing is present.
- `NOT_CHECKED` — Apple signing was **not** queried or verified.
- `UNKNOWN` — neither SEP nor baseband firmware compatibility was established.
- `NOT_DEMONSTRATED` — no unsigned downgrade success was observed.

Even a perfect BuildManifest match does **not** establish authorization to install iOS. Per [Apple's secure software updates description](https://support.apple.com/en-ca/guide/security/secf683e0b36/web), restore/update authorization is device-personalized and checks which software versions Apple currently authorizes.

## 4. Reproducibility and safety

Every supplied manifest is SHA256-hashed and enumerated in `research_summary.json`. No signing endpoints are called, no device is contacted, and no firmware is patched or flashed. Evidence documentation is vendor-sourced and is **not** a claim that an exploit exists.

For a clean baseline run with no supplied manifest, **0 real inputs is expected**. That is an honest evidence gap, not a CI failure.
