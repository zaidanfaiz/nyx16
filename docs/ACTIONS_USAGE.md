# Run Nyx16 through GitHub Actions

Nyx16 runs entirely on GitHub-hosted runners. You do not need to download IPSWs, install anything on macOS, or connect an iPhone.

## Fastest path: iPhone 11, iOS 26.1

1. Open [Nyx16 Firmware Research](https://github.com/zaidanfaiz/nyx16/actions/workflows/research.yml).
2. Choose **Run workflow**, branch `main`.
3. Keep `firmware_target` set to **iphone11-ios26.1** (default).
4. Leave `ipsw_url` and `manifest_url` empty, then press **Run workflow**.
5. Open the completed run, read **Summary**, and download `nyx16-research-reports-...` from **Artifacts**.

The preset points to a public Apple CDN firmware:
- Model: iPhone 12 (`iPhone13,2`), A14
- iOS version: `26.1`, build `23B85`
- File: `iPhone12,1_26.1_23B85_Restore.ipsw`
- Source reference: https://ipsw.me/download/iPhone12%2C1/23B85/
- Published full-file SHA256: `0dc182a5fc747f8a634526c9f11bf10c0d2db2b64f959848e2d0eee6a3cfa084` (**not verified** by partial download)
- Signing status reported by the catalog: **unsigned**. Nyx16 itself makes **no Apple signing request**.

Nyx16 uses HTTP `Range` requests to read only sections needed for the ZIP central directory and root `BuildManifest.plist`. It requests no more than 64 MiB total and refuses HTTP 200 full-file responses. If Apple stops accepting byte ranges, the workflow **fails clearly rather than downloading the 10.1 GB firmware**.

## Other input modes

| `firmware_target` | What to enter |
| --- | --- |
| `iphone11-ios26.1` | Nothing else; predefined Apple CDN iPhone 11 IPSW (default) |\n| `iphone12-ios26.1` | Nothing else; predefined Apple CDN iPhone 12 IPSW |
| `custom-ipsw-url` | `ipsw_url`: direct HTTPS `updates.cdn-apple.com/*.ipsw` URL |
| `public-manifest-url` | `manifest_url`: raw `BuildManifest.plist` URL on GitHub raw or gist |
| `baseline` | Nothing; no remote firmware input |

Pushes to `main` and pull requests that affect code or evidence also run the iPhone 11 preset as an integration test, so the network-based extraction is tested in GitHub Actions. On manual dispatch, select a different mode to disable this.

## Artifacts and interpretation

Downloadable artifact contains:
- `ipsw_http_source.json`: Apple CDN source, bytes fetched, manifest SHA256, explicit full IPSW hash not verified
- `firmware_manifest_matrix.csv`: declared build identity, board and product metadata
- `soc_research_matrix.csv`: A12–A16 baseline, **not** proven compatibility
- `secure_boot_evidence.md`: cited Apple Secure Boot design constraints
- `research_summary.json`: hashes and manifest inventory
- `RESEARCH_SUMMARY.md`: overview repeated in GitHub Actions Summary

A manifest matching iPhone 12/iOS 26.1 does **not** imply that Apple will authorize a restore. This workflow never tests or bypasses signing, SEP, baseband, Activation Lock, or device Secure Boot. No downgrade is attempted or demonstrated.

## Data and network limits

- TLS URLs restricted to official `updates.cdn-apple.com` for IPSW Range mode.
- Exact HTTP 206 and Content-Range required, transport encoding must be identity.
- 64 MiB maximum total data fetched; 10 MiB maximum extracted manifest size.
- No full IPSW hash validation is possible without processing the entire archive.
- Neither IPSW nor a full archive is saved as an artifact.
- GitHub Actions artifact retention: 21 days.

If the CDNs deny ranges, prefer `public-manifest-url` with a trusted source and report the provenance clearly.
