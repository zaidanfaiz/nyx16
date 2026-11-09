# Optional BuildManifest.plist inputs

Nyx16 GitHub Actions analyzes `*.plist` files in this directory recursively.

**Do not commit complete IPSWs, SHSH blobs, device identifiers, or other sensitive materials.** Prefer using the manual **Run workflow** input (`manifest_url`) with a publicly accessible raw GitHub-hosted BuildManifest.plist file. It is fetched to an ephemeral runner and not committed to the repo.

Every manifest is limited to 10 MiB; at most 64 manifests and 512 BuildIdentities per file. The report records SHA256 of each input. Neither CI nor its report contacts Apple signing endpoints or tries a firmware restore.

A BuildManifest describes firmware metadata. Its presence does not prove that Apple signs that version or that SEP/baseband versions are compatible.
