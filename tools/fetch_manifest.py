"""Fetch one public raw BuildManifest.plist into the ephemeral Actions workspace.

This intentionally does not fetch full IPSW archives or perform restore operations.
"""
import argparse
import hashlib
import plistlib
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

LIMIT = 10 * 1024 * 1024
ALLOWED = {"raw.githubusercontent.com", "gist.githubusercontent.com"}


def validate_url(url):
    p = urlparse(url)
    if p.scheme != "https" or p.hostname not in ALLOWED or p.username or p.password or p.port:
        raise ValueError("Only public HTTPS raw.githubusercontent.com or gist.githubusercontent.com URLs allowed")
    return url


def fetch(url, output):
    validate_url(url)
    request = Request(url, headers={"User-Agent": "nyx16-evidence-audit/0.2"})
    with urlopen(request, timeout=25) as response:
        validate_url(response.geturl())
        size = response.headers.get("Content-Length")
        if size and int(size) > LIMIT:
            raise ValueError("Remote manifest exceeds 10 MiB")
        data = response.read(LIMIT + 1)
    if not 0 < len(data) <= LIMIT:
        raise ValueError("Remote manifest empty or exceeds 10 MiB")
    manifest = plistlib.loads(data)
    if not isinstance(manifest, dict) or not isinstance(manifest.get("BuildIdentities"), list):
        raise ValueError("Remote data is not a valid BuildManifest.plist")
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    print("Fetched public plist, bytes:", len(data))
    print("SHA256:", hashlib.sha256(data).hexdigest())


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--url", required=True)
    p.add_argument("--out", required=True)
    args = p.parse_args()
    fetch(args.url, args.out)


if __name__ == "__main__":
    main()
