"""Read a root BuildManifest.plist from an Apple-hosted IPSW via HTTP byte ranges.

Never downloads a full IPSW, executes firmware, contacts signing servers,
accesses a device, or attempts any restore operation.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import plistlib
import re
import zipfile
from collections import OrderedDict
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

APPLE_IPSW_26_1_IPHONE12 = (
    "https://updates.cdn-apple.com/2025FallFCS/fullrestores/"
    "089-14534/0E0908EC-6F7A-4160-B6C7-63038FDBD53F/"
    "iPhone13,2,iPhone13,3_26.1_23B85_Restore.ipsw"
)

PRESETS = {
    "iphone11-ios26.1": {
        "url": (
            "https://updates.cdn-apple.com/2025FallFCS/fullrestores/"
            "089-13850/153DB905-D800-4CFF-80F0-E043747BCDF0/"
            "iPhone12,1_26.1_23B85_Restore.ipsw"
        ),
        "product_type": "iPhone12,1",
        "ios_version": "26.1",
        "build_version": "23B85",
        "chip": "A13",
        "reference": "https://ipsw.me/download/iPhone12%2C1/23B85/",
        "published_ipsw_sha256": "0dc182a5fc747f8a634526c9f11bf10c0d2db2b64f959848e2d0eee6a3cfa084",
    },
    "iphone12-ios26.1": {
        "url": APPLE_IPSW_26_1_IPHONE12,
        "product_type": "iPhone13,2",
        "ios_version": "26.1",
        "build_version": "23B85",
        "chip": "A14",
        "reference": "https://ipsw.me/download/iPhone13%2C2/23B85/",
        "published_ipsw_sha256": "23d19d631c47ccc008bdc28df6d93fdbc7975ceed7afa6c87885438e0a19e5cc",
    },
}
RANGE_BLOCK = 256 * 1024
CACHE_BLOCKS = 8
MAX_TRANSFER = 64 * 1024 * 1024
MAX_SIZE = 50 * 1024 * 1024 * 1024
MAX_MANIFEST = 10 * 1024 * 1024
CONTENT_RANGE = re.compile(r"^bytes (\d+)-(\d+)/(\d+)$")


class RangeError(ValueError):
    """Requested IPSW cannot be safely inspected using bounded byte ranges."""


def validate_url(url: str) -> str:
    parts = urlsplit(url)
    if (parts.scheme != "https" or parts.hostname != "updates.cdn-apple.com"
            or parts.username or parts.password or parts.port
            or parts.query or parts.fragment or not parts.path.lower().endswith(".ipsw")):
        raise RangeError("Only direct HTTPS updates.cdn-apple.com *.ipsw URLs are accepted")
    return url


def http_range(url: str, start: int, end: int) -> tuple[bytes, int]:
    """Only accept HTTP 206 and an exact byte range; never accept a full ZIP body."""
    validate_url(url)
    request = Request(url, headers={
        "Range": f"bytes={start}-{end}",
        "Accept-Encoding": "identity",
        "User-Agent": "Nyx16-ManifestResearch/0.3",
    })
    # urllib may follow redirects. Refuse any redirect away from Apple host.
    # Validate final URL before consuming any body.
    with urlopen(request, timeout=30) as response:
        if urlsplit(response.geturl()).hostname != "updates.cdn-apple.com":
            raise RangeError("IPSW response redirected outside approved Apple CDN host")
        if response.status != 206:
            raise RangeError(
                f"Server returned HTTP {response.status}, not 206 Partial Content. "
                "Refusing full IPSW download."
            )
        if response.headers.get("Content-Encoding", "identity").lower() != "identity":
            raise RangeError("Compressed HTTP transport cannot be used for ZIP byte ranges")
        match = CONTENT_RANGE.fullmatch(response.headers.get("Content-Range", "").strip())
        if not match:
            raise RangeError("Missing or invalid Content-Range header")
        got_start, got_end, total = map(int, match.groups())
        if (got_start, got_end) != (start, end) or not 0 < total <= MAX_SIZE:
            raise RangeError("HTTP Content-Range does not match requested bytes")
        expected = end - start + 1
        body = response.read(expected + 1)
        if len(body) != expected:
            raise RangeError("Remote HTTP Range response has unexpected length")
    return body, total


class RemoteIPSW(io.RawIOBase):
    """Seekable, bounded, block-cached virtual file for Python's zipfile.ZipFile."""

    def __init__(self, url: str, fetcher=None):
        super().__init__()
        self.url = validate_url(url)
        self.fetcher = fetcher or http_range
        self.transferred = 0
        self.requests = 0
        self.cache = OrderedDict()
        self.position = 0
        head, self.size = self._request(0, 0)
        if len(head) != 1:
            raise RangeError("IPSW initial range check failed")

    def _request(self, start: int, end: int) -> tuple[bytes, int]:
        expected = end - start + 1
        if self.requests >= 256 or self.transferred + expected > MAX_TRANSFER:
            raise RangeError("HTTP requests or bytes exceed bounded read budget (64 MiB)")
        content, total = self.fetcher(self.url, start, end)
        if len(content) != expected or not 0 < total <= MAX_SIZE:
            raise RangeError("Invalid range fetch result")
        if hasattr(self, "size") and self.size != total:
            raise RangeError("Remote IPSW file changed during reading")
        self.transferred += len(content)
        self.requests += 1
        return content, total

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self.position

    def seek(self, offset, whence=io.SEEK_SET):
        if whence == io.SEEK_SET:
            position = offset
        elif whence == io.SEEK_CUR:
            position = self.position + offset
        elif whence == io.SEEK_END:
            position = self.size + offset
        else:
            raise ValueError("Invalid seek mode")
        if position < 0 or position > self.size:
            raise RangeError("Requested position outside IPSW file")
        self.position = position
        return self.position

    def read(self, size=-1):
        if self.closed:
            raise ValueError("I/O operation on closed IPSW")
        remaining = self.size - self.position
        size = remaining if size is None or size < 0 else min(size, remaining)
        if size > MAX_TRANSFER:
            raise RangeError("Oversized single ZIP read blocked")
        if size <= 0:
            return b""
        segments = []
        end = self.position + size
        while self.position < end:
            block = self.position // RANGE_BLOCK
            cached = self.cache.get(block)
            if cached is None:
                start = block * RANGE_BLOCK
                last = min(start + RANGE_BLOCK, self.size) - 1
                cached, _ = self._request(start, last)
                self.cache[block] = cached
                if len(self.cache) > CACHE_BLOCKS:
                    self.cache.popitem(last=False)
            else:
                self.cache.move_to_end(block)
            index = self.position % RANGE_BLOCK
            take = min(len(cached) - index, end - self.position)
            segments.append(cached[index:index + take])
            self.position += take
        return b"".join(segments)


def extract_manifest(url: str, *, product_type=None, ios_version=None, build_version=None, fetcher=None):
    """Return (plist bytes, provenance dict), verifying explicitly requested metadata."""
    reader = RemoteIPSW(url, fetcher=fetcher)
    try:
        try:
            with zipfile.ZipFile(reader, "r") as archive:
                candidates = [i for i in archive.infolist() if i.filename == "BuildManifest.plist"]
                if len(candidates) != 1:
                    raise RangeError("Expected exactly one root BuildManifest.plist")
                info = candidates[0]
                if info.is_dir() or not 0 < info.file_size <= MAX_MANIFEST:
                    raise RangeError("Manifest is missing, empty, or larger than 10 MiB")
                with archive.open(info) as stream:
                    data = stream.read(MAX_MANIFEST + 1)
                if len(data) != info.file_size or len(data) > MAX_MANIFEST:
                    raise RangeError("Manifest expanded past its declared or permitted size")
        except (zipfile.BadZipFile, EOFError, RuntimeError, OSError) as exc:
            raise RangeError(f"Could not read remote IPSW ZIP directory: {exc}") from exc
        try:
            manifest = plistlib.loads(data)
        except (ValueError, TypeError, OverflowError, plistlib.InvalidFileException) as exc:
            raise RangeError(f"Invalid BuildManifest.plist: {exc}") from exc
        if not isinstance(manifest, dict) or not isinstance(manifest.get("BuildIdentities"), list):
            raise RangeError("IPSW contains no valid BuildManifest identity list")
        products = manifest.get("SupportedProductTypes", [])
        if product_type and (
            not isinstance(products, list) or product_type.casefold() not in
            [p.casefold() for p in products if isinstance(p, str)]
        ):
            raise RangeError(f"Manifest does not declare target model {product_type}")
        for field, expected in (("ProductVersion", ios_version), ("ProductBuildVersion", build_version)):
            if expected and manifest.get(field) != expected:
                raise RangeError(f"Manifest {field} mismatch: expected {expected}, observed {manifest.get(field)!r}")
        source = {
            "source_kind": "APPLE_CDN_IPSW_HTTP_RANGE",
            "source_url": url,
            "ipsw_size_bytes": reader.size,
            "http_range_requests": reader.requests,
            "http_bytes_transferred": reader.transferred,
            "manifest_sha256": hashlib.sha256(data).hexdigest(),
            "manifest_size_bytes": len(data),
            "ios_version": manifest.get("ProductVersion"),
            "build_version": manifest.get("ProductBuildVersion"),
            "product_type_checked": product_type,
            "full_ipsw_sha256_verified": False,
            "apple_signing_status": "NOT_CHECKED",
            "unsigned_downgrade": "NOT_DEMONSTRATED",
        }
        return data, source
    finally:
        reader.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description="Fetch only BuildManifest.plist from Apple IPSW via HTTP Range")
    parser.add_argument("--preset", choices=["iphone11-ios26.1", "iphone12-ios26.1", "custom-ipsw-url"], required=True)
    parser.add_argument("--url", default="", help="Direct updates.cdn-apple.com .ipsw URL for custom preset")
    parser.add_argument("--out", required=True, help="Path to write BuildManifest.plist")
    parser.add_argument("--metadata-out", required=True, help="Where to write input provenance")
    args = parser.parse_args(argv)
    preset = PRESETS.get(args.preset)
    if args.preset == "custom-ipsw-url" and not args.url:
        parser.error("custom-ipsw-url requires --url")
    if args.preset != "custom-ipsw-url" and args.url:
        parser.error("Do not supply --url when selecting a fixed firmware preset")
    url = preset["url"] if preset else args.url
    data, source = extract_manifest(
        url,
        product_type=preset["product_type"] if preset else None,
        ios_version=preset["ios_version"] if preset else None,
        build_version=preset["build_version"] if preset else None,
    )
    if preset:
        source["preset"] = args.preset
        source["reference"] = preset["reference"]
        source["published_full_ipsw_sha256_not_verified"] = preset["published_ipsw_sha256"]
    path = Path(args.out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    metadata = Path(args.metadata_out)
    metadata.parent.mkdir(parents=True, exist_ok=True)
    metadata.write_text(json.dumps(source, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "manifest_sha256": source["manifest_sha256"],
        "version": source["ios_version"],
        "build": source["build_version"],
        "bytes_transferred": source["http_bytes_transferred"],
        "ipws_full_download": False,
        "downgrade": "NOT_DEMONSTRATED",
    }, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
