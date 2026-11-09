"""Read-only BuildManifest analysis. Never communicates with or modifies a device."""
import hashlib
import plistlib
import zipfile
from pathlib import Path

MANIFEST_FILENAME = "BuildManifest.plist"
MAX_MANIFEST_BYTES = 10 * 1024 * 1024

class IPSWError(ValueError):
    """Input IPSW archive or manifest cannot be safely inspected."""

def _string_list(value):
    if not isinstance(value, list):
        return []
    return sorted({v for v in value if isinstance(v, str) and v.strip()})

def _match(expected, known):
    if not expected or not known:
        return "unknown"
    norm = {v.lower() for v in known}
    return "matched" if expected.lower() in norm else "mismatched"

def inspect_ipsw(filename, *, product_type=None, board=None):
    """Inspect root manifest only; return metadata, never a restore recommendation."""
    path = Path(filename)
    if not path.is_file():
        raise IPSWError(f"IPSW file does not exist: {path}")
    try:
        with zipfile.ZipFile(path, "r") as z:
            try:
                entry = z.getinfo(MANIFEST_FILENAME)
            except KeyError as exc:
                raise IPSWError("No root BuildManifest.plist found") from exc
            if entry.is_dir() or entry.file_size < 1 or entry.file_size > MAX_MANIFEST_BYTES:
                raise IPSWError("Manifest is empty or exceeds 10 MiB limit")
            with z.open(entry) as stream:
                raw = stream.read(MAX_MANIFEST_BYTES + 1)
            if len(raw) > MAX_MANIFEST_BYTES:
                raise IPSWError("Manifest exceeds 10 MiB limit")
    except (OSError, zipfile.BadZipFile, RuntimeError, EOFError, zlib_error()) as exc:
        raise IPSWError(f"Unable to read IPSW archive: {exc}") from exc
    try:
        manifest = plistlib.loads(raw)
    except (ValueError, TypeError, OverflowError, plistlib.InvalidFileException) as exc:
        raise IPSWError(f"Invalid BuildManifest.plist: {exc}") from exc
    if not isinstance(manifest, dict):
        raise IPSWError("BuildManifest.plist must contain a dictionary")
    identities = manifest.get("BuildIdentities", [])
    if not isinstance(identities, list):
        raise IPSWError("BuildIdentities is not an array")
    products = _string_list(manifest.get("SupportedProductTypes"))
    boards = _string_list([
        entry.get("Info", {}).get("DeviceClass")
        for entry in identities
        if isinstance(entry, dict) and isinstance(entry.get("Info"), dict)
    ])
    product_match = _match(product_type, products)
    board_match = _match(board, boards)
    if "mismatched" in (product_match, board_match):
        result = "mismatched"
    elif product_match == "matched" and board_match == "matched":
        result = "matched"
    else:
        result = "unknown"
    return {
        "filename": path.name,
        "manifest_sha256": hashlib.sha256(raw).hexdigest(),
        "ios_version": manifest.get("ProductVersion") if isinstance(manifest.get("ProductVersion"), str) else None,
        "build_version": manifest.get("ProductBuildVersion") if isinstance(manifest.get("ProductBuildVersion"), str) else None,
        "supported_product_types": products,
        "board_configurations": boards,
        "build_identity_count": len(identities),
        "requested_product_type": product_type,
        "requested_board": board,
        "product_type_result": product_match,
        "board_result": board_match,
        "metadata_result": result,
        "apple_signing_status": "NOT_CHECKED",
        "downgrade_feasibility": "UNDETERMINED",
        "notice": "Manifest metadata is not proof of signing, SEP/baseband compatibility, or restore feasibility.",
    }

def zlib_error():
    # Import inline to keep the user-facing module dependency-free and explicit.
    import zlib
    return zlib.error
