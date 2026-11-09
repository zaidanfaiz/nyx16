"""J4: bounded robustness experiments on Nyx16's OWN example binary parser.

No Apple system services, USB/DFU, network, external process, native fuzzing,
exploit payloads, or privileged paths. This is a reproducible research harness
for parser invariants and report generation, not an iOS vulnerability scanner.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import struct
import zlib
from pathlib import Path

MAGIC = b"NX16"
VERSION = 1
MAX_PAYLOAD = 128
HEADER_SIZE = 7
TRAILER_SIZE = 4
MAX_FRAME = HEADER_SIZE + MAX_PAYLOAD + TRAILER_SIZE


class FrameError(ValueError):
    """Expected malformed input, not a security vulnerability."""


def encode_frame(payload: bytes) -> bytes:
    if not isinstance(payload, bytes) or len(payload) > MAX_PAYLOAD:
        raise FrameError("Payload type/size invalid")
    prefix = MAGIC + bytes([VERSION]) + struct.pack(">H", len(payload))
    checksum = struct.pack(">I", zlib.crc32(prefix + payload) & 0xFFFFFFFF)
    return prefix + payload + checksum


def decode_frame(data: bytes) -> bytes:
    """Pure, total-for-bytes reference decoder. No side effects."""
    if not isinstance(data, bytes):
        raise FrameError("Frame must be bytes")
    if len(data) < HEADER_SIZE + TRAILER_SIZE or len(data) > MAX_FRAME:
        raise FrameError("Frame length out of bounds")
    if data[:4] != MAGIC or data[4] != VERSION:
        raise FrameError("Invalid magic or version")
    payload_size = struct.unpack(">H", data[5:7])[0]
    if payload_size > MAX_PAYLOAD:
        raise FrameError("Declared payload too large")
    if len(data) != HEADER_SIZE + payload_size + TRAILER_SIZE:
        raise FrameError("Declared size does not match supplied bytes")
    expected = struct.unpack(">I", data[-4:])[0]
    observed = zlib.crc32(data[:-4]) & 0xFFFFFFFF
    if expected != observed:
        raise FrameError("Checksum mismatch")
    return data[HEADER_SIZE:-TRAILER_SIZE]


def _mutate(raw: bytes, rng: random.Random) -> bytes:
    """Bounded, deterministic alterations of project-owned fixture frames."""
    mode = rng.randrange(6)
    blob = bytearray(raw)
    if mode == 0 and blob:
        blob[rng.randrange(len(blob))] ^= 1 << rng.randrange(8)
    elif mode == 1:
        blob = blob[:rng.randrange(len(blob) + 1)]
    elif mode == 2:
        blob.extend(bytes([rng.randrange(256)]) * rng.randrange(1, 9))
    elif mode == 3 and len(blob) >= 7:
        blob[5:7] = rng.randrange(0, 65536).to_bytes(2, "big")
    elif mode == 4 and blob:
        index = rng.randrange(len(blob))
        blob[index:index] = bytes([rng.randrange(256)])
    elif mode == 5 and blob:
        del blob[rng.randrange(len(blob))]
    return bytes(blob[:MAX_FRAME + 8])


def run_experiment(seed: int = 16, cases: int = 1000) -> dict:
    if not (0 <= seed <= 2**32 - 1):
        raise ValueError("seed must be within unsigned 32-bit range")
    if not (1 <= cases <= 10000):
        raise ValueError("cases must be from 1 to 10000")
    rng = random.Random(seed)
    accepted = rejected = unexpected = roundtrip_failures = 0
    examples = []
    corpus = [b"", b"a", b"nyx16", bytes(range(32)), bytes(range(MAX_PAYLOAD))]
    for i in range(cases):
        payload = corpus[i % len(corpus)]
        valid = encode_frame(payload)
        if decode_frame(valid) != payload:
            roundtrip_failures += 1

        candidate = _mutate(valid, rng)
        try:
            output = decode_frame(candidate)
            accepted += 1
            # If mutated frame was still well-formed, it must reconstruct exactly.
            if encode_frame(output) != candidate:
                unexpected += 1
                examples.append({"case": i, "kind": "ROUNDTRIP_MISMATCH",
                                 "sha256": hashlib.sha256(candidate).hexdigest()})
        except FrameError:
            rejected += 1
        except Exception as exc:
            unexpected += 1
            if len(examples) < 8:
                examples.append({"case": i, "kind": "UNEXPECTED_EXCEPTION",
                                 "exception_type": type(exc).__name__,
                                 "sha256": hashlib.sha256(candidate).hexdigest()})
    return {
        "experiment": "NYX16_J4_OWN_PARSER_ROBUSTNESS",
        "target": "PROJECT_OWNED_NX16_REFERENCE_FORMAT",
        "scope": "OFFLINE_AND_NON_PRIVILEGED",
        "seed": seed,
        "cases": cases,
        "valid_reference_roundtrip_failures": roundtrip_failures,
        "mutation_accepted_as_valid": accepted,
        "mutation_rejected_as_malformed": rejected,
        "unexpected_failures": unexpected,
        "failure_examples": examples[:8],
        "external_iOS_parsers_tested": False,
        "iPhone_contacted": False,
        "kernel_exploit_tested": False,
        "jailbreak_demonstrated": False,
        "finding": "NO_UNEXPECTED_FAILURES_OBSERVED" if not (unexpected or roundtrip_failures)
                   else "INVESTIGATE_LOCAL_PARSER_FAILURE",
        "note": "A successful run validates only this project's reference parser and experiment infrastructure.",
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Nyx16 J4 offline test of owned NX16 sample parser")
    parser.add_argument("--seed", type=int, default=16)
    parser.add_argument("--cases", type=int, default=1000)
    parser.add_argument("--out", type=Path, default=Path("reports/j4_owned_parser.json"))
    args = parser.parse_args(argv)
    try:
        result = run_experiment(seed=args.seed, cases=args.cases)
    except ValueError as exc:
        parser.error(str(exc))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({key: value for key, value in result.items()
                      if key not in ("failure_examples", "note")}, indent=2))
    return 1 if result["unexpected_failures"] or result["valid_reference_roundtrip_failures"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
