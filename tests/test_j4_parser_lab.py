"""J4 harness tests: only in-repository reference parser, no system interfaces."""
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from j4_parser_lab import (
    FrameError, MAX_PAYLOAD, decode_frame, encode_frame, main, run_experiment
)


class J4ParserLabTests(unittest.TestCase):
    def test_roundtrip_all_bounded_lengths(self):
        for n in range(MAX_PAYLOAD + 1):
            payload = bytes([n]) * n
            self.assertEqual(decode_frame(encode_frame(payload)), payload)

    def test_truncated_length_mismatch_and_header_corruption_rejected(self):
        frame = encode_frame(b"nyx16-test")
        candidates = [
            frame[:4], frame[:-1], frame + b"\x00",
            b"BAD!" + frame[4:],
            frame[:4] + b"\x02" + frame[5:],
            frame[:5] + struct.pack(">H", 65535) + frame[7:],
            frame[:-1] + b"\xff",
        ]
        for sample in candidates:
            with self.subTest(size=len(sample)):
                with self.assertRaises(FrameError):
                    decode_frame(sample)

    def test_payload_size_cap(self):
        with self.assertRaises(FrameError):
            encode_frame(bytes(MAX_PAYLOAD + 1))

    def test_non_bytes_input_is_rejected(self):
        for x in (123, None, "abc", bytearray(b"abc")):
            with self.assertRaises(FrameError):
                decode_frame(x)

    def test_reproducible_stats_and_no_false_exploit_claim(self):
        a = run_experiment(seed=1627, cases=1500)
        b = run_experiment(seed=1627, cases=1500)
        self.assertEqual(a, b)
        self.assertEqual(a["cases"], 1500)
        self.assertEqual(a["mutation_accepted_as_valid"] +
                         a["mutation_rejected_as_malformed"], 1500)
        self.assertEqual(a["unexpected_failures"], 0)
        self.assertEqual(a["valid_reference_roundtrip_failures"], 0)
        self.assertFalse(a["external_iOS_parsers_tested"])
        self.assertFalse(a["iPhone_contacted"])
        self.assertFalse(a["jailbreak_demonstrated"])
        self.assertEqual(a["finding"], "NO_UNEXPECTED_FAILURES_OBSERVED")

    def test_case_bounds(self):
        for cases in (0, 10001, -1):
            with self.assertRaises(ValueError):
                run_experiment(cases=cases)
        for seed in (-1, 2**32):
            with self.assertRaises(ValueError):
                run_experiment(seed=seed)

    def test_cli_writes_json_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "evidence.json"
            self.assertEqual(main(["--seed", "16", "--cases", "100",
                                   "--out", str(path)]), 0)
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(data["cases"], 100)
            self.assertEqual(data["unexpected_failures"], 0)
            self.assertEqual(data["target"], "PROJECT_OWNED_NX16_REFERENCE_FORMAT")


if __name__ == "__main__":
    unittest.main()
