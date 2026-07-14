#!/usr/bin/env python3
"""Host-only tests for the independent IA-64 FP representation model."""

from __future__ import annotations

import os
import sys
import unittest

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    from ia64.fpmodel import (BINARY32_EDGE_VECTORS,
                              BINARY64_EDGE_VECTORS, INTEGER_EXP,
                              NATVAL_EXP, REGISTER_SIGN_BIT, SPECIAL_EXP,
                              SIGNIFICAND_INTEGER_BIT,
                              binary32_to_spill, binary64_to_spill,
                              deterministic_words, fill_from_bytes,
                              fnorm_setf_sig, setf_sig_is_unnormal,
                              spill_to_binary32, spill_to_binary64,
                              spill_to_bytes)
else:
    from .fpmodel import (BINARY32_EDGE_VECTORS, BINARY64_EDGE_VECTORS,
                          INTEGER_EXP, NATVAL_EXP, REGISTER_SIGN_BIT,
                          SPECIAL_EXP,
                          SIGNIFICAND_INTEGER_BIT, binary32_to_spill,
                          binary64_to_spill, deterministic_words,
                          fill_from_bytes, fnorm_setf_sig,
                          setf_sig_is_unnormal, spill_to_binary32,
                          spill_to_binary64, spill_to_bytes)


BINARY32_KNOWN_SPILLS = {
    0x00000000: (0x0000000000000000, 0x00000),
    0x80000000: (0x0000000000000000, 0x20000),
    0x00000001: (0x0000010000000000, 0x0FF81),
    0x007FFFFF: (0x7FFFFF0000000000, 0x0FF81),
    0x00800000: (0x8000000000000000, 0x0FF81),
    0x3F800000: (0x8000000000000000, 0x0FFFF),
    0x7F7FFFFF: (0xFFFFFF0000000000, 0x1007E),
    0x7F800000: (0x8000000000000000, 0x1FFFF),
    0xFF800000: (0x8000000000000000, 0x3FFFF),
    0x7FC00001: (0xC000010000000000, 0x1FFFF),
    0x7FA12345: (0xA123450000000000, 0x1FFFF),
    0xFFC54321: (0xC543210000000000, 0x3FFFF),
}

BINARY64_KNOWN_SPILLS = {
    0x0000000000000000: (0x0000000000000000, 0x00000),
    0x8000000000000000: (0x0000000000000000, 0x20000),
    0x0000000000000001: (0x0000000000000800, 0x0FC01),
    0x000FFFFFFFFFFFFF: (0x7FFFFFFFFFFFF800, 0x0FC01),
    0x0010000000000000: (0x8000000000000000, 0x0FC01),
    0x3FF0000000000000: (0x8000000000000000, 0x0FFFF),
    0x7FEFFFFFFFFFFFFF: (0xFFFFFFFFFFFFF800, 0x103FE),
    0x7FF0000000000000: (0x8000000000000000, 0x1FFFF),
    0xFFF0000000000000: (0x8000000000000000, 0x3FFFF),
    0x7FF8000000000001: (0xC000000000000800, 0x1FFFF),
    0x7FF0123456789ABC: (0x8091A2B3C4D5E000, 0x1FFFF),
    0xFFF8FEDCBA987654: (0xC7F6E5D4C3B2A000, 0x3FFFF),
}


class FpModelTest(unittest.TestCase):
    def test_fnorm_setf_sig_normalizes_register_format(self) -> None:
        vectors = {
            0: ((0, 0), True),
            1: ((0x8000000000000000, 0x0FFFF), True),
            0x4000000000000895:
                ((0x800000000000112A, 0x1003D), True),
            0x8000000000000895:
                ((0x8000000000000895, INTEGER_EXP), False),
        }
        for value, (normalized, is_unnormal) in vectors.items():
            with self.subTest(value=f"{value:016x}"):
                self.assertEqual(fnorm_setf_sig(value), normalized)
                self.assertEqual(setf_sig_is_unnormal(value), is_unnormal)

        for invalid in (-1, 1 << 64, None):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    fnorm_setf_sig(invalid)  # type: ignore[arg-type]
                with self.assertRaises(ValueError):
                    setf_sig_is_unnormal(invalid)  # type: ignore[arg-type]

    def test_binary32_edge_encodings(self) -> None:
        self.assertEqual(set(BINARY32_EDGE_VECTORS),
                         set(BINARY32_KNOWN_SPILLS))
        for value, expected_spill in BINARY32_KNOWN_SPILLS.items():
            with self.subTest(value=f"{value:08x}"):
                self.assertEqual(binary32_to_spill(value), expected_spill)
                self.assertEqual(spill_to_binary32(*expected_spill), value)

    def test_binary64_edge_encodings(self) -> None:
        self.assertEqual(set(BINARY64_EDGE_VECTORS),
                         set(BINARY64_KNOWN_SPILLS))
        for value, expected_spill in BINARY64_KNOWN_SPILLS.items():
            with self.subTest(value=f"{value:016x}"):
                self.assertEqual(binary64_to_spill(value), expected_spill)
                self.assertEqual(spill_to_binary64(*expected_spill), value)

    def test_binary32_deterministic_round_trip(self) -> None:
        vectors = BINARY32_EDGE_VECTORS + deterministic_words(32, 4096)
        for value in vectors:
            self.assertEqual(
                spill_to_binary32(*binary32_to_spill(value)), value,
                f"binary32 round trip failed for {value:08x}")

    def test_binary64_deterministic_round_trip(self) -> None:
        vectors = BINARY64_EDGE_VECTORS + deterministic_words(64, 4096)
        for value in vectors:
            self.assertEqual(
                spill_to_binary64(*binary64_to_spill(value)), value,
                f"binary64 round trip failed for {value:016x}")

    def test_spill_fill_byte_layout_and_round_trip(self) -> None:
        low = 0x0123456789ABCDEF
        high = 0x23456
        little = bytes.fromhex("efcdab89674523015634020000000000")
        big = bytes.fromhex("00000000000234560123456789abcdef")
        self.assertEqual(spill_to_bytes(low, high), little)
        self.assertEqual(fill_from_bytes(little), (low, high))
        self.assertEqual(spill_to_bytes(low, high, byteorder="big"), big)
        self.assertEqual(fill_from_bytes(big, byteorder="big"), (low, high))

        pairs = (
            (0, 0),
            (SIGNIFICAND_INTEGER_BIT, 0x0FFFF),
            (0xFEDCBA9876543210, INTEGER_EXP),
            (0, NATVAL_EXP),
            (0x8000000000000001, SPECIAL_EXP | REGISTER_SIGN_BIT),
        )
        for pair in pairs:
            for byteorder in ("little", "big"):
                with self.subTest(pair=pair, byteorder=byteorder):
                    memory = spill_to_bytes(*pair, byteorder=byteorder)
                    self.assertEqual(
                        fill_from_bytes(memory, byteorder=byteorder), pair)

    def test_spill_fill_deterministic_round_trip(self) -> None:
        pairs = tuple(binary32_to_spill(value) for value in
                      deterministic_words(32, 512))
        pairs += tuple(binary64_to_spill(value) for value in
                       deterministic_words(64, 512))
        for pair in pairs:
            for byteorder in ("little", "big"):
                self.assertEqual(
                    fill_from_bytes(
                        spill_to_bytes(*pair, byteorder=byteorder),
                        byteorder=byteorder),
                    pair)

    def test_noncanonical_binary_values_are_rejected(self) -> None:
        invalid32 = (
            (0, NATVAL_EXP),
            (0, 0x0FF81),
            (SIGNIFICAND_INTEGER_BIT | 1, 0x0FFFF),
            (SIGNIFICAND_INTEGER_BIT, 0x0FC01),
        )
        invalid64 = (
            (0, NATVAL_EXP),
            (0, 0x0FC01),
            (SIGNIFICAND_INTEGER_BIT | 1, 0x0FFFF),
            (SIGNIFICAND_INTEGER_BIT, 0x0FBFF),
        )
        for pair in invalid32:
            with self.subTest(precision=32, pair=pair):
                with self.assertRaises(ValueError):
                    spill_to_binary32(*pair)
        for pair in invalid64:
            with self.subTest(precision=64, pair=pair):
                with self.assertRaises(ValueError):
                    spill_to_binary64(*pair)

    def test_invalid_spill_container_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            spill_to_bytes(-1, 0)
        with self.assertRaises(ValueError):
            spill_to_bytes(0, 1 << 18)
        with self.assertRaisesRegex(ValueError, "exactly 16 bytes"):
            fill_from_bytes(bytes(15))

        reserved_little = bytearray(16)
        reserved_little[11] = 1
        with self.assertRaisesRegex(ValueError, "reserved bits"):
            fill_from_bytes(reserved_little)
        reserved_big = bytearray(16)
        reserved_big[0] = 1
        with self.assertRaisesRegex(ValueError, "reserved bits"):
            fill_from_bytes(reserved_big, byteorder="big")

        with self.assertRaisesRegex(ValueError, "byteorder"):
            spill_to_bytes(0, 0, byteorder="native")
        with self.assertRaisesRegex(ValueError, "byteorder"):
            fill_from_bytes(bytes(16), byteorder="native")


if __name__ == "__main__":
    unittest.main()
