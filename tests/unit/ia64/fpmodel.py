"""Independent IA-64 floating-point register-format model.

This deliberately contains no QEMU imports.  The constants and transforms are
the bit-level rules from the IA-64 register-format definition and are used as
the oracle for generated setf.s/setf.d microprograms.
"""

from __future__ import annotations


INTEGER_EXP = 0x1003E
NATVAL_EXP = 0x1FFFE
SPECIAL_EXP = 0x1FFFF
SIGNIFICAND_INTEGER_BIT = 1 << 63
REGISTER_EXP_MASK = (1 << 17) - 1
REGISTER_SIGN_BIT = 1 << 17
REGISTER_HIGH_MASK = (1 << 18) - 1
UINT64_MASK = (1 << 64) - 1

_BINARY32_FRACTION_BITS = 23
_BINARY32_FRACTION_SHIFT = 40
_BINARY32_EXP_BIAS_DELTA = 0x0FF80
_BINARY64_FRACTION_BITS = 52
_BINARY64_FRACTION_SHIFT = 11
_BINARY64_EXP_BIAS_DELTA = 0x0FC00


def _uint64(value: int, name: str) -> int:
    if not isinstance(value, int) or not 0 <= value <= UINT64_MASK:
        raise ValueError(f"{name} is not a 64-bit unsigned value")
    return value


def setf_sig_is_unnormal(value: int) -> bool:
    """Return whether ``setf.sig`` produces an unnormalized FR value.

    ``setf.sig`` always supplies the integer exponent.  A payload without
    the explicit integer bit is therefore unnormalized.  This includes the
    zero payload: its nonzero exponent makes it a pseudo-zero, not the
    canonical floating-point zero.
    """
    return not bool(_uint64(value, "setf.sig payload") &
                    SIGNIFICAND_INTEGER_BIT)


def fnorm_setf_sig(value: int) -> tuple[int, int]:
    """Model register-precision ``fnorm`` of a ``setf.sig`` payload.

    The operation is the architectural ``fma f1 = f3, f1, f0`` pseudo-op.
    With FR 1 equal to 1.0, this shifts the payload's leading one into the
    explicit integer-bit position and reduces the exponent by the same
    amount.  A pseudo-zero is converted to canonical positive zero.
    """
    value = _uint64(value, "setf.sig payload")
    if value == 0:
        return 0, 0
    shift = 64 - value.bit_length()
    return (value << shift) & UINT64_MASK, INTEGER_EXP - shift


def _split_spill(significand: int, sign_exponent: int) -> tuple[int, int]:
    """Validate and split the architected 82-bit register representation."""
    if not 0 <= significand <= UINT64_MASK:
        raise ValueError("spill significand is not a 64-bit unsigned value")
    if not 0 <= sign_exponent <= REGISTER_HIGH_MASK:
        raise ValueError("spill sign/exponent contains reserved bits")
    return sign_exponent >> 17, sign_exponent & REGISTER_EXP_MASK


def _spill_to_binary(significand: int, sign_exponent: int, *,
                     fraction_bits: int, fraction_shift: int,
                     exponent_bias_delta: int,
                     binary_exponent_max: int) -> int:
    """Convert a canonical single-precision or double-precision FR value."""
    sign, exponent = _split_spill(significand, sign_exponent)
    if sign == 0 and exponent == NATVAL_EXP and significand == 0:
        raise ValueError("NaTVal has no floating-point memory representation")

    sign_result_bit = fraction_bits + binary_exponent_max.bit_length()
    sign_result = sign << sign_result_bit
    if exponent == 0 and significand == 0:
        return sign_result

    discarded_mask = (1 << fraction_shift) - 1
    if significand & discarded_mask:
        raise ValueError("spill significand exceeds the requested precision")
    fraction_mask = (1 << fraction_bits) - 1
    fraction = (significand >> fraction_shift) & fraction_mask
    integer_bit = bool(significand & SIGNIFICAND_INTEGER_BIT)

    if exponent == SPECIAL_EXP and integer_bit:
        return (sign_result | (binary_exponent_max << fraction_bits) |
                fraction)

    minimum_normal_exponent = exponent_bias_delta + 1
    if (exponent == minimum_normal_exponent and not integer_bit and
            fraction != 0):
        return sign_result | fraction

    binary_exponent = exponent - exponent_bias_delta
    if integer_bit and 0 < binary_exponent < binary_exponent_max:
        return sign_result | (binary_exponent << fraction_bits) | fraction

    raise ValueError("spill value is not canonical for the requested precision")


def binary32_to_spill(value: int) -> tuple[int, int]:
    value &= 0xFFFF_FFFF
    sign = value >> 31
    exponent = (value >> 23) & 0xFF
    fraction = value & 0x7F_FFFF
    if exponent == 0:
        if fraction == 0:
            register_exponent = 0
            significand = 0
        else:
            register_exponent = 0x0FF81
            significand = fraction << 40
    elif exponent == 0xFF:
        register_exponent = SPECIAL_EXP
        significand = SIGNIFICAND_INTEGER_BIT | (fraction << 40)
    else:
        register_exponent = 0x0FF80 + exponent
        significand = SIGNIFICAND_INTEGER_BIT | (fraction << 40)
    return significand, register_exponent | (sign * REGISTER_SIGN_BIT)


def binary64_to_spill(value: int) -> tuple[int, int]:
    value &= 0xFFFF_FFFF_FFFF_FFFF
    sign = value >> 63
    exponent = (value >> 52) & 0x7FF
    fraction = value & 0xF_FFFF_FFFF_FFFF
    if exponent == 0:
        if fraction == 0:
            register_exponent = 0
            significand = 0
        else:
            register_exponent = 0x0FC01
            significand = fraction << 11
    elif exponent == 0x7FF:
        register_exponent = SPECIAL_EXP
        significand = SIGNIFICAND_INTEGER_BIT | (fraction << 11)
    else:
        register_exponent = 0x0FC00 + exponent
        significand = SIGNIFICAND_INTEGER_BIT | (fraction << 11)
    return significand, register_exponent | (sign * REGISTER_SIGN_BIT)


def spill_to_binary32(significand: int, sign_exponent: int) -> int:
    """Return the exact IEEE binary32 memory bits for a canonical FR value.

    The conversion is deliberately limited to values created from binary32.
    Other register-format values need architectural rounding before a single
    precision store and are rejected instead of being silently truncated.
    """
    return _spill_to_binary(
        significand, sign_exponent,
        fraction_bits=_BINARY32_FRACTION_BITS,
        fraction_shift=_BINARY32_FRACTION_SHIFT,
        exponent_bias_delta=_BINARY32_EXP_BIAS_DELTA,
        binary_exponent_max=0xFF,
    )


def spill_to_binary64(significand: int, sign_exponent: int) -> int:
    """Return the exact IEEE binary64 memory bits for a canonical FR value.

    The conversion is deliberately limited to values created from binary64.
    Other register-format values need architectural rounding before a double
    precision store and are rejected instead of being silently truncated.
    """
    return _spill_to_binary(
        significand, sign_exponent,
        fraction_bits=_BINARY64_FRACTION_BITS,
        fraction_shift=_BINARY64_FRACTION_SHIFT,
        exponent_bias_delta=_BINARY64_EXP_BIAS_DELTA,
        binary_exponent_max=0x7FF,
    )


def spill_to_bytes(significand: int, sign_exponent: int, *,
                   byteorder: str = "little") -> bytes:
    """Model the 16-byte memory image produced by ``stf.spill``.

    IA-64 stores the 64-bit significand adjacent to an 18-bit sign/exponent
    field.  The remaining 46 bits of the 128-bit spill container are zero.
    """
    _split_spill(significand, sign_exponent)
    if byteorder == "little":
        return (significand.to_bytes(8, "little") +
                sign_exponent.to_bytes(8, "little"))
    if byteorder == "big":
        return (sign_exponent.to_bytes(8, "big") +
                significand.to_bytes(8, "big"))
    raise ValueError("byteorder must be 'little' or 'big'")


def fill_from_bytes(value: bytes | bytearray | memoryview, *,
                    byteorder: str = "little") -> tuple[int, int]:
    """Model ``ldf.fill`` and return ``(significand, sign_exponent)``."""
    try:
        memory = bytes(value)
    except (TypeError, ValueError) as error:
        raise TypeError("fill value must be bytes-like") from error
    if len(memory) != 16:
        raise ValueError("fill value must contain exactly 16 bytes")
    if byteorder == "little":
        significand = int.from_bytes(memory[:8], "little")
        sign_exponent = int.from_bytes(memory[8:], "little")
    elif byteorder == "big":
        sign_exponent = int.from_bytes(memory[:8], "big")
        significand = int.from_bytes(memory[8:], "big")
    else:
        raise ValueError("byteorder must be 'little' or 'big'")
    _split_spill(significand, sign_exponent)
    return significand, sign_exponent


def deterministic_words(width: int, count: int) -> tuple[int, ...]:
    """Return reproducible, non-cryptographic property vectors."""
    if width not in (32, 64):
        raise ValueError("only binary32 and binary64 are modeled")
    mask = (1 << width) - 1
    value = 0x9E37_79B9 if width == 32 else 0x9E37_79B9_7F4A_7C15
    words = []
    for _ in range(count):
        value ^= value << 13
        value ^= value >> 7
        value ^= value << 17
        value &= mask
        words.append(value)
    return tuple(words)


BINARY32_EDGE_VECTORS = (
    0x00000000, 0x80000000, 0x00000001, 0x007FFFFF,
    0x00800000, 0x3F800000, 0x7F7FFFFF, 0x7F800000,
    0xFF800000, 0x7FC00001, 0x7FA12345, 0xFFC54321,
)

BINARY64_EDGE_VECTORS = (
    0x0000000000000000, 0x8000000000000000,
    0x0000000000000001, 0x000FFFFFFFFFFFFF,
    0x0010000000000000, 0x3FF0000000000000,
    0x7FEFFFFFFFFFFFFF, 0x7FF0000000000000,
    0xFFF0000000000000, 0x7FF8000000000001,
    0x7FF0123456789ABC, 0xFFF8FEDCBA987654,
)
