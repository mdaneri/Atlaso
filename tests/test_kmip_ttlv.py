from __future__ import annotations

import struct

import pytest

from atlaso.app.kmip.ttlv import (
    TtlvError,
    TtlvType,
    decode,
    encode,
    enumeration,
    integer,
    structure,
    text_string,
)


def test_ttlv_round_trip_preserves_nested_values_and_padding() -> None:
    message = structure(
        0x420078,
        integer(0x42000D, 1),
        text_string(0x420094, "key-1"),
        enumeration(0x42005C, 1),
    )

    encoded = encode(message)
    decoded = decode(encoded)

    assert decoded == message
    assert len(encoded) % 8 == 0


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (b"", "empty"),
        (b"\x42\x00", "truncated"),
        (
            b"\x42\x00\x78\x02\x00\x00\x00\x04" + struct.pack(">i", 1) + b"\x01\x00\x00\x00",
            "padding must be zero",
        ),
        (
            b"\x42\x00\x78\x06\x00\x00\x00\x08" + struct.pack(">q", 2),
            "zero or one",
        ),
        (
            b"\x41\x00\x78\x02\x00\x00\x00\x04" + struct.pack(">i", 1) + b"\0" * 4,
            "non-standard",
        ),
    ],
)
def test_ttlv_decoder_rejects_malformed_input(payload: bytes, message: str) -> None:
    with pytest.raises(TtlvError, match=message):
        decode(payload)


def test_ttlv_encoder_rejects_wrong_value_type() -> None:
    with pytest.raises(TtlvError, match="32-bit"):
        encode(integer(0x42000D, True))


def test_ttlv_node_requires_exactly_one_child() -> None:
    node = structure(
        0x420078,
        integer(0x42000D, 1),
        integer(0x42000D, 1),
    )

    with pytest.raises(TtlvError, match="duplicated"):
        node.child(0x42000D)


def test_unknown_ttlv_type_is_rejected() -> None:
    payload = b"\x42\x00\x78\xff\x00\x00\x00\x00"

    with pytest.raises(TtlvError, match="unsupported type"):
        decode(payload)


def test_ttlv_enum_uses_signed_four_byte_wire_value() -> None:
    encoded = encode(enumeration(0x42005C, 0x18))

    assert encoded[:3] == b"\x42\x00\x5c"
    assert encoded[3] == TtlvType.ENUMERATION
    assert encoded[4:8] == b"\0\0\0\x04"
    assert encoded[8:12] == b"\0\0\0\x18"
