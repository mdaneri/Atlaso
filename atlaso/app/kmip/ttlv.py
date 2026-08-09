"""Minimal, bounded KMIP 1.4 TTLV codec."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import Iterable


MAX_MESSAGE_BYTES = 1_048_576
MAX_NESTING_DEPTH = 16
MAX_NODE_COUNT = 4096


class TtlvError(ValueError):
    """Raised when TTLV is malformed or exceeds a safety bound."""


class TtlvType(IntEnum):
    """Represent ttlv type.

    Attributes:
        STRUCTURE: Symbolic value representing 1.
        INTEGER: Symbolic value representing 2.
        LONG_INTEGER: Symbolic value representing 3.
        BIG_INTEGER: Symbolic value representing 4.
        ENUMERATION: Symbolic value representing 5.
        BOOLEAN: Symbolic value representing 6.
        TEXT_STRING: Symbolic value representing 7.
        BYTE_STRING: Symbolic value representing 8.
        DATE_TIME: Symbolic value representing 9.
        INTERVAL: Symbolic value representing 10.
    """
    STRUCTURE = 0x01
    INTEGER = 0x02
    LONG_INTEGER = 0x03
    BIG_INTEGER = 0x04
    ENUMERATION = 0x05
    BOOLEAN = 0x06
    TEXT_STRING = 0x07
    BYTE_STRING = 0x08
    DATE_TIME = 0x09
    INTERVAL = 0x0A


@dataclass(frozen=True)
class Ttlv:
    """Represent ttlv.

    Attributes:
        tag: Tag maintained by this ttlv.
        type: Type maintained by this ttlv.
        value: Value maintained by this ttlv.
    """
    tag: int
    type: TtlvType
    value: tuple["Ttlv", ...] | int | bool | str | bytes

    def children(self, tag: int | None = None) -> list["Ttlv"]:
        """Return children.

        Args:
            tag: Tag consumed by children.


        Raises:
            TtlvError: If the operation encounters an invalid state.
        """
        if self.type is not TtlvType.STRUCTURE:
            raise TtlvError("TTLV node is not a structure.")
        values = list(self.value)
        assert all(isinstance(item, Ttlv) for item in values)
        return values if tag is None else [item for item in values if item.tag == tag]

    def child(self, tag: int, *, required: bool = True) -> "Ttlv | None":
        """Return child.

        Args:
            tag: Tag consumed by child.
            required: Whether required applies to the operation.


        Raises:
            TtlvError: If the operation encounters an invalid state.
        """
        matches = self.children(tag)
        if len(matches) > 1:
            raise TtlvError(f"TTLV tag {tag:#08x} must not be duplicated.")
        if not matches:
            if required:
                raise TtlvError(f"TTLV tag {tag:#08x} is required.")
            return None
        return matches[0]


def structure(tag: int, *children: Ttlv) -> Ttlv:
    """Return structure.

    Args:
        tag: Tag consumed by structure.
        *children: Additional positional arguments accepted by the callable.
    """
    return Ttlv(tag, TtlvType.STRUCTURE, tuple(children))


def integer(tag: int, value: int) -> Ttlv:
    """Return integer.

    Args:
        tag: Tag consumed by integer.
        value: Candidate value consumed by integer.
    """
    return Ttlv(tag, TtlvType.INTEGER, value)


def enumeration(tag: int, value: int) -> Ttlv:
    """Return enumeration.

    Args:
        tag: Tag consumed by enumeration.
        value: Candidate value consumed by enumeration.
    """
    return Ttlv(tag, TtlvType.ENUMERATION, value)


def boolean(tag: int, value: bool) -> Ttlv:
    """Return boolean.

    Args:
        tag: Tag consumed by boolean.
        value: Candidate value consumed by boolean.
    """
    return Ttlv(tag, TtlvType.BOOLEAN, value)


def text_string(tag: int, value: str) -> Ttlv:
    """Return text string.

    Args:
        tag: Tag consumed by text string.
        value: Candidate value consumed by text string.
    """
    return Ttlv(tag, TtlvType.TEXT_STRING, value)


def byte_string(tag: int, value: bytes) -> Ttlv:
    """Return byte string.

    Args:
        tag: Tag consumed by byte string.
        value: Candidate value consumed by byte string.
    """
    return Ttlv(tag, TtlvType.BYTE_STRING, value)


def date_time(tag: int, value: int) -> Ttlv:
    """Return date time.

    Args:
        tag: Tag consumed by date time.
        value: Candidate value consumed by date time.
    """
    return Ttlv(tag, TtlvType.DATE_TIME, value)


def _encoded_value(node: Ttlv) -> bytes:
    """Return encoded value.

    Args:
        node: Node consumed by encoded value.


    Raises:
        TtlvError: If the operation encounters an invalid state.
    """
    if node.type is TtlvType.STRUCTURE:
        children = node.value
        if not isinstance(children, tuple) or not all(isinstance(item, Ttlv) for item in children):
            raise TtlvError("TTLV structure value is invalid.")
        return b"".join(encode(item) for item in children)
    if node.type in {TtlvType.INTEGER, TtlvType.ENUMERATION, TtlvType.INTERVAL}:
        if isinstance(node.value, bool) or not isinstance(node.value, int):
            raise TtlvError("TTLV 32-bit value is invalid.")
        return struct.pack(">i", node.value)
    if node.type in {TtlvType.LONG_INTEGER, TtlvType.DATE_TIME}:
        if isinstance(node.value, bool) or not isinstance(node.value, int):
            raise TtlvError("TTLV 64-bit value is invalid.")
        return struct.pack(">q", node.value)
    if node.type is TtlvType.BOOLEAN:
        if not isinstance(node.value, bool):
            raise TtlvError("TTLV boolean value is invalid.")
        return struct.pack(">q", 1 if node.value else 0)
    if node.type is TtlvType.TEXT_STRING:
        if not isinstance(node.value, str):
            raise TtlvError("TTLV text value is invalid.")
        return node.value.encode("utf-8")
    if node.type in {TtlvType.BYTE_STRING, TtlvType.BIG_INTEGER}:
        if not isinstance(node.value, bytes):
            raise TtlvError("TTLV byte value is invalid.")
        return node.value
    raise TtlvError(f"Unsupported TTLV type: {node.type!r}.")


def encode(node: Ttlv) -> bytes:
    """Serialize operation.

    Args:
        node: Node consumed by encode.


    Returns:
        The encode result.

    Raises:
        TtlvError: If the operation encounters an invalid state.
    """
    if node.tag < 0x420000 or node.tag > 0x42FFFF:
        raise TtlvError("Only standard KMIP tags are supported.")
    value = _encoded_value(node)
    if len(value) > MAX_MESSAGE_BYTES:
        raise TtlvError("TTLV value exceeds the maximum size.")
    padding = b"\0" * ((8 - len(value) % 8) % 8)
    header = node.tag.to_bytes(3, "big") + bytes([int(node.type)]) + len(value).to_bytes(4, "big")
    return header + value + padding


@dataclass
class _DecodeState:
    """Represent decode state.

    Attributes:
        nodes: Nodes maintained by this decodestate.
    """
    nodes: int = 0


def _decode_one(
    data: bytes,
    offset: int,
    *,
    depth: int,
    state: _DecodeState,
) -> tuple[Ttlv, int]:
    """Deserialize one.

    Args:
        data: Data consumed by decode one.
        offset: Offset consumed by decode one.
        depth: Depth consumed by decode one.
        state: Current lifecycle state consumed by the operation.


    Returns:
        The decode one result.

    Raises:
        TtlvError: If the operation encounters an invalid state.
    """
    if depth > MAX_NESTING_DEPTH:
        raise TtlvError("TTLV nesting exceeds the maximum depth.")
    if offset + 8 > len(data):
        raise TtlvError("TTLV header is truncated.")
    tag = int.from_bytes(data[offset : offset + 3], "big")
    if tag < 0x420000 or tag > 0x42FFFF:
        raise TtlvError("TTLV contains a non-standard KMIP tag.")
    try:
        data_type = TtlvType(data[offset + 3])
    except ValueError as exc:
        raise TtlvError("TTLV contains an unsupported type.") from exc
    length = int.from_bytes(data[offset + 4 : offset + 8], "big")
    if length > MAX_MESSAGE_BYTES:
        raise TtlvError("TTLV value exceeds the maximum size.")
    padded_length = length + ((8 - length % 8) % 8)
    value_start = offset + 8
    value_end = value_start + length
    next_offset = value_start + padded_length
    if next_offset > len(data):
        raise TtlvError("TTLV value is truncated.")
    if any(data[value_end:next_offset]):
        raise TtlvError("TTLV padding must be zero.")

    state.nodes += 1
    if state.nodes > MAX_NODE_COUNT:
        raise TtlvError("TTLV node count exceeds the maximum.")
    raw = data[value_start:value_end]
    if data_type is TtlvType.STRUCTURE:
        children: list[Ttlv] = []
        child_offset = 0
        while child_offset < len(raw):
            child, child_offset = _decode_one(
                raw,
                child_offset,
                depth=depth + 1,
                state=state,
            )
            children.append(child)
        value: tuple[Ttlv, ...] | int | bool | str | bytes = tuple(children)
    elif data_type in {TtlvType.INTEGER, TtlvType.ENUMERATION, TtlvType.INTERVAL}:
        if length != 4:
            raise TtlvError("TTLV 32-bit type must have length 4.")
        value = struct.unpack(">i", raw)[0]
    elif data_type in {TtlvType.LONG_INTEGER, TtlvType.DATE_TIME}:
        if length != 8:
            raise TtlvError("TTLV 64-bit type must have length 8.")
        value = struct.unpack(">q", raw)[0]
    elif data_type is TtlvType.BOOLEAN:
        if length != 8:
            raise TtlvError("TTLV boolean must have length 8.")
        numeric = struct.unpack(">q", raw)[0]
        if numeric not in {0, 1}:
            raise TtlvError("TTLV boolean must be zero or one.")
        value = bool(numeric)
    elif data_type is TtlvType.TEXT_STRING:
        try:
            value = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise TtlvError("TTLV text string is not valid UTF-8.") from exc
    else:
        value = raw
    return Ttlv(tag, data_type, value), next_offset


def decode(data: bytes) -> Ttlv:
    """Deserialize operation.

    Args:
        data: Data consumed by decode.


    Returns:
        The decode result.

    Raises:
        TtlvError: If the operation encounters an invalid state.
    """
    if not data:
        raise TtlvError("TTLV message is empty.")
    if len(data) > MAX_MESSAGE_BYTES + 8:
        raise TtlvError("TTLV message exceeds the maximum size.")
    node, offset = _decode_one(data, 0, depth=0, state=_DecodeState())
    if offset != len(data):
        raise TtlvError("TTLV message contains trailing data.")
    return node


def assert_only_tags(node: Ttlv, allowed: Iterable[int]) -> None:
    """Check only tags.

    Args:
        node: Node consumed by assert only tags.
        allowed: Allowed consumed by assert only tags.


    Raises:
        TtlvError: If the operation encounters an invalid state.
    """
    allowed_set = set(allowed)
    unexpected = sorted({child.tag for child in node.children()} - allowed_set)
    if unexpected:
        rendered = ", ".join(f"{tag:#08x}" for tag in unexpected)
        raise TtlvError(f"TTLV structure contains unsupported tags: {rendered}.")
