"""Strict DNS readback for Atlaso-owned service records."""

from __future__ import annotations

import ipaddress
import math
import secrets
import socket
import struct
from collections import defaultdict

_TYPE_CODES = {"A": 1, "CNAME": 5, "AAAA": 28}


def _name(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("DNS record name must be a non-empty string.")
    labels = value.rstrip(".").split(".")
    if not labels or any(not label for label in labels):
        raise ValueError("DNS record name is malformed.")
    try:
        encoded = [label.encode("idna") for label in labels]
    except UnicodeError as exc:
        raise ValueError("DNS record name is malformed.") from exc
    if any(len(label) > 63 for label in encoded) or sum(map(len, encoded)) + len(encoded) + 1 > 255:
        raise ValueError("DNS record name is too long.")
    return ".".join(label.decode("ascii").lower() for label in encoded) + "."


def _wire_name(name: str) -> bytes:
    return b"".join(bytes((len(label),)) + label.encode("ascii") for label in name.rstrip(".").split(".")) + b"\0"


def _read_name(packet: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    cursor = offset
    end = offset
    jumped = False
    visited: set[int] = set()
    wire_length = 1
    while True:
        if cursor >= len(packet):
            raise ValueError("DNS response contains an out-of-bounds name.")
        length = packet[cursor]
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(packet):
                raise ValueError("DNS response contains a truncated compression pointer.")
            target = ((length & 0x3F) << 8) | packet[cursor + 1]
            if target >= len(packet) or target in visited:
                raise ValueError("DNS response contains an invalid compression pointer.")
            visited.add(target)
            if not jumped:
                end = cursor + 2
                jumped = True
            cursor = target
            continue
        if length & 0xC0:
            raise ValueError("DNS response contains an invalid label encoding.")
        cursor += 1
        if length == 0:
            if not jumped:
                end = cursor
            break
        if length > 63 or cursor + length > len(packet):
            raise ValueError("DNS response contains a malformed label.")
        wire_length += length + 1
        if wire_length > 255:
            raise ValueError("DNS response name is too long.")
        try:
            labels.append(packet[cursor : cursor + length].decode("ascii").lower())
        except UnicodeDecodeError as exc:
            raise ValueError("DNS response name is not ASCII.") from exc
        cursor += length
    return (".".join(labels) + "." if labels else "."), end


def _parse_response(packet: bytes, identifier: int, qname: str, qtype: int) -> dict[tuple[str, int], set[str]]:
    if len(packet) < 12:
        raise ValueError("DNS response header is truncated.")
    response_id, flags, questions, answers, authorities, additional = struct.unpack_from("!HHHHHH", packet)
    if response_id != identifier:
        raise ValueError("DNS response identifier does not match the query.")
    if not flags & 0x8000 or flags & 0x7800 or flags & 0x0200 or flags & 0x000F:
        raise ValueError("DNS response has invalid flags, is truncated, or reports an error.")
    if questions != 1:
        raise ValueError("DNS response must echo exactly one question.")
    response_name, offset = _read_name(packet, 12)
    if offset + 4 > len(packet):
        raise ValueError("DNS response question is truncated.")
    response_type, response_class = struct.unpack_from("!HH", packet, offset)
    offset += 4
    if (response_name, response_type, response_class) != (qname, qtype, 1):
        raise ValueError("DNS response question does not match the query.")
    parsed: dict[tuple[str, int], set[str]] = defaultdict(set)
    for record_index in range(answers + authorities + additional):
        owner, offset = _read_name(packet, offset)
        if offset + 10 > len(packet):
            raise ValueError("DNS response record header is truncated.")
        rtype, rclass, _ttl, rdlength = struct.unpack_from("!HHIH", packet, offset)
        offset += 10
        data_end = offset + rdlength
        if data_end > len(packet):
            raise ValueError("DNS response record data is truncated.")
        value: str | None = None
        if rclass == 1 and rtype == 1 and rdlength == 4:
            value = str(ipaddress.IPv4Address(packet[offset:data_end]))
        elif rclass == 1 and rtype == 28 and rdlength == 16:
            value = str(ipaddress.IPv6Address(packet[offset:data_end]))
        elif rclass == 1 and rtype == 5:
            target, consumed = _read_name(packet, offset)
            if consumed != data_end:
                raise ValueError("DNS response CNAME data has an invalid length.")
            value = target
        if value is not None and record_index < answers:
            parsed[(owner, rtype)].add(value)
        offset = data_end
    if offset != len(packet):
        raise ValueError("DNS response contains trailing data.")
    return parsed


def _expected_records(records: list[dict[str, str]]) -> dict[tuple[str, str], set[str]]:
    expected: dict[tuple[str, str], set[str]] = defaultdict(set)
    for record in records:
        try:
            hostname = _name(record["hostname"])
            record_type = record["record_type"].upper()
            address = record["address"]
        except (KeyError, AttributeError) as exc:
            raise ValueError("DNS record is missing a required string field.") from exc
        if record_type not in _TYPE_CODES:
            raise ValueError("DNS readback supports only A, AAAA, and CNAME records.")
        if record_type == "A":
            value = str(ipaddress.IPv4Address(address))
        elif record_type == "AAAA":
            value = str(ipaddress.IPv6Address(address))
        else:
            value = _name(address)
        expected[(hostname, record_type)].add(value)
    return expected


def _query(nameserver: str, port: int, timeout: float, hostname: str, record_type: str) -> dict[tuple[str, int], set[str]]:
    identifier = int.from_bytes(secrets.token_bytes(2), "big")
    qtype = _TYPE_CODES[record_type]
    query = struct.pack("!HHHHHH", identifier, 0x0100, 1, 0, 0, 0) + _wire_name(hostname) + struct.pack("!HH", qtype, 1)
    try:
        server = ipaddress.ip_address(nameserver)
    except ValueError as exc:
        raise ValueError("DNS nameserver must be an IPv4 or IPv6 address.") from exc
    family = socket.AF_INET6 if server.version == 6 else socket.AF_INET
    destination = (nameserver, port, 0, 0) if family == socket.AF_INET6 else (nameserver, port)
    with socket.socket(family, socket.SOCK_DGRAM) as client:
        client.settimeout(timeout)
        client.sendto(query, destination)
        response, source = client.recvfrom(65535)
    try:
        source_ip = ipaddress.ip_address(source[0].split("%", 1)[0])
    except (ValueError, AttributeError, IndexError) as exc:
        raise ValueError("DNS response source is invalid.") from exc
    if source_ip != server or source[1] != port:
        raise ValueError("DNS response came from an unexpected server.")
    return _parse_response(response, identifier, hostname, qtype)


def verify_service_dns_records(
    records: list[dict[str, str]], nameserver: str = "127.0.0.1", port: int = 53, timeout: float = 2.0
) -> None:
    """Require DNS answers for owned service records to exactly match desired values."""
    if not 1 <= port <= 65535 or not math.isfinite(timeout) or not 0 < timeout <= 30:
        raise ValueError("DNS port and timeout must be positive and within bounded ranges.")
    expected = _expected_records(records)
    for (hostname, record_type), values in expected.items():
        qtype = _TYPE_CODES[record_type]
        answer = _query(nameserver, port, timeout, hostname, record_type)
        if record_type in {"A", "AAAA"}:
            owner = hostname
            visited: set[str] = set()
            while answer.get((owner, _TYPE_CODES["CNAME"])):
                aliases = answer[(owner, _TYPE_CODES["CNAME"])]
                if len(aliases) != 1 or owner in visited:
                    raise ValueError(f"DNS CNAME chain for {hostname} is ambiguous or cyclic.")
                if answer.get((owner, _TYPE_CODES["A"])) or answer.get((owner, _TYPE_CODES["AAAA"])):
                    raise ValueError(f"DNS CNAME chain for {hostname} has conflicting address data.")
                visited.add(owner)
                owner = next(iter(aliases))
                if owner in visited:
                    raise ValueError(f"DNS CNAME chain for {hostname} is cyclic.")
            actual = answer.get((owner, qtype), set())
        else:
            actual = answer.get((hostname, qtype), set())
        if actual != values:
            raise ValueError(f"DNS {record_type} readback for {hostname} does not match desired records.")
