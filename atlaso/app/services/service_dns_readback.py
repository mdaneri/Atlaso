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


def _parse_response(
    packet: bytes,
    identifier: int,
    qname: str,
    qtype: int,
    *,
    allow_nxdomain: bool = False,
    require_authoritative: bool = False,
) -> tuple[dict[tuple[str, int], set[str]], int]:
    if len(packet) < 12:
        raise ValueError("DNS response header is truncated.")
    response_id, flags, questions, answers, authorities, additional = struct.unpack_from("!HHHHHH", packet)
    if response_id != identifier:
        raise ValueError("DNS response identifier does not match the query.")
    rcode = flags & 0x000F
    if (not flags & 0x8000 or flags & 0x7800 or flags & 0x0200
            or rcode not in ({0, 3} if allow_nxdomain else {0})):
        raise ValueError("DNS response has invalid flags, is truncated, or reports an error.")
    if require_authoritative and not flags & 0x0400:
        raise ValueError("DNS response is not authoritative.")
    if questions != 1 or answers + authorities + additional > 4096:
        raise ValueError("DNS response must echo one question and a bounded record count.")
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
        if rtype in {1, 5, 28} and rclass != 1:
            raise ValueError("DNS response contains an owned record with an unexpected class.")
        if rclass == 1 and rtype == 1:
            if rdlength != 4:
                raise ValueError("DNS response A record has an invalid length.")
            value = str(ipaddress.IPv4Address(packet[offset:data_end]))
        elif rclass == 1 and rtype == 28:
            if rdlength != 16:
                raise ValueError("DNS response AAAA record has an invalid length.")
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
    return parsed, rcode


def _expected_records(records: list[dict[str, str]]) -> dict[tuple[str, str], set[str]]:
    if not isinstance(records, list) or any(not isinstance(record, dict) for record in records):
        raise ValueError("DNS records must be a list of record objects.")
    expected: dict[tuple[str, str], set[str]] = defaultdict(set)
    for record in records:
        if any(not isinstance(record.get(field), str) for field in ("hostname", "record_type", "address")):
            raise ValueError("DNS record is missing a required string field.")
        hostname = _name(record["hostname"])
        record_type = record["record_type"].upper()
        address = record["address"]
        if record_type not in _TYPE_CODES:
            raise ValueError("DNS readback supports only A, AAAA, and CNAME records.")
        try:
            if record_type == "A":
                value = str(ipaddress.IPv4Address(address))
            elif record_type == "AAAA":
                value = str(ipaddress.IPv6Address(address))
            else:
                value = _name(address)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"DNS {record_type} record value is malformed.") from exc
        expected[(hostname, record_type)].add(value)
    return expected


def _query(
    nameserver: str,
    port: int,
    timeout: float,
    hostname: str,
    record_type: str,
    *,
    allow_nxdomain: bool = False,
    require_authoritative: bool = False,
) -> tuple[dict[tuple[str, int], set[str]], int]:
    identifier = int.from_bytes(secrets.token_bytes(2), "big")
    qtype = _TYPE_CODES[record_type]
    query = struct.pack("!HHHHHH", identifier, 0x0100, 1, 0, 0, 0) + _wire_name(hostname) + struct.pack("!HH", qtype, 1)
    if not isinstance(nameserver, str):
        raise ValueError("DNS nameserver must be an IPv4 or IPv6 address.")
    try:
        server = ipaddress.ip_address(nameserver)
    except (TypeError, ValueError) as exc:
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
    return _parse_response(
        response, identifier, hostname, qtype,
        allow_nxdomain=allow_nxdomain,
        require_authoritative=require_authoritative,
    )


def _verify_positive_answer(
    expected: dict[tuple[str, str], set[str]],
    hostname: str,
    record_type: str,
    answer: dict[tuple[str, int], set[str]],
) -> None:
    qtype = _TYPE_CODES[record_type]
    values = expected[(hostname, record_type)]
    owner = hostname
    if record_type in {"A", "AAAA"}:
        visited: set[str] = set()
        while answer.get((owner, _TYPE_CODES["CNAME"])):
            aliases = answer[(owner, _TYPE_CODES["CNAME"])]
            if owner in visited or len(aliases) != 1:
                raise ValueError(f"DNS CNAME chain for {hostname} is ambiguous or cyclic.")
            target = next(iter(aliases))
            if target in visited or target == owner:
                raise ValueError(f"DNS CNAME chain for {hostname} is cyclic.")
            owned_aliases = expected.get((owner, "CNAME"))
            if owned_aliases is not None and aliases != owned_aliases:
                raise ValueError(f"DNS CNAME chain for {hostname} does not match owned aliases.")
            if answer.get((owner, _TYPE_CODES["A"])) or answer.get((owner, _TYPE_CODES["AAAA"])):
                raise ValueError(f"DNS CNAME chain for {hostname} has conflicting address data.")
            visited.add(owner)
            owner = target
        terminal_expected = expected.get((owner, record_type))
        actual = answer.get((owner, qtype), set())
        if terminal_expected is not None and actual != terminal_expected:
            raise ValueError(f"DNS {record_type} CNAME target readback for {hostname} does not match desired records.")
    else:
        actual = answer.get((hostname, qtype), set())
    if actual != values:
        raise ValueError(f"DNS {record_type} readback for {hostname} does not match desired records.")


def _verify_retired_cname_families(
    hostname: str,
    expected: dict[tuple[str, str], set[str]],
    nameserver: str,
    port: int,
    timeout: float,
    require_authoritative: bool,
) -> None:
    for record_type in ("A", "AAAA"):
        answer, rcode = _query(
            nameserver, port, timeout, hostname, record_type,
            allow_nxdomain=True, require_authoritative=require_authoritative,
        )
        if (hostname, record_type) in expected:
            if answer.get((hostname, _TYPE_CODES["CNAME"])):
                raise ValueError(f"Retired DNS CNAME name {hostname} still aliases its address replacement.")
            actual = answer.get((hostname, _TYPE_CODES[record_type]), set())
            if actual != expected[(hostname, record_type)] or rcode != 0:
                raise ValueError(f"DNS {record_type} replacement for {hostname} does not match its direct address set.")
            continue
        if expected.get((hostname, "CNAME")):
            owner = hostname
            visited: set[str] = set()
            chain_owners: set[str] = set()
            while answer.get((owner, _TYPE_CODES["CNAME"])):
                aliases = answer[(owner, _TYPE_CODES["CNAME"])]
                if aliases != expected.get((owner, "CNAME"), set()) or len(aliases) != 1 or owner in visited:
                    raise ValueError(f"DNS CNAME family chain for {hostname} is unexpected or cyclic.")
                if answer.get((owner, _TYPE_CODES["A"])) or answer.get((owner, _TYPE_CODES["AAAA"])):
                    raise ValueError(f"DNS CNAME family chain for {hostname} has conflicting address data.")
                visited.add(owner)
                chain_owners.add(owner)
                owner = next(iter(aliases))
            if not chain_owners:
                raise ValueError(f"DNS CNAME family readback for {hostname} is missing its replacement alias.")
            terminal_is_owned = any(key[0] == owner for key in expected)
            if terminal_is_owned and answer.get((owner, _TYPE_CODES[record_type]), set()) != expected.get((owner, record_type), set()):
                raise ValueError(f"DNS CNAME family target for {hostname} does not match desired records.")
            if rcode == 3:
                if terminal_is_owned:
                    raise ValueError(f"DNS CNAME family replacement for {hostname} contradicts expected target data.")
                if set(answer) - {(chain_owner, _TYPE_CODES["CNAME"]) for chain_owner in chain_owners}:
                    raise ValueError(f"DNS NXDOMAIN for {hostname} includes contradictory answer data.")
            continue
        if answer.get((hostname, _TYPE_CODES[record_type])) or answer.get((hostname, _TYPE_CODES["CNAME"])):
            raise ValueError(f"Retired DNS CNAME name {hostname} still has {record_type} or alias data.")
        if rcode == 3 and answer:
            raise ValueError(f"DNS NXDOMAIN for retired CNAME name {hostname} includes answer data.")


def _verify_retired_records(
    previous: dict[tuple[str, str], set[str]],
    expected: dict[tuple[str, str], set[str]],
    nameserver: str,
    port: int,
    timeout: float,
    require_authoritative: bool,
) -> None:
    for hostname, record_type in previous:
        if (hostname, record_type) not in expected:
            answer, rcode = _query(
                nameserver, port, timeout, hostname, record_type,
                allow_nxdomain=True, require_authoritative=require_authoritative,
            )
            qtype = _TYPE_CODES[record_type]
            if record_type in {"A", "AAAA"} and expected.get((hostname, "CNAME")):
                aliases = answer.get((hostname, _TYPE_CODES["CNAME"]), set())
                if aliases != expected[(hostname, "CNAME")]:
                    raise ValueError(f"Retired DNS {record_type} for {hostname} has an unexpected CNAME replacement.")
                if answer.get((hostname, qtype)):
                    raise ValueError(f"Retired DNS {record_type} for {hostname} is still present beside its CNAME.")
                owner = hostname
                visited: set[str] = set()
                chain_owners: set[str] = set()
                while answer.get((owner, _TYPE_CODES["CNAME"])):
                    aliases = answer[(owner, _TYPE_CODES["CNAME"])]
                    if aliases != expected.get((owner, "CNAME"), set()) or len(aliases) != 1 or owner in visited:
                        raise ValueError(f"DNS CNAME replacement chain for {hostname} is unexpected or cyclic.")
                    if answer.get((owner, _TYPE_CODES["A"])) or answer.get((owner, _TYPE_CODES["AAAA"])):
                        raise ValueError(f"DNS CNAME replacement chain for {hostname} has conflicting address data.")
                    visited.add(owner)
                    chain_owners.add(owner)
                    owner = next(iter(aliases))
                terminal_is_owned = any(key[0] == owner for key in expected)
                if terminal_is_owned and answer.get((owner, qtype), set()) != expected.get((owner, record_type), set()):
                    raise ValueError(f"DNS CNAME replacement target for {hostname} does not match desired records.")
                if rcode == 3:
                    if terminal_is_owned:
                        raise ValueError(f"DNS CNAME replacement for {hostname} contradicts expected target data.")
                    if set(answer) - {(chain_owner, _TYPE_CODES["CNAME"]) for chain_owner in chain_owners}:
                        raise ValueError(f"DNS NXDOMAIN for {hostname} includes contradictory answer data.")
                continue
            if rcode == 3 and answer:
                raise ValueError(f"DNS NXDOMAIN for retired {record_type} name {hostname} includes answer data.")
            if rcode == 3 and record_type == "CNAME" and any(
                (hostname, address_type) in expected for address_type in ("A", "AAAA")
            ):
                raise ValueError(f"DNS NXDOMAIN for retired CNAME name {hostname} contradicts its address replacement.")
            if rcode == 3 and record_type in {"A", "AAAA"} and any(
                (hostname, other_type) in expected for other_type in ("A", "AAAA")
            ):
                raise ValueError(f"DNS NXDOMAIN for retired {record_type} name {hostname} contradicts its address replacement.")
            if answer.get((hostname, qtype)):
                raise ValueError(f"Retired DNS {record_type} record for {hostname} is still present.")
            if record_type != "CNAME" and answer.get((hostname, _TYPE_CODES["CNAME"])):
                raise ValueError(f"Retired DNS {record_type} name {hostname} still has an alias.")
        if record_type == "CNAME":
            _verify_retired_cname_families(
                hostname, expected, nameserver, port, timeout, require_authoritative,
            )


def verify_service_dns_records(
    records: list[dict[str, str]],
    nameserver: str = "127.0.0.1",
    port: int = 53,
    timeout: float = 2.0,
    *,
    prior_records: list[dict[str, str]] | None = None,
    require_authoritative: bool = False,
) -> None:
    """Verify desired service records and prove prior owned records were retired."""
    if (isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535
            or isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout) or not 0 < timeout <= 30):
        raise ValueError("DNS port and timeout must be positive and within bounded ranges.")
    if not isinstance(require_authoritative, bool):
        raise ValueError("DNS authoritative response requirement must be a boolean.")
    expected = _expected_records(records)
    previous = _expected_records(prior_records or [])
    for (hostname, record_type) in expected:
        answer, _rcode = _query(
            nameserver, port, timeout, hostname, record_type,
            require_authoritative=require_authoritative,
        )
        _verify_positive_answer(expected, hostname, record_type, answer)
    if previous:
        _verify_retired_records(previous, expected, nameserver, port, timeout, require_authoritative)
