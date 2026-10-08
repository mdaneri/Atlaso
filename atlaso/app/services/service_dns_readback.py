"""Strict DNS readback for Atlaso-owned service records."""

from __future__ import annotations

import ipaddress
import json
import math
import os
import secrets
import socket
import struct
import subprocess
import sys
from collections import defaultdict

_TYPE_CODES = {"A": 1, "CNAME": 5, "AAAA": 28}


def _name(value: str) -> str:
    """Validate and normalize a DNS name for query construction.

    Args:
        value: DNS name text supplied for validation and normalization.
    """
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
    """Encode a DNS name in wire format.

    Args:
        name: DNS name to encode in wire format.
    """
    return b"".join(bytes((len(label),)) + label.encode("ascii") for label in name.rstrip(".").split(".")) + b"\0"


def _read_name(packet: bytes, offset: int) -> tuple[str, int]:
    """Read and normalize a DNS name from a DNS packet.

    Args:
        packet: DNS packet being parsed.
        offset: Byte offset at which the encoded DNS name begins.
    """
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
    """Parse and validate a DNS response for the requested question.

    Args:
        packet: DNS packet being parsed.
        identifier: Transaction identifier expected in the DNS response.
        qname: Normalized question name expected in the response.
        qtype: DNS record type requested by the query.
        allow_nxdomain: Whether authoritative NXDOMAIN may prove that a previously owned record was removed.
        require_authoritative: Whether the response must carry the authoritative-answer flag.
    """
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
    """Normalize desired DNS records for comparison.

    Args:
        records: Desired DNS records used for the readback check.
    """
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
    """Send one DNS query and parse its validated response.

    Args:
        nameserver: IP address of the DNS server to query.
        port: UDP port of the DNS server.
        timeout: Per-query timeout in seconds.
        hostname: Hostname whose DNS records are being verified.
        record_type: DNS record type being checked.
        allow_nxdomain: Whether authoritative NXDOMAIN may prove that a previously owned record was removed.
        require_authoritative: Whether the response must carry the authoritative-answer flag.
    """
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
    """Verify that positive DNS answers match the desired records.

    Args:
        expected: Normalized desired DNS data keyed by owner and record type.
        hostname: Hostname whose DNS records are being verified.
        record_type: DNS record type being checked.
        answer: Parsed DNS answer records keyed by owner and record type.
    """
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
    """Verify that retired CNAME owners no longer resolve to stale addresses.

    Args:
        hostname: Hostname whose DNS records are being verified.
        expected: Normalized desired DNS data keyed by owner and record type.
        nameserver: IP address of the DNS server to query.
        port: UDP port of the DNS server.
        timeout: Per-query timeout in seconds.
        require_authoritative: Whether the response must carry the authoritative-answer flag.
    """
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
    """Verify that prior owned DNS records have been retired.

    Args:
        previous: Previously owned DNS records that must be retired.
        expected: Normalized desired DNS data keyed by owner and record type.
        nameserver: IP address of the DNS server to query.
        port: UDP port of the DNS server.
        timeout: Per-query timeout in seconds.
        require_authoritative: Whether the response must carry the authoritative-answer flag.
    """
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
    """Verify desired service records and prove prior owned records were retired.

    Args:
        records: Desired DNS records used for the readback check.
        nameserver: IP address of the DNS server to query.
        port: UDP port of the DNS server.
        timeout: Per-query timeout in seconds.
        prior_records: Previously owned DNS records whose removal must be verified.
        require_authoritative: Whether the response must carry the authoritative-answer flag.
    """
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


def _nss_addresses(hostname: str, timeout: float, *, allow_missing: bool = False) -> set[str]:
    """Return NSS host addresses, optionally accepting a proven missing name.

    Args:
        hostname: Normalized DNS name sent to ``getent``.
        timeout: Maximum seconds allowed for the bounded lookup.
        allow_missing: Accept only the ``getent`` not-found status with no output.

    Raises:
        ValueError: The lookup failed, returned malformed data, or could not run.
    """
    try:
        result = subprocess.run(
            ["getent", "hosts", hostname.rstrip(".")],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except FileNotFoundError as exc:
        raise ValueError("Appliance NSS lookup tool is unavailable.") from exc
    except subprocess.TimeoutExpired as exc:
        raise ValueError(f"Appliance NSS lookup for {hostname} timed out.") from exc
    except OSError as exc:
        raise ValueError(f"Appliance NSS lookup for {hostname} could not run.") from exc

    if result.returncode != 0:
        if allow_missing and result.returncode == 2 and not result.stdout.strip() and not result.stderr.strip():
            return set()
        detail = "did not resolve" if not allow_missing else "could not verify retired-name absence"
        raise ValueError(f"Appliance NSS lookup for {hostname} {detail}.")
    lines = result.stdout.splitlines()
    if not lines:
        raise ValueError(f"Appliance NSS lookup for {hostname} returned no addresses.")
    resolved: set[str] = set()
    for line in lines:
        fields = line.split()
        if len(fields) < 2:
            raise ValueError(f"Appliance NSS lookup for {hostname} returned malformed data.")
        try:
            resolved.add(str(ipaddress.ip_address(fields[0])))
        except ValueError as exc:
            raise ValueError(f"Appliance NSS lookup for {hostname} returned a malformed address.") from exc
    if not resolved:
        raise ValueError(f"Appliance NSS lookup for {hostname} returned no addresses.")
    return resolved


def _synthetic_hostname_addresses(hostname: str, timeout: float) -> set[str]:
    """Prove a local synthetic answer and bound it to currently assigned addresses.

    Args:
        hostname: Exact current kernel hostname, already matched to a direct owner.
        timeout: Maximum seconds for each read-only native command.

    Raises:
        ValueError: Native synthesis or current local address ownership is unproven.
    """
    environment = {**os.environ, "LC_ALL": "C", "SYSTEMD_COLORS": "0"}
    try:
        synthetic = subprocess.run(
            ["resolvectl", "query", "--cache=no", "--network=no", "--legend=yes", hostname.rstrip(".")],
            capture_output=True, text=True, timeout=timeout, check=False, env=environment,
        )
        if synthetic.returncode != 0:
            raise ValueError("Appliance own-hostname synthesis could not be verified.")
        lines = [line.strip() for line in synthetic.stdout.splitlines() if line.strip()]
        if [line for line in lines if line.startswith("-- Data from:")] != ["-- Data from: synthetic"]:
            raise ValueError("Appliance own-hostname lookup is not proven exclusively synthetic.")
        prefix = hostname.rstrip(".") + ":"
        if not lines or not lines[0].startswith(prefix):
            raise ValueError("Appliance own-hostname synthesis returned a different name.")
        addresses: set[str] = set()
        for index, line in enumerate(lines):
            if line.startswith("--"):
                continue
            value = line.removeprefix(prefix).strip() if index == 0 else line
            # resolvectl prints an optional interface comment after the address.
            value = value.partition("-- link:")[0].strip()
            addresses.add(str(ipaddress.ip_address(value)))
        if not addresses:
            raise ValueError("Appliance own-hostname synthesis returned no addresses.")

        observed = subprocess.run(
            ["ip", "-j", "address", "show"],
            capture_output=True, text=True, timeout=timeout, check=False, env=environment,
        )
        if observed.returncode != 0:
            raise ValueError("Appliance local address ownership could not be verified.")
        interfaces = json.loads(observed.stdout)
        if not isinstance(interfaces, list) or not interfaces:
            raise ValueError("Appliance local address inventory is unavailable.")
        local: set[str] = set()
        for interface in interfaces:
            if not isinstance(interface, dict) or not isinstance(interface.get("addr_info"), list):
                raise ValueError("Appliance local address inventory is malformed.")
            for entry in interface["addr_info"]:
                if not isinstance(entry, dict) or not isinstance(entry.get("local"), str):
                    raise ValueError("Appliance local address inventory is malformed.")
                address = ipaddress.ip_address(entry["local"])
                if not (address.is_unspecified or address.is_multicast or address.is_link_local):
                    local.add(str(address))
        # These are systemd's exact own-hostname fallbacks, not arbitrary loopback.
        fallbacks = {"127.0.0.2", "::1"}
        if not addresses <= local | fallbacks:
            raise ValueError("Appliance own-hostname synthesis contains an unowned address.")
        if _name(socket.gethostname()) != hostname:
            raise ValueError("Appliance kernel hostname changed during synthesis verification.")
        return addresses | fallbacks
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        raise ValueError("Appliance own-hostname synthetic address proof failed.") from exc


def verify_service_dns_nss(
    records: list[dict[str, str]],
    timeout: float = 2.0,
    *,
    prior_records: list[dict[str, str]] | None = None,
) -> None:
    """Verify generated names resolve through the appliance NSS host database.

    Args:
        records: Captured owned A, AAAA, and CNAME records already verified directly.
        timeout: Maximum seconds allowed for each bounded ``getent`` invocation.
        prior_records: Previously owned records whose retired names must no longer resolve.

    Raises:
        ValueError: The captured ownership is ambiguous or NSS resolution is absent,
            malformed, stale, unavailable, or timed out.
    """
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout) or not 0 < timeout <= 30):
        raise ValueError("NSS timeout must be positive and within a bounded range.")
    expected = _expected_records(records)
    previous = _expected_records(prior_records or [])
    allowed_by_name: dict[str, set[str]] = {}
    for hostname in sorted({owner for owner, _record_type in expected}):
        owner_addresses = expected.get((hostname, "A"), set()) | expected.get((hostname, "AAAA"), set())
        aliases = expected.get((hostname, "CNAME"), set())
        if owner_addresses and aliases:
            raise ValueError(f"Captured DNS name {hostname} has conflicting address and CNAME ownership.")
        if owner_addresses:
            allowed_by_name[hostname] = owner_addresses
            continue
        if not aliases:
            raise ValueError(f"Captured DNS name {hostname} has no supported address ownership.")

        visited = {hostname}
        target = hostname
        while True:
            targets = expected.get((target, "CNAME"), set())
            target_addresses = expected.get((target, "A"), set()) | expected.get((target, "AAAA"), set())
            if target_addresses:
                if targets:
                    raise ValueError(f"Captured DNS CNAME target {target} has conflicting address ownership.")
                allowed_by_name[hostname] = target_addresses
                break
            if len(targets) != 1:
                raise ValueError(f"Captured DNS CNAME chain for {hostname} is ambiguous or has an unowned target.")
            target = next(iter(targets))
            if target in visited:
                raise ValueError(f"Captured DNS CNAME chain for {hostname} is cyclic.")
            visited.add(target)

    for hostname, allowed in allowed_by_name.items():
        resolved = _nss_addresses(hostname, timeout)
        if not resolved <= allowed:
            # Only a direct current kernel-name owner can use local synthesis.
            # Aliases, retired names, and non-native hosts retain the strict rule.
            try:
                own_hostname = sys.platform == "linux" and _name(socket.gethostname()) == hostname
            except (OSError, ValueError):
                own_hostname = False
            if (not own_hostname or (hostname, "CNAME") in expected
                    or not resolved <= _synthetic_hostname_addresses(hostname, timeout)):
                raise ValueError(f"Appliance NSS lookup for {hostname} returned an unexpected address.")

    for hostname in sorted({owner for owner, _record_type in previous} - set(allowed_by_name)):
        stale_addresses = _nss_addresses(hostname, timeout, allow_missing=True)
        if stale_addresses:
            raise ValueError(f"Retired appliance NSS name {hostname} still resolves to stale addresses.")
