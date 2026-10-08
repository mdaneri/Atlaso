"""Tests for strict service DNS readback."""

from __future__ import annotations

import ipaddress
import json
import struct
from types import SimpleNamespace

import pytest

from atlaso.app.services import service_dns_readback as dns_readback


def _wire_name(name: str) -> bytes:
    """Encode a DNS name in wire format.

    Args:
        name: DNS name to encode in wire format.
    """
    return b"".join(bytes((len(label),)) + label.encode("ascii") for label in name.rstrip(".").split(".")) + b"\0"


def _question_end(packet: bytes) -> int:
    """Return the byte offset immediately after a DNS question.

    Args:
        packet: DNS packet being parsed.
    """
    offset = 12
    while packet[offset]:
        offset += packet[offset] + 1
    return offset + 5


def _rr(owner: bytes, rtype: int, data: bytes, ttl: int = 60) -> bytes:
    """Encode a DNS resource record for a response packet.

    Args:
        owner: DNS owner name encoded in the resource record.
        rtype: DNS resource-record type.
        data: Raw resource-record data bytes.
        ttl: Resource-record time to live in seconds.
    """
    return owner + struct.pack("!HHIH", rtype, 1, ttl, len(data)) + data


def _response(query: bytes, answers: list[bytes], *, flags: int = 0x8180, extra: bytes = b"") -> bytes:
    """Build a DNS response packet for the supplied query and answers.

    Args:
        query: DNS query packet sent by the code under test.
        answers: Encoded answer resource records included in the response.
        flags: DNS response flags used to model authoritative and error states.
        extra: Additional encoded response records appended after the answers.
    """
    identifier = struct.unpack_from("!H", query)[0]
    question = query[12:_question_end(query)]
    return (
        struct.pack("!HHHHHH", identifier, flags, 1, len(answers), 0, 1 if extra else 0)
        + question
        + b"".join(answers)
        + extra
    )


class _Socket:
    def __init__(self, responder, source=("127.0.0.1", 53), family=None):
        """Initialize the mock socket with its response callback and source address.

        Args:
            responder: Callback that returns a DNS packet for the received query.
            source: Source address reported for the mocked DNS response.
            family: Socket address family represented by the mock.
        """
        self.responder = responder
        self.source = source
        self.family = family
        self.destination = None
        self.query = b""

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        """Close the mock socket after its context manager exits.

        Args:
            *_args: Positional arguments accepted by the wrapped operation.
        """
        return None

    def settimeout(self, _timeout):
        """Accept the timeout configured by the DNS client.

        Args:
            _timeout: Socket timeout set by the code under test.
        """
        pass

    def sendto(self, query, destination):
        """Capture a DNS query sent to the mocked nameserver.

        Args:
            query: DNS query packet sent by the code under test.
            destination: Nameserver address and port targeted by the query.
        """
        self.query = query
        self.destination = destination

    def recvfrom(self, _size):
        """Return a DNS response from the mocked nameserver.

        Args:
            _size: Maximum response size requested by the code under test.
        """
        return self.responder(self.query), self.source


def _mock_socket(monkeypatch, responder, source=("127.0.0.1", 53)):
    """Replace UDP socket creation with a controlled DNS responder.

    Args:
        monkeypatch: Pytest fixture for replacing dependencies with controlled test doubles.
        responder: Callback that returns a DNS packet for the received query.
        source: Source address reported for the mocked DNS response.
    """
    clients = []

    def create(family, _kind):
        """Create the mock socket used by the DNS client.

        Args:
            family: Socket address family represented by the mock.
            _kind: Socket type supplied by the code under test.
        """
        client = _Socket(responder, source, family)
        clients.append(client)
        return client

    monkeypatch.setattr(dns_readback.socket, "socket", create)
    return clients


def _query_parts(query: bytes) -> tuple[str, int]:
    """Decode the DNS question fields from a query packet.

    Args:
        query: DNS query packet sent by the code under test.
    """
    offset = 12
    labels = []
    while query[offset]:
        length = query[offset]
        labels.append(query[offset + 1 : offset + 1 + length].decode("ascii"))
        offset += length + 1
    return ".".join(labels).lower() + ".", struct.unpack_from("!H", query, offset + 1)[0]


def test_reads_back_a_aaaa_and_cname_with_compressed_owners_and_ignores_unrelated_rr(monkeypatch):
    """Verify A, AAAA, and CNAME answers are read correctly while unrelated records are ignored.

    Args:
        monkeypatch: Pytest fixture for replacing dependencies with controlled test doubles.
    """
    def responder(query):
        """Build a DNS response packet for the query received by the mock socket.

        Args:
            query: DNS query packet sent by the code under test.
        """
        hostname, qtype = _query_parts(query)
        if qtype == 1:
            answer = _rr(b"\xc0\x0c", 1, ipaddress.IPv4Address("192.0.2.10").packed)
        elif qtype == 28:
            answer = _rr(b"\xc0\x0c", 28, ipaddress.IPv6Address("2001:db8::10").packed)
        else:
            answer = _rr(b"\xc0\x0c", 5, _wire_name("target.example.internal."))
        unrelated = _rr(_wire_name("elsewhere.example.internal."), 16, b"\x03txt")
        return _response(query, [answer], extra=unrelated)

    _mock_socket(monkeypatch, responder)
    records = [
        {"hostname": "node.example.internal", "record_type": "A", "address": "192.0.2.10"},
        {"hostname": "node.example.internal.", "record_type": "AAAA", "address": "2001:db8::10"},
        {"hostname": "alias.example.internal", "record_type": "CNAME", "address": "target.example.internal"},
    ]
    dns_readback.verify_service_dns_records(records)


def test_follows_response_cname_chain_for_address_readback(monkeypatch):
    """Verify address readback follows the response CNAME chain.

    Args:
        monkeypatch: Pytest fixture for replacing dependencies with controlled test doubles.
    """
    def responder(query):
        """Build a DNS response packet for the query received by the mock socket.

        Args:
            query: DNS query packet sent by the code under test.
        """
        alias = _rr(b"\xc0\x0c", 5, _wire_name("target.example.internal."))
        target = _rr(_wire_name("target.example.internal."), 1, ipaddress.IPv4Address("192.0.2.20").packed)
        return _response(query, [alias, target])

    _mock_socket(monkeypatch, responder)
    dns_readback.verify_service_dns_records(
        [{"hostname": "alias.example.internal", "record_type": "A", "address": "192.0.2.20"}]
    )


def test_rejects_stale_old_ip_address(monkeypatch):
    """Verify a stale prior address fails DNS readback.

    Args:
        monkeypatch: Pytest fixture for replacing dependencies with controlled test doubles.
    """
    _mock_socket(
        monkeypatch,
        lambda query: _response(
            query, [_rr(b"\xc0\x0c", 1, ipaddress.IPv4Address("192.0.2.1").packed)]
        ),
    )
    with pytest.raises(ValueError, match="does not match"):
        dns_readback.verify_service_dns_records(
            [{"hostname": "node.example.internal", "record_type": "A", "address": "192.0.2.2"}]
        )


@pytest.mark.parametrize(
    "response, message",
    [
        (b"\x00", "header is truncated"),
        (None, "identifier does not match"),
        ("truncated", "is truncated"),
        ("error", "reports an error"),
    ],
)
def test_rejects_malformed_or_untrustworthy_response(monkeypatch, response, message):
    """Verify malformed and untrustworthy DNS responses are rejected.

    Args:
        monkeypatch: Pytest fixture for replacing dependencies with controlled test doubles.
        response: DNS response bytes or parsed response under test.
        message: Expected diagnostic text from the rejected response or operation.
    """
    def responder(query):
        """Build a DNS response packet for the query received by the mock socket.

        Args:
            query: DNS query packet sent by the code under test.
        """
        if response == "truncated":
            return _response(query, [], flags=0x8380)
        if response == "error":
            return _response(query, [], flags=0x8183)
        if response is None:
            packet = bytearray(_response(query, []))
            packet[0] ^= 1
            return bytes(packet)
        return response

    _mock_socket(monkeypatch, responder)
    with pytest.raises(ValueError, match=message):
        dns_readback.verify_service_dns_records(
            [{"hostname": "node.example.internal", "record_type": "A", "address": "192.0.2.2"}]
        )


def test_rejects_cyclic_cname_chain(monkeypatch):
    """Verify a cyclic CNAME chain is rejected.

    Args:
        monkeypatch: Pytest fixture for replacing dependencies with controlled test doubles.
    """
    _mock_socket(monkeypatch, lambda query: _response(query, [_rr(b"\xc0\x0c", 5, b"\xc0\x0c")]))
    with pytest.raises(ValueError, match="cyclic"):
        dns_readback.verify_service_dns_records(
            [{"hostname": "node.example.internal", "record_type": "A", "address": "192.0.2.2"}]
        )

@pytest.mark.parametrize("flags", [0x8580, 0x8583])
def test_retired_record_accepts_nodata_or_authoritative_nxdomain(monkeypatch, flags):
    """Verify NODATA or authoritative NXDOMAIN proves a retired record is absent.

    Args:
        monkeypatch: Pytest fixture for replacing dependencies with controlled test doubles.
        flags: DNS response flags used to model authoritative and error states.
    """
    _mock_socket(monkeypatch, lambda query: _response(query, [], flags=flags))

    dns_readback.verify_service_dns_records(
        [], prior_records=[{"hostname": "retired.example.internal", "record_type": "A", "address": "192.0.2.8"}],
        require_authoritative=True,
    )


@pytest.mark.parametrize("flags, message", [(0x8183, "not authoritative"), (0x8182, "reports an error")])
def test_retired_record_rejects_non_authoritative_or_server_failure(monkeypatch, flags, message):
    """Verify non-authoritative absence and server failures do not prove retirement.

    Args:
        monkeypatch: Pytest fixture for replacing dependencies with controlled test doubles.
        flags: DNS response flags used to model authoritative and error states.
        message: Expected diagnostic text from the rejected response or operation.
    """
    _mock_socket(monkeypatch, lambda query: _response(query, [], flags=flags))

    with pytest.raises(ValueError, match=message):
        dns_readback.verify_service_dns_records(
            [], prior_records=[{"hostname": "retired.example.internal", "record_type": "A", "address": "192.0.2.8"}],
            require_authoritative=True,
        )


def test_retired_record_queries_explicit_ipv6_nameserver_and_port(monkeypatch):
    """Verify retired-record checks use the configured IPv6 nameserver and port.

    Args:
        monkeypatch: Pytest fixture for replacing dependencies with controlled test doubles.
    """
    clients = _mock_socket(
        monkeypatch, lambda query: _response(query, [], flags=0x8580), source=("::1", 5353, 0, 0),
    )

    dns_readback.verify_service_dns_records(
        [], nameserver="::1", port=5353,
        prior_records=[{"hostname": "retired.example.internal", "record_type": "AAAA", "address": "2001:db8::8"}],
        require_authoritative=True,
    )

    assert clients[0].family == dns_readback.socket.AF_INET6
    assert clients[0].destination == ("::1", 5353, 0, 0)


@pytest.mark.parametrize(
    "record_type, qtype, target_address",
    [("A", 1, "192.0.2.30"), ("AAAA", 28, "2001:db8::30")],
)
def test_retired_address_accepts_exact_owned_cname_and_family_target(monkeypatch, record_type, qtype, target_address):
    """Verify retirement accepts the exact owned CNAME and family target.

    Args:
        monkeypatch: Pytest fixture for replacing dependencies with controlled test doubles.
        record_type: DNS record type being checked.
        qtype: DNS record type requested by the query.
        target_address: Expected address at the terminal target of the owned CNAME.
    """
    target_type = 1 if record_type == "A" else 28
    packed = ipaddress.ip_address(target_address).packed

    def responder(query):
        """Build a DNS response packet for the query received by the mock socket.

        Args:
            query: DNS query packet sent by the code under test.
        """
        hostname, requested_type = _query_parts(query)
        alias = _rr(b"\xc0\x0c", 5, _wire_name("target.example.internal."))
        target = _rr(_wire_name("target.example.internal."), target_type, packed)
        if hostname == "alias.example.internal." and requested_type == 5:
            answers = [alias]
        elif hostname == "alias.example.internal." and requested_type == qtype:
            answers = [alias, target]
        else:
            answers = [target]
        return _response(query, answers)

    _mock_socket(monkeypatch, responder)
    dns_readback.verify_service_dns_records(
        [
            {"hostname": "alias.example.internal", "record_type": "CNAME", "address": "target.example.internal"},
            {"hostname": "target.example.internal", "record_type": record_type, "address": target_address},
        ],
        prior_records=[{"hostname": "alias.example.internal", "record_type": record_type,
                        "address": "192.0.2.8" if record_type == "A" else "2001:db8::8"}],
    )


def test_retired_address_rejects_other_family_data_beside_replacement_cname(monkeypatch):
    """Verify conflicting other-family data beside a replacement CNAME is rejected.

    Args:
        monkeypatch: Pytest fixture for replacing dependencies with controlled test doubles.
    """
    alias = _rr(b"\xc0\x0c", 5, _wire_name("target.example.internal."))
    target = _rr(_wire_name("target.example.internal."), 1, ipaddress.IPv4Address("192.0.2.30").packed)
    stale_v6 = _rr(b"\xc0\x0c", 28, ipaddress.IPv6Address("2001:db8::8").packed)

    def responder(query):
        """Build a DNS response packet for the query received by the mock socket.

        Args:
            query: DNS query packet sent by the code under test.
        """
        hostname, requested_type = _query_parts(query)
        if hostname == "alias.example.internal." and requested_type == 5:
            return _response(query, [alias])
        if hostname == "target.example.internal." and requested_type == 1:
            return _response(query, [target])
        if hostname == "alias.example.internal." and requested_type == 1:
            return _response(query, [alias, target, stale_v6])
        return _response(query, [alias, target])

    _mock_socket(monkeypatch, responder)
    with pytest.raises(ValueError, match="CNAME replacement chain.*conflicting address data"):
        dns_readback.verify_service_dns_records(
            [
                {"hostname": "alias.example.internal", "record_type": "CNAME", "address": "target.example.internal"},
                {"hostname": "target.example.internal", "record_type": "A", "address": "192.0.2.30"},
            ],
            prior_records=[{"hostname": "alias.example.internal", "record_type": "A", "address": "192.0.2.8"}],
        )


def test_retired_family_rejects_stale_answer_at_an_owner_that_still_exists(monkeypatch):
    """Verify a stale answer is rejected while its owner still exists.

    Args:
        monkeypatch: Pytest fixture for replacing dependencies with controlled test doubles.
    """
    old = _rr(b"\xc0\x0c", 1, ipaddress.IPv4Address("192.0.2.8").packed)
    new = _rr(b"\xc0\x0c", 28, ipaddress.IPv6Address("2001:db8::9").packed)

    def responder(query):
        """Build a DNS response packet for the query received by the mock socket.

        Args:
            query: DNS query packet sent by the code under test.
        """
        _hostname, qtype = _query_parts(query)
        return _response(query, [new] if qtype == 28 else [old])

    _mock_socket(monkeypatch, responder)
    with pytest.raises(ValueError, match="Retired DNS A record.*still present"):
        dns_readback.verify_service_dns_records(
            [{"hostname": "node.example.internal", "record_type": "AAAA", "address": "2001:db8::9"}],
            prior_records=[{"hostname": "node.example.internal", "record_type": "A", "address": "192.0.2.8"}],
        )


def test_retired_cname_rejects_stale_alias_when_owner_has_direct_address(monkeypatch):
    """Verify a stale CNAME alias is rejected when its owner has a direct address.

    Args:
        monkeypatch: Pytest fixture for replacing dependencies with controlled test doubles.
    """
    direct = _rr(b"\xc0\x0c", 1, ipaddress.IPv4Address("192.0.2.9").packed)
    stale_alias = _rr(b"\xc0\x0c", 5, _wire_name("old-target.example.internal."))

    def responder(query):
        """Build a DNS response packet for the query received by the mock socket.

        Args:
            query: DNS query packet sent by the code under test.
        """
        _hostname, qtype = _query_parts(query)
        return _response(query, [direct] if qtype == 1 else [stale_alias])

    _mock_socket(monkeypatch, responder)
    with pytest.raises(ValueError, match="Retired DNS CNAME record.*still present"):
        dns_readback.verify_service_dns_records(
            [{"hostname": "alias.example.internal", "record_type": "A", "address": "192.0.2.9"}],
            prior_records=[{"hostname": "alias.example.internal", "record_type": "CNAME",
                            "address": "old-target.example.internal"}],
        )


@pytest.mark.parametrize(
    "answer, message",
    [
        (_rr(b"\xc0\x0c", 1, b"\xc0\x00\x01"), "A record has an invalid length"),
        (b"\xc0\x0c" + struct.pack("!HHIH", 1, 3, 60, 4) + ipaddress.IPv4Address("192.0.2.8").packed,
         "unexpected class"),
    ],
)
def test_rejects_malformed_old_address_rr_in_negative_readback(monkeypatch, answer, message):
    """Verify malformed prior-address records are rejected during negative readback.

    Args:
        monkeypatch: Pytest fixture for replacing dependencies with controlled test doubles.
        answer: Encoded malformed resource record included in the response.
        message: Expected diagnostic text from the rejected response or operation.
    """
    _mock_socket(monkeypatch, lambda query: _response(query, [answer]))
    with pytest.raises(ValueError, match=message):
        dns_readback.verify_service_dns_records(
            [], prior_records=[{"hostname": "retired.example.internal", "record_type": "A", "address": "192.0.2.8"}],
        )


def test_rejects_nxdomain_response_that_contains_answer_data(monkeypatch):
    """Verify NXDOMAIN responses containing answer records are rejected.

    Args:
        monkeypatch: Pytest fixture for replacing dependencies with controlled test doubles.
    """
    old = _rr(b"\xc0\x0c", 1, ipaddress.IPv4Address("192.0.2.8").packed)
    _mock_socket(monkeypatch, lambda query: _response(query, [old], flags=0x8583))

    with pytest.raises(ValueError, match="NXDOMAIN.*answer data"):
        dns_readback.verify_service_dns_records(
            [], prior_records=[{"hostname": "retired.example.internal", "record_type": "A", "address": "192.0.2.8"}],
            require_authoritative=True,
        )


def test_authoritative_requirement_applies_to_positive_answers(monkeypatch):
    """Verify positive answers must be authoritative when the caller requires it.

    Args:
        monkeypatch: Pytest fixture for replacing dependencies with controlled test doubles.
    """
    answer = _rr(b"\xc0\x0c", 1, ipaddress.IPv4Address("192.0.2.8").packed)
    _mock_socket(monkeypatch, lambda query: _response(query, [answer], flags=0x8180))

    with pytest.raises(ValueError, match="not authoritative"):
        dns_readback.verify_service_dns_records(
            [{"hostname": "node.example.internal", "record_type": "A", "address": "192.0.2.8"}],
            require_authoritative=True,
        )



@pytest.mark.parametrize("stale_alias", [False, True])
def test_retired_cname_owner_checks_address_families_after_cname_nodata(monkeypatch, stale_alias):
    """Verify both address families are checked after CNAME NODATA.

    Args:
        monkeypatch: Pytest fixture for replacing dependencies with controlled test doubles.
        stale_alias: Previously owned CNAME alias expected to be retired.
    """
    address = "192.0.2.9"
    direct = _rr(b"\xc0\x0c", 1, ipaddress.IPv4Address(address).packed)
    alias = _rr(b"\xc0\x0c", 5, _wire_name("target.example.internal."))
    target = _rr(_wire_name("target.example.internal."), 1, ipaddress.IPv4Address(address).packed)

    def responder(query):
        """Build a DNS response packet for the query received by the mock socket.

        Args:
            query: DNS query packet sent by the code under test.
        """
        hostname, qtype = _query_parts(query)
        if qtype == 5:
            return _response(query, [])
        if qtype == 1:
            return _response(query, [alias, target] if stale_alias else [direct])
        return _response(query, [])

    _mock_socket(monkeypatch, responder)
    current = ([{"hostname": "alias.example.internal", "record_type": "A", "address": address}]
               if stale_alias else [])
    with pytest.raises(ValueError, match="Retired DNS CNAME name.*aliases|still has A or alias"):
        dns_readback.verify_service_dns_records(
            current,
            prior_records=[{"hostname": "alias.example.internal", "record_type": "CNAME",
                            "address": "old-target.example.internal"}],
        )


@pytest.mark.parametrize("prior_type, replacement_type, old_address, new_address", [
    ("A", "AAAA", "192.0.2.8", "2001:db8::9"),
    ("CNAME", "A", "old-target.example.internal", "192.0.2.9"),
])
def test_nxdomain_cannot_contradict_a_different_type_replacement(
    monkeypatch, prior_type, replacement_type, old_address, new_address,
):
    """Verify NXDOMAIN cannot contradict a replacement record of another type.

    Args:
        monkeypatch: Pytest fixture for replacing dependencies with controlled test doubles.
        prior_type: Record type owned before the replacement.
        replacement_type: Record type present after the replacement.
        old_address: Listener address being replaced in the configuration.
        new_address: Proven address to write into the listener configuration.
    """
    def responder(query):
        """Build a DNS response packet for the query received by the mock socket.

        Args:
            query: DNS query packet sent by the code under test.
        """
        _hostname, qtype = _query_parts(query)
        if prior_type == "A" and qtype == 28 or prior_type == "CNAME" and qtype == 1:
            new_rr = _rr(b"\xc0\x0c", 28 if replacement_type == "AAAA" else 1,
                         ipaddress.ip_address(new_address).packed)
            return _response(query, [new_rr])
        return _response(query, [], flags=0x8183)

    _mock_socket(monkeypatch, responder)
    with pytest.raises(ValueError, match="NXDOMAIN.*contradicts"):
        dns_readback.verify_service_dns_records(
            [{"hostname": "node.example.internal", "record_type": replacement_type, "address": new_address}],
            prior_records=[{"hostname": "node.example.internal", "record_type": prior_type, "address": old_address}],
        )


@pytest.mark.parametrize("flags, succeeds", [(0x8180, True), (0x8183, False)])
def test_cname_family_query_is_nxdomain_only_when_terminal_target_is_unowned(monkeypatch, flags, succeeds):
    """Verify CNAME-family NXDOMAIN is accepted only for an unowned terminal target.

    Args:
        monkeypatch: Pytest fixture for replacing dependencies with controlled test doubles.
        flags: DNS response flags used to model authoritative and error states.
        succeeds: Whether DNS readback should accept the modeled response.
    """
    alias = _rr(b"\xc0\x0c", 5, _wire_name("target.example.internal."))
    target_a = _rr(_wire_name("target.example.internal."), 1, ipaddress.IPv4Address("192.0.2.30").packed)

    def responder(query):
        """Build a DNS response packet for the query received by the mock socket.

        Args:
            query: DNS query packet sent by the code under test.
        """
        hostname, qtype = _query_parts(query)
        if hostname == "alias.example.internal." and qtype == 5:
            return _response(query, [alias])
        if hostname == "target.example.internal." and qtype == 1:
            return _response(query, [target_a])
        if hostname == "alias.example.internal." and qtype == 1:
            return _response(query, [alias, target_a], flags=flags)
        return _response(query, [alias], flags=flags)

    _mock_socket(monkeypatch, responder)
    records = [
        {"hostname": "alias.example.internal", "record_type": "CNAME", "address": "target.example.internal"},
        {"hostname": "target.example.internal", "record_type": "A", "address": "192.0.2.30"},
    ]
    if succeeds:
        dns_readback.verify_service_dns_records(
            records, prior_records=[{"hostname": "alias.example.internal", "record_type": "CNAME",
                                    "address": "old-target.example.internal"}],
        )
    else:
        with pytest.raises(ValueError, match="contradicts expected target data"):
            dns_readback.verify_service_dns_records(
                records, prior_records=[{"hostname": "alias.example.internal", "record_type": "CNAME",
                                        "address": "old-target.example.internal"}],
            )


def test_nss_readback_checks_direct_and_cname_names_against_captured_addresses(monkeypatch):
    """Verify local name-service readback checks direct and CNAME names against captured addresses.

    Args:
        monkeypatch: Pytest fixture for replacing dependencies with controlled test doubles.
    """
    outputs = {
        "node.example.internal": "192.0.2.10 node.example.internal\n",
        "dual.example.internal": "2001:db8::10 dual.example.internal\n",
        "alias.example.internal": "192.0.2.10 node.example.internal alias.example.internal\n",
    }
    calls = []

    def run(args, **kwargs):
        """Return the controlled result for the command under test.

        Args:
            args: Argument list passed to the mocked getent command.
            **kwargs: Keyword arguments forwarded to the wrapped operation.
        """
        calls.append((args, kwargs))
        return SimpleNamespace(returncode=0, stdout=outputs[args[2]], stderr="")

    monkeypatch.setattr(dns_readback.subprocess, "run", run)
    dns_readback.verify_service_dns_nss([
        {"hostname": "node.example.internal", "record_type": "A", "address": "192.0.2.10"},
        {"hostname": "dual.example.internal", "record_type": "A", "address": "192.0.2.20"},
        {"hostname": "dual.example.internal", "record_type": "AAAA", "address": "2001:db8::10"},
        {"hostname": "alias.example.internal", "record_type": "CNAME", "address": "node.example.internal"},
    ], timeout=1.5)

    assert [call[0] for call in calls] == [
        ["getent", "hosts", "alias.example.internal"],
        ["getent", "hosts", "dual.example.internal"],
        ["getent", "hosts", "node.example.internal"],
    ]
    assert all(call[1] == {"capture_output": True, "text": True, "timeout": 1.5, "check": False}
               for call in calls)


def test_nss_readback_accepts_absence_for_retired_owned_names(monkeypatch):
    """Verify retired direct and alias names are queried and may be absent.

    Args:
        monkeypatch: Pytest fixture for replacing dependencies with controlled test doubles.
    """
    results = {
        "current.example.internal": SimpleNamespace(
            returncode=0, stdout="192.0.2.20 current.example.internal\n", stderr="",
        ),
        "retired.example.internal": SimpleNamespace(returncode=2, stdout="", stderr=""),
        "old-alias.example.internal": SimpleNamespace(returncode=2, stdout="", stderr=""),
    }
    calls = []

    def run(args, **kwargs):
        """Return the controlled getent response.

        Args:
            args: Argument list passed to the mocked getent command.
            **kwargs: Keyword arguments forwarded to the wrapped operation.
        """
        calls.append((args, kwargs))
        return results[args[2]]

    monkeypatch.setattr(dns_readback.subprocess, "run", run)
    dns_readback.verify_service_dns_nss(
        [{"hostname": "current.example.internal", "record_type": "A", "address": "192.0.2.20"}],
        prior_records=[
            {"hostname": "retired.example.internal", "record_type": "A", "address": "192.0.2.10"},
            {"hostname": "old-alias.example.internal", "record_type": "CNAME", "address": "current.example.internal"},
        ],
    )
    assert [call[0] for call in calls] == [
        ["getent", "hosts", "current.example.internal"],
        ["getent", "hosts", "old-alias.example.internal"],
        ["getent", "hosts", "retired.example.internal"],
    ]


@pytest.mark.parametrize(
    "prior_records",
    [
        [{"hostname": "retired.example.internal", "record_type": "A", "address": "192.0.2.10"}],
        [{"hostname": "retired.example.internal", "record_type": "CNAME", "address": "old-target.example.internal"}],
    ],
    ids=["direct-name", "retired-alias"],
)
def test_nss_readback_rejects_retired_owned_names_that_still_resolve(monkeypatch, prior_records):
    """Reject stale addresses returned for a previously owned retired name.

    Args:
        monkeypatch: Pytest fixture for replacing dependencies with controlled test doubles.
        prior_records: Previously owned records whose owner has been retired.
    """
    monkeypatch.setattr(
        dns_readback.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0, stdout="192.0.2.10 retired.example.internal\n", stderr="",
        ),
    )
    with pytest.raises(ValueError, match="Retired appliance NSS name.*still resolves"):
        dns_readback.verify_service_dns_nss([], prior_records=prior_records)


@pytest.mark.parametrize(
    "result",
    [
        SimpleNamespace(returncode=2, stdout="192.0.2.10 retired.example.internal\n", stderr=""),
        SimpleNamespace(returncode=2, stdout="", stderr="lookup backend failure"),
        SimpleNamespace(returncode=1, stdout="", stderr="lookup backend failure"),
    ],
)
def test_nss_readback_does_not_treat_retired_lookup_errors_as_absence(monkeypatch, result):
    """Only a clean getent not-found result proves an owner is absent.

    Args:
        monkeypatch: Pytest fixture for replacing dependencies with controlled test doubles.
        result: Resolver result returned by the mocked command.
    """
    monkeypatch.setattr(dns_readback.subprocess, "run", lambda *_args, **_kwargs: result)
    with pytest.raises(ValueError, match="could not verify retired-name absence"):
        dns_readback.verify_service_dns_nss(
            [],
            prior_records=[{"hostname": "retired.example.internal", "record_type": "A", "address": "192.0.2.10"}],
        )


@pytest.mark.parametrize("stale", [False, True], ids=["replacement", "stale-replacement"])
def test_nss_readback_checks_replaced_cname_alias_against_new_addresses(monkeypatch, stale):
    """A formerly owned alias may resolve only to its captured replacement chain.

    Args:
        monkeypatch: Pytest fixture for replacing dependencies with controlled test doubles.
        stale: Whether getent returns the retired alias address.
    """
    alias_address = "192.0.2.10" if stale else "192.0.2.20"
    outputs = {
        "alias.example.internal": SimpleNamespace(
            returncode=0, stdout=f"{alias_address} alias.example.internal\n", stderr="",
        ),
        "target.example.internal": SimpleNamespace(
            returncode=0, stdout="192.0.2.20 target.example.internal\n", stderr="",
        ),
    }
    monkeypatch.setattr(dns_readback.subprocess, "run", lambda args, **_kwargs: outputs[args[2]])
    records = [
        {"hostname": "alias.example.internal", "record_type": "CNAME", "address": "target.example.internal"},
        {"hostname": "target.example.internal", "record_type": "A", "address": "192.0.2.20"},
    ]
    prior = [{"hostname": "alias.example.internal", "record_type": "CNAME", "address": "old-target.example.internal"}]
    if stale:
        with pytest.raises(ValueError, match="unexpected address"):
            dns_readback.verify_service_dns_nss(records, prior_records=prior)
    else:
        dns_readback.verify_service_dns_nss(records, prior_records=prior)


@pytest.mark.parametrize(
    "result, message",
    [
        (SimpleNamespace(returncode=0, stdout="", stderr=""), "returned no addresses"),
        (SimpleNamespace(returncode=2, stdout="192.0.2.10 node.example.internal", stderr="not found"), "did not resolve"),
        (SimpleNamespace(returncode=0, stdout="192.0.2.99 node.example.internal\n", stderr=""), "unexpected address"),
        (SimpleNamespace(returncode=0, stdout="not-an-ip node.example.internal\n", stderr=""), "malformed address"),
        (SimpleNamespace(returncode=0, stdout="192.0.2.10\n", stderr=""), "malformed data"),
    ],
)
def test_nss_readback_rejects_missing_stale_and_malformed_results(monkeypatch, result, message):
    """Verify missing, stale, and malformed local name-service results are rejected.

    Args:
        monkeypatch: Pytest fixture for replacing dependencies with controlled test doubles.
        result: Resolver result returned by the mocked command.
        message: Expected diagnostic text from the rejected response or operation.
    """
    monkeypatch.setattr(dns_readback.subprocess, "run", lambda *_args, **_kwargs: result)
    with pytest.raises(ValueError, match=message):
        dns_readback.verify_service_dns_nss([
            {"hostname": "node.example.internal", "record_type": "A", "address": "192.0.2.10"},
        ])


@pytest.mark.parametrize("failure, message", [("timeout", "timed out"), ("missing", "tool is unavailable")])
def test_nss_readback_rejects_timeout_and_missing_getent(monkeypatch, failure, message):
    """Verify local name-service readback rejects timeouts and missing getent.

    Args:
        monkeypatch: Pytest fixture for replacing dependencies with controlled test doubles.
        failure: Resolver failure injected into the test.
        message: Expected diagnostic text from the rejected response or operation.
    """
    def run(*_args, **_kwargs):
        """Return the controlled result for the command under test.

        Args:
            *_args: Positional arguments accepted by the wrapped operation.
            **_kwargs: Keyword arguments accepted by the wrapped operation.
        """
        if failure == "timeout":
            raise dns_readback.subprocess.TimeoutExpired(["getent"], 2.0)
        raise FileNotFoundError("getent")

    monkeypatch.setattr(dns_readback.subprocess, "run", run)
    with pytest.raises(ValueError, match=message):
        dns_readback.verify_service_dns_nss([
            {"hostname": "node.example.internal", "record_type": "A", "address": "192.0.2.10"},
        ])


@pytest.mark.parametrize(
    "records, message",
    [
        ([
            {"hostname": "alias.example.internal", "record_type": "CNAME", "address": "one.example.internal"},
            {"hostname": "alias.example.internal", "record_type": "CNAME", "address": "two.example.internal"},
        ], "ambiguous or has an unowned target"),
        ([
            {"hostname": "alias.example.internal", "record_type": "CNAME", "address": "loop.example.internal"},
            {"hostname": "loop.example.internal", "record_type": "CNAME", "address": "alias.example.internal"},
        ], "cyclic"),
        ([
            {"hostname": "alias.example.internal", "record_type": "CNAME", "address": "external.example.net"},
        ], "ambiguous or has an unowned target"),
    ],
)
def test_nss_readback_fails_closed_for_ambiguous_or_uncaptured_cname_targets(monkeypatch, records, message):
    """Verify ambiguous or uncaptured CNAME targets fail local name-service readback.

    Args:
        monkeypatch: Pytest fixture for replacing dependencies with controlled test doubles.
        records: Desired DNS records used for the readback check.
        message: Expected diagnostic text from the rejected response or operation.
    """
    def unexpected_run(*_args, **_kwargs):
        """Fail the test if the unexpected resolver command is invoked.

        Args:
            *_args: Positional arguments accepted by the wrapped operation.
            **_kwargs: Keyword arguments accepted by the wrapped operation.
        """
        pytest.fail("NSS must not be queried when the captured CNAME chain is untrusted.")

    monkeypatch.setattr(dns_readback.subprocess, "run", unexpected_run)
    with pytest.raises(ValueError, match=message):
        dns_readback.verify_service_dns_nss(records)


@pytest.mark.parametrize("timeout", [0, -1, True, float("inf"), "2"])
def test_nss_readback_validates_bounded_timeout(monkeypatch, timeout):
    """Verify local name-service readback enforces a bounded timeout.

    Args:
        monkeypatch: Pytest fixture for replacing dependencies with controlled test doubles.
        timeout: Per-query timeout in seconds.
    """
    monkeypatch.setattr(dns_readback.subprocess, "run", lambda *_args, **_kwargs: pytest.fail("unexpected NSS call"))
    with pytest.raises(ValueError, match="timeout"):
        dns_readback.verify_service_dns_nss(
            [{"hostname": "node.example.internal", "record_type": "A", "address": "192.0.2.10"}],
            timeout=timeout,
        )


_KERNEL_HOSTNAME = "appliance.example.internal"
_LOCAL_ADDRESSES = ("192.0.2.10", "2001:db8::10")
_SYNTHETIC_QUERY = (
    f"{_KERNEL_HOSTNAME}: {_LOCAL_ADDRESSES[0]} -- link: mgmt0\n"
    f"                          {_LOCAL_ADDRESSES[1]} -- link: access0\n"
    "\n-- Information acquired via protocol DNS in 0.1ms.\n"
    "-- Data is authenticated: yes; Data was acquired via local or encrypted transport: yes\n"
    "-- Data from: synthetic\n"
)
_IP_JSON = json.dumps([{
    "ifname": "mgmt0",
    "addr_info": [
        {"family": "inet", "local": _LOCAL_ADDRESSES[0]},
        {"family": "inet6", "local": _LOCAL_ADDRESSES[1]},
    ],
}])
_IPV4_ONLY_JSON = json.dumps([{
    "ifname": "mgmt0",
    "addr_info": [{"family": "inet", "local": _LOCAL_ADDRESSES[0]}],
}])
_IPV6_ONLY_JSON = json.dumps([{
    "ifname": "access0",
    "addr_info": [{"family": "inet6", "local": _LOCAL_ADDRESSES[1]}],
}])


def _install_own_hostname_commands(monkeypatch, *, getent_output="::1 appliance.example.internal\n",
                                   resolvectl_output=_SYNTHETIC_QUERY, ip_output=_IP_JSON,
                                   platform="linux", hostname=_KERNEL_HOSTNAME, failures=None):
    """Install controlled NSS, resolver, and local-address commands for hostname proof tests.

    Args:
        monkeypatch: Pytest fixture used to replace native command and platform dependencies.
        getent_output: Output returned by the controlled getent invocation.
        resolvectl_output: Output returned by the controlled resolvectl invocation.
        ip_output: JSON output returned by the controlled ip invocation.
        platform: Platform value used by the NSS proof guard.
        hostname: Kernel hostname returned by the socket module.
        failures: Optional command-to-exception or command-to-exit-code mapping.
    """
    calls = []
    failures = failures or {}

    def run(args, **kwargs):
        """Return controlled native command output and retain invocation details.

        Args:
            args: Argument vector passed to subprocess.run.
            **kwargs: Keyword arguments passed to subprocess.run.
        """
        calls.append((list(args), kwargs))
        command = args[0]
        failure = failures.get(command)
        if isinstance(failure, BaseException):
            raise failure
        if failure is not None:
            return SimpleNamespace(returncode=failure, stdout="", stderr="failed")
        if command == "getent":
            return SimpleNamespace(returncode=0, stdout=getent_output, stderr="")
        if command == "resolvectl":
            return SimpleNamespace(returncode=0, stdout=resolvectl_output, stderr="")
        if command == "ip":
            return SimpleNamespace(returncode=0, stdout=ip_output, stderr="")
        pytest.fail(f"Unexpected native command: {command}")

    monkeypatch.setattr(dns_readback.subprocess, "run", run)
    monkeypatch.setattr(dns_readback, "sys", SimpleNamespace(platform=platform))
    monkeypatch.setattr(dns_readback.socket, "gethostname", lambda: hostname)
    return calls


def _own_hostname_records():
    """Return direct DNS address records for the current kernel hostname."""
    return [
        {"hostname": _KERNEL_HOSTNAME, "record_type": "A", "address": _LOCAL_ADDRESSES[0]},
        {"hostname": _KERNEL_HOSTNAME, "record_type": "AAAA", "address": _LOCAL_ADDRESSES[1]},
    ]


@pytest.mark.parametrize(
    "fallback, observed_json, resolver_output",
    [
        (
            "::1", _IPV4_ONLY_JSON,
            f"{_KERNEL_HOSTNAME}: {_LOCAL_ADDRESSES[0]} -- link: mgmt0\n"
            "                          ::1 -- link: lo\n\n"
            "-- Information acquired via protocol DNS in 0.1ms.\n"
            "-- Data from: synthetic\n",
        ),
        (
            "127.0.0.2", _IPV6_ONLY_JSON,
            f"{_KERNEL_HOSTNAME}: 127.0.0.2 -- link: lo\n"
            f"                          {_LOCAL_ADDRESSES[1]} -- link: access0\n\n"
            "-- Information acquired via protocol DNS in 0.1ms.\n"
            "-- Data from: synthetic\n",
        ),
    ],
    ids=["ipv6-loopback-fallback", "ipv4-loopback-fallback"],
)
def test_nss_readback_accepts_only_proven_synthetic_fallback_for_direct_kernel_hostname(
    monkeypatch, fallback, observed_json, resolver_output,
):
    """Allow exact own-hostname family fallback after resolver and address proofs succeed.

    Args:
        monkeypatch: Pytest fixture used to replace native host commands.
        fallback: The family-specific loopback fallback returned by NSS.
        observed_json: Local interface inventory for the non-fallback address family.
        resolver_output: System resolver output containing local addresses and synthetic provenance.
    """
    calls = _install_own_hostname_commands(
        monkeypatch,
        getent_output=f"{fallback} {_KERNEL_HOSTNAME}\n",
        resolvectl_output=resolver_output,
        ip_output=observed_json,
    )

    dns_readback.verify_service_dns_nss(_own_hostname_records())

    assert [call[0] for call in calls] == [
        ["getent", "hosts", _KERNEL_HOSTNAME],
        ["resolvectl", "query", "--cache=no", "--network=no", "--legend=yes", _KERNEL_HOSTNAME],
        ["ip", "-j", "address", "show"],
    ]
    assert calls[0][1] == {"capture_output": True, "text": True, "timeout": 2.0, "check": False}
    for _args, kwargs in calls[1:]:
        assert kwargs["capture_output"] is True
        assert kwargs["text"] is True
        assert kwargs["timeout"] == 2.0
        assert kwargs["check"] is False
        assert kwargs["env"]["LC_ALL"] == "C"
        assert kwargs["env"]["SYSTEMD_COLORS"] == "0"


@pytest.mark.parametrize("address", _LOCAL_ADDRESSES, ids=["management-ipv4", "access-ipv6"])
def test_nss_readback_keeps_actual_local_addresses_on_the_strict_path(monkeypatch, address):
    """Accept captured local IPv4/IPv6 addresses without invoking synthetic proof.

    Args:
        monkeypatch: Pytest fixture used to replace native host commands.
        address: Captured local management or access address returned by NSS.
    """
    calls = _install_own_hostname_commands(
        monkeypatch, getent_output=f"{address} {_KERNEL_HOSTNAME}\n",
    )

    dns_readback.verify_service_dns_nss(_own_hostname_records())

    assert [call[0] for call in calls] == [["getent", "hosts", _KERNEL_HOSTNAME]]


@pytest.mark.parametrize("address", ["2001:db8::10", "2001:db8::99", "127.0.0.9"])
def test_nss_readback_bounds_unpublished_nss_addresses_to_synthetic_evidence(monkeypatch, address):
    """Admit a synthetic access address while rejecting stale and arbitrary loopback answers.

    Args:
        monkeypatch: Replace native commands with local synthesis evidence.
        address: NSS address absent from the captured management-only DNS record.
    """
    calls = _install_own_hostname_commands(monkeypatch, getent_output=f"{address} {_KERNEL_HOSTNAME}\n")
    records = [{"hostname": _KERNEL_HOSTNAME, "record_type": "A", "address": _LOCAL_ADDRESSES[0]}]
    if address == "2001:db8::10":
        dns_readback.verify_service_dns_nss(records)
        assert [call[0][0] for call in calls] == ["getent", "resolvectl", "ip"]
    else:
        with pytest.raises(ValueError, match="unexpected address"):
            dns_readback.verify_service_dns_nss(records)


def test_nss_readback_rejects_synthetic_result_when_kernel_name_is_a_cname_owner(monkeypatch):
    """The kernel-name exception requires direct address ownership, not an alias.

    Args:
        monkeypatch: Replace native lookup and current kernel hostname.
    """
    calls = _install_own_hostname_commands(monkeypatch)
    records = [
        {"hostname": _KERNEL_HOSTNAME, "record_type": "CNAME", "address": "target.example.internal"},
        {"hostname": "target.example.internal", "record_type": "A", "address": _LOCAL_ADDRESSES[0]},
    ]
    with pytest.raises(ValueError, match="unexpected address"):
        dns_readback.verify_service_dns_nss(records)
    assert [call[0][0] for call in calls] == ["getent"]


def test_nss_readback_does_not_apply_synthesis_to_unrelated_names(monkeypatch):
    """Keep unexpected NSS results for unrelated direct names strict.

    Args:
        monkeypatch: Pytest fixture used to replace native host commands.
    """
    calls = _install_own_hostname_commands(monkeypatch)
    records = [{"hostname": "service.example.internal", "record_type": "A", "address": _LOCAL_ADDRESSES[0]}]

    with pytest.raises(ValueError, match="unexpected address"):
        dns_readback.verify_service_dns_nss(records)

    assert [call[0] for call in calls] == [["getent", "hosts", "service.example.internal"]]


def test_nss_readback_does_not_apply_synthesis_to_alias_pointing_at_kernel_hostname(monkeypatch):
    """Keep an alias to the kernel hostname under the strict captured-address rule.

    Args:
        monkeypatch: Pytest fixture used to replace native host commands.
    """
    calls = _install_own_hostname_commands(
        monkeypatch, getent_output="::1 alias.example.internal\n",
    )
    records = [
        *_own_hostname_records(),
        {"hostname": "alias.example.internal", "record_type": "CNAME", "address": _KERNEL_HOSTNAME},
    ]

    with pytest.raises(ValueError, match="unexpected address"):
        dns_readback.verify_service_dns_nss(records)

    assert [call[0] for call in calls] == [["getent", "hosts", "alias.example.internal"]]


def test_nss_readback_does_not_apply_synthesis_to_retired_kernel_hostname(monkeypatch):
    """Treat a retired own hostname that still resolves as stale NSS state.

    Args:
        monkeypatch: Pytest fixture used to replace native host commands.
    """
    calls = _install_own_hostname_commands(
        monkeypatch,
        getent_output="::1 appliance.example.internal\n",
    )

    with pytest.raises(ValueError, match="Retired appliance NSS name.*still resolves"):
        dns_readback.verify_service_dns_nss(
            [], prior_records=[
                {"hostname": _KERNEL_HOSTNAME, "record_type": "A", "address": _LOCAL_ADDRESSES[0]},
            ],
        )

    assert [call[0] for call in calls] == [["getent", "hosts", _KERNEL_HOSTNAME]]


def test_nss_readback_does_not_apply_synthesis_outside_linux(monkeypatch):
    """Keep the Linux-specific exception disabled on other platforms.

    Args:
        monkeypatch: Pytest fixture used to replace native host commands.
    """
    calls = _install_own_hostname_commands(monkeypatch, platform="win32")

    with pytest.raises(ValueError, match="unexpected address"):
        dns_readback.verify_service_dns_nss(_own_hostname_records())

    assert [call[0] for call in calls] == [["getent", "hosts", _KERNEL_HOSTNAME]]


@pytest.mark.parametrize(
    "resolvectl_output",
    [
        _SYNTHETIC_QUERY.replace("-- Data from: synthetic", "-- Data from: network"),
        _SYNTHETIC_QUERY.replace("-- Data from: synthetic", "-- Data from: synthetic network"),
        _SYNTHETIC_QUERY.replace("-- Data from: synthetic", "-- Data from: synthetic cache"),
        _SYNTHETIC_QUERY.replace("-- Data from: synthetic\n", ""),
        _SYNTHETIC_QUERY.replace(_KERNEL_HOSTNAME + ":", "other.example.internal:"),
        _SYNTHETIC_QUERY.replace(_LOCAL_ADDRESSES[0], "not-an-address"),
    ],
    ids=["network", "mixed-network", "mixed-cache", "missing-marker", "wrong-name", "bad-address"],
)
def test_nss_readback_rejects_unproven_or_malformed_synthetic_output(monkeypatch, resolvectl_output):
    """Reject non-synthetic, mixed-source, wrong-name, and malformed resolver output.

    Args:
        monkeypatch: Pytest fixture used to replace native host commands.
        resolvectl_output: Resolver output that must not authorize an NSS fallback.
    """
    _install_own_hostname_commands(monkeypatch, resolvectl_output=resolvectl_output)

    with pytest.raises(ValueError, match="synthetic address proof failed"):
        dns_readback.verify_service_dns_nss(_own_hostname_records())


@pytest.mark.parametrize("bad_address", ["192.0.2.99", "203.0.113.5"], ids=["stale", "unassigned"])
def test_nss_readback_rejects_synthetic_addresses_not_owned_locally(monkeypatch, bad_address):
    """Reject a synthetic resolver response containing stale or unassigned addresses.

    Args:
        monkeypatch: Pytest fixture used to replace native host commands.
        bad_address: Address present in resolved output but absent from local interface inventory.
    """
    output = _SYNTHETIC_QUERY.replace(_LOCAL_ADDRESSES[0], bad_address)
    _install_own_hostname_commands(monkeypatch, resolvectl_output=output)

    with pytest.raises(ValueError, match="synthetic address proof failed"):
        dns_readback.verify_service_dns_nss(_own_hostname_records())


@pytest.mark.parametrize("command", ["resolvectl", "ip"])
@pytest.mark.parametrize("failure", ["missing", "timeout", "exit"], ids=["missing", "timeout", "nonzero"])
def test_nss_readback_fails_closed_when_native_synthetic_proof_command_fails(monkeypatch, command, failure):
    """Fail closed when resolver or local-address proof is unavailable.

    Args:
        monkeypatch: Pytest fixture used to replace native host commands.
        command: Native command whose proof must fail.
        failure: Failure mode injected into the command.
    """
    if failure == "missing":
        error = FileNotFoundError(command)
    elif failure == "timeout":
        error = dns_readback.subprocess.TimeoutExpired([command], 2.0)
    else:
        error = 1
    _install_own_hostname_commands(monkeypatch, failures={command: error})

    with pytest.raises(ValueError, match="synthetic address proof failed"):
        dns_readback.verify_service_dns_nss(_own_hostname_records())


@pytest.mark.parametrize("ip_output", ["not json", "{}", "[]", '[{"ifname":"eth0"}]'])
def test_nss_readback_rejects_malformed_local_address_inventory(monkeypatch, ip_output):
    """Reject local address inventories that cannot prove address ownership.

    Args:
        monkeypatch: Pytest fixture used to replace native host commands.
        ip_output: Malformed or empty JSON output from ``ip -j address show``.
    """
    _install_own_hostname_commands(monkeypatch, ip_output=ip_output)

    with pytest.raises(ValueError, match="synthetic address proof failed"):
        dns_readback.verify_service_dns_nss(_own_hostname_records())


def test_nss_readback_rejects_kernel_hostname_change_during_synthetic_proof(monkeypatch):
    """Reject resolver proof if the kernel hostname changes during verification.

    Args:
        monkeypatch: Pytest fixture used to replace native host commands.
    """
    _install_own_hostname_commands(monkeypatch)
    names = iter([_KERNEL_HOSTNAME, "changed.example.internal"])
    monkeypatch.setattr(dns_readback.socket, "gethostname", lambda: next(names))

    with pytest.raises(ValueError, match="synthetic address proof failed"):
        dns_readback.verify_service_dns_nss(_own_hostname_records())


@pytest.mark.parametrize("resolver_scope", ["", "%access0", "%3"])
@pytest.mark.parametrize("nss_scope", ["", "%access0", "%3"])
def test_nss_readback_proves_assigned_link_local_address_and_scope(monkeypatch, resolver_scope, nss_scope):
    """Accept an assigned link-local answer with matching named, numeric, or absent scope.

    Args:
        monkeypatch: Replace native commands with current-link address evidence.
        resolver_scope: Interface scope emitted by resolvectl.
        nss_scope: Interface scope emitted or omitted by getent hosts.
    """
    local_address = "fe80::1234"
    output = (_SYNTHETIC_QUERY.replace(_LOCAL_ADDRESSES[1], local_address + resolver_scope))
    observed = json.dumps([
        {"ifname": "mgmt0", "ifindex": 2, "addr_info": [{"local": _LOCAL_ADDRESSES[0]}]},
        {"ifname": "access0", "ifindex": 3, "addr_info": [{"local": local_address}]},
    ])
    _install_own_hostname_commands(
        monkeypatch, getent_output=f"{local_address}{nss_scope} {_KERNEL_HOSTNAME}\n",
        resolvectl_output=output, ip_output=observed,
    )
    dns_readback.verify_service_dns_nss(_own_hostname_records())


@pytest.mark.parametrize("resolver_address", ["fe80::1234%mgmt0", "fe80::1234%2", "fe80::9999%access0"])
def test_nss_readback_rejects_link_local_address_on_unowned_scope(monkeypatch, resolver_address):
    """A scoped synthetic address must be assigned to that exact observed link.

    Args:
        monkeypatch: Replace native commands with a different-link inventory.
        resolver_address: Synthetic address with the wrong scope or an unassigned value.
    """
    observed = json.dumps([
        {"ifname": "mgmt0", "ifindex": 2, "addr_info": [{"local": _LOCAL_ADDRESSES[0]}]},
        {"ifname": "access0", "ifindex": 3, "addr_info": [{"local": "fe80::1234"}]},
    ])
    _install_own_hostname_commands(
        monkeypatch, resolvectl_output=_SYNTHETIC_QUERY.replace(_LOCAL_ADDRESSES[1], resolver_address),
        ip_output=observed,
    )
    with pytest.raises(ValueError, match="synthetic address proof failed"):
        dns_readback.verify_service_dns_nss(_own_hostname_records())


@pytest.mark.parametrize("nss_scope", ["%mgmt0", "%2"])
def test_nss_readback_rejects_nss_link_local_scope_not_assigned_to_address(monkeypatch, nss_scope):
    """Valid resolver proof does not admit an NSS result naming a different link.

    Args:
        monkeypatch: Replace native commands with the assigned access-link evidence.
        nss_scope: Management-link scope not owning the returned link-local address.
    """
    observed = json.dumps([
        {"ifname": "mgmt0", "ifindex": 2, "addr_info": [{"local": _LOCAL_ADDRESSES[0]}]},
        {"ifname": "access0", "ifindex": 3, "addr_info": [{"local": "fe80::1234"}]},
    ])
    _install_own_hostname_commands(
        monkeypatch, getent_output=f"fe80::1234{nss_scope} {_KERNEL_HOSTNAME}\n",
        resolvectl_output=_SYNTHETIC_QUERY.replace(_LOCAL_ADDRESSES[1], "fe80::1234%access0"),
        ip_output=observed,
    )
    with pytest.raises(ValueError, match="unexpected address"):
        dns_readback.verify_service_dns_nss(_own_hostname_records())
