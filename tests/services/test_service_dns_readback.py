"""Tests for strict service DNS readback."""

from __future__ import annotations

import ipaddress
import struct
from types import SimpleNamespace

import pytest

from atlaso.app.services import service_dns_readback as dns_readback


def _wire_name(name: str) -> bytes:
    return b"".join(bytes((len(label),)) + label.encode("ascii") for label in name.rstrip(".").split(".")) + b"\0"


def _question_end(packet: bytes) -> int:
    offset = 12
    while packet[offset]:
        offset += packet[offset] + 1
    return offset + 5


def _rr(owner: bytes, rtype: int, data: bytes, ttl: int = 60) -> bytes:
    return owner + struct.pack("!HHIH", rtype, 1, ttl, len(data)) + data


def _response(query: bytes, answers: list[bytes], *, flags: int = 0x8180, extra: bytes = b"") -> bytes:
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
        self.responder = responder
        self.source = source
        self.family = family
        self.destination = None
        self.query = b""

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def settimeout(self, _timeout):
        pass

    def sendto(self, query, destination):
        self.query = query
        self.destination = destination

    def recvfrom(self, _size):
        return self.responder(self.query), self.source


def _mock_socket(monkeypatch, responder, source=("127.0.0.1", 53)):
    clients = []

    def create(family, _kind):
        client = _Socket(responder, source, family)
        clients.append(client)
        return client

    monkeypatch.setattr(dns_readback.socket, "socket", create)
    return clients


def _query_parts(query: bytes) -> tuple[str, int]:
    offset = 12
    labels = []
    while query[offset]:
        length = query[offset]
        labels.append(query[offset + 1 : offset + 1 + length].decode("ascii"))
        offset += length + 1
    return ".".join(labels).lower() + ".", struct.unpack_from("!H", query, offset + 1)[0]


def test_reads_back_a_aaaa_and_cname_with_compressed_owners_and_ignores_unrelated_rr(monkeypatch):
    def responder(query):
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
    def responder(query):
        alias = _rr(b"\xc0\x0c", 5, _wire_name("target.example.internal."))
        target = _rr(_wire_name("target.example.internal."), 1, ipaddress.IPv4Address("192.0.2.20").packed)
        return _response(query, [alias, target])

    _mock_socket(monkeypatch, responder)
    dns_readback.verify_service_dns_records(
        [{"hostname": "alias.example.internal", "record_type": "A", "address": "192.0.2.20"}]
    )


def test_rejects_stale_old_ip_address(monkeypatch):
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
    def responder(query):
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
    _mock_socket(monkeypatch, lambda query: _response(query, [_rr(b"\xc0\x0c", 5, b"\xc0\x0c")]))
    with pytest.raises(ValueError, match="cyclic"):
        dns_readback.verify_service_dns_records(
            [{"hostname": "node.example.internal", "record_type": "A", "address": "192.0.2.2"}]
        )

@pytest.mark.parametrize("flags", [0x8580, 0x8583])
def test_retired_record_accepts_nodata_or_authoritative_nxdomain(monkeypatch, flags):
    _mock_socket(monkeypatch, lambda query: _response(query, [], flags=flags))

    dns_readback.verify_service_dns_records(
        [], prior_records=[{"hostname": "retired.example.internal", "record_type": "A", "address": "192.0.2.8"}],
        require_authoritative=True,
    )


@pytest.mark.parametrize("flags, message", [(0x8183, "not authoritative"), (0x8182, "reports an error")])
def test_retired_record_rejects_non_authoritative_or_server_failure(monkeypatch, flags, message):
    _mock_socket(monkeypatch, lambda query: _response(query, [], flags=flags))

    with pytest.raises(ValueError, match=message):
        dns_readback.verify_service_dns_records(
            [], prior_records=[{"hostname": "retired.example.internal", "record_type": "A", "address": "192.0.2.8"}],
            require_authoritative=True,
        )


def test_retired_record_queries_explicit_ipv6_nameserver_and_port(monkeypatch):
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
    target_type = 1 if record_type == "A" else 28
    packed = ipaddress.ip_address(target_address).packed

    def responder(query):
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
    alias = _rr(b"\xc0\x0c", 5, _wire_name("target.example.internal."))
    target = _rr(_wire_name("target.example.internal."), 1, ipaddress.IPv4Address("192.0.2.30").packed)
    stale_v6 = _rr(b"\xc0\x0c", 28, ipaddress.IPv6Address("2001:db8::8").packed)

    def responder(query):
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
    old = _rr(b"\xc0\x0c", 1, ipaddress.IPv4Address("192.0.2.8").packed)
    new = _rr(b"\xc0\x0c", 28, ipaddress.IPv6Address("2001:db8::9").packed)

    def responder(query):
        _hostname, qtype = _query_parts(query)
        return _response(query, [new] if qtype == 28 else [old])

    _mock_socket(monkeypatch, responder)
    with pytest.raises(ValueError, match="Retired DNS A record.*still present"):
        dns_readback.verify_service_dns_records(
            [{"hostname": "node.example.internal", "record_type": "AAAA", "address": "2001:db8::9"}],
            prior_records=[{"hostname": "node.example.internal", "record_type": "A", "address": "192.0.2.8"}],
        )


def test_retired_cname_rejects_stale_alias_when_owner_has_direct_address(monkeypatch):
    direct = _rr(b"\xc0\x0c", 1, ipaddress.IPv4Address("192.0.2.9").packed)
    stale_alias = _rr(b"\xc0\x0c", 5, _wire_name("old-target.example.internal."))

    def responder(query):
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
    _mock_socket(monkeypatch, lambda query: _response(query, [answer]))
    with pytest.raises(ValueError, match=message):
        dns_readback.verify_service_dns_records(
            [], prior_records=[{"hostname": "retired.example.internal", "record_type": "A", "address": "192.0.2.8"}],
        )


def test_rejects_nxdomain_response_that_contains_answer_data(monkeypatch):
    old = _rr(b"\xc0\x0c", 1, ipaddress.IPv4Address("192.0.2.8").packed)
    _mock_socket(monkeypatch, lambda query: _response(query, [old], flags=0x8583))

    with pytest.raises(ValueError, match="NXDOMAIN.*answer data"):
        dns_readback.verify_service_dns_records(
            [], prior_records=[{"hostname": "retired.example.internal", "record_type": "A", "address": "192.0.2.8"}],
            require_authoritative=True,
        )


def test_authoritative_requirement_applies_to_positive_answers(monkeypatch):
    answer = _rr(b"\xc0\x0c", 1, ipaddress.IPv4Address("192.0.2.8").packed)
    _mock_socket(monkeypatch, lambda query: _response(query, [answer], flags=0x8180))

    with pytest.raises(ValueError, match="not authoritative"):
        dns_readback.verify_service_dns_records(
            [{"hostname": "node.example.internal", "record_type": "A", "address": "192.0.2.8"}],
            require_authoritative=True,
        )



@pytest.mark.parametrize("stale_alias", [False, True])
def test_retired_cname_owner_checks_address_families_after_cname_nodata(monkeypatch, stale_alias):
    address = "192.0.2.9"
    direct = _rr(b"\xc0\x0c", 1, ipaddress.IPv4Address(address).packed)
    alias = _rr(b"\xc0\x0c", 5, _wire_name("target.example.internal."))
    target = _rr(_wire_name("target.example.internal."), 1, ipaddress.IPv4Address(address).packed)

    def responder(query):
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
    def responder(query):
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
    alias = _rr(b"\xc0\x0c", 5, _wire_name("target.example.internal."))
    target_a = _rr(_wire_name("target.example.internal."), 1, ipaddress.IPv4Address("192.0.2.30").packed)

    def responder(query):
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
    outputs = {
        "node.example.internal": "192.0.2.10 node.example.internal\n",
        "dual.example.internal": "2001:db8::10 dual.example.internal\n",
        "alias.example.internal": "192.0.2.10 node.example.internal alias.example.internal\n",
    }
    calls = []

    def run(args, **kwargs):
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
    monkeypatch.setattr(dns_readback.subprocess, "run", lambda *_args, **_kwargs: result)
    with pytest.raises(ValueError, match=message):
        dns_readback.verify_service_dns_nss([
            {"hostname": "node.example.internal", "record_type": "A", "address": "192.0.2.10"},
        ])


@pytest.mark.parametrize("failure, message", [("timeout", "timed out"), ("missing", "tool is unavailable")])
def test_nss_readback_rejects_timeout_and_missing_getent(monkeypatch, failure, message):
    def run(*_args, **_kwargs):
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
    def unexpected_run(*_args, **_kwargs):
        pytest.fail("NSS must not be queried when the captured CNAME chain is untrusted.")

    monkeypatch.setattr(dns_readback.subprocess, "run", unexpected_run)
    with pytest.raises(ValueError, match=message):
        dns_readback.verify_service_dns_nss(records)


@pytest.mark.parametrize("timeout", [0, -1, True, float("inf"), "2"])
def test_nss_readback_validates_bounded_timeout(monkeypatch, timeout):
    monkeypatch.setattr(dns_readback.subprocess, "run", lambda *_args, **_kwargs: pytest.fail("unexpected NSS call"))
    with pytest.raises(ValueError, match="timeout"):
        dns_readback.verify_service_dns_nss(
            [{"hostname": "node.example.internal", "record_type": "A", "address": "192.0.2.10"}],
            timeout=timeout,
        )
