"""Tests for strict service DNS readback."""

from __future__ import annotations

import ipaddress
import struct

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
    def __init__(self, responder):
        self.responder = responder
        self.query = b""

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def settimeout(self, _timeout):
        pass

    def sendto(self, query, _destination):
        self.query = query

    def recvfrom(self, _size):
        return self.responder(self.query), ("127.0.0.1", 53)


def _mock_socket(monkeypatch, responder):
    monkeypatch.setattr(dns_readback.socket, "socket", lambda *_args: _Socket(responder))


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
