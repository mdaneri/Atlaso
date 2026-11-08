"""Readiness waits preserve original trust and never retry a login or Apply."""

import json
import ssl
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts/interop"))
import ntp_cold_start_native as fixture  # noqa: E402 - Local interop entrypoint.
from certificate_peer_transport import PeerTransportRefusal  # noqa: E402 - Local transport module.


@pytest.fixture
def readiness(monkeypatch):
    """Replace network boundaries while exercising real deadlines and page parsing.

    Args:
        monkeypatch: Scoped transport, client and monotonic-clock substitutions.
    """
    clock = [0.0]
    sleeps = []

    def sleep(seconds):
        """Advance only the private fake monotonic clock.

        Args:
            seconds: Requested bounded retry delay.
        """
        sleeps.append(seconds)
        clock[0] += seconds

    monkeypatch.setattr(fixture, "time", SimpleNamespace(monotonic=lambda: clock[0], sleep=sleep))
    raw = Mock()
    peer = SimpleNamespace(topology_guard=Mock(), tcp_reachable=Mock(return_value=True), open_socket=Mock(return_value=raw))
    client = Mock(spec=fixture.Client)
    page = '<input name="csrf" value="synthetic-private-form-token">'
    client.request.return_value = (200, page)
    constructor = Mock(return_value=client)
    monkeypatch.setattr(fixture, "Client", constructor)

    def name(proxy, address, ca):
        """Exercise the bounded bootstrap socket without a real TLS connection.

        Args:
            proxy: Socket provider passed to the unchanged CA-validated SAN procedure.
            address: Admitted management endpoint.
            ca: Original public CA path.
        """
        assert address == "192.168.77.10" and ca == "original-ca.pem"
        assert proxy.open_socket(address) is raw
        return "original.fixture.test"

    discover = Mock(side_effect=name)
    monkeypatch.setattr(fixture, "tls_name", discover)
    return SimpleNamespace(peer=peer, raw=raw, client=client, constructor=constructor, discover=discover,
                           clock=clock, sleeps=sleeps, page=page,
                           plan={"current_address": "192.168.77.10", "ca_path": "original-ca.pem"})


def test_refused_startup_then_original_https_login_page(readiness):
    """Explicit early non-acceptance waits without sending credentials or Apply.

    Args:
        readiness: Private clock and original-identity transport stand-ins.
    """
    readiness.peer.tcp_reachable.side_effect = [False, False, True]
    client, facts = fixture.wait_management_client(readiness.peer, readiness.plan)
    assert client is readiness.client and facts["tcp_attempts"] == 3 and facts["elapsed_seconds"] == 4
    readiness.raw.settimeout.assert_called_once_with(8)
    readiness.constructor.assert_called_once_with("https://original.fixture.test", "original-ca.pem",
                                                peer=readiness.peer, connect_ip="192.168.77.10")
    readiness.client.request.assert_called_once_with("/ui/management/login")
    readiness.client.login.assert_not_called()
    assert "synthetic-private-form-token" not in json.dumps(facts)


@pytest.mark.parametrize("code", [502, 503, 504])
def test_only_gateway_startup_gets_retry_without_reauthentication(readiness, code):
    """Temporary backend startup failures retain the same original validated client.

    Args:
        readiness: Private-clock transport stand-ins.
        code: Explicit gateway startup response.
    """
    readiness.client.request.side_effect = [fixture.ClientRefusal(f"http_{code}"), (200, readiness.page)]
    fixture.wait_management_client(readiness.peer, readiness.plan)
    assert readiness.client.request.call_count == 2 and readiness.sleeps == [2]
    readiness.discover.assert_called_once()
    readiness.client.login.assert_not_called()


@pytest.mark.parametrize("boundary", ["tcp", "topology", "ca", "hostname", "http403", "missing-form"])
def test_trust_transport_topology_and_invalid_pages_fail_without_retry(readiness, boundary):
    """A startup wait never downgrades trust or treats policy failures as readiness.

    Args:
        readiness: Original transport and client stand-ins.
        boundary: Immediate failure boundary to exercise.
    """
    if boundary == "tcp":
        readiness.peer.tcp_reachable.side_effect = PeerTransportRefusal("peer_tcp_probe_unproven")
    elif boundary == "topology":
        readiness.peer.topology_guard.side_effect = fixture.Refusal("topology_changed")
    elif boundary == "ca":
        readiness.discover.side_effect = ssl.SSLCertVerificationError("synthetic CA mismatch")
    elif boundary == "hostname":
        readiness.client.request.side_effect = ssl.SSLCertVerificationError("synthetic hostname mismatch")
    elif boundary == "http403":
        readiness.client.request.side_effect = fixture.ClientRefusal("http_403")
    else:
        readiness.client.request.return_value = (200, "wrong login page")
    with pytest.raises((fixture.Refusal, fixture.ClientRefusal, PeerTransportRefusal, ssl.SSLCertVerificationError)):
        fixture.wait_management_client(readiness.peer, readiness.plan)
    assert readiness.sleeps == []
    readiness.client.login.assert_not_called()


@pytest.mark.parametrize("boundary", ["tcp", "gateway"])
def test_permanent_unreadiness_expires_one_shared_deadline(readiness, boundary):
    """Repeated explicit unavailability cannot renew the original wait budget.

    Args:
        readiness: Original transport and private monotonic clock.
        boundary: Permanently unavailable service layer.
    """
    if boundary == "tcp":
        readiness.peer.tcp_reachable.return_value = False
    else:
        readiness.client.request.side_effect = fixture.ClientRefusal("http_503")
    with pytest.raises(fixture.Refusal, match="management_readiness_timeout"):
        fixture.wait_management_client(readiness.peer, readiness.plan)
    assert 90 <= readiness.clock[0] <= 120
    readiness.client.login.assert_not_called()
