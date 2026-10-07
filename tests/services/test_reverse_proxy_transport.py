"""Verify the upstream transport refuses unsafe destinations and TLS peers."""

import asyncio
import hashlib
import json
import socket
import ssl
from unittest.mock import AsyncMock, Mock

import pytest

from atlaso.app.services import reverse_proxy_transport as transport


def route(**changes):
    """Return one bounded transport request without credentials."""
    return {"socket_id": "1-1", "probe_host": "portal.example.test", "probe_path": "/app/",
            "upstream_scheme": "https", "upstream_host": "app.example.test",
            "upstream_port": 443, "trust_mode": "fingerprint", "fingerprint": hashlib.sha256(b"leaf").hexdigest(),
            "connect_timeout": 5, "read_timeout": 60, "send_timeout": 60, **changes}


@pytest.mark.parametrize("address", ["127.0.0.1", "::1", "169.254.169.254", "fe80::1", "224.0.0.1", "0.0.0.0", "::", "::ffff:192.0.2.1"])
def test_special_destinations_are_refused(address):
    """DNS cannot bypass special-address restrictions."""
    assert not transport.safe_destination(address, set())


def test_actual_peer_pin_and_default_ca_verification():
    """Pin the established peer, while retaining normal trust by default."""
    writer = Mock()
    writer.get_extra_info.return_value.getpeercert.return_value = b"leaf"
    transport.verify_peer(route(), writer)
    writer.get_extra_info.assert_called_once_with("ssl_object")
    writer.get_extra_info.return_value.getpeercert.return_value = b"different leaf"
    with pytest.raises(ssl.SSLCertVerificationError):
        transport.verify_peer(route(), writer)
    trusted = transport.tls_context(route(trust_mode="trusted_ca", fingerprint=""))
    assert trusted.check_hostname and trusted.verify_mode == ssl.CERT_REQUIRED


@pytest.mark.asyncio
async def test_mixed_dns_answers_refused_before_connect(monkeypatch):
    """Reject a DNS answer set containing any appliance address."""
    monkeypatch.setattr(transport, "native_addresses", lambda: {"192.0.2.10"})
    resolve = AsyncMock(return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", (value, 443))
                                     for value in ["192.0.2.20", "192.0.2.10"]])
    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", resolve)
    connect = AsyncMock()
    monkeypatch.setattr(asyncio, "open_connection", connect)
    with pytest.raises(OSError, match="excluded"):
        await transport.open_upstream(route(), set())
    connect.assert_not_awaited()


@pytest.mark.asyncio
async def test_pin_mismatch_closes_same_connection_before_bytes(monkeypatch):
    """Reject a wrong certificate on the actual stream without writing a request."""
    monkeypatch.setattr(transport, "native_addresses", lambda: {"192.0.2.10"})
    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", AsyncMock(return_value=[
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.20", 443))]))
    writer = Mock()
    writer.get_extra_info.return_value.getpeercert.return_value = b"wrong"
    connect = AsyncMock(return_value=(Mock(), writer))
    monkeypatch.setattr(asyncio, "open_connection", connect)
    with pytest.raises(ssl.SSLCertVerificationError):
        await transport.open_upstream(route(), set())
    assert connect.await_args.args[0] == "192.0.2.20"
    assert connect.await_args.kwargs["server_hostname"] == "app.example.test"
    writer.write.assert_not_called()
    writer.close.assert_called_once()


@pytest.mark.asyncio
async def test_native_observation_failure_refuses_outbound(monkeypatch):
    """Unknown local-address state cannot silently relax the exclusion set."""
    def unavailable():
        raise OSError("no native inventory")

    monkeypatch.setattr(transport, "native_addresses", unavailable)
    connect = AsyncMock()
    monkeypatch.setattr(asyncio, "open_connection", connect)
    with pytest.raises(OSError):
        await transport.open_upstream(route(), set())
    connect.assert_not_awaited()


@pytest.mark.asyncio
async def test_health_cache_sampling_is_periodic_atomic_and_bounded(tmp_path, monkeypatch):
    """Sample at most eight routes concurrently and publish one compact cache generation."""
    routes = [route(socket_id=f"1-{index}", trust_mode="trusted_ca", fingerprint="") for index in range(1, 11)]
    manifest = {"generation": "a" * 64, "routes": routes, "forbidden_addresses": ["192.0.2.10"]}
    release = asyncio.Event()
    eight_started = asyncio.Event()
    active = 0
    peak = 0
    calls = 0

    async def fake_probe(selected, _forbidden):
        nonlocal active, peak, calls
        calls += 1
        active += 1
        peak = max(peak, active)
        if active == 8:
            eight_started.set()
        await release.wait()
        active -= 1
        return {"status": "healthy", "last_success": None, "failure_class": None,
                "http_status": 204, "tls_status": "trusted_ca"}

    class StopAfterPublish(Exception):
        pass

    async def stop_after_interval(seconds):
        assert seconds == 30
        raise StopAfterPublish

    monkeypatch.setattr(transport, "probe", fake_probe)
    monkeypatch.setattr(transport.asyncio, "sleep", stop_after_interval)
    task = asyncio.create_task(transport.observe_health(manifest, tmp_path))
    await asyncio.wait_for(eight_started.wait(), timeout=2)
    assert calls == 8
    release.set()
    with pytest.raises(StopAfterPublish):
        await asyncio.wait_for(task, timeout=2)

    cache_path = tmp_path / "health.json"
    cache = json.loads(cache_path.read_text(encoding="utf-8"))
    assert peak == 8
    assert calls == len(routes)
    assert not (tmp_path / "health.pending").exists()
    assert cache["generation"] == manifest["generation"]
    assert set(cache["health"]) == {item["socket_id"] for item in routes}
    assert len(cache_path.read_bytes()) < 16_384
    assert all(set(item) == {"status", "last_success", "failure_class", "http_status", "tls_status"}
               for item in cache["health"].values())


@pytest.mark.asyncio
async def test_probe_uses_public_host_and_route_aware_path_without_retaining_body(monkeypatch):
    """Health requests target the published virtual host and only the bounded HEAD path."""
    reader = Mock()
    reader.readuntil = AsyncMock(return_value=b"HTTP/1.1 204 No Content\r\n")
    writer = Mock()
    writer.drain = AsyncMock()
    monkeypatch.setattr(transport, "open_upstream", AsyncMock(return_value=(reader, writer)))

    result = await transport.probe(route(probe_path="/app/a%20b"), set())

    assert writer.write.call_args.args[0] == (
        b"HEAD /app/a%20b HTTP/1.1\r\nHost: portal.example.test\r\nConnection: close\r\n\r\n"
    )
    assert result["status"] == "healthy"
    assert result["http_status"] == 204
    assert "body" not in result
    writer.close.assert_called_once()


@pytest.mark.asyncio
async def test_probe_timeout_is_reported_as_bounded_unavailable_health(monkeypatch):
    """A timed-out HEAD observation degrades status without surfacing exception data."""
    monkeypatch.setattr(transport, "open_upstream", AsyncMock(side_effect=TimeoutError("private detail")))

    result = await transport.probe(route(), set())

    assert result == {"status": "degraded", "last_success": None,
                      "failure_class": "unavailable", "http_status": None,
                      "tls_status": "not_probed"}
