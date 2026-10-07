"""Validate bounded cached observations for managed reverse proxies."""

import json
from datetime import datetime, timezone

from atlaso.app.adapters.system import AdapterResult
from atlaso.app.services import reverse_proxy_observation as observation


def _desired():
    """Return one canonical in-memory proxy snapshot."""
    return [{
        "id": 1,
        "name": "Example",
        "description": "",
        "hostname": "example.test",
        "scheme": "https",
        "port": 8443,
        "redirect_http": False,
        "redirect_port": 80,
        "enabled": True,
        "public_listing": True,
        "managed_dns": False,
        "listeners": [{"interface": "eth1", "address": "192.0.2.10"}],
        "connect_timeout": 5,
        "read_timeout": 60,
        "send_timeout": 60,
        "body_limit": 16777216,
        "routes": [{
            "id": 2,
            "position": 0,
            "path_prefix": "/",
            "upstream_scheme": "https",
            "upstream_host": "backend.example.test",
            "upstream_port": 9443,
            "path_behavior": "preserve",
            "trust_mode": "trusted_ca",
            "fingerprint": "",
        }],
    }]


def _payload(*, proxies=None, observed_at="2026-10-07T00:00:00+00:00", health=None):
    """Return a complete helper payload with one body-free status row."""
    return {
        "schema": 1,
        "proxies": _desired() if proxies is None else proxies,
        "generation": "a" * 64,
        "health": health if health is not None else {
            "1-2": {
                "status": "healthy",
                "last_success": "2026-10-07T00:00:00+00:00",
                "failure_class": None,
                "http_status": 204,
                "tls_status": "trusted_ca",
            }
        },
        "observed_at": observed_at,
    }


def _configure(monkeypatch, payload, *, dry_run=False, returncode=0):
    """Replace desired-state and helper boundaries for a focused observation test."""
    monkeypatch.setattr(observation, "runtime_snapshot", lambda _db: _desired())
    monkeypatch.setattr(
        observation.SystemAdapter,
        "reverse_proxy_status",
        lambda _self: AdapterResult(command=["atlaso-helper"], dry_run=dry_run,
                                    stdout=json.dumps(payload), returncode=returncode),
    )


def test_applied_snapshot_projects_cached_healthy_status_without_probing(monkeypatch):
    now = datetime(2026, 10, 7, tzinfo=timezone.utc)
    _configure(monkeypatch, _payload())

    result = observation.observe_reverse_proxy_health(object(), now=now)

    assert len(result) == 1
    assert result[0]["status"] == "healthy"
    assert result[0]["applied"] is True
    assert result[0]["pending"] is False
    assert result[0]["http_status"] == 204
    assert "body" not in result[0]


def test_fresh_batch_does_not_refresh_an_old_route_sample(monkeypatch):
    """A recently written batch must not restamp a stale successful route.

    Args:
        monkeypatch: Isolated helper and desired-state boundaries.
    """
    payload = _payload(observed_at="2026-10-07T00:02:00+00:00")
    payload["health"]["1-2"]["observed_at"] = "2026-10-07T00:00:00+00:00"
    _configure(monkeypatch, payload)
    result = observation.observe_reverse_proxy_health(object(), now=datetime(2026, 10, 7, 0, 2, tzinfo=timezone.utc))
    assert result[0]["status"] == "unavailable"
    assert result[0]["applied"] is True
    assert result[0]["http_status"] is None


def test_changed_snapshot_is_pending_and_does_not_expose_old_health(monkeypatch):
    previous = _desired()
    previous[0]["name"] = "Old name"
    _configure(monkeypatch, _payload(proxies=previous))

    result = observation.observe_reverse_proxy_health(object(), now=datetime(2026, 10, 7, tzinfo=timezone.utc))

    assert result[0]["status"] == "pending"
    assert result[0]["applied"] is False
    assert result[0]["pending"] is True
    assert result[0]["http_status"] is None


def test_stale_malformed_and_dry_run_snapshots_fail_closed(monkeypatch):
    now = datetime(2026, 10, 7, tzinfo=timezone.utc)
    _configure(monkeypatch, _payload(observed_at="2026-10-06T23:58:00+00:00"))
    stale = observation.observe_reverse_proxy_health(object(), now=now)
    assert stale[0]["status"] == "unavailable"
    assert stale[0]["applied"] is False

    _configure(monkeypatch, {"schema": 1, "proxies": [], "generation": "bad", "health": {}, "observed_at": "2026-10-07T00:00:00+00:00"})
    malformed = observation.observe_reverse_proxy_health(object(), now=now)
    assert malformed[0]["failure_class"] == "runtime_observer_unavailable"

    _configure(monkeypatch, _payload(), dry_run=True)
    dry_run = observation.observe_reverse_proxy_health(object(), now=now)
    assert dry_run[0]["status"] == "unavailable"


def test_insecure_upstream_is_always_degraded_even_when_cached_probe_is_healthy(monkeypatch):
    desired = _desired()
    desired[0]["routes"][0]["trust_mode"] = "insecure"
    desired[0]["routes"][0]["fingerprint"] = ""
    monkeypatch.setattr(observation, "runtime_snapshot", lambda _db: desired)
    payload = _payload()
    payload["proxies"] = desired
    monkeypatch.setattr(
        observation.SystemAdapter,
        "reverse_proxy_status",
        lambda _self: AdapterResult(command=["atlaso-helper"], dry_run=False, stdout=json.dumps(payload)),
    )

    result = observation.observe_reverse_proxy_health(object(), now=datetime(2026, 10, 7, tzinfo=timezone.utc))

    assert result[0]["status"] == "degraded"
    assert result[0]["failure_class"] == "insecure_verification"
    assert "verification is disabled" in result[0]["warning"]
