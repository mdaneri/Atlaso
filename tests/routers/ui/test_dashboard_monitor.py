"""Test Dashboard and Monitor management UI transports."""

from tests.routers.ui.helpers import login


def test_dashboard_monitor_router_owns_exact_transport_set():
    """Keep Dashboard and Monitor route identities in established order."""
    from atlaso.app import ui

    assert [
        (route.path, tuple(sorted((route.methods or set()) - {"HEAD"})), route.name)
        for route in ui.dashboard_monitor_router.routes
    ] == [
        ("/ui/management/dashboard", ("GET",), "dashboard"),
        ("/ui/management/dashboard/data", ("GET",), "dashboard_data"),
        ("/ui/management/monitor", ("GET",), "monitor_page"),
        ("/ui/management/monitor/data", ("GET",), "monitor_data"),
        ("/ui/management/monitor/network/data", ("GET",), "monitor_network_data"),
        ("/ui/management/monitor/network/lookup", ("GET",), "monitor_network_lookup"),
        ("/ui/management/network-diagnostics", ("GET",), "network_diagnostics_page"),
        ("/ui/management/network-diagnostics", ("POST",), "network_diagnostics_run"),
        ("/ui/management/monitor/network/updates/{job_id}", ("GET",), "monitor_update_data"),
        ("/ui/management/monitor/services/data", ("GET",), "monitor_services_data"),
        ("/ui/management/server-time", ("GET",), "server_time"),
    ]


def test_dashboard_data_requires_session_and_keeps_private_shape(client):
    """Verify the private Dashboard data transport retains its session contract.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    legacy = client.get("/dashboard/data", follow_redirects=False)
    assert legacy.status_code == 307
    assert legacy.headers["location"] == "/ui/management/dashboard/data"

    private = client.get("/ui/management/dashboard/data", follow_redirects=False)
    assert private.status_code == 303
    assert (
        private.headers["location"]
        == "/ui/management/login?next=/ui/management/dashboard/data"
    )

    login(client)
    private = client.get("/ui/management/dashboard/data")
    assert private.status_code == 200
    payload = private.json()
    assert set(payload) == {
        "generated_at",
        "overall",
        "readiness",
        "attention_items",
        "pending_changes",
        "tasks",
        "services",
        "network",
        "recent_activity",
    }
    assert set(payload["overall"]) == {
        "state",
        "label",
        "hostname",
        "fqdn",
        "dry_run",
        "primary_action",
    }


def test_monitor_data_and_server_time_keep_transport_contracts(client):
    """Verify Monitor history and server-time responses remain compatible.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    login(client)

    data = client.get("/monitor/data")
    assert data.status_code == 200, data.text
    payload = data.json()
    assert payload["window_hours"] == 6
    assert "summary" in payload
    assert "virtualization" in payload
    assert "cpu" in payload
    assert "cpu_cores" in payload
    assert "memory" in payload
    assert "network_totals" in payload
    assert "disk_devices" in payload
    assert "disks" in payload

    day_data = client.get("/monitor/data?hours=24")
    assert day_data.status_code == 200, day_data.text
    assert day_data.json()["window_hours"] == 24

    server_time = client.get("/server-time")
    assert server_time.status_code == 200
    assert server_time.json()["label"].startswith("Server ")


def test_runtime_monitor_permissions_and_direct_links(client):
    """Enforce monitoring and resource scopes on the browser page and data endpoints.

    Args:
        client: Test client for the management interface.
    """
    from atlaso.app.security import Identity, require_session_identity

    login(client)
    root = "/ui/management/monitor"
    identity = Identity("test-monitor", "viewer", {"read:monitoring"})
    client.app.dependency_overrides[require_session_identity] = lambda: identity
    try:
        assert client.get(root).status_code == 200
        for path in ("?view=network", "?view=services", "/network/data",
                     "/network/lookup?destination=192.0.2.1", "/network/updates/job_missing", "/services/data"):
            assert client.get(root + path).status_code == 403, path
        identity.scopes.update({"read:routes", "read:services"})
        assert client.get(root + "?view=network&update=job_missing").status_code == 200
        assert client.get(root + "?view=services").status_code == 200
        for path in ("/network/data", "/services/data"):
            observed = client.get(root + path)
            assert observed.status_code == 200, observed.text
            assert set(observed.json()) == {"captured_at", "sections"}
            assert observed.headers["cache-control"] == "no-store"
        assert client.get(root + "/network/updates/job_missing").status_code == 404
        assert client.get(root + "/network/lookup?destination=example.org").status_code == 422
    finally:
        client.app.dependency_overrides.pop(require_session_identity, None)


def test_network_diagnostics_require_operator_and_csrf(client, monkeypatch):
    """Only an authorized explicit submission can send a probe.

    Args:
        client: Test client for the management interface.
        monkeypatch: Fixture that substitutes the local addresses and probe result.
    """
    from atlaso.app.security import Identity, require_session_identity
    from atlaso.app.services import network_diagnostics as diagnostics

    calls = []

    def probe(*args):
        """Capture the submitted probe and return a projected result.

        Args:
            *args: Diagnostic, destination, source address, and family.
        """
        calls.append(args)
        return diagnostics.Result(
            "reply", "Destination reached.", "2001:db8::8", "2001:db8::2",
            [diagnostics.ResultRow(1, "2001:db8::8", "0.25", "Reply")],
        )

    monkeypatch.setattr(diagnostics, "run_check", probe)
    monkeypatch.setattr(diagnostics, "local_sources", lambda: [diagnostics.Source("2001:db8::2", "eth0")])
    path = "/ui/management/network-diagnostics"
    payload = {"check": "traceroute", "target": "2001:db8::8", "source": "2001:db8::2", "family": "6"}
    assert client.get(path, follow_redirects=False).status_code == 303
    assert client.post(path, data={**payload, "csrf": "invalid"}, follow_redirects=False).status_code == 303
    login(client)

    identity = Identity("probe-user", "viewer", {"read:monitoring", "read:routes"})
    client.app.dependency_overrides[require_session_identity] = lambda: identity
    try:
        assert client.get(path).status_code == 403
        assert client.post(path, data={**payload, "csrf": "invalid"}).status_code == 403
        monitor = client.get("/ui/management/monitor?view=network")
        assert path not in monitor.text
        identity.scopes.add("write:routes")
        form = client.get(path)
        assert form.status_code == 200
        assert form.headers["cache-control"] == "no-store"
        assert "2001:db8::2 (eth0)" in form.text
        csrf = form.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
        assert client.post(path, data={**payload, "csrf": "invalid"}).status_code == 403
        assert calls == []
        result = client.post(path, data={**payload, "csrf": csrf})
        assert result.status_code == 200
        assert result.headers["cache-control"] == "no-store"
        assert "Destination reached." in result.text
        assert "<code>2001:db8::2</code>" in result.text
        assert "0.25" in result.text
        assert calls == [("traceroute", "2001:db8::8", "2001:db8::2", "6")]
    finally:
        client.app.dependency_overrides.pop(require_session_identity, None)
