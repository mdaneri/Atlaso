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
