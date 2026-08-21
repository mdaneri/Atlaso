"""Test NTP and NTS management UI transports."""

import json

from sqlalchemy import select

from atlaso.app import ui
from atlaso.app.adapters.system import AdapterResult
from atlaso.app.database import SessionLocal
from atlaso.app.models import AuditEvent, NtpSettings
from tests.routers.ui.helpers import login


def test_ntp_router_owns_exact_transport_set() -> None:
    """Keep the extracted router limited to the three established transports."""
    assert [
        (route.path, tuple(sorted(route.methods or ())), route.name)
        for route in ui.ntp_router.routes
    ] == [
        ("/ui/management/ntp", ("GET",), "ntp_page"),
        (
            "/ui/management/ntp/source-health",
            ("GET",),
            "ntp_source_health",
        ),
        (
            "/ui/management/ntp/settings",
            ("POST",),
            "update_ntp_settings_from_ui",
        ),
    ]


def test_ntp_page_keeps_legacy_and_session_redirects(client) -> None:
    """Preserve the legacy facade redirect and canonical session enforcement.

    Args:
        client: The application test client.
    """
    legacy = client.get("/ntp", follow_redirects=False)
    assert legacy.status_code == 307
    assert legacy.headers["location"] == "/ui/management/ntp"

    canonical = client.get("/ui/management/ntp", follow_redirects=False)
    assert canonical.status_code == 303
    assert (
        canonical.headers["location"]
        == "/ui/management/login?next=/ui/management/ntp"
    )


def test_ntp_source_health_keeps_facade_adapter_monkeypatch_seam(
    client, monkeypatch
) -> None:
    """Resolve the facade adapter late enough for compatibility monkeypatching.

    Args:
        client: The application test client.
        monkeypatch: The pytest monkeypatch fixture.
    """

    class FacadeAdapter:
        """Return one bounded NTP status response."""

        def read_ntpd_status(self) -> AdapterResult:
            """Return the representative helper payload."""
            return AdapterResult(
                command=["atlaso-helper", "ntpd", "status"],
                dry_run=False,
                stdout=json.dumps({"peers": [{"remote": "192.0.2.10"}]}),
            )

    monkeypatch.setattr("atlaso.app.ui.SystemAdapter", FacadeAdapter)
    login(client)
    response = client.get("/ui/management/ntp/source-health")

    assert response.status_code == 200
    assert response.json() == {
        "ok": True,
        "dry_run": False,
        "returncode": 0,
        "stdout": '{"peers": [{"remote": "192.0.2.10"}]}',
        "stderr": "",
        "status": {"peers": [{"remote": "192.0.2.10"}]},
    }


def test_ntp_settings_autosave_preserves_desired_state_and_audit(
    client, monkeypatch
) -> None:
    """Preserve form parsing, desired-state persistence, and audit behavior.

    Args:
        client: The application test client.
        monkeypatch: The pytest monkeypatch fixture.
    """
    monkeypatch.setattr(
        "atlaso.app.ui.SystemAdapter.read_ntpd_capabilities",
        lambda _self: AdapterResult(
            command=["atlaso-helper", "ntpd", "capabilities"],
            dry_run=False,
            stdout=json.dumps({"nts": True, "version": "ntpd test (+NTS)"}),
        ),
    )
    login(client)
    page = client.get("/ui/management/ntp")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    response = client.post(
        "/ui/management/ntp/settings",
        data={
            "enabled": "on",
            "hostname": "ntp.atlaso.internal",
            "listen_interfaces_present": "1",
            "listen_addresses_present": "1",
            "listen_interfaces": ["eth2"],
            "upstream_sources_json": json.dumps(
                [
                    {
                        "id": "cloudflare-nts",
                        "source": "time.cloudflare.com",
                        "enabled": True,
                        "use_nts": True,
                        "description": "Cloudflare public NTS",
                    }
                ]
            ),
            "allow_clients": "any",
            "port": "123",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "saved"
    assert payload["enabled"] is True
    assert payload["upstream_sources"][0]["use_nts"] is True
    assert "server time.cloudflare.com iburst nts" in payload["config_preview"]
    with SessionLocal() as db:
        settings = db.execute(select(NtpSettings)).scalar_one()
        assert settings.hostname == "ntp.atlaso.internal"
        assert db.execute(
            select(AuditEvent).where(AuditEvent.action == "update_ntp_settings")
        ).scalar_one().actor == "admin"


def test_ntp_settings_rejects_duplicate_normalized_sources(
    client, monkeypatch
) -> None:
    """Preserve duplicate-source validation and its transport status.

    Args:
        client: The application test client.
        monkeypatch: The pytest monkeypatch fixture.
    """
    monkeypatch.setattr(
        "atlaso.app.ui.SystemAdapter.read_ntpd_capabilities",
        lambda _self: AdapterResult(
            command=["atlaso-helper", "ntpd", "capabilities"],
            dry_run=False,
            stdout=json.dumps({"nts": True}),
        ),
    )
    login(client)
    page = client.get("/ui/management/ntp")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/ui/management/ntp/settings",
        data={
            "upstream_sources_json": json.dumps(
                [
                    {"source": "time.example.test", "enabled": True},
                    {"source": "TIME.EXAMPLE.TEST.", "enabled": True},
                ]
            ),
            "csrf": csrf,
        },
    )

    assert response.status_code == 422
    assert "Source names must be unique" in response.json()["detail"]
