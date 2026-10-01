"""Test NTP and NTS management UI transports."""

import json

import pytest
from sqlalchemy import select

from atlaso.app import ui
from atlaso.app.adapters.system import AdapterResult
from atlaso.app.database import SessionLocal
from atlaso.app.models import AuditEvent, NtpSettings
from tests.routers.ui.helpers import login


def _mock_ntpd_capabilities(monkeypatch, payload: dict[str, object]) -> None:
    """Provide a deterministic helper capability result for an NTP test.

    Args:
        monkeypatch: The pytest monkeypatch fixture.
        payload: Capability fields reported by the helper.
    """
    monkeypatch.setattr(
        "atlaso.app.ui.SystemAdapter.read_ntpd_capabilities",
        lambda _self: AdapterResult(
            command=["atlaso-helper", "ntpd", "capabilities"],
            dry_run=False,
            stdout=json.dumps(payload),
        ),
    )


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
    assert payload["time_source"] == "ntp_client"
    assert payload["time_mode"] == "ntp_server"
    assert payload["upstream_sources"][0]["use_nts"] is True
    assert "server time.cloudflare.com iburst nts" in payload["config_preview"]
    with SessionLocal() as db:
        settings = db.execute(select(NtpSettings)).scalar_one()
        assert settings.hostname == "ntp.atlaso.internal"
        assert db.execute(
            select(AuditEvent).where(AuditEvent.action == "update_ntp_settings")
        ).scalar_one().actor == "admin"


def test_ntp_settings_preserves_client_choice_while_server_mode_is_enabled(
    client, monkeypatch
) -> None:
    """Keep the remembered client source while the server owns the clock.

    Args:
        client: The application test client.
        monkeypatch: The pytest monkeypatch fixture.
    """
    _mock_ntpd_capabilities(monkeypatch, {"nts": True, "vmware_tools": True})
    login(client)
    page = client.get("/ui/management/ntp")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    selected = client.post(
        "/ui/management/ntp/settings",
        data={"time_source": "vmware_tools", "csrf": csrf},
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert selected.status_code == 200
    assert selected.json()["time_source"] == "vmware_tools"
    assert selected.json()["time_mode"] == "vmware_tools"

    enabled = client.post(
        "/ui/management/ntp/settings",
        data={"enabled": "on", "csrf": csrf},
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert enabled.status_code == 200
    assert enabled.json()["time_source"] == "vmware_tools"
    assert enabled.json()["time_mode"] == "ntp_server"


def test_ntp_settings_rejects_unknown_time_source_without_saving(client) -> None:
    """Reject unsupported clock source values at the UI transport boundary.

    Args:
        client: The application test client.
    """
    login(client)
    page = client.get("/ui/management/ntp")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/ui/management/ntp/settings",
        data={"time_source": "ntp_client,vmware_tools", "csrf": csrf},
        headers={"X-Atlaso-Autosave": "1"},
    )

    assert response.status_code == 422
    assert "Time source must be ntp_client or vmware_tools" in response.json()[
        "detail"
    ]
    with SessionLocal() as db:
        settings = db.execute(select(NtpSettings)).scalar_one()
        assert settings.time_source == "ntp_client"


@pytest.mark.parametrize(
    ("capabilities", "unavailable_text", "option_label"),
    [
        ({"nts": True}, "could not be verified", "availability unknown"),
        ({"nts": True, "vmware_tools": False}, "unavailable", "unavailable"),
    ],
)
def test_ntp_settings_rejects_vmware_without_positive_capability(
    client, monkeypatch, capabilities, unavailable_text, option_label
) -> None:
    """Reject VMware Tools selections without positive helper evidence.

    Args:
        client: The application test client.
        monkeypatch: The pytest monkeypatch fixture.
        capabilities: Helper capability result under test.
        unavailable_text: Expected user-actionable status detail.
        option_label: Expected rendered option availability label.
    """
    _mock_ntpd_capabilities(monkeypatch, capabilities)
    login(client)
    page = client.get("/ui/management/ntp")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    assert (
        f'<option value="vmware_tools" disabled>VMware Tools ({option_label})</option>'
        in page.text
    )

    response = client.post(
        "/ui/management/ntp/settings",
        data={"time_source": "vmware_tools", "csrf": csrf},
        headers={"X-Atlaso-Autosave": "1"},
    )

    assert response.status_code == 422
    assert unavailable_text in response.json()["detail"]
    with SessionLocal() as db:
        settings = db.execute(select(NtpSettings)).scalar_one()
        assert settings.time_source == "ntp_client"
        assert db.execute(
            select(AuditEvent).where(AuditEvent.action == "update_ntp_settings")
        ).scalar_one_or_none() is None


def test_ntp_settings_accepts_vmware_only_when_capability_is_true(
    client, monkeypatch
) -> None:
    """Allow VMware Tools only when the helper positively reports support.

    Args:
        client: The application test client.
        monkeypatch: The pytest monkeypatch fixture.
    """
    _mock_ntpd_capabilities(monkeypatch, {"nts": True, "vmware_tools": True})
    login(client)
    page = client.get("/ui/management/ntp")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    assert '<option value="vmware_tools">VMware Tools</option>' in page.text

    response = client.post(
        "/ui/management/ntp/settings",
        data={"time_source": "vmware_tools", "csrf": csrf},
        headers={"X-Atlaso-Autosave": "1"},
    )

    assert response.status_code == 200
    assert response.json()["time_source"] == "vmware_tools"
    assert response.json()["time_mode"] == "vmware_tools"


def test_ntp_context_normalizes_saved_vmware_mode_when_unavailable(
    client, monkeypatch
) -> None:
    """Reset a restored VMware Tools preference when support is known absent.

    Args:
        client: The application test client.
        monkeypatch: The pytest monkeypatch fixture.
    """
    login(client)
    client.get("/ui/management/ntp")
    with SessionLocal() as db:
        settings = db.execute(select(NtpSettings)).scalar_one()
        settings.time_source = "vmware_tools"
        db.commit()

    _mock_ntpd_capabilities(monkeypatch, {"nts": True, "vmware_tools": False})
    response = client.get("/ui/management/ntp")

    assert response.status_code == 200
    assert 'value="ntp_client" selected' in response.text
    assert "Any saved VMware Tools choice was normalized to NTP client." in response.text
    with SessionLocal() as db:
        settings = db.execute(select(NtpSettings)).scalar_one()
        assert settings.time_source == "ntp_client"
        assert db.execute(
            select(AuditEvent).where(
                AuditEvent.action == "normalize_unavailable_ntp_time_source"
            )
        ).scalar_one_or_none() is not None


def test_ntp_settings_preserves_unknown_vmware_preference_under_server_mode(
    client, monkeypatch
) -> None:
    """Keep a remembered source when managed NTP server mode overrides it.

    Args:
        client: The application test client.
        monkeypatch: The pytest monkeypatch fixture.
    """
    _mock_ntpd_capabilities(monkeypatch, {"nts": True, "vmware_tools": True})
    login(client)
    page = client.get("/ui/management/ntp")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    selected = client.post(
        "/ui/management/ntp/settings",
        data={"time_source": "vmware_tools", "csrf": csrf},
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert selected.status_code == 200

    _mock_ntpd_capabilities(monkeypatch, {"nts": True})
    enabled = client.post(
        "/ui/management/ntp/settings",
        data={"enabled": "on", "csrf": csrf},
        headers={"X-Atlaso-Autosave": "1"},
    )

    assert enabled.status_code == 200
    assert enabled.json()["time_mode"] == "ntp_server"
    assert enabled.json()["time_source"] == "vmware_tools"


def test_ntp_page_renders_clock_choice_and_effective_helper_diagnostic(
    client, monkeypatch
) -> None:
    """Show saved choice and effective host clock status from helper fields.

    Args:
        client: The application test client.
        monkeypatch: The pytest monkeypatch fixture.
    """
    monkeypatch.setattr(
        "atlaso.app.ui.SystemAdapter.read_ntpd_status",
        lambda _self: AdapterResult(
            command=["atlaso-helper", "ntpd", "status"],
            dry_run=False,
            stdout=json.dumps(
                {
                    "mode": "ntp_client",
                    "selected_controller": {
                        "name": "ntpd",
                        "active": True,
                        "detail": "NTPsec is active.",
                    },
                    "daemon_conflicts": {
                        "chronyd": {"active": False, "detail": "inactive"},
                        "systemd_timesyncd": {
                            "active": False,
                            "detail": "inactive",
                        },
                        "vmware_tools": {"active": False, "detail": "disabled"},
                    },
                    "synchronization": {
                        "state": "synchronized",
                        "healthy": True,
                        "detail": "Selected peer 192.0.2.10.",
                    },
                }
            ),
        ),
    )
    login(client)

    response = client.get("/ui/management/ntp")

    assert response.status_code == 200
    assert '<select name="time_source"' in response.text
    assert "NTP client" in response.text
    assert "Desired mode" in response.text
    assert "Effective mode" in response.text
    assert "Selected controller" in response.text
    assert "NTPsec is active." in response.text
    assert "Selected peer 192.0.2.10." in response.text
    assert 'data-clock-health="healthy"' in response.text


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
