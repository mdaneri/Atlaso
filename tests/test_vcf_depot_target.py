"""Test vcf depot target behavior."""

import pytest

from atlaso.app.services import vcf_depot_target as service


LOCAL = service.LocalDepotEndpoint("depot.atlaso.internal", 443, "https://depot.atlaso.internal", "vcf-depot")


def remote(host="old.example", status="DEPOT_CONNECTION_SUCCESSFUL"):
    """Return remote."""
    return {
        "offlineAccount": {"username": "vcf-depot", "status": status, "message": "Depot Status: Success"},
        "depotConfiguration": {"isOfflineDepot": True, "hostname": host, "port": 443, "url": f"https://{host}"},
    }


def test_depot_sanitization_never_returns_passwords():
    """Verify that depot sanitization never returns passwords."""
    payload = remote()
    payload["offlineAccount"]["password"] = "secret"
    sanitized = service.sanitize_remote_depot(payload)
    assert "password" not in sanitized
    assert service.depot_matches(remote("depot.atlaso.internal"), LOCAL)


def test_configure_target_updates_syncs_and_verifies(monkeypatch):
    """Verify that configure target updates syncs and verifies."""
    class FakeClient:
        """Represent fake client."""
        def __init__(self, *_args, **_kwargs):
            """Initialize the fake client."""
            self.current = remote()
            self.sync_calls = 0

        def __enter__(self):
            """Enter the managed context.

            Returns:
                The enter result.
            """
            return self

        def __exit__(self, *_args):
            """Exit the managed context without suppressing exceptions.

            Returns:
                The exit result.
            """
            return None

        def appliance_info(self):
            """Return appliance info."""
            return {"role": "SddcManager", "version": "9.1.0"}

        def depot_settings(self):
            """Return depot settings."""
            return self.current
        def update_depot(self, local, password):
            """Update depot.

            Args:
                local: Local supplied by the caller.
                password: Password supplied for the immediate authenticated operation.

            Returns:
                The update depot result.
            """
            assert password == "one-time"
            self.current = remote(local.hostname)
            return self.current
        def sync_info(self):
            """Return sync info."""
            self.sync_calls += 1
            return {"syncStatus": "COMPLETED", "errorMessage": "", "lastSyncCompletionTimestamp": "new" if self.sync_calls > 1 else "old"}
        def start_sync(self):
            """Return start sync."""
            return {"syncStatus": "IN_PROGRESS"}

    monkeypatch.setattr(service, "VcfDepotApiClient", FakeClient)
    result = service.configure_target_depot("sddc", "admin", "api", LOCAL, "one-time", replace_existing=True, poll_interval=0)
    assert result["configuration"] == "updated"
    assert result["depot"]["status"] == "DEPOT_CONNECTION_SUCCESSFUL"


def test_configure_target_requires_replacement_confirmation(monkeypatch):
    """Verify that configure target requires replacement confirmation."""
    class FakeClient:
        """Represent fake client."""
        def __init__(self, *_args, **_kwargs):
            """Initialize the fake client."""
            pass

        def __enter__(self):
            """Enter the managed context.

            Returns:
                The enter result.
            """
            return self

        def __exit__(self, *_args):
            """Exit the managed context without suppressing exceptions.

            Returns:
                The exit result.
            """
            return None

        def appliance_info(self):
            """Return appliance info."""
            return {"role": "VcfInstaller", "version": "9.1.0"}

        def depot_settings(self):
            """Return depot settings."""
            return remote()

    monkeypatch.setattr(service, "VcfDepotApiClient", FakeClient)
    with pytest.raises(service.VcfDepotTargetError, match="confirm replacement"):
        service.configure_target_depot("installer", "admin", "api", LOCAL, "one-time", replace_existing=False)


def test_update_depot_uses_authenticated_fqdn_port_payload_without_url():
    """Verify that update depot uses authenticated fqdn port payload without url."""
    captured: dict[str, object] = {}

    class FakeResponse:
        """Represent fake response."""
        is_success = True
        status_code = 200

        def json(self):
            """Return json."""
            return remote(LOCAL.hostname)

    class FakeHttpClient:
        """Represent fake http client."""
        def put(self, path, *, json):
            """Return put.

            Args:
                path: Filesystem or URL path to read, validate, or update.
                json: Json supplied by the caller.
            """
            captured["path"] = path
            captured["json"] = json
            return FakeResponse()

    api = service.VcfDepotApiClient.__new__(service.VcfDepotApiClient)
    api.client = FakeHttpClient()

    api.update_depot(LOCAL, "one-time")

    assert captured["path"] == "/v1/system/settings/depot"
    assert captured["json"] == {
        "offlineAccount": {"username": "vcf-depot", "password": "one-time"},
        "depotConfiguration": {
            "isOfflineDepot": True,
            "hostname": "depot.atlaso.internal",
            "port": 443,
        },
    }
