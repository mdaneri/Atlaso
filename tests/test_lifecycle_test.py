"""Test lifecycle test behavior."""

from __future__ import annotations

import argparse
import base64
import html
import importlib.util
import io
import json
import ssl
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def load_lifecycle_module():
    """Return lifecycle module."""
    path = Path(__file__).resolve().parents[1] / "scripts" / "interop" / "lifecycle_test.py"
    spec = importlib.util.spec_from_file_location("lifecycle_test_module", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def load_network_boot_lifecycle_module():
    """Return network boot lifecycle module."""
    path = Path(__file__).resolve().parents[1] / "scripts" / "interop" / "network_boot_lifecycle.py"
    spec = importlib.util.spec_from_file_location("network_boot_lifecycle_module", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_configure_signed_release_source_uses_wizard_edit_data():
    """Update the source identified by the current edit button, not a removed inline form."""
    lifecycle = load_lifecycle_module()
    payload = {"id": 17, "kind": "atlaso", "name": "Signed & Verified", "priority": 42}
    encoded_payload = html.escape(json.dumps(payload), quote=True)
    page = (
        '<input type="hidden" name="csrf" value="csrf-123">'
        '<details data-update-source-group="photon"></details>'
        '<details data-update-source-group="atlaso">'
        '<button data-update-source-wizard-open data-update-source-mode="edit" '
        'data-update-source-kind="atlaso" data-update-source=\'' + encoded_payload + "'></button>"
        '</details>'
    )

    class FakeClient:
        """Serve the rendered wizard data and check the submitted source fields."""

        def request(self, method, path, **kwargs):  # type: ignore[no-untyped-def]  # Fake models the lifecycle client boundary.
            if (method, path) == ("GET", "/appliance-update"):
                return 200, page, {}
            assert (method, path) == ("POST", "/appliance-update/sources/17")
            assert kwargs["form"] == {
                "csrf": "csrf-123",
                "name": "Signed & Verified",
                "url": "https://release-fixture.example.test/updates",
                "priority": "42",
                "enabled_present": "1",
                "enabled": "on",
                "channel": "preview",
            }
            assert kwargs["headers"] == {"X-Atlaso-Autosave": "1", "Accept": "application/json"}
            assert kwargs["follow_redirects"] is False
            return 200, '{"status":"saved"}', {}

    result = lifecycle._configure_signed_release_source(
        FakeClient(),
        argparse.Namespace(signed_release_repository_url="https://release-fixture.example.test/updates/"),
        channel="preview",
    )
    assert result == {
        "source_id": 17,
        "source_name": "Signed & Verified",
        "base_url": "https://release-fixture.example.test/updates",
        "channel": "preview",
    }


def test_signed_release_availability_check_confirms_current_candidate(monkeypatch):
    """Submit and await the exact Atlaso Release check before installation.

    Args:
        monkeypatch: Replace polling delay for the bounded fake task.
    """
    lifecycle = load_lifecycle_module()
    monkeypatch.setattr(lifecycle.time, "sleep", lambda _seconds: None)

    class FakeClient:
        """Serve the browser check form and its exact task status."""

        polls = 0

        def request(self, method, path, **kwargs):  # type: ignore[no-untyped-def]  # Fake models the lifecycle client boundary.
            if (method, path) == ("GET", "/appliance-update"):
                return 200, '<input type="hidden" name="csrf" value="csrf-123">', {}
            assert (method, path) == ("POST", "/appliance-update/check")
            assert kwargs["form"] == [("csrf", "csrf-123"), ("selected_streams", "atlaso_release")]
            assert kwargs["headers"] == {"Accept": "application/json"}
            return 202, '{"job_id":"job_abcdef123456"}', {}

        def json_request(self, method, path):  # type: ignore[no-untyped-def]  # Fake returns the exact submitted task.
            assert (method, path) == ("GET", "/tasks/job_abcdef123456/status")
            self.polls += 1
            if self.polls == 1:
                return {"task": {"status": "running"}}
            return {"task": {
                "status": "succeeded",
                "_children": [{"component_key": "atlaso_release", "status": "succeeded"}],
                "result": {"stream_results": {"atlaso_release": {"availability": {"update_available": True}}}},
            }}

    client = FakeClient()
    assert lifecycle._check_signed_release_availability(client) == "job_abcdef123456"
    assert client.polls == 2


def test_signed_release_availability_check_rejects_up_to_date_candidate(monkeypatch):
    """Do not install when a successful check reports no candidate.

    Args:
        monkeypatch: Replace the task submission with a deterministic fake.
    """
    lifecycle = load_lifecycle_module()

    class FakeClient:
        """Report a successful but up-to-date signed-release check."""

        def request(self, method, path, **_kwargs):  # type: ignore[no-untyped-def]  # Fake models the lifecycle client boundary.
            if method == "GET":
                return 200, '<input type="hidden" name="csrf" value="csrf-123">', {}
            assert path == "/appliance-update/check"
            return 202, '{"job_id":"job_abcdef123456"}', {}

        def json_request(self, method, path):  # type: ignore[no-untyped-def]  # Fake returns the exact submitted task.
            assert (method, path) == ("GET", "/tasks/job_abcdef123456/status")
            return {"task": {
                "status": "succeeded",
                "_children": [{"component_key": "atlaso_release", "status": "succeeded"}],
                "result": {"stream_results": {"atlaso_release": {"availability": {"update_available": False}}}},
            }}

    with pytest.raises(lifecycle.LifecycleError, match="did not confirm an available update"):
        lifecycle._check_signed_release_availability(FakeClient())


def test_signed_release_lifecycle_rechecks_after_channel_change(monkeypatch):
    """Check each channel after configuring it and before its install.

    Args:
        monkeypatch: Replace appliance operations with deterministic evidence.
    """
    lifecycle = load_lifecycle_module()
    events = []
    before = {"current_release": "release-v1", "compatibility_venv": "venv", "schema_sha256": "schema", "users": []}
    after = {**before, "current_release": "release-v2"}
    identities = iter((before, after, after, after, after, after))
    monkeypatch.setattr(lifecycle, "_release_database_identity", lambda _args: next(identities))
    monkeypatch.setattr(lifecycle, "_configure_signed_release_source", lambda _client, _args, *, channel: events.append(f"source:{channel}") or {})
    monkeypatch.setattr(lifecycle, "_check_signed_release_availability", lambda _client: events.append("check") or "job_abcdef123456")

    def submit(_client, *, expected_status):  # type: ignore[no-untyped-def]  # Fake records the release task selected by the lifecycle.
        events.append(f"install:{expected_status}")
        transaction = (
            {"candidate_version": "0.9.2"}
            if expected_status == "succeeded"
            else {"rolled_back": True, "rollback_health": True, "failure_layer": "nginx_configuration"}
        )
        return {"id": "job_123456abcdef", "result": {"release_transaction": transaction}}

    monkeypatch.setattr(lifecycle, "_submit_signed_release_update", submit)
    monkeypatch.setattr(lifecycle, "appliance_health", lambda _client, _args: {"version": {"base_version": "0.9.2"}})
    monkeypatch.setattr(lifecycle, "_reboot_appliance_and_wait", lambda _client, _args: {})
    monkeypatch.setattr(lifecycle.time, "sleep", lambda _seconds: None)
    args = argparse.Namespace(signed_release_repository_url="https://release-fixture.example.test/updates")

    result = lifecycle.signed_release_update_check(object(), args)

    assert events == [
        "source:preview", "check", "install:succeeded",
        "source:development", "check", "install:failed",
    ]
    assert result["preview_check_task_id"] == "job_abcdef123456"
    assert result["development_check_task_id"] == "job_abcdef123456"


def test_load_lifecycle_secrets_populates_passwords_from_stdin_envelope():
    """Verify that lifecycle secrets are validated and loaded without argv values."""
    lifecycle = load_lifecycle_module()
    args = lifecycle.parse_args(["--secret-stdin"])
    secret_values = {
        "password": "AdminSecret!",
        "appliance_ssh_password": "ApplianceSecret!",
        "ssh_password": "ClientSecret!",
        "vcf_backup_password": "BackupSecret!",
        "esxi_password": "EsxiSecret!",
    }

    lifecycle.load_lifecycle_secrets(args, io.StringIO(json.dumps(secret_values)))

    assert args.password == secret_values["password"]
    assert args.appliance_ssh_password == secret_values["appliance_ssh_password"]
    assert args.ssh_password == secret_values["ssh_password"]
    assert args.vcf_backup_password == secret_values["vcf_backup_password"]
    assert args.esxi_password == secret_values["esxi_password"]


def test_load_lifecycle_secrets_rejects_unexpected_schema():
    """Verify that stdin secret envelopes fail closed on unexpected fields."""
    lifecycle = load_lifecycle_module()
    args = lifecycle.parse_args(["--secret-stdin"])
    secret_values = {
        "password": "AdminSecret!",
        "appliance_ssh_password": "ApplianceSecret!",
        "ssh_password": "ClientSecret!",
        "vcf_backup_password": "BackupSecret!",
        "esxi_password": "",
        "unexpected": "value",
    }

    with pytest.raises(lifecycle.LifecycleError, match="required schema"):
        lifecycle.load_lifecycle_secrets(args, io.StringIO(json.dumps(secret_values)))


@pytest.mark.parametrize("focused_option", ["--oidc-only", "--routing-wan-only"])
def test_load_lifecycle_secrets_allows_focused_runs_without_vcf_backup_password(focused_option):
    """Verify focused modes omit the unrelated VCF Backup credential.

    Args:
        focused_option: Focused lifecycle option under test.
    """
    lifecycle = load_lifecycle_module()
    args = lifecycle.parse_args(["--secret-stdin", focused_option])
    secret_values = {
        "password": "AdminSecret!",
        "appliance_ssh_password": "ApplianceSecret!",
        "ssh_password": "ClientSecret!",
    }

    lifecycle.load_lifecycle_secrets(args, io.StringIO(json.dumps(secret_values)))

    assert args.vcf_backup_password == ""
    assert args.esxi_password == ""


def test_load_lifecycle_secrets_requires_vcf_backup_password_for_full_run():
    """Verify the full lifecycle still requires its VCF Backup credential."""
    lifecycle = load_lifecycle_module()
    args = lifecycle.parse_args(["--secret-stdin"])
    secret_values = {
        "password": "AdminSecret!",
        "appliance_ssh_password": "ApplianceSecret!",
        "ssh_password": "ClientSecret!",
    }

    with pytest.raises(lifecycle.LifecycleError, match="requires a VCF Backup password"):
        lifecycle.load_lifecycle_secrets(args, io.StringIO(json.dumps(secret_values)))


def test_network_boot_lifecycle_extracts_csrf_without_password_query_login():
    """Verify that network boot lifecycle extracts csrf without password query login."""
    lifecycle = load_network_boot_lifecycle_module()
    assert lifecycle.csrf_from_page('<input type="hidden" name="csrf" value="csrf-158">') == "csrf-158"
    source = Path(lifecycle.__file__).read_text(encoding="utf-8")
    assert "/api/v1/auth/login?" not in source
    assert '"password": password' in source


def write_baseline(path: Path, *, fingerprint: str = "abc123") -> None:
    """Persist baseline.

    Args:
        path: Filesystem or URL path to read, validate, or update.
        fingerprint: Fingerprint supplied by the caller.
    """
    path.write_text(
        """
{
  "steps": [
    {
      "name": "ca-client-certificate-check",
      "status": "passed",
      "evidence": {
        "common_name": "client-a.atlaso.internal",
        "certificate": {
          "serial_number": "01",
          "sha256_fingerprint": "%s",
          "subject": "CN=client-a.atlaso.internal",
          "issuer": "CN=Atlaso Internal Root CA"
        }
      }
    }
  ]
}
"""
        % fingerprint,
        encoding="utf-8",
    )


def test_restored_certificate_baseline_check_matches_fingerprint(tmp_path):
    """Verify that restored certificate baseline check matches fingerprint.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    lifecycle = load_lifecycle_module()
    baseline = tmp_path / "result.json"
    write_baseline(baseline)
    args = argparse.Namespace(certificate_baseline_result=str(baseline))

    evidence = lifecycle.restored_certificate_baseline_check(
        args,
        {
            "common_name": "client-a.atlaso.internal",
            "certificate": {
                "serial_number": "01",
                "sha256_fingerprint": "abc123",
                "subject": "CN=client-a.atlaso.internal",
                "issuer": "CN=Atlaso Internal Root CA",
            },
        },
    )

    assert evidence["sha256_fingerprint"] == "abc123"


def test_restored_certificate_baseline_check_rejects_changed_fingerprint(tmp_path):
    """Verify that restored certificate baseline check rejects changed fingerprint.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    lifecycle = load_lifecycle_module()
    baseline = tmp_path / "result.json"
    write_baseline(baseline)
    args = argparse.Namespace(certificate_baseline_result=str(baseline))

    with pytest.raises(lifecycle.LifecycleError, match="does not match pre-restore certificate"):
        lifecycle.restored_certificate_baseline_check(
            args,
            {
                "common_name": "client-a.atlaso.internal",
                "certificate": {
                    "serial_number": "01",
                    "sha256_fingerprint": "changed",
                    "subject": "CN=client-a.atlaso.internal",
                    "issuer": "CN=Atlaso Internal Root CA",
                },
            },
        )


def test_wan_policy_payload_sets_loss_without_changing_latency_baseline():
    """Verify that wan policy payload sets loss without changing latency baseline."""
    lifecycle = load_lifecycle_module()

    payload = lifecycle.wan_policy_payload(packet_loss_percent=100.0)

    assert payload["name"] == "Lifecycle WAN"
    assert payload["latency_ms"] == 25
    assert payload["jitter_ms"] == 5
    assert payload["packet_loss_percent"] == 100.0
    assert payload["bandwidth_mbit"] == 100


def test_set_lifecycle_wan_policy_updates_duplicate_restored_rows():
    """Verify that set lifecycle wan policy updates duplicate restored rows."""
    lifecycle = load_lifecycle_module()

    class FakeClient:
        """Represent fake client.

        Attributes:
            patched: Patched captured or supplied by this test helper.
        """
        def __init__(self) -> None:
            """Initialize the fake client."""
            self.patched: list[tuple[str, dict[str, object]]] = []

        def json_request(self, method: str, path: str, json_body=None):  # type: ignore[no-untyped-def]  # Fake accepts the production client's dynamic payload shape.
            """Return json request.

            Args:
                method: HTTP or protocol method to invoke.
                path: Filesystem or URL path to read, validate, or update.
                json_body: Json body supplied by the caller.
            """
            if method == "GET" and path == "/api/v1/wan/policies":
                return [
                    {"id": 1, "name": "Lifecycle WAN"},
                    {"id": 2, "name": "Other WAN"},
                    {"id": 3, "name": "Lifecycle WAN"},
                ]
            assert method == "PATCH"
            assert json_body is not None
            self.patched.append((path, json_body))
            return {"id": int(path.rsplit("/", 1)[-1]), **json_body}

    client = FakeClient()
    result = lifecycle.set_lifecycle_wan_policy(client, packet_loss_percent=100.0)

    assert [path for path, _payload in client.patched] == ["/api/v1/wan/policies/1", "/api/v1/wan/policies/3"]
    assert [payload["packet_loss_percent"] for _path, payload in client.patched] == [100.0, 100.0]
    assert result["updated_count"] == 2


def test_appliance_health_checks_version_before_authentication(monkeypatch):
    """Verify that appliance health checks version before authentication.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    lifecycle = load_lifecycle_module()
    calls: list[tuple[str, str]] = []
    version_payload = {
        "version": "0.9.87",
        "base_version": "0.9.87",
        "git_commit": "0123456789abcdef0123456789abcdef01234567",
        "built_at": "2026-08-09T20:15:00Z",
    }

    class FakeClient:
        """Represent fake client.

        Attributes:
            base_url: URL used for base.
        """
        base_url = "https://192.0.2.10"

        def request(self, method, path):  # type: ignore[no-untyped-def]  # Minimal fake models only arguments exercised by this test.
            """Return request.

            Args:
                method: HTTP or protocol method to invoke.
                path: Filesystem or URL path to read, validate, or update.
            """
            calls.append((method, path))
            return 200, "{}", {}

        def json_request(self, method, path):  # type: ignore[no-untyped-def]  # Minimal fake models only arguments exercised by this test.
            """Return json request.

            Args:
                method: HTTP or protocol method to invoke.
                path: Filesystem or URL path to read, validate, or update.
            """
            calls.append((method, path))
            assert path == "/api/v1/dashboard"
            return {"services": []}

    class AnonymousVersionClient:
        """Represent anonymous version client."""
        def __init__(self, base_url):  # type: ignore[no-untyped-def]  # Minimal fake stores the untyped lifecycle URL.
            """Initialize the anonymous version client.

            Args:
                base_url: URL used for base.
            """
            assert base_url == FakeClient.base_url

        def json_request(self, method, path):  # type: ignore[no-untyped-def]  # Minimal fake models only arguments exercised by this test.
            """Return json request.

            Args:
                method: HTTP or protocol method to invoke.
                path: Filesystem or URL path to read, validate, or update.
            """
            calls.append((method, path))
            assert path == "/api/v1/version"
            return version_payload

    monkeypatch.setattr(lifecycle, "HttpClient", AnonymousVersionClient)
    monkeypatch.setattr(lifecycle, "api_login", lambda client, args: calls.append(("AUTH", "api")))
    monkeypatch.setattr(lifecycle, "ui_login", lambda client, args: calls.append(("AUTH", "ui")))
    monkeypatch.setattr(
        lifecycle,
        "ssh_command",
        lambda *args, **kwargs: {"returncode": 0, "stdout": "", "stderr": "", "command": "redacted"},
    )

    evidence = lifecycle.appliance_health(FakeClient(), argparse.Namespace(appliance_ssh_host="192.0.2.10"))

    assert calls.index(("GET", "/api/v1/version")) < calls.index(("AUTH", "api"))
    assert evidence["version"] == version_payload


def test_appliance_console_geometry_requires_deployed_framebuffer_and_tty1(monkeypatch):
    """Verify lifecycle coverage requires the deployed 1280x800 50-row console.

    Args:
        monkeypatch: Pytest fixture used to replace lifecycle dependencies.
    """
    lifecycle = load_lifecycle_module()
    commands: list[str] = []

    def fake_ssh_command(host, command_args, command, *, role):  # type: ignore[no-untyped-def]  # Fake mirrors the lifecycle SSH helper.
        """Return deployed console geometry evidence.

        Args:
            host: Appliance host selected by the lifecycle test.
            command_args: Parsed lifecycle command arguments.
            command: Remote shell command issued by the check.
            role: Lifecycle SSH role used for the command.
        """
        assert host == "192.0.2.10"
        assert command_args.appliance_ssh_host == host
        assert role == "appliance"
        commands.append(command)
        return {
            "returncode": 0,
            "stdout": "1280,800\n50 160\n",
            "stderr": "",
            "command": "redacted",
        }

    monkeypatch.setattr(lifecycle, "ssh_command", fake_ssh_command)

    evidence = lifecycle.appliance_console_geometry(
        argparse.Namespace(appliance_ssh_host="192.0.2.10")
    )

    assert "/sys/class/graphics/fb0/virtual_size" in commands[0]
    assert "stty -F /dev/tty1 size" in commands[0]
    assert "printf" not in commands[0]
    assert evidence["framebuffer_virtual_size"] == "1280,800"
    assert evidence["tty1_rows_columns"] == "50 160"

    def wrong_geometry(host, command_args, command, *, role):  # type: ignore[no-untyped-def]  # Fake mirrors the lifecycle SSH helper.
        """Return a healthy command with the wrong tty1 dimensions.

        Args:
            host: Appliance host selected by the lifecycle test.
            command_args: Parsed lifecycle command arguments.
            command: Remote shell command issued by the check.
            role: Lifecycle SSH role used for the command.
        """
        assert host and command_args and command and role
        return {"returncode": 0, "stdout": "1280,800\n48 160\n", "stderr": "", "command": "redacted"}

    monkeypatch.setattr(lifecycle, "ssh_command", wrong_geometry)
    with pytest.raises(lifecycle.LifecycleError, match="console geometry did not match"):
        lifecycle.appliance_console_geometry(argparse.Namespace(appliance_ssh_host="192.0.2.10"))


def test_authentication_lifetime_uses_appliance_issuance_clock(monkeypatch):
    """Verify token policy from server timestamps when host and appliance clocks differ.

    Args:
        monkeypatch: Pytest fixture used to replace lifecycle dependencies.
    """
    lifecycle = load_lifecycle_module()
    policy = {"browser_session_idle_timeout_minutes": 30, "api_token_max_lifetime_days": 90}

    class PolicyClient:
        """Serve policy reads and immediate autosave writes."""

        def json_request(self, method, path):  # type: ignore[no-untyped-def]  # Fake mirrors the lifecycle HTTP client.
            """Return the currently persisted policy.

            Args:
                method: HTTP method requested by the lifecycle check.
                path: API path requested by the lifecycle check.
            """
            assert method == "GET" and path == "/api/v1/settings"
            return policy.copy()

        def request(self, method, path, *, form=None, headers=None):  # type: ignore[no-untyped-def]  # Fake mirrors the lifecycle HTTP client.
            """Serve the settings page and autosave endpoint.

            Args:
                method: HTTP method requested by the lifecycle check.
                path: UI path requested by the lifecycle check.
                form: Submitted settings values, when present.
                headers: Request headers, when present.
            """
            if method == "GET":
                assert path == "/settings"
                return 200, "settings", {}
            assert method == "POST" and path == "/settings/authentication-lifetimes"
            assert form and headers == {"X-Atlaso-Autosave": "1"}
            policy["browser_session_idle_timeout_minutes"] = form["browser_session_idle_timeout_minutes"]
            policy["api_token_max_lifetime_days"] = form["api_token_max_lifetime_days"]
            return 200, "saved", {}

    class IssuanceClient:
        """Serve a seven-day token issued by an appliance clock one day ahead."""

        def __init__(self, base_url):  # type: ignore[no-untyped-def]  # Fake mirrors the lifecycle HTTP client.
            """Retain the selected appliance URL.

            Args:
                base_url: Appliance URL selected by the lifecycle check.
            """
            assert base_url == "https://192.0.2.10"

        def json_request(self, method, path, *, json_body):  # type: ignore[no-untyped-def]  # Fake mirrors the lifecycle HTTP client.
            """Return server-side creation and expiration timestamps.

            Args:
                method: HTTP method requested by the lifecycle check.
                path: API path requested by the lifecycle check.
                json_body: Login request payload.
            """
            assert method == "POST" and path.startswith("/api/v1/auth/login?")
            assert json_body["scopes"] == ["read:dashboard"]
            return {"token": {"created_at": "2026-09-23T00:00:00+00:00", "expires_at": "2026-09-30T00:00:00+00:00"}}

        def request(self, method, path, *, json_body):  # type: ignore[no-untyped-def]  # Fake mirrors the lifecycle HTTP client.
            """Reject an explicit expiry beyond the seven-day policy.

            Args:
                method: HTTP method requested by the lifecycle check.
                path: API path requested by the lifecycle check.
                json_body: Login request payload.
            """
            assert method == "POST" and path.startswith("/api/v1/auth/login?")
            assert json_body["expires_at"] == "2026-10-01T00:00:00+00:00"
            return 422, "configured maximum lifetime of 7 days", {}

    monkeypatch.setattr(lifecycle, "authenticated_ui_client", lambda client, args: PolicyClient())
    monkeypatch.setattr(lifecycle, "extract_csrf", lambda page: "csrf")
    monkeypatch.setattr(lifecycle, "HttpClient", IssuanceClient)
    evidence = lifecycle.authentication_lifetime_policy_check(
        argparse.Namespace(base_url="https://192.0.2.10", username="admin", password="test"),
        argparse.Namespace(username="admin", password="test"),
    )
    assert evidence["issued_lifetime_seconds"] == 7 * 24 * 60 * 60
    assert policy == {"browser_session_idle_timeout_minutes": 30, "api_token_max_lifetime_days": 90}


def test_reboot_appliance_waits_for_new_boot_and_host_facing_readiness(monkeypatch):
    """Verify reboot coverage requires a changed boot ID and recovered nginx front door.

    Args:
        monkeypatch: Pytest fixture used to replace lifecycle dependencies.
    """
    lifecycle = load_lifecycle_module()
    boot_ids = iter(
        [
            "11111111-1111-1111-1111-111111111111",
            "22222222-2222-2222-2222-222222222222",
            "22222222-2222-2222-2222-222222222222",
        ]
    )
    monkeypatch.setattr(lifecycle, "_appliance_boot_id", lambda _args: next(boot_ids))

    class FakeClient:
        """Model the authenticated reboot request."""

        base_url = "https://192.0.2.10"

        def request(self, method, path, **_kwargs):  # type: ignore[no-untyped-def]  # Minimal fake accepts the production client's dynamic request shape.
            """Return one simulated authenticated management response.

            Args:
                method: HTTP method requested by the lifecycle runner.
                path: Management route requested by the lifecycle runner.
                **_kwargs: Additional request options accepted by the production client.
            """
            if (method, path) == ("GET", "/dashboard"):
                return 200, '<input type="hidden" name="csrf" value="csrf-367">', {}
            if (method, path) == ("POST", "/appliance/power/reboot"):
                return 303, "", {}
            raise AssertionError(f"unexpected authenticated request: {method} {path}")

    class ProbeClient:
        """Model an interrupted and then recovered host-facing endpoint."""

        calls = 0

        def __init__(self, _base_url):  # type: ignore[no-untyped-def]  # Minimal fake stores only the untyped lifecycle URL.
            """Initialize the simulated host-facing probe client.

            Args:
                _base_url: Management base URL accepted for production compatibility.
            """
            pass

        def request(self, method, path, **_kwargs):  # type: ignore[no-untyped-def]  # Minimal fake accepts the production client's dynamic request shape.
            """Return one simulated host-facing readiness response.

            Args:
                method: HTTP method requested by the lifecycle runner.
                path: Management route requested by the lifecycle runner.
                **_kwargs: Additional request options accepted by the production client.
            """
            assert (method, path) == ("GET", "/openapi.json")
            type(self).calls += 1
            if self.calls == 1:
                return 503, "{}", {}
            if self.calls == 2:
                raise lifecycle.urllib.error.URLError("nginx is still starting")
            return 200, "{}", {}

    monkeypatch.setattr(lifecycle, "HttpClient", ProbeClient)
    monkeypatch.setattr(lifecycle.time, "sleep", lambda _seconds: None)

    evidence = lifecycle._reboot_appliance_and_wait(FakeClient(), argparse.Namespace())

    assert evidence == {
        "scheduled": True,
        "endpoint_interrupted": True,
        "boot_id_changed": True,
        "openapi_status": 200,
    }
    assert ProbeClient.calls == 4


def test_routing_wan_only_plan_and_routing_rule_payload():
    """Verify that routing wan only plan and routing rule payload."""
    lifecycle = load_lifecycle_module()
    args = lifecycle.parse_args(["--password", "test", "--routing-wan-only", "--plan-only"])

    plan = lifecycle.lifecycle_plan(args)
    payload = lifecycle.routing_rule_form_payload(args)

    assert plan["routing_wan_only"] is True
    assert payload == {
        "name": "Lifecycle SiteA to WAN",
        "source_interface": "eth1",
        "destination_interface": "eth3",
        "priority": "100",
        "description": "Lifecycle explicit access-network routing permission.",
        "enabled": "on",
    }


def test_oidc_only_plan_is_focused_and_mutually_exclusive():
    """Verify that oidc only plan is focused and mutually exclusive."""
    lifecycle = load_lifecycle_module()
    args = lifecycle.parse_args(["--password", "test", "--oidc-only", "--plan-only"])

    plan = lifecycle.lifecycle_plan(args)

    assert plan["oidc_only"] is True
    assert plan["routing_wan_only"] is False
    assert plan["checks"] == [
        "appliance health",
        "addressed OIDC access listener and applied managed certificate",
        (
            "OIDC Authorization Code, explicit Local selection, client-specific "
            "local-role group mapping, scope-filtered claims, PKCE S256, signed "
            "browser session, five-minute RS256 tokens, UserInfo revalidation, "
            "replay rejection, and exact logout redirect"
        ),
    ]
    assert plan["apply_units"] == ["network", "firewall", "ca", "public_services"]
    with pytest.raises(SystemExit):
        lifecycle.parse_args(
            ["--password", "test", "--oidc-only", "--routing-wan-only"]
        )


def test_focused_oidc_prepares_applied_listener_and_certificate_before_authorization(monkeypatch):
    """Verify the focused check uses the applied site listener with trusted TLS and firewall.

    Args:
        monkeypatch: Fixture used to capture lifecycle steps without appliance calls.
    """
    lifecycle = load_lifecycle_module()
    calls = []
    applied_units = []
    checked_client = []
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Lifecycle test root")])
    now = datetime.now(timezone.utc)
    root_ca_pem = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
        .decode("ascii")
    )

    class ManagementClient:
        def request(self, method, path):  # type: ignore[no-untyped-def]  # Focused management transport stub.
            """Return the test CA root from the management download endpoint.

            Args:
                method: HTTP method requested by the lifecycle setup.
                path: Management API path requested by the lifecycle setup.
            """
            assert (method, path) == ("GET", "/certificate-authority/downloads/root-ca.pem")
            return 200, root_ca_pem, {}

    def capture_step(_results, name, _func, *_args):  # type: ignore[no-untyped-def]  # Lifecycle steps have heterogeneous arguments.
        """Capture the ordered focused steps and their relevant arguments.

        Args:
            _results: Result collection unused by this stub.
            name: Lifecycle step name under test.
            _func: Step callable bypassed by this stub.
            *_args: Step arguments inspected for listener and apply behavior.
        """
        calls.append(name)
        if name == "configure-oidc-provider":
            return {"listen_addresses": ["192.168.12.1"], "port": 443}
        if name == "apply-oidc-certificate-and-listener":
            applied_units.extend(_args[1])
        if name == "oidc-authorization-code-check":
            checked_client.append(_args[2])

    monkeypatch.setattr(lifecycle, "run_step", capture_step)
    lifecycle.run_oidc_lifecycle(
        [],
        ManagementClient(),
        lifecycle.parse_args(["--password", "test", "--oidc-only", "--site-cidr", "192.168.12.1/24"]),
    )
    assert calls == [
        "appliance-health",
        "configure-oidc-listener",
        "apply-oidc-network",
        "configure-ca",
        "configure-oidc-provider",
        "apply-oidc-certificate-and-listener",
        "oidc-authorization-code-check",
    ]
    assert applied_units == ["ca", "firewall", "public_services"]
    assert checked_client[0].base_url == "https://192.168.12.1:443"
    assert checked_client[0].https_context.verify_mode == ssl.CERT_REQUIRED
    assert checked_client[0].https_context.check_hostname is True
    assert checked_client[0].https_context.get_ca_certs()


def test_focused_oidc_provider_rejects_unready_certificate():
    """The focused setup must fail if provider enablement still lacks its certificate."""
    lifecycle = load_lifecycle_module()

    class Client:
        def json_request(self, method, path, **_kwargs):  # type: ignore[no-untyped-def]  # Test client mirrors dynamic HTTP calls.
            """Return signing-key and provider state for the focused test.

            Args:
                method: HTTP method requested by provider setup.
                path: API path requested by provider setup.
                **_kwargs: Additional request options unused by this stub.
            """
            if path == "/api/v1/oidc/signing-keys":
                return [{"status": "active"}]
            if path == "/api/v1/oidc/provider":
                return {"port": 443}
            raise AssertionError((method, path))

        def request(self, method, path, **_kwargs):  # type: ignore[no-untyped-def]  # Test client mirrors dynamic HTTP calls.
            """Return an unready provider form after the CSRF request.

            Args:
                method: HTTP method requested by provider setup.
                path: Provider form path requested by setup.
                **_kwargs: Additional request options unused by this stub.
            """
            if method == "GET":
                return 200, '<input name="csrf" value="test-token">', {}
            assert path == "/authentication/oidc/provider"
            return 200, json.dumps({"enabled": False, "valid": False, "validation_errors": ["certificate unavailable"]}), {}

    with pytest.raises(lifecycle.LifecycleError, match="certificate unavailable"):
        lifecycle.configure_oidc_provider(Client(), lifecycle.parse_args(["--password", "test", "--oidc-only"]))


def test_focused_oidc_authorization_uses_public_listener_after_management_setup():
    """The browser flow must leave the management listener after client registration."""
    lifecycle = load_lifecycle_module()

    class ManagementClient:
        def json_request(self, method, path, **_kwargs):  # type: ignore[no-untyped-def]  # Focused API transport stub.
            """Return management API state needed before the public request.

            Args:
                method: HTTP method used for setup.
                path: Management API path used for setup.
                **_kwargs: Additional request options unused by this stub.
            """
            if (method, path) == ("GET", "/api/v1/oidc/signing-keys"):
                return [{"status": "active"}]
            if (method, path) == ("POST", "/api/v1/oidc/clients"):
                return {"client": {"id": 1, "client_id": "lifecycle"}, "client_secret": "test-secret"}
            if (method, path) == ("POST", "/api/v1/oidc/group-mappings"):
                return {}
            if (method, path) == ("GET", "/api/v1/oidc/provider"):
                return {"port": 443, "hostname": "core.atlaso.internal"}
            if (method, path) == ("PUT", "/api/v1/oidc/provider"):
                assert _kwargs["json_body"]["issuer_url"] == "https://core.atlaso.internal/identity"
                return {"enabled": True, "valid": True}
            raise AssertionError((method, path))

        def request(self, *_args, **_kwargs):  # type: ignore[no-untyped-def]  # Public OIDC traffic must not use this client.
            """Reject any browser request sent to the management listener.

            Args:
                *_args: Positional request values forbidden on this client.
                **_kwargs: Keyword request values forbidden on this client.
            """
            raise AssertionError("OIDC browser traffic used the management listener")

    class ReachedPublicListener(Exception):
        pass

    class PublicClient:
        def request(self, method, path, **_kwargs):  # type: ignore[no-untyped-def]  # Stops at the first public request.
            """Confirm the authorization request reaches the public listener.

            Args:
                method: HTTP method used by the browser flow.
                path: Public OIDC path requested by the browser flow.
                **_kwargs: Additional request options unused by this stub.
            """
            assert method == "GET"
            assert path.startswith("/identity/authorize?")
            raise ReachedPublicListener

    with pytest.raises(ReachedPublicListener):
        lifecycle.oidc_authorization_code_check(
            ManagementClient(),
            lifecycle.parse_args(["--password", "test", "--oidc-only"]),
            PublicClient(),
        )


@pytest.mark.parametrize(
    ("mode", "expected_hostname"),
    [(["--oidc-only"], "core.atlaso.internal"), ([], "oidc.atlaso.internal")],
)
def test_oidc_provider_sets_access_listener_before_enabling(mode, expected_hostname):
    """Provider setup must send a distinct full-lifecycle name and addressed listener.

    Args:
        mode: Lifecycle mode under test.
        expected_hostname: Expected site hostname.
    """
    lifecycle = load_lifecycle_module()
    submitted = {}

    class Client:
        def json_request(self, method, path, **_kwargs):  # type: ignore[no-untyped-def]  # Test client mirrors dynamic HTTP calls.
            """Return provider and signing-key state for listener setup.

            Args:
                method: HTTP method requested by provider setup.
                path: API path requested by provider setup.
                **_kwargs: Additional request options unused by this stub.
            """
            if path == "/api/v1/oidc/signing-keys":
                return [{"status": "active"}]
            if path == "/api/v1/oidc/provider":
                return {"port": 443}
            raise AssertionError((method, path))

        def request(self, method, path, **kwargs):  # type: ignore[no-untyped-def]  # Test client mirrors dynamic HTTP calls.
            """Capture the addressed listener submitted through the provider form.

            Args:
                method: HTTP method requested by provider setup.
                path: Provider form path requested by setup.
                **kwargs: Request options containing the submitted form.
            """
            if method == "GET":
                return 200, '<input name="csrf" value="test-token">', {}
            assert path == "/authentication/oidc/provider"
            submitted.update(kwargs["form"])
            return 200, json.dumps({"enabled": True, "valid": True, "hostname": expected_hostname, "listen_addresses": ["192.0.2.1"]}), {}

    result = lifecycle.configure_oidc_provider(
        Client(), lifecycle.parse_args(["--password", "test", *mode, "--site-interface", "eth1"])
    )
    assert result["enabled"] is True
    assert result["port"] == 443
    assert submitted["listen_interfaces"] == ["eth1"]
    assert submitted["hostname"] == expected_hostname
    assert submitted["csrf"] == "test-token"


def test_full_oidc_site_listener_uses_client_and_verifies_ca(monkeypatch):
    """The full lab must probe the site-only listener from its reachable client.

    Args:
        monkeypatch: Replace external behavior for this scenario.
    """
    lifecycle = load_lifecycle_module()
    args = lifecycle.parse_args(["--password", "test", "--site-cidr", "192.168.12.1/24"])
    args.client_a_host = "192.0.2.10"
    calls = []

    def fake_ssh_command(host, _args, command, *, role):
        """Fake ssh command.

        Args:
            host: Host selected for the simulated SSH command.
            _args: Unused lifecycle arguments accepted by the fake.
            command: Command issued by the scenario.
            role: Role selected for the simulated SSH command.
        """
        calls.append((host, command, role))
        return {"returncode": 0, "stdout": "200", "stderr": ""}

    monkeypatch.setattr(lifecycle, "ssh_command", fake_ssh_command)
    result = lifecycle.oidc_site_listener_check(
        args,
        {"hostname": "oidc.atlaso.internal", "port": 443, "listen_addresses": ["192.168.12.1"]},
    )

    assert result == {"site_address": "192.168.12.1", "http_status": 200, "tls_verified": True}
    assert calls[0][0] == args.client_a_host
    assert calls[0][2] == "client"
    assert "--cacert /tmp/atlaso-root-ca.pem" in calls[0][1]
    assert "dig +short A oidc.atlaso.internal @192.168.12.1" in calls[0][1]
    assert "grep -qFx 192.168.12.1" in calls[0][1]
    assert "--resolve" not in calls[0][1]
    assert "https://oidc.atlaso.internal:443/identity/.well-known/openid-configuration" in calls[0][1]
    assert " -k" not in calls[0][1]


@pytest.mark.parametrize("server_ready", [False, True])
def test_ntp_client_check_waits_for_synchronized_server(monkeypatch, server_ready):
    """Do not judge client NTS/NTP while a new server advertises leap_alarm.

    Args:
        monkeypatch: Replace external behavior for this scenario.
        server_ready: Whether the NTP server reports synchronization.
    """
    lifecycle = load_lifecycle_module()
    args = lifecycle.parse_args([
        "--password", "test", "--client-a-host", "192.0.2.11", "--appliance-ssh-host", "192.0.2.10",
    ])
    calls = []

    def fake_wait(host, _args, command, **kwargs):
        """Fake wait.

        Args:
            host: Host selected for the simulated SSH command.
            _args: Unused lifecycle arguments accepted by the fake.
            command: Command issued by the scenario.
            **kwargs: Additional request arguments accepted by the fake.
        """
        calls.append(("wait", host, command, kwargs))
        if not server_ready:
            raise lifecycle.LifecycleError("appliance NTP synchronization failed")
        return {"attempts": 3}

    def fake_ssh(host, _args, command, *, role):
        """Fake ssh.

        Args:
            host: Host selected for the simulated SSH command.
            _args: Unused lifecycle arguments accepted by the fake.
            command: Command issued by the scenario.
            role: Role selected for the simulated SSH command.
        """
        calls.append(("client", host, command, role))
        return {"returncode": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(lifecycle, "ssh_until_success", fake_wait)
    monkeypatch.setattr(lifecycle, "ssh_command", fake_ssh)
    if server_ready:
        evidence = lifecycle.ntp_client_checks(args)
        assert evidence["server_synchronization_attempts"] == 3
        assert calls[1][0] == "client"
    else:
        with pytest.raises(lifecycle.LifecycleError, match="synchronization"):
            lifecycle.ntp_client_checks(args)
        assert len(calls) == 1
    assert calls[0][0:3] == ("wait", args.appliance_ssh_host, "ntpq -c rv | grep -q leap=00")
    assert calls[0][3]["timeout_seconds"] == 600


@pytest.mark.parametrize(
    ("returncode", "output", "accepted"),
    [(0, "Disabled\n", True), (0, "Enabled\n", False), (1, "Disabled\n", False)],
)
def test_lifecycle_disables_vmware_clock_sync_before_ntp(monkeypatch, returncode, output, accepted):
    """The VMware lab must not leave Tools competing with NTPsec.

    Args:
        monkeypatch: Replace external behavior for this scenario.
        returncode: Simulated VMware command exit status.
        output: Simulated VMware command output.
        accepted: Whether the simulated result should be accepted.
    """
    lifecycle = load_lifecycle_module()
    args = lifecycle.parse_args(["--password", "test", "--appliance-ssh-host", "192.0.2.10"])
    calls = []

    def fake_ssh(host, _args, command, *, role):
        """Fake ssh.

        Args:
            host: Host selected for the simulated SSH command.
            _args: Unused lifecycle arguments accepted by the fake.
            command: Command issued by the scenario.
            role: Role selected for the simulated SSH command.
        """
        calls.append((host, command, role))
        return {"returncode": returncode, "stdout": output, "stderr": ""}

    monkeypatch.setattr(lifecycle, "ssh_command", fake_ssh)
    if accepted:
        assert lifecycle.prepare_vmware_ntp_clock(args) == {"vmware_tools_time_sync": "disabled"}
    else:
        with pytest.raises(lifecycle.LifecycleError):
            lifecycle.prepare_vmware_ntp_clock(args)
    assert calls == [(args.appliance_ssh_host, "sudo -n vmware-toolbox-cmd timesync disable", "appliance")]


def test_full_lifecycle_plan_includes_passwordless_web_terminal_acceptance():
    """Verify that full lifecycle plan includes passwordless web terminal acceptance."""
    lifecycle = load_lifecycle_module()
    args = lifecycle.parse_args(["--password", "test", "--plan-only"])

    plan = lifecycle.lifecycle_plan(args)

    assert "1280x800 framebuffer and 50-row by 160-column tty1 console geometry" in plan["checks"]
    assert "passwordless admin web terminal on management and one selected extra interface" in plan["checks"]
    assert any("atomic generated certificate request with explicit SAN verification" in check for check in plan["checks"])
    assert "ldap" in plan["apply_units"]
    assert any("Managed LDAP desired state" in check for check in plan["checks"])
    assert any(
        "explicit Local selection" in check
        and "local-role group mapping" in check
        and "scope-filtered claims" in check
        for check in plan["checks"]
    )


def test_web_terminal_check_probes_canonical_browser_planes(monkeypatch):
    """Verify lifecycle coverage exercises canonical management and public browser paths.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    lifecycle = load_lifecycle_module()
    calls: list[tuple[str, str, bool | None]] = []

    class ManagementClient:
        """Represent the management-plane lifecycle client."""

        def request(self, method, path, **kwargs):  # type: ignore[no-untyped-def]  # Fake accepts the production client's dynamic request options.
            """Return the ready management terminal page.

            Args:
                method: HTTP method requested by the lifecycle check.
                path: Browser route requested by the lifecycle check.
                **kwargs: Additional request options accepted by the test double.
            """
            calls.append((method, path, kwargs.get("follow_redirects")))
            assert path == "/ui/management/terminal"
            return 200, '<main data-terminal-available="true"></main>', {}

    class SiteClient:
        """Represent the selected public-listener lifecycle client."""

        def request(self, method, path, **kwargs):  # type: ignore[no-untyped-def]  # Fake accepts the production client's dynamic request options.
            """Return the expected public terminal, protocol, and isolation responses.

            Args:
                method: HTTP method requested by the lifecycle check.
                path: Browser or protocol route requested by the lifecycle check.
                **kwargs: Additional request options accepted by the test double.
            """
            calls.append((method, path, kwargs.get("follow_redirects")))
            if method == "GET" and path == "/ui/public/terminal":
                return 200, '<main data-terminal-available="true" data-csrf="csrf-323"></main>', {}
            if method == "POST" and path == "/terminal/tickets":
                assert kwargs["form"]["csrf"] == "csrf-323"
                assert 16 <= len(kwargs["form"]["browser_session_id"]) <= 80
                return 200, '{"websocket_path": "/terminal/ws", "ticket": "ticket-323"}', {}
            if method == "GET" and path == "/ui/management/dashboard":
                assert kwargs["follow_redirects"] is False
                return 404, "not found", {}
            raise AssertionError(f"unexpected request {method} {path}")

    site_client = SiteClient()
    monkeypatch.setattr(lifecycle, "HttpClient", lambda base_url: site_client)
    monkeypatch.setattr(lifecycle, "ui_login", lambda client, args: None)
    monkeypatch.setattr(
        lifecycle,
        "ssh_command",
        lambda *args, **kwargs: {
            "returncode": 0,
            "stdout": '{"enabled": true, "ca_public_key": "web-terminal-ca.pub"}',
            "stderr": "",
            "command": "redacted",
        },
    )

    evidence = lifecycle.web_terminal_check(
        ManagementClient(),
        argparse.Namespace(
            appliance_ssh_host="192.0.2.10",
            site_cidr="192.0.2.32/24",
            site_interface="eth2",
        ),
    )

    assert evidence["dashboard_status"] == 404
    assert ("GET", "/ui/management/terminal", None) in calls
    assert ("GET", "/ui/public/terminal", None) in calls
    assert ("GET", "/ui/management/dashboard", False) in calls
    assert ("POST", "/terminal/tickets", None) in calls


def test_web_terminal_check_uses_site_client_on_isolated_lab(monkeypatch):
    """The full lab checks site routing from Client A without a Windows host route.

    Args:
        monkeypatch: Replace external behavior for this scenario.
    """
    lifecycle = load_lifecycle_module()
    commands = []

    class ManagementClient:
        def request(self, method, path, **_kwargs):
            """Request.

            Args:
                method: HTTP method issued by the probe.
                path: Site route to probe.
                **_kwargs: Unused request arguments accepted by the fake.
            """
            if (method, path) == ("GET", "/ui/management/terminal"):
                return 200, '<main data-terminal-available="true" data-csrf="csrf-323"></main>', {}
            if (method, path) == ("GET", "/ui/public/terminal"):
                return 404, 'not found', {}
            if (method, path) == ("POST", "/terminal/tickets"):
                assert _kwargs["form"]["csrf"] == "csrf-323"
                assert 16 <= len(_kwargs["form"]["browser_session_id"]) <= 80
                return 200, '{"websocket_path": "/terminal/ws", "ticket": "ticket-323"}', {}
            raise AssertionError((method, path))

    def fake_ssh_command(host, _args, command, *, role):
        """Fake ssh command.

        Args:
            host: Host selected for the simulated SSH command.
            _args: Unused lifecycle arguments accepted by the fake.
            command: Command issued by the scenario.
            role: Role selected for the simulated SSH command.
        """
        commands.append((host, command, role))
        if role == "appliance":
            return {"returncode": 0, "stdout": '{"enabled": true, "ca_public_key": "web-terminal-ca.pub"}', "stderr": ""}
        status = "404" if "/ui/management/dashboard" in command else "302"
        return {"returncode": 0, "stdout": status, "stderr": ""}

    monkeypatch.setattr(lifecycle, "ssh_command", fake_ssh_command)
    monkeypatch.setattr(lifecycle, "HttpClient", lambda _url: (_ for _ in ()).throw(AssertionError("direct host route")))
    monkeypatch.setattr(lifecycle, "ui_login", lambda *_args: (_ for _ in ()).throw(AssertionError("new login")))
    args = argparse.Namespace(
        appliance_ssh_host="192.0.2.10", client_a_host="192.0.2.11",
        site_cidr="192.168.12.1/24", site_interface="eth1",
    )

    evidence = lifecycle.web_terminal_check(ManagementClient(), args)

    assert evidence["extra_terminal_status"] == 302
    assert evidence["site_probe_status"] == 302
    assert evidence["dashboard_status"] == 404
    assert len(commands) == 3
    assert "grep -i trustedusercakeys" in commands[0][1]
    assert all(host == args.client_a_host and role == "client" for host, _command, role in commands[1:])


def test_release_database_identity_uses_privileged_appliance_command(monkeypatch):
    """Verify that release database identity uses privileged appliance command.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    lifecycle = load_lifecycle_module()
    args = lifecycle.parse_args(["--password", "test", "--ssh-password", "test", "--plan-only"])
    captured: dict[str, str] = {}

    def fake_ssh_command(host, command_args, command, *, role):  # type: ignore[no-untyped-def]  # Fake mirrors the heterogeneous integration helper signature.
        """Return fake ssh command.

        Args:
            host: Host supplied to the test scenario.
            command_args: Command args supplied to the test scenario.
            command: Command and arguments to execute.
            role: Role supplied to the test scenario.
        """
        captured.update(host=host, command=command, role=role)
        return {
            "returncode": 0,
            "stdout": json.dumps(
                {
                    "current_release": "/opt/atlaso/releases/0.9.0",
                    "compatibility_venv": "/opt/atlaso/releases/0.9.0/venv",
                    "schema_sha256": "abc123",
                    "users": [[1, "admin"]],
                }
            ),
            "stderr": "",
            "command": "redacted",
        }

    monkeypatch.setattr(lifecycle, "ssh_command", fake_ssh_command)

    identity = lifecycle._release_database_identity(args)

    assert captured["role"] == "appliance"
    assert "sudo -S" in captured["command"]
    assert "base64 -d | python3 -" in captured["command"]
    assert identity["schema_sha256"] == "abc123"


def test_esx_storage_lifecycle_plan_is_dual_stack_and_format_is_explicit():
    """Verify that esx storage lifecycle plan is dual stack and format is explicit."""
    lifecycle = load_lifecycle_module()
    args = lifecycle.parse_args(
        [
            "--password",
            "test",
            "--plan-only",
            "--esx-storage-test",
            "--esx-storage-device-id",
            "/dev/disk/by-id/wwn-test",
            "--confirm-esx-storage-format",
        ]
    )

    plan = lifecycle.lifecycle_plan(args)

    assert plan["interfaces"]["site"]["ipv6_cidr"] == "fd00:50::1/64"
    assert plan["esx_storage"] == {
        "enabled": True,
        "device_id": "/dev/disk/by-id/wwn-test",
        "ipv4_client": "192.168.50.210/32",
        "ipv6_client": "fd00:50::210/128",
        "format_authorized": True,
    }
    assert "esx_storage" in plan["apply_units"]
    assert any("NFS 3 and 4.1" in check and "IPv4/IPv6" in check for check in plan["checks"])


def test_apply_units_requires_and_submits_esx_format_confirmation(monkeypatch):
    """Verify that apply units requires and submits esx format confirmation.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    lifecycle = load_lifecycle_module()

    class FakeClient:
        """Represent fake client.

        Attributes:
            form: Form captured or supplied by this test helper.
        """
        def __init__(self) -> None:
            """Initialize the fake client."""
            self.form = []

        def request(self, method, path, **kwargs):  # type: ignore[no-untyped-def]  # Fake accepts the production client's dynamic request options.
            """Return request.

            Args:
                method: HTTP or protocol method to invoke.
                path: Filesystem or URL path to read, validate, or update.
                **kwargs: Additional keyword arguments forwarded to the wrapped call.
            """
            if method == "GET" and path == "/ui/management/appliance-apply":
                return 200, '<input type="hidden" name="csrf" value="token">', {}
            assert method == "POST"
            assert path == "/ui/management/appliance-apply"
            self.form = kwargs["form"]
            return 202, json.dumps({"job_id": "job-1", "status_url": "/tasks/job-1/status"}), {}

        def json_request(self, method, path, **_kwargs):  # type: ignore[no-untyped-def]  # Fake accepts the production client's dynamic request options.
            """Return json request.

            Args:
                method: HTTP or protocol method to invoke.
                path: Filesystem or URL path to read, validate, or update.
                **_kwargs: Additional keyword arguments accepted by the test double.
            """
            if path == "/ui/management/appliance-apply/review":
                return {
                    "units": [
                        {
                            "id": "esx_storage",
                            "format_volumes": [{"id": 7, "confirmation": "FORMAT lifecycle-esx-data"}],
                        }
                    ]
                }
            return {"task": {"status": "succeeded", "result": {"dry_run": False}, "_children": []}}

    monkeypatch.setattr(lifecycle.time, "sleep", lambda _seconds: None)
    client = FakeClient()
    args = argparse.Namespace(allow_dry_run=False, confirm_esx_storage_format=True)

    lifecycle.apply_units(client, ["esx_storage"], args)

    confirmations = [value for key, value in client.form if key == "format_confirmations"]
    assert json.loads(confirmations[0]) == {"volume_id": 7, "confirmation": "FORMAT lifecycle-esx-data"}


def test_authoritative_dns_lifecycle_probe_covers_authority_reverse_nxdomain_and_recursion():
    """Verify that authoritative dns lifecycle probe covers authority reverse nxdomain and recursion."""
    import base64

    lifecycle = load_lifecycle_module()
    command = lifecycle.authoritative_dns_probe_command("atlaso.internal", "192.168.50.1", "192.168.50.1")
    encoded = command.split()[2]
    script = base64.b64decode(encoded).decode("utf-8")

    compile(script, "<authoritative-dns-probe>", "exec")
    assert '(domain, 6, 0, 6, True, None)' in script
    assert '(domain, 2, 0, 2, True, None)' in script
    assert '("ns1." + domain, 1, 0, 1, True, \'192.168.50.1\')' in script
    assert '("interop-appliance." + domain, 1, 0, 1, True, \'192.168.50.1\')' in script
    assert "for _ in range(2):" in script
    assert 'query("missing-authoritative." + domain, 1)' in script
    assert "assert 6 in sections[1]" in script
    assert 'query("example.com", 1, tcp=tcp)' in script

    dynamic_command = lifecycle.authoritative_dns_probe_command(
        "atlaso.internal", "192.168.50.1", "192.168.50.1", "interop-client", "192.168.50.105"
    )
    dynamic_script = base64.b64decode(dynamic_command.split()[2]).decode("utf-8")
    compile(dynamic_script, "<dynamic-dns-probe>", "exec")
    assert "dynamic_hostname = 'interop-client'" in dynamic_script
    assert '(1, dynamic_ip) in values[0]' in dynamic_script
    assert 'expected.append((dynamic_hostname + "." + domain, 1, 0, 1, True, dynamic_ip))' in dynamic_script
    assert 'expected.append((ip_address(dynamic_ip).reverse_pointer, 12, 0, 12, False,' in dynamic_script
    assert 'assert (expected_type, expected_value) in values[0]' in dynamic_script

    recursive_command = lifecycle.recursive_dns_probe_command("127.0.0.1", "192.168.50.1")
    recursive_script = base64.b64decode(recursive_command.split()[2]).decode("utf-8")
    assert "1.50.168.192.in-addr.arpa" in recursive_script
    assert 'query("example.com", 1)' in recursive_script

    source = Path(lifecycle.__file__).read_text(encoding="utf-8")
    assert 'run_step(results, "authoritative-dns-state-check", authoritative_dns_state_check, args)' in source
    assert 'run_step(results, "recursive-dns-state-check", recursive_dns_state_check, args)' in source


def test_lifecycle_enables_routing_before_wan_apply(monkeypatch):
    """The WAN lab must turn on its global gates before applying routes.

    Args:
        monkeypatch: Pytest fixture used to replace network setup helpers.
    """
    lifecycle = load_lifecycle_module()
    calls = []

    class Client:
        def json_request(self, method, path, *, json_body):
            """Record a settings request and return its supplied state.

            Args:
                method: HTTP method used for the request.
                path: API path receiving the request.
                json_body: Settings payload to record.
            """
            calls.append((method, path, json_body))
            return json_body

    monkeypatch.setattr(lifecycle, "configure_firewall", lambda *_args: {})
    monkeypatch.setattr(lifecycle, "configure_wan_policy", lambda *_args: {"id": 1})
    monkeypatch.setattr(lifecycle, "configure_routes_nat", lambda *_args: {})
    monkeypatch.setattr(lifecycle, "configure_routing_permissions", lambda *_args: {})

    result = lifecycle.configure_firewall_wan(Client(), argparse.Namespace())

    assert calls == [(
        "PUT", "/api/v1/routes-wan/settings",
        {"routing_enabled": True, "nat_enabled": True, "wan_simulation_enabled": True},
    )]
    assert result["settings"] == calls[0][2]


def test_apply_units_retries_once_when_desired_state_drifts(monkeypatch):
    """Verify that apply units retries once when desired state drifts.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    lifecycle = load_lifecycle_module()

    class FakeClient:
        """Represent fake client.

        Attributes:
            submissions: Submissions captured or supplied by this test helper.
        """
        def __init__(self) -> None:
            """Initialize the fake client."""
            self.submissions = 0

        def request(self, method, path, **_kwargs):
            """Return request.

            Args:
                method: HTTP or protocol method to invoke.
                path: Filesystem or URL path to read, validate, or update.
                **_kwargs: Additional keyword arguments accepted by the test double.

            Raises:
                AssertionError: If an expected invariant is not satisfied.
            """
            if method == "GET" and path == "/ui/management/appliance-apply":
                return 200, '<input type="hidden" name="csrf" value="token">', {}
            if method == "POST" and path == "/ui/management/appliance-apply":
                self.submissions += 1
                body = json.dumps(
                    {
                        "job_id": f"job_{self.submissions}",
                        "status_url": f"/tasks/job_{self.submissions}/status",
                    }
                )
                return 202, body, {}
            raise AssertionError(f"unexpected request {method} {path}")

        def json_request(self, method, path, **_kwargs):
            """Return json request.

            Args:
                method: HTTP or protocol method to invoke.
                path: Filesystem or URL path to read, validate, or update.
                **_kwargs: Additional keyword arguments accepted by the test double.

            Raises:
                AssertionError: If an expected invariant is not satisfied.
            """
            assert method == "GET"
            if path == "/tasks/job_1/status":
                return {
                    "task": {
                        "status": "failed",
                        "error": "Desired state changed after task submission: DNS/DHCP (dnsmasq). Submit the appliance changes again.",
                    }
                }
            if path == "/tasks/job_2/status":
                return {"task": {"status": "succeeded", "result": {"dry_run": False}, "_children": []}}
            raise AssertionError(f"unexpected status path {path}")

    monkeypatch.setattr(lifecycle.time, "sleep", lambda _seconds: None)
    client = FakeClient()

    evidence = lifecycle.apply_units(client, ["dnsmasq", "ca"], argparse.Namespace(allow_dry_run=False))

    assert client.submissions == 2
    assert evidence["attempts"] == 2
    assert evidence["job_id"] == "job_2"
    assert evidence["status"] == "succeeded"


def test_routing_probe_commands_cover_block_allow_and_route_role_paths():
    """Verify that routing probe commands cover block allow and route role paths."""
    lifecycle = load_lifecycle_module()
    args = lifecycle.parse_args(["--password", "test"])

    blocked = lifecycle.client_a_access_to_wan_command(args, expect_success=False)
    allowed = lifecycle.client_a_access_to_wan_command(args, expect_success=True)
    route_role = lifecycle.client_a_route_role_to_wan_command(args)
    client_b = lifecycle.client_b_wan_setup_command(args, include_site_route=False, include_vlan_route=True)

    assert "test \"$rc\" -ne 0" in blocked
    assert "test \"$rc\" -ne 0" not in allowed
    assert "ip route replace 172.31.50.0/24 via 192.168.50.1 dev eth1" in allowed
    assert "ip link add link eth2 name eth2.50 type vlan id 50" in route_role
    assert "ip route replace 172.31.50.0/24 via 192.168.60.1 dev eth2.50" in route_role
    assert "ip route replace 192.168.60.0/24 via 172.31.50.1 dev eth1" in client_b


def test_routing_host_firewall_check_uses_default_drop_isolation():
    """The lab verifies its configured forward policy and explicit route rule."""
    lifecycle = load_lifecycle_module()
    args = lifecycle.parse_args(["--password", "test"])

    command = lifecycle.routing_host_check_commands(args)["firewall"]

    assert 'nft list chain inet atlaso forward | grep -F "policy drop;"' in command
    assert 'comment \\"route-' in command
    assert 'isolate-' not in command


def test_host_checks_encode_shell_before_ssh_transport(monkeypatch):
    """Preserve nested quotes and substitutions across plink and sudo parsing.

    Args:
        monkeypatch: Pytest fixture used to replace remote execution.
    """
    lifecycle = load_lifecycle_module()
    args = lifecycle.parse_args(["--password", "test"])
    command = "test \"$(printf '%s' a)\" = a"
    sent: list[str] = []

    def fake_ssh_command(_host, _args, remote_command, **_kwargs):
        """Capture the transport command without contacting an appliance.

        Args:
            _host: Ignored appliance host.
            _args: Ignored lifecycle arguments.
            remote_command: Command sent through the SSH transport.
            **_kwargs: Ignored SSH options.
        """
        sent.append(remote_command)
        return {"returncode": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(lifecycle, "ssh_command", fake_ssh_command)

    lifecycle.run_host_checks(args, {"quoted": command})

    encoded = lifecycle.base64.b64encode(command.encode("utf-8")).decode("ascii")
    assert sent == [f"printf %s {encoded} | base64 -d | sh"]


def test_host_state_checks_verify_vcf_trust_runtime_dependencies(monkeypatch):
    """Verify that host state checks verify vcf trust runtime dependencies.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    lifecycle = load_lifecycle_module()
    args = lifecycle.parse_args(["--password", "test"])
    captured = {}
    execution_contexts = {}

    def fake_run_host_checks(_args, checks, *, appliance_as_root=True):
        """Return fake run host checks.

        Args:
            _args: Parsed command-line options consumed by the operation.
            checks: Checks supplied to the test scenario.
            appliance_as_root: Appliance as root supplied to the test scenario.
        """
        captured.update(checks)
        execution_contexts.update({name: appliance_as_root for name in checks})
        return checks

    monkeypatch.setattr(lifecycle, "run_host_checks", fake_run_host_checks)

    lifecycle.host_state_checks(args)

    assert "/opt/atlaso/.venv/bin/python" in captured["vcf_trust_dependencies"]
    encoded_httpx_probe = lifecycle.base64.b64encode(b"import httpx; print(httpx.__version__)").decode("ascii")
    assert encoded_httpx_probe in captured["vcf_trust_dependencies"]
    assert "paramiko" not in captured["vcf_trust_dependencies"]
    encoded_vcf_sdk_probe = lifecycle.base64.b64encode(
        b'from importlib.metadata import version; assert version("vcf-sdk") == "9.1.0.0"'
    ).decode("ascii")
    powercli_version = json.loads(Path("image/common/powershell/powercli-lock.json").read_text(encoding="utf-8"))["suite_version"]
    encoded_powercli_probe = lifecycle.base64.b64encode(
        (
            f'$m = Get-Module VCF.PowerCLI -ListAvailable | Where-Object Version -eq "{powercli_version}" | '
            'Select-Object -First 1; if (-not $m) { exit 1 }; Import-Module $m.Path -Force; '
            '$configured = Get-PowerCLIConfiguration -Scope AllUsers; if ([bool]$configured.ParticipateInCEIP) { exit 1 }; '
            'if (-not (Get-Command Connect-VIServer -ErrorAction SilentlyContinue)) { exit 1 }'
        ).encode("utf-16le")
    ).decode("ascii")
    assert encoded_vcf_sdk_probe in captured["vcf_automation_tooling"]
    assert execution_contexts["vcf_automation_tooling"] is True
    assert "slapd.service" in captured["ldap_service"]
    assert "636" in captured["ldap_listeners"]
    assert "389" in captured["ldap_listeners"]
    assert "-verify_hostname ldap.atlaso.internal" in captured["ldap_tls"]
    assert encoded_powercli_probe in captured["vcf_powercli_user"]
    assert execution_contexts["vcf_powercli_user"] is False
    assert "console status --real | grep -F '\"maintenance_isolation\": false'" in captured["local_console"]


def test_managed_ldap_lifecycle_check_sends_directory_password_only_through_stdin(monkeypatch):
    """Verify that managed ldap lifecycle check sends directory password only through stdin.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    lifecycle = load_lifecycle_module()
    args = lifecycle.parse_args(
        [
            "--password",
            "admin-secret",
            "--ssh-password",
            "ssh-secret",
            "--appliance-ssh-password",
            "appliance-secret",
            "--appliance-ssh-host",
            "192.0.2.10",
        ]
    )
    captured = {}

    def fake_run(command, **kwargs):
        """Fake run.

        Args:
            command: Command issued by the scenario.
            **kwargs: Additional request arguments accepted by the fake.
        """
        captured["command"] = command
        captured["input"] = kwargs["input"]
        return subprocess.CompletedProcess(command, 0, b'{"helper":"atlaso-helper","action":"authenticate"}\n', b"")

    monkeypatch.setattr(lifecycle.subprocess, "run", fake_run)
    evidence = lifecycle.managed_ldap_helper_authentication_check(args)

    assert captured["input"] == f"appliance-secret\n{lifecycle.LIFECYCLE_LDAP_PASSWORD}\n".encode()
    assert lifecycle.LIFECYCLE_LDAP_PASSWORD not in " ".join(captured["command"])
    assert lifecycle.LIFECYCLE_LDAP_PASSWORD not in json.dumps(evidence)
    assert evidence["password_transport"] == "stdin-only"
    assert evidence["bind_transport"] == "ldapi:///"
    encoded = captured["command"][-1].split("printf %s ", 1)[1].split(" |", 1)[0]
    remote_script = base64.b64decode(encoded).decode()
    assert "sudo -S -p '' -v" in remote_script
    assert "sudo -n env PYTHONUNBUFFERED=1 /opt/atlaso/bin/atlaso-helper ldap authenticate --real" in remote_script
    assert "appliance-secret" not in remote_script
    assert lifecycle.LIFECYCLE_LDAP_PASSWORD not in remote_script


def test_appliance_user_ssh_command_does_not_wrap_with_sudo(monkeypatch):
    """Verify that appliance user ssh command does not wrap with sudo.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    lifecycle = load_lifecycle_module()
    args = lifecycle.parse_args(
        [
            "--password",
            "test",
            "--ssh-password",
            "ssh-secret",
            "--appliance-ssh-password",
            "appliance-secret",
            "--appliance-ssh-host",
            "192.0.2.10",
        ]
    )
    captured = {}

    def fake_run(command, **_kwargs):
        """Return fake run.

        Args:
            command: Command and arguments to execute.
            **_kwargs: Additional keyword arguments accepted by the callable.
        """
        captured["command"] = command
        return lifecycle.subprocess.CompletedProcess(command, 0, "ok\n", "")

    monkeypatch.setattr(lifecycle.subprocess, "run", fake_run)

    result = lifecycle.ssh_command(
        args.appliance_ssh_host,
        args,
        "pwsh -NoLogo -NoProfile -NonInteractive -Command Get-Date",
        role="appliance",
        appliance_as_root=False,
    )

    assert result["returncode"] == 0
    assert lifecycle.ssh_password(args, "appliance") == "appliance-secret"
    assert lifecycle.ssh_password(args, "client") == "ssh-secret"
    assert captured["command"][4] == "appliance-secret"
    assert "ssh-secret" not in captured["command"]
    assert captured["command"][-1] == "pwsh -NoLogo -NoProfile -NonInteractive -Command Get-Date"
    assert "sudo" not in captured["command"][-1]


def test_esxi_pxe_payload_uses_dhcp_lifecycle_host():
    """Verify that esxi pxe payload uses dhcp lifecycle host."""
    lifecycle = load_lifecycle_module()
    args = lifecycle.parse_args(["--password", "test", "--pxe-test-mode", "esxi", "--pxe-client-mac", "00:50:56:20:01:02"])

    assert lifecycle.pxe_client_ip(args) == "192.168.50.210"
    content = lifecycle.lifecycle_esxi_kickstart_content()

    assert "network --bootproto=dhcp" in content
    assert "rootpw {{vault.lifecycle_esxi.esx.lifecycle.root.password}}" in content
    assert "rootpw vmware01!" not in content
    assert "vim-cmd hostsvc/start_ssh" in content

    with pytest.raises(lifecycle.LifecycleError, match="vault marker is invalid"):
        lifecycle.lifecycle_esxi_kickstart_content("vault.somewhere.else.password")


def test_lifecycle_esxi_vault_inventory_reuses_normalized_marker_name():
    """Verify a normalized-equivalent lifecycle vault is reused."""
    lifecycle = load_lifecycle_module()
    body = (
        '<section data-vault-id="7" data-vault-name="Lifecycle-ESXi">'
        '<script type="application/json" id="vault-entries-data-7">'
        '[{"id": 9, "key": "esx.lifecycle.root"}]</script>'
    )

    vault_id, entries = lifecycle._lifecycle_esxi_vault_inventory(body)

    assert vault_id == 7
    assert entries == [{"id": 9, "key": "esx.lifecycle.root"}]


def test_lifecycle_esxi_vault_inventory_rejects_ambiguous_marker_names():
    """Verify normalized lifecycle vault collisions fail before creation."""
    lifecycle = load_lifecycle_module()
    body = (
        '<section data-vault-id="7" data-vault-name="Lifecycle ESXi">'
        '<section data-vault-id="8" data-vault-name="Lifecycle-ESXi">'
    )

    with pytest.raises(lifecycle.LifecycleError, match="marker name is ambiguous"):
        lifecycle._lifecycle_esxi_vault_inventory(body)


def test_restored_esxi_lifecycle_recreates_vault_secret_before_apply(monkeypatch, tmp_path):
    """Verify restored ESXi state rehydrates its excluded vault secret before apply.

    Args:
        monkeypatch: Pytest fixture used to replace the lifecycle step runner.
        tmp_path: Pytest-managed temporary result directory.
    """
    lifecycle = load_lifecycle_module()
    args = lifecycle.parse_args(
        [
            "--secret-stdin",
            "--restore-settings-backup",
            str(tmp_path / "settings-backup.json"),
            "--pxe-test-mode",
            "esxi",
            "--result-dir",
            str(tmp_path),
        ]
    )
    args.esxi_password = "LifecycleEsxi01!"
    client = object()
    calls = []

    def fake_run_step(_results, name, operation, *operation_args):
        """Record a lifecycle operation without executing it.

        Args:
            _results: Unused lifecycle results collection.
            name: Lifecycle step name.
            operation: Callable selected for the lifecycle step.
            *operation_args: Positional arguments supplied to the operation.

        Returns:
            An empty result mapping for the simulated step.
        """
        calls.append((name, operation, operation_args))
        return {}

    monkeypatch.setattr(lifecycle, "run_step", fake_run_step)
    lifecycle.run_restored_lifecycle([], client, args)

    call_names = [name for name, _operation, _arguments in calls]
    stage_index = call_names.index("stage-esxi-vault-secret")
    assert call_names.index("restore-settings-backup") < call_names.index("reauthenticate-after-restore")
    assert call_names.index("reauthenticate-after-restore") < call_names.index("authentication-lifetime-policy-check")
    assert call_names.index("restore-settings-backup") < stage_index
    assert stage_index < call_names.index("apply-connectivity-units")
    assert calls[stage_index][1] is lifecycle.ensure_lifecycle_esxi_vault_secret
    assert calls[stage_index][2] == (client, args.esxi_password)
    connectivity = next(arguments for name, _operation, arguments in calls if name == "apply-connectivity-units")
    assert "appliance_settings" in connectivity[1]
    assert {"ca", "ldap", "ntpd", "vcf_offline_depot", "public_services"}.issubset(connectivity[1])


def test_reauthenticate_after_restore_replaces_revoked_credentials(monkeypatch):
    """A restored archive requires a fresh browser session and API token.

    Args:
        monkeypatch: Replace external behavior for this scenario.
    """
    lifecycle = load_lifecycle_module()
    calls = []

    class CookieJar:
        def clear(self):
            calls.append("clear")

    client = argparse.Namespace(cookie_jar=CookieJar(), bearer_token="old-token")

    def fake_api_login(selected_client, _args):
        """Fake api login.

        Args:
            selected_client: Client selected for the simulated login.
            _args: Unused lifecycle arguments accepted by the fake.
        """
        assert selected_client is client
        assert selected_client.bearer_token == ""
        calls.append("api")
        selected_client.bearer_token = "new-token"

    def fake_ui_login(selected_client, _args):
        """Fake ui login.

        Args:
            selected_client: Client selected for the simulated login.
            _args: Unused lifecycle arguments accepted by the fake.
        """
        assert selected_client is client
        assert selected_client.bearer_token == "new-token"
        calls.append("browser")

    monkeypatch.setattr(lifecycle, "api_login", fake_api_login)
    monkeypatch.setattr(lifecycle, "ui_login", fake_ui_login)

    assert lifecycle.reauthenticate_after_restore(client, object()) == {
        "api": "authenticated", "browser": "authenticated"
    }
    assert calls == ["clear", "api", "browser"]


def test_full_lifecycle_selects_resolver_settings_with_initial_dns_apply(monkeypatch):
    """The first DNS Apply must include resolver consent and changed CA listeners.

    Args:
        monkeypatch: Replace external behavior for this scenario.
    """
    lifecycle = load_lifecycle_module()
    args = lifecycle.parse_args(["--secret-stdin"])
    calls = []

    def fake_run_step(_results, name, _operation, *operation_args):
        """Fake run step.

        Args:
            _results: Unused result collection accepted by the fake.
            name: Lifecycle step name.
            _operation: Unused operation accepted by the fake.
            *operation_args: Operation arguments captured by the fake.
        """
        calls.append((name, operation_args))
        return {}

    monkeypatch.setattr(lifecycle, "run_step", fake_run_step)
    management_client = object()
    lifecycle.run_full_lifecycle([], management_client, args)

    connectivity = next(arguments for name, arguments in calls if name == "apply-connectivity-units")
    assert "dnsmasq" in connectivity[1]
    assert "appliance_settings" in connectivity[1]
    assert {"ca", "ldap", "ntpd", "vcf_offline_depot", "public_services"}.issubset(connectivity[1])
    call_names = [name for name, _arguments in calls]
    assert call_names.index("management-https-check") < call_names.index("configure-oidc-provider")
    assert call_names.index("configure-oidc-provider") < call_names.index("apply-oidc-certificate-and-listener")
    assert call_names.index("apply-oidc-certificate-and-listener") < call_names.index("oidc-site-listener-check")
    assert call_names.index("oidc-site-listener-check") < call_names.index("oidc-authorization-code-check")
    oidc_call = next(arguments for name, arguments in calls if name == "oidc-authorization-code-check")
    assert oidc_call[2] is management_client
    oidc_apply = next(arguments for name, arguments in calls if name == "apply-oidc-certificate-and-listener")
    assert "dnsmasq" in oidc_apply[1]


def test_full_lifecycle_skips_oidc_site_probe_without_client_checks(monkeypatch):
    """No-client mode must not rely on a site client or its installed CA root.

    Args:
        monkeypatch: Replace external behavior for this scenario.
    """
    lifecycle = load_lifecycle_module()
    args = lifecycle.parse_args(["--secret-stdin", "--skip-client-checks"])
    calls = []

    def fake_run_step(_results, name, _operation, *_operation_args):
        """Fake run step.

        Args:
            _results: Unused result collection accepted by the fake.
            name: Lifecycle step name.
            _operation: Unused operation accepted by the fake.
            *_operation_args: Unused operation arguments accepted by the fake.
        """
        calls.append(name)
        return {}

    monkeypatch.setattr(lifecycle, "run_step", fake_run_step)
    lifecycle.run_full_lifecycle([], object(), args)

    assert "apply-oidc-certificate-and-listener" in calls
    assert "oidc-site-listener-check" not in calls
    assert "web-terminal-check" not in calls


def test_restored_lifecycle_skips_terminal_site_probe_without_client_checks(monkeypatch, tmp_path):
    """Restored no-client mode must not require the isolated Client A VM.

    Args:
        monkeypatch: Replace external behavior for this scenario.
        tmp_path: Temporary directory for isolated test state.
    """
    lifecycle = load_lifecycle_module()
    args = lifecycle.parse_args(
        ["--secret-stdin", "--skip-client-checks", "--client-a-host", "192.0.2.11", "--restore-settings-backup", str(tmp_path / "backup.json")]
    )
    calls = []
    monkeypatch.setattr(lifecycle, "run_step", lambda _results, name, _operation, *_args: calls.append(name) or {})

    lifecycle.run_restored_lifecycle([], object(), args)

    assert "management-https-check" in calls
    assert "web-terminal-check" not in calls


def test_configure_esxi_pxe_selects_dhcp_scope_and_proves_reservation():
    """Verify that configure esxi pxe selects dhcp scope and proves reservation."""
    lifecycle = load_lifecycle_module()
    args = lifecycle.parse_args(
        [
            "--password",
            "test",
            "--pxe-test-mode",
            "esxi",
            "--pxe-client-mac",
            "00:50:56:20:01:02",
            "--pxe-installer-iso-path",
            "/mnt/atlaso-vcf-offline-depot/PROD/COMP/ESX_HOST/esxi.iso",
            "--secret-stdin",
        ]
    )
    args.esxi_password = "LifecycleEsxi01!"

    class FakeClient:
        """Represent fake client.

        Attributes:
            boot_form: Boot form captured or supplied by this test helper.
            host_payload: Host payload captured or supplied by this test helper.
        """
        def __init__(self):
            """Initialize the fake client."""
            self.boot_form = []
            self.host_payload = {}
            self.kickstart_payload = {}
            self.vault_form = {}

        def request(self, method, path, **kwargs):
            """Return request.

            Args:
                method: HTTP or protocol method to invoke.
                path: Filesystem or URL path to read, validate, or update.
                **kwargs: Additional keyword arguments forwarded to the wrapped call.

            Raises:
                AssertionError: If an expected invariant is not satisfied.
            """
            if method == "GET" and path == "/esxi-pxe":
                return 200, '<input type="hidden" name="csrf" value="token">', {}
            if method == "GET" and path == "/ui/management/vaults":
                return (
                    200,
                    '<input type="hidden" name="csrf" value="token">'
                    '<section data-vault-id="12" data-vault-name="Lifecycle ESXi">'
                    '<script type="application/json" id="vault-entries-data-12">[]</script>',
                    {},
                )
            if method == "POST" and path == "/ui/management/vaults/12/entries":
                self.vault_form = kwargs["form"]
                return 303, "", {"Location": "/vaults#vault-panel-12"}
            if method == "POST" and path == "/esxi-pxe/boot-settings":
                self.boot_form = kwargs["form"]
                return 200, '{"validation_errors": [], "dns_record_action": "created"}', {}
            if method == "GET" and path.startswith("/pxe/boot.ipxe?"):
                return (
                    200,
                    "choose --timeout 10000 --default esxi_assigned selected",
                    {"Cache-Control": "no-store"},
                )
            raise AssertionError(f"unexpected request {method} {path}")

        def json_request(self, method, path, json_body=None, **_kwargs):
            """Return json request.

            Args:
                method: HTTP or protocol method to invoke.
                path: Filesystem or URL path to read, validate, or update.
                json_body: Json body supplied by the caller.
                **_kwargs: Additional keyword arguments accepted by the test double.

            Raises:
                AssertionError: If an expected invariant is not satisfied.
            """
            if method == "GET" and path == "/api/v1/dhcp/scopes":
                return [
                    {
                        "id": 42,
                        "name": "Lifecycle SiteA",
                        "interface_name": "eth1",
                        "site_address": "192.168.50.1",
                    }
                ]
            if method == "GET" and path == "/api/v1/esxi-pxe/kickstarts":
                return []
            if method == "POST" and path == "/api/v1/esxi-pxe/kickstarts":
                self.kickstart_payload = json_body
                return {"id": 7, **json_body}
            if method == "GET" and path == "/api/v1/esxi-pxe/hosts":
                return []
            if method == "POST" and path == "/api/v1/esxi-pxe/hosts":
                self.host_payload = json_body
                return {"id": 9, **json_body}
            if method == "GET" and path == "/api/v1/dhcp/reservations":
                return [
                    {
                        "id": 11,
                        "mac_address": "00:50:56:20:01:02",
                        "ip_address": "192.168.50.210",
                        "enabled": True,
                    }
                ]
            raise AssertionError(f"unexpected json_request {method} {path}")

    fake = FakeClient()
    evidence = lifecycle.configure_esxi_pxe(fake, args)

    assert ("dhcp_scope_id", "42") in fake.boot_form
    assert ("dhcp_scope_ids", "42") in fake.boot_form
    assert fake.host_payload["kickstart_id"] == 7
    assert fake.host_payload["ip_address"] == "192.168.50.210"
    assert fake.vault_form["value"] == "LifecycleEsxi01!"
    assert fake.vault_form["key"] == "esx.lifecycle.root"
    assert "LifecycleEsxi01!" not in json.dumps(fake.kickstart_payload)
    assert "{{vault.lifecycle_esxi.esx.lifecycle.root.password}}" in fake.kickstart_payload["content"]
    assert evidence["dhcp_scope_id"] == 42
    assert evidence["dhcp_reservation_id"] == 11
    assert evidence["menu_default"] == "esxi_assigned"
