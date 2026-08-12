"""Test lifecycle test behavior."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

import pytest


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

        def json_request(self, method: str, path: str, json_body=None):  # type: ignore[no-untyped-def]
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

        def request(self, method, path):  # type: ignore[no-untyped-def]
            """Return request.

            Args:
                method: HTTP or protocol method to invoke.
                path: Filesystem or URL path to read, validate, or update.
            """
            calls.append((method, path))
            return 200, "{}", {}

        def json_request(self, method, path):  # type: ignore[no-untyped-def]
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
        def __init__(self, base_url):  # type: ignore[no-untyped-def]
            """Initialize the anonymous version client.

            Args:
                base_url: URL used for base.
            """
            assert base_url == FakeClient.base_url

        def json_request(self, method, path):  # type: ignore[no-untyped-def]
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
        (
            "OIDC Authorization Code, explicit Local selection, client-specific "
            "local-role group mapping, scope-filtered claims, PKCE S256, signed "
            "browser session, five-minute RS256 tokens, UserInfo revalidation, "
            "replay rejection, and exact logout redirect"
        ),
    ]
    with pytest.raises(SystemExit):
        lifecycle.parse_args(
            ["--password", "test", "--oidc-only", "--routing-wan-only"]
        )


def test_full_lifecycle_plan_includes_passwordless_web_terminal_acceptance():
    """Verify that full lifecycle plan includes passwordless web terminal acceptance."""
    lifecycle = load_lifecycle_module()
    args = lifecycle.parse_args(["--password", "test", "--plan-only"])

    plan = lifecycle.lifecycle_plan(args)

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

        def request(self, method, path, **kwargs):  # type: ignore[no-untyped-def]
            """Return the ready management terminal page."""
            calls.append((method, path, kwargs.get("follow_redirects")))
            assert path == "/ui/management/terminal"
            return 200, '<main data-terminal-available="true"></main>', {}

    class SiteClient:
        """Represent the selected public-listener lifecycle client."""

        def request(self, method, path, **kwargs):  # type: ignore[no-untyped-def]
            """Return the expected public terminal, protocol, and isolation responses."""
            calls.append((method, path, kwargs.get("follow_redirects")))
            if method == "GET" and path == "/ui/public/terminal":
                return 200, '<main data-terminal-available="true" data-csrf="csrf-323"></main>', {}
            if method == "POST" and path == "/terminal/tickets":
                assert kwargs["form"] == {"csrf": "csrf-323"}
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


def test_release_database_identity_uses_privileged_appliance_command(monkeypatch):
    """Verify that release database identity uses privileged appliance command.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    lifecycle = load_lifecycle_module()
    args = lifecycle.parse_args(["--password", "test", "--ssh-password", "test", "--plan-only"])
    captured: dict[str, str] = {}

    def fake_ssh_command(host, command_args, command, *, role):  # type: ignore[no-untyped-def]
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

        def request(self, method, path, **kwargs):  # type: ignore[no-untyped-def]
            """Return request.

            Args:
                method: HTTP or protocol method to invoke.
                path: Filesystem or URL path to read, validate, or update.
                **kwargs: Additional keyword arguments forwarded to the wrapped call.
            """
            if method == "GET":
                return 200, '<input type="hidden" name="csrf" value="token">', {}
            self.form = kwargs["form"]
            return 202, json.dumps({"job_id": "job-1", "status_url": "/tasks/job-1/status"}), {}

        def json_request(self, method, path, **_kwargs):  # type: ignore[no-untyped-def]
            """Return json request.

            Args:
                method: HTTP or protocol method to invoke.
                path: Filesystem or URL path to read, validate, or update.
                **_kwargs: Additional keyword arguments accepted by the test double.
            """
            if path == "/appliance-apply/review":
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

    assert '(domain, 6, 0, 6, True)' in script
    assert '(domain, 2, 0, 2, True)' in script
    assert '("ns1." + domain, 1, 0, 1, True)' in script
    assert '("interop-appliance." + domain, 1, 0, 1, True)' in script
    assert 'query("missing-authoritative." + domain, 1)' in script
    assert "assert 6 in sections[1]" in script

    recursive_command = lifecycle.recursive_dns_probe_command("127.0.0.1", "192.168.50.1")
    recursive_script = base64.b64decode(recursive_command.split()[2]).decode("utf-8")
    assert "1.50.168.192.in-addr.arpa" in recursive_script
    assert 'query("example.com", 1)' in recursive_script

    source = Path(lifecycle.__file__).read_text(encoding="utf-8")
    assert 'run_step(results, "authoritative-dns-state-check", authoritative_dns_state_check, args)' in source
    assert 'run_step(results, "recursive-dns-state-check", recursive_dns_state_check, args)' in source


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
            if method == "GET" and path == "/appliance-apply":
                return 200, '<input type="hidden" name="csrf" value="token">', {}
            if method == "POST" and path == "/appliance-apply":
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
    encoded_powercli_probe = lifecycle.base64.b64encode(
        (
            '$m = Get-Module VCF.PowerCLI -ListAvailable | Where-Object Version -eq "9.1.0.25380678" | '
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
        """Return fake run.

        Args:
            command: Command and arguments to execute.
            **kwargs: Additional keyword arguments accepted by the callable.
        """
        captured["command"] = command
        captured["input"] = kwargs.get("input")
        return lifecycle.subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(lifecycle.subprocess, "run", fake_run)
    evidence = lifecycle.managed_ldap_helper_authentication_check(args)

    assert lifecycle.LIFECYCLE_LDAP_PASSWORD in captured["input"]
    assert lifecycle.LIFECYCLE_LDAP_PASSWORD not in " ".join(captured["command"])
    assert lifecycle.LIFECYCLE_LDAP_PASSWORD not in json.dumps(evidence)
    assert evidence["password_transport"] == "stdin-only"
    assert evidence["bind_transport"] == "ldapi:///"
    assert "atlaso-helper ldap authenticate --real" in " ".join(captured["command"])


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
    assert "{{" not in content
    assert "vim-cmd hostsvc/start_ssh" in content


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
        ]
    )

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
    assert evidence["dhcp_scope_id"] == 42
    assert evidence["dhcp_reservation_id"] == 11
    assert evidence["menu_default"] == "esxi_assigned"
