from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

import pytest


def load_lifecycle_module():
    path = Path(__file__).resolve().parents[1] / "scripts" / "interop" / "lifecycle_test.py"
    spec = importlib.util.spec_from_file_location("lifecycle_test_module", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_baseline(path: Path, *, fingerprint: str = "abc123") -> None:
    path.write_text(
        """
{
  "steps": [
    {
      "name": "ca-client-certificate-check",
      "status": "passed",
      "evidence": {
        "common_name": "client-a.labfoundry.internal",
        "certificate": {
          "serial_number": "01",
          "sha256_fingerprint": "%s",
          "subject": "CN=client-a.labfoundry.internal",
          "issuer": "CN=LabFoundry Internal Root CA"
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
    lifecycle = load_lifecycle_module()
    baseline = tmp_path / "result.json"
    write_baseline(baseline)
    args = argparse.Namespace(certificate_baseline_result=str(baseline))

    evidence = lifecycle.restored_certificate_baseline_check(
        args,
        {
            "common_name": "client-a.labfoundry.internal",
            "certificate": {
                "serial_number": "01",
                "sha256_fingerprint": "abc123",
                "subject": "CN=client-a.labfoundry.internal",
                "issuer": "CN=LabFoundry Internal Root CA",
            },
        },
    )

    assert evidence["sha256_fingerprint"] == "abc123"


def test_restored_certificate_baseline_check_rejects_changed_fingerprint(tmp_path):
    lifecycle = load_lifecycle_module()
    baseline = tmp_path / "result.json"
    write_baseline(baseline)
    args = argparse.Namespace(certificate_baseline_result=str(baseline))

    with pytest.raises(lifecycle.LifecycleError, match="does not match pre-restore certificate"):
        lifecycle.restored_certificate_baseline_check(
            args,
            {
                "common_name": "client-a.labfoundry.internal",
                "certificate": {
                    "serial_number": "01",
                    "sha256_fingerprint": "changed",
                    "subject": "CN=client-a.labfoundry.internal",
                    "issuer": "CN=LabFoundry Internal Root CA",
                },
            },
        )


def test_wan_policy_payload_sets_loss_without_changing_latency_baseline():
    lifecycle = load_lifecycle_module()

    payload = lifecycle.wan_policy_payload(packet_loss_percent=100.0)

    assert payload["name"] == "Lifecycle WAN"
    assert payload["latency_ms"] == 25
    assert payload["jitter_ms"] == 5
    assert payload["packet_loss_percent"] == 100.0
    assert payload["bandwidth_mbit"] == 100


def test_set_lifecycle_wan_policy_updates_duplicate_restored_rows():
    lifecycle = load_lifecycle_module()

    class FakeClient:
        def __init__(self) -> None:
            self.patched: list[tuple[str, dict[str, object]]] = []

        def json_request(self, method: str, path: str, json_body=None):  # type: ignore[no-untyped-def]
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


def test_routing_wan_only_plan_and_routing_rule_payload():
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


def test_full_lifecycle_plan_includes_passwordless_web_terminal_acceptance():
    lifecycle = load_lifecycle_module()
    args = lifecycle.parse_args(["--password", "test", "--plan-only"])

    plan = lifecycle.lifecycle_plan(args)

    assert "passwordless admin web terminal on management and one selected extra interface" in plan["checks"]
    assert any("atomic generated certificate request with explicit SAN verification" in check for check in plan["checks"])
    assert "ldap" in plan["apply_units"]
    assert any("Managed LDAP desired state" in check for check in plan["checks"])


def test_release_database_identity_uses_privileged_appliance_command(monkeypatch):
    lifecycle = load_lifecycle_module()
    args = lifecycle.parse_args(["--password", "test", "--ssh-password", "test", "--plan-only"])
    captured: dict[str, str] = {}

    def fake_ssh_command(host, command_args, command, *, role):  # type: ignore[no-untyped-def]
        captured.update(host=host, command=command, role=role)
        return {
            "returncode": 0,
            "stdout": json.dumps(
                {
                    "current_release": "/opt/labfoundry/releases/0.9.0",
                    "compatibility_venv": "/opt/labfoundry/releases/0.9.0/venv",
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
    lifecycle = load_lifecycle_module()

    class FakeClient:
        def __init__(self) -> None:
            self.form = []

        def request(self, method, path, **kwargs):  # type: ignore[no-untyped-def]
            if method == "GET":
                return 200, '<input type="hidden" name="csrf" value="token">', {}
            self.form = kwargs["form"]
            return 202, json.dumps({"job_id": "job-1", "status_url": "/tasks/job-1/status"}), {}

        def json_request(self, method, path, **_kwargs):  # type: ignore[no-untyped-def]
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
    import base64

    lifecycle = load_lifecycle_module()
    command = lifecycle.authoritative_dns_probe_command("labfoundry.internal", "192.168.50.1", "192.168.50.1")
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
    lifecycle = load_lifecycle_module()

    class FakeClient:
        def __init__(self) -> None:
            self.submissions = 0

        def request(self, method, path, **_kwargs):
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
    lifecycle = load_lifecycle_module()
    args = lifecycle.parse_args(["--password", "test"])
    captured = {}
    execution_contexts = {}

    def fake_run_host_checks(_args, checks, *, appliance_as_root=True):
        captured.update(checks)
        execution_contexts.update({name: appliance_as_root for name in checks})
        return checks

    monkeypatch.setattr(lifecycle, "run_host_checks", fake_run_host_checks)

    lifecycle.host_state_checks(args)

    assert "/opt/labfoundry/.venv/bin/python" in captured["vcf_trust_dependencies"]
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
    assert "-verify_hostname ldap.labfoundry.internal" in captured["ldap_tls"]
    assert encoded_powercli_probe in captured["vcf_powercli_user"]
    assert execution_contexts["vcf_powercli_user"] is False


def test_managed_ldap_lifecycle_check_sends_directory_password_only_through_stdin(monkeypatch):
    lifecycle = load_lifecycle_module()
    args = lifecycle.parse_args(
        [
            "--password",
            "admin-secret",
            "--ssh-password",
            "ssh-secret",
            "--appliance-ssh-host",
            "192.0.2.10",
        ]
    )
    captured = {}

    def fake_run(command, **kwargs):
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
    assert "labfoundry-helper ldap authenticate --real" in " ".join(captured["command"])


def test_appliance_user_ssh_command_does_not_wrap_with_sudo(monkeypatch):
    lifecycle = load_lifecycle_module()
    args = lifecycle.parse_args(
        [
            "--password",
            "test",
            "--ssh-password",
            "ssh-secret",
            "--appliance-ssh-host",
            "192.0.2.10",
        ]
    )
    captured = {}

    def fake_run(command, **_kwargs):
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
    assert captured["command"][-1] == "pwsh -NoLogo -NoProfile -NonInteractive -Command Get-Date"
    assert "sudo" not in captured["command"][-1]


def test_esxi_pxe_payload_uses_dhcp_lifecycle_host():
    lifecycle = load_lifecycle_module()
    args = lifecycle.parse_args(["--password", "test", "--pxe-test-mode", "esxi", "--pxe-client-mac", "00:50:56:20:01:02"])

    assert lifecycle.pxe_client_ip(args) == "192.168.50.210"
    content = lifecycle.lifecycle_esxi_kickstart_content()

    assert "network --bootproto=dhcp" in content
    assert "{{" not in content
    assert "vim-cmd hostsvc/start_ssh" in content


def test_configure_esxi_pxe_selects_dhcp_scope_and_proves_reservation():
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
            "/mnt/labfoundry-vcf-offline-depot/PROD/COMP/ESX_HOST/esxi.iso",
        ]
    )

    class FakeClient:
        def __init__(self):
            self.boot_form = []
            self.host_payload = {}

        def request(self, method, path, **kwargs):
            if method == "GET" and path == "/esxi-pxe":
                return 200, '<input type="hidden" name="csrf" value="token">', {}
            if method == "POST" and path == "/esxi-pxe/boot-settings":
                self.boot_form = kwargs["form"]
                return 200, '{"validation_errors": [], "dns_record_action": "created"}', {}
            raise AssertionError(f"unexpected request {method} {path}")

        def json_request(self, method, path, json_body=None, **_kwargs):
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
