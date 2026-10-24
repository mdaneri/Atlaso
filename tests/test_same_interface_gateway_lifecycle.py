"""Exercise same-interface gateway lifecycle admission and evidence helpers."""

from __future__ import annotations

import hashlib
import html
import importlib.machinery
import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.interop import lifecycle_test
from scripts.interop import same_interface_gateway_lifecycle as gateway_lifecycle


def _gateway_cli_args(*extra: str) -> list[str]:
    return [
        "--same-interface-gateway-only",
        "--appliance-ssh-hostkey",
        "SHA256:router-host-key",
        "--gateway-client-host",
        "192.0.2.20",
        "--gateway-client-hostkey",
        "SHA256:client-host-key",
        "--gateway-upstream",
        "192.0.2.1",
        "--gateway-expected-commit",
        "a" * 40,
        *extra,
    ]


def test_gateway_lifecycle_cli_requires_client_identity_upstream_and_exact_commit():
    """Admit a focused run only with both pinned identity data and the full commit."""
    accepted = lifecycle_test.parse_args(_gateway_cli_args())
    assert accepted.gateway_client_host == "192.0.2.20"
    assert accepted.gateway_upstream == "192.0.2.1"
    assert accepted.gateway_expected_commit == "a" * 40

    for option in (
        "--appliance-ssh-hostkey",
        "--gateway-client-host",
        "--gateway-client-hostkey",
        "--gateway-upstream",
    ):
        args = _gateway_cli_args()
        index = args.index(option)
        del args[index : index + 2]
        with pytest.raises(SystemExit):
            lifecycle_test.parse_args(args)

    for commit in ("a" * 39, "A" * 40, "z" * 40):
        args = _gateway_cli_args()
        args[-1] = commit
        with pytest.raises(SystemExit):
            lifecycle_test.parse_args(args)


@pytest.mark.parametrize(
    "mode",
    [
        "--routing-wan-only",
        "--time-source-only",
        "--oidc-only",
        "--reverse-proxy-only",
        "--restored-state-run",
        "--export-settings-backup",
        "--restore-settings-backup",
        "--signed-release-repository-url",
    ],
)
def test_gateway_lifecycle_cli_rejects_mixed_modes(mode):
    """The same-interface scenario cannot share a run with another mutation mode."""
    args = _gateway_cli_args()
    args.extend([mode, "fixture-value"] if mode in {
        "--export-settings-backup", "--restore-settings-backup", "--signed-release-repository-url"
    } else [mode])

    with pytest.raises(SystemExit):
        lifecycle_test.parse_args(args)


def test_gateway_lifecycle_plan_keeps_secrets_out_and_lists_native_path_checks():
    """The plan exposes focused acceptance checks without carrying credentials."""
    args = lifecycle_test.parse_args(_gateway_cli_args())
    args.password = "lifecycle-web-secret"
    args.appliance_ssh_password = "lifecycle-appliance-secret"
    args.ssh_password = "lifecycle-client-secret"
    plan = lifecycle_test.lifecycle_plan(args)
    rendered = json.dumps(plan)

    assert plan["apply_units"] == ["ntpd", "network", "wan", "firewall"]
    assert plan["client_host"] == args.gateway_client_host
    assert plan["upstream"] == args.gateway_upstream
    assert plan["source_commit"] == args.gateway_expected_commit
    assert "exclusive fixture clock authority" in plan["checks"]
    assert any("MAC and TTL evidence" in check for check in plan["checks"])
    assert any("negative permission control" in check for check in plan["checks"])
    assert any("recovery and reboot persistence" in check for check in plan["checks"])
    assert "external IP separate from DNS" in plan["checks"]
    assert all(secret not in rendered for secret in (
        args.password, args.appliance_ssh_password, args.ssh_password,
    ))
    assert not any("password" in key.lower() or "secret" in key.lower() for key in plan)


def test_gateway_rows_parser_decodes_html_escaped_data_json():
    """Parse the server-rendered row payload after HTML attribute escaping."""
    rows = [{"id": 8, "name": 'Gateway "east" & north', "enabled": True}]
    markup = f'<div data-rules="{html.escape(json.dumps(rows), quote=True)}"></div>'
    parser = gateway_lifecycle._Rows("data-rules")

    parser.feed(markup)

    assert parser.rows == rows


def test_source_hashes_normalize_newlines_for_admitted_lifecycle_sources(tmp_path):
    """Hash the same text whether the checked-out source uses LF or CRLF bytes."""
    sources = {
        "atlaso/app/services/firewall.py": b"firewall\r\nsource\r\n",
        "atlaso/app/services/routing_permissions.py": b"permissions\nsource\n",
        "scripts/appliance/atlaso-helper": b"#!/bin/sh\r\nhelper\r\n",
    }
    for relative, content in sources.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    hashes = gateway_lifecycle.source_hashes(tmp_path)

    expected = {
        relative: hashlib.sha256(content.replace(b"\r\n", b"\n")).hexdigest()
        for relative, content in sources.items()
    }
    assert hashes == expected


def test_gateway_secret_envelope_and_dispatch_skip_legacy_api_client(monkeypatch, tmp_path):
    """Focused stdin credentials work without VCF secrets or the generic API client."""
    args = lifecycle_test.parse_args(
        _gateway_cli_args("--secret-stdin", "--result-dir", str(tmp_path))
    )
    envelope = {
        "password": "gateway-web-fixture-secret",
        "appliance_ssh_password": "gateway-appliance-fixture-secret",
        "ssh_password": "gateway-client-fixture-secret",
    }
    dispatched = []

    class FakeLoader:
        def create_module(self, spec):
            return None

        def exec_module(self, module):
            def accept(lifecycle, results, received_args):
                assert lifecycle is lifecycle_test
                assert received_args.password == envelope["password"]
                assert received_args.appliance_ssh_password == envelope["appliance_ssh_password"]
                assert received_args.ssh_password == envelope["ssh_password"]
                assert received_args.vcf_backup_password == ""
                assert results == []
                dispatched.append("same-interface")

            module.run_same_interface_gateway_acceptance = accept

    fake_spec = importlib.machinery.ModuleSpec("fake_gateway_lifecycle", FakeLoader())
    monkeypatch.setattr(lifecycle_test, "parse_args", lambda: args)
    monkeypatch.setattr(lifecycle_test.sys, "stdin", io.StringIO(json.dumps(envelope)))
    monkeypatch.setattr(lifecycle_test.importlib.util, "spec_from_file_location", lambda *_args: fake_spec)
    monkeypatch.setattr(
        lifecycle_test,
        "HttpClient",
        lambda *_args: pytest.fail("Focused gateway dispatch must not create the legacy API client."),
    )

    assert lifecycle_test.main() == 0
    assert dispatched == ["same-interface"]
    result_text = (tmp_path / "result.json").read_text(encoding="utf-8")
    assert json.loads(result_text)["status"] == "passed"
    assert all(secret not in result_text for secret in envelope.values())


def _link(name: str, *, flags: list[str], addr_info: list[dict] | None = None) -> dict:
    return {
        "ifname": name,
        "flags": flags,
        "addr_info": addr_info or [],
        "address": "02:00:00:00:00:01",
    }


def _inventory(*links: dict) -> dict:
    return {"addresses": [_link("lo", flags=["UP"]), *links]}


def test_active_nat_link_accepts_eth0_with_or_without_inert_inherited_adapter():
    """Keep the active NAT identity while tolerating only an inert extra NIC."""
    eth0 = _link("eth0", flags=["BROADCAST", "UP"], addr_info=[{"family": "inet"}])
    assert gateway_lifecycle._active_nat_link(_inventory(eth0)) is eth0

    down = _link("eth1", flags=["BROADCAST"])
    assert gateway_lifecycle._active_nat_link(_inventory(eth0, down)) is eth0


@pytest.mark.parametrize(
    "extra_link",
    [
        _link("eth1", flags=["BROADCAST", "UP"]),
        _link("eth1", flags=["BROADCAST"], addr_info=[{"family": "inet", "local": "192.0.2.30"}]),
        _link("eth1", flags=["BROADCAST"], addr_info=[{"family": "inet6", "local": "2001:db8::30"}]),
    ],
    ids=["up-without-address", "ipv4-addressed", "ipv6-addressed"],
)
def test_active_nat_link_rejects_other_active_or_addressed_adapters(extra_link):
    """An inherited adapter must be down and have no IPv4 or IPv6 addresses."""
    eth0 = _link("eth0", flags=["BROADCAST", "UP"], addr_info=[{"family": "inet"}])

    with pytest.raises(gateway_lifecycle.GatewayLifecycleError, match="Only the NAT eth0 adapter"):
        gateway_lifecycle._active_nat_link(_inventory(eth0, extra_link))


def test_active_nat_link_rejects_inventory_without_eth0():
    """A passive inherited NIC cannot replace the receipt-bound NAT adapter."""
    with pytest.raises(gateway_lifecycle.GatewayLifecycleError, match="Only the NAT eth0 adapter"):
        gateway_lifecycle._active_nat_link(_inventory(_link("eth1", flags=["BROADCAST"])))


def test_gateway_guest_inventory_uses_role_specific_pinned_ssh_credentials(monkeypatch):
    """Initial router/client native reads use their own usernames and SSH passwords."""
    args = lifecycle_test.parse_args(
        _gateway_cli_args(
            "--appliance-ssh-host",
            "192.0.2.10",
            "--appliance-ssh-user",
            "router-operator",
            "--client-ssh-user",
            "client-operator",
        )
    )
    args.password = "browser-login-fixture-secret"
    args.appliance_ssh_password = "router-ssh-fixture-secret"
    args.ssh_password = "client-ssh-fixture-secret"
    calls = []
    results = []

    def fake_pinned_ssh(host, username, password, fingerprint, command, **kwargs):
        calls.append((host, username, password, fingerprint, command, kwargs))
        inventory = {
            "forwarding": "0",
            "addresses": [
                {"ifname": "lo", "flags": ["UP"], "addr_info": []},
                {
                    "ifname": "eth0",
                    "flags": ["BROADCAST", "UP"],
                    "addr_info": [{"family": "inet", "local": host, "prefixlen": 24}],
                    "address": "02:00:00:00:00:01" if host == "192.0.2.10" else "02:00:00:00:00:02",
                },
            ]
        }
        return json.dumps(inventory).encode()

    class StopAtUiLogin(Exception):
        pass

    monkeypatch.setattr(gateway_lifecycle, "run_pinned_ssh_command", fake_pinned_ssh)
    monkeypatch.setattr(lifecycle_test, "HttpClient", lambda *_args: object())
    monkeypatch.setattr(lifecycle_test, "ui_login", lambda *_args: (_ for _ in ()).throw(StopAtUiLogin()))

    with pytest.raises(StopAtUiLogin):
        gateway_lifecycle.run_same_interface_gateway_acceptance(lifecycle_test, results, args)

    assert [(call[0], call[1], call[2], call[3]) for call in calls] == [
        ("192.0.2.10", "router-operator", "router-ssh-fixture-secret", "SHA256:router-host-key"),
        ("192.0.2.20", "client-operator", "client-ssh-fixture-secret", "SHA256:client-host-key"),
    ]
    assert all(call[2] != args.password for call in calls)
    assert all(call[4].endswith("/opt/atlaso/.venv/bin/python -I -") for call in calls)
    assert [step.name for step in results] == ["gateway-inventory-router", "gateway-inventory-client"]
    assert all(step.status == "passed" for step in results)


def test_gateway_client_username_default_and_explicit_overrides():
    """Use admin in focused gateway mode and retain ordinary or explicit user choices."""
    gateway_args = lifecycle_test.parse_args(_gateway_cli_args())
    ordinary_args = lifecycle_test.parse_args([])
    client_override = lifecycle_test.parse_args(_gateway_cli_args("--client-ssh-user", "gateway-client"))
    shared_override = lifecycle_test.parse_args(_gateway_cli_args("--ssh-user", "compat-user"))

    assert gateway_args.client_ssh_user == "admin"
    assert lifecycle_test.ssh_username(gateway_args, "client") == "admin"
    assert ordinary_args.client_ssh_user == "alpine"
    assert lifecycle_test.ssh_username(ordinary_args, "client") == "alpine"
    assert lifecycle_test.ssh_username(client_override, "client") == "gateway-client"
    assert lifecycle_test.ssh_username(shared_override, "appliance") == "compat-user"
    assert lifecycle_test.ssh_username(shared_override, "client") == "compat-user"


def test_gateway_plan_only_runs_with_isolated_python_imports(tmp_path):
    """The standalone lifecycle entry point loads its exact sibling under python -I."""
    runner = Path(lifecycle_test.__file__).resolve()
    result_dir = tmp_path / "isolated-result"
    command = [
        sys.executable,
        "-B",
        "-I",
        "-X",
        f"pycache_prefix={tmp_path / 'bytecode'}",
        str(runner),
        *_gateway_cli_args("--plan-only", "--result-dir", str(result_dir)),
    ]
    completed = subprocess.run(
        command,
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    result = json.loads((result_dir / "result.json").read_text(encoding="utf-8"))
    assert result["status"] == "planned"
    assert result["plan"]["same_interface_gateway_only"] is True
    assert result["plan"]["apply_units"] == ["ntpd", "network", "wan", "firewall"]
