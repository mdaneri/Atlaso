"""Exercise same-interface gateway lifecycle admission and evidence helpers."""

from __future__ import annotations

import hashlib
import html
import importlib.machinery
import io
import json

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

    assert plan["apply_units"] == ["network", "wan", "firewall"]
    assert plan["client_host"] == args.gateway_client_host
    assert plan["upstream"] == args.gateway_upstream
    assert plan["source_commit"] == args.gateway_expected_commit
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
