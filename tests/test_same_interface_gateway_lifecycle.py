"""Exercise same-interface gateway lifecycle admission and evidence helpers."""

from __future__ import annotations

import hashlib
import html
import http.client
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
    """Return valid required lifecycle flags plus optional additions.

    Args:
        *extra: Additional lifecycle command-line arguments.
    """
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
    """The same-interface scenario cannot share a run with another mutation mode.

    Args:
        mode: Conflicting lifecycle mode or backup option.
    """
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
    """Hash the same text whether the checked-out source uses LF or CRLF bytes.

    Args:
        tmp_path: Isolated source tree used to provide test content.
    """
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
    """Focused stdin credentials work without VCF secrets or the generic API client.

    Args:
        monkeypatch: Replace lifecycle dispatch and stdin with bounded test doubles.
        tmp_path: Isolated result directory for the lifecycle command.
    """
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
            """Use the default module allocator for the synthetic loader.

            Args:
                spec: Import specification for the mocked acceptance module.
            """
            return None

        def exec_module(self, module):
            """Attach the mocked acceptance entry point to the module.

            Args:
                module: Synthetic module receiving the acceptance callback.
            """
            def accept(lifecycle, results, received_args):
                """Check focused credential loading and record dispatch.

                Args:
                    lifecycle: Lifecycle helpers passed to the acceptance module.
                    results: Mutable lifecycle step collection.
                    received_args: Parsed options populated from stdin.
                """
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
    """Build one synthetic native address inventory record.

    Args:
        name: Interface name reported by the native inventory.
        flags: Link state flags returned by ``ip -j addr``.
        addr_info: Address records associated with the interface.
    """
    return {
        "ifname": name,
        "flags": flags,
        "addr_info": addr_info or [],
        "address": "02:00:00:00:00:01",
    }


def _inventory(*links: dict) -> dict:
    """Build an address inventory with loopback plus supplied links.

    Args:
        *links: Non-loopback interface records to include.
    """
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
    """An inherited adapter must be down and have no IPv4 or IPv6 addresses.

    Args:
        extra_link: Inherited interface state that must fail admission.
    """
    eth0 = _link("eth0", flags=["BROADCAST", "UP"], addr_info=[{"family": "inet"}])

    with pytest.raises(gateway_lifecycle.GatewayLifecycleError, match="Only the NAT eth0 adapter"):
        gateway_lifecycle._active_nat_link(_inventory(eth0, extra_link))


def test_active_nat_link_rejects_inventory_without_eth0():
    """A passive inherited NIC cannot replace the receipt-bound NAT adapter."""
    with pytest.raises(gateway_lifecycle.GatewayLifecycleError, match="Only the NAT eth0 adapter"):
        gateway_lifecycle._active_nat_link(_inventory(_link("eth1", flags=["BROADCAST"])))


def test_gateway_guest_inventory_uses_role_specific_pinned_ssh_credentials(monkeypatch):
    """Initial router/client native reads use their own usernames and SSH passwords.

    Args:
        monkeypatch: Replace pinned SSH and the UI login with bounded test doubles.
    """
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
    clients = []
    root_ca = "-----BEGIN CERTIFICATE-----\nPublic fixture CA\n-----END CERTIFICATE-----\n"

    def fake_pinned_ssh(host, username, password, fingerprint, command, **kwargs):
        """Return the guest's initial inventory or fixture CA over pinned SSH.

        Args:
            host: IPv4 address selected for the guest connection.
            username: Role-specific SSH username used by the lifecycle.
            password: Role-specific SSH password used by the lifecycle.
            fingerprint: Pinned public SSH identity for the guest.
            command: Bounded Python command sent to the guest.
            **kwargs: Stdin program and other SSH transport options.
        """
        calls.append((host, username, password, fingerprint, command, kwargs))
        if b"/etc/atlaso/ca/root-ca.pem" in kwargs["stdin_data"]:
            return root_ca.encode()
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

    class DummyLifecycleClient:
        def __init__(self, base_url, *, trusted_ca_pem=None):
            """Capture the client URL and trusted CA passed before browser login.

            Args:
                base_url: Management URL for the guest.
                trusted_ca_pem: Public root CA supplied to the HTTPS client.
            """
            self.base_url = base_url
            self.trusted_ca_pem = trusted_ca_pem
            clients.append(self)

        def request_bytes(self, *_args, **_kwargs):
            """Fail if the inventory test unexpectedly sends an HTTP request.

            Args:
                *_args: Request method and path that were not expected yet.
                **_kwargs: Request options that were not expected yet.
            """
            pytest.fail("The inventory test stops before an HTTP request.")

    monkeypatch.setattr(gateway_lifecycle, "run_pinned_ssh_command", fake_pinned_ssh)
    monkeypatch.setattr(lifecycle_test, "HttpClient", DummyLifecycleClient)
    monkeypatch.setattr(lifecycle_test, "ui_login", lambda *_args: (_ for _ in ()).throw(StopAtUiLogin()))

    with pytest.raises(StopAtUiLogin):
        gateway_lifecycle.run_same_interface_gateway_acceptance(lifecycle_test, results, args)

    assert [(call[0], call[1], call[2], call[3]) for call in calls] == [
        ("192.0.2.10", "router-operator", "router-ssh-fixture-secret", "SHA256:router-host-key"),
        ("192.0.2.20", "client-operator", "client-ssh-fixture-secret", "SHA256:client-host-key"),
        ("192.0.2.10", "router-operator", "router-ssh-fixture-secret", "SHA256:router-host-key"),
    ]
    assert all(call[2] != args.password for call in calls)
    assert all(call[4].endswith("/opt/atlaso/.venv/bin/python -I -") for call in calls)
    assert b"/etc/atlaso/ca/root-ca.pem" in calls[2][5]["stdin_data"]
    assert len(clients) == 1
    assert clients[0].base_url == "https://192.0.2.10"
    assert clients[0].trusted_ca_pem == root_ca
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
    """The standalone lifecycle entry point loads its exact sibling under python -I.

    Args:
        tmp_path: Isolated working and result directory for the subprocess.
    """
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


def _gateway_client_with_responses(monkeypatch, responses):
    """Construct the retry client around a queued-response transport double.

    Args:
        monkeypatch: Patch module backoff to prevent real sleeps.
        responses: Ordered response tuples or exceptions for the fake transport.
    """
    calls = []
    sleeps = []

    class BaseClient:
        def __init__(self, base_url):
            """Store the fake transport base URL.

            Args:
                base_url: Management origin assigned to the fake client.
            """
            self.base_url = base_url

        def request_bytes(self, method, path, **kwargs):
            """Return or raise the next queued transport outcome.

            Args:
                method: HTTP method supplied to the client.
                path: Request path supplied to the client.
                **kwargs: Request options supplied to the client.
            """
            calls.append((method, path, kwargs))
            response = responses.pop(0)
            if isinstance(response, BaseException):
                raise response
            return response

    monkeypatch.setattr(gateway_lifecycle.time, "sleep", sleeps.append)
    client_type = gateway_lifecycle._gateway_http_client_type(BaseClient)
    return client_type("https://192.0.2.10"), calls, sleeps


@pytest.mark.parametrize("method", ["GET", "HEAD"])
@pytest.mark.parametrize("status", [502, 503, 504])
def test_gateway_http_read_retries_transient_handoff_status(monkeypatch, method, status):
    """GET and HEAD retry only transient gateway statuses and recover on success.

    Args:
        monkeypatch: Patch backoff to avoid real sleeps.
        method: Read-only HTTP method under test.
        status: Transient gateway status returned before recovery.
    """
    client, calls, sleeps = _gateway_client_with_responses(
        monkeypatch,
        [(status, b"handoff", {}), (200, b"ready", {})],
    )

    response = client.request_bytes(method, "/dashboard")

    assert response == (200, b"ready", {})
    assert [call[0] for call in calls] == [method, method]
    assert sleeps == [2]
    assert all(call[2]["timeout"] <= 30 for call in calls)


@pytest.mark.parametrize("method", ["GET", "HEAD"])
@pytest.mark.parametrize(
    "error",
    [OSError("connection reset"), http.client.RemoteDisconnected("connection closed")],
    ids=["os-error", "http-error"],
)
def test_gateway_http_read_retries_transient_connection_errors(monkeypatch, method, error):
    """GET and HEAD recover from bounded socket and HTTP protocol failures.

    Args:
        monkeypatch: Patch backoff to avoid real sleeps.
        method: Read-only HTTP method under test.
        error: Transient connection error raised before recovery.
    """
    client, calls, sleeps = _gateway_client_with_responses(
        monkeypatch,
        [error, (200, b"ready", {})],
    )

    response = client.request_bytes(method, "/routes-wan")

    assert response == (200, b"ready", {})
    assert [call[0] for call in calls] == [method, method]
    assert sleeps == [2]


@pytest.mark.parametrize("status", [401, 500])
def test_gateway_http_read_does_not_retry_auth_or_validation_responses(monkeypatch, status):
    """Authentication and ordinary application errors are returned unchanged.

    Args:
        monkeypatch: Patch backoff to check that no sleep occurs.
        status: Non-retryable response status to return unchanged.
    """
    client, calls, sleeps = _gateway_client_with_responses(
        monkeypatch,
        [(status, b"rejected", {})],
    )

    assert client.request_bytes("GET", "/routes-wan") == (status, b"rejected", {})
    assert len(calls) == 1
    assert sleeps == []


@pytest.mark.parametrize(
    "outcome",
    [(503, b"handoff", {}), OSError("connection reset")],
    ids=["transient-status", "connection-error"],
)
def test_gateway_http_mutation_never_retries(monkeypatch, outcome):
    """POST keeps the canonical transport's single-attempt mutation semantics.

    Args:
        monkeypatch: Patch backoff to check that no sleep occurs.
        outcome: Mutation response or connection error from the fake transport.
    """
    client, calls, sleeps = _gateway_client_with_responses(monkeypatch, [outcome])

    if isinstance(outcome, BaseException):
        with pytest.raises(OSError, match="connection reset"):
            client.request_bytes("POST", "/routes-wan/routing-rules", form={"enabled": "on"})
    else:
        assert client.request_bytes("POST", "/routes-wan/routing-rules", form={"enabled": "on"}) == outcome
    assert len(calls) == 1
    assert sleeps == []


def test_gateway_http_read_retry_limit_is_five_without_real_sleep(monkeypatch):
    """A sustained handoff gets at most five reads and four patched backoffs.

    Args:
        monkeypatch: Patch backoff to count sleeps without waiting.
    """
    client, calls, sleeps = _gateway_client_with_responses(
        monkeypatch,
        [(503, b"handoff", {})] * 5,
    )

    response = client.request_bytes("GET", "/tasks/status")

    assert response == (503, b"handoff", {})
    assert len(calls) == 5
    assert sleeps == [2, 2, 2, 2]
    assert all(call[2]["timeout"] <= 30 for call in calls)


def test_gateway_http_read_does_not_retry_after_deadline(monkeypatch):
    """A slow transient response cannot extend read retries beyond 30 seconds.

    Args:
        monkeypatch: Replace the clock and backoff with deterministic test doubles.
    """
    now = [0.0]
    calls = []
    sleeps = []

    class SlowResponseClient:
        def __init__(self, base_url):
            """Store the fake transport's management URL.

            Args:
                base_url: Management origin assigned to the fake client.
            """
            self.base_url = base_url

        def request_bytes(self, method, path, **kwargs):
            """Advance the fake clock by the selected request timeout.

            Args:
                method: HTTP method supplied to the fake transport.
                path: Request path supplied to the fake transport.
                **kwargs: Retry-provided request options, including timeout.
            """
            calls.append((method, path, kwargs["timeout"]))
            now[0] += kwargs["timeout"]
            return 503, b"handoff", {}

    monkeypatch.setattr(gateway_lifecycle.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(gateway_lifecycle.time, "sleep", lambda seconds: (sleeps.append(seconds), now.__setitem__(0, now[0] + seconds)))
    client = gateway_lifecycle._gateway_http_client_type(SlowResponseClient)("https://192.0.2.10")

    with pytest.raises(gateway_lifecycle.GatewayLifecycleError, match="within 30 seconds"):
        client.request_bytes("GET", "/tasks/status")
    assert calls == [("GET", "/tasks/status", 30)]
    assert sleeps == []
