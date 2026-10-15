"""Focused tests for graceful nginx activation during management handoff."""

import importlib.machinery
import importlib.util
import json
import re
import subprocess
from ipaddress import ip_address
from pathlib import Path

import pytest

from atlaso.app.services.public_services import render_public_services_nginx_config

HELPER_PATH = Path(__file__).resolve().parents[1] / "scripts" / "appliance" / "atlaso-helper"


def load_helper_module():
    """Load the executable appliance helper as a Python module."""
    loader = importlib.machinery.SourceFileLoader("atlaso_helper_nginx_activation", str(HELPER_PATH))
    spec = importlib.util.spec_from_loader("atlaso_helper_nginx_activation", loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def test_active_workers_reports_master_and_worker_start_identity(monkeypatch, tmp_path):
    """Use Linux start time with PID to distinguish a reloaded worker generation.

    Args:
        monkeypatch: Replace procfs and process probes with an isolated fixture.
        tmp_path: Temporary procfs tree for the synthetic nginx processes.
    """
    helper = load_helper_module()
    proc_root = tmp_path / "proc"
    worker_dir = proc_root / "431"
    (worker_dir / "task" / "431").mkdir(parents=True)
    (worker_dir / "task" / "431" / "children").write_text("432 433\n", encoding="utf-8")
    (proc_root / "432").mkdir()
    (proc_root / "432" / "cmdline").write_bytes(b"nginx: worker process\0")
    worker_fields = ["S", *(str(value) for value in range(1, 20))]
    (proc_root / "432" / "stat").write_text(
        "432 (nginx) " + " ".join(worker_fields), encoding="utf-8",
    )
    (proc_root / "433").mkdir()
    (proc_root / "433" / "cmdline").write_bytes(b"nginx: cache manager process\0")
    (proc_root / "433" / "stat").write_text("433 (nginx) S " + " ".join("1" for _ in range(20)), encoding="utf-8")

    monkeypatch.setattr(
        helper, "Path",
        lambda value: proc_root if str(value) == "/proc" else proc_root / str(value).lstrip("/\\"),
    )
    monkeypatch.setattr(
        helper, "_run",
        lambda command, **_kwargs: subprocess.CompletedProcess(command, 0, "431\n", ""),
    )

    assert helper._nginx_active_workers() == (431, {(432, 19)})


def test_reload_nginx_waits_for_new_worker_generation_without_restart(monkeypatch):
    """A successful signal command is insufficient until new workers accept.

    Args:
        monkeypatch: Replace nginx generation observations and systemd reload.
    """
    helper = load_helper_module()
    generations = iter([(431, {(432, 19)}), (431, {(433, 20)})])
    commands = []
    monkeypatch.setattr(helper, "_nginx_active_workers", lambda: next(generations))
    monkeypatch.setattr(
        helper, "_run",
        lambda command, **_kwargs: commands.append(command)
        or subprocess.CompletedProcess(command, 0, "", ""),
    )

    assert helper._reload_nginx(verify_activation=True) == 0
    assert commands == [["systemctl", "reload", "nginx"]]


def test_reload_nginx_rejects_successful_signal_without_new_workers(monkeypatch, capsys):
    """Do not report activation or use restart when reload leaves old workers.

    Args:
        monkeypatch: Replace time, worker observations, and systemd reload.
        capsys: Capture the diagnostic that explains the failed activation.
    """
    helper = load_helper_module()
    commands = []
    ticks = iter(value / 4 for value in range(100))
    monkeypatch.setattr(helper, "_nginx_active_workers", lambda: (431, {(432, 19)}))
    monkeypatch.setattr(helper.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(helper.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        helper, "_run",
        lambda command, **_kwargs: commands.append(command)
        or subprocess.CompletedProcess(command, 0, "", ""),
    )

    assert helper._reload_nginx(verify_activation=True) == 1
    assert commands == [["systemctl", "reload", "nginx"]]
    assert "restart was not attempted" in capsys.readouterr().err


def test_management_handoff_reuseport_is_added_once_to_every_listener():
    """Arm every handoff socket while keeping the transform idempotent."""
    helper = load_helper_module()
    site = (
        "server {\n"
        "  listen 443 ssl default_server;\n"
        "  listen [::]:443 ssl default_server reuseport;\n"
        "}\n"
    )

    transformed = helper._management_handoff_reuseport_site(site)

    assert transformed.count("reuseport") == 2
    assert "listen 443 ssl default_server reuseport;" in transformed
    assert "listen [::]:443 ssl default_server reuseport;" in transformed
    assert helper._management_handoff_reuseport_site(transformed) == transformed


@pytest.mark.parametrize(
    ("address", "oidc_port"),
    [
        ("192.0.2.20", 443),
        ("2001:db8::20", 443),
        ("192.0.2.20", 8443),
        ("2001:db8::20", 8443),
    ],
)
def test_reuseport_is_declared_once_per_rendered_public_socket(address, oidc_port):
    """Arm each socket once in rendered cohosted CA, OIDC, and management sites.

    Args:
        address: IPv4 or IPv6 Access address shared by the rendered services.
        oidc_port: OIDC HTTPS port, shared with or separate from the CA listener.
    """
    helper = load_helper_module()
    site = render_public_services_nginx_config(
        [
            {
                "interface": "eth1",
                "role": "access",
                "address": address,
                "management_ui": True,
                "services": [
                    {"id": "ca", "dns_names": ["ca.example.test"]},
                    {"id": "oidc", "port": oidc_port, "dns_names": ["identity.example.test"]},
                ],
            },
        ],
        ca_certificate_path="/ca.crt",
        ca_key_path="/ca.key",
        oidc_certificate_path="/oidc.crt",
        oidc_key_path="/oidc.key",
        management_certificate_path="/management.crt",
        management_key_path="/management.key",
    )

    transformed = helper._management_handoff_reuseport_site(site)
    sockets: dict[tuple[str, int], list[list[str]]] = {}
    for line in transformed.splitlines():
        match = re.fullmatch(r"\s*listen\s+(\S+)(?:\s+(.*))?;", line)
        if match is None:
            continue
        endpoint = match.group(1)
        if endpoint.startswith("["):
            host, port = endpoint[1:].split("]:", 1)
        else:
            host, port = endpoint.rsplit(":", 1)
        sockets.setdefault((str(ip_address(host)), int(port)), []).append(
            (match.group(2) or "").split(),
        )

    assert sockets
    for declarations in sockets.values():
        assert sum("reuseport" in options for options in declarations) == 1
    if oidc_port == 443:
        assert len(sockets[(str(ip_address(address)), 443)]) == 3
    else:
        assert len(sockets[(str(ip_address(address)), 443)]) == 2
        assert len(sockets[(str(ip_address(address)), 8443)]) == 1
    assert helper._management_handoff_reuseport_site(transformed) == transformed


def test_reuseport_preserves_later_existing_socket_owner_and_normalizes_aliases():
    """Keep a later preexisting option owner and coalesce equivalent endpoints."""
    helper = load_helper_module()
    site = (
        "server {\n"
        "  listen 443 ssl default_server;\n"
        "  listen 0.0.0.0:443 ssl;\n"
        "  listen *:443 ssl reuseport;\n"
        "  listen [2001:db8::20]:443 ssl;\n"
        "  listen [2001:0db8:0:0:0:0:0:20]:443 ssl reuseport;\n"
        "}\n"
    )

    transformed = helper._management_handoff_reuseport_site(site)
    listeners = [line for line in transformed.splitlines() if line.strip().startswith("listen ")]

    assert ["reuseport" in line.removesuffix(";").split() for line in listeners] == [
        False, False, True, False, True,
    ]
    assert helper._management_handoff_reuseport_site(transformed) == transformed


@pytest.mark.parametrize("reuseport", [False, True])
def test_committed_reuseport_preserves_settings_scope_and_public_tls_ownership(monkeypatch, tmp_path, reuseport):
    """A later Apply must read both committed dedicated and Access TLS listeners.

    Args:
        monkeypatch: Isolate management and Public Services site paths.
        tmp_path: Temporary files containing committed site snapshots.
        reuseport: Whether the persisted generated listeners carry the option.
    """
    helper = load_helper_module()
    management = tmp_path / "management.conf"
    public = tmp_path / "public.conf"
    backup = tmp_path / "public.snapshot"
    addresses = ["127.0.0.1", "::1", "192.0.2.10", "2001:db8::10"]
    text = helper._management_nginx_config(
        {"fqdn": "atlaso.example.test", "management_https_enabled": True},
        Path("/etc/atlaso/management.crt"), Path("/etc/atlaso/management.key"),
        listen_addresses=addresses, https_listen_addresses=["127.0.0.1", "::1"],
    )
    public_text = (
        "# Managed by Atlaso. Local changes may be overwritten.\nserver {\n"
        "  listen 192.0.2.10:443 ssl default_server;\n"
        "  listen [2001:db8::10]:443 ssl default_server;\n  server_name _;\n}\n"
    )
    if reuseport:
        text = helper._management_handoff_reuseport_site(text)
        public_text = helper._management_handoff_reuseport_site(public_text)
    management.write_text(text, encoding="utf-8")
    public.write_text(public_text, encoding="utf-8")
    backup.write_text(public_text, encoding="utf-8")
    monkeypatch.setattr(helper, "NGINX_MANAGEMENT_SITE_PATH", management)
    monkeypatch.setattr(helper, "NGINX_PUBLIC_SERVICES_SITE_PATH", public)
    monkeypatch.setattr(helper, "_install_nginx_site", lambda *_args, **_kwargs: pytest.fail("scope changed"))
    preserved = helper._existing_management_scoped_addresses()
    assert set(preserved[0]) == set(addresses)
    assert set(preserved[1]) == {"127.0.0.1", "::1"}
    assert preserved[2:] == (80, 443)
    state = {
        "previous_management_addresses": ["192.0.2.10", "2001:db8::10"],
        "previous_https_enabled": True,
        "previous_management_public_port": 443,
        "snapshots": [{"path": str(public), "backup": str(backup)}],
    }
    expected = {"192.0.2.10", "2001:db8::10"}
    assert helper._management_handoff_previous_public_tls_addresses(state) == expected
    assert helper._management_handoff_candidate_public_tls_addresses(public, 443) == expected
    helper._scope_management_handoff_old_listener(state)
    assert management.read_text(encoding="utf-8") == text


def test_old_listener_migration_stops_after_unverified_wildcard_bridge(monkeypatch, tmp_path):
    """Do not scope the old listener until its reuseport bridge is active.

    Args:
        monkeypatch: Replace journal and nginx installation boundaries.
        tmp_path: Temporary prior management site.
    """
    helper = load_helper_module()
    site = tmp_path / "management.conf"
    original = (
        "# Managed by Atlaso. Local changes may be overwritten.\n"
        "server {\n  listen 80 default_server;\n  listen 443 ssl default_server;\n}\n"
    )
    site.write_text(original, encoding="utf-8")
    events = []
    monkeypatch.setattr(helper, "NGINX_MANAGEMENT_SITE_PATH", site)
    monkeypatch.setattr(
        helper, "_write_management_handoff_state",
        lambda state, phase: events.append(("journal", state.copy(), phase)),
    )

    def install(_path, text, *, verify_activation=False):
        """Record each installation before simulating an activation failure.

        Args:
            _path: Management site path passed to the installer.
            text: Candidate configuration requested for installation.
            verify_activation: Whether a new accepting worker generation is required.
        """
        events.append(("install", text, verify_activation))
        return 1

    monkeypatch.setattr(helper, "_install_nginx_site", install)

    with pytest.raises(ValueError, match="previous wildcard nginx socket could not be prepared"):
        helper._scope_management_handoff_old_listener({
            "previous_https_enabled": True,
            "previous_management_addresses": ["192.0.2.10"],
        })

    assert events[0][0] == "journal"
    assert events[0][1]["nginx_reuseport_bridge"] is True
    assert events[1][0] == "install"
    assert events[1][2] is True
    assert len(events) == 2
    assert site.read_text(encoding="utf-8") == original


def test_restore_management_handoff_nginx_bridge_persists_exact_prior_bytes(monkeypatch, tmp_path):
    """Use a transient reusable wildcard, then persist and reload the exact prior site.

    Args:
        monkeypatch: Replace service state, filesystem sync, validation, and reload.
        tmp_path: Temporary management site whose original bytes must be restored.
    """
    helper = load_helper_module()
    site = tmp_path / "management.conf"
    original = (
        b"# Managed by Atlaso. Local changes may be overwritten.\n"
        b"server {\n  listen 443 ssl default_server;\n}\n"
    )
    site.write_bytes(original)
    events = []
    monkeypatch.setattr(helper, "NGINX_MANAGEMENT_SITE_PATH", site)
    monkeypatch.setattr(
        helper, "_run",
        lambda command, **_kwargs: subprocess.CompletedProcess(
            command, 0, "ActiveState=active\nMainPID=431\n", "",
        ),
    )

    def install(_path, text, *, verify_activation=False):
        """Record transient rollback configuration and accept its activation.

        Args:
            _path: Management site path passed to the installer.
            text: Transient reusable-wildcard configuration.
            verify_activation: Whether a new accepting worker generation is required.
        """
        events.append(("install", text, verify_activation))
        return 0

    monkeypatch.setattr(helper, "_install_nginx_site", install)
    monkeypatch.setattr(helper, "_fsync_file", lambda path: events.append(("fsync-file", path.read_bytes())))
    monkeypatch.setattr(helper, "_fsync_directory", lambda path: events.append(("fsync-directory", path)))
    monkeypatch.setattr(
        helper, "_nginx_test_command",
        lambda: events.append(("validate", site.read_bytes()))
        or subprocess.CompletedProcess(["nginx", "-t"], 0, "", ""),
    )
    monkeypatch.setattr(helper, "_reload_nginx", lambda **kwargs: events.append(("reload", kwargs)) or 0)

    helper._restore_management_handoff_nginx_bridge({"nginx_reuseport_bridge": True})

    assert site.read_bytes() == original
    assert events == [
        ("install", original.decode("utf-8").replace("listen 443 ssl default_server;",
                                                      "listen 443 ssl default_server reuseport;"), True),
        ("fsync-file", original),
        ("fsync-directory", site.parent),
        ("validate", original),
        ("reload", {"verify_activation": True}),
    ]


def test_restore_management_handoff_nginx_bridge_keeps_exact_prior_bytes_on_activation_failure(
    monkeypatch, tmp_path,
):
    """A failed transient wildcard activation still restores the exact site bytes.

    Args:
        monkeypatch: Replace systemd and nginx boundaries with a failed activation.
        tmp_path: Temporary site for verifying byte-exact rollback.
    """
    helper = load_helper_module()
    site = tmp_path / "management.conf"
    original = b"server {\n  listen 443 ssl default_server;\n}\n"
    site.write_bytes(original)
    events = []
    monkeypatch.setattr(helper, "NGINX_MANAGEMENT_SITE_PATH", site)
    monkeypatch.setattr(
        helper, "_run",
        lambda command, **_kwargs: subprocess.CompletedProcess(
            command, 0, "ActiveState=active\nMainPID=431\n", "",
        ),
    )
    monkeypatch.setattr(
        helper, "_install_nginx_site",
        lambda _path, text, *, verify_activation=False: events.append((text, verify_activation)) or 1,
    )
    monkeypatch.setattr(helper, "_fsync_file", lambda path: events.append(("fsync-file", path.read_bytes())))
    monkeypatch.setattr(helper, "_fsync_directory", lambda _path: None)
    monkeypatch.setattr(helper, "_nginx_test_command", lambda: pytest.fail("failed bridge must not publish old config"))
    monkeypatch.setattr(helper, "_reload_nginx", lambda **_kwargs: pytest.fail("failed bridge must not reload"))

    with pytest.raises(ValueError, match="previous nginx wildcard socket could not be restored gracefully"):
        helper._restore_management_handoff_nginx_bridge({"nginx_reuseport_bridge": True})

    assert site.read_bytes() == original
    assert events[-1] == ("fsync-file", original)
    assert events[0][1] is True


def test_restore_management_handoff_starts_inactive_nginx_without_restart(monkeypatch, tmp_path):
    """Start exact restored configuration after reboot and wait for its workers.

    Args:
        monkeypatch: Replace systemd, validation, and worker-generation probes.
        tmp_path: Temporary directory reserved for recovery-related files.
    """
    helper = load_helper_module()
    commands = []
    events = []

    def run(command, **_kwargs):
        """Simulate an inactive service and record bounded systemctl requests.

        Args:
            command: systemctl command requested by the helper.
            **_kwargs: Additional process-run options accepted by the helper.
        """
        commands.append(command)
        output = "ActiveState=inactive\nMainPID=0\n" if command[1:2] == ["show"] else ""
        return subprocess.CompletedProcess(command, 0, output, "")

    monkeypatch.setattr(helper, "_run", run)
    monkeypatch.setattr(
        helper, "_nginx_test_command",
        lambda: events.append("validate") or subprocess.CompletedProcess(["nginx", "-t"], 0, "", ""),
    )
    monkeypatch.setattr(
        helper, "_nginx_active_workers",
        lambda: events.append("workers") or (431, {(432, 19)}),
    )

    helper._restore_management_handoff_nginx_bridge({"nginx_reuseport_bridge": True})

    assert commands == [
        ["systemctl", "show", "nginx.service", "--property=ActiveState,MainPID"],
        ["systemctl", "start", "nginx.service"],
    ]
    assert events == ["validate", "workers"]


def test_restore_management_handoff_refuses_ambiguous_nginx_state(monkeypatch):
    """Do not mutate nginx when systemd cannot prove an inactive service.

    Args:
        monkeypatch: Replace systemd and make nginx mutations fail if attempted.
    """
    helper = load_helper_module()
    commands = []

    def run(command, **_kwargs):
        """Return an indeterminate active service state.

        Args:
            command: systemctl command requested by the helper.
            **_kwargs: Additional process-run options accepted by the helper.
        """
        commands.append(command)
        return subprocess.CompletedProcess(
            command, 0, "ActiveState=activating\nMainPID=431\n", "",
        )

    monkeypatch.setattr(helper, "_run", run)
    monkeypatch.setattr(helper, "_nginx_test_command", lambda: pytest.fail("ambiguous service must not validate"))
    monkeypatch.setattr(helper, "_install_nginx_site", lambda *_args, **_kwargs: pytest.fail("must not install"))
    monkeypatch.setattr(helper, "_reload_nginx", lambda **_kwargs: pytest.fail("must not reload"))

    with pytest.raises(ValueError, match="nginx rollback service state is indeterminate"):
        helper._restore_management_handoff_nginx_bridge({"nginx_reuseport_bridge": True})

    assert commands == [["systemctl", "show", "nginx.service", "--property=ActiveState,MainPID"]]


@pytest.mark.parametrize("timeout_point", ["service-state", "service-start", "worker-probe"])
def test_nginx_bridge_timeout_is_recorded_while_recovery_continues(
    monkeypatch, tmp_path, capsys, timeout_point,
):
    """Convert bridge subprocess timeouts to bounded rollback errors and continue recovery.

    Args:
        monkeypatch: Isolate rollback dependencies while keeping recovery and bridge real.
        tmp_path: Temporary journal, networkd, and nginx paths for interrupted recovery.
        capsys: Capture the structured recovery failure without traceback output.
        timeout_point: Bridge subprocess boundary that raises the timeout.
    """
    helper = load_helper_module()
    state = {
        "phase": "candidate-ready",
        "nginx_reuseport_bridge": True,
        "snapshots": [],
        "previous_management_addresses": ["192.0.2.10"],
        "previous_https_enabled": True,
        "previous_management_public_port": 443,
    }
    state_path = tmp_path / "management-handoff.json"
    state_path.write_text(json.dumps(state), encoding="utf-8")
    networkd = tmp_path / "networkd"
    networkd.mkdir()
    events = []
    commands = []
    cleared = []
    monkeypatch.setattr(helper, "MANAGEMENT_HANDOFF_STATE_PATH", state_path)
    monkeypatch.setattr(helper, "NETWORKD_CONFIG_DIR", networkd)
    monkeypatch.setattr(helper, "NETWORKD_MGMT_CONFIG_PATH", networkd / "00-atlaso-mgmt.network")
    monkeypatch.setattr(helper, "NGINX_MANAGEMENT_SITE_PATH", tmp_path / "management.conf")
    monkeypatch.setattr(helper, "NAT_RUNTIME_CONFIG_PATH", tmp_path / "nat.conf")
    monkeypatch.setattr(helper, "_quiesce_management_handoff_apply", lambda: {"state": "inactive"})
    monkeypatch.setattr(helper, "_clear_management_handoff_state", lambda: cleared.append(True))
    monkeypatch.setattr(helper, "_capture_management_handoff_lease_updates", lambda _state: None)
    monkeypatch.setattr(helper, "_stop_route_domains_for_restore", lambda _state: None)
    monkeypatch.setattr(helper, "_quiesce_management_handoff_firewall", lambda _state, _commands: None)
    monkeypatch.setattr(helper, "_restore_management_handoff_resolver", lambda _state, _commands: None)
    monkeypatch.setattr(helper, "_restore_management_handoff_links", lambda _state, _commands: None)
    monkeypatch.setattr(helper, "_wait_restored_management_addresses", lambda _state: {"stable_samples": 3})
    monkeypatch.setattr(helper, "_restore_route_domains", lambda _state: None)
    monkeypatch.setattr(helper, "_restore_management_handoff_wan", lambda _state, _commands: None)
    monkeypatch.setattr(helper, "_restore_management_handoff_firewall", lambda _state, _commands: None)
    monkeypatch.setattr(helper, "_nginx_binary", lambda: "/usr/sbin/nginx")
    monkeypatch.setattr(
        helper,
        "_nginx_test_command",
        lambda: subprocess.CompletedProcess(["nginx", "-t"], 0, "", ""),
    )

    def run(command, **kwargs):
        """Raise at the selected bridge command and accept other rollback commands.

        Args:
            command: systemd command issued by rollback or bridge restoration.
            **kwargs: Process options, including each command's timeout.
        """
        commands.append(command)
        if command == ["systemctl", "show", "nginx.service", "--property=ActiveState,MainPID"]:
            if timeout_point == "service-state":
                raise subprocess.TimeoutExpired(command, kwargs.get("timeout"))
            return subprocess.CompletedProcess(
                command, 0, "ActiveState=inactive\nMainPID=0\n", "",
            )
        if command == ["systemctl", "start", "nginx.service"]:
            if timeout_point == "service-start":
                raise subprocess.TimeoutExpired(command, kwargs.get("timeout"))
            return subprocess.CompletedProcess(command, 0, "", "")
        if command == ["systemctl", "start", "atlaso.service"]:
            events.append("atlaso-start")
        return subprocess.CompletedProcess(command, 0, "", "")

    def active_workers():
        """Return one accepting worker unless this test injects a worker-probe timeout."""
        if timeout_point == "worker-probe":
            raise subprocess.TimeoutExpired(["nginx-worker-probe"], 10)
        return 431, {(432, 19)}

    monkeypatch.setattr(helper, "_run", run)
    monkeypatch.setattr(helper, "_nginx_active_workers", active_workers)
    monkeypatch.setattr(
        helper,
        "_management_handoff_readiness",
        lambda *_args: events.append("old-path-readiness") or {"stable_samples": 3},
    )

    assert helper._recover_management_handoff() == 1

    output = capsys.readouterr()
    payload = json.loads(output.err.splitlines()[-1])
    assert payload["management_handoff"] == "rollback incomplete"
    assert payload["failing_layer"] == "interruption recovery"
    assert "nginx wildcard restore: TimeoutExpired" in payload["error"]
    assert "Traceback" not in output.err + output.out
    assert state_path.is_file()
    assert cleared == []
    assert events == ["atlaso-start", "old-path-readiness"]
    assert ["systemctl", "start", "atlaso.service"] in commands
    assert ["systemctl", "restart", "nginx.service"] not in commands
    assert ["systemctl", "reload-or-restart", "nginx.service"] not in commands
