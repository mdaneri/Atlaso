"""Focused tests for graceful nginx activation during management handoff."""

import importlib.machinery
import importlib.util
import subprocess
from pathlib import Path

import pytest

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
    """Use Linux start time with PID to distinguish a reloaded worker generation."""
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
    """A successful signal command is insufficient until new workers accept."""
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
    """Do not report activation or use restart when reload leaves old workers."""
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


@pytest.mark.parametrize("reuseport", [False, True])
def test_committed_reuseport_preserves_settings_scope_and_public_tls_ownership(monkeypatch, tmp_path, reuseport):
    """A later Apply must read both committed dedicated and Access TLS listeners."""
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
    """Do not scope the old listener until its reuseport bridge is active."""
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
    """Use a transient reusable wildcard, then persist and reload the exact prior site."""
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
    """A failed transient wildcard activation still restores the exact site bytes."""
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
    """Start exact restored configuration after reboot and wait for its workers."""
    helper = load_helper_module()
    commands = []
    events = []

    def run(command, **_kwargs):
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
    """Do not mutate nginx when systemd cannot prove an inactive service."""
    helper = load_helper_module()
    commands = []

    def run(command, **_kwargs):
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
