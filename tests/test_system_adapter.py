"""Test system adapter behavior."""

import subprocess

from atlaso.app.adapters.system import SystemAdapter


def test_esx_storage_inventory_executes_read_only_helper_during_dry_run(monkeypatch):
    """Verify that esx storage inventory executes read only helper during dry run.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import atlaso.app.adapters.system as system_adapter

    commands: list[list[str]] = []

    def fake_run(command, **_kwargs):
        """Return fake run.

        Args:
            command: Command and arguments to execute.
            **_kwargs: Additional keyword arguments accepted by the callable.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, '[{"device_path":"/dev/sde"}]', "")

    monkeypatch.setattr(system_adapter.subprocess, "run", fake_run)

    result = SystemAdapter(dry_run=True).esx_storage_inventory()

    assert result.returncode == 0
    assert result.dry_run is False
    assert result.command == ["sudo", "-n", SystemAdapter.HELPER_PATH, "esx-storage", "inventory", "--real"]
    assert commands == [result.command]
    assert "/dev/sde" in result.stdout


def test_real_appliance_power_action_uses_sudo_helper(monkeypatch):
    """Verify that real appliance power action uses sudo helper.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import atlaso.app.adapters.system as system_adapter

    commands: list[list[str]] = []

    def fake_run(command, **_kwargs):
        """Return fake run.

        Args:
            command: Command and arguments to execute.
            **_kwargs: Additional keyword arguments accepted by the callable.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "scheduled\n", "")

    monkeypatch.setattr(system_adapter.subprocess, "run", fake_run)

    result = SystemAdapter(dry_run=False).schedule_appliance_power("reboot")

    assert result.returncode == 0
    assert result.command == [
        "sudo",
        "-n",
        SystemAdapter.HELPER_PATH,
        "appliance-power",
        "reboot",
        "--real",
    ]
    assert commands == [result.command]


def test_real_vcf_depot_software_id_readback_uses_fixed_helper_action(monkeypatch):
    """Verify that real vcf depot software id readback uses fixed helper action.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import atlaso.app.adapters.system as system_adapter

    commands: list[list[str]] = []

    def fake_run(command, **_kwargs):
        """Return fake run.

        Args:
            command: Command and arguments to execute.
            **_kwargs: Additional keyword arguments accepted by the callable.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, '{"software_depot_id":"safe-id"}', "")

    monkeypatch.setattr(system_adapter.subprocess, "run", fake_run)

    result = SystemAdapter(dry_run=False).read_vcf_offline_depot_software_depot_id()

    assert result.returncode == 0
    assert result.command == [
        "sudo",
        "-n",
        SystemAdapter.HELPER_PATH,
        "vcf-offline-depot",
        "read-software-depot-id",
        "--real",
    ]
    assert commands == [result.command]


def test_factory_reset_network_runtime_cleanup_uses_constrained_helper(monkeypatch):
    """The reset transaction reaches bounded runtime cleanup only through the helper.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import atlaso.app.adapters.system as system_adapter

    commands: list[list[str]] = []

    def fake_run(command, **_kwargs):
        """Record the exact helper command.

        Args:
            command: Exact command arguments.
            **_kwargs: Additional subprocess options accepted by the adapter.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, '{"factory_reset_network_runtime":"cleanup complete"}\n', "")

    monkeypatch.setattr(system_adapter.subprocess, "run", fake_run)

    result = SystemAdapter(dry_run=False).reset_factory_network_runtime()

    assert result.returncode == 0
    assert result.command == [
        "sudo",
        "-n",
        SystemAdapter.HELPER_PATH,
        "factory-reset",
        "reset-network-runtime",
        "--real",
    ]
    assert commands == [result.command]


def test_factory_reset_login_cleanup_uses_constrained_helper(monkeypatch):
    """The reset terminates OS sessions only through the constrained helper.

    Args:
        monkeypatch: Pytest fixture used to replace helper execution.
    """
    import atlaso.app.adapters.system as system_adapter

    commands: list[list[str]] = []
    monkeypatch.setattr(
        system_adapter.subprocess,
        "run",
        lambda command, **_kwargs: commands.append(command)
        or subprocess.CompletedProcess(command, 0, "", ""),
    )

    result = SystemAdapter(dry_run=False).terminate_factory_reset_login_sessions()

    assert result.command == [
        "sudo",
        "-n",
        SystemAdapter.HELPER_PATH,
        "factory-reset",
        "terminate-login-sessions",
        "--real",
    ]
    assert commands == [result.command]


def test_root_helper_call_avoids_sudo_environment_scrub(monkeypatch):
    """A root reset runner invokes the helper without a root-to-root sudo hop.

    Args:
        monkeypatch: Pytest fixture used to replace process identity and execution.
    """
    import atlaso.app.adapters.system as system_adapter

    commands: list[list[str]] = []

    def fake_run(command, **_kwargs):
        """Record the helper command and return success.

        Args:
            command: Exact command arguments passed to subprocess.
            **_kwargs: Subprocess options ignored by the test double.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(system_adapter.os, "name", "posix")
    monkeypatch.setattr(system_adapter.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setenv("ATLASO_HELPER_USE_SYSTEMD_RUN", "1")
    monkeypatch.setattr(system_adapter.subprocess, "run", fake_run)

    result = SystemAdapter(dry_run=False).reset_factory_network_runtime()

    expected = [
        SystemAdapter.HELPER_PATH,
        "factory-reset",
        "reset-network-runtime",
        "--real",
    ]
    assert result.command == expected
    assert commands == [expected]


def test_appliance_power_action_rejects_unknown_action():
    """Verify that appliance power action rejects unknown action."""
    result = SystemAdapter(dry_run=False).schedule_appliance_power("restart")

    assert result.returncode == 2
    assert "Unsupported appliance power action" in result.stderr


def test_real_dhcp_leases_use_unprivileged_helper_first(monkeypatch):
    """Verify that real dhcp leases use unprivileged helper first.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import atlaso.app.adapters.system as system_adapter

    commands: list[list[str]] = []

    def fake_run(command, check, capture_output, text):
        """Return fake run.

        Args:
            command: Command and arguments to execute.
            check: Whether a nonzero command status raises an exception.
            capture_output: Whether to capture the child process output.
            text: Text content consumed by the operation.
        """
        commands.append(command)
        return subprocess.CompletedProcess(
            command,
            0,
            "1893456000 02:15:5d:00:20:40 192.168.50.140 live-client.atlaso.internal *\n",
            "",
        )

    monkeypatch.setattr(system_adapter.subprocess, "run", fake_run)

    result = SystemAdapter(dry_run=False).read_dhcp_leases()

    assert result.returncode == 0
    assert result.dry_run is False
    assert result.command == [SystemAdapter.HELPER_PATH, "dnsmasq", "leases", "--real"]
    assert commands == [[SystemAdapter.HELPER_PATH, "dnsmasq", "leases", "--real"]]
    assert "live-client.atlaso.internal" in result.stdout


def test_real_ntpd_logs_use_privileged_fixed_helper_action(monkeypatch):
    """Verify that real ntpd logs use privileged fixed helper action.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import atlaso.app.adapters.system as system_adapter

    commands: list[list[str]] = []

    def fake_run(command, **kwargs):
        """Return fake run.

        Args:
            command: Command and arguments to execute.
            **kwargs: Additional keyword arguments accepted by the callable.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "ntpd ready\n", "")

    monkeypatch.setattr(system_adapter.subprocess, "run", fake_run)

    result = SystemAdapter(dry_run=False).read_ntpd_logs()

    assert result.returncode == 0
    assert result.command == ["sudo", "-n", SystemAdapter.HELPER_PATH, "ntpd", "logs", "--real"]
    assert commands == [result.command]
    assert result.stdout == "ntpd ready\n"


def test_real_ldap_logs_use_privileged_fixed_helper_action(monkeypatch):
    """Verify that real ldap logs use privileged fixed helper action.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import atlaso.app.adapters.system as system_adapter

    commands: list[list[str]] = []

    def fake_run(command, **kwargs):
        """Return fake run.

        Args:
            command: Command and arguments to execute.
            **kwargs: Additional keyword arguments accepted by the callable.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "slapd ready\n", "")

    monkeypatch.setattr(system_adapter.subprocess, "run", fake_run)

    result = SystemAdapter(dry_run=False).read_ldap_logs()

    assert result.returncode == 0
    assert result.command == ["sudo", "-n", SystemAdapter.HELPER_PATH, "ldap", "logs", "--real"]
    assert commands == [result.command]
    assert result.stdout == "slapd ready\n"


def test_managed_ldap_authentication_password_uses_stdin_not_argv(monkeypatch):
    """Verify that managed ldap authentication password uses stdin not argv.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import atlaso.app.adapters.system as system_adapter

    captured: dict[str, object] = {}

    def fake_run(command, **kwargs):
        """Return fake run.

        Args:
            command: Command and arguments to execute.
            **kwargs: Additional keyword arguments accepted by the callable.
        """
        captured["command"] = command
        captured["input"] = kwargs.get("input")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(system_adapter.subprocess, "run", fake_run)
    result = SystemAdapter(dry_run=False).authenticate_ldap_user(
        "uid=alice,ou=users,dc=example,dc=test",
        "Correct-Horse-Battery-Staple!",
    )
    assert result.returncode == 0
    assert captured["input"] == "Correct-Horse-Battery-Staple!\n"
    assert "Correct-Horse-Battery-Staple!" not in " ".join(captured["command"])
    assert result.command == captured["command"]


def test_real_dnsmasq_logs_use_privileged_fixed_helper_action(monkeypatch):
    """Verify that real dnsmasq logs use privileged fixed helper action.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import atlaso.app.adapters.system as system_adapter

    commands: list[list[str]] = []

    def fake_run(command, **kwargs):
        """Return fake run.

        Args:
            command: Command and arguments to execute.
            **kwargs: Additional keyword arguments accepted by the callable.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "dnsmasq ready\n", "")

    monkeypatch.setattr(system_adapter.subprocess, "run", fake_run)

    result = SystemAdapter(dry_run=False).read_dnsmasq_logs()

    assert result.returncode == 0
    assert result.command == ["sudo", "-n", SystemAdapter.HELPER_PATH, "dnsmasq", "logs", "--real"]
    assert commands == [result.command]
    assert result.stdout == "dnsmasq ready\n"


def test_real_nginx_logs_use_privileged_fixed_helper_action(monkeypatch):
    """Verify that real nginx logs use privileged fixed helper action.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import atlaso.app.adapters.system as system_adapter

    commands: list[list[str]] = []

    def fake_run(command, **kwargs):
        """Return fake run.

        Args:
            command: Command and arguments to execute.
            **kwargs: Additional keyword arguments accepted by the callable.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "nginx ready\n", "")

    monkeypatch.setattr(system_adapter.subprocess, "run", fake_run)

    result = SystemAdapter(dry_run=False).read_nginx_logs()

    assert result.returncode == 0
    assert result.command == ["sudo", "-n", SystemAdapter.HELPER_PATH, "nginx", "logs", "--real"]
    assert commands == [result.command]
    assert result.stdout == "nginx ready\n"


def test_real_nginx_http_logs_use_privileged_fixed_helper_actions(monkeypatch):
    """Verify that real nginx http logs use privileged fixed helper actions.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import atlaso.app.adapters.system as system_adapter

    commands: list[list[str]] = []

    def fake_run(command, **kwargs):
        """Return fake run.

        Args:
            command: Command and arguments to execute.
            **kwargs: Additional keyword arguments accepted by the callable.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "http request\n", "")

    monkeypatch.setattr(system_adapter.subprocess, "run", fake_run)
    adapter = SystemAdapter(dry_run=False)

    access = adapter.read_nginx_access_logs()
    errors = adapter.read_nginx_error_logs()

    assert access.command == ["sudo", "-n", SystemAdapter.HELPER_PATH, "nginx", "access-logs", "--real"]
    assert errors.command == ["sudo", "-n", SystemAdapter.HELPER_PATH, "nginx", "error-logs", "--real"]
    assert commands == [access.command, errors.command]


def test_real_ntpd_capabilities_use_unprivileged_fixed_helper_action(monkeypatch):
    """Verify that real ntpd capabilities use unprivileged fixed helper action.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import atlaso.app.adapters.system as system_adapter

    commands: list[list[str]] = []

    def fake_run(command, **kwargs):
        """Return fake run.

        Args:
            command: Command and arguments to execute.
            **kwargs: Additional keyword arguments accepted by the callable.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, '{"nts": false}\n', "")

    monkeypatch.setattr(system_adapter.subprocess, "run", fake_run)

    result = SystemAdapter(dry_run=False).read_ntpd_capabilities()

    assert result.command == [SystemAdapter.HELPER_PATH, "ntpd", "capabilities", "--real"]
    assert commands == [result.command]


def test_real_dhcp_leases_fall_back_to_sudo_helper(monkeypatch):
    """Verify that real dhcp leases fall back to sudo helper.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import atlaso.app.adapters.system as system_adapter

    commands: list[list[str]] = []

    def fake_run(command, check, capture_output, text):
        """Return fake run.

        Args:
            command: Command and arguments to execute.
            check: Whether a nonzero command status raises an exception.
            capture_output: Whether to capture the child process output.
            text: Text content consumed by the operation.
        """
        commands.append(command)
        if command[0] == SystemAdapter.HELPER_PATH:
            return subprocess.CompletedProcess(command, 1, "", "permission denied\n")
        return subprocess.CompletedProcess(
            command,
            0,
            "1893456000 02:15:5d:00:20:41 192.168.50.141 fallback-client.atlaso.internal *\n",
            "",
        )

    monkeypatch.setattr(system_adapter.subprocess, "run", fake_run)

    result = SystemAdapter(dry_run=False).read_dhcp_leases()

    assert result.returncode == 0
    assert result.command == ["sudo", "-n", SystemAdapter.HELPER_PATH, "dnsmasq", "leases", "--real"]
    assert commands == [
        [SystemAdapter.HELPER_PATH, "dnsmasq", "leases", "--real"],
        ["sudo", "-n", SystemAdapter.HELPER_PATH, "dnsmasq", "leases", "--real"],
    ]
    assert "fallback-client.atlaso.internal" in result.stdout


def test_real_dhcp_leases_sudo_password_error_becomes_operator_guidance(monkeypatch):
    """Verify that real dhcp leases sudo password error becomes operator guidance.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import atlaso.app.adapters.system as system_adapter

    def fake_run(command, check, capture_output, text):
        """Return fake run.

        Args:
            command: Command and arguments to execute.
            check: Whether a nonzero command status raises an exception.
            capture_output: Whether to capture the child process output.
            text: Text content consumed by the operation.
        """
        if command[0] == SystemAdapter.HELPER_PATH:
            return subprocess.CompletedProcess(command, 1, "", "permission denied\n")
        return subprocess.CompletedProcess(command, 1, "", "sudo: a password is required\n")

    monkeypatch.setattr(system_adapter.subprocess, "run", fake_run)

    result = SystemAdapter(dry_run=False).read_dhcp_leases()

    assert result.returncode == 1
    assert result.command == ["sudo", "-n", SystemAdapter.HELPER_PATH, "dnsmasq", "leases", "--real"]
    assert "updated Atlaso sudoers helper rule" in result.stderr
    assert "sudo: a password is required" not in result.stderr


def test_networkd_dhcp_dns_executes_read_only_helper_during_dry_run(monkeypatch):
    """Verify that networkd dhcp dns executes read only helper during dry run.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import atlaso.app.adapters.system as system_adapter

    commands: list[list[str]] = []

    def fake_run(command, **_kwargs):
        """Return fake run.

        Args:
            command: Command and arguments to execute.
            **_kwargs: Additional keyword arguments accepted by the callable.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, '{"interface":"eth0","ifindex":2,"servers":["192.168.167.2"]}\n', "")

    monkeypatch.setattr(system_adapter.subprocess, "run", fake_run)

    result = SystemAdapter(dry_run=True).read_networkd_dhcp_dns("eth0")

    assert result.returncode == 0
    assert result.command == [SystemAdapter.HELPER_PATH, "network", "dhcp-dns", "--real", "eth0"]
    assert commands == [result.command]


def test_real_vcf_backup_apply_uses_sudo_helper(monkeypatch):
    """Verify that real vcf backup apply uses sudo helper.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import atlaso.app.adapters.system as system_adapter

    commands: list[list[str]] = []

    def fake_run(command, check, capture_output, text):
        """Return fake run.

        Args:
            command: Command and arguments to execute.
            check: Whether a nonzero command status raises an exception.
            capture_output: Whether to capture the child process output.
            text: Text content consumed by the operation.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, '{"vcf_backups": "apply complete"}\n', "")

    monkeypatch.setattr(system_adapter.subprocess, "run", fake_run)

    result = SystemAdapter(dry_run=False).apply_vcf_backup_config("/var/lib/atlaso/apply/vcf-backups/atlaso-vcf-backups-sshd.conf")

    assert result.returncode == 0
    assert result.dry_run is False
    assert result.command == [
        "sudo",
        "-n",
        SystemAdapter.HELPER_PATH,
        "vcf-backups",
        "apply",
        "--real",
        "/var/lib/atlaso/apply/vcf-backups/atlaso-vcf-backups-sshd.conf",
    ]
    assert commands == [result.command]


def test_real_ldap_apply_uses_constrained_helper(monkeypatch):
    """Verify that real ldap apply uses constrained helper.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import atlaso.app.adapters.system as system_adapter

    commands: list[list[str]] = []

    def fake_run(command, **_kwargs):
        """Return fake run.

        Args:
            command: Command and arguments to execute.
            **_kwargs: Additional keyword arguments accepted by the callable.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, '{"ldap":"apply complete"}\n', "")

    monkeypatch.setattr(system_adapter.subprocess, "run", fake_run)
    path = "/var/lib/atlaso/apply/ldap/atlaso-ldap.json"

    result = SystemAdapter(dry_run=False).apply_ldap_config(path)

    assert result.returncode == 0
    assert result.command == ["sudo", "-n", SystemAdapter.HELPER_PATH, "ldap", "apply", "--real", path]
    assert commands == [result.command]


def test_real_local_user_authentication_passes_password_only_on_stdin(monkeypatch):
    """Verify that real local user authentication passes password only on stdin.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import atlaso.app.adapters.system as system_adapter

    calls: list[tuple[list[str], str | None]] = []

    def fake_run(command, **kwargs):
        """Return fake run.

        Args:
            command: Command and arguments to execute.
            **kwargs: Additional keyword arguments accepted by the callable.
        """
        calls.append((command, kwargs.get("input")))
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(system_adapter.subprocess, "run", fake_run)

    password = "Depot-user1!"
    result = SystemAdapter(dry_run=False).authenticate_local_user("vcf-depot", password)

    assert result.returncode == 0
    assert result.command == ["sudo", "-n", SystemAdapter.HELPER_PATH, "local-users", "authenticate", "--real", "vcf-depot"]
    assert calls == [(result.command, f"{password}\n")]
    assert password not in " ".join(result.command)
    assert password not in result.stdout
    assert password not in result.stderr


def test_dry_run_local_user_authentication_fails_closed():
    """Verify that dry run local user authentication fails closed."""
    result = SystemAdapter(dry_run=True).authenticate_local_user("vcf-depot", "Depot-user1!")

    assert result.returncode == 1
    assert result.dry_run is True
