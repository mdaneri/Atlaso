import subprocess

from labfoundry.app.adapters.system import SystemAdapter


def test_esx_storage_inventory_executes_read_only_helper_during_dry_run(monkeypatch):
    import labfoundry.app.adapters.system as system_adapter

    commands: list[list[str]] = []

    def fake_run(command, **_kwargs):
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
    import labfoundry.app.adapters.system as system_adapter

    commands: list[list[str]] = []

    def fake_run(command, **_kwargs):
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


def test_appliance_power_action_rejects_unknown_action():
    result = SystemAdapter(dry_run=False).schedule_appliance_power("restart")

    assert result.returncode == 2
    assert "Unsupported appliance power action" in result.stderr


def test_real_dhcp_leases_use_unprivileged_helper_first(monkeypatch):
    import labfoundry.app.adapters.system as system_adapter

    commands: list[list[str]] = []

    def fake_run(command, check, capture_output, text):
        commands.append(command)
        return subprocess.CompletedProcess(
            command,
            0,
            "1893456000 02:15:5d:00:20:40 192.168.50.140 live-client.labfoundry.internal *\n",
            "",
        )

    monkeypatch.setattr(system_adapter.subprocess, "run", fake_run)

    result = SystemAdapter(dry_run=False).read_dhcp_leases()

    assert result.returncode == 0
    assert result.dry_run is False
    assert result.command == [SystemAdapter.HELPER_PATH, "dnsmasq", "leases", "--real"]
    assert commands == [[SystemAdapter.HELPER_PATH, "dnsmasq", "leases", "--real"]]
    assert "live-client.labfoundry.internal" in result.stdout


def test_real_ntpd_logs_use_privileged_fixed_helper_action(monkeypatch):
    import labfoundry.app.adapters.system as system_adapter

    commands: list[list[str]] = []

    def fake_run(command, **kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "ntpd ready\n", "")

    monkeypatch.setattr(system_adapter.subprocess, "run", fake_run)

    result = SystemAdapter(dry_run=False).read_ntpd_logs()

    assert result.returncode == 0
    assert result.command == ["sudo", "-n", SystemAdapter.HELPER_PATH, "ntpd", "logs", "--real"]
    assert commands == [result.command]
    assert result.stdout == "ntpd ready\n"


def test_real_ldap_logs_use_privileged_fixed_helper_action(monkeypatch):
    import labfoundry.app.adapters.system as system_adapter

    commands: list[list[str]] = []

    def fake_run(command, **kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "slapd ready\n", "")

    monkeypatch.setattr(system_adapter.subprocess, "run", fake_run)

    result = SystemAdapter(dry_run=False).read_ldap_logs()

    assert result.returncode == 0
    assert result.command == ["sudo", "-n", SystemAdapter.HELPER_PATH, "ldap", "logs", "--real"]
    assert commands == [result.command]
    assert result.stdout == "slapd ready\n"


def test_managed_ldap_authentication_password_uses_stdin_not_argv(monkeypatch):
    import labfoundry.app.adapters.system as system_adapter

    captured: dict[str, object] = {}

    def fake_run(command, **kwargs):
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
    import labfoundry.app.adapters.system as system_adapter

    commands: list[list[str]] = []

    def fake_run(command, **kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "dnsmasq ready\n", "")

    monkeypatch.setattr(system_adapter.subprocess, "run", fake_run)

    result = SystemAdapter(dry_run=False).read_dnsmasq_logs()

    assert result.returncode == 0
    assert result.command == ["sudo", "-n", SystemAdapter.HELPER_PATH, "dnsmasq", "logs", "--real"]
    assert commands == [result.command]
    assert result.stdout == "dnsmasq ready\n"


def test_real_nginx_logs_use_privileged_fixed_helper_action(monkeypatch):
    import labfoundry.app.adapters.system as system_adapter

    commands: list[list[str]] = []

    def fake_run(command, **kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "nginx ready\n", "")

    monkeypatch.setattr(system_adapter.subprocess, "run", fake_run)

    result = SystemAdapter(dry_run=False).read_nginx_logs()

    assert result.returncode == 0
    assert result.command == ["sudo", "-n", SystemAdapter.HELPER_PATH, "nginx", "logs", "--real"]
    assert commands == [result.command]
    assert result.stdout == "nginx ready\n"


def test_real_nginx_http_logs_use_privileged_fixed_helper_actions(monkeypatch):
    import labfoundry.app.adapters.system as system_adapter

    commands: list[list[str]] = []

    def fake_run(command, **kwargs):
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
    import labfoundry.app.adapters.system as system_adapter

    commands: list[list[str]] = []

    def fake_run(command, **kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, '{"nts": false}\n', "")

    monkeypatch.setattr(system_adapter.subprocess, "run", fake_run)

    result = SystemAdapter(dry_run=False).read_ntpd_capabilities()

    assert result.command == [SystemAdapter.HELPER_PATH, "ntpd", "capabilities", "--real"]
    assert commands == [result.command]


def test_real_dhcp_leases_fall_back_to_sudo_helper(monkeypatch):
    import labfoundry.app.adapters.system as system_adapter

    commands: list[list[str]] = []

    def fake_run(command, check, capture_output, text):
        commands.append(command)
        if command[0] == SystemAdapter.HELPER_PATH:
            return subprocess.CompletedProcess(command, 1, "", "permission denied\n")
        return subprocess.CompletedProcess(
            command,
            0,
            "1893456000 02:15:5d:00:20:41 192.168.50.141 fallback-client.labfoundry.internal *\n",
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
    assert "fallback-client.labfoundry.internal" in result.stdout


def test_real_dhcp_leases_sudo_password_error_becomes_operator_guidance(monkeypatch):
    import labfoundry.app.adapters.system as system_adapter

    def fake_run(command, check, capture_output, text):
        if command[0] == SystemAdapter.HELPER_PATH:
            return subprocess.CompletedProcess(command, 1, "", "permission denied\n")
        return subprocess.CompletedProcess(command, 1, "", "sudo: a password is required\n")

    monkeypatch.setattr(system_adapter.subprocess, "run", fake_run)

    result = SystemAdapter(dry_run=False).read_dhcp_leases()

    assert result.returncode == 1
    assert result.command == ["sudo", "-n", SystemAdapter.HELPER_PATH, "dnsmasq", "leases", "--real"]
    assert "updated LabFoundry sudoers helper rule" in result.stderr
    assert "sudo: a password is required" not in result.stderr


def test_real_vcf_backup_apply_uses_sudo_helper(monkeypatch):
    import labfoundry.app.adapters.system as system_adapter

    commands: list[list[str]] = []

    def fake_run(command, check, capture_output, text):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, '{"vcf_backups": "apply complete"}\n', "")

    monkeypatch.setattr(system_adapter.subprocess, "run", fake_run)

    result = SystemAdapter(dry_run=False).apply_vcf_backup_config("/var/lib/labfoundry/apply/vcf-backups/labfoundry-vcf-backups-sshd.conf")

    assert result.returncode == 0
    assert result.dry_run is False
    assert result.command == [
        "sudo",
        "-n",
        SystemAdapter.HELPER_PATH,
        "vcf-backups",
        "apply",
        "--real",
        "/var/lib/labfoundry/apply/vcf-backups/labfoundry-vcf-backups-sshd.conf",
    ]
    assert commands == [result.command]


def test_real_ldap_apply_uses_constrained_helper(monkeypatch):
    import labfoundry.app.adapters.system as system_adapter

    commands: list[list[str]] = []

    def fake_run(command, **_kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, '{"ldap":"apply complete"}\n', "")

    monkeypatch.setattr(system_adapter.subprocess, "run", fake_run)
    path = "/var/lib/labfoundry/apply/ldap/labfoundry-ldap.json"

    result = SystemAdapter(dry_run=False).apply_ldap_config(path)

    assert result.returncode == 0
    assert result.command == ["sudo", "-n", SystemAdapter.HELPER_PATH, "ldap", "apply", "--real", path]
    assert commands == [result.command]


def test_real_local_user_authentication_passes_password_only_on_stdin(monkeypatch):
    import labfoundry.app.adapters.system as system_adapter

    calls: list[tuple[list[str], str | None]] = []

    def fake_run(command, **kwargs):
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
    result = SystemAdapter(dry_run=True).authenticate_local_user("vcf-depot", "Depot-user1!")

    assert result.returncode == 1
    assert result.dry_run is True
