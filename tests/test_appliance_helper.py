"""Test appliance helper behavior."""

import base64
import importlib.machinery
import importlib.util
import io
import json
import os
import subprocess
import tarfile
import hashlib
import re
import stat
from ipaddress import ip_network
from pathlib import Path
from types import SimpleNamespace

import pytest


HELPER_PATH = Path(__file__).resolve().parents[1] / "scripts" / "appliance" / "atlaso-helper"


def load_helper_module():
    """Return helper module."""
    loader = importlib.machinery.SourceFileLoader("atlaso_helper", str(HELPER_PATH))
    spec = importlib.util.spec_from_loader("atlaso_helper", loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def test_appliance_power_helper_schedules_reboot(monkeypatch):
    """Verify that appliance power helper schedules reboot.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    helper = load_helper_module()
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "scheduled\n", "")

    monkeypatch.setattr(helper, "_command_path", lambda command: "/usr/bin/systemctl" if command == "systemctl" else None)
    monkeypatch.setattr(helper.shutil, "which", lambda command: "/usr/bin/systemd-run" if command == "systemd-run" else None)
    monkeypatch.setattr(helper, "_run", fake_run)

    assert helper._handle_appliance_power("reboot", []) == 0
    assert len(commands) == 1
    command = commands[0]
    assert command[:3] == ["/usr/bin/systemd-run", "--quiet", "--on-active=5"]
    assert command[3].startswith("--unit=atlaso-reboot-")
    assert command[-2:] == ["/usr/bin/systemctl", "reboot"]


def test_appliance_power_helper_maps_shutdown_to_poweroff(monkeypatch):
    """Verify that appliance power helper maps shutdown to poweroff.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    helper = load_helper_module()
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "_command_path", lambda command: "/usr/bin/systemctl" if command == "systemctl" else None)
    monkeypatch.setattr(helper.shutil, "which", lambda command: "/usr/bin/systemd-run" if command == "systemd-run" else None)
    monkeypatch.setattr(helper, "_run", fake_run)

    assert helper._handle_appliance_power("shutdown", []) == 0
    assert commands[0][-2:] == ["/usr/bin/systemctl", "poweroff"]


def test_appliance_power_helper_fails_closed_without_systemd_run(monkeypatch, capsys):
    """Verify that appliance power helper fails closed without systemd run.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    helper = load_helper_module()
    commands: list[list[str]] = []
    monkeypatch.setattr(helper, "_command_path", lambda command: "/usr/bin/systemctl" if command == "systemctl" else None)
    monkeypatch.setattr(helper.shutil, "which", lambda _command: None)
    monkeypatch.setattr(helper, "_run", lambda command: commands.append(command))

    assert helper._handle_appliance_power("shutdown", []) == 127
    assert commands == []
    assert "refusing an immediate appliance power action" in capsys.readouterr().err


def ldap_payload(*, enabled: bool = False) -> dict:
    """Return ldap payload.

    Args:
        enabled: Whether the associated resource or behavior is enabled.
    """
    suffix = "dc=org-a,dc=ldap,dc=atlaso,dc=internal"
    user_dn = f"uid=operator,ou=users,{suffix}"
    return {
        "schema_version": 1,
        "service": {
            "enabled": enabled,
            "hostname": "ldap.atlaso.internal",
            "listen_interface": "eth0",
            "listen_address": "192.168.49.1",
            "ldaps_enabled": True,
            "port": 636,
            "ldap_enabled": False,
            "ldap_port": 389,
            "certificate_path": "/etc/atlaso/ldap/tls/server.crt",
            "key_path": "/etc/atlaso/ldap/tls/server.key",
            "chain_path": "/etc/atlaso/ldap/tls/server-chain.crt",
            "root_ca_path": "/etc/atlaso/ca/root.crt",
            "password_policy": {
                "min_length": 14,
                "history": 5,
                "max_failures": 5,
                "failure_window_minutes": 15,
                "lockout_minutes": 15,
                "max_age_days": 0,
            },
        },
        "organizations": [
            {
                "id": 1,
                "name": "Org A",
                "slug": "org-a",
                "suffix_dn": suffix,
                "bind_dn": f"uid=vcf-bind,ou=service-accounts,{suffix}",
                "bind_password": "SecretBind1!",
                "enabled": True,
                "vcf_settings": {
                    "definedSettings": {"userAttributes": {"serviceAccount": "employeeType"}},
                    "vcf91IdentityBrokerCompatibility": {
                        "requiredInternalAttribute": "serviceAccount",
                        "ldapAttribute": "employeeType",
                    },
                },
                "users": [
                    {
                        "id": 1,
                        "uid": "operator",
                        "dn": user_dn,
                        "surname": "Operator",
                        "display_name": "Operator",
                        "email": "",
                        "telephone": "",
                        "enabled": True,
                        "password": "VeryStrong1!Directory",
                        "password_status": "pending_apply",
                    }
                ],
                "groups": [
                    {
                        "id": 1,
                        "name": "VCF Administrators",
                        "dn": f"cn=VCF Administrators,ou=groups,{suffix}",
                        "description": "",
                        "enabled": True,
                        "members": [{"type": "user", "id": 1, "dn": user_dn}],
                    }
                ],
            }
        ],
    }


def test_ldap_helper_renders_separate_mdb_acl_overlays_and_configurable_listeners():
    """Verify that ldap helper renders separate mdb acl overlays and configurable listeners."""
    helper = load_helper_module()
    payload = ldap_payload()

    assert helper._ldap_config_errors(payload) == []
    config = helper._render_ldap_slapd_config(payload)
    assert "database mdb" in config
    assert 'suffix "dc=org-a,dc=ldap,dc=atlaso,dc=internal"' in config
    assert "overlay ppolicy" in config
    assert "overlay memberof" in config
    assert "overlay refint" in config
    assert "modulepath /usr/lib/openldap" in config
    assert "moduleload ppolicy.so" in config
    assert "ppolicy.schema" not in config
    assert 'by dn.exact="uid=vcf-bind,ou=service-accounts,dc=org-a,dc=ldap,dc=atlaso,dc=internal" read' in config
    assert helper._ldap_listener_urls(payload["service"]) == "ldapi:/// ldaps://192.168.49.1:636/"
    assert "ldap:///" not in helper._ldap_listener_urls(payload["service"])

    payload["service"].update({"port": 1636, "ldap_enabled": True, "ldap_port": 1389})
    assert helper._ldap_config_errors(payload) == []
    assert helper._ldap_listener_urls(payload["service"]) == (
        "ldapi:/// ldaps://192.168.49.1:1636/ ldap://192.168.49.1:1389/"
    )

    payload["service"]["ldap_port"] = 1636
    assert "different TCP ports" in " ".join(helper._ldap_config_errors(payload))

    payload["service"].update({"ldaps_enabled": False, "port": 636, "ldap_enabled": True, "ldap_port": 1389})
    plaintext_config = helper._render_ldap_slapd_config(payload)
    assert "TLSCertificateFile" not in plaintext_config
    assert helper._ldap_listener_urls(payload["service"]) == "ldapi:/// ldap://192.168.49.1:1389/"


@pytest.mark.parametrize("action", ["validate", "apply"])
def test_ldap_helper_removes_invalid_apply_payload(monkeypatch, tmp_path, capsys, action):
    """Verify that ldap helper removes invalid apply payload.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        capsys: Pytest fixture used to capture standard output and standard error.
        action: Action supplied to the test scenario.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "ldap"
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "atlaso-ldap.json"
    config_path.write_text("{}", encoding="utf-8")

    monkeypatch.setattr(helper, "LDAP_APPLY_DIR", apply_dir)

    assert helper._handle_ldap(action, [str(config_path)]) == 2
    assert capsys.readouterr().err
    assert not config_path.exists()


def test_plaintext_only_ldap_validation_does_not_require_tls_files(monkeypatch):
    """Verify that plaintext only ldap validation does not require tls files.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    helper = load_helper_module()
    payload = ldap_payload(enabled=True)
    payload["service"].update({"ldaps_enabled": False, "ldap_enabled": True, "ldap_port": 1389})
    monkeypatch.setattr(helper.shutil, "which", lambda command: f"/usr/bin/{command}")

    errors = helper._ldap_config_errors(payload)

    assert not any("LDAP certificate" in error or "LDAP private key" in error or "LDAP root CA" in error for error in errors)
    assert errors == []


def test_ldap_render_can_use_isolated_validation_data_root(tmp_path):
    """Verify that ldap render can use isolated validation data root.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    payload = ldap_payload()
    config = helper._render_ldap_slapd_config(payload, state_root=tmp_path / "validation-data")

    assert f"directory {tmp_path / 'validation-data' / 'org-a'}" in config
    assert str(helper.LDAP_STATE_DIR / "org-a") not in config


def test_ldap_render_can_use_isolated_validation_runtime_root(tmp_path):
    """Verify that ldap render can use isolated validation runtime root.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    payload = ldap_payload()
    runtime_root = tmp_path / "validation-run"

    config = helper._render_ldap_slapd_config(payload, runtime_root=runtime_root)

    assert f"pidfile {runtime_root / 'slapd.pid'}" in config
    assert f"argsfile {runtime_root / 'slapd.args'}" in config
    assert "/run/openldap/slapd.pid" not in config


def test_ldap_runtime_directory_is_created_for_first_apply(monkeypatch, tmp_path):
    """Verify that ldap runtime directory is created for first apply.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    runtime_dir = tmp_path / "run" / "openldap"
    ownership: list[tuple[Path, str, str]] = []
    modes: list[tuple[Path, int]] = []
    monkeypatch.setattr(helper, "_ldap_account_name", lambda: "ldap")
    monkeypatch.setattr(
        helper.shutil,
        "chown",
        lambda path, *, user, group: ownership.append((Path(path), user, group)),
    )
    monkeypatch.setattr(helper.os, "chmod", lambda path, mode: modes.append((Path(path), mode)))

    helper._prepare_ldap_runtime_dir(runtime_dir=runtime_dir)

    assert runtime_dir.is_dir()
    assert ownership == [(runtime_dir, "ldap", "ldap")]
    assert modes == [(runtime_dir, 0o750)]


def test_ldap_reconcile_clears_lock_for_every_enabled_user(monkeypatch):
    """Verify that ldap reconcile clears lock for every enabled user.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    helper = load_helper_module()
    payload = ldap_payload(enabled=True)
    organization = payload["organizations"][0]
    user = organization["users"][0]
    user.update({"password": "", "unlock_requested": False, "enabled": True})
    deleted_attributes: list[tuple[str, str]] = []
    monkeypatch.setattr(helper, "_ldap_upsert_entry", lambda *_args, **_kwargs: 0)
    monkeypatch.setattr(helper, "_ldap_delete_attribute", lambda dn, attribute: deleted_attributes.append((dn, attribute)) or 0)
    monkeypatch.setattr(helper, "_ldap_list_dns", lambda _base_dn: [])
    monkeypatch.setattr(helper, "_ldap_delete_entries", lambda _dns: 0)

    assert helper._ldap_reconcile_organization(organization, payload["service"]["password_policy"]) == 0
    assert (user["dn"], "pwdAccountLockedTime") in deleted_attributes


def test_ldap_recovery_restores_slapd_ownership(monkeypatch, tmp_path):
    """Verify that ldap recovery restores slapd ownership.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    payload = ldap_payload(enabled=True)
    suffix = payload["organizations"][0]["suffix_dn"]
    ldif_path = tmp_path / "org-a.ldif"
    ldif_path.write_text(f"dn: {suffix}\nobjectClass: domain\ndc: org-a\n", encoding="utf-8")
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "format": "atlaso-ldap-slapcat-v1",
                "databases": [
                    {
                        "suffix": suffix,
                        "filename": ldif_path.name,
                        "sha256": hashlib.sha256(ldif_path.read_bytes()).hexdigest(),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    archive_buffer = io.BytesIO()
    with tarfile.open(fileobj=archive_buffer, mode="w:gz") as archive:
        archive.add(manifest_path, arcname="manifest.json")
        archive.add(ldif_path, arcname=ldif_path.name)
    archive_bytes = archive_buffer.getvalue()
    payload["recovery_import"] = {
        "payload_b64": base64.b64encode(archive_bytes).decode("ascii"),
        "sha256": hashlib.sha256(archive_bytes).hexdigest(),
    }
    state_dir = tmp_path / "ldap-state"
    data_dir = state_dir / "org-a"
    data_dir.mkdir(parents=True)
    ownership: list[tuple[Path, str, str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        if Path(command[0]).name == "slapadd":
            (data_dir / "data.mdb").write_text("restored", encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "LDAP_STATE_DIR", state_dir)
    monkeypatch.setattr(helper, "_ldap_account_name", lambda: "ldap")
    monkeypatch.setattr(helper, "_run", fake_run)
    monkeypatch.setattr(helper.shutil, "which", lambda command: command)
    monkeypatch.setattr(helper.shutil, "chown", lambda path, *, user, group: ownership.append((Path(path), user, group)))

    assert helper._restore_ldap_recovery(payload, tmp_path / "slapd.d") == 0
    assert (data_dir, "ldap", "ldap") in ownership
    assert (data_dir / "data.mdb", "ldap", "ldap") in ownership


def test_ldap_apply_removes_only_obsolete_managed_data_directories(monkeypatch, tmp_path):
    """Verify that ldap apply removes only obsolete managed data directories.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    state_dir = tmp_path / "ldap-state"
    desired_dir = state_dir / "org-a"
    obsolete_dir = state_dir / "deleted-org"
    desired_dir.mkdir(parents=True)
    obsolete_dir.mkdir()
    (desired_dir / "data.mdb").write_text("keep", encoding="utf-8")
    (obsolete_dir / "data.mdb").write_text("remove", encoding="utf-8")
    unrelated_file = state_dir / "README"
    unrelated_file.write_text("keep", encoding="utf-8")
    monkeypatch.setattr(helper, "LDAP_STATE_DIR", state_dir)

    helper._remove_obsolete_ldap_data_directories(ldap_payload(enabled=True))

    assert desired_dir.is_dir()
    assert (desired_dir / "data.mdb").read_text(encoding="utf-8") == "keep"
    assert not obsolete_dir.exists()
    assert unrelated_file.read_text(encoding="utf-8") == "keep"


def test_ldap_listener_dropin_overrides_photon_hard_coded_plaintext_listener(monkeypatch, tmp_path):
    """Verify that ldap listener dropin overrides photon hard coded plaintext listener.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    dropin_dir = tmp_path / "slapd.service.d"
    dropin_path = dropin_dir / "atlaso.conf"
    sysconfig_path = tmp_path / "slapd"
    monkeypatch.setattr(helper, "LDAP_SYSTEMD_DROPIN_DIR", dropin_dir)
    monkeypatch.setattr(helper, "LDAP_SYSTEMD_DROPIN_PATH", dropin_path)
    monkeypatch.setattr(helper, "LDAP_SYSCONFIG_PATH", sysconfig_path)
    monkeypatch.setattr(helper, "LDAP_CONFIG_DIR", "/etc/openldap/slapd.d")
    monkeypatch.setattr(helper, "_ldap_account_name", lambda: "ldap")

    helper._install_ldap_listener_config(ldap_payload(enabled=True)["service"])

    rendered = dropin_path.read_text(encoding="utf-8")
    assert "ExecStart=" in rendered
    assert "ExecStartPre=/usr/bin/install -d -m 0750 -o ldap -g ldap /run/openldap" in rendered
    assert 'ExecStart=/usr/sbin/slapd -u ldap -F /etc/openldap/slapd.d -h "ldapi:/// ldaps://192.168.49.1:636/"' in rendered
    assert "ldap:///" not in rendered


def test_ldap_listener_dropin_supports_custom_ldaps_and_opt_in_plaintext_ports(monkeypatch, tmp_path):
    """Verify that ldap listener dropin supports custom ldaps and opt in plaintext ports.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    dropin_dir = tmp_path / "slapd.service.d"
    dropin_path = dropin_dir / "atlaso.conf"
    sysconfig_path = tmp_path / "slapd"
    monkeypatch.setattr(helper, "LDAP_SYSTEMD_DROPIN_DIR", dropin_dir)
    monkeypatch.setattr(helper, "LDAP_SYSTEMD_DROPIN_PATH", dropin_path)
    monkeypatch.setattr(helper, "LDAP_SYSCONFIG_PATH", sysconfig_path)
    monkeypatch.setattr(helper, "LDAP_CONFIG_DIR", "/etc/openldap/slapd.d")
    monkeypatch.setattr(helper, "_ldap_account_name", lambda: "ldap")
    service = ldap_payload(enabled=True)["service"]
    service.update({"port": 1636, "ldap_enabled": True, "ldap_port": 1389})

    helper._install_ldap_listener_config(service)

    rendered = dropin_path.read_text(encoding="utf-8")
    assert "ldaps://192.168.49.1:1636/" in rendered
    assert "ldap://192.168.49.1:1389/" in rendered


def test_ldap_private_key_is_group_readable_only_for_slapd(monkeypatch, tmp_path):
    """Verify that ldap private key is group readable only for slapd.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    key_path = tmp_path / "server.key"
    key_path.write_text("private", encoding="utf-8")
    ownership: list[tuple[Path, str, str]] = []
    modes: list[tuple[Path, int]] = []
    monkeypatch.setattr(helper.shutil, "chown", lambda path, *, user, group: ownership.append((Path(path), user, group)))
    monkeypatch.setattr(helper.os, "chmod", lambda path, mode: modes.append((Path(path), mode)))
    monkeypatch.setattr(helper, "_ldap_account_name", lambda: "ldap")

    helper._grant_ldap_private_key_read(key_path)

    assert ownership == [(key_path, "root", "ldap")]
    assert modes == [(key_path, 0o640)]


def test_kms_private_key_reconciles_upgrade_identity_before_granting_access(monkeypatch, tmp_path):
    """Verify that kms private key reconciles upgrade identity before granting access.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    key_path = tmp_path / "server.key"
    key_path.write_text("private", encoding="utf-8")
    identity_created = {"group": False, "account": False}
    commands: list[list[str]] = []
    ownership: list[tuple[Path, int, int]] = []

    def fake_group(_name):
        """Return fake group.

        Args:
            _name: Stable name identifying the resource or operation.


        Raises:
            KeyError: If a required mapping entry is absent.
        """
        if not identity_created["group"]:
            raise KeyError
        return SimpleNamespace(gr_gid=1002)

    def fake_account(_name):
        """Return fake account.

        Args:
            _name: Stable name identifying the resource or operation.


        Raises:
            KeyError: If a required mapping entry is absent.
        """
        if not identity_created["account"]:
            raise KeyError
        return SimpleNamespace(pw_uid=1001)

    def fake_run(command):
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        commands.append(command)
        if str(command[0]).endswith("groupadd"):
            identity_created["group"] = True
        if str(command[0]).endswith("useradd"):
            identity_created["account"] = True
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper.grp, "getgrnam", fake_group)
    monkeypatch.setattr(helper.pwd, "getpwnam", fake_account)
    monkeypatch.setattr(helper, "_command_path", lambda name: Path("/usr/sbin") / name)
    monkeypatch.setattr(helper, "_run", fake_run)
    monkeypatch.setattr(
        helper.os,
        "chown",
        lambda path, uid, gid: ownership.append((Path(path), uid, gid)),
        raising=False,
    )

    helper._grant_kms_private_key_read(key_path)

    assert commands[0][:3] == [Path("/usr/sbin") / "groupadd", "--system", "atlaso-kmip"]
    assert commands[1][0] == Path("/usr/sbin") / "useradd"
    assert ownership == [(key_path, 0, 1002)]


def test_ldap_directory_queries_disable_ldif_wrapping(monkeypatch):
    """Verify that ldap directory queries disable ldif wrapping.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    helper = load_helper_module()
    commands: list[list[str]] = []

    def fake_run(command: list[str]):
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper.shutil, "which", lambda command: f"/usr/bin/{command}")
    monkeypatch.setattr(helper, "_run", fake_run)

    helper._ldap_entry_exists("uid=operator,ou=users,dc=org-a,dc=ldap,dc=atlaso,dc=internal")
    helper._ldap_list_dns("ou=groups,dc=org-a,dc=ldap,dc=atlaso,dc=internal")

    assert all(["-o", "ldif-wrap=no"] == command[2:4] for command in commands)


def test_ldap_helper_rejects_missing_service_account_mapping_and_group_cycle():
    """Verify that ldap helper rejects missing service account mapping and group cycle."""
    helper = load_helper_module()
    payload = ldap_payload()
    payload["organizations"][0]["vcf_settings"]["definedSettings"]["userAttributes"].pop("serviceAccount")
    payload["organizations"][0]["groups"] = [
        {
            "id": 1,
            "name": "First",
            "dn": "cn=First,ou=groups,dc=org-a,dc=ldap,dc=atlaso,dc=internal",
            "enabled": True,
            "members": [{"type": "group", "id": 2, "dn": "cn=Second,ou=groups,dc=org-a,dc=ldap,dc=atlaso,dc=internal"}],
        },
        {
            "id": 2,
            "name": "Second",
            "dn": "cn=Second,ou=groups,dc=org-a,dc=ldap,dc=atlaso,dc=internal",
            "enabled": True,
            "members": [{"type": "group", "id": 1, "dn": "cn=First,ou=groups,dc=org-a,dc=ldap,dc=atlaso,dc=internal"}],
        },
    ]

    errors = helper._ldap_config_errors(payload)
    assert any("serviceAccount" in error for error in errors)
    assert any("cycle" in error for error in errors)


def kms_config_text(managed_root: Path, *, enabled: bool = True, database_path: Path | None = None) -> str:
    """Return kms config text.

    Args:
        managed_root: Filesystem path associated with managed root.
        enabled: Whether the associated resource or behavior is enabled.
        database_path: Filesystem path used for database.
    """
    database_path = database_path or Path("/var/lib/atlaso/kmip/store.db")
    return json.dumps(
        {
            "schema_version": 1,
            "enabled": enabled,
            "listen": {"host": "192.168.50.1", "port": 5696},
            "tls": {
                "certificate_path": str(managed_root / "kmip" / "certs" / "kms.atlaso.internal.crt"),
                "private_key_path": str(managed_root / "kmip" / "certs" / "kms.atlaso.internal.key"),
                "ca_path": str(managed_root / "kmip" / "client-trust.pem"),
            },
            "store": {
                "database_path": str(database_path),
                "kek_path": str(database_path.parent / "kek.json"),
            },
            "limits": {
                "max_request_bytes": 1_048_576,
                "max_connections": 32,
                "idle_timeout_seconds": 30,
                "max_requests_per_connection": 128,
            },
            "providers": (
                [
                    {
                        "id": "885841f9-0878-45c2-aee0-b72bc9fc643f",
                        "name": "VCF",
                        "client_fingerprints": ["ab" * 32],
                        "client_certificate_paths": [
                            str(managed_root / "kmip" / "clients" / "vcf.crt")
                        ],
                    }
                ]
                if enabled
                else []
            ),
            "interop_trace_path": "",
        },
        indent=2,
        sort_keys=True,
    )


def network_config_text(
    *,
    eth2_mode: str = "trunk",
    eth2_admin_state: str = "up",
    include_vlan: bool = True,
    include_removed_vlan: bool = False,
    dual_stack: bool = False,
    management_gateway: str = "",
) -> str:
    """Return network config text.

    Args:
        eth2_mode: Eth2 mode supplied by the caller.
        eth2_admin_state: Eth2 admin state supplied by the caller.
        include_vlan: Include vlan supplied by the caller.
        include_removed_vlan: Include removed vlan supplied by the caller.
        dual_stack: Dual stack supplied by the caller.
        management_gateway: Management gateway supplied by the caller.
    """
    lines = [
        "[physical_interfaces]",
        "interface=eth0",
        "  role=management",
        "  mode=access",
        "  ipv4_method=static",
        "  ip_cidr=192.168.49.1/24",
        f"  gateway={management_gateway}",
        f"  ipv6_cidr={'2001:db8:49::1/64' if dual_stack else ''}",
        "  admin_state=up",
        "  mtu=1500",
        "interface=eth2",
        "  role=access",
        f"  mode={eth2_mode}",
        "  ipv4_method=static",
        "  ip_cidr=",
        f"  ipv6_cidr={'2001:db8:60::1/64' if dual_stack else ''}",
        f"  admin_state={eth2_admin_state}",
        "  mtu=1500",
        "",
        "[vlan_interfaces]",
    ]
    if include_vlan:
        lines.extend(
            [
                "vlan=eth2.20",
                "  parent=eth2",
                "  vlan_id=20",
                "  ip_cidr=192.168.20.1/24",
                f"  ipv6_cidr={'2001:db8:20::1/64' if dual_stack else ''}",
                "  mtu=1500",
                "  role=services",
            ]
        )
    if include_removed_vlan:
        lines.extend(
            [
                "",
                "[removed_vlan_interfaces]",
                "vlan=eth2.20",
                "  parent=eth2",
                "  vlan_id=20",
            ]
        )
    return "\n".join(lines)


def public_services_config_text() -> str:
    """Return public services config text."""
    return "\n".join(
        [
            "# Managed by Atlaso. Local changes may be overwritten.",
            "# IP-scoped public service front door for non-management interfaces.",
            "server {",
            "  listen 192.168.87.32:80;",
            "  server_name _;",
            "  location /pxe/esxi/ks/ {",
            "    proxy_pass http://127.0.0.1:8000;",
            "  }",
            "  location /pxe/esxi/ {",
            "    alias /var/lib/atlaso/pxe/http/esxi/;",
            "    autoindex off;",
            "  }",
            "  location / {",
            "    return 404;",
            "  }",
            "}",
            "",
        ]
    )


def public_services_ca_https_config_text(cert_path: Path, key_path: Path) -> str:
    """Return public services ca https config text.

    Args:
        cert_path: Filesystem path used for cert.
        key_path: Filesystem path used for key.
    """
    return "\n".join(
        [
            "# Managed by Atlaso. Local changes may be overwritten.",
            "# IP-scoped public service front door for non-management interfaces.",
            "server {",
            "  # CA portal HTTPS front door.",
            "  listen 192.168.87.32:443 ssl;",
            "  server_name ca.atlaso.internal;",
            f"  ssl_certificate {cert_path};",
            f"  ssl_certificate_key {key_path};",
            "  location = / {",
            "    proxy_pass http://127.0.0.1:8000;",
            "    proxy_set_header X-Forwarded-Proto https;",
            "  }",
            "  location = /ca {",
            "    proxy_pass http://127.0.0.1:8000;",
            "    proxy_set_header X-Forwarded-Proto https;",
            "  }",
            "  location ^~ /ca/ {",
            "    proxy_pass http://127.0.0.1:8000;",
            "    proxy_set_header X-Forwarded-Proto https;",
            "  }",
            "  location = /requests {",
            "    proxy_pass http://127.0.0.1:8000;",
            "    proxy_set_header X-Forwarded-Proto https;",
            "  }",
            "  location ^~ /requests/ {",
            "    proxy_pass http://127.0.0.1:8000;",
            "    proxy_set_header X-Forwarded-Proto https;",
            "  }",
            "  location ^~ /static/ {",
            "    proxy_pass http://127.0.0.1:8000;",
            "    proxy_set_header X-Forwarded-Proto https;",
            "  }",
            "  location = /favicon.ico {",
            "    proxy_pass http://127.0.0.1:8000;",
            "    proxy_set_header X-Forwarded-Proto https;",
            "  }",
            "  location = /manifest.webmanifest {",
            "    proxy_pass http://127.0.0.1:8000;",
            "    proxy_set_header X-Forwarded-Proto https;",
            "  }",
            "  location = /service-worker.js {",
            "    proxy_pass http://127.0.0.1:8000;",
            "    proxy_set_header X-Forwarded-Proto https;",
            "  }",
            "  location / {",
            "    return 404;",
            "  }",
            "}",
            "",
        ]
    )


def public_services_ip_https_depot_config_text(cert_path: Path, key_path: Path) -> str:
    """Return public services ip https depot config text.

    Args:
        cert_path: Filesystem path used for cert.
        key_path: Filesystem path used for key.
    """
    return "\n".join(
        [
            "# Managed by Atlaso. Local changes may be overwritten.",
            "# IP-scoped public service front door for non-management interfaces.",
            "server {",
            "  # IP-scoped HTTPS public services front door.",
            "  listen 192.168.87.32:443 ssl;",
            "  server_name _ 192.168.87.32;",
            f"  ssl_certificate {cert_path};",
            f"  ssl_certificate_key {key_path};",
            "  location = /PROD {",
            "    return 301 /PROD/;",
            "  }",
            "  location = /PROD/login {",
            "    proxy_pass http://127.0.0.1:8000;",
            "    proxy_set_header X-Forwarded-Proto https;",
            "  }",
            "  location = /PROD/logout {",
            "    proxy_pass http://127.0.0.1:8000;",
            "    proxy_set_header X-Forwarded-Proto https;",
            "  }",
            "  location = /PROD/ {",
            "    proxy_pass http://127.0.0.1:8000;",
            "    proxy_set_header X-Forwarded-Proto https;",
            "  }",
            "  location ~ ^/PROD/.*/$ {",
            "    proxy_pass http://127.0.0.1:8000;",
            "    proxy_set_header X-Forwarded-Proto https;",
            "  }",
            "  location ~ ^/PROD/(?!login$|logout$|auth-check$)(.+[^/])$ {",
            "    alias /mnt/atlaso-vcf-offline-depot/PROD/$1;",
            "  }",
            "}",
            "",
        ]
    )


def test_public_services_helper_validates_staged_nginx_config(monkeypatch, tmp_path, capsys):
    """Verify that public services helper validates staged nginx config.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "public-services"
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "atlaso-public-services.conf"
    config_path.write_text(public_services_config_text(), encoding="utf-8")
    monkeypatch.setattr(helper, "PUBLIC_SERVICES_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "VCF_DEPOT_PROD_PATH", Path("/mnt/atlaso-vcf-offline-depot/PROD"))

    result = helper._handle_public_services("validate", [str(config_path)])

    captured = capsys.readouterr()
    assert result == 0
    assert "validation ok" in captured.out


def test_public_services_helper_allows_ip_scoped_depot_https_paths(monkeypatch, tmp_path, capsys):
    """Verify that public services helper allows ip scoped depot https paths.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "public-services"
    managed_root = tmp_path / "managed"
    cert_path = managed_root / "ca-portal" / "certs" / "ca.atlaso.internal.crt"
    key_path = managed_root / "ca-portal" / "certs" / "ca.atlaso.internal.key"
    cert_path.parent.mkdir(parents=True)
    cert_path.write_text("-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n", encoding="utf-8")
    key_path.write_text("-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n", encoding="utf-8")
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "atlaso-public-services.conf"
    config_path.write_text(public_services_ip_https_depot_config_text(cert_path, key_path), encoding="utf-8")
    monkeypatch.setattr(helper, "PUBLIC_SERVICES_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "CA_MANAGED_PATH_BASE", managed_root)
    monkeypatch.setattr(helper, "VCF_DEPOT_PROD_PATH", Path("/mnt/atlaso-vcf-offline-depot/PROD"))

    result = helper._handle_public_services("validate", [str(config_path)])

    captured = capsys.readouterr()
    assert result == 0
    assert "validation ok" in captured.out


def test_public_services_helper_validates_ca_https_sni_config(monkeypatch, tmp_path, capsys):
    """Verify that public services helper validates ca https sni config.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "public-services"
    managed_root = tmp_path / "managed"
    cert_path = managed_root / "ca-portal" / "certs" / "ca.atlaso.internal.crt"
    key_path = managed_root / "ca-portal" / "certs" / "ca.atlaso.internal.key"
    cert_path.parent.mkdir(parents=True)
    cert_path.write_text("-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n", encoding="utf-8")
    key_path.write_text("-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n", encoding="utf-8")
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "atlaso-public-services.conf"
    config_path.write_text(public_services_ca_https_config_text(cert_path, key_path), encoding="utf-8")
    monkeypatch.setattr(helper, "PUBLIC_SERVICES_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "CA_MANAGED_PATH_BASE", managed_root)

    result = helper._handle_public_services("validate", [str(config_path)])

    captured = capsys.readouterr()
    assert result == 0
    assert "validation ok" in captured.out


def test_nginx_site_conflict_detects_duplicate_sni_name_on_same_listener(monkeypatch, tmp_path):
    """Verify that nginx site conflict detects duplicate sni name on same listener.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    sites_dir = tmp_path / "sites.d"
    sites_dir.mkdir()
    existing = sites_dir / "vcf-offline-depot.conf"
    existing.write_text(
        "\n".join(
            [
                "server {",
                "  listen 192.168.87.32:443 ssl;",
                "  server_name ca.atlaso.internal;",
                "}",
            ]
        ),
        encoding="utf-8",
    )
    candidate = "\n".join(
        [
            "server {",
            "  listen 192.168.87.32:443 ssl;",
            "  server_name ca.atlaso.internal;",
            "}",
        ]
    )
    monkeypatch.setattr(helper, "NGINX_SITES_DIR", sites_dir)

    assert "duplicates server_name ca.atlaso.internal" in helper._nginx_site_conflict(sites_dir / "public-services.conf", candidate)


def test_nginx_listen_parser_requires_brackets_for_ipv6_literals():
    """Verify that nginx listen parser requires brackets for ipv6 literals."""
    helper = load_helper_module()

    assert helper._listen_address_and_port("[fd87::254]:443 ssl") == ("fd87::254", 443)
    with pytest.raises(ValueError, match="IPv6 listen address must be bracketed"):
        helper._listen_address_and_port("fd87::254:443 ssl")


def test_public_services_helper_rejects_broad_root_and_registry_proxy(monkeypatch, tmp_path, capsys):
    """Verify that public services helper rejects broad root and registry proxy.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "public-services"
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "atlaso-public-services.conf"
    config_path.write_text(
        public_services_config_text().replace("  location / {", "  root /mnt/atlaso-vcf-offline-depot;\n  location /registry {\n    proxy_pass http://127.0.0.1:8080;\n  }\n  location / {"),
        encoding="utf-8",
    )
    monkeypatch.setattr(helper, "PUBLIC_SERVICES_APPLY_DIR", apply_dir)

    result = helper._handle_public_services("validate", [str(config_path)])

    captured = capsys.readouterr()
    assert result == 2
    assert "must not expose a broad server root" in captured.err
    assert "must not add registry proxy locations" in captured.err


def test_public_services_helper_apply_installs_site(monkeypatch, tmp_path, capsys):
    """Verify that public services helper apply installs site.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "public-services"
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "atlaso-public-services.conf"
    config_text = public_services_config_text()
    config_path.write_text(config_text, encoding="utf-8")
    site_path = tmp_path / "sites" / "public-services.conf"
    calls: list[tuple[Path, str]] = []

    def fake_install(path, text):
        """Return fake install.

        Args:
            path: Filesystem or URL path to read, validate, or update.
            text: Text to parse, render, or persist.
        """
        calls.append((path, text))
        return 0

    monkeypatch.setattr(helper, "PUBLIC_SERVICES_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "NGINX_PUBLIC_SERVICES_SITE_PATH", site_path)
    monkeypatch.setattr(helper, "_install_nginx_site", fake_install)

    result = helper._handle_public_services("apply", [str(config_path)])

    captured = capsys.readouterr()
    assert result == 0
    assert calls == [(site_path, config_text)]
    assert "apply complete" in captured.out


def wan_config_text(
    *,
    bad_nat_source: bool = False,
    bad_target: bool = False,
    wan_mode: str = "interface",
    target_role: str = "route",
    ipv6_route: bool = False,
    ipv6_only_target: bool = False,
) -> str:
    """Return wan config text.

    Args:
        bad_nat_source: Bad nat source supplied by the caller.
        bad_target: Bad target supplied by the caller.
        wan_mode: Wan mode supplied by the caller.
        target_role: Target role supplied by the caller.
        ipv6_route: Ipv6 route supplied by the caller.
        ipv6_only_target: Ipv6 only target supplied by the caller.
    """
    source = "not-a-cidr" if bad_nat_source else "192.168.50.0/24"
    outbound = "eth9" if bad_target else "eth1.20"
    ipv4_cidr = "" if ipv6_only_target else "192.168.20.1/24"
    ipv6_cidr = "2001:db8:20::1/64" if ipv6_route or ipv6_only_target else ""
    destination = "2001:db8:100::/64" if ipv6_route else "10.20.0.0/24"
    gateway = "2001:db8:20::fe" if ipv6_route else ""
    return "\n".join(
        [
            "[targets]",
            "target=eth1.20",
            "  kind=vlan",
            f"  role={target_role}",
            f"  ip_cidr={ipv4_cidr}",
            f"  ipv6_cidr={ipv6_cidr}",
            "",
            "[routes]",
            f"route={destination}",
            f"  gateway={gateway}",
            "  interface=eth1.20",
            "  metric=120",
            "  enabled=true",
            "  wan_policy=Slow WAN",
            f"  wan_mode={wan_mode}",
            "",
            "[nat_rules]",
            "nat=SiteA outbound WAN",
            "  enabled=true",
            f"  source={source}",
            f"  source_resolved={source}",
            f"  outbound_interface={outbound}",
            "  masquerade=true",
            "  priority=100",
            "  description=demo",
            "",
            "[wan_policies]",
            "policy=Slow WAN",
            "  enabled=true",
            "  latency_ms=100",
            "  jitter_ms=10",
            "  packet_loss_percent=0.5",
            "  bandwidth_mbit=100",
            "  corrupt_percent=0",
            "  duplicate_percent=0",
            "  reorder_percent=0",
        ]
    )


def esxi_pxe_manifest(http_root: Path, *, enabled: bool = True, stale_id: int = 99, iso_root: Path | None = None) -> dict:
    """Return esxi pxe manifest.

    Args:
        http_root: Filesystem path associated with HTTP root.
        enabled: Whether the associated resource or behavior is enabled.
        stale_id: Stable identifier of the associated stale resource.
        iso_root: Filesystem path associated with ISO root.
    """
    content = "install\nnetwork --bootproto=dhcp\nrootpw VMware01!\nreboot\n%firstboot\n%end\n"
    content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
    kickstart_http_path = f"/pxe/esxi/ks/{content_hash[:12]}.cfg"
    kickstart_url = f"http://192.168.50.1:8080{kickstart_http_path}"
    iso_root = iso_root or http_root.parent / "iso"
    iso_path = iso_root / "VMware-VMvisor-Installer-8.0U3.iso"
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", iso_path.stem).strip("-._").lower()
    image_key = f"{slug}-{hashlib.sha1(str(iso_path).encode('utf-8')).hexdigest()[:10]}"
    http_base = http_root.parent
    image_path = http_base / "images" / image_key
    mac_key = "01-00-50-56-aa-bb-cc"
    kickstart_url = f"{kickstart_url}?mac={mac_key}"
    return {
        "kind": "atlaso-esxi-pxe",
        "schema_version": 2,
        "http_root": str(http_root),
        "http_base": str(http_base),
        "image_http_root": str(http_base / "images"),
        "installer_iso_root": str(iso_root),
        "installer_isos": [
            {
                "name": iso_path.name,
                "path": str(iso_path),
                "relative_path": iso_path.name,
                "size_bytes": 12,
                "updated_at": "2026-06-28T00:00:00+00:00",
            }
        ],
        "kickstarts": [
            {
                "id": 7,
                "name": "ESXi install",
                "enabled": enabled,
                "content": content,
                "content_hash": content_hash,
                "http_path": kickstart_http_path,
                "generated_path": str(http_root / f"{content_hash[:12]}.cfg"),
            }
        ],
        "hosts": [
            {
                "id": 1,
                "hostname": "esxi-01",
                "mac_address": "00:50:56:aa:bb:cc",
                "kickstart_id": 7 if enabled else None,
                "installer_iso_path": str(iso_path),
                "installer_iso_name": iso_path.name,
                "enabled": True,
            }
        ],
        "artifacts": [
            {
                "host_id": 1,
                "hostname": "esxi-01",
                "mac_address": "00:50:56:aa:bb:cc",
                "mac_key": mac_key,
                "image_key": image_key,
                "installer_iso_path": str(iso_path),
                "installer_iso_name": iso_path.name,
                "image_http_path": f"/pxe/esxi/images/{image_key}",
                "image_http_url": f"http://192.168.50.1:8080/pxe/esxi/images/{image_key}",
                "image_generated_path": str(image_path),
                "kickstart_id": 7 if enabled else None,
                "kickstart_http_path": kickstart_http_path if enabled else "",
                "kickstart_url": kickstart_url if enabled else "",
                "pxelinux_config_path": str(http_root.parents[2] / "tftp" / "pxelinux.cfg" / mac_key),
                "uefi_tftp_boot_cfg_path": str(http_root.parents[2] / "tftp" / mac_key / "boot.cfg"),
                "http_boot_cfg_path": str(http_base / mac_key / "boot.cfg"),
            }
        ],
        "stale_id": stale_id,
    }


def test_esxi_pxe_helper_validates_network_boot_media_hashes(monkeypatch, tmp_path):
    """Verify that esxi pxe helper validates network boot media hashes.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    media_root = tmp_path / "media"
    http_root = tmp_path / "http"
    installed = media_root / "memtest86plus" / "8.10"
    installed.mkdir(parents=True)
    artifact = installed / "memtest"
    artifact.write_bytes(b"verified memtest payload")
    manifest = {
        "schema_version": 1,
        "environment": "memtest86plus",
        "artifacts": {"memtest": hashlib.sha256(artifact.read_bytes()).hexdigest()},
    }
    (installed / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(helper, "NETWORK_BOOT_MEDIA_ROOT", media_root)
    monkeypatch.setattr(helper, "NETWORK_BOOT_HTTP_ROOT", http_root)
    payload = {
        "boot": {"enabled": False},
        "network_boot": {
            "media_root": str(media_root),
            "http_root": str(http_root),
            "environments": [
                {
                    "key": "memtest86plus",
                    "enabled": True,
                    "desired_version": "8.10",
                    "installed_path": str(installed),
                    "manifest": manifest,
                }
            ],
        },
        "kickstarts": [],
        "hosts": [],
        "artifacts": [],
    }
    original_read_bytes = Path.read_bytes

    def reject_artifact_read_bytes(path):
        """Return reject artifact read bytes.

        Args:
            path: Filesystem or URL path to read, validate, or update.

        Raises:
            AssertionError: If an expected invariant is not satisfied.
        """
        if path == artifact:
            raise AssertionError("Network Boot artifacts must be hashed as a stream.")
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", reject_artifact_read_bytes)

    errors = helper._esxi_pxe_manifest_errors(payload)
    assert not [error for error in errors if error.startswith("Network Boot")]

    artifact.write_bytes(b"tampered")
    errors = helper._esxi_pxe_manifest_errors(payload)
    assert any("failed SHA-256 verification" in error for error in errors)


def test_esxi_pxe_helper_accepts_verified_shredos_digest_directory(
    monkeypatch,
    tmp_path,
):
    """Verify that esxi pxe helper accepts verified shredos digest directory.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    media_root = tmp_path / "media"
    http_root = tmp_path / "http"
    version = "2025.11"
    artifact_sha256 = "b" * 64
    installed = (
        media_root
        / "shredos"
        / f"{version}.sha256-{artifact_sha256[:12]}-{'d' * 12}"
    )
    installed.mkdir(parents=True)
    artifact = installed / "shredos"
    artifact.write_bytes(b"verified ShredOS kernel")
    manifest = {
        "schema_version": 1,
        "environment": "shredos",
        "artifacts": {
            "shredos": hashlib.sha256(artifact.read_bytes()).hexdigest(),
        },
    }
    (installed / "manifest.json").write_text(
        json.dumps(manifest),
        encoding="utf-8",
    )
    monkeypatch.setattr(helper, "NETWORK_BOOT_MEDIA_ROOT", media_root)
    monkeypatch.setattr(helper, "NETWORK_BOOT_HTTP_ROOT", http_root)
    environment = {
        "key": "shredos",
        "enabled": True,
        "desired_version": version,
        "installed_path": str(installed),
        "artifact_sha256": artifact_sha256,
        "manifest": manifest,
    }
    payload = {
        "boot": {"enabled": False},
        "network_boot": {
            "media_root": str(media_root),
            "http_root": str(http_root),
            "environments": [environment],
        },
        "kickstarts": [],
        "hosts": [],
        "artifacts": [],
    }

    errors = helper._esxi_pxe_manifest_errors(payload)

    assert not [error for error in errors if error.startswith("Network Boot")]

    environment["installed_path"] = str(
        media_root
        / "shredos"
        / f"{version}.sha256-{'c' * 12}-{'d' * 12}"
    )
    errors = helper._esxi_pxe_manifest_errors(payload)

    assert any(
        "installed path must be the immutable desired version" in error
        for error in errors
    )


def test_esxi_pxe_helper_activates_and_disables_network_boot_media(monkeypatch, tmp_path):
    """Verify that esxi pxe helper activates and disables network boot media.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    media_root = tmp_path / "media"
    http_root = tmp_path / "http"
    installed = media_root / "inventory" / "0.9.51"
    installed.mkdir(parents=True)
    monkeypatch.setattr(helper, "NETWORK_BOOT_MEDIA_ROOT", media_root)
    monkeypatch.setattr(helper, "NETWORK_BOOT_HTTP_ROOT", http_root)
    environment = {
        "key": "inventory",
        "enabled": True,
        "desired_version": "0.9.51",
        "installed_path": str(installed),
    }
    payload = {"network_boot": {"environments": [environment]}}

    assert helper._activate_network_boot_media(payload) == ["inventory"]
    active = http_root / "inventory"
    assert active.is_symlink()
    assert active.resolve() == installed.resolve()

    environment["enabled"] = False
    assert helper._activate_network_boot_media(payload) == []
    assert not active.exists()


def ca_payload_text(root_dir: Path) -> str:
    """Return ca payload text.

    Args:
        root_dir: Filesystem path associated with root dir.
    """
    root_cert = "-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----\n"
    cert = "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n"
    key = "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n"
    crl = "-----BEGIN X509 CRL-----\ncrl\n-----END X509 CRL-----\n"
    return json.dumps(
        {
            "enabled": True,
            "root": {
                "common_name": "Atlaso Internal Root CA",
                "certificate_pem": root_cert,
                "private_key_pem": key,
                "root_cert_path": str(root_dir / "ca" / "root-ca.pem"),
                "legacy_root_cert_path": str(root_dir / "ca" / "root.crt"),
                "ca_bundle_path": str(root_dir / "ca" / "ca-bundle.pem"),
                "crl_path": str(root_dir / "ca" / "atlaso-ca.crl"),
                "crl_pem": crl,
            },
            "certificates": [
                {
                    "common_name": "kms.atlaso.internal",
                    "managed_owner": "kms:server",
                    "certificate_pem": cert,
                    "chain_pem": cert + root_cert,
                    "private_key_pem": key,
                    "cert_path": str(root_dir / "kms" / "certs" / "kms.atlaso.internal.crt"),
                    "key_path": str(root_dir / "kms" / "certs" / "kms.atlaso.internal.key"),
                    "chain_path": str(root_dir / "kms" / "certs" / "kms.atlaso.internal-chain.pem"),
                }
            ],
        }
    )


def test_network_helper_validates_vlan_parent_must_be_trunk(tmp_path):
    """Verify that network helper validates vlan parent must be trunk.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    config_path = tmp_path / "atlaso-network.conf"
    config_path.write_text(network_config_text(eth2_mode="access"), encoding="utf-8")

    errors = helper._network_config_errors(config_path)

    assert "VLAN eth2.20 parent eth2 is not marked trunk." in errors


def test_network_helper_accepts_valid_vlan_config(tmp_path):
    """Verify that network helper accepts valid vlan config.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    config_path = tmp_path / "atlaso-network.conf"
    config_path.write_text(network_config_text(), encoding="utf-8")

    assert helper._network_config_errors(config_path) == []


def test_network_helper_validates_explicit_management_gateway(tmp_path):
    """Verify that network helper validates explicit management gateway.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    valid = tmp_path / "valid-gateway.conf"
    valid.write_text(network_config_text(management_gateway="192.168.49.254"), encoding="utf-8")
    off_link = tmp_path / "off-link-gateway.conf"
    off_link.write_text(network_config_text(management_gateway="192.168.1.1"), encoding="utf-8")
    non_management = tmp_path / "non-management-gateway.conf"
    non_management.write_text(
        network_config_text().replace("  ip_cidr=\n", "  ip_cidr=192.168.50.1/24\n  gateway=192.168.50.254\n", 1),
        encoding="utf-8",
    )

    assert helper._network_config_errors(valid) == []
    assert any("is not on-link" in error for error in helper._network_config_errors(off_link))
    assert any("only when it is management" in error for error in helper._network_config_errors(non_management))


def test_network_helper_renders_explicit_management_gateway_without_runtime_fallback(monkeypatch, tmp_path):
    """Verify that network helper renders explicit management gateway without runtime fallback.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    config_path = tmp_path / "management-gateway.conf"
    config_path.write_text(network_config_text(management_gateway="192.168.49.254"), encoding="utf-8")
    monkeypatch.setattr(helper, "NETWORKD_MGMT_CONFIG_PATH", tmp_path / "missing.network")
    monkeypatch.setattr(helper, "_runtime_default_gateways_for_interface", lambda _interface_name: [])
    monkeypatch.setattr(helper.shutil, "which", lambda command: f"/usr/sbin/{command}" if command == "ip" else None)

    files, _links, _admin_down = helper._systemd_networkd_files(config_path)

    rendered = files["00-atlaso-mgmt.network"]
    assert "From=192.168.49.0/24" in rendered
    assert rendered.count("Gateway=192.168.49.254") == 2
    assert "Table=100" in rendered


def test_network_helper_rejects_static_management_without_ipv4(tmp_path):
    """Verify that network helper rejects static management without ipv4.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    config_path = tmp_path / "atlaso-network.conf"
    config_path.write_text(network_config_text().replace("  ip_cidr=192.168.49.1/24", "  ip_cidr=", 1), encoding="utf-8")

    errors = helper._network_config_errors(config_path)

    assert "Interface eth0 must set an IPv4 CIDR when IPv4 method is static." in errors


def test_network_helper_requires_eth0_management(tmp_path):
    """Verify that network helper requires eth0 management.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    config_path = tmp_path / "atlaso-network.conf"
    config_path.write_text(network_config_text().replace("interface=eth0", "interface=eth1", 1), encoding="utf-8")

    errors = helper._network_config_errors(config_path)

    assert "Network config must keep eth0 as the management physical interface." in errors


def test_network_helper_renders_dual_stack_networkd_addresses(tmp_path):
    """Verify that network helper renders dual stack networkd addresses.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    config_path = tmp_path / "atlaso-network.conf"
    config_path.write_text(network_config_text(dual_stack=True), encoding="utf-8")

    assert helper._network_config_errors(config_path) == []
    files, _reconfigure_links, _admin_down_links = helper._systemd_networkd_files(config_path)

    assert "Address=192.168.49.1/24" in files["00-atlaso-mgmt.network"]
    assert "Address=2001:db8:49::1/64" in files["00-atlaso-mgmt.network"]
    assert "IPv6AcceptRA=no" in files["00-atlaso-mgmt.network"]
    assert "LinkLocalAddressing=ipv6" in files["00-atlaso-mgmt.network"]
    vlan_network = files["10-atlaso-eth2.20.network"]
    assert "Address=192.168.20.1/24" in vlan_network
    assert "Address=2001:db8:20::1/64" in vlan_network


def test_network_helper_replaces_stale_preserved_management_gateway(monkeypatch, tmp_path):
    """Verify that network helper replaces stale preserved management gateway.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    config_path = tmp_path / "atlaso-network.conf"
    config_path.write_text(
        network_config_text()
        .replace("  ip_cidr=192.168.49.1/24", "  ip_cidr=192.168.1.10/24", 1)
        .replace("  gateway=\n", "", 1),
        encoding="utf-8",
    )
    management_network = tmp_path / "00-atlaso-mgmt.network"
    management_network.write_text(
        "\n".join(
            [
                "[Match]",
                "Name=eth0",
                "",
                "[Network]",
                "Address=192.168.1.10/24",
                "",
                "[Route]",
                "Gateway=192.168.167.2",
                "Table=100",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        if command == ["ip", "route", "show", "default", "dev", "eth0"]:
            return subprocess.CompletedProcess(command, 0, "default via 192.168.1.1 dev eth0\n", "")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "NETWORKD_MGMT_CONFIG_PATH", management_network)
    monkeypatch.setattr(helper, "_run", fake_run)
    monkeypatch.setattr(helper.shutil, "which", lambda command: f"/usr/sbin/{command}" if command == "ip" else None)

    files, _reconfigure_links, _admin_down_links = helper._systemd_networkd_files(config_path)

    rendered = files["00-atlaso-mgmt.network"]
    assert "Gateway=192.168.1.1" in rendered
    assert "Gateway=192.168.167.2" not in rendered
    assert "From=192.168.1.0/24" in rendered
    assert "Table=100" in rendered


def test_network_helper_omits_management_policy_rule_without_default_gateway(monkeypatch, tmp_path):
    """Verify that network helper omits management policy rule without default gateway.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    config_path = tmp_path / "atlaso-network.conf"
    config_path.write_text(
        network_config_text().replace("  ip_cidr=192.168.49.1/24", "  ip_cidr=192.168.1.10/24", 1),
        encoding="utf-8",
    )

    monkeypatch.setattr(helper, "NETWORKD_MGMT_CONFIG_PATH", tmp_path / "missing.network")
    monkeypatch.setattr(helper, "_runtime_default_gateways_for_interface", lambda _interface_name: [])
    monkeypatch.setattr(helper.shutil, "which", lambda command: f"/usr/sbin/{command}" if command == "ip" else None)

    files, _reconfigure_links, _admin_down_links = helper._systemd_networkd_files(config_path)

    rendered = files["00-atlaso-mgmt.network"]
    assert "Address=192.168.1.10/24" in rendered
    assert "[RoutingPolicyRule]" not in rendered
    assert "Table=100" not in rendered
    assert "Gateway=" not in rendered


def test_network_helper_renders_management_dhcp_networkd(tmp_path):
    """Verify that network helper renders management dhcp networkd.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    config_path = tmp_path / "atlaso-network.conf"
    config_path.write_text(
        "\n".join(
            [
                "[physical_interfaces]",
                "interface=eth0",
                "  role=management",
                "  mode=access",
                "  ipv4_method=dhcp",
                "  ip_cidr=",
                "  ipv6_cidr=",
                "  admin_state=up",
                "  mtu=1500",
                "",
                "[vlan_interfaces]",
            ]
        ),
        encoding="utf-8",
    )

    assert helper._network_config_errors(config_path) == []
    files, _reconfigure_links, _admin_down_links = helper._systemd_networkd_files(config_path)

    management_network = files["00-atlaso-mgmt.network"]
    assert "DHCP=ipv4" in management_network
    assert "Address=" not in management_network
    assert "IPv6AcceptRA=no" in management_network
    assert "LinkLocalAddressing=no" in management_network


def test_network_helper_preserves_automatic_ipv6_for_management(tmp_path):
    """Verify that network helper preserves automatic ipv6 for management.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    config_path = tmp_path / "atlaso-network.conf"
    config_path.write_text(
        "\n".join(
            [
                "[physical_interfaces]",
                "interface=eth0",
                "  role=management",
                "  mode=access",
                "  ipv4_method=dhcp",
                "  ip_cidr=",
                "  ipv6_enabled=true",
                "  ipv6_cidr=",
                "  admin_state=up",
                "  mtu=1500",
                "",
                "[vlan_interfaces]",
            ]
        ),
        encoding="utf-8",
    )

    assert helper._network_config_errors(config_path) == []
    files, _reconfigure_links, _admin_down_links = helper._systemd_networkd_files(config_path)

    management_network = files["00-atlaso-mgmt.network"]
    assert "DHCP=ipv4" in management_network
    assert "IPv6AcceptRA=yes" in management_network
    assert "LinkLocalAddressing=ipv6" in management_network


def test_network_helper_renders_static_management_ipv6_gateway_in_main_and_table_100(tmp_path):
    """Verify that network helper renders static management ipv6 gateway in main and table 100.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    config_path = tmp_path / "atlaso-network.conf"
    config_path.write_text(
        "\n".join(
            [
                "[physical_interfaces]",
                "interface=eth0",
                "  role=management",
                "  mode=access",
                "  ipv4_method=dhcp",
                "  ip_cidr=",
                "  gateway=",
                "  ipv6_enabled=true",
                "  ipv6_cidr=2001:db8:49::10/64",
                "  ipv6_gateway=fe80::1",
                "  admin_state=up",
                "  mtu=1500",
                "",
                "[vlan_interfaces]",
            ]
        ),
        encoding="utf-8",
    )

    assert helper._network_config_errors(config_path) == []
    files, _reconfigure_links, _admin_down_links = helper._systemd_networkd_files(config_path)
    rendered = files["00-atlaso-mgmt.network"]
    assert "IPv6AcceptRA=no" in rendered
    assert "LinkLocalAddressing=ipv6" in rendered
    assert "Address=2001:db8:49::10/64" in rendered
    assert "From=2001:db8:49::/64" in rendered
    assert rendered.count("Gateway=fe80::1") == 2
    assert "Table=100" in rendered


def test_wan_helper_rejects_config_outside_apply_dir(tmp_path):
    """Verify that wan helper rejects config outside apply dir.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.


    Raises:
        AssertionError: If an expected invariant is not satisfied.
    """
    helper = load_helper_module()
    config_path = tmp_path / "atlaso-wan.conf"
    config_path.write_text(wan_config_text(), encoding="utf-8")

    try:
        helper._validate_wan_config_path(str(config_path))
    except ValueError as exc:
        assert "WAN config must be staged under" in str(exc)
    else:
        raise AssertionError("WAN config outside apply directory should be rejected")


def test_wan_helper_validates_routes_nat_and_netem(tmp_path):
    """Verify that wan helper validates routes nat and netem.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    config_path = tmp_path / "atlaso-wan.conf"
    config_path.write_text(wan_config_text(), encoding="utf-8")

    assert helper._wan_config_errors(config_path) == []
    nat_config = helper._render_wan_nat_config(helper._parse_wan_config(config_path)["nat_rules"])
    assert "table ip atlaso_nat" in nat_config
    assert 'ip saddr 192.168.50.0/24 oifname "eth1.20" masquerade' in nat_config


def test_wan_helper_rejects_bad_nat_source_and_target(tmp_path):
    """Verify that wan helper rejects bad nat source and target.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    bad_source = tmp_path / "bad-source.conf"
    bad_source.write_text(wan_config_text(bad_nat_source=True), encoding="utf-8")
    bad_target = tmp_path / "bad-target.conf"
    bad_target.write_text(wan_config_text(bad_target=True), encoding="utf-8")

    assert any("source not-a-cidr is not a valid CIDR" in error for error in helper._wan_config_errors(bad_source))
    assert any("must use an access physical interface or enabled VLAN" in error for error in helper._wan_config_errors(bad_target))


def test_wan_helper_rejects_route_wan_mode(tmp_path):
    """Verify that wan helper rejects route wan mode.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    config_path = tmp_path / "route-mode.conf"
    config_path.write_text(wan_config_text(wan_mode="route"), encoding="utf-8")

    assert any("WAN mode route is planned but not supported in v1" in error for error in helper._wan_config_errors(config_path))


def test_wan_helper_ignores_disabled_routing_rule_missing_targets(tmp_path):
    """Verify that wan helper ignores disabled routing rule missing targets.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    config_path = tmp_path / "disabled-routing-rule.conf"
    config_path.write_text(
        wan_config_text()
        + "\n".join(
            [
                "",
                "[routing_rules]",
                "routing=Stale disabled rule",
                "  enabled=false",
                "  source_interface=missing-source",
                "  destination_interface=missing-destination",
                "  priority=100",
            ]
        ),
        encoding="utf-8",
    )

    assert helper._wan_config_errors(config_path) == []


def test_wan_helper_rejects_enabled_routing_rule_missing_targets(tmp_path):
    """Verify that wan helper rejects enabled routing rule missing targets.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    config_path = tmp_path / "enabled-routing-rule.conf"
    config_path.write_text(
        wan_config_text()
        + "\n".join(
            [
                "",
                "[routing_rules]",
                "routing=Stale enabled rule",
                "  enabled=true",
                "  source_interface=missing-source",
                "  destination_interface=missing-destination",
                "  priority=100",
            ]
        ),
        encoding="utf-8",
    )

    errors = helper._wan_config_errors(config_path)
    assert any("references missing source target missing-source" in error for error in errors)
    assert any("references missing destination target missing-destination" in error for error in errors)


def test_wan_helper_allows_nat_on_access_role_target(tmp_path):
    """Verify that wan helper allows nat on access role target.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    config_path = tmp_path / "nat-access-target.conf"
    config_path.write_text(wan_config_text(target_role="access"), encoding="utf-8")

    assert helper._wan_config_errors(config_path) == []


def test_wan_helper_accepts_ipv6_routes_and_rejects_ipv6_only_nat_targets(tmp_path):
    """Verify that wan helper accepts ipv6 routes and rejects ipv6 only nat targets.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    ipv6_route = tmp_path / "ipv6-route.conf"
    ipv6_route.write_text(wan_config_text(ipv6_route=True), encoding="utf-8")
    ipv6_only_nat = tmp_path / "ipv6-only-nat.conf"
    ipv6_only_nat.write_text(wan_config_text(ipv6_route=True, ipv6_only_target=True), encoding="utf-8")

    assert helper._wan_config_errors(ipv6_route) == []
    parsed = helper._parse_wan_config(ipv6_route)
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    helper._run = fake_run
    helper.shutil.which = lambda command: f"/usr/sbin/{command}" if command in {"ip", "tc"} else None
    assert helper._apply_wan_routes_and_qdiscs(parsed) == 0
    assert ["ip", "-6", "route", "replace", "2001:db8:100::/64", "via", "2001:db8:20::fe", "dev", "eth1.20", "metric", "120", "table", "200"] in commands
    assert any("outbound interface with an IPv4 CIDR" in error for error in helper._wan_config_errors(ipv6_only_nat))


def test_wan_helper_cleans_managed_policy_rule_windows_before_apply(tmp_path):
    """Verify that wan helper cleans managed policy rule windows before apply.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    config_path = tmp_path / "policy-rules.conf"
    config_path.write_text(wan_config_text(), encoding="utf-8")
    parsed = helper._parse_wan_config(config_path)
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    helper._run = fake_run
    helper.shutil.which = lambda command: f"/usr/sbin/{command}" if command == "ip" else None

    assert helper._apply_wan_policy_rules(parsed) == 0
    assert ["ip", "rule", "del", "priority", "1000"] in commands
    assert ["ip", "-6", "rule", "del", "priority", "1000"] in commands
    assert ["ip", "rule", "del", "priority", "2099"] in commands
    assert ["ip", "-6", "rule", "del", "priority", "2099"] in commands
    assert ["ip", "rule", "add", "from", "192.168.20.0/24", "table", "200", "priority", "2000"] in commands


def test_wan_helper_preserves_management_default_gateway(monkeypatch, tmp_path):
    """Verify that wan helper preserves management default gateway.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    networkd_dir = tmp_path / "systemd-network"
    networkd_dir.mkdir()
    management_network = networkd_dir / "00-atlaso-mgmt.network"
    management_network.write_text(
        "\n".join(
            [
                "[Match]",
                "Name=eth0",
                "",
                "[Network]",
                "Address=192.168.49.10/24",
                "",
                "[Route]",
                "Gateway=192.168.49.254",
                "Table=100",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    config_path = tmp_path / "management-default.conf"
    config_path.write_text(
        "\n".join(
            [
                "[targets]",
                "target=eth0",
                "  kind=physical",
                "  role=management",
                "  ip_cidr=192.168.49.10/24",
                "  ipv6_cidr=",
                "  routing_domain=management",
                "  route_allowed=false",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    parsed = helper._parse_wan_config(config_path)
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "NETWORKD_MGMT_CONFIG_PATH", management_network)
    monkeypatch.setattr(helper, "_run", fake_run)
    monkeypatch.setattr(helper.shutil, "which", lambda command: f"/usr/sbin/{command}" if command == "ip" else None)

    assert helper._apply_wan_target_routes(parsed) == 0
    assert ["ip", "route", "replace", "192.168.49.0/24", "dev", "eth0", "table", "100"] in commands
    assert ["ip", "route", "replace", "default", "via", "192.168.49.254", "dev", "eth0"] in commands
    assert ["ip", "route", "replace", "default", "via", "192.168.49.254", "dev", "eth0", "table", "100"] in commands


def test_wan_helper_replaces_stale_preserved_management_gateway_with_runtime_gateway(monkeypatch, tmp_path):
    """Verify that wan helper replaces stale preserved management gateway with runtime gateway.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    management_network = tmp_path / "00-atlaso-mgmt.network"
    management_network.write_text(
        "\n".join(
            [
                "[Match]",
                "Name=eth0",
                "",
                "[Network]",
                "Address=192.168.1.10/24",
                "",
                "[Route]",
                "Gateway=192.168.167.2",
                "Table=100",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    config_path = tmp_path / "stale-management-gateway.conf"
    config_path.write_text(
        "\n".join(
            [
                "[targets]",
                "target=eth0",
                "  kind=physical",
                "  role=management",
                "  ip_cidr=192.168.1.10/24",
                "  ipv6_cidr=",
                "  routing_domain=management",
                "  route_allowed=false",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    parsed = helper._parse_wan_config(config_path)
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        commands.append(command)
        if command == ["ip", "route", "show", "default", "dev", "eth0"]:
            return subprocess.CompletedProcess(command, 0, "default via 192.168.1.1 dev eth0\n", "")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "NETWORKD_MGMT_CONFIG_PATH", management_network)
    monkeypatch.setattr(helper, "_run", fake_run)
    monkeypatch.setattr(helper.shutil, "which", lambda command: f"/usr/sbin/{command}" if command == "ip" else None)

    assert helper._management_default_gateways_for_target(parsed["targets"][0]) == ["192.168.1.1"]
    assert helper._apply_wan_target_routes(parsed) == 0
    assert helper._apply_wan_policy_rules(parsed) == 0
    assert ["ip", "route", "replace", "default", "via", "192.168.1.1", "dev", "eth0"] in commands
    assert ["ip", "route", "replace", "default", "via", "192.168.1.1", "dev", "eth0", "table", "100"] in commands
    assert ["ip", "route", "replace", "default", "via", "192.168.167.2", "dev", "eth0", "table", "100"] not in commands
    assert ["ip", "rule", "add", "from", "192.168.1.0/24", "table", "100", "priority", "1000"] in commands


def test_wan_helper_skips_management_policy_rule_without_usable_gateway(monkeypatch, tmp_path):
    """Verify that wan helper skips management policy rule without usable gateway.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    config_path = tmp_path / "management-without-gateway.conf"
    config_path.write_text(
        "\n".join(
            [
                "[targets]",
                "target=eth0",
                "  kind=physical",
                "  role=management",
                "  ip_cidr=192.168.1.10/24",
                "  ipv6_cidr=",
                "  gateway=",
                "  routing_domain=management",
                "  route_allowed=false",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    parsed = helper._parse_wan_config(config_path)
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        commands.append(command)
        if command[:4] == ["ip", "route", "del", "default"]:
            return subprocess.CompletedProcess(command, 2, "", "RTNETLINK answers: No such process\n")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "NETWORKD_MGMT_CONFIG_PATH", tmp_path / "missing.network")
    monkeypatch.setattr(helper, "_run", fake_run)
    monkeypatch.setattr(helper.shutil, "which", lambda command: f"/usr/sbin/{command}" if command == "ip" else None)

    assert helper._apply_wan_target_routes(parsed) == 0
    assert helper._apply_wan_policy_rules(parsed) == 0
    assert ["ip", "route", "replace", "192.168.1.0/24", "dev", "eth0", "table", "100"] not in commands
    assert ["ip", "route", "del", "192.168.1.0/24", "dev", "eth0", "table", "100"] in commands
    assert ["ip", "route", "del", "default", "dev", "eth0", "table", "100"] in commands
    assert ["ip", "route", "del", "default", "dev", "eth0"] in commands
    assert ["ip", "route", "show", "default", "dev", "eth0"] not in commands
    assert ["ip", "rule", "add", "from", "192.168.1.0/24", "table", "100", "priority", "1000"] not in commands


def test_wan_helper_does_not_delete_dhcp_management_default(monkeypatch, tmp_path):
    """Verify that wan helper does not delete dhcp management default.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    config_path = tmp_path / "dhcp-management.conf"
    config_path.write_text(
        "\n".join(
            [
                "[targets]",
                "target=eth0",
                "  kind=physical",
                "  role=management",
                "  ip_cidr=",
                "  ipv6_cidr=",
                "  gateway=",
                "  ipv4_method=dhcp",
                "  routing_domain=management",
                "  route_allowed=false",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    parsed = helper._parse_wan_config(config_path)
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "NETWORKD_MGMT_CONFIG_PATH", tmp_path / "missing.network")
    monkeypatch.setattr(helper, "_run", fake_run)
    monkeypatch.setattr(helper.shutil, "which", lambda command: f"/usr/sbin/{command}" if command == "ip" else None)

    assert helper._apply_wan_target_routes(parsed) == 0
    assert ["ip", "route", "del", "default", "dev", "eth0"] not in commands


def test_wan_helper_gives_management_ownership_of_duplicate_vlan_network(monkeypatch, tmp_path):
    """Verify that wan helper gives management ownership of duplicate vlan network.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    config_path = tmp_path / "duplicate-management-vlan.conf"
    config_path.write_text(
        "\n".join(
            [
                "[targets]",
                "target=eth0",
                "  kind=physical",
                "  role=management",
                "  ip_cidr=192.168.1.10/24",
                "  ipv6_cidr=",
                "  routing_domain=management",
                "  route_allowed=false",
                "target=eth1.1",
                "  kind=vlan",
                "  role=access",
                "  ip_cidr=192.168.1.20/24",
                "  ipv6_cidr=",
                "  routing_domain=lab",
                "  route_allowed=true",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    parsed = helper._parse_wan_config(config_path)
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        commands.append(command)
        if command == ["ip", "route", "show", "default", "dev", "eth0"]:
            return subprocess.CompletedProcess(command, 0, "default via 192.168.1.1 dev eth0\n", "")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "_run", fake_run)
    monkeypatch.setattr(helper.shutil, "which", lambda command: f"/usr/sbin/{command}" if command == "ip" else None)

    assert helper._apply_wan_target_routes(parsed) == 0
    assert helper._apply_wan_policy_rules(parsed) == 0
    assert ["ip", "route", "replace", "192.168.1.0/24", "dev", "eth0", "table", "100"] in commands
    assert ["ip", "route", "replace", "192.168.1.0/24", "dev", "eth1.1", "table", "200"] not in commands
    assert ["ip", "route", "del", "192.168.1.0/24", "dev", "eth1.1", "table", "200"] in commands
    assert ["ip", "rule", "add", "from", "192.168.1.0/24", "table", "100", "priority", "1000"] in commands
    assert ["ip", "rule", "add", "from", "192.168.1.0/24", "table", "200", "priority", "2001"] not in commands


def test_staging_prepare_repairs_apply_directory_ownership(monkeypatch, tmp_path):
    """Verify that staging prepare repairs apply directory ownership.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    apply_root = tmp_path / "apply"
    config_path = apply_root / "wan" / "atlaso-wan.conf"
    chowned: list[tuple[Path, str, str]] = []
    chmodded: list[tuple[Path, int]] = []

    monkeypatch.setattr(helper, "ATLASO_APPLY_DIR", apply_root)
    monkeypatch.setattr(helper.shutil, "chown", lambda path, user, group: chowned.append((Path(path), user, group)))
    monkeypatch.setattr(helper.os, "chmod", lambda path, mode: chmodded.append((Path(path), mode)))

    assert helper.main(["atlaso-helper", "staging", "prepare", "--real", str(config_path)]) == 0

    assert config_path.parent.is_dir()
    assert (apply_root, "atlaso", "atlaso") in chowned
    assert (config_path.parent, "atlaso", "atlaso") in chowned
    assert (apply_root, 0o755) in chmodded
    assert (config_path.parent, 0o750) in chmodded


def test_esxi_pxe_helper_validates_and_writes_generated_kickstarts(monkeypatch, tmp_path):
    """Verify that esxi pxe helper validates and writes generated kickstarts.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    http_root = tmp_path / "pxe" / "http" / "esxi" / "ks"
    http_base = http_root.parent
    tftp_root = tmp_path / "pxe" / "tftp"
    ipxe_binary_dir = tmp_path / "usr" / "share" / "ipxe"
    iso_root = tmp_path / "vcf-depot" / "PROD" / "COMP" / "ESX_HOST"
    apply_dir = tmp_path / "apply" / "esxi-pxe"
    apply_dir.mkdir(parents=True)
    http_root.mkdir(parents=True)
    ipxe_binary_dir.mkdir(parents=True)
    iso_root.mkdir(parents=True)
    iso_tree = iso_root / "VMware-VMvisor-Installer-8.0U3.iso"
    (iso_tree / "efi" / "boot").mkdir(parents=True)
    (iso_tree / "boot.cfg").write_text(
        "title=ESXi\n"
        "kernel=/b.b00\n"
        "kernelopt=cdromBoot runweasel\n"
        "modules=/jumpstrt.gz---/useropts.gz\n",
        encoding="utf-8",
    )
    (iso_tree / "mboot.c32").write_bytes(b"mboot c32")
    (iso_tree / "efi" / "boot" / "bootx64.efi").write_bytes(b"mboot efi")
    (iso_tree / "efi" / "boot" / "crypto64.efi").write_bytes(b"crypto")
    (ipxe_binary_dir / "undionly.kpxe").write_bytes(b"bios ipxe")
    (ipxe_binary_dir / "snponly.efi").write_bytes(b"uefi ipxe")
    (ipxe_binary_dir / "pxelinux.0").write_bytes(b"pxelinux")
    (ipxe_binary_dir / "ldlinux.c32").write_bytes(b"ldlinux")
    (ipxe_binary_dir / "ldlinux.c32").write_bytes(b"ldlinux")
    (http_base / "boot.ipxe").write_text("old ipxe script", encoding="utf-8")
    (tftp_root / "bootx64.efi").parent.mkdir(parents=True, exist_ok=True)
    (tftp_root / "bootx64.efi").write_bytes(b"old uefi first stage")
    (tftp_root / "esxi.ipxe").write_text("old tftp script", encoding="utf-8")
    stale_mac = "01-aa-bb-cc-dd-ee-ff"
    (tftp_root / "pxelinux.cfg").mkdir(parents=True, exist_ok=True)
    (tftp_root / "pxelinux.cfg" / stale_mac).write_text("old pxelinux", encoding="utf-8")
    (tftp_root / stale_mac).mkdir(parents=True, exist_ok=True)
    (tftp_root / stale_mac / "boot.cfg").write_text("old tftp boot cfg", encoding="utf-8")
    (http_base / stale_mac).mkdir(parents=True, exist_ok=True)
    (http_base / stale_mac / "boot.cfg").write_text("old http boot cfg", encoding="utf-8")
    stale = http_root / "99.cfg"
    stale.write_text("old", encoding="utf-8")
    manifest = esxi_pxe_manifest(http_root, iso_root=iso_root)
    default_artifact = dict(manifest["artifacts"][0])
    default_artifact.update(
        {
            "host_id": None,
            "hostname": "Default / undefined MACs",
            "mac_address": "*",
            "mac_key": "default",
            "is_default": True,
            "kickstart_id": None,
            "kickstart_http_path": "",
            "kickstart_url": "",
            "pxelinux_config_path": str(tftp_root / "pxelinux.cfg" / "default"),
            "uefi_tftp_boot_cfg_path": str(tftp_root / "boot.cfg"),
            "http_boot_cfg_path": str(http_base / "boot.cfg"),
        }
    )
    manifest["artifacts"].append(default_artifact)
    manifest["boot"] = {
        "enabled": True,
        "hostname": "esxi-pxe.atlaso.internal",
        "listen_interface": "eth1",
        "listen_address": "192.168.50.1",
        "tftp_root": str(tftp_root),
        "bios_bootfile": "undionly.kpxe",
        "uefi_bootfile": "snponly.efi",
        "bios_second_stage_bootfile": "pxelinux.0",
        "uefi_second_stage_bootfile": "mboot.efi",
        "native_uefi_bootfile": "mboot.efi",
        "http_port": 8080,
        "http_base_url": "http://192.168.50.1:8080/pxe/esxi",
        "native_uefi_http_enabled": True,
        "effective_native_uefi_http_url": "http://192.168.50.1:8080/pxe/esxi/snponly.efi",
        "ipxe_script": "#!ipxe\necho Atlaso PXE ready\nshell\n",
    }
    config_path = apply_dir / "atlaso-esxi-pxe.json"
    config_path.write_text(json.dumps(manifest), encoding="utf-8")

    monkeypatch.setattr(helper, "ESXI_PXE_HTTP_ROOT", http_root)
    monkeypatch.setattr(helper, "ESXI_PXE_HTTP_BASE", http_base)
    monkeypatch.setattr(helper, "ESXI_PXE_IMAGE_HTTP_ROOT", http_base / "images")
    monkeypatch.setattr(helper, "ESXI_IPXE_HTTP_SCRIPT_PATH", http_base / "boot.ipxe")
    monkeypatch.setattr(helper, "ESXI_TFTP_ROOT", tftp_root)
    monkeypatch.setattr(helper, "PXE_BOOT_BINARY_DIRS", [ipxe_binary_dir])
    monkeypatch.setattr(helper, "ESXI_PXE_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "ESXI_INSTALLER_ISO_ROOT", iso_root)
    monkeypatch.setattr(helper, "ESXI_PXE_NGINX_SITE_PATH", tmp_path / "nginx" / "sites.d" / "esxi-pxe.conf")
    monkeypatch.setattr(helper, "_install_nginx_site", lambda path, text: (path.parent.mkdir(parents=True, exist_ok=True), path.write_text(text, encoding="utf-8"), 0)[2])

    payload = helper._load_esxi_pxe_manifest(helper._validate_esxi_pxe_config_path(str(config_path)))
    assert helper._esxi_pxe_manifest_errors(payload) == []
    assert helper._apply_esxi_pxe_manifest(payload) == 0
    generated_kickstart = Path(manifest["kickstarts"][0]["generated_path"])
    assert generated_kickstart.read_text(encoding="utf-8") == manifest["kickstarts"][0]["content"]
    assert (tftp_root / "undionly.kpxe").read_bytes() == b"bios ipxe"
    assert (tftp_root / "snponly.efi").read_bytes() == b"uefi ipxe"
    assert (http_base / "snponly.efi").read_bytes() == b"uefi ipxe"
    assert (tftp_root / "pxelinux.0").read_bytes() == b"pxelinux"
    assert (tftp_root / "ldlinux.c32").read_bytes() == b"ldlinux"
    assert (tftp_root / "mboot.efi").read_bytes() == b"mboot efi"
    assert (http_base / "mboot.efi").read_bytes() == b"mboot efi"
    assert (http_base / "boot.ipxe").read_text(encoding="utf-8") == "#!ipxe\necho Atlaso PXE ready\nshell\n"
    assert not (tftp_root / "bootx64.efi").exists()
    assert not (tftp_root / "esxi.ipxe").exists()
    assert not (tftp_root / "pxelinux.cfg" / stale_mac).exists()
    assert not (tftp_root / stale_mac / "boot.cfg").exists()
    assert not (http_base / stale_mac / "boot.cfg").exists()
    assert (tftp_root / "images" / manifest["artifacts"][0]["image_key"] / "mboot.c32").read_bytes() == b"mboot c32"
    assert (tftp_root / "01-00-50-56-aa-bb-cc" / "mboot.efi").read_bytes() == b"mboot efi"
    assert (tftp_root / "01-00-50-56-aa-bb-cc" / "crypto64.efi").read_bytes() == b"crypto"
    assert (http_base / "01-00-50-56-aa-bb-cc" / "mboot.efi").read_bytes() == b"mboot efi"
    assert (http_base / "01-00-50-56-aa-bb-cc" / "crypto64.efi").read_bytes() == b"crypto"
    boot_cfg = (tftp_root / "01-00-50-56-aa-bb-cc" / "boot.cfg").read_text(encoding="utf-8")
    http_boot_cfg = (http_base / "01-00-50-56-aa-bb-cc" / "boot.cfg").read_text(encoding="utf-8")
    assert f"prefix={manifest['artifacts'][0]['image_http_url']}" in boot_cfg
    assert http_boot_cfg == boot_cfg
    assert "kernel=b.b00" in boot_cfg
    assert f"kernelopt=runweasel ks={manifest['artifacts'][0]['kickstart_url']} BOOTIF=01-00-50-56-aa-bb-cc" in boot_cfg
    assert "modules=jumpstrt.gz---useropts.gz" in boot_cfg
    default_boot_cfg = (tftp_root / "boot.cfg").read_text(encoding="utf-8")
    assert "kernelopt=runweasel netdevice=vmnic0" in default_boot_cfg
    assert "ks=" not in default_boot_cfg
    assert "BOOTIF=" not in default_boot_cfg
    assert (http_base / "boot.cfg").read_text(encoding="utf-8") == default_boot_cfg
    pxelinux = (tftp_root / "pxelinux.cfg" / "01-00-50-56-aa-bb-cc").read_text(encoding="utf-8")
    assert "KERNEL images/" in pxelinux
    assert "IPAPPEND 2" in pxelinux
    nginx_site = (tmp_path / "nginx" / "sites.d" / "esxi-pxe.conf").read_text(encoding="utf-8")
    assert nginx_site.count("listen 8080;") == 1
    assert nginx_site.count("proxy_set_header Host $http_host;") == 4
    assert "proxy_set_header Host $host;" not in nginx_site
    assert "location /pxe/esxi/ks/" in nginx_site
    assert "proxy_pass http://127.0.0.1:8000;" in nginx_site
    assert f"alias {http_base}/;" in nginx_site
    assert not stale.exists()

    manifest["hosts"][0]["installer_iso_path"] = str(tmp_path / "escape.iso")
    assert any("installer ISO must be under" in error for error in helper._esxi_pxe_manifest_errors(manifest))


def test_esxi_pxe_helper_writes_http_ipxe_script_without_profiles(monkeypatch, tmp_path):
    """Verify that esxi pxe helper writes http ipxe script without profiles.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    http_root = tmp_path / "pxe" / "http" / "esxi" / "ks"
    http_base = http_root.parent
    tftp_root = tmp_path / "pxe" / "tftp"
    apply_dir = tmp_path / "apply" / "esxi-pxe"
    iso_root = tmp_path / "vcf-depot" / "PROD" / "COMP" / "ESX_HOST"
    ipxe_binary_dir = tmp_path / "bootloaders"
    http_root.mkdir(parents=True)
    apply_dir.mkdir(parents=True)
    iso_root.mkdir(parents=True)
    ipxe_binary_dir.mkdir(parents=True)
    (ipxe_binary_dir / "undionly.kpxe").write_bytes(b"bios ipxe")
    (ipxe_binary_dir / "snponly.efi").write_bytes(b"uefi ipxe")
    (ipxe_binary_dir / "pxelinux.0").write_bytes(b"pxelinux")
    (ipxe_binary_dir / "ldlinux.c32").write_bytes(b"ldlinux")
    manifest = {
        "kind": "atlaso-esxi-pxe",
        "schema_version": 2,
        "http_root": str(http_root),
        "http_base": str(http_base),
        "image_http_root": str(http_base / "images"),
        "installer_iso_root": str(iso_root),
        "installer_isos": [],
        "boot": {
            "enabled": True,
            "hostname": "esxi-pxe.atlaso.internal",
            "listen_interface": "eth1",
            "listen_address": "192.168.50.1",
            "tftp_root": str(tftp_root),
            "bios_bootfile": "undionly.kpxe",
            "uefi_bootfile": "snponly.efi",
            "bios_second_stage_bootfile": "pxelinux.0",
            "uefi_second_stage_bootfile": "mboot.efi",
            "native_uefi_bootfile": "mboot.efi",
            "http_port": 8080,
            "http_base_url": "http://192.168.50.1:8080/pxe/esxi",
            "native_uefi_http_enabled": True,
            "effective_native_uefi_http_url": "http://192.168.50.1:8080/pxe/esxi/snponly.efi",
            "ipxe_script": "#!ipxe\necho No profiles yet\nshell\n",
        },
        "kickstarts": [],
        "hosts": [],
        "artifacts": [],
    }
    config_path = apply_dir / "atlaso-esxi-pxe.json"
    config_path.write_text(json.dumps(manifest), encoding="utf-8")

    monkeypatch.setattr(helper, "ESXI_PXE_HTTP_ROOT", http_root)
    monkeypatch.setattr(helper, "ESXI_PXE_HTTP_BASE", http_base)
    monkeypatch.setattr(helper, "ESXI_PXE_IMAGE_HTTP_ROOT", http_base / "images")
    monkeypatch.setattr(helper, "ESXI_IPXE_HTTP_SCRIPT_PATH", http_base / "boot.ipxe")
    monkeypatch.setattr(helper, "ESXI_TFTP_ROOT", tftp_root)
    monkeypatch.setattr(helper, "PXE_BOOT_BINARY_DIRS", [ipxe_binary_dir])
    monkeypatch.setattr(helper, "ESXI_PXE_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "ESXI_INSTALLER_ISO_ROOT", iso_root)
    monkeypatch.setattr(helper, "ESXI_PXE_NGINX_SITE_PATH", tmp_path / "nginx" / "sites.d" / "esxi-pxe.conf")
    monkeypatch.setattr(helper, "_install_nginx_site", lambda path, text: (path.parent.mkdir(parents=True, exist_ok=True), path.write_text(text, encoding="utf-8"), 0)[2])

    payload = helper._load_esxi_pxe_manifest(helper._validate_esxi_pxe_config_path(str(config_path)))
    assert helper._esxi_pxe_manifest_errors(payload) == []
    assert helper._apply_esxi_pxe_manifest(payload) == 0

    assert (http_base / "boot.ipxe").read_text(encoding="utf-8") == "#!ipxe\necho No profiles yet\nshell\n"
    assert (tftp_root / "undionly.kpxe").read_bytes() == b"bios ipxe"
    assert (tftp_root / "snponly.efi").read_bytes() == b"uefi ipxe"
    assert (tftp_root / "pxelinux.0").read_bytes() == b"pxelinux"
    assert (tftp_root / "ldlinux.c32").read_bytes() == b"ldlinux"


def test_esxi_pxe_helper_does_not_copy_host_artifact_to_default_fallback(monkeypatch, tmp_path):
    """Verify that esxi pxe helper does not copy host artifact to default fallback.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    http_root = tmp_path / "pxe" / "http" / "esxi" / "ks"
    http_base = http_root.parent
    tftp_root = tmp_path / "pxe" / "tftp"
    apply_dir = tmp_path / "apply" / "esxi-pxe"
    iso_root = tmp_path / "vcf-depot" / "PROD" / "COMP" / "ESX_HOST"
    ipxe_binary_dir = tmp_path / "bootloaders"
    http_root.mkdir(parents=True)
    http_base.mkdir(parents=True, exist_ok=True)
    tftp_root.mkdir(parents=True)
    (tftp_root / "pxelinux.cfg").mkdir(parents=True)
    apply_dir.mkdir(parents=True)
    iso_root.mkdir(parents=True)
    ipxe_binary_dir.mkdir(parents=True)
    (ipxe_binary_dir / "undionly.kpxe").write_bytes(b"bios ipxe")
    (ipxe_binary_dir / "snponly.efi").write_bytes(b"uefi ipxe")
    (ipxe_binary_dir / "pxelinux.0").write_bytes(b"pxelinux")
    (ipxe_binary_dir / "ldlinux.c32").write_bytes(b"ldlinux")
    (tftp_root / "boot.cfg").write_text("stale default", encoding="utf-8")
    (http_base / "boot.cfg").write_text("stale default", encoding="utf-8")
    (tftp_root / "pxelinux.cfg" / "default").write_text("stale default", encoding="utf-8")
    iso_tree = iso_root / "VMware-VMvisor-Installer-8.0U3.iso"
    iso_tree.mkdir()
    (iso_tree / "boot.cfg").write_text(
        "kernel=b.b00\nkernelopt=runweasel\nmodules=jumpstrt.gz --- useropts.gz\n",
        encoding="utf-8",
    )
    (iso_tree / "mboot.c32").write_bytes(b"mboot c32")
    (iso_tree / "EFI" / "BOOT").mkdir(parents=True)
    (iso_tree / "EFI" / "BOOT" / "BOOTX64.EFI").write_bytes(b"mboot efi")
    manifest = esxi_pxe_manifest(http_root, iso_root=iso_root)
    manifest["boot"] = {
        "enabled": True,
        "hostname": "esxi-pxe.atlaso.internal",
        "listen_interface": "eth1",
        "listen_address": "192.168.50.1",
        "tftp_root": str(tftp_root),
        "bios_bootfile": "undionly.kpxe",
        "uefi_bootfile": "snponly.efi",
        "bios_second_stage_bootfile": "pxelinux.0",
        "uefi_second_stage_bootfile": "mboot.efi",
        "native_uefi_bootfile": "mboot.efi",
        "http_port": 8080,
        "http_base_url": "http://192.168.50.1:8080/pxe/esxi",
        "native_uefi_http_enabled": True,
        "effective_native_uefi_http_url": "http://192.168.50.1:8080/pxe/esxi/snponly.efi",
        "ipxe_script": "#!ipxe\necho Atlaso PXE ready\nshell\n",
    }
    config_path = apply_dir / "atlaso-esxi-pxe.json"
    config_path.write_text(json.dumps(manifest), encoding="utf-8")

    monkeypatch.setattr(helper, "ESXI_PXE_HTTP_ROOT", http_root)
    monkeypatch.setattr(helper, "ESXI_PXE_HTTP_BASE", http_base)
    monkeypatch.setattr(helper, "ESXI_PXE_IMAGE_HTTP_ROOT", http_base / "images")
    monkeypatch.setattr(helper, "ESXI_IPXE_HTTP_SCRIPT_PATH", http_base / "boot.ipxe")
    monkeypatch.setattr(helper, "ESXI_TFTP_ROOT", tftp_root)
    monkeypatch.setattr(helper, "PXE_BOOT_BINARY_DIRS", [ipxe_binary_dir])
    monkeypatch.setattr(helper, "ESXI_PXE_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "ESXI_INSTALLER_ISO_ROOT", iso_root)
    monkeypatch.setattr(helper, "ESXI_PXE_NGINX_SITE_PATH", tmp_path / "nginx" / "sites.d" / "esxi-pxe.conf")
    monkeypatch.setattr(helper, "_install_nginx_site", lambda path, text: (path.parent.mkdir(parents=True, exist_ok=True), path.write_text(text, encoding="utf-8"), 0)[2])

    payload = helper._load_esxi_pxe_manifest(helper._validate_esxi_pxe_config_path(str(config_path)))
    assert helper._esxi_pxe_manifest_errors(payload) == []
    assert helper._apply_esxi_pxe_manifest(payload) == 0

    assert not (tftp_root / "boot.cfg").exists()
    assert not (http_base / "boot.cfg").exists()
    assert not (tftp_root / "pxelinux.cfg" / "default").exists()
    host_boot_cfg = (tftp_root / "01-00-50-56-aa-bb-cc" / "boot.cfg").read_text(encoding="utf-8")
    assert "?mac=01-00-50-56-aa-bb-cc" in host_boot_cfg


def test_esxi_pxe_helper_rejects_disabled_kickstart_references(monkeypatch, tmp_path):
    """Verify that esxi pxe helper rejects disabled kickstart references.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    http_root = tmp_path / "pxe" / "http" / "esxi" / "ks"
    http_base = http_root.parent
    tftp_root = tmp_path / "pxe" / "tftp"
    iso_root = tmp_path / "vcf-depot" / "PROD" / "COMP" / "ESX_HOST"
    http_root.mkdir(parents=True)
    tftp_root.mkdir(parents=True)
    iso_root.mkdir(parents=True)
    iso_tree = iso_root / "VMware-VMvisor-Installer-8.0U3.iso"
    iso_tree.mkdir()

    monkeypatch.setattr(helper, "ESXI_PXE_HTTP_ROOT", http_root)
    monkeypatch.setattr(helper, "ESXI_PXE_HTTP_BASE", http_base)
    monkeypatch.setattr(helper, "ESXI_PXE_IMAGE_HTTP_ROOT", http_base / "images")
    monkeypatch.setattr(helper, "ESXI_TFTP_ROOT", tftp_root)
    monkeypatch.setattr(helper, "ESXI_INSTALLER_ISO_ROOT", iso_root)
    manifest = esxi_pxe_manifest(http_root, enabled=True, iso_root=iso_root)
    manifest["kickstarts"][0]["enabled"] = False
    manifest["hosts"][0]["kickstart_id"] = 7
    manifest["artifacts"][0]["kickstart_id"] = 7

    errors = helper._esxi_pxe_manifest_errors(manifest)

    assert any("references disabled or missing Kickstart 7" in error for error in errors)


def test_esxi_boot_cfg_rewrite_uses_http_prefix_and_kickstart():
    """Verify that esxi boot cfg rewrite uses http prefix and kickstart."""
    helper = load_helper_module()
    source = "\n".join(
        [
            "title=ESXi",
            "kernel=/b.b00",
            "kernelopt=cdromBoot runweasel systemMediaSize=max",
            "modules=jumpstrt.gz --- /useropts.gz --- /features.gz",
            "",
        ]
    )

    rendered = helper._render_esxi_boot_cfg(
        source,
        prefix_url="http://192.168.50.1:8080/pxe/esxi/images/esx-9",
        kickstart_url="http://192.168.50.1:8080/pxe/esxi/ks/7.cfg",
        bootif="BOOTIF=01-00-50-56-aa-bb-cc",
    )

    assert "prefix=http://192.168.50.1:8080/pxe/esxi/images/esx-9" in rendered
    assert "kernel=b.b00" in rendered
    assert "cdromBoot" not in rendered
    assert "kernelopt=runweasel systemMediaSize=max ks=http://192.168.50.1:8080/pxe/esxi/ks/7.cfg BOOTIF=01-00-50-56-aa-bb-cc" in rendered
    assert "modules=jumpstrt.gz---useropts.gz---features.gz" in rendered

    default_rendered = helper._render_esxi_boot_cfg(
        source,
        prefix_url="http://192.168.50.1:8080/pxe/esxi/images/esx-9",
        kickstart_url="http://192.168.50.1:8080/pxe/esxi/ks/7.cfg",
        fallback_netdevice="vmnic0",
    )

    assert "BOOTIF=" not in default_rendered
    assert "kernelopt=runweasel systemMediaSize=max ks=http://192.168.50.1:8080/pxe/esxi/ks/7.cfg netdevice=vmnic0" in default_rendered


def test_esxi_uefi_bootloader_must_come_from_iso_efi_boot(tmp_path):
    """Verify that esxi uefi bootloader must come from iso efi boot.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    image_root = tmp_path / "image"
    (image_root / "random").mkdir(parents=True)
    (image_root / "random" / "mboot.efi").write_bytes(b"wrong")

    assert helper._find_esxi_uefi_bootloader(image_root) is None

    (image_root / "EFI" / "BOOT").mkdir(parents=True)
    expected = image_root / "EFI" / "BOOT" / "BOOTX64.EFI"
    expected.write_bytes(b"right")

    assert helper._find_esxi_uefi_bootloader(image_root) == expected


def test_ca_helper_rejects_config_outside_apply_dir(tmp_path):
    """Verify that ca helper rejects config outside apply dir.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.


    Raises:
        AssertionError: If an expected invariant is not satisfied.
    """
    helper = load_helper_module()
    config_path = tmp_path / "atlaso-ca.json"
    config_path.write_text(ca_payload_text(tmp_path / "etc" / "atlaso"), encoding="utf-8")

    try:
        helper._validate_ca_config_path(str(config_path))
    except ValueError as exc:
        assert "CA config must be staged under" in str(exc)
    else:
        raise AssertionError("CA config outside apply directory should be rejected")


def test_ca_helper_validates_and_writes_managed_files(monkeypatch, tmp_path):
    """Verify that ca helper validates and writes managed files.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "ca"
    managed_root = tmp_path / "etc" / "atlaso"
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "atlaso-ca.json"
    config_path.write_text(ca_payload_text(managed_root), encoding="utf-8")

    monkeypatch.setattr(helper, "CA_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "CA_MANAGED_PATH_BASE", managed_root)
    monkeypatch.setattr(helper, "_ca_key_matches_certificate", lambda certificate_pem, private_key_pem: True)

    assert helper._handle_ca("validate", [str(config_path)]) == 0
    assert helper._handle_ca("apply", [str(config_path)]) == 0

    root_ca = managed_root / "ca" / "root-ca.pem"
    crl_path = managed_root / "ca" / "atlaso-ca.crl"
    key_path = managed_root / "kms" / "certs" / "kms.atlaso.internal.key"
    assert root_ca.read_text(encoding="utf-8").startswith("-----BEGIN CERTIFICATE-----")
    assert crl_path.read_text(encoding="utf-8").startswith("-----BEGIN X509 CRL-----")
    assert key_path.read_text(encoding="utf-8").startswith("-----BEGIN PRIVATE KEY-----")
    assert not config_path.exists()
    if os.name != "nt":
        assert oct(key_path.stat().st_mode & 0o777) == "0o600"


def test_ca_helper_preserves_slapd_access_when_rewriting_ldap_key(monkeypatch, tmp_path):
    """Verify that ca helper preserves slapd access when rewriting ldap key.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "ca"
    managed_root = tmp_path / "etc" / "atlaso"
    ldap_key_path = managed_root / "ldap" / "tls" / "server.key"
    apply_dir.mkdir(parents=True)
    payload = json.loads(ca_payload_text(managed_root))
    payload["certificates"][0]["key_path"] = str(ldap_key_path)
    config_path = apply_dir / "atlaso-ca.json"
    config_path.write_text(json.dumps(payload), encoding="utf-8")
    ownership: list[tuple[Path, str, str]] = []
    modes: list[tuple[Path, int]] = []
    real_chmod = helper.os.chmod

    def track_ldap_key_mode(path, mode, **kwargs):
        """Handle track ldap key mode.

        Args:
            path: Filesystem or URL path to read, validate, or update.
            mode: Operating mode selected for the workflow.
            **kwargs: Additional keyword arguments forwarded to the wrapped call.
        """
        real_chmod(path, mode, **kwargs)
        if Path(path) == ldap_key_path:
            modes.append((Path(path), mode))

    monkeypatch.setattr(helper, "CA_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "CA_MANAGED_PATH_BASE", managed_root)
    monkeypatch.setattr(helper, "LDAP_KEY_PATH", ldap_key_path)
    monkeypatch.setattr(helper, "_ldap_account_name", lambda: "ldap")
    monkeypatch.setattr(helper, "_ca_key_matches_certificate", lambda certificate_pem, private_key_pem: True)
    monkeypatch.setattr(helper.shutil, "chown", lambda path, *, user, group: ownership.append((Path(path), user, group)))
    monkeypatch.setattr(helper.os, "chmod", track_ldap_key_mode)

    assert helper._handle_ca("apply", [str(config_path)]) == 0

    assert ownership == [(ldap_key_path, "root", "ldap")]
    assert modes == [(ldap_key_path, 0o600), (ldap_key_path, 0o640)]


def test_ca_helper_preserves_ntpd_access_when_rewriting_nts_key(monkeypatch, tmp_path):
    """Verify that ca helper preserves ntpd access when rewriting nts key.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "ca"
    managed_root = tmp_path / "etc" / "atlaso"
    ntp_cert_dir = managed_root / "ntp" / "certs"
    ntp_key_path = ntp_cert_dir / "ntp.atlaso.internal.key"
    apply_dir.mkdir(parents=True)
    payload = json.loads(ca_payload_text(managed_root))
    payload["certificates"][0]["key_path"] = str(ntp_key_path)
    config_path = apply_dir / "atlaso-ca.json"
    config_path.write_text(json.dumps(payload), encoding="utf-8")
    ownership: list[tuple[Path, int, int]] = []
    modes: list[tuple[Path, int]] = []
    real_chmod = helper.os.chmod

    def track_nts_key_mode(path, mode, **kwargs):
        """Handle track nts key mode.

        Args:
            path: Filesystem or URL path to read, validate, or update.
            mode: Operating mode selected for the workflow.
            **kwargs: Additional keyword arguments forwarded to the wrapped call.
        """
        real_chmod(path, mode, **kwargs)
        if Path(path) == ntp_key_path:
            modes.append((Path(path), mode))

    monkeypatch.setattr(helper, "CA_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "CA_MANAGED_PATH_BASE", managed_root)
    monkeypatch.setattr(helper, "NTP_CERT_DIR", ntp_cert_dir)
    monkeypatch.setattr(helper, "_ca_key_matches_certificate", lambda certificate_pem, private_key_pem: True)
    monkeypatch.setattr(helper.grp, "getgrnam", lambda group: type("Group", (), {"gr_gid": 123})())
    monkeypatch.setattr(helper.os, "chown", lambda path, uid, gid: ownership.append((Path(path), uid, gid)), raising=False)
    monkeypatch.setattr(helper.os, "chmod", track_nts_key_mode)

    assert helper._handle_ca("apply", [str(config_path)]) == 0

    assert ownership == [(ntp_key_path, 0, 123)]
    assert modes == [(ntp_key_path, 0o600), (ntp_key_path, 0o640)]


def test_ca_helper_removes_stale_crl_when_publication_is_empty(monkeypatch, tmp_path):
    """Verify that ca helper removes stale crl when publication is empty.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "ca"
    managed_root = tmp_path / "etc" / "atlaso"
    apply_dir.mkdir(parents=True)
    payload = json.loads(ca_payload_text(managed_root))
    crl_path = managed_root / "ca" / "atlaso-ca.crl"
    crl_path.parent.mkdir(parents=True)
    crl_path.write_text("-----BEGIN X509 CRL-----\nstale\n-----END X509 CRL-----\n", encoding="utf-8")
    payload["root"]["crl_pem"] = ""
    config_path = apply_dir / "atlaso-ca.json"
    config_path.write_text(json.dumps(payload), encoding="utf-8")

    monkeypatch.setattr(helper, "CA_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "CA_MANAGED_PATH_BASE", managed_root)
    monkeypatch.setattr(helper, "_ca_key_matches_certificate", lambda certificate_pem, private_key_pem: True)

    assert helper._handle_ca("validate", [str(config_path)]) == 0
    assert helper._handle_ca("apply", [str(config_path)]) == 0
    assert not crl_path.exists()


def test_ca_helper_allows_csr_certificate_without_private_key(monkeypatch, tmp_path):
    """Verify that ca helper allows csr certificate without private key.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "ca"
    managed_root = tmp_path / "etc" / "atlaso"
    apply_dir.mkdir(parents=True)
    payload = json.loads(ca_payload_text(managed_root))
    payload["certificates"].append(
        {
            "common_name": "client-a.atlaso.internal",
            "managed_owner": "",
            "certificate_pem": "-----BEGIN CERTIFICATE-----\nclient\n-----END CERTIFICATE-----\n",
            "chain_pem": "-----BEGIN CERTIFICATE-----\nclient\n-----END CERTIFICATE-----\n",
            "private_key_pem": "",
            "cert_path": str(managed_root / "ca" / "client-a.crt"),
            "key_path": "",
            "chain_path": str(managed_root / "ca" / "client-a-chain.pem"),
        }
    )
    config_path = apply_dir / "atlaso-ca.json"
    config_path.write_text(json.dumps(payload), encoding="utf-8")

    monkeypatch.setattr(helper, "CA_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "CA_MANAGED_PATH_BASE", managed_root)
    monkeypatch.setattr(helper, "_ca_key_matches_certificate", lambda certificate_pem, private_key_pem: True)

    assert helper._handle_ca("validate", [str(config_path)]) == 0
    assert helper._handle_ca("apply", [str(config_path)]) == 0

    assert (managed_root / "ca" / "client-a.crt").read_text(encoding="utf-8").startswith("-----BEGIN CERTIFICATE-----")
    assert not (managed_root / "ca" / "client-a.key").exists()


def test_ca_helper_rejects_key_path_without_private_key(monkeypatch, tmp_path):
    """Verify that ca helper rejects key path without private key.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "ca"
    managed_root = tmp_path / "etc" / "atlaso"
    apply_dir.mkdir(parents=True)
    payload = json.loads(ca_payload_text(managed_root))
    payload["certificates"][0]["private_key_pem"] = ""
    config_path = apply_dir / "atlaso-ca.json"
    config_path.write_text(json.dumps(payload), encoding="utf-8")

    monkeypatch.setattr(helper, "CA_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "CA_MANAGED_PATH_BASE", managed_root)

    errors = helper._ca_payload_errors(config_path)

    assert "certificate kms.atlaso.internal key_path requires a private key." in errors


@pytest.mark.parametrize("action", ["validate", "apply"])
def test_ca_helper_removes_invalid_apply_payload(monkeypatch, tmp_path, capsys, action):
    """Verify that ca helper removes invalid apply payload.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        capsys: Pytest fixture used to capture standard output and standard error.
        action: Action supplied to the test scenario.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "ca"
    managed_root = tmp_path / "etc" / "atlaso"
    apply_dir.mkdir(parents=True)
    payload = json.loads(ca_payload_text(managed_root))
    payload["certificates"][0]["private_key_pem"] = ""
    config_path = apply_dir / "atlaso-ca.json"
    config_path.write_text(json.dumps(payload), encoding="utf-8")

    monkeypatch.setattr(helper, "CA_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "CA_MANAGED_PATH_BASE", managed_root)

    assert helper._handle_ca(action, [str(config_path)]) == 2
    assert "key_path requires a private key" in capsys.readouterr().err
    assert not config_path.exists()


def test_wan_helper_apply_routes_nat_and_netem(monkeypatch, tmp_path):
    """Verify that wan helper apply routes nat and netem.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "wan"
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "atlaso-wan.conf"
    config_path.write_text(wan_config_text(), encoding="utf-8")
    nat_dir = tmp_path / "nftables.d"
    service_path = tmp_path / "atlaso-nat.service"
    sysctl_path = tmp_path / "90-atlaso-routing-wan.conf"
    commands: list[list[str]] = []
    input_commands: list[tuple[list[str], str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    def fake_run_with_input(command: list[str], input_text: str) -> subprocess.CompletedProcess[str]:
        """Return fake run with input.

        Args:
            command: Command and arguments to execute.
            input_text: Text supplied to the invoked command through standard input.
        """
        input_commands.append((command, input_text))
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "WAN_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "WAN_NAT_CONFIG_DIR", nat_dir)
    monkeypatch.setattr(helper, "WAN_NAT_CONFIG_PATH", nat_dir / "atlaso-nat.nft")
    monkeypatch.setattr(helper, "WAN_NAT_SERVICE_PATH", service_path)
    monkeypatch.setattr(helper, "WAN_SYSCTL_PATH", sysctl_path)
    monkeypatch.setattr(helper.shutil, "which", lambda command: f"/usr/sbin/{command}")
    monkeypatch.setattr(helper, "_run", fake_run)
    monkeypatch.setattr(helper, "_run_with_input", fake_run_with_input)

    assert helper._handle_wan("apply", [str(config_path)]) == 0

    assert input_commands[0][0] == ["nft", "-c", "-f", "-"]
    assert 'oifname "eth1.20" masquerade' in input_commands[0][1]
    assert ["sysctl", "-w", "net.ipv4.ip_forward=1"] in commands
    assert ["nft", "-f", str(nat_dir / "atlaso-nat.nft")] in commands
    assert ["ip", "route", "replace", "192.168.20.0/24", "dev", "eth1.20", "table", "200"] in commands
    assert ["ip", "rule", "add", "from", "192.168.20.0/24", "table", "200", "priority", "2000"] in commands
    assert ["ip", "route", "replace", "10.20.0.0/24", "dev", "eth1.20", "metric", "120", "table", "200"] in commands
    assert ["tc", "qdisc", "replace", "dev", "eth1.20", "root", "netem", "delay", "100ms", "10ms", "loss", "0.5%", "rate", "100mbit"] in commands
    assert service_path.exists()
    assert sysctl_path.read_text(encoding="utf-8") == "net.ipv4.ip_forward = 1\n"


def test_automation_helper_gives_powershell_private_writable_xdg_home(monkeypatch, tmp_path):
    """Verify that automation helper gives powershell private writable xdg home.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    script_root = tmp_path / "scripts"
    run_root = tmp_path / "runs"
    script_root.mkdir()
    script_path = script_root / "job.ps1"
    script_path.write_text("Write-Output 'ok'\n", encoding="utf-8")
    commands: list[list[str]] = []
    wrapper_source = ""

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        nonlocal wrapper_source
        commands.append(command)
        wrapper_source = Path(command[-3]).read_text(encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "ok\n", "")

    monkeypatch.setattr(helper, "AUTOMATION_SCRIPT_DIR", script_root)
    monkeypatch.setattr(helper, "AUTOMATION_RUN_DIR", run_root)
    monkeypatch.setattr(helper, "_command_path", lambda command: "/usr/bin/pwsh" if command == "pwsh" else None)
    monkeypatch.setattr(helper.shutil, "which", lambda command: "/usr/bin/systemd-run" if command == "systemd-run" else None)
    monkeypatch.setattr(helper.pwd, "getpwnam", lambda _username: SimpleNamespace(pw_uid=1200, pw_gid=1200))
    monkeypatch.setattr(helper, "_chown_path", lambda *_args: None)
    monkeypatch.setattr(helper, "_run", fake_run)

    assert helper._handle_automation("run", [str(script_path), "powershell", "30", "--", "-Mode", "check"]) == 0
    assert len(commands) == 1
    command = commands[0]
    home_argument = next(argument for argument in command if argument.startswith("--setenv=HOME="))
    run_home = Path(home_argument.split("=", 2)[2])
    assert f"--setenv=XDG_CACHE_HOME={run_home / '.cache'}" in command
    assert f"--setenv=XDG_CONFIG_HOME={run_home / '.config'}" in command
    assert f"--setenv=XDG_DATA_HOME={run_home / '.local' / 'share'}" in command
    assert f"--property=ReadWritePaths={run_home}" in command
    assert f"--property=WorkingDirectory={run_home}" in command
    assert command[-4] == "/usr/bin/pwsh"
    assert Path(command[-3]).name == "atlaso-managed-script.ps1"
    assert command[-2:] == ["-Mode", "check"]
    assert "function global:Get-AtlasoVault" in wrapper_source
    assert str(script_path).replace("\\", "\\") in wrapper_source
    assert not run_home.exists()


def test_real_mutating_helper_action_escapes_service_mount_namespace(monkeypatch, tmp_path, capsys):
    """Verify that real mutating helper action escapes service mount namespace.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    helper = load_helper_module()
    config_path = tmp_path / "atlaso.conf"
    config_path.write_text("# staged dnsmasq config\n", encoding="utf-8")
    commands: list[list[str]] = []

    def fake_which(command: str) -> str | None:
        """Return fake which.

        Args:
            command: Command and arguments to execute.
        """
        return "/usr/bin/systemd-run" if command == "systemd-run" else None

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "child helper output\n", "")

    monkeypatch.setenv("ATLASO_HELPER_USE_SYSTEMD_RUN", "1")
    monkeypatch.delenv(helper.SYSTEMD_RUN_CHILD_ENV, raising=False)
    monkeypatch.setattr(helper.shutil, "which", fake_which)
    monkeypatch.setattr(helper, "_run", fake_run)
    monkeypatch.setattr(helper, "_handle_dnsmasq", lambda action, args: (_ for _ in ()).throw(AssertionError("handler should run in child")))

    assert helper.main(["atlaso-helper", "dnsmasq", "apply", "--real", str(config_path)]) == 0

    out = capsys.readouterr().out
    assert out == "child helper output\n"
    assert len(commands) == 1
    assert commands[0][:7] == [
        "/usr/bin/systemd-run",
        "--quiet",
        "--wait",
        "--pipe",
        "--collect",
        "--service-type=exec",
        f"--setenv={helper.SYSTEMD_RUN_CHILD_ENV}=1",
    ]
    assert commands[0][-4:] == ["dnsmasq", "apply", "--real", str(config_path)]


def test_powercli_helper_actions_receive_writable_root_configuration_environment(monkeypatch, tmp_path):
    """Verify that powercli helper actions receive writable root configuration environment.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    config_path = tmp_path / "atlaso-settings.json"
    config_path.write_text("{}\n", encoding="utf-8")
    commands: list[list[str]] = []

    monkeypatch.setattr(
        helper.shutil,
        "which",
        lambda command: "/usr/bin/systemd-run" if command == "systemd-run" else None,
    )
    monkeypatch.setattr(
        helper,
        "_run",
        lambda command: (
            commands.append(command)
            or subprocess.CompletedProcess(command, 0, "", "")
        ),
    )

    assert helper._run_real_action_with_systemd(
        "appliance-settings",
        "apply",
        [str(config_path)],
    ) == 0

    assert "--setenv=HOME=/root" in commands[0]
    assert "--setenv=XDG_CACHE_HOME=/root/.cache" in commands[0]
    assert "--setenv=XDG_CONFIG_HOME=/root/.config" in commands[0]
    assert "--setenv=XDG_DATA_HOME=/root/.local/share" in commands[0]
    helper_index = commands[0].index(str(Path(helper.__file__).resolve()))
    assert commands[0].index("--setenv=HOME=/root") < helper_index


def test_appliance_update_receives_writable_powershell_environment(monkeypatch, tmp_path):
    """Verify that appliance update receives writable powershell environment.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    config_path = tmp_path / "atlaso-update.json"
    config_path.write_text("{}\n", encoding="utf-8")
    powershell_home = tmp_path / "powershell"
    commands: list[list[str]] = []

    monkeypatch.setattr(helper, "ATLASO_POWERSHELL_HOME", powershell_home)
    monkeypatch.setattr(
        helper.shutil,
        "which",
        lambda command: "/usr/bin/systemd-run" if command == "systemd-run" else None,
    )
    monkeypatch.setattr(
        helper,
        "_run",
        lambda command: (
            commands.append(command)
            or subprocess.CompletedProcess(command, 0, "", "")
        ),
    )

    assert helper._run_real_action_with_systemd(
        "appliance-update",
        "check",
        [str(config_path)],
    ) == 0

    assert f"--property=WorkingDirectory={powershell_home}" in commands[0]
    assert f"--setenv=HOME={powershell_home}" in commands[0]
    assert f"--setenv=XDG_CACHE_HOME={powershell_home / '.cache'}" in commands[0]
    assert f"--setenv=XDG_CONFIG_HOME={powershell_home / '.config'}" in commands[0]
    assert f"--setenv=XDG_DATA_HOME={powershell_home / '.local' / 'share'}" in commands[0]
    assert "--setenv=HOME=/root" not in commands[0]
    assert powershell_home.is_dir()
    assert (powershell_home / ".cache").is_dir()


def test_network_helper_renders_systemd_networkd_files(tmp_path):
    """Verify that network helper renders systemd networkd files.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    config_path = tmp_path / "atlaso-network.conf"
    config_path.write_text(network_config_text(), encoding="utf-8")

    files, links, admin_down_links = helper._systemd_networkd_files(config_path)

    assert "00-atlaso-mgmt.network" in files
    assert "Name=eth0" in files["00-atlaso-mgmt.network"]
    assert "Name=eth*" not in files["00-atlaso-mgmt.network"]
    assert "Address=192.168.49.1/24" in files["00-atlaso-mgmt.network"]
    assert "[RoutingPolicyRule]" not in files["00-atlaso-mgmt.network"]
    assert "Table=100" not in files["00-atlaso-mgmt.network"]
    assert "10-atlaso-eth2.network" in files
    assert "VLAN=eth2.20" in files["10-atlaso-eth2.network"]
    assert "10-atlaso-eth2.20.netdev" in files
    assert "Id=20" in files["10-atlaso-eth2.20.netdev"]
    assert "10-atlaso-eth2.20.network" in files
    assert "Address=192.168.20.1/24" in files["10-atlaso-eth2.20.network"]
    assert links == ["eth2", "eth2.20"]
    assert admin_down_links == []


def test_network_helper_keeps_admin_down_physical_links_unmanaged(tmp_path):
    """Verify that network helper keeps admin down physical links unmanaged.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    config_path = tmp_path / "atlaso-network.conf"
    config_path.write_text(network_config_text(eth2_mode="access", eth2_admin_state="down", include_vlan=False), encoding="utf-8")

    files, links, admin_down_links = helper._systemd_networkd_files(config_path)

    assert "00-atlaso-mgmt.network" in files
    assert "10-atlaso-eth2.network" not in files
    assert links == []
    assert admin_down_links == ["eth2"]


def test_network_helper_installs_networkd_files_and_reconfigures_non_management(monkeypatch, tmp_path):
    """Verify that network helper installs networkd files and reconfigures non management.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    config_path = tmp_path / "atlaso-network.conf"
    config_path.write_text(network_config_text(), encoding="utf-8")
    networkd_dir = tmp_path / "systemd-network"
    networkd_dir.mkdir()
    old_managed = networkd_dir / "10-atlaso-old.network"
    old_managed.write_text("old", encoding="utf-8")
    old_default = networkd_dir / "99-dhcp-en.network"
    old_default.write_text("old default", encoding="utf-8")
    commands: list[list[str]] = []
    stdin_commands: list[tuple[list[str], str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    def fake_run_with_input(command: list[str], stdin_text: str) -> subprocess.CompletedProcess[str]:
        """Return fake run with input.

        Args:
            command: Command and arguments to execute.
            stdin_text: Stdin text supplied to the test scenario.
        """
        stdin_commands.append((command, stdin_text))
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "NETWORKD_CONFIG_DIR", networkd_dir)
    monkeypatch.setattr(helper, "NETWORKD_MGMT_CONFIG_PATH", networkd_dir / "00-atlaso-mgmt.network")
    monkeypatch.setattr(helper.shutil, "which", lambda command: "/usr/bin/networkctl" if command == "networkctl" else None)
    monkeypatch.setattr(helper, "_run", fake_run)
    monkeypatch.setattr(helper, "_link_exists", lambda name: True)

    returncode, installed, links, admin_down_links = helper._install_systemd_networkd_files(config_path)

    assert returncode == 0
    assert not old_managed.exists()
    assert not old_default.exists()
    assert (networkd_dir / "00-atlaso-mgmt.network").is_file()
    assert (networkd_dir / "10-atlaso-eth2.network").is_file()
    assert (networkd_dir / "10-atlaso-eth2.20.netdev").is_file()
    assert ["networkctl", "reload"] in commands
    assert ["networkctl", "reconfigure", "eth2"] in commands
    assert ["networkctl", "reconfigure", "eth2.20"] in commands
    assert ["networkctl", "reconfigure", "eth0"] not in commands
    assert any(path.endswith("00-atlaso-mgmt.network") for path in installed)
    assert links == ["eth2", "eth2.20"]
    assert admin_down_links == []


def test_network_helper_sets_admin_down_links_down_after_reload(monkeypatch, tmp_path):
    """Verify that network helper sets admin down links down after reload.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    config_path = tmp_path / "atlaso-network.conf"
    config_path.write_text(network_config_text(eth2_mode="access", eth2_admin_state="down", include_vlan=False), encoding="utf-8")
    networkd_dir = tmp_path / "systemd-network"
    networkd_dir.mkdir()
    commands: list[list[str]] = []

    def fake_which(command: str) -> str | None:
        """Return fake which.

        Args:
            command: Command and arguments to execute.
        """
        return f"/usr/bin/{command}" if command in {"networkctl", "ip"} else None

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "NETWORKD_CONFIG_DIR", networkd_dir)
    monkeypatch.setattr(helper, "NETWORKD_MGMT_CONFIG_PATH", networkd_dir / "00-atlaso-mgmt.network")
    monkeypatch.setattr(helper.shutil, "which", fake_which)
    monkeypatch.setattr(helper, "_run", fake_run)
    monkeypatch.setattr(helper, "_link_exists", lambda name: True)

    returncode, _installed, links, admin_down_links = helper._install_systemd_networkd_files(config_path)

    assert returncode == 0
    assert links == []
    assert admin_down_links == ["eth2"]
    assert ["ip", "link", "set", "dev", "eth2", "down"] in commands


def test_network_helper_sets_vlan_ip_after_link_up_and_flush(monkeypatch, tmp_path):
    """Verify that network helper sets vlan ip after link up and flush.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    config_path = tmp_path / "atlaso-network.conf"
    config_path.write_text(network_config_text(), encoding="utf-8")
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper.shutil, "which", lambda command: "/usr/sbin/ip" if command == "ip" else None)
    monkeypatch.setattr(helper, "_run", fake_run)

    assert helper._apply_vlan_interfaces(config_path) == 0

    assert ["ip", "link", "set", "dev", "eth2.20", "up"] in commands
    assert ["ip", "address", "flush", "dev", "eth2.20", "scope", "global"] in commands
    assert ["ip", "address", "replace", "192.168.20.1/24", "dev", "eth2.20"] in commands
    assert commands.index(["ip", "link", "set", "dev", "eth2.20", "up"]) < commands.index(
        ["ip", "address", "flush", "dev", "eth2.20", "scope", "global"]
    )
    assert commands.index(["ip", "address", "flush", "dev", "eth2.20", "scope", "global"]) < commands.index(
        ["ip", "address", "replace", "192.168.20.1/24", "dev", "eth2.20"]
    )


def test_network_helper_deletes_removed_vlan_links(monkeypatch, tmp_path):
    """Verify that network helper deletes removed vlan links.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    config_path = tmp_path / "atlaso-network.conf"
    config_path.write_text(network_config_text(include_vlan=False, include_removed_vlan=True), encoding="utf-8")
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        commands.append(command)
        if command[:5] == ["ip", "-j", "-d", "link", "show"]:
            return subprocess.CompletedProcess(command, 0, '[{"linkinfo":{"info_kind":"vlan"}}]', "")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper.shutil, "which", lambda command: "/usr/sbin/ip" if command == "ip" else None)
    monkeypatch.setattr(helper, "_run", fake_run)

    assert helper._apply_vlan_interfaces(config_path) == 0

    assert ["ip", "link", "show", "dev", "eth2.20"] in commands
    assert ["ip", "-j", "-d", "link", "show", "dev", "eth2.20"] in commands
    assert ["ip", "link", "delete", "dev", "eth2.20"] in commands


def test_network_helper_refuses_to_delete_non_vlan_link(monkeypatch, tmp_path):
    """Verify that network helper refuses to delete non vlan link.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    config_path = tmp_path / "atlaso-network.conf"
    config_path.write_text(network_config_text(include_vlan=False, include_removed_vlan=True), encoding="utf-8")

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        if command[:5] == ["ip", "-j", "-d", "link", "show"]:
            return subprocess.CompletedProcess(command, 0, '[{"linkinfo":{"info_kind":"dummy"}}]', "")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper.shutil, "which", lambda command: "/usr/sbin/ip" if command == "ip" else None)
    monkeypatch.setattr(helper, "_run", fake_run)

    assert helper._apply_vlan_interfaces(config_path) == 2


def test_kms_helper_rejects_config_outside_apply_dir(tmp_path):
    """Verify that kms helper rejects config outside apply dir.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    config_path = tmp_path / "server.json"
    config_path.write_text(kms_config_text(tmp_path), encoding="utf-8")

    assert helper._handle_kms("validate", [str(config_path)]) == 2


def test_kms_helper_validates_disabled_staged_config(monkeypatch, tmp_path):
    """Verify that kms helper validates disabled staged config.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "kms"
    state_dir = tmp_path / "state" / "kms"
    managed_root = tmp_path / "etc" / "atlaso"
    apply_dir.mkdir(parents=True)
    state_dir.mkdir(parents=True)
    config_path = apply_dir / "server.json"
    trust_path = apply_dir / "client-trust.pem"
    config_path.write_text(kms_config_text(managed_root, enabled=False, database_path=state_dir / "store.db"), encoding="utf-8")

    monkeypatch.setattr(helper, "KMS_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "KMS_STATE_DIR", state_dir)
    monkeypatch.setattr(helper, "KMS_CONFIG_DIR", managed_root / "kmip")
    monkeypatch.setattr(helper, "CA_MANAGED_PATH_BASE", managed_root)

    assert helper._handle_kms("validate", [str(config_path)]) == 0


@pytest.mark.parametrize(
    ("path", "value", "expected"),
    [
        (("schema_version",), True, "schema_version"),
        (("listen", "port"), "5696", "port must be an integer"),
        (("providers", 0, "name"), 42, "provider name"),
        (("interop_trace_path",), None, "trace path must be a string"),
    ],
)
def test_kms_helper_rejects_coerced_json_types(
    tmp_path,
    path,
    value,
    expected,
):
    """Verify that kms helper rejects coerced json types.

    Args:
        tmp_path: Filesystem path for the tmp.
        path: Filesystem or URL path to read, validate, or update.
        value: Value to process.
        expected: Expected supplied by the caller.
    """
    helper = load_helper_module()
    payload = json.loads(kms_config_text(tmp_path))
    target = payload
    for segment in path[:-1]:
        target = target[segment]
    target[path[-1]] = value
    config_path = tmp_path / "server.json"
    config_path.write_text(json.dumps(payload), encoding="utf-8")

    assert any(expected in error for error in helper._kms_config_errors(config_path))


def test_kms_helper_apply_installs_atlaso_kmip_service(monkeypatch, tmp_path):
    """Verify that kms helper apply installs atlaso kmip service.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "kms"
    state_dir = tmp_path / "state" / "kmip"
    log_dir = tmp_path / "log" / "kmip"
    managed_root = tmp_path / "etc" / "atlaso"
    service_path = tmp_path / "systemd" / "atlaso-kmip.service"
    appliance_env_path = managed_root / "atlaso.env"
    kms_credential_path = managed_root / "kmip" / "atlaso-secrets-key.cred"
    command_path = tmp_path / "venv" / "bin" / "atlaso-kmip"
    config_path = apply_dir / "server.json"
    trust_path = apply_dir / "client-trust.pem"
    cert_path = managed_root / "kmip" / "certs" / "kms.atlaso.internal.crt"
    key_path = managed_root / "kmip" / "certs" / "kms.atlaso.internal.key"
    client_path = managed_root / "kmip" / "clients" / "vcf.crt"
    ca_path = managed_root / "ca" / "root.crt"
    apply_dir.mkdir(parents=True)
    state_dir.mkdir(parents=True)
    cert_path.parent.mkdir(parents=True)
    client_path.parent.mkdir(parents=True)
    command_path.parent.mkdir(parents=True)
    ca_path.parent.mkdir(parents=True)
    cert_path.write_text("-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n", encoding="utf-8")
    key_path.write_text("-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n", encoding="utf-8")
    client_path.write_text("-----BEGIN CERTIFICATE-----\nclient\n-----END CERTIFICATE-----\n", encoding="utf-8")
    ca_path.write_text("-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----\n", encoding="utf-8")
    appliance_env_path.write_text(
        "ATLASO_SECRET_KEY=web-session-secret\n"
        "ATLASO_BOOTSTRAP_ADMIN_PASSWORD=bootstrap-secret\n"
        "ATLASO_SECRETS_KEY=kmip-kek-secret\n",
        encoding="utf-8",
    )
    command_path.write_text("#!/bin/sh\n", encoding="utf-8")
    config_path.write_text(kms_config_text(managed_root, database_path=state_dir / "store.db"), encoding="utf-8")
    trust_path.write_text("-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----\n", encoding="utf-8")
    commands: list[list[str]] = []
    credential_inputs: list[tuple[list[str], str]] = []
    ownership: list[tuple[Path, int, int]] = []

    def fake_run(command):
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    def fake_run_with_input(command, input_text):
        """Return fake run with input.

        Args:
            command: Command and arguments to execute.
            input_text: Text supplied to the invoked command through standard input.
        """
        credential_inputs.append((command, input_text))
        return subprocess.CompletedProcess(command, 0, "encrypted-machine-credential\n", "")

    monkeypatch.setattr(helper, "KMS_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "KMS_STATE_DIR", state_dir)
    monkeypatch.setattr(helper, "KMS_LOG_DIR", log_dir)
    monkeypatch.setattr(helper, "KMS_CONFIG_DIR", managed_root / "kmip")
    monkeypatch.setattr(helper, "KMS_CONFIG_PATH", managed_root / "kmip" / "server.json")
    monkeypatch.setattr(helper, "ATLASO_ENV_PATH", appliance_env_path)
    monkeypatch.setattr(helper, "KMS_CREDENTIAL_PATH", kms_credential_path)
    monkeypatch.setattr(helper, "KMS_SERVICE_PATH", service_path)
    monkeypatch.setattr(helper, "ATLASO_KMIP_VENV_PATH", command_path)
    monkeypatch.setattr(helper, "CA_MANAGED_PATH_BASE", managed_root)
    monkeypatch.setattr(helper, "_run", fake_run)
    monkeypatch.setattr(helper, "_run_with_input", fake_run_with_input)
    monkeypatch.setattr(helper, "_command_path", lambda name: Path("/usr/bin") / name)
    monkeypatch.setattr(helper.pwd, "getpwnam", lambda _name: SimpleNamespace(pw_uid=1001))
    monkeypatch.setattr(helper.grp, "getgrnam", lambda _name: SimpleNamespace(gr_gid=1002))
    monkeypatch.setattr(
        helper.os,
        "chown",
        lambda path, uid, gid: ownership.append((Path(path), uid, gid)),
        raising=False,
    )

    assert helper._handle_kms("apply", [str(config_path)]) == 0

    assert (managed_root / "kmip" / "server.json").is_file()
    runtime_trust_path = managed_root / "kmip" / "client-trust.pem"
    assert runtime_trust_path.read_text(encoding="utf-8").startswith("-----BEGIN CERTIFICATE-----")
    assert "PRIVATE KEY" not in runtime_trust_path.read_text(encoding="utf-8")
    service = service_path.read_text(encoding="utf-8")
    assert "User=atlaso-kmip" in service
    assert f"LoadCredentialEncrypted=atlaso-secrets-key:{kms_credential_path}" in service
    assert "Environment=ATLASO_SECRETS_KEY_FILE=%d/atlaso-secrets-key" in service
    assert str(appliance_env_path) not in service
    assert f"ExecStart={command_path} --config {managed_root / 'kmip' / 'server.json'}" in service
    assert "ProtectSystem=strict" in service
    assert "CapabilityBoundingSet=" in service
    assert "RestrictAddressFamilies=AF_INET AF_INET6" in service
    assert f"StandardOutput=append:{log_dir / 'server.log'}" in service
    assert (state_dir, 1001, 1002) in ownership
    assert (log_dir, 1001, 1002) in ownership
    assert (managed_root / "kmip", 0, 1002) in ownership
    assert (runtime_trust_path, 0, 1002) in ownership
    assert ["systemctl", "daemon-reload"] in commands
    assert ["systemctl", "disable", "--now", "atlaso-kms.service"] in commands
    assert ["systemctl", "enable", "atlaso-kmip.service"] in commands
    assert ["systemctl", "restart", "atlaso-kmip.service"] in commands
    assert credential_inputs == [
        (
            [str(Path("/usr/bin") / "systemd-creds"), "encrypt", "--name=atlaso-secrets-key", "-", "-"],
            "kmip-kek-secret",
        )
    ]
    credential_text = kms_credential_path.read_text(encoding="utf-8")
    assert credential_text == "encrypted-machine-credential\n"
    assert "kmip-kek-secret" not in credential_text
    assert "web-session-secret" not in credential_text
    assert "bootstrap-secret" not in credential_text
    if os.name != "nt":
        assert kms_credential_path.stat().st_mode & 0o777 == 0o600
        assert runtime_trust_path.stat().st_mode & 0o777 == 0o640


def test_kms_helper_rejects_symlinked_staged_public_trust_bundle(monkeypatch, tmp_path):
    """Verify staged vCenter trust cannot escape through a symbolic link.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "kms"
    state_dir = tmp_path / "state" / "kmip"
    managed_root = tmp_path / "etc" / "atlaso"
    config_path = apply_dir / "server.json"
    trust_target = tmp_path / "outside-trust.pem"
    trust_path = apply_dir / "client-trust.pem"
    cert_path = managed_root / "kmip" / "certs" / "kms.atlaso.internal.crt"
    key_path = managed_root / "kmip" / "certs" / "kms.atlaso.internal.key"
    client_path = managed_root / "kmip" / "clients" / "vcf.crt"
    for path, value in (
        (cert_path, "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n"),
        (key_path, "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n"),
        (client_path, "-----BEGIN CERTIFICATE-----\nclient\n-----END CERTIFICATE-----\n"),
        (trust_target, "-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----\n"),
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding="utf-8")
    apply_dir.mkdir(parents=True, exist_ok=True)
    state_dir.mkdir(parents=True, exist_ok=True)
    config_path.write_text(kms_config_text(managed_root, database_path=state_dir / "store.db"), encoding="utf-8")
    try:
        trust_path.symlink_to(trust_target)
    except OSError:
        pytest.skip("Symbolic link creation is unavailable on this test host.")

    monkeypatch.setattr(helper, "KMS_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "KMS_STATE_DIR", state_dir)
    monkeypatch.setattr(helper, "KMS_CONFIG_DIR", managed_root / "kmip")
    monkeypatch.setattr(helper, "CA_MANAGED_PATH_BASE", managed_root)

    errors = helper._kms_config_errors(config_path)
    assert any("regular file" in error for error in errors)


def test_kms_helper_rejects_symlinked_staged_config(monkeypatch, tmp_path):
    """Verify the fixed staged KMS configuration cannot be a symbolic link.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "kms"
    config_target = tmp_path / "outside-server.json"
    config_path = apply_dir / "server.json"
    apply_dir.mkdir(parents=True)
    config_target.write_text("{}", encoding="utf-8")
    try:
        config_path.symlink_to(config_target)
    except OSError:
        pytest.skip("Symbolic link creation is unavailable on this test host.")
    monkeypatch.setattr(helper, "KMS_APPLY_DIR", apply_dir)

    with pytest.raises(ValueError, match="symbolic links"):
        helper._validate_kms_config_path(str(config_path))


def test_kms_helper_status_returns_only_authenticated_redacted_counts(monkeypatch, tmp_path, capsys):
    """Verify the fixed status operation returns no credential or operational key IDs.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        capsys: Pytest fixture capturing standard output and error streams.
    """
    helper = load_helper_module()
    config_path = tmp_path / "server.json"
    credential_path = tmp_path / "atlaso-secrets-key.cred"
    command_path = tmp_path / "atlaso-kmip"
    config_path.write_text("{}", encoding="utf-8")
    credential_path.write_text("encrypted", encoding="utf-8")
    command_path.write_text("#!/bin/sh\n", encoding="utf-8")
    provider_id = "885841f9-0878-45c2-aee0-b72bc9fc643f"
    status_payload = {
        "status": "available",
        "runtime_state": "running",
        "store_status": "authenticated",
        "providers": {provider_id: {"pre_active": 1, "active": 2, "total": 3}},
    }

    monkeypatch.setattr(helper, "KMS_CONFIG_PATH", config_path)
    monkeypatch.setattr(helper, "KMS_CREDENTIAL_PATH", credential_path)
    monkeypatch.setattr(helper, "ATLASO_KMIP_VENV_PATH", command_path)
    monkeypatch.setattr(
        helper,
        "_run",
        lambda command: subprocess.CompletedProcess(command, 0, "protected-runtime-secret\n", ""),
    )
    monkeypatch.setattr(
        helper.subprocess,
        "run",
        lambda command, **kwargs: subprocess.CompletedProcess(command, 0, json.dumps(status_payload), ""),
    )

    assert helper._handle_kms("status", []) == 0
    output = capsys.readouterr().out
    assert json.loads(output) == status_payload
    assert "protected-runtime-secret" not in output
    assert "key_id" not in output


def test_kms_helper_status_fails_closed_when_store_material_cannot_be_authenticated(
    monkeypatch,
    tmp_path,
    capsys,
):
    """Verify missing runtime credentials never convert retained store state into zero counts.

    Args:
        monkeypatch: Pytest fixture used to replace fixed helper paths.
        tmp_path: Temporary directory provided for isolated runtime state.
        capsys: Pytest fixture capturing standard output and error streams.
    """
    helper = load_helper_module()
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    (state_dir / "store.db").write_bytes(b"retained-operational-store")
    monkeypatch.setattr(helper, "KMS_STATE_DIR", state_dir)
    monkeypatch.setattr(helper, "KMS_CONFIG_PATH", tmp_path / "missing-server.json")
    monkeypatch.setattr(helper, "KMS_CREDENTIAL_PATH", tmp_path / "missing-credential")

    assert helper._handle_kms("status", []) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "unavailable" in captured.err


def test_kms_helper_status_reports_empty_only_when_all_fixed_runtime_state_is_absent(
    monkeypatch,
    tmp_path,
    capsys,
):
    """Verify a clean fixed runtime path provides trustworthy empty-store evidence.

    Args:
        monkeypatch: Pytest fixture used to replace fixed helper paths.
        tmp_path: Temporary directory provided for isolated runtime state.
        capsys: Pytest fixture capturing standard output and error streams.
    """
    helper = load_helper_module()
    monkeypatch.setattr(helper, "KMS_STATE_DIR", tmp_path / "missing-state")
    monkeypatch.setattr(helper, "KMS_CONFIG_PATH", tmp_path / "missing-server.json")
    monkeypatch.setattr(helper, "KMS_CREDENTIAL_PATH", tmp_path / "missing-credential")

    assert helper._handle_kms("status", []) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["store_status"] == "empty"
    assert payload["providers"] == {}


def test_kms_helper_status_cli_requires_no_path_and_returns_only_status(monkeypatch, capsys):
    """Verify the fixed read-only CLI emits no helper action envelope.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        capsys: Pytest fixture capturing standard output and error streams.
    """
    helper = load_helper_module()
    status_payload = {
        "status": "available",
        "runtime_state": "running",
        "store_status": "authenticated",
        "providers": {},
    }

    def fake_status(action, args):
        """Return a fixed redacted status payload.

        Args:
            action: Helper action selected by the CLI.
            args: Validated positional arguments supplied to the helper action.

        Returns:
            Successful helper exit status.
        """
        assert action == "status"
        assert args == []
        print(json.dumps(status_payload))
        return 0

    monkeypatch.setattr(helper, "_handle_kms", fake_status)

    assert helper.main(["atlaso-helper", "kms", "status", "--real"]) == 0
    assert json.loads(capsys.readouterr().out) == status_payload


def test_kms_apply_reconciles_service_identity(
    monkeypatch,
    tmp_path,
):
    """Verify that KMS apply reconciles its constrained service identity.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    state_dir = tmp_path / "state" / "kmip"
    commands: list[list[str]] = []
    identity_created = {"group": False, "account": False}

    def fake_group(name):
        """Return fake group.

        Args:
            name: Stable name identifying the resource or operation.


        Raises:
            KeyError: If a required mapping entry is absent.
        """
        if name == helper.KMS_SERVICE_USER and identity_created["group"]:
            return SimpleNamespace(gr_gid=1002)
        raise KeyError(name)

    def fake_account(name):
        """Return fake account.

        Args:
            name: Stable name identifying the resource or operation.


        Raises:
            KeyError: If a required mapping entry is absent.
        """
        if name == helper.KMS_SERVICE_USER and identity_created["account"]:
            return SimpleNamespace(pw_uid=1001)
        raise KeyError(name)

    def fake_run(command):
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        commands.append(command)
        if command[0].endswith("groupadd"):
            identity_created["group"] = True
        if command[0].endswith("useradd"):
            identity_created["account"] = True
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "KMS_STATE_DIR", state_dir)
    monkeypatch.setattr(helper.grp, "getgrnam", fake_group)
    monkeypatch.setattr(helper.pwd, "getpwnam", fake_account)
    monkeypatch.setattr(
        helper,
        "_command_path",
        lambda name: f"/usr/sbin/{name}" if name in {"groupadd", "useradd"} else None,
    )
    monkeypatch.setattr(helper, "_run", fake_run)

    account, group = helper._ensure_kms_service_identity()

    assert account.pw_uid == 1001
    assert group.gr_gid == 1002
    assert ["/usr/sbin/groupadd", "--system", "atlaso-kmip"] in commands
    assert [
        "/usr/sbin/useradd",
        "--system",
        "--gid",
        "atlaso-kmip",
        "--home-dir",
        str(state_dir),
        "--shell",
        "/sbin/nologin",
        "atlaso-kmip",
    ] in commands


def test_dnsmasq_helper_validates_staged_config(monkeypatch, tmp_path):
    """Verify that dnsmasq helper validates staged config.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "dnsmasq"
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "atlaso.conf"
    config_path.write_text("domain=atlaso.internal\n", encoding="utf-8")
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "dnsmasq: syntax check OK.\n", "")

    monkeypatch.setattr(helper, "DNSMASQ_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper.shutil, "which", lambda command: "/usr/sbin/dnsmasq" if command == "dnsmasq" else None)
    monkeypatch.setattr(helper, "_run", fake_run)

    assert helper._handle_dnsmasq("validate", [str(config_path)]) == 0

    assert commands == [["/usr/sbin/dnsmasq", "--test", f"--conf-file={config_path}"]]


def test_dnsmasq_helper_rejects_missing_required_dhcp_upstream(monkeypatch, tmp_path, capsys):
    """Verify that dnsmasq helper rejects missing required dhcp upstream.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "dnsmasq"
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "atlaso.conf"
    config_path.write_text(
        "# atlaso-dhcp-upstream-required\nno-resolv\nserver=/atlaso.internal/127.0.0.1\nserver=fe80::53\n",
        encoding="utf-8",
    )
    commands: list[list[str]] = []

    monkeypatch.setattr(helper, "DNSMASQ_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "_run", lambda command: commands.append(command))

    assert helper._handle_dnsmasq("validate", [str(config_path)]) == 2
    assert "requires a usable management DHCP upstream server" in capsys.readouterr().err
    assert commands == []


def test_dnsmasq_helper_accepts_rendered_required_dhcp_upstream(monkeypatch, tmp_path):
    """Verify that dnsmasq helper accepts rendered required dhcp upstream.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "dnsmasq"
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "atlaso.conf"
    config_path.write_text(
        "# atlaso-dhcp-upstream-required\nno-resolv\nserver=192.168.167.2\n",
        encoding="utf-8",
    )
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "dnsmasq: syntax check OK.\n", "")

    monkeypatch.setattr(helper, "DNSMASQ_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper.shutil, "which", lambda command: "/usr/sbin/dnsmasq" if command == "dnsmasq" else None)
    monkeypatch.setattr(helper, "_run", fake_run)

    assert helper._handle_dnsmasq("validate", [str(config_path)]) == 0
    assert commands == [["/usr/sbin/dnsmasq", "--test", f"--conf-file={config_path}"]]


def test_networkd_dhcp_dns_reads_only_requested_interface_lease(monkeypatch, tmp_path):
    """Verify that networkd dhcp dns reads only requested interface lease.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    interface_dir = tmp_path / "sys" / "class" / "net"
    lease_dir = tmp_path / "run" / "systemd" / "netif" / "leases"
    (interface_dir / "eth0").mkdir(parents=True)
    lease_dir.mkdir(parents=True)
    (interface_dir / "eth0" / "ifindex").write_text("2\n", encoding="utf-8")
    (lease_dir / "2").write_text(
        "ADDRESS=192.168.167.251\n"
        "DNS=127.0.0.1 192.168.167.2 malformed 192.168.167.2 ::1 fe80::53 2001:4860:4860::8888\n",
        encoding="utf-8",
    )
    (lease_dir / "3").write_text("DNS=192.168.99.99\n", encoding="utf-8")
    monkeypatch.setattr(helper, "SYSTEMD_NETWORK_INTERFACE_DIR", interface_dir)
    monkeypatch.setattr(helper, "SYSTEMD_NETWORK_LEASE_DIR", lease_dir)

    payload = helper._networkd_dhcp_dns_payload("eth0")

    assert payload == {
        "interface": "eth0",
        "ifindex": 2,
        "servers": ["192.168.167.2", "2001:4860:4860::8888"],
    }
    assert "192.168.99.99" not in payload["servers"]


def test_dnsmasq_helper_prepares_dnssec_trust_anchors(monkeypatch, tmp_path):
    """Verify that dnsmasq helper prepares dnssec trust anchors.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "dnsmasq"
    anchor_source = tmp_path / "usr" / "share" / "dnsmasq" / "trust-anchors.conf"
    apply_dir.mkdir(parents=True)
    anchor_source.parent.mkdir(parents=True)
    anchor_source.write_text("trust-anchor=.,20326,8,2,abc\n", encoding="utf-8")
    config_path = apply_dir / "atlaso.conf"
    anchor_target = apply_dir / "atlaso-trust-anchors.conf"
    config_path.write_text(f"dnssec\nconf-file={anchor_target}\n", encoding="utf-8")
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        commands.append(command)
        if command == ["/usr/sbin/dnsmasq", "--version"]:
            return subprocess.CompletedProcess(command, 0, "Compile time options: DNSSEC\n", "")
        return subprocess.CompletedProcess(command, 0, "dnsmasq: syntax check OK.\n", "")

    monkeypatch.setattr(helper, "DNSMASQ_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "DNSMASQ_DNSSEC_TRUST_ANCHORS_PATH", anchor_target)
    monkeypatch.setattr(helper, "DNSMASQ_DNSSEC_TRUST_ANCHOR_CANDIDATES", [anchor_source])
    monkeypatch.setattr(helper.shutil, "which", lambda command: "/usr/sbin/dnsmasq" if command == "dnsmasq" else None)
    monkeypatch.setattr(helper, "_run", fake_run)

    assert helper._handle_dnsmasq("validate", [str(config_path)]) == 0

    assert anchor_target.read_text(encoding="utf-8") == "trust-anchor=.,20326,8,2,abc\n"
    assert commands == [
        ["/usr/sbin/dnsmasq", "--version"],
        ["/usr/sbin/dnsmasq", "--test", f"--conf-file={config_path}"],
    ]


def test_dnsmasq_helper_rejects_dnssec_when_package_lacks_support(monkeypatch, tmp_path, capsys):
    """Verify that dnsmasq helper rejects dnssec when package lacks support.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "dnsmasq"
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "atlaso.conf"
    config_path.write_text("dnssec\n", encoding="utf-8")

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        return subprocess.CompletedProcess(command, 0, "Compile time options: no-DNSSEC\n", "")

    monkeypatch.setattr(helper, "DNSMASQ_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper.shutil, "which", lambda command: "/usr/sbin/dnsmasq" if command == "dnsmasq" else None)
    monkeypatch.setattr(helper, "_run", fake_run)

    assert helper._handle_dnsmasq("validate", [str(config_path)]) == 2
    captured = capsys.readouterr()
    assert "DNSSEC validation is enabled" in captured.err
    assert "no-DNSSEC" in captured.err


def test_dnsmasq_helper_apply_installs_config_dropin_and_enables_service(monkeypatch, tmp_path):
    """Verify that dnsmasq helper apply installs config dropin and enables service.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "dnsmasq"
    state_dir = tmp_path / "var" / "lib" / "atlaso" / "dnsmasq"
    config_dir = tmp_path / "etc" / "atlaso" / "dnsmasq.d"
    dropin_dir = tmp_path / "etc" / "systemd" / "system" / "dnsmasq.service.d"
    networkd_dir = tmp_path / "etc" / "systemd" / "network"
    apply_dir.mkdir(parents=True)
    networkd_dir.mkdir(parents=True)
    mgmt_network = networkd_dir / "00-atlaso-mgmt.network"
    mgmt_network.write_text(
        "\n".join(
            [
                "[Match]",
                "Name=eth0",
                "",
                "[Network]",
                "Address=192.168.49.1/24",
                "Gateway=192.168.49.254",
                "DNS=1.1.1.1",
                "DNS=9.9.9.9",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    config_path = apply_dir / "atlaso.conf"
    config_path.write_text("domain=atlaso.internal\n", encoding="utf-8")
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "DNSMASQ_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "DNSMASQ_STATE_DIR", state_dir)
    monkeypatch.setattr(helper, "DNSMASQ_CONFIG_DIR", config_dir)
    monkeypatch.setattr(helper, "DNSMASQ_CONFIG_PATH", config_dir / "atlaso.conf")
    monkeypatch.setattr(helper, "DNSMASQ_SERVICE_DROPIN_DIR", dropin_dir)
    monkeypatch.setattr(helper, "DNSMASQ_SERVICE_DROPIN_PATH", dropin_dir / "atlaso.conf")
    monkeypatch.setattr(helper, "NETWORKD_MGMT_CONFIG_PATH", mgmt_network)
    monkeypatch.setattr(helper.shutil, "which", lambda command: "/usr/sbin/dnsmasq" if command == "dnsmasq" else None)
    monkeypatch.setattr(helper, "_run", fake_run)

    assert helper._handle_dnsmasq("apply", [str(config_path)]) == 0

    assert (config_dir / "atlaso.conf").read_text(encoding="utf-8") == "domain=atlaso.internal\n"
    dropin = (dropin_dir / "atlaso.conf").read_text(encoding="utf-8")
    assert "ExecStart=" in dropin
    assert f"--conf-file={config_dir / 'atlaso.conf'}" in dropin
    assert ["/usr/sbin/dnsmasq", "--test", f"--conf-file={config_path}"] in commands
    assert ["systemctl", "daemon-reload"] in commands
    assert ["systemctl", "enable", "dnsmasq"] in commands
    assert ["systemctl", "reload-or-restart", "dnsmasq"] in commands
    assert ["resolvectl", "dns", "eth0", "127.0.0.1"] not in commands
    assert ["resolvectl", "domain", "eth0", "~."] not in commands
    assert "DNS=1.1.1.1" in mgmt_network.read_text(encoding="utf-8")
    assert "DNS=127.0.0.1" not in mgmt_network.read_text(encoding="utf-8")
    assert "Domains=~." not in mgmt_network.read_text(encoding="utf-8")


def test_dnsmasq_helper_apply_creates_allowlisted_tftp_root(monkeypatch, tmp_path):
    """Verify that dnsmasq helper apply creates allowlisted tftp root.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "dnsmasq"
    state_dir = tmp_path / "var" / "lib" / "atlaso" / "dnsmasq"
    config_dir = tmp_path / "etc" / "atlaso" / "dnsmasq.d"
    dropin_dir = tmp_path / "etc" / "systemd" / "system" / "dnsmasq.service.d"
    tftp_root = tmp_path / "var" / "lib" / "atlaso" / "pxe" / "tftp"
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "atlaso.conf"
    config_path.write_text(f"enable-tftp\ntftp-root={tftp_root}\n", encoding="utf-8")
    commands: list[list[str]] = []
    chowned: list[Path] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "DNSMASQ_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "DNSMASQ_STATE_DIR", state_dir)
    monkeypatch.setattr(helper, "DNSMASQ_CONFIG_DIR", config_dir)
    monkeypatch.setattr(helper, "DNSMASQ_CONFIG_PATH", config_dir / "atlaso.conf")
    monkeypatch.setattr(helper, "DNSMASQ_SERVICE_DROPIN_DIR", dropin_dir)
    monkeypatch.setattr(helper, "DNSMASQ_SERVICE_DROPIN_PATH", dropin_dir / "atlaso.conf")
    monkeypatch.setattr(helper, "ESXI_TFTP_ROOT", tftp_root)
    monkeypatch.setattr(helper.shutil, "which", lambda command: "/usr/sbin/dnsmasq" if command == "dnsmasq" else None)
    monkeypatch.setattr(helper.shutil, "chown", lambda path, user, group: chowned.append(Path(path)))
    monkeypatch.setattr(helper, "_run", fake_run)

    assert helper._handle_dnsmasq("apply", [str(config_path)]) == 0

    assert tftp_root.is_dir()
    assert chowned == [tftp_root]
    assert ["systemctl", "reload-or-restart", "dnsmasq"] in commands


def test_dnsmasq_helper_apply_rejects_unexpected_tftp_root(monkeypatch, tmp_path, capsys):
    """Verify that dnsmasq helper apply rejects unexpected tftp root.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "dnsmasq"
    allowed_root = tmp_path / "var" / "lib" / "atlaso" / "pxe" / "tftp"
    unexpected_root = tmp_path / "tmp" / "not-atlaso"
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "atlaso.conf"
    config_path.write_text(f"enable-tftp\ntftp-root={unexpected_root}\n", encoding="utf-8")
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "DNSMASQ_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "ESXI_TFTP_ROOT", allowed_root)
    monkeypatch.setattr(helper.shutil, "which", lambda command: "/usr/sbin/dnsmasq" if command == "dnsmasq" else None)
    monkeypatch.setattr(helper, "_run", fake_run)

    assert helper._handle_dnsmasq("apply", [str(config_path)]) == 2

    captured = capsys.readouterr()
    assert f"dnsmasq TFTP root must be {allowed_root}" in captured.err
    assert not unexpected_root.exists()
    assert ["systemctl", "reload-or-restart", "dnsmasq"] not in commands


def test_dnsmasq_helper_reload_restarts_service(monkeypatch):
    """Verify that dnsmasq helper reload restarts service.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    helper = load_helper_module()
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "_run", fake_run)

    assert helper._handle_dnsmasq("reload", []) == 0

    assert commands == [
        ["systemctl", "daemon-reload"],
        ["systemctl", "reload-or-restart", "dnsmasq"],
    ]


def test_dnsmasq_helper_reads_allowlisted_lease_file(monkeypatch, tmp_path, capsys):
    """Verify that dnsmasq helper reads allowlisted lease file.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    helper = load_helper_module()
    state_dir = tmp_path / "var" / "lib" / "atlaso" / "dnsmasq"
    state_dir.mkdir(parents=True)
    lease_file = state_dir / "dhcp.leases"
    lease_file.write_text("1893456000 02:15:5d:00:20:30 192.168.50.130 api-client *\n", encoding="utf-8")

    monkeypatch.setattr(helper, "DNSMASQ_STATE_DIR", state_dir)
    monkeypatch.setattr(helper, "DNSMASQ_LEASE_FILE_PATH", lease_file)

    assert helper._handle_dnsmasq("leases", []) == 0
    captured = capsys.readouterr()
    assert "api-client" in captured.out
    assert captured.err == ""


def test_dnsmasq_helper_missing_lease_file_is_empty_success(monkeypatch, tmp_path, capsys):
    """Verify that dnsmasq helper missing lease file is empty success.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    helper = load_helper_module()
    state_dir = tmp_path / "var" / "lib" / "atlaso" / "dnsmasq"
    state_dir.mkdir(parents=True)

    monkeypatch.setattr(helper, "DNSMASQ_STATE_DIR", state_dir)
    monkeypatch.setattr(helper, "DNSMASQ_LEASE_FILE_PATH", state_dir / "dhcp.leases")

    assert helper._handle_dnsmasq("leases", []) == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_dnsmasq_helper_rejects_lease_paths_outside_allowlisted_state(monkeypatch, tmp_path, capsys):
    """Verify that dnsmasq helper rejects lease paths outside allowlisted state.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    helper = load_helper_module()
    state_dir = tmp_path / "var" / "lib" / "atlaso" / "dnsmasq"
    outside_file = tmp_path / "elsewhere" / "dhcp.leases"
    state_dir.mkdir(parents=True)
    outside_file.parent.mkdir(parents=True)
    outside_file.write_text("1893456000 02:15:5d:00:20:30 192.168.50.130 api-client *\n", encoding="utf-8")

    monkeypatch.setattr(helper, "DNSMASQ_STATE_DIR", state_dir)
    monkeypatch.setattr(helper, "DNSMASQ_LEASE_FILE_PATH", outside_file)

    assert helper._handle_dnsmasq("leases", []) == 2
    captured = capsys.readouterr()
    assert "dnsmasq lease file must stay under" in captured.err


def local_users_json(*, username: str = "sync-user", enabled: bool = True, password: str | None = "BridgeStrong1!") -> str:
    """Return local users json.

    Args:
        username: Account name used for authentication or lookup.
        enabled: Whether the requested behavior is enabled.
        password: Password supplied for the immediate authenticated operation.
    """
    row = {
        "username": username,
        "role": "viewer",
        "enabled": enabled,
        "home": f"/var/lib/atlaso/users/{username}",
        "shell": "/sbin/nologin",
        "password_pending": bool(password),
        "password_pending_since": "2026-06-23T12:00:00+00:00" if password else "",
    }
    if password:
        row["password"] = password
    return json.dumps({"managed_by": "Atlaso", "version": 1, "scope": "Photon OS local users", "users": [row]})


def test_local_users_helper_validates_staged_config(monkeypatch, tmp_path, capsys):
    """Verify that local users helper validates staged config.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "local-users"
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "atlaso-users.json"
    config_path.write_text(local_users_json(), encoding="utf-8")

    monkeypatch.setattr(helper, "LOCAL_USERS_APPLY_DIR", apply_dir)

    assert helper._handle_local_users("validate", [str(config_path)]) == 0
    captured = capsys.readouterr()
    assert '"local_users": "validation ok"' in captured.out
    assert '"passwords_pending": 1' in captured.out
    assert "BridgeStrong1!" not in captured.out


def test_local_users_helper_rejects_reserved_username(monkeypatch, tmp_path, capsys):
    """Verify that local users helper rejects reserved username.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "local-users"
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "atlaso-users.json"
    config_path.write_text(local_users_json(username="root"), encoding="utf-8")

    monkeypatch.setattr(helper, "LOCAL_USERS_APPLY_DIR", apply_dir)

    assert helper._handle_local_users("validate", [str(config_path)]) == 2
    captured = capsys.readouterr()
    assert "local user root is reserved" in captured.err


@pytest.mark.parametrize("action", ["validate", "apply"])
def test_local_users_helper_removes_invalid_apply_payload(monkeypatch, tmp_path, capsys, action):
    """Verify that local users helper removes invalid apply payload.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        capsys: Pytest fixture used to capture standard output and standard error.
        action: Action supplied to the test scenario.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "local-users"
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "atlaso-users.json"
    config_path.write_text(local_users_json(username="root"), encoding="utf-8")

    monkeypatch.setattr(helper, "LOCAL_USERS_APPLY_DIR", apply_dir)

    assert helper._handle_local_users(action, [str(config_path)]) == 2
    assert "local user root is reserved" in capsys.readouterr().err
    assert not config_path.exists()


def test_local_users_helper_creates_deletes_and_sets_password_without_leaking(monkeypatch, tmp_path, capsys):
    """Verify that local users helper creates deletes and sets password without leaking.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "local-users"
    home_base = tmp_path / "users"
    pwquality_path = tmp_path / "etc" / "security" / "pwquality.conf"
    pam_path = tmp_path / "etc" / "pam.d" / "system-password"
    pam_path.parent.mkdir(parents=True)
    pam_path.write_text("password  required    pam_unix.so       sha512 shadow use_authtok\n", encoding="utf-8")
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "atlaso-users.json"
    payload = json.loads(local_users_json())
    payload["users"][0]["home"] = (home_base / "sync-user").as_posix()
    payload["users"].append(
        {
            "username": "disabled-user",
            "role": "viewer",
            "enabled": False,
            "home": (home_base / "disabled-user").as_posix(),
            "shell": "/sbin/nologin",
            "password_pending": False,
            "password_pending_since": "",
        }
    )
    config_path.write_text(json.dumps(payload), encoding="utf-8")
    commands: list[list[str]] = []
    stdin_values: list[str] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        commands.append(command)
        if command == ["id", "sync-user"]:
            return subprocess.CompletedProcess(command, 1, "", "")
        return subprocess.CompletedProcess(command, 0, "", "")

    def fake_run_with_input(command: list[str], input_text: str) -> subprocess.CompletedProcess[str]:
        """Return fake run with input.

        Args:
            command: Command and arguments to execute.
            input_text: Text supplied to the invoked command through standard input.
        """
        commands.append(command)
        stdin_values.append(input_text)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "LOCAL_USERS_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "LOCAL_USERS_HOME_BASE", home_base)
    monkeypatch.setattr(helper, "LOCAL_USERS_PWQUALITY_PATH", pwquality_path)
    monkeypatch.setattr(helper, "LOCAL_USERS_SYSTEM_PASSWORD_PAM_PATH", pam_path)
    monkeypatch.setattr(helper, "_command_path", lambda command: command)
    monkeypatch.setattr(helper, "_run", fake_run)
    monkeypatch.setattr(helper, "_run_with_input", fake_run_with_input)

    assert helper._handle_local_users("apply", [str(config_path)]) == 0
    captured = capsys.readouterr()

    assert ["useradd", "--home-dir", (home_base / "sync-user").as_posix(), "--create-home", "--shell", "/sbin/nologin", "sync-user"] in commands
    assert ["usermod", "--shell", "/sbin/nologin", "sync-user"] in commands
    assert ["passwd", "-u", "sync-user"] in commands
    assert ["userdel", "-r", "disabled-user"] in commands
    assert ["passwd", "-l", "disabled-user"] not in commands
    assert stdin_values == ["sync-user:BridgeStrong1!\n"]
    assert all("BridgeStrong1!" not in arg for command in commands for arg in command)
    assert "BridgeStrong1!" not in captured.out
    assert "BridgeStrong1!" not in captured.err
    assert "pam_pwquality.so" in pam_path.read_text(encoding="utf-8")
    assert "minlen = 12" in pwquality_path.read_text(encoding="utf-8")
    assert not config_path.exists()


def test_local_users_helper_authenticates_shadow_password_without_leaking(monkeypatch, capsys):
    """Verify that local users helper authenticates shadow password without leaking.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    helper = load_helper_module()

    class FakeCrypt:
        """Represent fake crypt.

        Attributes:
            argtypes: Argtypes captured or supplied by this test helper.
            restype: Restype captured or supplied by this test helper.
        """
        argtypes = None
        restype = None

        def __call__(self, password: bytes, password_hash: bytes) -> bytes:
            """Return call.

            Args:
                password: Password supplied for the immediate authenticated operation.
                password_hash: Password hash supplied by the caller.
            """
            return password_hash if password == b"Depot-user1!" else b"$6$not-a-match"

    class FakeCryptLibrary:
        """Represent fake crypt library.

        Attributes:
            crypt: Crypt captured or supplied by this test helper.
        """
        crypt = FakeCrypt()

    monkeypatch.setattr(helper, "_shadow_hash_for_user", lambda username: "$6$rounds=5000$valid-hash")
    monkeypatch.setattr(helper.ctypes.util, "find_library", lambda name: "libcrypt.so.1")
    monkeypatch.setattr(helper.ctypes, "CDLL", lambda name: FakeCryptLibrary())

    monkeypatch.setattr(helper.sys, "stdin", io.StringIO("Depot-user1!\n"))
    assert helper.main(["atlaso-helper", "local-users", "authenticate", "--real", "vcf-depot"]) == 0
    valid_output = capsys.readouterr()
    assert "Depot-user1!" not in valid_output.out
    assert "valid-hash" not in valid_output.out

    monkeypatch.setattr(helper.sys, "stdin", io.StringIO("wrong-password\n"))
    assert helper.main(["atlaso-helper", "local-users", "authenticate", "--real", "vcf-depot"]) == 1
    invalid_output = capsys.readouterr()
    assert "wrong-password" not in invalid_output.out
    assert "valid-hash" not in invalid_output.out


def test_ldap_helper_authenticates_with_mode_0600_password_file_and_redacts(monkeypatch, tmp_path, capsys):
    """Verify that ldap helper authenticates with mode 0600 password file and redacts.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    helper = load_helper_module()
    seen: dict[str, object] = {}

    class ManagedTemporaryFile:
        """Represent managed temporary file.

        Attributes:
            path: Path captured or supplied by this test helper.
            handle: Handle captured or supplied by this test helper.
            name: Operator-facing name of the resource.
        """
        def __init__(self, **_kwargs):
            """Initialize the managed temporary file.

            Args:
                **_kwargs: Additional keyword arguments accepted by the callable.
            """
            self.path = tmp_path / "ldap-password"
            self.handle = self.path.open("w", encoding="utf-8")
            self.name = str(self.path)

        def __enter__(self):
            """Enter the managed context.

            Returns:
                The enter result.
            """
            return self.handle

        def __exit__(self, *_args):
            """Exit the managed context without suppressing exceptions.

            Args:
                *_args: Additional positional arguments accepted by the callable.
            """
            self.handle.close()

    def fake_run(command, **_kwargs):
        """Return fake run.

        Args:
            command: Command and arguments to execute.
            **_kwargs: Additional keyword arguments accepted by the callable.
        """
        password_path = Path(command[command.index("-y") + 1])
        seen["command"] = command
        seen["mode"] = stat.S_IMODE(password_path.stat().st_mode)
        seen["password"] = password_path.read_text(encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "dn:uid=alice,ou=users,dc=example,dc=test\n", "")

    real_chmod = helper.os.chmod

    def capture_chmod(path, mode):
        """Handle capture chmod.

        Args:
            path: Filesystem or URL path to read, validate, or update.
            mode: Operating mode selected for the workflow.
        """
        seen["chmod"] = (Path(path), mode)
        real_chmod(path, mode)

    monkeypatch.setattr(helper.tempfile, "NamedTemporaryFile", ManagedTemporaryFile)
    monkeypatch.setattr(helper.shutil, "which", lambda command: "/usr/bin/ldapwhoami" if command == "ldapwhoami" else None)
    monkeypatch.setattr(helper.os, "chmod", capture_chmod)
    monkeypatch.setattr(helper, "_run", fake_run)
    monkeypatch.setattr(helper.sys, "stdin", io.StringIO("Secret-Ldap-Password!\n"))

    assert helper.main(
        [
            "atlaso-helper",
            "ldap",
            "authenticate",
            "--real",
            "uid=alice,ou=users,dc=example,dc=test",
        ]
    ) == 0
    output = capsys.readouterr()
    assert seen["chmod"][1] == 0o600
    assert seen["password"] == "Secret-Ldap-Password!\n"
    assert "Secret-Ldap-Password!" not in " ".join(seen["command"])
    assert "Secret-Ldap-Password!" not in output.out
    assert "Secret-Ldap-Password!" not in output.err
    assert not (tmp_path / "ldap-password").exists()


def test_local_users_helper_authentication_rejects_locked_missing_and_unsupported_hashes(monkeypatch):
    """Verify that local users helper authentication rejects locked missing and unsupported hashes.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    helper = load_helper_module()

    for error in (
        "VCF Offline Depot OS user is locked.",
        "VCF Offline Depot OS user is missing.",
    ):
        def reject_shadow(username: str, message: str = error) -> str:
            """Return reject shadow.

            Args:
                username: Atlaso account name associated with the operation.
                message: Human-readable message associated with the operation.


            Raises:
                ValueError: If an input value is invalid.
            """
            raise ValueError(message)

        monkeypatch.setattr(helper, "_shadow_hash_for_user", reject_shadow)
        monkeypatch.setattr(helper.sys, "stdin", io.StringIO("Depot-user1!\n"))
        assert helper.main(["atlaso-helper", "local-users", "authenticate", "--real", "vcf-depot"]) == 1

    class UnsupportedCrypt:
        """Represent unsupported crypt.

        Attributes:
            argtypes: Argtypes captured or supplied by this test helper.
            restype: Restype captured or supplied by this test helper.
        """
        argtypes = None
        restype = None

        def __call__(self, password: bytes, password_hash: bytes) -> bytes:
            """Return call.

            Args:
                password: Password supplied for the immediate authenticated operation.
                password_hash: Password hash supplied by the caller.
            """
            return b"*0"

    monkeypatch.setattr(helper, "_shadow_hash_for_user", lambda username: "$y$unsupported")
    monkeypatch.setattr(helper.ctypes.util, "find_library", lambda name: "libcrypt.so.1")
    monkeypatch.setattr(helper.ctypes, "CDLL", lambda name: type("Library", (), {"crypt": UnsupportedCrypt()})())
    monkeypatch.setattr(helper.sys, "stdin", io.StringIO("Depot-user1!\n"))
    assert helper.main(["atlaso-helper", "local-users", "authenticate", "--real", "vcf-depot"]) == 1


def test_local_users_helper_refreshes_existing_depot_htpasswd_and_fails_closed(monkeypatch, tmp_path):
    """Verify that local users helper refreshes existing depot htpasswd and fails closed.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    htpasswd_path = tmp_path / "nginx" / "htpasswd" / "vcf-offline-depot.htpasswd"
    htpasswd_path.parent.mkdir(parents=True)
    htpasswd_path.write_text("vcf-depot:$6$stale\n", encoding="utf-8")

    monkeypatch.setattr(helper, "VCF_DEPOT_HTPASSWD_PATH", htpasswd_path)
    monkeypatch.setattr(helper.shutil, "chown", lambda *args, **kwargs: None)
    monkeypatch.setattr(helper.os, "chmod", lambda *args, **kwargs: None)
    monkeypatch.setattr(helper, "_shadow_hash_for_user", lambda username: "$6$fresh")

    assert helper._refresh_existing_vcf_depot_htpasswd() == 0
    assert htpasswd_path.read_text(encoding="utf-8") == "vcf-depot:$6$fresh\n"

    def locked_user(username: str) -> str:
        """Return locked user.

        Args:
            username: Atlaso account name associated with the operation.


        Raises:
            ValueError: If an input value is invalid.
        """
        raise ValueError("locked")

    monkeypatch.setattr(helper, "_shadow_hash_for_user", locked_user)
    assert helper._refresh_existing_vcf_depot_htpasswd() == 0
    assert htpasswd_path.read_text(encoding="utf-8") == "vcf-depot:!\n"


def test_local_users_helper_applies_per_user_shell(monkeypatch, tmp_path):
    """Verify that local users helper applies per user shell.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "local-users"
    home_base = tmp_path / "users"
    pwquality_path = tmp_path / "etc" / "security" / "pwquality.conf"
    pam_path = tmp_path / "etc" / "pam.d" / "system-password"
    pam_path.parent.mkdir(parents=True)
    pam_path.write_text("password  required    pam_pwquality.so  retry=3\npassword  required    pam_unix.so\n", encoding="utf-8")
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "atlaso-users.json"
    payload = json.loads(local_users_json(password=None))
    payload["users"][0]["home"] = (home_base / "sync-user").as_posix()
    payload["users"][0]["shell"] = "/bin/bash"
    config_path.write_text(json.dumps(payload), encoding="utf-8")
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "LOCAL_USERS_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "LOCAL_USERS_HOME_BASE", home_base)
    monkeypatch.setattr(helper, "LOCAL_USERS_PWQUALITY_PATH", pwquality_path)
    monkeypatch.setattr(helper, "LOCAL_USERS_SYSTEM_PASSWORD_PAM_PATH", pam_path)
    monkeypatch.setattr(helper, "_command_path", lambda command: command)
    monkeypatch.setattr(helper, "_run", fake_run)

    assert helper._handle_local_users("apply", [str(config_path)]) == 0
    assert ["usermod", "--shell", "/bin/bash", "sync-user"] in commands


def test_local_users_helper_keeps_admin_role_sudo_capable(monkeypatch, tmp_path):
    """Verify that local users helper keeps admin role sudo capable.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "local-users"
    home_base = tmp_path / "users"
    pwquality_path = tmp_path / "etc" / "security" / "pwquality.conf"
    pam_path = tmp_path / "etc" / "pam.d" / "system-password"
    pam_path.parent.mkdir(parents=True)
    pam_path.write_text("password  required    pam_pwquality.so  retry=3\npassword  required    pam_unix.so\n", encoding="utf-8")
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "atlaso-users.json"
    payload = json.loads(local_users_json(username="admin", password=None))
    payload["users"][0]["role"] = "admin"
    payload["users"][0]["home"] = (home_base / "admin").as_posix()
    config_path.write_text(json.dumps(payload), encoding="utf-8")
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "LOCAL_USERS_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "LOCAL_USERS_HOME_BASE", home_base)
    monkeypatch.setattr(helper, "LOCAL_USERS_PWQUALITY_PATH", pwquality_path)
    monkeypatch.setattr(helper, "LOCAL_USERS_SYSTEM_PASSWORD_PAM_PATH", pam_path)
    monkeypatch.setattr(helper, "_command_path", lambda command: command)
    monkeypatch.setattr(helper, "_run", fake_run)

    assert helper._handle_local_users("apply", [str(config_path)]) == 0
    assert ["usermod", "--shell", "/sbin/nologin", "admin"] in commands
    assert ["usermod", "--append", "--groups", "wheel", "admin"] in commands


def test_local_users_helper_removes_wheel_on_admin_downgrade(monkeypatch, tmp_path):
    """Verify that local users helper removes wheel on admin downgrade.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "local-users"
    home_base = tmp_path / "users"
    pwquality_path = tmp_path / "etc" / "security" / "pwquality.conf"
    pam_path = tmp_path / "etc" / "pam.d" / "system-password"
    pam_path.parent.mkdir(parents=True)
    pam_path.write_text("password  required    pam_pwquality.so  retry=3\npassword  required    pam_unix.so\n", encoding="utf-8")
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "atlaso-users.json"
    payload = json.loads(local_users_json(username="downgraded-user", password=None))
    payload["users"][0]["role"] = "viewer"
    payload["users"][0]["home"] = (home_base / "downgraded-user").as_posix()
    config_path.write_text(json.dumps(payload), encoding="utf-8")
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        commands.append(command)
        if command == ["id", "-nG", "downgraded-user"]:
            return subprocess.CompletedProcess(command, 0, "downgraded-user wheel", "")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "LOCAL_USERS_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "LOCAL_USERS_HOME_BASE", home_base)
    monkeypatch.setattr(helper, "LOCAL_USERS_PWQUALITY_PATH", pwquality_path)
    monkeypatch.setattr(helper, "LOCAL_USERS_SYSTEM_PASSWORD_PAM_PATH", pam_path)
    monkeypatch.setattr(helper, "_command_path", lambda command: command)
    monkeypatch.setattr(helper, "_run", fake_run)

    assert helper._handle_local_users("apply", [str(config_path)]) == 0
    assert ["gpasswd", "--delete", "downgraded-user", "wheel"] in commands


def test_local_users_helper_allows_powershell_shell(monkeypatch, tmp_path, capsys):
    """Verify that local users helper allows powershell shell.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "local-users"
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "atlaso-users.json"
    payload = json.loads(local_users_json(password=None))
    payload["users"][0]["shell"] = "/usr/bin/pwsh"
    config_path.write_text(json.dumps(payload), encoding="utf-8")

    monkeypatch.setattr(helper, "LOCAL_USERS_APPLY_DIR", apply_dir)

    assert helper._handle_local_users("validate", [str(config_path)]) == 0
    captured = capsys.readouterr()
    assert '"local_users": "validation ok"' in captured.out


def test_local_users_helper_unlock_request_resets_passwd_and_faillock(monkeypatch, tmp_path):
    """Verify that local users helper unlock request resets passwd and faillock.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "local-users"
    home_base = tmp_path / "users"
    pwquality_path = tmp_path / "etc" / "security" / "pwquality.conf"
    pam_path = tmp_path / "etc" / "pam.d" / "system-password"
    pam_path.parent.mkdir(parents=True)
    pam_path.write_text("password  required    pam_pwquality.so  retry=3\npassword  required    pam_unix.so\n", encoding="utf-8")
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "atlaso-users.json"
    payload = json.loads(local_users_json(password=None))
    payload["users"][0]["home"] = (home_base / "sync-user").as_posix()
    payload["users"][0]["unlock_requested"] = True
    config_path.write_text(json.dumps(payload), encoding="utf-8")
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "LOCAL_USERS_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "LOCAL_USERS_HOME_BASE", home_base)
    monkeypatch.setattr(helper, "LOCAL_USERS_PWQUALITY_PATH", pwquality_path)
    monkeypatch.setattr(helper, "LOCAL_USERS_SYSTEM_PASSWORD_PAM_PATH", pam_path)
    monkeypatch.setattr(helper, "_command_path", lambda command: command)
    monkeypatch.setattr(helper, "_run", fake_run)

    assert helper._handle_local_users("apply", [str(config_path)]) == 0
    assert ["passwd", "-u", "sync-user"] in commands
    assert ["faillock", "--user", "sync-user", "--reset"] in commands
    assert ["chpasswd"] not in commands


def test_local_users_helper_status_reports_faillock_blocked(monkeypatch, tmp_path, capsys):
    """Verify that local users helper status reports faillock blocked.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "local-users"
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "atlaso-users.json"
    config_path.write_text(local_users_json(password=None), encoding="utf-8")

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        if command == ["id", "sync-user"]:
            return subprocess.CompletedProcess(command, 0, "", "")
        if command == ["passwd", "-S", "sync-user"]:
            return subprocess.CompletedProcess(command, 0, "sync-user L 2026-06-23 0 99999 7 -1\n", "")
        if command == ["faillock", "--user", "sync-user"]:
            return subprocess.CompletedProcess(command, 0, "sync-user:\nWhen                Type  Source                                           Valid\n2026-06-23 10:00   TTY   ssh                                              V\n", "")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "LOCAL_USERS_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "_command_path", lambda command: command)
    monkeypatch.setattr(helper, "_run", fake_run)

    assert helper._handle_local_users("status", [str(config_path)]) == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["users"][0]["username"] == "sync-user"
    assert payload["users"][0]["state"] == "faillock blocked"


def test_local_users_helper_status_does_not_block_on_zero_faillock_failures(monkeypatch, tmp_path, capsys):
    """Verify that local users helper status does not block on zero faillock failures.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "local-users"
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "atlaso-users.json"
    config_path.write_text(local_users_json(password=None), encoding="utf-8")

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        if command == ["id", "sync-user"]:
            return subprocess.CompletedProcess(command, 0, "", "")
        if command == ["passwd", "-S", "sync-user"]:
            return subprocess.CompletedProcess(command, 0, "sync-user P 2026-06-23 0 99999 7 -1\n", "")
        if command == ["faillock", "--user", "sync-user"]:
            return subprocess.CompletedProcess(command, 0, "Login           Failures    Latest failure         From\nsync-user           0\n", "")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "LOCAL_USERS_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "_command_path", lambda command: command)
    monkeypatch.setattr(helper, "_run", fake_run)

    assert helper._handle_local_users("status", [str(config_path)]) == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["users"][0]["state"] == "present"


def vcf_backups_config_text(*, enabled: bool = True) -> str:
    """Return vcf backups config text.

    Args:
        enabled: Whether the associated resource or behavior is enabled.
    """
    if not enabled:
        return "\n".join(
            [
                "# Managed by Atlaso. Local changes may be overwritten.",
                "# Atlaso VCF Backups enabled: false",
                "# Atlaso VCF Backups user: vcf-backup",
                "# Backup volume mount: /mnt/atlaso-vcf-backups",
                "# VCF remote directory: /backups",
                "# VCF Backup SFTP desired state is disabled.",
                "",
            ]
        )
    return "\n".join(
        [
            "# Managed by Atlaso. Local changes may be overwritten.",
            "# Atlaso VCF Backups enabled: true",
            "# Atlaso VCF Backups user: vcf-backup",
            "# Backup volume mount: /mnt/atlaso-vcf-backups",
            "# VCF remote directory: /backups",
            "# The selected listen target is enforced by the Atlaso firewall apply unit.",
            "",
            "# Service listener target: 192.168.50.1:22",
            "Match User vcf-backup",
            "  AuthorizedKeysFile /etc/atlaso/ssh/authorized_keys/%u",
            "  ChrootDirectory /mnt/atlaso-vcf-backups",
            "  ForceCommand internal-sftp -d /backups",
            "  PasswordAuthentication yes",
            "  PubkeyAuthentication yes",
            "  MaxSessions 4",
            "  PermitTTY no",
            "  PermitTunnel no",
            "  AllowAgentForwarding no",
            "  AllowTcpForwarding no",
            "  X11Forwarding no",
            "",
        ]
    )


def test_vcf_backups_helper_validates_staged_config(monkeypatch, tmp_path, capsys):
    """Verify that vcf backups helper validates staged config.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "vcf-backups"
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "atlaso-vcf-backups-sshd.conf"
    config_path.write_text(vcf_backups_config_text(), encoding="utf-8")

    monkeypatch.setattr(helper, "VCF_BACKUPS_APPLY_DIR", apply_dir)

    assert helper._handle_vcf_backups("validate", [str(config_path)]) == 0
    captured = capsys.readouterr()
    assert '"vcf_backups": "validation ok"' in captured.out
    assert '"username": "vcf-backup"' in captured.out


def test_vcf_backups_helper_rejects_unmanaged_config(tmp_path):
    """Verify that vcf backups helper rejects unmanaged config.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    config_path = tmp_path / "atlaso-vcf-backups-sshd.conf"
    config_path.write_text("Match User root\n", encoding="utf-8")

    errors = helper._vcf_backups_config_errors(config_path)

    assert "VCF backups config must be rendered by Atlaso." in errors


def test_vcf_backups_helper_apply_installs_sshd_dropin_and_storage(monkeypatch, tmp_path):
    """Verify that vcf backups helper apply installs sshd dropin and storage.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "vcf-backups"
    config_dir = tmp_path / "etc" / "ssh" / "sshd_config.d"
    atlaso_ssh_dir = tmp_path / "etc" / "atlaso" / "ssh" / "authorized_keys"
    storage_path = tmp_path / "mnt" / "atlaso-vcf-backups"
    sshd_config = tmp_path / "etc" / "ssh" / "sshd_config"
    apply_dir.mkdir(parents=True)
    sshd_config.parent.mkdir(parents=True)
    sshd_config.write_text("Subsystem sftp internal-sftp\n", encoding="utf-8")
    config_path = apply_dir / "atlaso-vcf-backups-sshd.conf"
    config_path.write_text(vcf_backups_config_text(), encoding="utf-8")
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "VCF_BACKUPS_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "VCF_BACKUPS_CONFIG_DIR", config_dir)
    monkeypatch.setattr(helper, "VCF_BACKUPS_CONFIG_PATH", config_dir / "atlaso-vcf-backups.conf")
    monkeypatch.setattr(helper, "VCF_BACKUPS_AUTHORIZED_KEYS_DIR", atlaso_ssh_dir)
    def fake_path(value):
        """Return fake path.

        Args:
            value: Candidate value consumed by fake path.
        """
        if value == "/etc/ssh/sshd_config":
            return sshd_config
        if value == "/mnt/atlaso-vcf-backups":
            return storage_path
        return Path(value)

    monkeypatch.setattr(helper, "Path", fake_path)
    monkeypatch.setattr(helper, "_chown_path", lambda path, uid, gid: None)
    monkeypatch.setattr(helper.shutil, "which", lambda command: {"id": "id", "sshd": "sshd"}.get(command))
    monkeypatch.setattr(helper, "_run", fake_run)

    assert helper._handle_vcf_backups("apply", [str(config_path)]) == 0

    assert (config_dir / "atlaso-vcf-backups.conf").is_file()
    assert "Match User vcf-backup" in (config_dir / "atlaso-vcf-backups.conf").read_text(encoding="utf-8")
    assert (storage_path / "backups").is_dir()
    assert (atlaso_ssh_dir / "vcf-backup").is_file()
    assert sshd_config.read_text(encoding="utf-8").startswith("Include /etc/ssh/sshd_config.d/*.conf\n")
    assert ["id", "vcf-backup"] in commands
    assert all(arg != "atlaso-vcf-backup" for command in commands for arg in command)
    assert ["sshd", "-t"] in commands
    assert ["systemctl", "restart", "sshd"] in commands


def test_vcf_backups_helper_apply_requires_existing_os_user(monkeypatch, tmp_path, capsys):
    """Verify that vcf backups helper apply requires existing os user.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "vcf-backups"
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "atlaso-vcf-backups-sshd.conf"
    config_path.write_text(vcf_backups_config_text(), encoding="utf-8")

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        if command == ["id", "vcf-backup"]:
            return subprocess.CompletedProcess(command, 1, "", "")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "VCF_BACKUPS_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper.shutil, "which", lambda command: "id" if command == "id" else None)
    monkeypatch.setattr(helper, "_run", fake_run)

    assert helper._handle_vcf_backups("apply", [str(config_path)]) == 2
    captured = capsys.readouterr()
    assert "Apply the Local Users unit before VCF Backups" in captured.err


def test_vcf_offline_depot_helper_applies_nginx_site(monkeypatch, tmp_path):
    """Verify that vcf offline depot helper applies nginx site.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "vcf-offline-depot"
    managed_root = tmp_path / "etc" / "atlaso"
    site_dir = managed_root / "nginx" / "sites.d"
    cert_path = managed_root / "vcf-offline-depot" / "certs" / "depot.crt"
    key_path = managed_root / "vcf-offline-depot" / "certs" / "depot.key"
    nginx_include = tmp_path / "nginx" / "conf.d" / "atlaso.conf"
    apply_dir.mkdir(parents=True)
    cert_path.parent.mkdir(parents=True)
    cert_path.write_text("-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n", encoding="utf-8")
    key_path.write_text("-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n", encoding="utf-8")
    config_path = apply_dir / "atlaso-vcf-offline-depot.conf"
    config_path.write_text(
        "\n".join(
            [
                "# Managed by Atlaso. Local changes may be overwritten.",
                "server {",
                "  listen 192.168.50.1:443 ssl;",
                "  server_name depot.atlaso.internal;",
                f"  ssl_certificate {cert_path};",
                f"  ssl_certificate_key {key_path};",
                "",
                "  location = / {",
                "    proxy_pass http://127.0.0.1:8000;",
                "  }",
                "",
                "  location ^~ /static/ {",
                "    proxy_pass http://127.0.0.1:8000;",
                "  }",
                "",
                "  location = /favicon.ico {",
                "    proxy_pass http://127.0.0.1:8000;",
                "  }",
                "",
                "  location = /manifest.webmanifest {",
                "    proxy_pass http://127.0.0.1:8000;",
                "  }",
                "",
                "  location = /service-worker.js {",
                "    proxy_pass http://127.0.0.1:8000;",
                "  }",
                "",
                "  location = /PROD {",
                "    return 301 /PROD/;",
                "  }",
                "",
                "  location = /PROD/login {",
                "    proxy_pass http://127.0.0.1:8000;",
                "  }",
                "",
                "  location = /PROD/logout {",
                "    proxy_pass http://127.0.0.1:8000;",
                "  }",
                "",
                "  location = /PROD/ {",
                "    proxy_pass http://127.0.0.1:8000;",
                "  }",
                "",
                "  location ~ ^/PROD/.*/$ {",
                "    proxy_pass http://127.0.0.1:8000;",
                "  }",
                "",
                "  location ~ ^/PROD/(?!login$|logout$|auth-check$)(.+[^/])$ {",
                "    alias /mnt/atlaso-vcf-offline-depot/PROD/$1;",
                "    sendfile on;",
                "    default_type application/octet-stream;",
                "  }",
                "",
                "  location / {",
                "    return 404;",
                "  }",
                "}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "VCF_DEPOT_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "CA_MANAGED_PATH_BASE", managed_root)
    monkeypatch.setattr(helper, "NGINX_CONF_INCLUDE_PATH", nginx_include)
    monkeypatch.setattr(helper, "NGINX_MAIN_CONFIG_PATH", tmp_path / "nginx" / "nginx.conf")
    monkeypatch.setattr(helper, "NGINX_SITES_DIR", site_dir)
    monkeypatch.setattr(helper, "VCF_DEPOT_SITE_PATH", site_dir / "vcf-offline-depot.conf")
    monkeypatch.setattr(helper, "_prepare_vcf_depot_web_tree", lambda text: None)
    monkeypatch.setattr(helper, "_run", fake_run)
    monkeypatch.setattr(helper.shutil, "which", lambda command: "/usr/sbin/nginx" if command == "nginx" else None)

    assert helper._handle_vcf_offline_depot("validate", [str(config_path)]) == 0
    assert helper._handle_vcf_offline_depot("apply-https", [str(config_path)]) == 0

    site_text = (site_dir / "vcf-offline-depot.conf").read_text(encoding="utf-8")
    assert "server_name depot.atlaso.internal;" in site_text
    assert "alias /mnt/atlaso-vcf-offline-depot/PROD/$1;" in site_text
    assert "root /mnt/atlaso-vcf-offline-depot;" not in site_text
    assert "sendfile on;" in site_text
    assert nginx_include.read_text(encoding="utf-8").strip().endswith(f"include {site_dir}/*.conf;")
    assert ["/usr/sbin/nginx", "-t"] in commands
    assert ["systemctl", "enable", "--now", "nginx"] in commands


def test_vcf_offline_depot_helper_uses_browser_session_or_basic_auth_for_authenticated_site(monkeypatch, tmp_path):
    """Verify that vcf offline depot helper uses browser session or basic auth for authenticated site.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "vcf-offline-depot"
    managed_root = tmp_path / "etc" / "atlaso"
    site_dir = managed_root / "nginx" / "sites.d"
    cert_path = managed_root / "vcf-offline-depot" / "certs" / "depot.crt"
    key_path = managed_root / "vcf-offline-depot" / "certs" / "depot.key"
    htpasswd_path = managed_root / "nginx" / "htpasswd" / "vcf-offline-depot.htpasswd"
    nginx_include = tmp_path / "nginx" / "conf.d" / "atlaso.conf"
    apply_dir.mkdir(parents=True)
    cert_path.parent.mkdir(parents=True)
    cert_path.write_text("-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n", encoding="utf-8")
    key_path.write_text("-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n", encoding="utf-8")
    htpasswd_path.parent.mkdir(parents=True)
    htpasswd_path.write_text("vcf-depot:stale-basic-auth-hash\n", encoding="utf-8")
    config_path = apply_dir / "atlaso-vcf-offline-depot.conf"
    config_path.write_text(
        "\n".join(
            [
                "# Managed by Atlaso. Local changes may be overwritten.",
                "# Atlaso VCF Offline Depot unauthenticated access: false",
                "# Atlaso VCF Offline Depot user: vcf-depot",
                "server {",
                "  listen 192.168.50.1:443 ssl;",
                "  server_name depot.atlaso.internal;",
                f"  ssl_certificate {cert_path};",
                f"  ssl_certificate_key {key_path};",
                "",
                "  location = / {",
                "    proxy_pass http://127.0.0.1:8000;",
                "  }",
                "",
                "  location ^~ /static/ {",
                "    proxy_pass http://127.0.0.1:8000;",
                "  }",
                "",
                "  location = /favicon.ico {",
                "    proxy_pass http://127.0.0.1:8000;",
                "  }",
                "",
                "  location = /manifest.webmanifest {",
                "    proxy_pass http://127.0.0.1:8000;",
                "  }",
                "",
                "  location = /service-worker.js {",
                "    proxy_pass http://127.0.0.1:8000;",
                "  }",
                "",
                "  location = /PROD {",
                "    return 301 /PROD/;",
                "  }",
                "",
                "  location = /PROD/login {",
                "    proxy_pass http://127.0.0.1:8000;",
                "  }",
                "",
                "  location = /PROD/logout {",
                "    proxy_pass http://127.0.0.1:8000;",
                "  }",
                "",
                "  location = /_atlaso_depot_auth {",
                "    internal;",
                "    proxy_pass http://127.0.0.1:8000/PROD/auth-check;",
                "    proxy_pass_request_body off;",
                "    proxy_set_header Content-Length \"\";",
                "    proxy_set_header Host $host;",
                "    proxy_set_header X-Original-URI $request_uri;",
                "  }",
                "",
                "  location = /_atlaso_depot_login {",
                "    internal;",
                "    proxy_pass http://127.0.0.1:8000/PROD/auth-failure;",
                "    proxy_pass_request_body off;",
                "    proxy_set_header Content-Length \"\";",
                "    proxy_set_header Host $host;",
                "    proxy_set_header X-Original-URI $request_uri;",
                "    proxy_set_header X-Forwarded-Proto https;",
                "  }",
                "",
                "  location = /PROD/ {",
                "    satisfy any;",
                '    auth_basic "VCF Offline Depot";',
                f"    auth_basic_user_file {htpasswd_path};",
                "    auth_request /_atlaso_depot_auth;",
                "    error_page 401 = /_atlaso_depot_login;",
                "    proxy_pass http://127.0.0.1:8000;",
                "  }",
                "",
                "  location ~ ^/PROD/.*/$ {",
                "    satisfy any;",
                '    auth_basic "VCF Offline Depot";',
                f"    auth_basic_user_file {htpasswd_path};",
                "    auth_request /_atlaso_depot_auth;",
                "    error_page 401 = /_atlaso_depot_login;",
                "    proxy_pass http://127.0.0.1:8000;",
                "  }",
                "",
                "  location ~ ^/PROD/(?!login$|logout$|auth-check$)(.+[^/])$ {",
                "    satisfy any;",
                '    auth_basic "VCF Offline Depot";',
                f"    auth_basic_user_file {htpasswd_path};",
                "    auth_request /_atlaso_depot_auth;",
                "    error_page 401 = /_atlaso_depot_login;",
                "    alias /mnt/atlaso-vcf-offline-depot/PROD/$1;",
                "    sendfile on;",
                "    default_type application/octet-stream;",
                "  }",
                "",
                "  location / {",
                "    return 404;",
                "  }",
                "}",
                "",
            ]
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(helper, "VCF_DEPOT_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "CA_MANAGED_PATH_BASE", managed_root)
    monkeypatch.setattr(helper, "NGINX_CONF_INCLUDE_PATH", nginx_include)
    monkeypatch.setattr(helper, "NGINX_MAIN_CONFIG_PATH", tmp_path / "nginx" / "nginx.conf")
    monkeypatch.setattr(helper, "NGINX_SITES_DIR", site_dir)
    monkeypatch.setattr(helper, "VCF_DEPOT_SITE_PATH", site_dir / "vcf-offline-depot.conf")
    monkeypatch.setattr(helper, "VCF_DEPOT_HTPASSWD_PATH", htpasswd_path)
    monkeypatch.setattr(helper, "_prepare_vcf_depot_web_tree", lambda text: None)
    monkeypatch.setattr(helper.shutil, "which", lambda command: "/usr/sbin/nginx" if command == "nginx" else None)
    monkeypatch.setattr(helper.shutil, "chown", lambda *args, **kwargs: None)
    monkeypatch.setattr(helper.pwd, "getpwnam", lambda username: object())
    monkeypatch.setattr(helper.grp, "getgrnam", lambda group: (_ for _ in ()).throw(KeyError(group)))
    monkeypatch.setattr(helper, "_run", lambda command: subprocess.CompletedProcess(command, 0, "", ""))
    monkeypatch.setattr(
        helper,
        "_write_vcf_depot_htpasswd",
        lambda username: (htpasswd_path.write_text(f"{username}:fresh-shadow-hash\n", encoding="utf-8"), 0)[1],
    )

    assert helper._handle_vcf_offline_depot("apply-https", [str(config_path)]) == 0

    assert htpasswd_path.read_text(encoding="utf-8") == "vcf-depot:fresh-shadow-hash\n"
    site_text = (site_dir / "vcf-offline-depot.conf").read_text(encoding="utf-8")
    assert "auth_request /_atlaso_depot_auth;" in site_text
    assert "error_page 401 = /_atlaso_depot_login;" in site_text
    assert "proxy_pass http://127.0.0.1:8000/PROD/auth-failure;" in site_text
    assert "satisfy any;" in site_text
    assert 'auth_basic "VCF Offline Depot";' in site_text
    assert f"auth_basic_user_file {htpasswd_path};" in site_text


def test_vcf_offline_depot_helper_prepares_prod_tree_permissions(monkeypatch, tmp_path):
    """Verify that vcf offline depot helper prepares prod tree permissions.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    prod_path = tmp_path / "depot" / "PROD"
    nested_dir = prod_path / "COMP"
    nested_file = nested_dir / "artifact.json"
    nested_dir.mkdir(parents=True)
    nested_file.write_text("{}", encoding="utf-8")
    prod_path.chmod(0o750)
    nested_dir.chmod(0o750)
    nested_file.chmod(0o640)
    monkeypatch.setattr(helper, "VCF_DEPOT_PROD_PATH", prod_path)

    helper._prepare_vcf_depot_web_tree(f"alias {prod_path}/;\n")

    assert prod_path.stat().st_mode & 0o005 == 0o005
    assert nested_dir.stat().st_mode & 0o005 == 0o005
    assert nested_file.stat().st_mode & 0o004 == 0o004


def test_vcf_offline_depot_helper_rejects_broad_nginx_root(monkeypatch, tmp_path, capsys):
    """Verify that vcf offline depot helper rejects broad nginx root.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "vcf-offline-depot"
    managed_root = tmp_path / "etc" / "atlaso"
    cert_path = managed_root / "vcf-offline-depot" / "certs" / "depot.crt"
    key_path = managed_root / "vcf-offline-depot" / "certs" / "depot.key"
    apply_dir.mkdir(parents=True)
    cert_path.parent.mkdir(parents=True)
    cert_path.write_text("-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n", encoding="utf-8")
    key_path.write_text("-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n", encoding="utf-8")
    config_path = apply_dir / "atlaso-vcf-offline-depot.conf"
    config_path.write_text(
        "\n".join(
            [
                "server {",
                "  listen 192.168.50.1:443 ssl;",
                "  server_name depot.atlaso.internal;",
                "  root /mnt/atlaso-vcf-offline-depot;",
                "  sendfile on;",
                "  default_type application/octet-stream;",
                f"  ssl_certificate {cert_path};",
                f"  ssl_certificate_key {key_path};",
                "}",
                "",
            ]
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(helper, "VCF_DEPOT_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "CA_MANAGED_PATH_BASE", managed_root)

    assert helper._handle_vcf_offline_depot("validate", [str(config_path)]) == 2
    captured = capsys.readouterr()
    assert "must not expose the depot store as a broad server root" in captured.err
    assert "must include a /PROD/ alias" in captured.err


def test_vcf_offline_depot_helper_extracts_vcfdt_tool(monkeypatch, tmp_path, capsys):
    """Verify that vcf offline depot helper extracts vcfdt tool.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    helper = load_helper_module()
    archive_path = tmp_path / "vcf-download-tool-9.1.0.test.tar.gz"
    payload = b"#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'vcf-download-tool 9.1.0.0100.25429019'; else echo software depot id 8c9506c6-7bdf-44d5-b2e9-50d829d66b99; fi\n"
    with tarfile.open(archive_path, "w:gz") as archive:
        info = tarfile.TarInfo("vcfdt/bin/vcf-download-tool")
        info.mode = 0o750
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
        jar_payload = b"jar"
        jar_info = tarfile.TarInfo("vcfdt/lib/lcm-tools-uber.jar")
        jar_info.mode = 0o640
        jar_info.size = len(jar_payload)
        archive.addfile(jar_info, io.BytesIO(jar_payload))

    tool_dir = tmp_path / "opt" / "atlaso" / "vcf-download-tool"
    runtime_tool_dir = tmp_path / "var" / "lib" / "atlaso" / "vcfDownloadTool" / "active-tool"
    (runtime_tool_dir / "secrets").mkdir(parents=True)
    (runtime_tool_dir / "secrets" / "download-token.txt").write_text("secret", encoding="utf-8")
    (runtime_tool_dir / "stale.jar").write_text("stale", encoding="utf-8")
    monkeypatch.setattr(helper, "VCF_DEPOT_TOOL_DIR", tool_dir)
    monkeypatch.setattr(helper, "VCF_DEPOT_RUNTIME_TOOL_DIR", runtime_tool_dir)
    monkeypatch.setattr(
        helper,
        "_run_vcfdt_user_command",
        lambda command: subprocess.CompletedProcess(command, 0, "vcf-download-tool 9.1.0.0100.25429019\n", ""),
    )

    assert helper._handle_vcf_offline_depot("stage-tool", [str(archive_path)]) == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["vcf_offline_depot"] == "stage-tool complete"
    assert payload["executable"] == str(tool_dir / "vcf-download-tool")
    assert payload["runtime_executable"] == str(runtime_tool_dir / "vcf-download-tool")
    assert payload["tool_version"] == "9.1.0.0100.25429019"
    assert payload["version_command"] == "vcf-download-tool --version"
    wrapper = tool_dir / "vcf-download-tool"
    extracted = tool_dir / "extracted" / "vcfdt" / "bin" / "vcf-download-tool"
    jar = tool_dir / "extracted" / "vcfdt" / "lib" / "lcm-tools-uber.jar"
    assert wrapper.is_file()
    assert extracted.is_file()
    assert jar.is_file()
    assert (runtime_tool_dir / "bin" / "vcf-download-tool").is_file()
    assert (runtime_tool_dir / "vcf-download-tool").is_file()
    assert (runtime_tool_dir / "lib" / "lcm-tools-uber.jar").is_file()
    assert (runtime_tool_dir / "secrets" / "download-token.txt").is_file()
    assert not (runtime_tool_dir / "stale.jar").exists()
    assert os.access(wrapper, os.X_OK)
    assert os.access(extracted, os.X_OK)
    if os.name == "posix":
        assert stat.S_IMODE(extracted.stat().st_mode) == 0o755
        assert stat.S_IMODE(jar.stat().st_mode) == 0o644
    wrapper_text = wrapper.read_text(encoding="utf-8")
    assert f"cd '{extracted.parent.parent}' || exit 1" in wrapper_text
    assert str(extracted) in wrapper_text


def test_vcf_offline_depot_helper_renews_runtime_when_retired_tree_stays_busy(monkeypatch, tmp_path, capsys):
    """Verify that vcf offline depot helper renews runtime when retired tree stays busy.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    helper = load_helper_module()
    archive_path = tmp_path / "vcf-download-tool-9.1.0.renew.tar.gz"
    tool_payload = b"#!/bin/sh\necho 'vcf-download-tool 9.1.0'\n"
    with tarfile.open(archive_path, "w:gz") as archive:
        info = tarfile.TarInfo("vcfdt/bin/vcf-download-tool")
        info.mode = 0o750
        info.size = len(tool_payload)
        archive.addfile(info, io.BytesIO(tool_payload))

    tool_dir = tmp_path / "opt" / "atlaso" / "vcf-download-tool"
    runtime_tool_dir = tmp_path / "var" / "lib" / "atlaso" / "vcfDownloadTool" / "active-tool"
    busy_dir = runtime_tool_dir / "esximage" / "python" / "lib" / "python3.11"
    busy_dir.mkdir(parents=True)
    (busy_dir / "stale.pyc").write_bytes(b"stale")
    (runtime_tool_dir / "secrets").mkdir()
    (runtime_tool_dir / "secrets" / "download-token.txt").write_text("secret", encoding="utf-8")
    monkeypatch.setattr(helper, "VCF_DEPOT_TOOL_DIR", tool_dir)
    monkeypatch.setattr(helper, "VCF_DEPOT_RUNTIME_TOOL_DIR", runtime_tool_dir)
    monkeypatch.setattr(
        helper,
        "_run_vcfdt_user_command",
        lambda command: subprocess.CompletedProcess(command, 0, "vcf-download-tool 9.1.0\n", ""),
    )
    real_rmtree = helper.shutil.rmtree

    def busy_rmtree(path, *args, **kwargs):
        """Return busy rmtree.

        Args:
            path: Filesystem or URL path to read, validate, or update.
            *args: Parsed command-line arguments.
            **kwargs: Additional keyword arguments forwarded to the wrapped call.

        Raises:
            OSError: If the operating-system operation fails.
        """
        if Path(path).name.startswith(".active-tool.retired-"):
            raise OSError(39, "Directory not empty", str(path))
        return real_rmtree(path, *args, **kwargs)

    monkeypatch.setattr(helper.shutil, "rmtree", busy_rmtree)

    assert helper._handle_vcf_offline_depot("stage-tool", [str(archive_path)]) == 0

    captured = capsys.readouterr()
    assert json.loads(captured.out)["vcf_offline_depot"] == "stage-tool complete"
    assert "warning: unable to remove retired VCF Download Tool runtime" in captured.err
    assert (runtime_tool_dir / "bin" / "vcf-download-tool").read_bytes() == tool_payload
    assert (runtime_tool_dir / "secrets" / "download-token.txt").read_text(encoding="utf-8") == "secret"
    assert not (runtime_tool_dir / "esximage").exists()
    assert list(runtime_tool_dir.parent.glob(".active-tool.retired-*"))


def test_vcf_offline_depot_helper_preserves_root_level_runtime_executable(monkeypatch, tmp_path, capsys):
    """Verify that vcf offline depot helper preserves root level runtime executable.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    helper = load_helper_module()
    archive_path = tmp_path / "vcf-download-tool-9.1.0.root.tar.gz"
    payload = b"#!/bin/sh\necho 'vcf-download-tool 9.1.0'\n"
    with tarfile.open(archive_path, "w:gz") as archive:
        info = tarfile.TarInfo("vcf-download-tool")
        info.mode = 0o750
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))

    tool_dir = tmp_path / "opt" / "atlaso" / "vcf-download-tool"
    runtime_tool_dir = tmp_path / "var" / "lib" / "atlaso" / "vcfDownloadTool" / "active-tool"
    monkeypatch.setattr(helper, "VCF_DEPOT_TOOL_DIR", tool_dir)
    monkeypatch.setattr(helper, "VCF_DEPOT_RUNTIME_TOOL_DIR", runtime_tool_dir)
    monkeypatch.setattr(
        helper,
        "_run_vcfdt_user_command",
        lambda command: subprocess.CompletedProcess(command, 0, "vcf-download-tool 9.1.0\n", ""),
    )

    assert helper._handle_vcf_offline_depot("stage-tool", [str(archive_path)]) == 0
    capsys.readouterr()
    wrapper = runtime_tool_dir / "vcf-download-tool"
    preserved = runtime_tool_dir / "vcf-download-tool.real"
    assert wrapper.is_file()
    assert preserved.read_bytes() == payload
    wrapper_text = wrapper.read_text(encoding="utf-8")
    assert str(preserved) in wrapper_text
    assert f'exec {wrapper} "$@"' not in wrapper_text


def test_vcf_offline_depot_helper_resets_staged_and_active_tool_trees(monkeypatch, tmp_path, capsys):
    """Verify that vcf offline depot helper resets staged and active tool trees.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    helper = load_helper_module()
    tool_dir = tmp_path / "opt" / "atlaso" / "vcf-download-tool"
    runtime_tool_dir = tmp_path / "var" / "lib" / "atlaso" / "vcfDownloadTool" / "active-tool"
    (tool_dir / "extracted").mkdir(parents=True)
    (tool_dir / "extracted" / "stale.jar").write_text("stale", encoding="utf-8")
    (runtime_tool_dir / "bin").mkdir(parents=True)
    (runtime_tool_dir / "bin" / "vcf-download-tool").write_text("stale", encoding="utf-8")
    (runtime_tool_dir / "secrets").mkdir()
    (runtime_tool_dir / "secrets" / "download-token.txt").write_text("secret", encoding="utf-8")
    monkeypatch.setattr(helper, "VCF_DEPOT_TOOL_DIR", tool_dir)
    monkeypatch.setattr(helper, "VCF_DEPOT_RUNTIME_TOOL_DIR", runtime_tool_dir)
    monkeypatch.setattr(helper.pwd, "getpwnam", lambda _username: (_ for _ in ()).throw(KeyError()))

    assert helper._handle_vcf_offline_depot("reset-tool", []) == 0

    assert not tool_dir.exists()
    assert runtime_tool_dir.is_dir()
    assert list(runtime_tool_dir.iterdir()) == [runtime_tool_dir / "secrets"]
    assert list((runtime_tool_dir / "secrets").iterdir()) == []
    assert json.loads(capsys.readouterr().out)["vcf_offline_depot"] == "tool runtime reset complete"


def test_vcf_offline_depot_helper_prepares_atlaso_vcfdt_home(monkeypatch, tmp_path):
    """Verify that vcf offline depot helper prepares atlaso vcfdt home.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    state_home = tmp_path / "var" / "lib" / "atlaso"
    chowned: list[tuple[Path, int, int]] = []

    class Account:
        """Represent account.

        Attributes:
            pw_dir: Pw dir captured or supplied by this test helper.
            pw_uid: Pw uid captured or supplied by this test helper.
            pw_gid: Pw gid captured or supplied by this test helper.
        """
        pw_dir = str(state_home)
        pw_uid = 1200
        pw_gid = 1200

    monkeypatch.setattr(helper.pwd, "getpwnam", lambda username: Account())
    monkeypatch.setattr(helper, "_chown_path", lambda path, uid, gid: chowned.append((path, uid, gid)))

    env, uid, gid = helper._vcfdt_atlaso_environment()

    assert uid == 1200
    assert gid == 1200
    assert env["HOME"] == str(state_home)
    assert env["XDG_DATA_HOME"] == str(state_home / ".local" / "share")
    assert (state_home / ".local" / "share" / "vmware" / "vdt").is_dir()
    assert (state_home / ".local" / "share" / "vmware" / "vdt", 1200, 1200) in chowned


def test_vcf_offline_depot_helper_generates_software_depot_id(monkeypatch, tmp_path, capsys):
    """Verify that vcf offline depot helper generates software depot id.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    helper = load_helper_module()
    runtime_tool_dir = tmp_path / "var" / "lib" / "atlaso" / "vcfDownloadTool" / "active-tool"
    wrapper = runtime_tool_dir / "vcf-download-tool"
    wrapper.parent.mkdir(parents=True)
    wrapper.write_text("#!/bin/sh\n", encoding="utf-8")
    wrapper.chmod(0o755)
    credential_paths = [
        runtime_tool_dir / "secrets" / "download-token.txt",
        runtime_tool_dir / "secrets" / "activation-code.txt",
    ]
    for credential_path in credential_paths:
        credential_path.parent.mkdir(parents=True, exist_ok=True)
        credential_path.write_text("non-secret-fixture", encoding="utf-8")
    commands: list[tuple[list[str], str]] = []

    def fake_run_vcfdt(command: list[str], *, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
        """Return fake run vcfdt.

        Args:
            command: Command and arguments to execute.
            input_text: Text supplied to the invoked command through standard input.
        """
        commands.append((command, input_text or ""))
        if "generate" in command:
            return subprocess.CompletedProcess(command, 0, "Initialized request 11111111-1111-1111-1111-111111111111\n", "")
        return subprocess.CompletedProcess(
            command,
            0,
            "Session 22222222-2222-2222-2222-222222222222\n"
            "Software Depot ID: 8c9506c6-7bdf-44d5-b2e9-50d829d66b99\n",
            "",
        )

    monkeypatch.setattr(helper, "VCF_DEPOT_RUNTIME_TOOL_DIR", runtime_tool_dir)
    monkeypatch.setattr(helper, "_run_vcfdt_user_command", fake_run_vcfdt)

    assert helper._handle_vcf_offline_depot("generate-software-depot-id", []) == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert commands == [
        ([str(wrapper), "configuration", "generate", "--software-depot-id"], "Y\n"),
        ([str(wrapper), "configuration", "get", "--software-depot-id"], ""),
    ]
    assert payload["software_depot_id"] == "8c9506c6-7bdf-44d5-b2e9-50d829d66b99"
    assert "credentials_cleared" not in payload
    assert "command" not in payload
    assert "readback_command" not in payload
    assert all(not credential_path.exists() for credential_path in credential_paths)


def test_vcf_offline_depot_helper_rejects_ambiguous_uuid_only_output():
    """Verify that vcf offline depot helper rejects ambiguous uuid only output."""
    helper = load_helper_module()

    assert (
        helper._parse_software_depot_id(
            "11111111-1111-1111-1111-111111111111\n22222222-2222-2222-2222-222222222222\n"
        )
        == ""
    )


def test_vcf_offline_depot_helper_invalidates_stored_id_when_readback_fails(monkeypatch, tmp_path, capsys):
    """Verify that vcf offline depot helper invalidates stored id when readback fails.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    helper = load_helper_module()
    runtime_tool_dir = tmp_path / "var" / "lib" / "atlaso" / "vcfDownloadTool" / "active-tool"
    wrapper = runtime_tool_dir / "vcf-download-tool"
    wrapper.parent.mkdir(parents=True)
    wrapper.write_text("#!/bin/sh\n", encoding="utf-8")
    wrapper.chmod(0o755)
    credential_paths = [
        runtime_tool_dir / "secrets" / "download-token.txt",
        runtime_tool_dir / "secrets" / "activation-code.txt",
    ]
    for credential_path in credential_paths:
        credential_path.parent.mkdir(parents=True, exist_ok=True)
        credential_path.write_text("non-secret-fixture", encoding="utf-8")

    def fake_run_vcfdt(command: list[str], *, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
        """Return fake run vcfdt.

        Args:
            command: Command and arguments to execute.
            input_text: Text supplied to the invoked command through standard input.
        """
        if "generate" in command:
            return subprocess.CompletedProcess(command, 0, "Software depot ID generated.\n", "")
        return subprocess.CompletedProcess(command, 5, "", "readback failed")

    monkeypatch.setattr(helper, "VCF_DEPOT_RUNTIME_TOOL_DIR", runtime_tool_dir)
    monkeypatch.setattr(helper, "_run_vcfdt_user_command", fake_run_vcfdt)

    assert helper._handle_vcf_offline_depot("generate-software-depot-id", []) == 5
    captured = capsys.readouterr()
    assert json.loads(captured.out)["software_depot_id_invalidated"] is True
    assert "readback exited with code 5" in captured.err
    assert all(not credential_path.exists() for credential_path in credential_paths)


def test_vcf_offline_depot_helper_preserves_credentials_when_generation_fails(monkeypatch, tmp_path, capsys):
    """Verify that vcf offline depot helper preserves credentials when generation fails.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    helper = load_helper_module()
    runtime_tool_dir = tmp_path / "var" / "lib" / "atlaso" / "vcfDownloadTool" / "active-tool"
    wrapper = runtime_tool_dir / "vcf-download-tool"
    wrapper.parent.mkdir(parents=True)
    wrapper.write_text("#!/bin/sh\n", encoding="utf-8")
    wrapper.chmod(0o755)
    credential_paths = [
        runtime_tool_dir / "secrets" / "download-token.txt",
        runtime_tool_dir / "secrets" / "activation-code.txt",
    ]
    for credential_path in credential_paths:
        credential_path.parent.mkdir(parents=True, exist_ok=True)
        credential_path.write_text("non-secret-fixture", encoding="utf-8")

    monkeypatch.setattr(helper, "VCF_DEPOT_RUNTIME_TOOL_DIR", runtime_tool_dir)
    monkeypatch.setattr(
        helper,
        "_run_vcfdt_user_command",
        lambda command, input_text=None: subprocess.CompletedProcess(command, 5, "", "generation failed"),
    )

    assert helper._handle_vcf_offline_depot("generate-software-depot-id", []) == 5
    assert "VCFDT exited with code 5" in capsys.readouterr().err
    assert all(credential_path.exists() for credential_path in credential_paths)


def test_vcf_offline_depot_generate_software_depot_id_main_allows_no_path(monkeypatch):
    """Verify that vcf offline depot generate software depot id main allows no path.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    helper = load_helper_module()
    calls: list[tuple[str, list[str]]] = []

    def fake_handle(action: str, args: list[str]) -> int:
        """Return fake handle.

        Args:
            action: Action supplied to the test scenario.
            args: Parsed command-line options consumed by the operation.
        """
        calls.append((action, args))
        return 0

    monkeypatch.delenv("ATLASO_HELPER_USE_SYSTEMD_RUN", raising=False)
    monkeypatch.setattr(helper, "_handle_vcf_offline_depot", fake_handle)

    assert helper.main(["atlaso-helper", "vcf-offline-depot", "generate-software-depot-id", "--real"]) == 0
    assert calls == [("generate-software-depot-id", [])]


def test_vcf_offline_depot_helper_reads_software_depot_id_without_mutation(monkeypatch, tmp_path, capsys):
    """Verify that vcf offline depot helper reads software depot id without mutation.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    helper = load_helper_module()
    runtime_tool_dir = tmp_path / "var" / "lib" / "atlaso" / "vcfDownloadTool" / "active-tool"
    wrapper = runtime_tool_dir / "vcf-download-tool"
    wrapper.parent.mkdir(parents=True)
    wrapper.write_text("#!/bin/sh\n", encoding="utf-8")
    wrapper.chmod(0o755)
    commands: list[list[str]] = []

    def fake_run_vcfdt(command: list[str], *, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
        """Return fake run vcfdt.

        Args:
            command: Command and arguments to execute.
            input_text: Text supplied to the invoked command through standard input.
        """
        commands.append(command)
        return subprocess.CompletedProcess(
            command,
            0,
            "Software Depot ID: 8c9506c6-7bdf-44d5-b2e9-50d829d66b99\n",
            "",
        )

    monkeypatch.setattr(helper, "VCF_DEPOT_RUNTIME_TOOL_DIR", runtime_tool_dir)
    monkeypatch.setattr(helper, "_run_vcfdt_user_command", fake_run_vcfdt)

    assert helper._handle_vcf_offline_depot("read-software-depot-id", []) == 0
    payload = json.loads(capsys.readouterr().out)
    assert commands == [[str(wrapper), "configuration", "get", "--software-depot-id"]]
    assert payload == {
        "software_depot_id": "8c9506c6-7bdf-44d5-b2e9-50d829d66b99",
        "vcf_offline_depot": "software depot ID read back",
    }


def test_vcf_offline_depot_read_software_depot_id_main_allows_no_path(monkeypatch):
    """Verify that vcf offline depot read software depot id main allows no path.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    helper = load_helper_module()
    calls: list[tuple[str, list[str]]] = []

    monkeypatch.delenv("ATLASO_HELPER_USE_SYSTEMD_RUN", raising=False)
    monkeypatch.setattr(helper, "_handle_vcf_offline_depot", lambda action, args: calls.append((action, args)) or 0)

    assert helper.main(["atlaso-helper", "vcf-offline-depot", "read-software-depot-id", "--real"]) == 0
    assert calls == [("read-software-depot-id", [])]


def test_vcf_offline_depot_helper_applies_vcfdt_application_properties(monkeypatch, tmp_path, capsys):
    """Verify that vcf offline depot helper applies vcfdt application properties.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "vcf-offline-depot"
    properties_path = apply_dir / "application-prodv2.properties"
    apply_dir.mkdir(parents=True)
    properties_path.write_text("spring.profiles.active=depot\nlcm.depot.adapter.host=stage.example.test\n", encoding="utf-8")
    tool_dir = tmp_path / "opt" / "atlaso" / "vcf-download-tool"
    tool_bin = tool_dir / "extracted" / "vcfdt" / "bin" / "vcf-download-tool"
    tool_bin.parent.mkdir(parents=True)
    tool_bin.write_text("#!/bin/sh\n", encoding="utf-8")
    runtime_tool_dir = tmp_path / "var" / "lib" / "atlaso" / "vcfDownloadTool" / "active-tool"
    chowned: list[tuple[Path, int, int]] = []
    chmodded: list[tuple[Path, int]] = []

    class Account:
        """Represent account.

        Attributes:
            pw_uid: Pw uid captured or supplied by this test helper.
            pw_gid: Pw gid captured or supplied by this test helper.
        """
        pw_uid = 1200
        pw_gid = 1200

    monkeypatch.setattr(helper, "VCF_DEPOT_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "VCF_DEPOT_TOOL_DIR", tool_dir)
    monkeypatch.setattr(helper, "VCF_DEPOT_RUNTIME_TOOL_DIR", runtime_tool_dir)
    monkeypatch.setattr(helper.pwd, "getpwnam", lambda username: Account())
    monkeypatch.setattr(helper, "_chown_path", lambda path, uid, gid: chowned.append((path, uid, gid)))
    real_chmod = helper.os.chmod
    monkeypatch.setattr(helper.os, "chmod", lambda path, mode: (chmodded.append((Path(path), mode)), real_chmod(path, mode))[1])

    assert helper._handle_vcf_offline_depot("apply-properties", [str(properties_path)]) == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["vcf_offline_depot"] == "application properties apply complete"
    target = tool_dir / "extracted" / "vcfdt" / "conf" / "application-prodv2.properties"
    runtime_target = runtime_tool_dir / "conf" / "application-prodv2.properties"
    assert payload["config_path"] == str(target)
    assert payload["runtime_config_path"] == str(runtime_target)
    assert target.read_text(encoding="utf-8") == properties_path.read_text(encoding="utf-8")
    assert runtime_target.read_text(encoding="utf-8") == properties_path.read_text(encoding="utf-8")
    assert (target.parent, 1200, 1200) in chowned
    assert (target, 1200, 1200) in chowned
    assert (runtime_target.parent, 1200, 1200) in chowned
    assert (runtime_target, 1200, 1200) in chowned
    assert (runtime_tool_dir, 1200, 1200) in chowned
    assert (runtime_tool_dir / "secrets", 1200, 1200) in chowned
    assert (runtime_tool_dir / "secrets", 0o700) in chmodded

    outside_path = tmp_path / "application-prodv2.properties"
    outside_path.write_text("spring.profiles.active=depot\n", encoding="utf-8")
    assert helper._handle_vcf_offline_depot("apply-properties", [str(outside_path)]) == 2


def test_vcf_offline_depot_helper_removes_disabled_nginx_site(monkeypatch, tmp_path):
    """Verify that vcf offline depot helper removes disabled nginx site.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "vcf-offline-depot"
    site_dir = tmp_path / "sites.d"
    config_path = apply_dir / "atlaso-vcf-offline-depot.conf"
    site_path = site_dir / "vcf-offline-depot.conf"
    apply_dir.mkdir(parents=True)
    site_dir.mkdir(parents=True)
    config_path.write_text("# VCF Offline Depot HTTPS endpoint is disabled.\n", encoding="utf-8")
    site_path.write_text("server { listen 443 ssl; }\n", encoding="utf-8")
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "VCF_DEPOT_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "NGINX_CONF_INCLUDE_PATH", tmp_path / "nginx" / "conf.d" / "atlaso.conf")
    monkeypatch.setattr(helper, "NGINX_MAIN_CONFIG_PATH", tmp_path / "nginx" / "nginx.conf")
    monkeypatch.setattr(helper, "NGINX_SITES_DIR", site_dir)
    monkeypatch.setattr(helper, "VCF_DEPOT_SITE_PATH", site_path)
    monkeypatch.setattr(helper, "_run", fake_run)
    monkeypatch.setattr(helper.shutil, "which", lambda command: "/usr/sbin/nginx" if command == "nginx" else None)

    assert helper._handle_vcf_offline_depot("apply-https", [str(config_path)]) == 0

    assert not site_path.exists()
    assert ["/usr/sbin/nginx", "-t"] in commands


def patch_appliance_settings_nginx_paths(monkeypatch, helper, tmp_path):
    """Return patch appliance settings nginx paths.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        helper: Helper supplied to the test scenario.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    nginx_include = tmp_path / "nginx" / "conf.d" / "atlaso.conf"
    nginx_main = tmp_path / "nginx" / "nginx.conf"
    nginx_sites = tmp_path / "nginx" / "sites.d"
    nginx_management_site = nginx_sites / "management.conf"
    nginx_main.parent.mkdir(parents=True, exist_ok=True)
    nginx_main.write_text(
        "\n".join(
            [
                "events { worker_connections 1024; }",
                "",
                "http {",
                "    include mime.types;",
                "    server {",
                "        listen 80;",
                "    }",
                "}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(helper, "NGINX_CONF_INCLUDE_PATH", nginx_include)
    monkeypatch.setattr(helper, "NGINX_MAIN_CONFIG_PATH", nginx_main)
    monkeypatch.setattr(helper, "NGINX_SITES_DIR", nginx_sites)
    monkeypatch.setattr(helper, "NGINX_MANAGEMENT_SITE_PATH", nginx_management_site)
    sshd_config_dir = tmp_path / "ssh" / "sshd_config.d"
    sshd_root_login = sshd_config_dir / "atlaso-root-login.conf"
    sshd_main = tmp_path / "ssh" / "sshd_config"
    sshd_main.parent.mkdir(parents=True, exist_ok=True)
    sshd_main.write_text("PermitRootLogin no\nPasswordAuthentication no\nSubsystem sftp /usr/libexec/sftp-server\n", encoding="utf-8")
    monkeypatch.setattr(helper, "SSHD_CONFIG_DIR", sshd_config_dir)
    monkeypatch.setattr(helper, "SSHD_MAIN_CONFIG_PATH", sshd_main)
    monkeypatch.setattr(helper, "SSHD_ROOT_LOGIN_CONFIG_PATH", sshd_root_login)
    return {
        "include": nginx_include,
        "main": nginx_main,
        "sites": nginx_sites,
        "management_site": nginx_management_site,
        "sshd_main": sshd_main,
        "sshd_root_login": sshd_root_login,
    }


def appliance_settings_json(
    *,
    resolver_mode: str = "local_dns",
    resolver_servers: list[str] | None = None,
    local_dns_enabled: bool = True,
    management_https_enabled: bool = False,
    management_https_cert_path: str = "",
    management_https_key_path: str = "",
    root_ssh_enabled: bool = False,
    vmware_ceip_enabled: bool = False,
    web_terminal_enabled: bool = False,
    web_terminal_interfaces: list[str] | None = None,
    web_terminal_addresses: list[str] | None = None,
) -> str:
    """Return appliance settings json.

    Args:
        resolver_mode: Resolver mode supplied by the caller.
        resolver_servers: Resolver servers supplied by the caller.
        local_dns_enabled: Local dns enabled supplied by the caller.
        management_https_enabled: Management https enabled supplied by the caller.
        management_https_cert_path: Filesystem path for the management https cert.
        management_https_key_path: Filesystem path for the management https key.
        root_ssh_enabled: Root ssh enabled supplied by the caller.
        vmware_ceip_enabled: Vmware ceip enabled supplied by the caller.
        web_terminal_enabled: Web terminal enabled supplied by the caller.
        web_terminal_interfaces: Web terminal interfaces supplied by the caller.
        web_terminal_addresses: Web terminal addresses supplied by the caller.
    """
    import json

    payload = {
        "fqdn": "core.atlaso.internal",
        "resolver_mode": resolver_mode,
        "resolver_servers": ["127.0.0.1"] if resolver_servers is None else resolver_servers,
        "local_dns_enabled": local_dns_enabled,
        "management_interface": "eth0",
        "management_ip": "192.168.49.1",
        "management_ip_cidr": "192.168.49.1/24",
        "management_https_enabled": management_https_enabled,
        "web_terminal_enabled": web_terminal_enabled,
        "web_terminal_interfaces": web_terminal_interfaces or [],
        "web_terminal_addresses": web_terminal_addresses or [],
        "root_ssh_enabled": root_ssh_enabled,
        "vmware_ceip_enabled": vmware_ceip_enabled,
        "management_http_port": 8000,
        "management_public_http_port": 80,
        "management_public_https_port": 443,
        "management_upstream_host": "127.0.0.1",
        "management_upstream_port": 8000,
        "management_https_cert_path": management_https_cert_path,
        "management_https_key_path": management_https_key_path,
    }
    return json.dumps(payload)


def ntpd_config_text(
    *,
    enabled: bool = True,
    server: str = "time1.google.com",
    listen_address: str = "192.168.50.1",
    allow_clients: str = "192.168.50.0/24",
    nts_server_cert_path: str = "",
    nts_server_key_path: str = "",
) -> str:
    """Return ntpd config text.

    Args:
        enabled: Whether the requested behavior is enabled.
        server: Server supplied by the caller.
        listen_address: Address on which the service should listen.
        allow_clients: Allow clients supplied by the caller.
        nts_server_cert_path: Filesystem path for the nts server cert.
        nts_server_key_path: Filesystem path for the nts server key.
    """
    restrict_lines = ["restrict default kod limited nomodify noquery"]
    if allow_clients != "any":
        restrict_lines = ["restrict default ignore"]
        for entry in allow_clients.replace(",", "\n").splitlines():
            try:
                network = ip_network(entry.strip(), strict=False)
            except ValueError:
                continue
            restrict_lines.append(
                f"restrict {network.network_address} mask {network.netmask} kod limited nomodify noquery"
            )
    return "\n".join(
        [
            "# Managed by Atlaso. Local changes may be overwritten.",
            f"# Atlaso NTP enabled: {str(enabled).lower()}",
            "# Atlaso NTP hostname: ntp.atlaso.internal",
            "# Atlaso NTP listen interfaces: eth2.50",
            f"# Atlaso NTP listen addresses: {listen_address if listen_address else 'none'}",
            f"# Atlaso NTP client allow list: {allow_clients}",
            "driftfile /var/lib/ntp/ntp.drift",
            "interface ignore wildcard",
            *([f"server {server} iburst"] if server else []),
            *([f"interface listen {listen_address}"] if listen_address else []),
            "restrict source kod limited nomodify noquery",
            *restrict_lines,
            *(["nts enable", f"nts cert {nts_server_cert_path}", f"nts key {nts_server_key_path}", "nts cookie /var/lib/ntp/nts-keys"] if nts_server_cert_path and nts_server_key_path else []),
            "",
        ]
    )


def test_appliance_settings_helper_validates_staged_json(monkeypatch, tmp_path):
    """Verify that appliance settings helper validates staged json.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "appliance-settings"
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "atlaso-settings.json"
    config_path.write_text(appliance_settings_json(), encoding="utf-8")

    monkeypatch.setattr(helper, "APPLIANCE_SETTINGS_APPLY_DIR", apply_dir)

    assert helper._handle_appliance_settings("validate", [str(config_path)]) == 0


def test_powercli_ceip_uses_all_users_scope_and_verifies_choice(monkeypatch):
    """Verify that powercli ceip uses all users scope and verifies choice.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import base64

    helper = load_helper_module()
    captured = {}

    def fake_run(command):
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        captured["command"] = command
        return subprocess.CompletedProcess(command, 0, '{"Scope":"AllUsers","ParticipateInCEIP":true}\n', "")

    monkeypatch.setattr(helper.shutil, "which", lambda name: "/usr/bin/pwsh" if name == "pwsh" else None)
    monkeypatch.setattr(helper, "_run", fake_run)

    returncode, status = helper._configure_powercli_ceip(True)

    assert returncode == 0
    assert status == "applied: AllUsers ParticipateInCEIP=true"
    script = base64.b64decode(captured["command"][-1]).decode("utf-16-le")
    assert "Set-PowerCLIConfiguration -ParticipateInCeip $true -Scope AllUsers -Confirm:$false" in script
    assert "Get-PowerCLIConfiguration -Scope AllUsers" in script


def test_powercli_ceip_skips_when_product_is_not_installed(monkeypatch):
    """Verify that powercli ceip skips when product is not installed.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    helper = load_helper_module()
    monkeypatch.setattr(helper.shutil, "which", lambda name: "/usr/bin/pwsh" if name == "pwsh" else None)
    monkeypatch.setattr(
        helper,
        "_run",
        lambda command: subprocess.CompletedProcess(command, 3, "VCF.PowerCLI is not installed\n", ""),
    )

    assert helper._configure_powercli_ceip(False) == (0, "skipped: VCF.PowerCLI is not installed")


def test_vcfdt_ceip_writes_service_owned_runtime_flag(monkeypatch, tmp_path):
    """Verify that vcfdt ceip writes service owned runtime flag.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    runtime_tool_dir = tmp_path / "active-tool"
    tool = runtime_tool_dir / "vcf-download-tool"
    tool.parent.mkdir(parents=True)
    tool.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(helper, "VCF_DEPOT_RUNTIME_TOOL_DIR", runtime_tool_dir)
    monkeypatch.setattr(helper.pwd, "getpwnam", lambda _name: (_ for _ in ()).throw(KeyError()))

    returncode, status = helper._apply_vcf_download_tool_ceip(False)

    telemetry = runtime_tool_dir / "conf" / "telemetry" / "telemetry.flag"
    assert returncode == 0
    assert status == "applied: obtu.telemetry.config=DISABLE"
    assert telemetry.read_text(encoding="utf-8") == "obtu.telemetry.config=DISABLE\n"
    if os.name != "nt":
        assert telemetry.stat().st_mode & 0o777 == 0o600


def test_vcfdt_apply_ceip_rejects_unset_choice():
    """Verify that vcfdt apply ceip rejects unset choice."""
    helper = load_helper_module()

    assert helper._apply_vcf_download_tool_ceip_choice("NOT_PROVIDED") == 2


def test_appliance_settings_helper_requires_https_cert_files(tmp_path):
    """Verify that appliance settings helper requires https cert files.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    config_path = tmp_path / "atlaso-settings.json"
    config_path.write_text(appliance_settings_json(management_https_enabled=True), encoding="utf-8")

    errors = helper._appliance_settings_config_errors(config_path)

    assert "management_https_cert_path is required when management HTTPS is enabled." in errors
    assert "management_https_key_path is required when management HTTPS is enabled." in errors


def test_appliance_settings_helper_requires_https_and_management_for_web_terminal(tmp_path):
    """Verify that appliance settings helper requires https and management for web terminal.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    config_path = tmp_path / "atlaso-settings.json"
    config_path.write_text(
        appliance_settings_json(
            web_terminal_enabled=True,
            web_terminal_interfaces=["eth2"],
            web_terminal_addresses=["192.168.87.32"],
        ),
        encoding="utf-8",
    )

    errors = helper._appliance_settings_config_errors(config_path)

    assert "web terminal requires management HTTPS." in errors
    assert "web terminal interfaces must include the management interface." in errors
    assert "web terminal addresses must include the management IP." in errors


def test_web_terminal_helper_installs_ca_trust_and_disables_without_deleting_ca(monkeypatch, tmp_path):
    """Verify that web terminal helper installs ca trust and disables without deleting ca.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    ssh_dir = tmp_path / "ssh" / "sshd_config.d"
    ssh_main = tmp_path / "ssh" / "sshd_config"
    config_dir = tmp_path / "etc" / "atlaso" / "ssh"
    runtime_dir = tmp_path / "var" / "lib" / "atlaso" / "web-terminal"
    request_dir = runtime_dir / "requests"
    dropin = ssh_dir / "atlaso-web-terminal.conf"
    ca_key = config_dir / "web-terminal-ca"
    ca_public = config_dir / "web-terminal-ca.pub"
    ssh_main.parent.mkdir(parents=True)
    ssh_main.write_text("PasswordAuthentication no\n", encoding="utf-8")
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        commands.append(command)
        if "-t" in command and "-f" in command:
            key_path = Path(command[command.index("-f") + 1])
            key_path.write_text("private", encoding="utf-8")
            Path(f"{key_path}.pub").write_text("ssh-ed25519 AAAA terminal-ca\n", encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "SSHD_CONFIG_DIR", ssh_dir)
    monkeypatch.setattr(helper, "SSHD_MAIN_CONFIG_PATH", ssh_main)
    monkeypatch.setattr(helper, "SSHD_WEB_TERMINAL_CONFIG_PATH", dropin)
    monkeypatch.setattr(helper, "WEB_TERMINAL_CONFIG_DIR", config_dir)
    monkeypatch.setattr(helper, "WEB_TERMINAL_CA_KEY_PATH", ca_key)
    monkeypatch.setattr(helper, "WEB_TERMINAL_CA_PUBLIC_KEY_PATH", ca_public)
    monkeypatch.setattr(helper, "WEB_TERMINAL_RUNTIME_DIR", runtime_dir)
    monkeypatch.setattr(helper, "WEB_TERMINAL_REQUEST_DIR", request_dir)
    monkeypatch.setattr(helper.pwd, "getpwnam", lambda _name: SimpleNamespace(pw_uid=1000, pw_gid=1000))
    monkeypatch.setattr(helper, "_chown_path", lambda *_args: None)
    monkeypatch.setattr(
        helper.shutil,
        "which",
        lambda command: {"ssh-keygen": "/usr/bin/ssh-keygen", "sshd": "/usr/sbin/sshd"}.get(command),
    )
    monkeypatch.setattr(helper, "_run", fake_run)

    assert helper._configure_web_terminal(True) == 0
    assert dropin.read_text(encoding="utf-8").endswith(f"TrustedUserCAKeys {ca_public}\n")
    assert ca_key.exists()
    assert ca_public.exists()
    assert request_dir.is_dir()
    assert ["systemctl", "restart", "sshd"] in commands

    assert helper._configure_web_terminal(False) == 0
    assert not dropin.exists()
    assert ca_key.exists()


def test_web_terminal_helper_signs_short_lived_restricted_certificate_for_non_wheel_user(monkeypatch, tmp_path, capsys):
    """Verify that web terminal helper signs short lived restricted certificate for non wheel user.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    helper = load_helper_module()
    request_dir = tmp_path / "requests"
    request_dir.mkdir()
    dropin = tmp_path / "atlaso-web-terminal.conf"
    ca_key = tmp_path / "web-terminal-ca"
    dropin.write_text("TrustedUserCAKeys test\n", encoding="utf-8")
    ca_key.write_text("private", encoding="utf-8")
    request_path = request_dir / "session_1234.json"
    request_path.write_text(
        json.dumps(
            {
                "username": "admin",
                "session_id": "session_1234",
                "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest session-key",
            }
        ),
        encoding="utf-8",
    )
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        commands.append(command)
        public_path = Path(command[-1])
        public_path.with_name("session-cert.pub").write_text(
            "ssh-ed25519-cert-v01@openssh.com AAAA signed\n",
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "WEB_TERMINAL_REQUEST_DIR", request_dir)
    monkeypatch.setattr(helper, "SSHD_WEB_TERMINAL_CONFIG_PATH", dropin)
    monkeypatch.setattr(helper, "WEB_TERMINAL_CA_KEY_PATH", ca_key)
    monkeypatch.setattr(
        helper.pwd,
        "getpwnam",
        lambda _name: SimpleNamespace(pw_shell="/usr/bin/pwsh", pw_gid=1000),
    )
    monkeypatch.setattr(
        helper.grp,
        "getgrnam",
        lambda _name: (_ for _ in ()).throw(AssertionError("Web terminal signing must not require wheel membership.")),
    )
    monkeypatch.setattr(helper.shutil, "which", lambda command: "/usr/bin/ssh-keygen" if command == "ssh-keygen" else None)
    monkeypatch.setattr(helper, "_run", fake_run)

    assert helper._handle_web_terminal("sign", [str(request_path)]) == 0
    command = commands[0]
    assert command[command.index("-V") + 1] == "-5s:+60s"
    assert "source-address=127.0.0.1/32" in command
    assert "no-port-forwarding" in command
    assert "no-agent-forwarding" in command
    assert "no-x11-forwarding" in command
    assert "no-user-rc" in command
    assert "ssh-ed25519-cert-v01@openssh.com AAAA signed" in capsys.readouterr().out
    assert not request_path.exists()


def test_public_services_helper_rejects_management_routes_in_terminal_listener(tmp_path):
    """Verify that public services helper rejects management routes in terminal listener.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    config_path = tmp_path / "public-services.conf"
    config_path.write_text(
        """# IP-scoped public service front door for non-management interfaces.
server {
  # Terminal-only HTTPS front door.
  location = /login { proxy_pass http://127.0.0.1:8000; }
  location = /logout { proxy_pass http://127.0.0.1:8000; }
  location = /terminal { proxy_pass http://127.0.0.1:8000; }
  location = /terminal/tickets { proxy_pass http://127.0.0.1:8000; }
  location = /terminal/ws {
    proxy_set_header X-Atlaso-Listener-Address $server_addr;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
  }
  location ^~ /static/ { proxy_pass http://127.0.0.1:8000; }
  location = /dashboard { proxy_pass http://127.0.0.1:8000; }
  location / { return 404; }
}
""",
        encoding="utf-8",
    )

    errors = helper._public_services_config_errors(config_path)

    assert "Public services web terminal config must not expose location = /dashboard." in errors


def test_appliance_settings_helper_rejects_invalid_json(tmp_path):
    """Verify that appliance settings helper rejects invalid json.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    config_path = tmp_path / "atlaso-settings.json"
    config_path.write_text('{"fqdn": "bad name"}', encoding="utf-8")

    errors = helper._appliance_settings_config_errors(config_path)

    assert "fqdn must be a valid fully qualified DNS name." in errors
    assert "resolver_mode must be local_dns, external, or dhcp." in errors


def test_appliance_settings_helper_accepts_dhcp_resolver_mode(tmp_path):
    """Verify that appliance settings helper accepts dhcp resolver mode.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    config_path = tmp_path / "atlaso-settings.json"
    config_path.write_text(
        appliance_settings_json(resolver_mode="dhcp", resolver_servers=[], local_dns_enabled=False),
        encoding="utf-8",
    )

    errors = helper._appliance_settings_config_errors(config_path)

    assert errors == []


def test_appliance_settings_helper_writes_management_nginx_proxy(monkeypatch, tmp_path):
    """Verify that appliance settings helper writes management nginx proxy.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "appliance-settings"
    managed_root = tmp_path / "etc" / "atlaso"
    cert_path = managed_root / "https" / "certs" / "core.atlaso.internal.crt"
    key_path = managed_root / "https" / "certs" / "core.atlaso.internal.key"
    dropin_dir = tmp_path / "systemd" / "atlaso.service.d"
    nginx_include = tmp_path / "nginx" / "conf.d" / "atlaso.conf"
    nginx_main = tmp_path / "nginx" / "nginx.conf"
    nginx_sites = tmp_path / "nginx" / "sites.d"
    nginx_management_site = nginx_sites / "management.conf"
    sshd_config_dir = tmp_path / "ssh" / "sshd_config.d"
    sshd_root_login = sshd_config_dir / "atlaso-root-login.conf"
    sshd_main = tmp_path / "ssh" / "sshd_config"
    apply_dir.mkdir(parents=True)
    cert_path.parent.mkdir(parents=True)
    nginx_main.parent.mkdir(parents=True)
    sshd_main.parent.mkdir(parents=True)
    sshd_main.write_text("PermitRootLogin no\nPasswordAuthentication no\nSubsystem sftp /usr/libexec/sftp-server\n", encoding="utf-8")
    nginx_main.write_text(
        "\n".join(
            [
                "events { worker_connections 1024; }",
                "",
                "http {",
                "    include mime.types;",
                "    server {",
                "        listen 80;",
                "    }",
                "}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    cert_path.write_text("-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n", encoding="utf-8")
    key_path.write_text("-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n", encoding="utf-8")
    config_path = apply_dir / "atlaso-settings.json"
    config_path.write_text(
        appliance_settings_json(
            management_https_enabled=True,
            management_https_cert_path=str(cert_path),
            management_https_key_path=str(key_path),
            root_ssh_enabled=True,
        ),
        encoding="utf-8",
    )
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "APPLIANCE_SETTINGS_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "CA_MANAGED_PATH_BASE", managed_root)
    monkeypatch.setattr(helper, "ATLASO_SERVICE_DROPIN_DIR", dropin_dir)
    monkeypatch.setattr(helper, "ATLASO_SERVICE_HTTPS_DROPIN_PATH", dropin_dir / "management-https.conf")
    monkeypatch.setattr(helper, "NGINX_CONF_INCLUDE_PATH", nginx_include)
    monkeypatch.setattr(helper, "NGINX_MAIN_CONFIG_PATH", nginx_main)
    monkeypatch.setattr(helper, "NGINX_SITES_DIR", nginx_sites)
    monkeypatch.setattr(helper, "NGINX_MANAGEMENT_SITE_PATH", nginx_management_site)
    monkeypatch.setattr(helper, "SSHD_CONFIG_DIR", sshd_config_dir)
    monkeypatch.setattr(helper, "SSHD_MAIN_CONFIG_PATH", sshd_main)
    monkeypatch.setattr(helper, "SSHD_ROOT_LOGIN_CONFIG_PATH", sshd_root_login)
    monkeypatch.setattr(helper.shutil, "chown", lambda *args, **kwargs: None)
    monkeypatch.setattr(helper, "_ca_key_matches_certificate", lambda certificate_pem, private_key_pem: True)
    monkeypatch.setattr(helper, "_run", fake_run)
    monkeypatch.setattr(
        helper.shutil,
        "which",
        lambda command: {
            "hostnamectl": "/usr/bin/hostnamectl",
            "systemd-run": "/usr/bin/systemd-run",
            "nginx": "/usr/sbin/nginx",
            "sshd": "/usr/sbin/sshd",
        }.get(command),
    )

    assert helper._handle_appliance_settings("apply", [str(config_path)]) == 0

    dropin = (dropin_dir / "management-https.conf").read_text(encoding="utf-8")
    assert "--host 127.0.0.1 --port 8000" in dropin
    assert "--ssl-certfile" not in dropin
    assert nginx_include.read_text(encoding="utf-8").strip().endswith(f"include {nginx_sites}/*.conf;")
    assert f"include {nginx_include};" in nginx_main.read_text(encoding="utf-8")
    management_site = nginx_management_site.read_text(encoding="utf-8")
    assert "listen 80 default_server;" in management_site
    assert "location = /ca/downloads/root-ca.pem {" in management_site
    assert "location = /ca/downloads/ca-bundle.pem {" in management_site
    assert "location / {\n    return 308 https://$host$request_uri;" in management_site
    assert "listen 443 ssl default_server;" in management_site
    assert "client_max_body_size 1g;" in management_site
    assert "client_max_body_size 512m;" not in management_site
    assert f"ssl_certificate {cert_path};" in management_site
    assert f"ssl_certificate_key {key_path};" in management_site
    assert "proxy_pass http://127.0.0.1:8000;" in management_site
    assert "proxy_set_header X-Forwarded-Proto http;" in management_site
    assert "proxy_set_header X-Forwarded-Proto https;" in management_site
    assert 'proxy_set_header X-Atlaso-Depot-Basic-User "";' in management_site
    root_login = sshd_root_login.read_text(encoding="utf-8")
    assert "PermitRootLogin yes" in root_login
    assert "PasswordAuthentication yes" in root_login
    sshd_main_text = sshd_main.read_text(encoding="utf-8")
    assert "Include /etc/ssh/sshd_config.d/*.conf" in sshd_main_text
    assert "# Atlaso manages this directive through atlaso-root-login.conf: PermitRootLogin no" in sshd_main_text
    assert "# Atlaso manages this directive through atlaso-root-login.conf: PasswordAuthentication no" in sshd_main_text
    assert ["systemctl", "daemon-reload"] in commands
    assert ["systemctl", "enable", "--now", "nginx"] in commands
    assert ["/usr/sbin/nginx", "-t"] in commands
    assert ["/usr/sbin/sshd", "-t"] in commands
    assert ["systemctl", "restart", "sshd"] in commands
    assert any(command[:5] == ["/usr/bin/systemd-run", "--quiet", "--collect", "--on-active=3", "--unit=atlaso-management-ui-restart"] for command in commands)


def test_appliance_settings_helper_writes_http_management_proxy_without_https(monkeypatch, tmp_path):
    """Verify that appliance settings helper writes http management proxy without https.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "appliance-settings"
    dropin_dir = tmp_path / "systemd" / "atlaso.service.d"
    apply_dir.mkdir(parents=True)
    nginx_paths = patch_appliance_settings_nginx_paths(monkeypatch, helper, tmp_path)
    config_path = apply_dir / "atlaso-settings.json"
    config_path.write_text(appliance_settings_json(management_https_enabled=False), encoding="utf-8")
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "APPLIANCE_SETTINGS_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "ATLASO_SERVICE_DROPIN_DIR", dropin_dir)
    monkeypatch.setattr(helper, "ATLASO_SERVICE_HTTPS_DROPIN_PATH", dropin_dir / "management-https.conf")
    monkeypatch.setattr(helper, "_run", fake_run)
    monkeypatch.setattr(
        helper.shutil,
        "which",
        lambda command: {
            "hostnamectl": "/usr/bin/hostnamectl",
            "systemd-run": "/usr/bin/systemd-run",
            "nginx": "/usr/sbin/nginx",
            "sshd": "/usr/sbin/sshd",
        }.get(command),
    )

    assert helper._handle_appliance_settings("apply", [str(config_path)]) == 0

    dropin = (dropin_dir / "management-https.conf").read_text(encoding="utf-8")
    assert "--host 127.0.0.1 --port 8000" in dropin
    management_site = nginx_paths["management_site"].read_text(encoding="utf-8")
    assert "listen 80 default_server;" in management_site
    assert "return 308 https://$host$request_uri;" not in management_site
    assert "listen 443" not in management_site
    assert "ssl_certificate" not in management_site
    assert "proxy_pass http://127.0.0.1:8000;" in management_site
    assert "proxy_set_header X-Forwarded-Proto http;" in management_site
    assert 'proxy_set_header X-Atlaso-Depot-Basic-User "";' in management_site
    root_login = nginx_paths["sshd_root_login"].read_text(encoding="utf-8")
    assert "PermitRootLogin no" in root_login
    assert "PasswordAuthentication yes" not in root_login
    assert "Include /etc/ssh/sshd_config.d/*.conf" in nginx_paths["sshd_main"].read_text(encoding="utf-8")
    assert ["systemctl", "enable", "--now", "nginx"] in commands
    assert ["/usr/sbin/nginx", "-t"] in commands
    assert ["/usr/sbin/sshd", "-t"] in commands
    assert ["systemctl", "restart", "sshd"] in commands
    assert any(command[:5] == ["/usr/bin/systemd-run", "--quiet", "--collect", "--on-active=3", "--unit=atlaso-management-ui-restart"] for command in commands)


def test_appliance_settings_helper_applies_local_resolver_without_timesyncd(monkeypatch, tmp_path):
    """Verify that appliance settings helper applies local resolver without timesyncd.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "appliance-settings"
    networkd_dir = tmp_path / "etc" / "systemd" / "network"
    dropin_dir = tmp_path / "systemd" / "atlaso.service.d"
    apply_dir.mkdir(parents=True)
    networkd_dir.mkdir(parents=True)
    mgmt_network = networkd_dir / "00-atlaso-mgmt.network"
    mgmt_network.write_text(
        "\n".join(
            [
                "[Match]",
                "Name=eth0",
                "",
                "[Network]",
                "Address=192.168.49.1/24",
                "DNS=1.1.1.1",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    config_path = apply_dir / "atlaso-settings.json"
    config_path.write_text(appliance_settings_json(), encoding="utf-8")
    patch_appliance_settings_nginx_paths(monkeypatch, helper, tmp_path)
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "APPLIANCE_SETTINGS_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "NETWORKD_MGMT_CONFIG_PATH", mgmt_network)
    monkeypatch.setattr(helper, "ATLASO_SERVICE_DROPIN_DIR", dropin_dir)
    monkeypatch.setattr(helper, "ATLASO_SERVICE_HTTPS_DROPIN_PATH", dropin_dir / "management-https.conf")
    monkeypatch.setattr(helper, "_run", fake_run)
    monkeypatch.setattr(
        helper.shutil,
        "which",
        lambda command: {
            "hostnamectl": "/usr/bin/hostnamectl",
            "nginx": "/usr/sbin/nginx",
            "sshd": "/usr/sbin/sshd",
        }.get(command),
    )

    assert helper._handle_appliance_settings("apply", [str(config_path)]) == 0

    assert ["/usr/bin/hostnamectl", "set-hostname", "core.atlaso.internal"] in commands
    assert ["resolvectl", "dns", "eth0", "127.0.0.1"] in commands
    assert ["resolvectl", "domain", "eth0", "~."] in commands
    assert ["systemctl", "enable", "--now", "systemd-timesyncd"] not in commands
    assert ["systemctl", "restart", "systemd-timesyncd"] not in commands
    network_text = mgmt_network.read_text(encoding="utf-8")
    assert "DNS=1.1.1.1" not in network_text
    assert "DNS=127.0.0.1" in network_text
    assert "Domains=~." in network_text


def test_appliance_settings_helper_applies_external_resolver_without_catchall(monkeypatch, tmp_path):
    """Verify that appliance settings helper applies external resolver without catchall.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "appliance-settings"
    networkd_dir = tmp_path / "etc" / "systemd" / "network"
    dropin_dir = tmp_path / "systemd" / "atlaso.service.d"
    apply_dir.mkdir(parents=True)
    networkd_dir.mkdir(parents=True)
    mgmt_network = networkd_dir / "00-atlaso-mgmt.network"
    mgmt_network.write_text(
        "\n".join(["[Match]", "Name=eth0", "", "[Network]", "Address=192.168.49.1/24", "DNS=127.0.0.1", "Domains=~."]) + "\n",
        encoding="utf-8",
    )
    config_path = apply_dir / "atlaso-settings.json"
    config_path.write_text(
        appliance_settings_json(resolver_mode="external", resolver_servers=["1.1.1.1", "9.9.9.9"], local_dns_enabled=False),
        encoding="utf-8",
    )
    patch_appliance_settings_nginx_paths(monkeypatch, helper, tmp_path)
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "APPLIANCE_SETTINGS_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "NETWORKD_MGMT_CONFIG_PATH", mgmt_network)
    monkeypatch.setattr(helper, "ATLASO_SERVICE_DROPIN_DIR", dropin_dir)
    monkeypatch.setattr(helper, "ATLASO_SERVICE_HTTPS_DROPIN_PATH", dropin_dir / "management-https.conf")
    monkeypatch.setattr(helper, "_run", fake_run)
    monkeypatch.setattr(
        helper.shutil,
        "which",
        lambda command: {
            "hostnamectl": "/usr/bin/hostnamectl",
            "nginx": "/usr/sbin/nginx",
            "sshd": "/usr/sbin/sshd",
        }.get(command),
    )

    assert helper._handle_appliance_settings("apply", [str(config_path)]) == 0

    assert ["/usr/bin/hostnamectl", "set-hostname", "core.atlaso.internal"] in commands
    assert ["resolvectl", "dns", "eth0", "1.1.1.1", "9.9.9.9"] in commands
    assert ["resolvectl", "domain", "eth0", ""] in commands
    network_text = mgmt_network.read_text(encoding="utf-8")
    assert "DNS=127.0.0.1" not in network_text
    assert "Domains=~." not in network_text
    assert "DNS=1.1.1.1" in network_text
    assert "DNS=9.9.9.9" in network_text


def test_ntpd_helper_rejects_invalid_staged_config(monkeypatch, tmp_path):
    """Verify that ntpd helper rejects invalid staged config.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "ntpd"
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "atlaso-ntp.conf"
    config_path.write_text(ntpd_config_text(server="bad_name", listen_address="not-an-ip", allow_clients="any, 192.168.50.0/24"), encoding="utf-8")

    monkeypatch.setattr(helper, "NTP_APPLY_DIR", apply_dir)

    errors = helper._ntpd_config_errors(config_path)

    assert "ntpd server bad_name must be an IPv4 address, IPv6 address, or fully qualified DNS name with an optional port." in errors
    assert "ntpd interface listen address not-an-ip must be a valid IP address." in errors
    assert "ntpd client allow list can use 'any' only by itself." in errors


def test_ntpd_helper_accepts_source_ports_and_rejects_invalid_or_nts_ip_sources(monkeypatch, tmp_path):
    """Verify that ntpd helper accepts source ports and rejects invalid or nts ip sources.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    monkeypatch.setattr(helper, "_ntpd_supports_nts", lambda: True)
    valid_config = tmp_path / "valid-ntp.conf"
    valid_config.write_text(
        ntpd_config_text(server="time.example.com:7443").replace(
            "server time.example.com:7443 iburst",
            "server time.example.com:7443 iburst nts\nserver [2001:db8::10]:123 iburst",
        ),
        encoding="utf-8",
    )
    assert helper._ntpd_config_errors(valid_config) == []

    invalid_port = tmp_path / "invalid-port.conf"
    invalid_port.write_text(ntpd_config_text(server="time.example.com:70000"), encoding="utf-8")
    assert "optional port" in "\n".join(helper._ntpd_config_errors(invalid_port))

    nts_ip = tmp_path / "nts-ip.conf"
    nts_ip.write_text(
        ntpd_config_text(server="192.0.2.10:4460").replace(" iburst", " iburst nts"),
        encoding="utf-8",
    )
    assert "certificate-valid DNS hostname" in "\n".join(helper._ntpd_config_errors(nts_ip))


def test_ntpd_helper_apply_installs_config_and_switches_from_timesyncd(monkeypatch, tmp_path):
    """Verify that ntpd helper apply installs config and switches from timesyncd.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "ntpd"
    config_path = apply_dir / "atlaso-ntp.conf"
    ntp_conf = tmp_path / "etc" / "ntp.conf"
    state_dir = tmp_path / "var" / "lib" / "ntp"
    apply_dir.mkdir(parents=True)
    config_path.write_text(
        ntpd_config_text(server="time.cloudflare.com").replace(
            "server time.cloudflare.com iburst",
            "server time.cloudflare.com iburst nts",
        ),
        encoding="utf-8",
    )
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "NTP_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "NTP_CONFIG_PATH", ntp_conf)
    monkeypatch.setattr(helper, "NTP_STATE_DIR", state_dir)
    monkeypatch.setattr(helper, "NTP_DRIFT_PATH", state_dir / "ntp.drift")
    monkeypatch.setattr(helper, "NTP_NTS_COOKIE_PATH", state_dir / "nts-keys")
    monkeypatch.setattr(helper, "NTP_CERT_DIR", state_dir / "certs")
    monkeypatch.setattr(helper, "_ntpd_supports_nts", lambda: True)
    monkeypatch.setattr(helper, "_ntpd_runtime_identity_errors", lambda: [])
    monkeypatch.setattr(helper.pwd, "getpwnam", lambda name: type("NtpUser", (), {"pw_uid": 123})())
    monkeypatch.setattr(helper.grp, "getgrnam", lambda name: type("NtpGroup", (), {"gr_gid": 44})())
    monkeypatch.setattr(helper.os, "chown", lambda *args: None, raising=False)
    monkeypatch.setattr(helper, "_run", fake_run)
    (state_dir / "nts-keys").mkdir(parents=True)
    (state_dir / "nts-keys" / "cookie.key").write_text("cookie", encoding="utf-8")
    (state_dir / "certs").mkdir(parents=True)
    (state_dir / "certs" / "server.crt").write_text("certificate", encoding="utf-8")

    assert helper._handle_ntpd("apply", [str(config_path)]) == 0

    assert ntp_conf.read_text(encoding="utf-8") == config_path.read_text(encoding="utf-8")
    assert "server time.cloudflare.com iburst nts" in ntp_conf.read_text(encoding="utf-8")
    assert state_dir.exists()
    assert (state_dir / "ntp.drift").read_text(encoding="utf-8") == "0.0\n"
    assert not (state_dir / "nts-keys").exists()
    assert not (state_dir / "certs").exists()
    assert ["systemctl", "disable", "--now", "systemd-timesyncd"] in commands
    assert ["systemctl", "disable", "--now", "chronyd.service"] in commands
    assert ["systemctl", "enable", "ntpd.service"] in commands
    assert ["systemctl", "restart", "ntpd.service"] in commands


def test_ntpd_helper_apply_grants_ntp_group_read_to_nts_key(monkeypatch, tmp_path):
    """Verify that ntpd helper apply grants ntp group read to nts key.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "ntpd"
    managed_root = tmp_path / "etc" / "atlaso"
    config_path = apply_dir / "atlaso-ntp.conf"
    ntp_conf = tmp_path / "etc" / "ntp.conf"
    state_dir = tmp_path / "var" / "lib" / "ntp"
    cert_path = managed_root / "ntp" / "certs" / "ntp.atlaso.internal.crt"
    key_path = managed_root / "ntp" / "certs" / "ntp.atlaso.internal.key"
    apply_dir.mkdir(parents=True)
    cert_path.parent.mkdir(parents=True)
    cert_path.write_text("-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n", encoding="utf-8")
    key_path.write_text("-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n", encoding="utf-8")
    key_path.chmod(0o600)
    config_path.write_text(
        ntpd_config_text(nts_server_cert_path=str(cert_path), nts_server_key_path=str(key_path)),
        encoding="utf-8",
    )
    commands: list[list[str]] = []
    chown_calls: list[tuple[Path, int, int]] = []

    class NTPsecGroup:
        """Represent ntpsec group.

        Attributes:
            gr_gid: Gr gid captured or supplied by this test helper.
        """
        gr_gid = 44

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "NTP_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "NTP_CONFIG_PATH", ntp_conf)
    monkeypatch.setattr(helper, "NTP_STATE_DIR", state_dir)
    monkeypatch.setattr(helper, "NTP_DRIFT_PATH", state_dir / "ntp.drift")
    monkeypatch.setattr(helper, "NTP_NTS_COOKIE_PATH", state_dir / "nts-keys")
    monkeypatch.setattr(helper, "NTP_CERT_DIR", cert_path.parent)
    monkeypatch.setattr(helper.grp, "getgrnam", lambda name: NTPsecGroup())
    monkeypatch.setattr(helper.pwd, "getpwnam", lambda name: type("NtpUser", (), {"pw_uid": 123})())
    monkeypatch.setattr(helper.os, "chown", lambda path, uid, gid: chown_calls.append((Path(path), uid, gid)), raising=False)
    monkeypatch.setattr(helper, "_ntpd_supports_nts", lambda: True)
    monkeypatch.setattr(helper, "_ntpd_runtime_identity_errors", lambda: [])
    monkeypatch.setattr(helper, "_run", fake_run)
    (state_dir / "nts-keys").mkdir(parents=True)
    (state_dir / "nts-keys" / "cookie.key").write_text("cookie", encoding="utf-8")

    assert helper._handle_ntpd("apply", [str(config_path)]) == 0

    assert (key_path, 0, 44) in chown_calls
    assert cert_path.exists()
    assert key_path.exists()
    assert (state_dir / "nts-keys" / "cookie.key").exists()
    if os.name != "nt":
        assert oct(key_path.stat().st_mode & 0o777) == "0o640"
    assert ["systemctl", "restart", "ntpd.service"] in commands


def test_ntpd_helper_rejects_missing_nts_certificate_files(monkeypatch, tmp_path):
    """Verify that ntpd helper rejects missing nts certificate files.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "ntpd"
    config_path = apply_dir / "atlaso-ntp.conf"
    apply_dir.mkdir(parents=True)
    config_path.write_text(
        ntpd_config_text(
            nts_server_cert_path=str(tmp_path / "missing.crt"),
            nts_server_key_path=str(tmp_path / "missing.key"),
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(helper, "NTP_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "_ntpd_supports_nts", lambda: True)

    errors = helper._ntpd_config_errors(config_path)

    assert f"ntpd NTS server certificate does not exist: {tmp_path / 'missing.crt'}" in errors
    assert f"ntpd NTS server key does not exist: {tmp_path / 'missing.key'}" in errors


def test_ntpd_helper_requires_complete_allowlisted_nts_server_directives(monkeypatch, tmp_path):
    """Verify that ntpd helper requires complete allowlisted nts server directives.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    monkeypatch.setattr(helper, "_ntpd_supports_nts", lambda: True)

    enable_only = tmp_path / "enable-only.conf"
    enable_only.write_text(f"{ntpd_config_text()}nts enable\n", encoding="utf-8")
    enable_errors = helper._ntpd_config_errors(enable_only)
    assert "ntpd NTS server config must include nts cert." in enable_errors
    assert "ntpd NTS server config must include nts key." in enable_errors
    assert "ntpd NTS server config must include nts cookie storage." in enable_errors

    directives_without_enable = tmp_path / "directives-without-enable.conf"
    directives_without_enable.write_text(
        "\n".join(
            [
                ntpd_config_text(),
                f"nts cert {tmp_path / 'server.crt'}",
                f"nts key {tmp_path / 'server.key'}",
                f"nts cookie {tmp_path / 'cookies'}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    errors_without_enable = helper._ntpd_config_errors(directives_without_enable)
    assert "ntpd NTS server config must include nts enable." in errors_without_enable

    unsupported = tmp_path / "unsupported.conf"
    unsupported.write_text(f"{ntpd_config_text()}nts rotate-keys automatically\n", encoding="utf-8")
    assert "unsupported ntpd NTS directive: nts rotate-keys automatically" in helper._ntpd_config_errors(unsupported)


def test_ntpd_helper_rejects_nts_when_installed_binary_lacks_support(monkeypatch, tmp_path):
    """Verify that ntpd helper rejects nts when installed binary lacks support.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "ntpd"
    config_path = apply_dir / "atlaso-ntp.conf"
    apply_dir.mkdir(parents=True)
    config_path.write_text(ntpd_config_text(server="time.cloudflare.com").replace(" iburst", " iburst nts"), encoding="utf-8")
    monkeypatch.setattr(helper, "NTP_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "_ntpd_supports_nts", lambda: False)

    errors = helper._ntpd_config_errors(config_path)

    assert "required NTPsec implementation with NTS support" in "\n".join(errors)


def test_ntpd_helper_rejects_remote_control_or_blocked_time_service(monkeypatch, tmp_path):
    """Verify that ntpd helper rejects remote control or blocked time service.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "ntpd"
    config_path = apply_dir / "atlaso-ntp.conf"
    apply_dir.mkdir(parents=True)
    config_path.write_text(
        ntpd_config_text(allow_clients="any").replace(
            "restrict default kod limited nomodify noquery",
            "restrict default noserve",
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(helper, "NTP_APPLY_DIR", apply_dir)

    errors = helper._ntpd_config_errors(config_path)

    assert "ntpd default access restriction must permit time while denying remote modification and queries." in errors


def test_ntpd_helper_logs_reads_fixed_systemd_unit(monkeypatch, capsys):
    """Verify that ntpd helper logs reads fixed systemd unit.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    helper = load_helper_module()
    commands: list[list[str]] = []
    monkeypatch.setattr(helper.shutil, "which", lambda command: "/usr/bin/journalctl" if command == "journalctl" else None)
    monkeypatch.setattr(
        helper,
        "_run",
        lambda command: commands.append(command) or subprocess.CompletedProcess(command, 0, "ntpd ready\n", ""),
    )

    assert helper._handle_ntpd("logs", []) == 0
    assert "ntpd ready" in capsys.readouterr().out
    assert commands == [["/usr/bin/journalctl", "-u", "ntpd.service", "-n", "500", "--no-pager", "--output=short-iso"]]


def test_ldap_helper_logs_reads_fixed_systemd_unit(monkeypatch, capsys):
    """Verify that ldap helper logs reads fixed systemd unit.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    helper = load_helper_module()
    commands: list[list[str]] = []
    monkeypatch.setattr(helper.shutil, "which", lambda command: "/usr/bin/journalctl" if command == "journalctl" else None)
    monkeypatch.setattr(
        helper,
        "_run",
        lambda command: commands.append(command) or subprocess.CompletedProcess(command, 0, "slapd ready\n", ""),
    )

    assert helper._handle_ldap("logs", []) == 0
    assert "slapd ready" in capsys.readouterr().out
    assert commands == [["/usr/bin/journalctl", "-u", "slapd.service", "-n", "500", "--no-pager", "--output=short-iso"]]
    assert helper._handle_ldap("logs", ["/tmp/other.log"]) == 2
    assert "does not accept a path" in capsys.readouterr().err


def test_dnsmasq_helper_logs_reads_fixed_systemd_unit(monkeypatch, capsys):
    """Verify that dnsmasq helper logs reads fixed systemd unit.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    helper = load_helper_module()
    commands: list[list[str]] = []
    monkeypatch.setattr(helper.shutil, "which", lambda command: "/usr/bin/journalctl" if command == "journalctl" else None)
    monkeypatch.setattr(
        helper,
        "_run",
        lambda command: commands.append(command) or subprocess.CompletedProcess(command, 0, "dnsmasq ready\n", ""),
    )

    assert helper._handle_dnsmasq("logs", []) == 0
    assert "dnsmasq ready" in capsys.readouterr().out
    assert commands == [["/usr/bin/journalctl", "-u", "dnsmasq.service", "-n", "500", "--no-pager", "--output=short-iso"]]


def test_nginx_helper_logs_reads_fixed_systemd_unit(monkeypatch, capsys):
    """Verify that nginx helper logs reads fixed systemd unit.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    helper = load_helper_module()
    commands: list[list[str]] = []

    monkeypatch.setattr(helper.shutil, "which", lambda command: "/usr/bin/journalctl" if command == "journalctl" else None)

    def fake_run(command, **_kwargs):
        """Return fake run.

        Args:
            command: Command and arguments to execute.
            **_kwargs: Additional keyword arguments accepted by the callable.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "nginx ready\n", "")

    monkeypatch.setattr(helper, "_run", fake_run)

    assert helper._handle_nginx("logs", []) == 0
    assert capsys.readouterr().out == "nginx ready\n"
    assert commands == [["/usr/bin/journalctl", "-u", "nginx.service", "-n", "500", "--no-pager", "--output=short-iso"]]


def test_nginx_helper_reads_only_fixed_http_log_files(monkeypatch, tmp_path, capsys):
    """Verify that nginx helper reads only fixed http log files.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    helper = load_helper_module()
    access_log = tmp_path / "access.log"
    error_log = tmp_path / "error.log"
    access_log.write_text("management request\nservice request\n", encoding="utf-8")
    error_log.write_text("upstream error\n", encoding="utf-8")
    monkeypatch.setattr(helper, "NGINX_ACCESS_LOG_PATH", access_log)
    monkeypatch.setattr(helper, "NGINX_ERROR_LOG_PATH", error_log)

    assert helper._handle_nginx("access-logs", []) == 0
    assert capsys.readouterr().out == "management request\nservice request\n"
    assert helper._handle_nginx("error-logs", []) == 0
    assert capsys.readouterr().out == "upstream error\n"
    assert helper._handle_nginx("access-logs", ["/tmp/other.log"]) == 2
    assert "does not accept a path" in capsys.readouterr().err


def test_ntpd_helper_capabilities_reports_supported_nts(monkeypatch, capsys):
    """Verify that ntpd helper capabilities reports supported nts.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    helper = load_helper_module()
    monkeypatch.setattr(helper.shutil, "which", lambda command: {"ntpd": "/usr/sbin/ntpd", "rpm": "/usr/bin/rpm"}.get(command))
    monkeypatch.setattr(
        helper,
        "_run",
        lambda command, timeout=None: subprocess.CompletedProcess(command, 0, "ntpd ntpsec-1.2.3\n" if "--version" in command else "ntpsec-1.2.3-15.ph5\n", ""),
    )

    assert helper._handle_ntpd("capabilities", []) == 0
    assert json.loads(capsys.readouterr().out)["nts"] is True


def test_ntpd_helper_capabilities_reports_unsupported_identity(monkeypatch, capsys):
    """Verify that ntpd helper capabilities reports unsupported identity.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    helper = load_helper_module()
    monkeypatch.setattr(helper.shutil, "which", lambda command: {"ntpd": "/usr/sbin/ntpd", "rpm": "/usr/bin/rpm"}.get(command))

    def fake_run(command, timeout=None):
        """Return fake run.

        Args:
            command: Command and arguments to execute or validate.
            timeout: Maximum time to wait for completion.
        """
        if "--version" in command:
            return subprocess.CompletedProcess(command, 0, "ntpd 4.2.8p15\n", "")
        return subprocess.CompletedProcess(command, 1, "", f"package {command[-1]} is not installed\n")

    monkeypatch.setattr(helper, "_run", fake_run)

    assert helper._handle_ntpd("capabilities", []) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["nts"] is False
    assert payload["errors"]


def test_ntpd_helper_capabilities_returns_unknown_when_version_probe_fails(monkeypatch, capsys):
    """Verify that ntpd helper capabilities returns unknown when version probe fails.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    helper = load_helper_module()
    monkeypatch.setattr(helper.shutil, "which", lambda command: "/usr/sbin/ntpd" if command == "ntpd" else None)
    monkeypatch.setattr(
        helper,
        "_run",
        lambda command, timeout=None: (_ for _ in ()).throw(subprocess.TimeoutExpired(command, timeout)),
    )

    assert helper._handle_ntpd("capabilities", []) == 1
    payload = json.loads(capsys.readouterr().out)
    assert "nts" not in payload
    assert "timed out" in payload["error"]


@pytest.mark.parametrize("failed_probe", ["rpm", "second-version"])
def test_ntpd_helper_capabilities_returns_unknown_when_identity_probe_fails(monkeypatch, capsys, failed_probe):
    """Verify that ntpd helper capabilities returns unknown when identity probe fails.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        capsys: Pytest fixture used to capture standard output and standard error.
        failed_probe: Failed probe supplied to the test scenario.
    """
    helper = load_helper_module()
    monkeypatch.setattr(helper.shutil, "which", lambda command: {"ntpd": "/usr/sbin/ntpd", "rpm": "/usr/bin/rpm"}.get(command))
    version_calls = 0

    def fake_run(command, timeout=None):
        """Return fake run.

        Args:
            command: Command and arguments to execute or validate.
            timeout: Maximum time to wait for completion.

        Raises:
            OSError: If the operating-system operation fails.
            TimeoutExpired: If the operation encounters an invalid state.
        """
        nonlocal version_calls
        if "--version" in command:
            version_calls += 1
            if failed_probe == "second-version" and version_calls == 2:
                raise subprocess.TimeoutExpired(command, timeout)
            return subprocess.CompletedProcess(command, 0, "ntpd ntpsec-1.2.3\n", "")
        if failed_probe == "rpm" and command[-1] == "ntpsec":
            raise OSError("temporary rpm failure")
        return subprocess.CompletedProcess(command, 0, f"{command[-1]}-1.2.3-15.ph5\n", "")

    monkeypatch.setattr(helper, "_run", fake_run)

    assert helper._handle_ntpd("capabilities", []) == 1
    payload = json.loads(capsys.readouterr().out)
    assert "nts" not in payload
    assert payload["error"] == "NTPsec capability identity probe failed"
    assert payload["errors"]


def test_ntpd_helper_requires_photon_package_and_ntpsec_binary_identity(monkeypatch):
    """Verify that ntpd helper requires photon package and ntpsec binary identity.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    helper = load_helper_module()
    monkeypatch.setattr(helper.shutil, "which", lambda command: {"ntpd": "/usr/sbin/ntpd", "rpm": "/usr/bin/rpm"}.get(command))

    def fake_run(command, timeout=None):
        """Return fake run.

        Args:
            command: Command and arguments to execute or validate.
            timeout: Maximum time to wait for completion.
        """
        if command[-2:] in (["-q", "ntpsec"], ["-q", "python3-ntp"]):
            return subprocess.CompletedProcess(command, 1, "", f"package {command[-1]} is not installed\n")
        return subprocess.CompletedProcess(command, 0, "ntpd 4.2.8p15\n", "")

    monkeypatch.setattr(helper, "_run", fake_run)

    assert helper._ntpd_runtime_identity_errors() == [
        "Photon ntpsec package is required.",
        "Photon python3-ntp package is required for ntpq.",
        "installed ntpd is not Photon NTPsec.",
    ]


def test_ntpd_helper_disabled_apply_stops_ntpd_without_installing_config(monkeypatch, tmp_path):
    """Verify that ntpd helper disabled apply stops ntpd without installing config.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "ntpd"
    config_path = apply_dir / "atlaso-ntp.conf"
    ntp_conf = tmp_path / "etc" / "ntp.conf"
    apply_dir.mkdir(parents=True)
    config_path.write_text(ntpd_config_text(enabled=False, listen_address="", allow_clients="any"), encoding="utf-8")
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "NTP_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "NTP_CONFIG_PATH", ntp_conf)
    monkeypatch.setattr(helper, "_run", fake_run)

    assert helper._handle_ntpd("apply", [str(config_path)]) == 0

    assert not ntp_conf.exists()
    assert commands == [["systemctl", "disable", "--now", "ntpd.service"]]


def test_ntpd_helper_disabled_apply_allows_empty_upstream_list(monkeypatch, tmp_path):
    """Verify that ntpd helper disabled apply allows empty upstream list.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "ntpd"
    config_path = apply_dir / "atlaso-ntp.conf"
    ntp_conf = tmp_path / "etc" / "ntp.conf"
    apply_dir.mkdir(parents=True)
    config_path.write_text(ntpd_config_text(enabled=False, server="", listen_address="", allow_clients="any"), encoding="utf-8")
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "NTP_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "NTP_CONFIG_PATH", ntp_conf)
    monkeypatch.setattr(helper, "_run", fake_run)

    assert helper._handle_ntpd("apply", [str(config_path)]) == 0

    assert not ntp_conf.exists()
    assert commands == [["systemctl", "disable", "--now", "ntpd.service"]]


def test_ntpd_helper_status_reads_peers_variables_and_nts(monkeypatch, capsys):
    """Verify that ntpd helper status reads peers variables and nts.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    helper = load_helper_module()
    commands: list[tuple[list[str], float | None]] = []

    def fake_run(command: list[str], *, timeout: float | None = None) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute or validate.
            timeout: Maximum time to wait for completion.
        """
        commands.append((command, timeout))
        return subprocess.CompletedProcess(command, 0, f"{' '.join(command[2:])} ok\n", "")

    monkeypatch.setattr(helper.shutil, "which", lambda command: "/usr/bin/ntpq" if command == "ntpq" else None)
    monkeypatch.setattr(helper, "_run", fake_run)

    assert helper._handle_ntpd("status", []) == 0

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["peers"]["stdout"] == " ok\n"
    assert payload["variables"]["stdout"] == "rv ok\n"
    assert payload["nts"]["stdout"] == "ntsinfo ok\n"
    assert commands == [
        (["/usr/bin/ntpq", "-pn"], 1.5),
        (["/usr/bin/ntpq", "-c", "rv"], 1.5),
        (["/usr/bin/ntpq", "-c", "ntsinfo"], 1.5),
    ]


def test_ntpd_helper_status_reports_timeout_without_blocking(monkeypatch, capsys):
    """Verify that ntpd helper status reports timeout without blocking.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    helper = load_helper_module()

    def fake_run(command: list[str], *, timeout: float | None = None) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute or validate.
            timeout: Maximum time to wait for completion.

        Raises:
            TimeoutExpired: If the operation encounters an invalid state.
        """
        raise subprocess.TimeoutExpired(command, timeout)

    monkeypatch.setattr(helper.shutil, "which", lambda command: "/usr/bin/ntpq" if command == "ntpq" else None)
    monkeypatch.setattr(helper, "_run", fake_run)

    assert helper._handle_ntpd("status", []) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["peers"]["returncode"] == 124
    assert payload["variables"]["returncode"] == 124
    assert payload["nts"]["stderr"] == "ntpq status command timed out after 1.5 seconds"


def test_appliance_settings_hostname_fallback_writes_etc_hostname(monkeypatch, tmp_path):
    """Verify that appliance settings hostname fallback writes etc hostname.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    hostname_path = tmp_path / "hostname"
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper.shutil, "which", lambda command: "/usr/bin/hostname" if command == "hostname" else None)
    monkeypatch.setattr(helper, "_run", fake_run)
    monkeypatch.setattr(helper, "Path", lambda value: hostname_path if value == "/etc/hostname" else Path(value))

    assert helper._apply_hostname("fallback.atlaso.internal") == 0

    assert hostname_path.read_text(encoding="utf-8") == "fallback.atlaso.internal\n"
    assert commands == [["/usr/bin/hostname", "fallback.atlaso.internal"]]


def test_esx_storage_existing_bind_mount_is_recognized_by_inode(monkeypatch):
    """Verify that esx storage existing bind mount is recognized by inode.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    helper = load_helper_module()
    source = Path("/mnt/atlaso-esx-storage/data/share")
    target = Path("/srv/atlaso/esx-storage/share")
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, str(target), "")

    def fake_stat(path: os.PathLike[str], *, follow_symlinks: bool = True) -> SimpleNamespace:
        """Return fake stat.

        Args:
            path: Filesystem or URL path to read, validate, or update.
            follow_symlinks: Follow symlinks supplied by the caller.
        """
        assert follow_symlinks is True
        assert Path(path) in {source, target}
        return SimpleNamespace(st_dev=2049, st_ino=8192)

    monkeypatch.setattr(helper, "_run", fake_run)
    monkeypatch.setattr(helper.os, "stat", fake_stat)

    assert helper._esx_storage_bind_mount_matches("/usr/bin/findmnt", source, target) is True
    assert commands == [["/usr/bin/findmnt", "-n", "--mountpoint", str(target)]]


def test_esx_storage_rejects_wrong_mount_at_bind_target(monkeypatch):
    """Verify that esx storage rejects wrong mount at bind target.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    helper = load_helper_module()
    source = Path("/mnt/atlaso-esx-storage/data/share")
    target = Path("/srv/atlaso/esx-storage/share")

    monkeypatch.setattr(
        helper,
        "_run",
        lambda command: subprocess.CompletedProcess(command, 0, str(target), ""),
    )
    monkeypatch.setattr(
        helper.os,
        "stat",
        lambda path, *, follow_symlinks=True: SimpleNamespace(
            st_dev=2049,
            st_ino=8192 if Path(path) == source else 16384,
        ),
    )

    with pytest.raises(ValueError, match="does not match ESX Storage source"):
        helper._esx_storage_bind_mount_matches("/usr/bin/findmnt", source, target)
