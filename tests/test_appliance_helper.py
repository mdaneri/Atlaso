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


HELPER_PATH = Path(__file__).resolve().parents[1] / "scripts" / "appliance" / "labfoundry-helper"


def load_helper_module():
    loader = importlib.machinery.SourceFileLoader("labfoundry_helper", str(HELPER_PATH))
    spec = importlib.util.spec_from_loader("labfoundry_helper", loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def test_appliance_power_helper_schedules_reboot(monkeypatch):
    helper = load_helper_module()
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "scheduled\n", "")

    monkeypatch.setattr(helper, "_command_path", lambda command: "/usr/bin/systemctl" if command == "systemctl" else None)
    monkeypatch.setattr(helper.shutil, "which", lambda command: "/usr/bin/systemd-run" if command == "systemd-run" else None)
    monkeypatch.setattr(helper, "_run", fake_run)

    assert helper._handle_appliance_power("reboot", []) == 0
    assert len(commands) == 1
    command = commands[0]
    assert command[:3] == ["/usr/bin/systemd-run", "--quiet", "--on-active=5"]
    assert command[3].startswith("--unit=labfoundry-reboot-")
    assert command[-2:] == ["/usr/bin/systemctl", "reboot"]


def test_appliance_power_helper_maps_shutdown_to_poweroff(monkeypatch):
    helper = load_helper_module()
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "_command_path", lambda command: "/usr/bin/systemctl" if command == "systemctl" else None)
    monkeypatch.setattr(helper.shutil, "which", lambda command: "/usr/bin/systemd-run" if command == "systemd-run" else None)
    monkeypatch.setattr(helper, "_run", fake_run)

    assert helper._handle_appliance_power("shutdown", []) == 0
    assert commands[0][-2:] == ["/usr/bin/systemctl", "poweroff"]


def test_appliance_power_helper_fails_closed_without_systemd_run(monkeypatch, capsys):
    helper = load_helper_module()
    commands: list[list[str]] = []
    monkeypatch.setattr(helper, "_command_path", lambda command: "/usr/bin/systemctl" if command == "systemctl" else None)
    monkeypatch.setattr(helper.shutil, "which", lambda _command: None)
    monkeypatch.setattr(helper, "_run", lambda command: commands.append(command))

    assert helper._handle_appliance_power("shutdown", []) == 127
    assert commands == []
    assert "refusing an immediate appliance power action" in capsys.readouterr().err


def ldap_payload(*, enabled: bool = False) -> dict:
    suffix = "dc=org-a,dc=ldap,dc=labfoundry,dc=internal"
    user_dn = f"uid=operator,ou=users,{suffix}"
    return {
        "schema_version": 1,
        "service": {
            "enabled": enabled,
            "hostname": "ldap.labfoundry.internal",
            "listen_interface": "eth0",
            "listen_address": "192.168.49.1",
            "ldaps_enabled": True,
            "port": 636,
            "ldap_enabled": False,
            "ldap_port": 389,
            "certificate_path": "/etc/labfoundry/ldap/tls/server.crt",
            "key_path": "/etc/labfoundry/ldap/tls/server.key",
            "chain_path": "/etc/labfoundry/ldap/tls/server-chain.crt",
            "root_ca_path": "/etc/labfoundry/ca/root.crt",
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
    helper = load_helper_module()
    payload = ldap_payload()

    assert helper._ldap_config_errors(payload) == []
    config = helper._render_ldap_slapd_config(payload)
    assert "database mdb" in config
    assert 'suffix "dc=org-a,dc=ldap,dc=labfoundry,dc=internal"' in config
    assert "overlay ppolicy" in config
    assert "overlay memberof" in config
    assert "overlay refint" in config
    assert "modulepath /usr/lib/openldap" in config
    assert "moduleload ppolicy.so" in config
    assert "ppolicy.schema" not in config
    assert 'by dn.exact="uid=vcf-bind,ou=service-accounts,dc=org-a,dc=ldap,dc=labfoundry,dc=internal" read' in config
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


def test_plaintext_only_ldap_validation_does_not_require_tls_files(monkeypatch):
    helper = load_helper_module()
    payload = ldap_payload(enabled=True)
    payload["service"].update({"ldaps_enabled": False, "ldap_enabled": True, "ldap_port": 1389})
    monkeypatch.setattr(helper.shutil, "which", lambda command: f"/usr/bin/{command}")

    errors = helper._ldap_config_errors(payload)

    assert not any("LDAP certificate" in error or "LDAP private key" in error or "LDAP root CA" in error for error in errors)
    assert errors == []


def test_ldap_render_can_use_isolated_validation_data_root(tmp_path):
    helper = load_helper_module()
    payload = ldap_payload()
    config = helper._render_ldap_slapd_config(payload, state_root=tmp_path / "validation-data")

    assert f"directory {tmp_path / 'validation-data' / 'org-a'}" in config
    assert str(helper.LDAP_STATE_DIR / "org-a") not in config


def test_ldap_render_can_use_isolated_validation_runtime_root(tmp_path):
    helper = load_helper_module()
    payload = ldap_payload()
    runtime_root = tmp_path / "validation-run"

    config = helper._render_ldap_slapd_config(payload, runtime_root=runtime_root)

    assert f"pidfile {runtime_root / 'slapd.pid'}" in config
    assert f"argsfile {runtime_root / 'slapd.args'}" in config
    assert "/run/openldap/slapd.pid" not in config


def test_ldap_runtime_directory_is_created_for_first_apply(monkeypatch, tmp_path):
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
    helper = load_helper_module()
    payload = ldap_payload(enabled=True)
    suffix = payload["organizations"][0]["suffix_dn"]
    ldif_path = tmp_path / "org-a.ldif"
    ldif_path.write_text(f"dn: {suffix}\nobjectClass: domain\ndc: org-a\n", encoding="utf-8")
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "format": "labfoundry-ldap-slapcat-v1",
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
    helper = load_helper_module()
    dropin_dir = tmp_path / "slapd.service.d"
    dropin_path = dropin_dir / "labfoundry.conf"
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
    helper = load_helper_module()
    dropin_dir = tmp_path / "slapd.service.d"
    dropin_path = dropin_dir / "labfoundry.conf"
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


def test_ldap_directory_queries_disable_ldif_wrapping(monkeypatch):
    helper = load_helper_module()
    commands: list[list[str]] = []

    def fake_run(command: list[str]):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper.shutil, "which", lambda command: f"/usr/bin/{command}")
    monkeypatch.setattr(helper, "_run", fake_run)

    helper._ldap_entry_exists("uid=operator,ou=users,dc=org-a,dc=ldap,dc=labfoundry,dc=internal")
    helper._ldap_list_dns("ou=groups,dc=org-a,dc=ldap,dc=labfoundry,dc=internal")

    assert all(["-o", "ldif-wrap=no"] == command[2:4] for command in commands)


def test_ldap_helper_rejects_missing_service_account_mapping_and_group_cycle():
    helper = load_helper_module()
    payload = ldap_payload()
    payload["organizations"][0]["vcf_settings"]["definedSettings"]["userAttributes"].pop("serviceAccount")
    payload["organizations"][0]["groups"] = [
        {
            "id": 1,
            "name": "First",
            "dn": "cn=First,ou=groups,dc=org-a,dc=ldap,dc=labfoundry,dc=internal",
            "enabled": True,
            "members": [{"type": "group", "id": 2, "dn": "cn=Second,ou=groups,dc=org-a,dc=ldap,dc=labfoundry,dc=internal"}],
        },
        {
            "id": 2,
            "name": "Second",
            "dn": "cn=Second,ou=groups,dc=org-a,dc=ldap,dc=labfoundry,dc=internal",
            "enabled": True,
            "members": [{"type": "group", "id": 1, "dn": "cn=First,ou=groups,dc=org-a,dc=ldap,dc=labfoundry,dc=internal"}],
        },
    ]

    errors = helper._ldap_config_errors(payload)
    assert any("serviceAccount" in error for error in errors)
    assert any("cycle" in error for error in errors)


def kms_config_text(managed_root: Path, *, enabled: bool = True, database_path: Path | None = None) -> str:
    database_path = database_path or Path("/var/lib/labfoundry/kms/pykmip.db")
    return "\n".join(
        [
            "# Managed by LabFoundry. Local changes may be overwritten.",
            f"# LabFoundry KMS enabled: {str(enabled).lower()}",
            "# LabFoundry KMS endpoint hostname: kms.labfoundry.internal",
            "# Backend: PyKMIP lab KMIP server desired state.",
            "[server]",
            "hostname=192.168.50.1",
            "port=5696",
            f"certificate_path={managed_root / 'kms' / 'certs' / 'kms.labfoundry.internal.crt'}",
            f"key_path={managed_root / 'kms' / 'certs' / 'kms.labfoundry.internal.key'}",
            f"ca_path={managed_root / 'ca' / 'root.crt'}",
            "auth_suite=TLS1.2",
            f"policy_path={managed_root / 'kms' / 'policies'}",
            "enable_tls_client_auth=True",
            "logging_level=INFO",
            f"database_path={database_path}",
            "",
        ]
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
    return "\n".join(
        [
            "# Managed by LabFoundry. Local changes may be overwritten.",
            "# IP-scoped public service front door for non-management interfaces.",
            "server {",
            "  listen 192.168.87.32:80;",
            "  server_name _;",
            "  location /pxe/esxi/ks/ {",
            "    proxy_pass http://127.0.0.1:8000;",
            "  }",
            "  location /pxe/esxi/ {",
            "    alias /var/lib/labfoundry/pxe/http/esxi/;",
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
    return "\n".join(
        [
            "# Managed by LabFoundry. Local changes may be overwritten.",
            "# IP-scoped public service front door for non-management interfaces.",
            "server {",
            "  # CA portal HTTPS front door.",
            "  listen 192.168.87.32:443 ssl;",
            "  server_name ca.labfoundry.internal;",
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
    return "\n".join(
        [
            "# Managed by LabFoundry. Local changes may be overwritten.",
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
            "    alias /mnt/labfoundry-vcf-offline-depot/PROD/$1;",
            "  }",
            "}",
            "",
        ]
    )


def test_public_services_helper_validates_staged_nginx_config(monkeypatch, tmp_path, capsys):
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "public-services"
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "labfoundry-public-services.conf"
    config_path.write_text(public_services_config_text(), encoding="utf-8")
    monkeypatch.setattr(helper, "PUBLIC_SERVICES_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "VCF_DEPOT_PROD_PATH", Path("/mnt/labfoundry-vcf-offline-depot/PROD"))

    result = helper._handle_public_services("validate", [str(config_path)])

    captured = capsys.readouterr()
    assert result == 0
    assert "validation ok" in captured.out


def test_public_services_helper_allows_ip_scoped_depot_https_paths(monkeypatch, tmp_path, capsys):
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "public-services"
    managed_root = tmp_path / "managed"
    cert_path = managed_root / "ca-portal" / "certs" / "ca.labfoundry.internal.crt"
    key_path = managed_root / "ca-portal" / "certs" / "ca.labfoundry.internal.key"
    cert_path.parent.mkdir(parents=True)
    cert_path.write_text("-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n", encoding="utf-8")
    key_path.write_text("-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n", encoding="utf-8")
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "labfoundry-public-services.conf"
    config_path.write_text(public_services_ip_https_depot_config_text(cert_path, key_path), encoding="utf-8")
    monkeypatch.setattr(helper, "PUBLIC_SERVICES_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "CA_MANAGED_PATH_BASE", managed_root)
    monkeypatch.setattr(helper, "VCF_DEPOT_PROD_PATH", Path("/mnt/labfoundry-vcf-offline-depot/PROD"))

    result = helper._handle_public_services("validate", [str(config_path)])

    captured = capsys.readouterr()
    assert result == 0
    assert "validation ok" in captured.out


def test_public_services_helper_validates_ca_https_sni_config(monkeypatch, tmp_path, capsys):
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "public-services"
    managed_root = tmp_path / "managed"
    cert_path = managed_root / "ca-portal" / "certs" / "ca.labfoundry.internal.crt"
    key_path = managed_root / "ca-portal" / "certs" / "ca.labfoundry.internal.key"
    cert_path.parent.mkdir(parents=True)
    cert_path.write_text("-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n", encoding="utf-8")
    key_path.write_text("-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n", encoding="utf-8")
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "labfoundry-public-services.conf"
    config_path.write_text(public_services_ca_https_config_text(cert_path, key_path), encoding="utf-8")
    monkeypatch.setattr(helper, "PUBLIC_SERVICES_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "CA_MANAGED_PATH_BASE", managed_root)

    result = helper._handle_public_services("validate", [str(config_path)])

    captured = capsys.readouterr()
    assert result == 0
    assert "validation ok" in captured.out


def test_nginx_site_conflict_detects_duplicate_sni_name_on_same_listener(monkeypatch, tmp_path):
    helper = load_helper_module()
    sites_dir = tmp_path / "sites.d"
    sites_dir.mkdir()
    existing = sites_dir / "vcf-offline-depot.conf"
    existing.write_text(
        "\n".join(
            [
                "server {",
                "  listen 192.168.87.32:443 ssl;",
                "  server_name ca.labfoundry.internal;",
                "}",
            ]
        ),
        encoding="utf-8",
    )
    candidate = "\n".join(
        [
            "server {",
            "  listen 192.168.87.32:443 ssl;",
            "  server_name ca.labfoundry.internal;",
            "}",
        ]
    )
    monkeypatch.setattr(helper, "NGINX_SITES_DIR", sites_dir)

    assert "duplicates server_name ca.labfoundry.internal" in helper._nginx_site_conflict(sites_dir / "public-services.conf", candidate)


def test_nginx_listen_parser_requires_brackets_for_ipv6_literals():
    helper = load_helper_module()

    assert helper._listen_address_and_port("[fd87::254]:443 ssl") == ("fd87::254", 443)
    with pytest.raises(ValueError, match="IPv6 listen address must be bracketed"):
        helper._listen_address_and_port("fd87::254:443 ssl")


def test_public_services_helper_rejects_broad_root_and_registry_proxy(monkeypatch, tmp_path, capsys):
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "public-services"
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "labfoundry-public-services.conf"
    config_path.write_text(
        public_services_config_text().replace("  location / {", "  root /mnt/labfoundry-vcf-offline-depot;\n  location /registry {\n    proxy_pass http://127.0.0.1:8080;\n  }\n  location / {"),
        encoding="utf-8",
    )
    monkeypatch.setattr(helper, "PUBLIC_SERVICES_APPLY_DIR", apply_dir)

    result = helper._handle_public_services("validate", [str(config_path)])

    captured = capsys.readouterr()
    assert result == 2
    assert "must not expose a broad server root" in captured.err
    assert "must not add registry proxy locations" in captured.err


def test_public_services_helper_apply_installs_site(monkeypatch, tmp_path, capsys):
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "public-services"
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "labfoundry-public-services.conf"
    config_text = public_services_config_text()
    config_path.write_text(config_text, encoding="utf-8")
    site_path = tmp_path / "sites" / "public-services.conf"
    calls: list[tuple[Path, str]] = []

    def fake_install(path, text):
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
        "kind": "labfoundry-esxi-pxe",
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


def ca_payload_text(root_dir: Path) -> str:
    root_cert = "-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----\n"
    cert = "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n"
    key = "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n"
    crl = "-----BEGIN X509 CRL-----\ncrl\n-----END X509 CRL-----\n"
    return json.dumps(
        {
            "enabled": True,
            "root": {
                "common_name": "LabFoundry Internal Root CA",
                "certificate_pem": root_cert,
                "private_key_pem": key,
                "root_cert_path": str(root_dir / "ca" / "root-ca.pem"),
                "legacy_root_cert_path": str(root_dir / "ca" / "root.crt"),
                "ca_bundle_path": str(root_dir / "ca" / "ca-bundle.pem"),
                "crl_path": str(root_dir / "ca" / "labfoundry-ca.crl"),
                "crl_pem": crl,
            },
            "certificates": [
                {
                    "common_name": "kms.labfoundry.internal",
                    "managed_owner": "kms:server",
                    "certificate_pem": cert,
                    "chain_pem": cert + root_cert,
                    "private_key_pem": key,
                    "cert_path": str(root_dir / "kms" / "certs" / "kms.labfoundry.internal.crt"),
                    "key_path": str(root_dir / "kms" / "certs" / "kms.labfoundry.internal.key"),
                    "chain_path": str(root_dir / "kms" / "certs" / "kms.labfoundry.internal-chain.pem"),
                }
            ],
        }
    )


def test_network_helper_validates_vlan_parent_must_be_trunk(tmp_path):
    helper = load_helper_module()
    config_path = tmp_path / "labfoundry-network.conf"
    config_path.write_text(network_config_text(eth2_mode="access"), encoding="utf-8")

    errors = helper._network_config_errors(config_path)

    assert "VLAN eth2.20 parent eth2 is not marked trunk." in errors


def test_network_helper_accepts_valid_vlan_config(tmp_path):
    helper = load_helper_module()
    config_path = tmp_path / "labfoundry-network.conf"
    config_path.write_text(network_config_text(), encoding="utf-8")

    assert helper._network_config_errors(config_path) == []


def test_network_helper_validates_explicit_management_gateway(tmp_path):
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
    helper = load_helper_module()
    config_path = tmp_path / "management-gateway.conf"
    config_path.write_text(network_config_text(management_gateway="192.168.49.254"), encoding="utf-8")
    monkeypatch.setattr(helper, "NETWORKD_MGMT_CONFIG_PATH", tmp_path / "missing.network")
    monkeypatch.setattr(helper, "_runtime_default_gateways_for_interface", lambda _interface_name: [])
    monkeypatch.setattr(helper.shutil, "which", lambda command: f"/usr/sbin/{command}" if command == "ip" else None)

    files, _links, _admin_down = helper._systemd_networkd_files(config_path)

    rendered = files["00-labfoundry-mgmt.network"]
    assert "From=192.168.49.0/24" in rendered
    assert rendered.count("Gateway=192.168.49.254") == 2
    assert "Table=100" in rendered


def test_network_helper_rejects_static_management_without_ipv4(tmp_path):
    helper = load_helper_module()
    config_path = tmp_path / "labfoundry-network.conf"
    config_path.write_text(network_config_text().replace("  ip_cidr=192.168.49.1/24", "  ip_cidr=", 1), encoding="utf-8")

    errors = helper._network_config_errors(config_path)

    assert "Interface eth0 must set an IPv4 CIDR when IPv4 method is static." in errors


def test_network_helper_requires_eth0_management(tmp_path):
    helper = load_helper_module()
    config_path = tmp_path / "labfoundry-network.conf"
    config_path.write_text(network_config_text().replace("interface=eth0", "interface=eth1", 1), encoding="utf-8")

    errors = helper._network_config_errors(config_path)

    assert "Network config must keep eth0 as the management physical interface." in errors


def test_network_helper_renders_dual_stack_networkd_addresses(tmp_path):
    helper = load_helper_module()
    config_path = tmp_path / "labfoundry-network.conf"
    config_path.write_text(network_config_text(dual_stack=True), encoding="utf-8")

    assert helper._network_config_errors(config_path) == []
    files, _reconfigure_links, _admin_down_links = helper._systemd_networkd_files(config_path)

    assert "Address=192.168.49.1/24" in files["00-labfoundry-mgmt.network"]
    assert "Address=2001:db8:49::1/64" in files["00-labfoundry-mgmt.network"]
    assert "IPv6AcceptRA=no" in files["00-labfoundry-mgmt.network"]
    assert "LinkLocalAddressing=ipv6" in files["00-labfoundry-mgmt.network"]
    vlan_network = files["10-labfoundry-eth2.20.network"]
    assert "Address=192.168.20.1/24" in vlan_network
    assert "Address=2001:db8:20::1/64" in vlan_network


def test_network_helper_replaces_stale_preserved_management_gateway(monkeypatch, tmp_path):
    helper = load_helper_module()
    config_path = tmp_path / "labfoundry-network.conf"
    config_path.write_text(
        network_config_text()
        .replace("  ip_cidr=192.168.49.1/24", "  ip_cidr=192.168.1.10/24", 1)
        .replace("  gateway=\n", "", 1),
        encoding="utf-8",
    )
    management_network = tmp_path / "00-labfoundry-mgmt.network"
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
        if command == ["ip", "route", "show", "default", "dev", "eth0"]:
            return subprocess.CompletedProcess(command, 0, "default via 192.168.1.1 dev eth0\n", "")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "NETWORKD_MGMT_CONFIG_PATH", management_network)
    monkeypatch.setattr(helper, "_run", fake_run)
    monkeypatch.setattr(helper.shutil, "which", lambda command: f"/usr/sbin/{command}" if command == "ip" else None)

    files, _reconfigure_links, _admin_down_links = helper._systemd_networkd_files(config_path)

    rendered = files["00-labfoundry-mgmt.network"]
    assert "Gateway=192.168.1.1" in rendered
    assert "Gateway=192.168.167.2" not in rendered
    assert "From=192.168.1.0/24" in rendered
    assert "Table=100" in rendered


def test_network_helper_omits_management_policy_rule_without_default_gateway(monkeypatch, tmp_path):
    helper = load_helper_module()
    config_path = tmp_path / "labfoundry-network.conf"
    config_path.write_text(
        network_config_text().replace("  ip_cidr=192.168.49.1/24", "  ip_cidr=192.168.1.10/24", 1),
        encoding="utf-8",
    )

    monkeypatch.setattr(helper, "NETWORKD_MGMT_CONFIG_PATH", tmp_path / "missing.network")
    monkeypatch.setattr(helper, "_runtime_default_gateways_for_interface", lambda _interface_name: [])
    monkeypatch.setattr(helper.shutil, "which", lambda command: f"/usr/sbin/{command}" if command == "ip" else None)

    files, _reconfigure_links, _admin_down_links = helper._systemd_networkd_files(config_path)

    rendered = files["00-labfoundry-mgmt.network"]
    assert "Address=192.168.1.10/24" in rendered
    assert "[RoutingPolicyRule]" not in rendered
    assert "Table=100" not in rendered
    assert "Gateway=" not in rendered


def test_network_helper_renders_management_dhcp_networkd(tmp_path):
    helper = load_helper_module()
    config_path = tmp_path / "labfoundry-network.conf"
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

    management_network = files["00-labfoundry-mgmt.network"]
    assert "DHCP=ipv4" in management_network
    assert "Address=" not in management_network
    assert "IPv6AcceptRA=no" in management_network
    assert "LinkLocalAddressing=no" in management_network


def test_network_helper_preserves_automatic_ipv6_for_management(tmp_path):
    helper = load_helper_module()
    config_path = tmp_path / "labfoundry-network.conf"
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

    management_network = files["00-labfoundry-mgmt.network"]
    assert "DHCP=ipv4" in management_network
    assert "IPv6AcceptRA=yes" in management_network
    assert "LinkLocalAddressing=ipv6" in management_network


def test_network_helper_renders_static_management_ipv6_gateway_in_main_and_table_100(tmp_path):
    helper = load_helper_module()
    config_path = tmp_path / "labfoundry-network.conf"
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
    rendered = files["00-labfoundry-mgmt.network"]
    assert "IPv6AcceptRA=no" in rendered
    assert "LinkLocalAddressing=ipv6" in rendered
    assert "Address=2001:db8:49::10/64" in rendered
    assert "From=2001:db8:49::/64" in rendered
    assert rendered.count("Gateway=fe80::1") == 2
    assert "Table=100" in rendered


def test_wan_helper_rejects_config_outside_apply_dir(tmp_path):
    helper = load_helper_module()
    config_path = tmp_path / "labfoundry-wan.conf"
    config_path.write_text(wan_config_text(), encoding="utf-8")

    try:
        helper._validate_wan_config_path(str(config_path))
    except ValueError as exc:
        assert "WAN config must be staged under" in str(exc)
    else:
        raise AssertionError("WAN config outside apply directory should be rejected")


def test_wan_helper_validates_routes_nat_and_netem(tmp_path):
    helper = load_helper_module()
    config_path = tmp_path / "labfoundry-wan.conf"
    config_path.write_text(wan_config_text(), encoding="utf-8")

    assert helper._wan_config_errors(config_path) == []
    nat_config = helper._render_wan_nat_config(helper._parse_wan_config(config_path)["nat_rules"])
    assert "table ip labfoundry_nat" in nat_config
    assert 'ip saddr 192.168.50.0/24 oifname "eth1.20" masquerade' in nat_config


def test_wan_helper_rejects_bad_nat_source_and_target(tmp_path):
    helper = load_helper_module()
    bad_source = tmp_path / "bad-source.conf"
    bad_source.write_text(wan_config_text(bad_nat_source=True), encoding="utf-8")
    bad_target = tmp_path / "bad-target.conf"
    bad_target.write_text(wan_config_text(bad_target=True), encoding="utf-8")

    assert any("source not-a-cidr is not a valid CIDR" in error for error in helper._wan_config_errors(bad_source))
    assert any("must use an access physical interface or enabled VLAN" in error for error in helper._wan_config_errors(bad_target))


def test_wan_helper_rejects_route_wan_mode(tmp_path):
    helper = load_helper_module()
    config_path = tmp_path / "route-mode.conf"
    config_path.write_text(wan_config_text(wan_mode="route"), encoding="utf-8")

    assert any("WAN mode route is planned but not supported in v1" in error for error in helper._wan_config_errors(config_path))


def test_wan_helper_ignores_disabled_routing_rule_missing_targets(tmp_path):
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
    helper = load_helper_module()
    config_path = tmp_path / "nat-access-target.conf"
    config_path.write_text(wan_config_text(target_role="access"), encoding="utf-8")

    assert helper._wan_config_errors(config_path) == []


def test_wan_helper_accepts_ipv6_routes_and_rejects_ipv6_only_nat_targets(tmp_path):
    helper = load_helper_module()
    ipv6_route = tmp_path / "ipv6-route.conf"
    ipv6_route.write_text(wan_config_text(ipv6_route=True), encoding="utf-8")
    ipv6_only_nat = tmp_path / "ipv6-only-nat.conf"
    ipv6_only_nat.write_text(wan_config_text(ipv6_route=True, ipv6_only_target=True), encoding="utf-8")

    assert helper._wan_config_errors(ipv6_route) == []
    parsed = helper._parse_wan_config(ipv6_route)
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    helper._run = fake_run
    helper.shutil.which = lambda command: f"/usr/sbin/{command}" if command in {"ip", "tc"} else None
    assert helper._apply_wan_routes_and_qdiscs(parsed) == 0
    assert ["ip", "-6", "route", "replace", "2001:db8:100::/64", "via", "2001:db8:20::fe", "dev", "eth1.20", "metric", "120", "table", "200"] in commands
    assert any("outbound interface with an IPv4 CIDR" in error for error in helper._wan_config_errors(ipv6_only_nat))


def test_wan_helper_cleans_managed_policy_rule_windows_before_apply(tmp_path):
    helper = load_helper_module()
    config_path = tmp_path / "policy-rules.conf"
    config_path.write_text(wan_config_text(), encoding="utf-8")
    parsed = helper._parse_wan_config(config_path)
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
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
    helper = load_helper_module()
    networkd_dir = tmp_path / "systemd-network"
    networkd_dir.mkdir()
    management_network = networkd_dir / "00-labfoundry-mgmt.network"
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
    helper = load_helper_module()
    management_network = tmp_path / "00-labfoundry-mgmt.network"
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
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "NETWORKD_MGMT_CONFIG_PATH", tmp_path / "missing.network")
    monkeypatch.setattr(helper, "_run", fake_run)
    monkeypatch.setattr(helper.shutil, "which", lambda command: f"/usr/sbin/{command}" if command == "ip" else None)

    assert helper._apply_wan_target_routes(parsed) == 0
    assert ["ip", "route", "del", "default", "dev", "eth0"] not in commands


def test_wan_helper_gives_management_ownership_of_duplicate_vlan_network(monkeypatch, tmp_path):
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
    helper = load_helper_module()
    apply_root = tmp_path / "apply"
    config_path = apply_root / "wan" / "labfoundry-wan.conf"
    chowned: list[tuple[Path, str, str]] = []
    chmodded: list[tuple[Path, int]] = []

    monkeypatch.setattr(helper, "LABFOUNDRY_APPLY_DIR", apply_root)
    monkeypatch.setattr(helper.shutil, "chown", lambda path, user, group: chowned.append((Path(path), user, group)))
    monkeypatch.setattr(helper.os, "chmod", lambda path, mode: chmodded.append((Path(path), mode)))

    assert helper.main(["labfoundry-helper", "staging", "prepare", "--real", str(config_path)]) == 0

    assert config_path.parent.is_dir()
    assert (apply_root, "labfoundry", "labfoundry") in chowned
    assert (config_path.parent, "labfoundry", "labfoundry") in chowned
    assert (apply_root, 0o755) in chmodded
    assert (config_path.parent, 0o750) in chmodded


def test_esxi_pxe_helper_validates_and_writes_generated_kickstarts(monkeypatch, tmp_path):
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
        "hostname": "esxi-pxe.labfoundry.internal",
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
        "effective_native_uefi_http_url": "http://192.168.50.1:8080/pxe/esxi/mboot.efi",
        "ipxe_script": "#!ipxe\necho LabFoundry PXE ready\nshell\n",
    }
    config_path = apply_dir / "labfoundry-esxi-pxe.json"
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
    assert (tftp_root / "pxelinux.0").read_bytes() == b"pxelinux"
    assert (tftp_root / "ldlinux.c32").read_bytes() == b"ldlinux"
    assert (tftp_root / "mboot.efi").read_bytes() == b"mboot efi"
    assert (http_base / "mboot.efi").read_bytes() == b"mboot efi"
    assert (http_base / "boot.ipxe").read_text(encoding="utf-8") == "#!ipxe\necho LabFoundry PXE ready\nshell\n"
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
    assert "location /pxe/esxi/ks/" in nginx_site
    assert "proxy_pass http://127.0.0.1:8000;" in nginx_site
    assert f"alias {http_base}/;" in nginx_site
    assert not stale.exists()

    manifest["hosts"][0]["installer_iso_path"] = str(tmp_path / "escape.iso")
    assert any("installer ISO must be under" in error for error in helper._esxi_pxe_manifest_errors(manifest))


def test_esxi_pxe_helper_writes_http_ipxe_script_without_profiles(monkeypatch, tmp_path):
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
        "kind": "labfoundry-esxi-pxe",
        "schema_version": 2,
        "http_root": str(http_root),
        "http_base": str(http_base),
        "image_http_root": str(http_base / "images"),
        "installer_iso_root": str(iso_root),
        "installer_isos": [],
        "boot": {
            "enabled": True,
            "hostname": "esxi-pxe.labfoundry.internal",
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
            "effective_native_uefi_http_url": "http://192.168.50.1:8080/pxe/esxi/mboot.efi",
            "ipxe_script": "#!ipxe\necho No profiles yet\nshell\n",
        },
        "kickstarts": [],
        "hosts": [],
        "artifacts": [],
    }
    config_path = apply_dir / "labfoundry-esxi-pxe.json"
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
        "hostname": "esxi-pxe.labfoundry.internal",
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
        "effective_native_uefi_http_url": "http://192.168.50.1:8080/pxe/esxi/mboot.efi",
        "ipxe_script": "#!ipxe\necho LabFoundry PXE ready\nshell\n",
    }
    config_path = apply_dir / "labfoundry-esxi-pxe.json"
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
    helper = load_helper_module()
    config_path = tmp_path / "labfoundry-ca.json"
    config_path.write_text(ca_payload_text(tmp_path / "etc" / "labfoundry"), encoding="utf-8")

    try:
        helper._validate_ca_config_path(str(config_path))
    except ValueError as exc:
        assert "CA config must be staged under" in str(exc)
    else:
        raise AssertionError("CA config outside apply directory should be rejected")


def test_ca_helper_validates_and_writes_managed_files(monkeypatch, tmp_path):
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "ca"
    managed_root = tmp_path / "etc" / "labfoundry"
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "labfoundry-ca.json"
    config_path.write_text(ca_payload_text(managed_root), encoding="utf-8")

    monkeypatch.setattr(helper, "CA_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "CA_MANAGED_PATH_BASE", managed_root)
    monkeypatch.setattr(helper, "_ca_key_matches_certificate", lambda certificate_pem, private_key_pem: True)

    assert helper._handle_ca("validate", [str(config_path)]) == 0
    assert helper._handle_ca("apply", [str(config_path)]) == 0

    root_ca = managed_root / "ca" / "root-ca.pem"
    crl_path = managed_root / "ca" / "labfoundry-ca.crl"
    key_path = managed_root / "kms" / "certs" / "kms.labfoundry.internal.key"
    assert root_ca.read_text(encoding="utf-8").startswith("-----BEGIN CERTIFICATE-----")
    assert crl_path.read_text(encoding="utf-8").startswith("-----BEGIN X509 CRL-----")
    assert key_path.read_text(encoding="utf-8").startswith("-----BEGIN PRIVATE KEY-----")
    if os.name != "nt":
        assert oct(key_path.stat().st_mode & 0o777) == "0o600"


def test_ca_helper_preserves_slapd_access_when_rewriting_ldap_key(monkeypatch, tmp_path):
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "ca"
    managed_root = tmp_path / "etc" / "labfoundry"
    ldap_key_path = managed_root / "ldap" / "tls" / "server.key"
    apply_dir.mkdir(parents=True)
    payload = json.loads(ca_payload_text(managed_root))
    payload["certificates"][0]["key_path"] = str(ldap_key_path)
    config_path = apply_dir / "labfoundry-ca.json"
    config_path.write_text(json.dumps(payload), encoding="utf-8")
    ownership: list[tuple[Path, str, str]] = []
    modes: list[tuple[Path, int]] = []
    real_chmod = helper.os.chmod

    def track_ldap_key_mode(path, mode, **kwargs):
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


def test_ca_helper_removes_stale_crl_when_publication_is_empty(monkeypatch, tmp_path):
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "ca"
    managed_root = tmp_path / "etc" / "labfoundry"
    apply_dir.mkdir(parents=True)
    payload = json.loads(ca_payload_text(managed_root))
    crl_path = managed_root / "ca" / "labfoundry-ca.crl"
    crl_path.parent.mkdir(parents=True)
    crl_path.write_text("-----BEGIN X509 CRL-----\nstale\n-----END X509 CRL-----\n", encoding="utf-8")
    payload["root"]["crl_pem"] = ""
    config_path = apply_dir / "labfoundry-ca.json"
    config_path.write_text(json.dumps(payload), encoding="utf-8")

    monkeypatch.setattr(helper, "CA_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "CA_MANAGED_PATH_BASE", managed_root)
    monkeypatch.setattr(helper, "_ca_key_matches_certificate", lambda certificate_pem, private_key_pem: True)

    assert helper._handle_ca("validate", [str(config_path)]) == 0
    assert helper._handle_ca("apply", [str(config_path)]) == 0
    assert not crl_path.exists()


def test_ca_helper_allows_csr_certificate_without_private_key(monkeypatch, tmp_path):
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "ca"
    managed_root = tmp_path / "etc" / "labfoundry"
    apply_dir.mkdir(parents=True)
    payload = json.loads(ca_payload_text(managed_root))
    payload["certificates"].append(
        {
            "common_name": "client-a.labfoundry.internal",
            "managed_owner": "",
            "certificate_pem": "-----BEGIN CERTIFICATE-----\nclient\n-----END CERTIFICATE-----\n",
            "chain_pem": "-----BEGIN CERTIFICATE-----\nclient\n-----END CERTIFICATE-----\n",
            "private_key_pem": "",
            "cert_path": str(managed_root / "ca" / "client-a.crt"),
            "key_path": "",
            "chain_path": str(managed_root / "ca" / "client-a-chain.pem"),
        }
    )
    config_path = apply_dir / "labfoundry-ca.json"
    config_path.write_text(json.dumps(payload), encoding="utf-8")

    monkeypatch.setattr(helper, "CA_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "CA_MANAGED_PATH_BASE", managed_root)
    monkeypatch.setattr(helper, "_ca_key_matches_certificate", lambda certificate_pem, private_key_pem: True)

    assert helper._handle_ca("validate", [str(config_path)]) == 0
    assert helper._handle_ca("apply", [str(config_path)]) == 0

    assert (managed_root / "ca" / "client-a.crt").read_text(encoding="utf-8").startswith("-----BEGIN CERTIFICATE-----")
    assert not (managed_root / "ca" / "client-a.key").exists()


def test_ca_helper_rejects_key_path_without_private_key(monkeypatch, tmp_path):
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "ca"
    managed_root = tmp_path / "etc" / "labfoundry"
    apply_dir.mkdir(parents=True)
    payload = json.loads(ca_payload_text(managed_root))
    payload["certificates"][0]["private_key_pem"] = ""
    config_path = apply_dir / "labfoundry-ca.json"
    config_path.write_text(json.dumps(payload), encoding="utf-8")

    monkeypatch.setattr(helper, "CA_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "CA_MANAGED_PATH_BASE", managed_root)

    errors = helper._ca_payload_errors(config_path)

    assert "certificate kms.labfoundry.internal key_path requires a private key." in errors


def test_wan_helper_apply_routes_nat_and_netem(monkeypatch, tmp_path):
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "wan"
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "labfoundry-wan.conf"
    config_path.write_text(wan_config_text(), encoding="utf-8")
    nat_dir = tmp_path / "nftables.d"
    service_path = tmp_path / "labfoundry-nat.service"
    sysctl_path = tmp_path / "90-labfoundry-routing-wan.conf"
    commands: list[list[str]] = []
    input_commands: list[tuple[list[str], str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    def fake_run_with_input(command: list[str], input_text: str) -> subprocess.CompletedProcess[str]:
        input_commands.append((command, input_text))
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "WAN_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "WAN_NAT_CONFIG_DIR", nat_dir)
    monkeypatch.setattr(helper, "WAN_NAT_CONFIG_PATH", nat_dir / "labfoundry-nat.nft")
    monkeypatch.setattr(helper, "WAN_NAT_SERVICE_PATH", service_path)
    monkeypatch.setattr(helper, "WAN_SYSCTL_PATH", sysctl_path)
    monkeypatch.setattr(helper.shutil, "which", lambda command: f"/usr/sbin/{command}")
    monkeypatch.setattr(helper, "_run", fake_run)
    monkeypatch.setattr(helper, "_run_with_input", fake_run_with_input)

    assert helper._handle_wan("apply", [str(config_path)]) == 0

    assert input_commands[0][0] == ["nft", "-c", "-f", "-"]
    assert 'oifname "eth1.20" masquerade' in input_commands[0][1]
    assert ["sysctl", "-w", "net.ipv4.ip_forward=1"] in commands
    assert ["nft", "-f", str(nat_dir / "labfoundry-nat.nft")] in commands
    assert ["ip", "route", "replace", "192.168.20.0/24", "dev", "eth1.20", "table", "200"] in commands
    assert ["ip", "rule", "add", "from", "192.168.20.0/24", "table", "200", "priority", "2000"] in commands
    assert ["ip", "route", "replace", "10.20.0.0/24", "dev", "eth1.20", "metric", "120", "table", "200"] in commands
    assert ["tc", "qdisc", "replace", "dev", "eth1.20", "root", "netem", "delay", "100ms", "10ms", "loss", "0.5%", "rate", "100mbit"] in commands
    assert service_path.exists()
    assert sysctl_path.read_text(encoding="utf-8") == "net.ipv4.ip_forward = 1\n"


def test_automation_helper_gives_powershell_private_writable_xdg_home(monkeypatch, tmp_path):
    helper = load_helper_module()
    script_root = tmp_path / "scripts"
    run_root = tmp_path / "runs"
    script_root.mkdir()
    script_path = script_root / "job.ps1"
    script_path.write_text("Write-Output 'ok'\n", encoding="utf-8")
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        commands.append(command)
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
    assert command[-4:] == ["/usr/bin/pwsh", str(script_path), "-Mode", "check"]
    assert not run_home.exists()


def test_real_mutating_helper_action_escapes_service_mount_namespace(monkeypatch, tmp_path, capsys):
    helper = load_helper_module()
    config_path = tmp_path / "labfoundry.conf"
    config_path.write_text("# staged dnsmasq config\n", encoding="utf-8")
    commands: list[list[str]] = []

    def fake_which(command: str) -> str | None:
        return "/usr/bin/systemd-run" if command == "systemd-run" else None

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "child helper output\n", "")

    monkeypatch.setenv("LABFOUNDRY_HELPER_USE_SYSTEMD_RUN", "1")
    monkeypatch.delenv(helper.SYSTEMD_RUN_CHILD_ENV, raising=False)
    monkeypatch.setattr(helper.shutil, "which", fake_which)
    monkeypatch.setattr(helper, "_run", fake_run)
    monkeypatch.setattr(helper, "_handle_dnsmasq", lambda action, args: (_ for _ in ()).throw(AssertionError("handler should run in child")))

    assert helper.main(["labfoundry-helper", "dnsmasq", "apply", "--real", str(config_path)]) == 0

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
    helper = load_helper_module()
    config_path = tmp_path / "labfoundry-settings.json"
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
    helper = load_helper_module()
    config_path = tmp_path / "labfoundry-update.json"
    config_path.write_text("{}\n", encoding="utf-8")
    powershell_home = tmp_path / "powershell"
    commands: list[list[str]] = []

    monkeypatch.setattr(helper, "LABFOUNDRY_POWERSHELL_HOME", powershell_home)
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
    helper = load_helper_module()
    config_path = tmp_path / "labfoundry-network.conf"
    config_path.write_text(network_config_text(), encoding="utf-8")

    files, links, admin_down_links = helper._systemd_networkd_files(config_path)

    assert "00-labfoundry-mgmt.network" in files
    assert "Name=eth0" in files["00-labfoundry-mgmt.network"]
    assert "Name=eth*" not in files["00-labfoundry-mgmt.network"]
    assert "Address=192.168.49.1/24" in files["00-labfoundry-mgmt.network"]
    assert "[RoutingPolicyRule]" not in files["00-labfoundry-mgmt.network"]
    assert "Table=100" not in files["00-labfoundry-mgmt.network"]
    assert "10-labfoundry-eth2.network" in files
    assert "VLAN=eth2.20" in files["10-labfoundry-eth2.network"]
    assert "10-labfoundry-eth2.20.netdev" in files
    assert "Id=20" in files["10-labfoundry-eth2.20.netdev"]
    assert "10-labfoundry-eth2.20.network" in files
    assert "Address=192.168.20.1/24" in files["10-labfoundry-eth2.20.network"]
    assert links == ["eth2", "eth2.20"]
    assert admin_down_links == []


def test_network_helper_keeps_admin_down_physical_links_unmanaged(tmp_path):
    helper = load_helper_module()
    config_path = tmp_path / "labfoundry-network.conf"
    config_path.write_text(network_config_text(eth2_mode="access", eth2_admin_state="down", include_vlan=False), encoding="utf-8")

    files, links, admin_down_links = helper._systemd_networkd_files(config_path)

    assert "00-labfoundry-mgmt.network" in files
    assert "10-labfoundry-eth2.network" not in files
    assert links == []
    assert admin_down_links == ["eth2"]


def test_network_helper_installs_networkd_files_and_reconfigures_non_management(monkeypatch, tmp_path):
    helper = load_helper_module()
    config_path = tmp_path / "labfoundry-network.conf"
    config_path.write_text(network_config_text(), encoding="utf-8")
    networkd_dir = tmp_path / "systemd-network"
    networkd_dir.mkdir()
    old_managed = networkd_dir / "10-labfoundry-old.network"
    old_managed.write_text("old", encoding="utf-8")
    old_default = networkd_dir / "99-dhcp-en.network"
    old_default.write_text("old default", encoding="utf-8")
    commands: list[list[str]] = []
    stdin_commands: list[tuple[list[str], str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    def fake_run_with_input(command: list[str], stdin_text: str) -> subprocess.CompletedProcess[str]:
        stdin_commands.append((command, stdin_text))
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "NETWORKD_CONFIG_DIR", networkd_dir)
    monkeypatch.setattr(helper, "NETWORKD_MGMT_CONFIG_PATH", networkd_dir / "00-labfoundry-mgmt.network")
    monkeypatch.setattr(helper.shutil, "which", lambda command: "/usr/bin/networkctl" if command == "networkctl" else None)
    monkeypatch.setattr(helper, "_run", fake_run)
    monkeypatch.setattr(helper, "_link_exists", lambda name: True)

    returncode, installed, links, admin_down_links = helper._install_systemd_networkd_files(config_path)

    assert returncode == 0
    assert not old_managed.exists()
    assert not old_default.exists()
    assert (networkd_dir / "00-labfoundry-mgmt.network").is_file()
    assert (networkd_dir / "10-labfoundry-eth2.network").is_file()
    assert (networkd_dir / "10-labfoundry-eth2.20.netdev").is_file()
    assert ["networkctl", "reload"] in commands
    assert ["networkctl", "reconfigure", "eth2"] in commands
    assert ["networkctl", "reconfigure", "eth2.20"] in commands
    assert ["networkctl", "reconfigure", "eth0"] not in commands
    assert any(path.endswith("00-labfoundry-mgmt.network") for path in installed)
    assert links == ["eth2", "eth2.20"]
    assert admin_down_links == []


def test_network_helper_sets_admin_down_links_down_after_reload(monkeypatch, tmp_path):
    helper = load_helper_module()
    config_path = tmp_path / "labfoundry-network.conf"
    config_path.write_text(network_config_text(eth2_mode="access", eth2_admin_state="down", include_vlan=False), encoding="utf-8")
    networkd_dir = tmp_path / "systemd-network"
    networkd_dir.mkdir()
    commands: list[list[str]] = []

    def fake_which(command: str) -> str | None:
        return f"/usr/bin/{command}" if command in {"networkctl", "ip"} else None

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "NETWORKD_CONFIG_DIR", networkd_dir)
    monkeypatch.setattr(helper, "NETWORKD_MGMT_CONFIG_PATH", networkd_dir / "00-labfoundry-mgmt.network")
    monkeypatch.setattr(helper.shutil, "which", fake_which)
    monkeypatch.setattr(helper, "_run", fake_run)
    monkeypatch.setattr(helper, "_link_exists", lambda name: True)

    returncode, _installed, links, admin_down_links = helper._install_systemd_networkd_files(config_path)

    assert returncode == 0
    assert links == []
    assert admin_down_links == ["eth2"]
    assert ["ip", "link", "set", "dev", "eth2", "down"] in commands


def test_network_helper_sets_vlan_ip_after_link_up_and_flush(monkeypatch, tmp_path):
    helper = load_helper_module()
    config_path = tmp_path / "labfoundry-network.conf"
    config_path.write_text(network_config_text(), encoding="utf-8")
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
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
    helper = load_helper_module()
    config_path = tmp_path / "labfoundry-network.conf"
    config_path.write_text(network_config_text(include_vlan=False, include_removed_vlan=True), encoding="utf-8")
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
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
    helper = load_helper_module()
    config_path = tmp_path / "labfoundry-network.conf"
    config_path.write_text(network_config_text(include_vlan=False, include_removed_vlan=True), encoding="utf-8")

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        if command[:5] == ["ip", "-j", "-d", "link", "show"]:
            return subprocess.CompletedProcess(command, 0, '[{"linkinfo":{"info_kind":"dummy"}}]', "")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper.shutil, "which", lambda command: "/usr/sbin/ip" if command == "ip" else None)
    monkeypatch.setattr(helper, "_run", fake_run)

    assert helper._apply_vlan_interfaces(config_path) == 2


def test_kms_helper_rejects_config_outside_apply_dir(tmp_path):
    helper = load_helper_module()
    config_path = tmp_path / "pykmip.conf"
    config_path.write_text(kms_config_text(tmp_path), encoding="utf-8")

    assert helper._handle_kms("validate", [str(config_path)]) == 2


def test_kms_helper_validates_disabled_staged_config(monkeypatch, tmp_path):
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "kms"
    state_dir = tmp_path / "state" / "kms"
    managed_root = tmp_path / "etc" / "labfoundry"
    apply_dir.mkdir(parents=True)
    state_dir.mkdir(parents=True)
    config_path = apply_dir / "pykmip.conf"
    config_path.write_text(kms_config_text(managed_root, enabled=False, database_path=state_dir / "pykmip.db"), encoding="utf-8")

    monkeypatch.setattr(helper, "KMS_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "KMS_STATE_DIR", state_dir)
    monkeypatch.setattr(helper, "KMS_CONFIG_DIR", managed_root / "kms")
    monkeypatch.setattr(helper, "CA_MANAGED_PATH_BASE", managed_root)

    assert helper._handle_kms("validate", [str(config_path)]) == 0


def test_kms_helper_apply_installs_pykmip_service(monkeypatch, tmp_path):
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "kms"
    state_dir = tmp_path / "state" / "kms"
    log_dir = tmp_path / "log" / "kms"
    managed_root = tmp_path / "etc" / "labfoundry"
    pykmip_dir = tmp_path / "etc" / "pykmip"
    service_path = tmp_path / "systemd" / "labfoundry-kms.service"
    config_path = apply_dir / "pykmip.conf"
    cert_path = managed_root / "kms" / "certs" / "kms.labfoundry.internal.crt"
    key_path = managed_root / "kms" / "certs" / "kms.labfoundry.internal.key"
    ca_path = managed_root / "ca" / "root.crt"
    apply_dir.mkdir(parents=True)
    state_dir.mkdir(parents=True)
    cert_path.parent.mkdir(parents=True)
    ca_path.parent.mkdir(parents=True)
    cert_path.write_text("-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n", encoding="utf-8")
    key_path.write_text("-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n", encoding="utf-8")
    ca_path.write_text("-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----\n", encoding="utf-8")
    config_path.write_text(kms_config_text(managed_root, database_path=state_dir / "pykmip.db"), encoding="utf-8")
    commands: list[list[str]] = []

    def fake_run(command):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "KMS_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "KMS_STATE_DIR", state_dir)
    monkeypatch.setattr(helper, "KMS_LOG_DIR", log_dir)
    monkeypatch.setattr(helper, "KMS_CONFIG_DIR", managed_root / "kms")
    monkeypatch.setattr(helper, "KMS_CONFIG_PATH", managed_root / "kms" / "pykmip.conf")
    monkeypatch.setattr(helper, "KMS_POLICY_DIR", managed_root / "kms" / "policies")
    monkeypatch.setattr(helper, "KMS_SERVICE_PATH", service_path)
    monkeypatch.setattr(helper, "PYKMIP_CONFIG_DIR", pykmip_dir)
    monkeypatch.setattr(helper, "PYKMIP_CONFIG_PATH", pykmip_dir / "server.conf")
    monkeypatch.setattr(helper, "CA_MANAGED_PATH_BASE", managed_root)
    monkeypatch.setattr(helper, "_run", fake_run)
    monkeypatch.setattr(helper.shutil, "which", lambda command: "/opt/labfoundry/.venv/bin/pykmip-server" if command == "pykmip-server" else None)

    assert helper._handle_kms("apply", [str(config_path)]) == 0

    assert (managed_root / "kms" / "pykmip.conf").is_file()
    assert (pykmip_dir / "server.conf").is_file()
    assert "pykmip_compat_server.py" in service_path.read_text(encoding="utf-8")
    assert ["systemctl", "daemon-reload"] in commands
    assert ["systemctl", "enable", "labfoundry-kms.service"] in commands
    assert ["systemctl", "restart", "labfoundry-kms.service"] in commands


def test_dnsmasq_helper_validates_staged_config(monkeypatch, tmp_path):
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "dnsmasq"
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "labfoundry.conf"
    config_path.write_text("domain=labfoundry.internal\n", encoding="utf-8")
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "dnsmasq: syntax check OK.\n", "")

    monkeypatch.setattr(helper, "DNSMASQ_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper.shutil, "which", lambda command: "/usr/sbin/dnsmasq" if command == "dnsmasq" else None)
    monkeypatch.setattr(helper, "_run", fake_run)

    assert helper._handle_dnsmasq("validate", [str(config_path)]) == 0

    assert commands == [["/usr/sbin/dnsmasq", "--test", f"--conf-file={config_path}"]]


def test_dnsmasq_helper_prepares_dnssec_trust_anchors(monkeypatch, tmp_path):
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "dnsmasq"
    anchor_source = tmp_path / "usr" / "share" / "dnsmasq" / "trust-anchors.conf"
    apply_dir.mkdir(parents=True)
    anchor_source.parent.mkdir(parents=True)
    anchor_source.write_text("trust-anchor=.,20326,8,2,abc\n", encoding="utf-8")
    config_path = apply_dir / "labfoundry.conf"
    anchor_target = apply_dir / "labfoundry-trust-anchors.conf"
    config_path.write_text(f"dnssec\nconf-file={anchor_target}\n", encoding="utf-8")
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
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
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "dnsmasq"
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "labfoundry.conf"
    config_path.write_text("dnssec\n", encoding="utf-8")

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, "Compile time options: no-DNSSEC\n", "")

    monkeypatch.setattr(helper, "DNSMASQ_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper.shutil, "which", lambda command: "/usr/sbin/dnsmasq" if command == "dnsmasq" else None)
    monkeypatch.setattr(helper, "_run", fake_run)

    assert helper._handle_dnsmasq("validate", [str(config_path)]) == 2
    captured = capsys.readouterr()
    assert "DNSSEC validation is enabled" in captured.err
    assert "no-DNSSEC" in captured.err


def test_dnsmasq_helper_apply_installs_config_dropin_and_enables_service(monkeypatch, tmp_path):
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "dnsmasq"
    state_dir = tmp_path / "var" / "lib" / "labfoundry" / "dnsmasq"
    config_dir = tmp_path / "etc" / "labfoundry" / "dnsmasq.d"
    dropin_dir = tmp_path / "etc" / "systemd" / "system" / "dnsmasq.service.d"
    networkd_dir = tmp_path / "etc" / "systemd" / "network"
    apply_dir.mkdir(parents=True)
    networkd_dir.mkdir(parents=True)
    mgmt_network = networkd_dir / "00-labfoundry-mgmt.network"
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
    config_path = apply_dir / "labfoundry.conf"
    config_path.write_text("domain=labfoundry.internal\n", encoding="utf-8")
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "DNSMASQ_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "DNSMASQ_STATE_DIR", state_dir)
    monkeypatch.setattr(helper, "DNSMASQ_CONFIG_DIR", config_dir)
    monkeypatch.setattr(helper, "DNSMASQ_CONFIG_PATH", config_dir / "labfoundry.conf")
    monkeypatch.setattr(helper, "DNSMASQ_SERVICE_DROPIN_DIR", dropin_dir)
    monkeypatch.setattr(helper, "DNSMASQ_SERVICE_DROPIN_PATH", dropin_dir / "labfoundry.conf")
    monkeypatch.setattr(helper, "NETWORKD_MGMT_CONFIG_PATH", mgmt_network)
    monkeypatch.setattr(helper.shutil, "which", lambda command: "/usr/sbin/dnsmasq" if command == "dnsmasq" else None)
    monkeypatch.setattr(helper, "_run", fake_run)

    assert helper._handle_dnsmasq("apply", [str(config_path)]) == 0

    assert (config_dir / "labfoundry.conf").read_text(encoding="utf-8") == "domain=labfoundry.internal\n"
    dropin = (dropin_dir / "labfoundry.conf").read_text(encoding="utf-8")
    assert "ExecStart=" in dropin
    assert f"--conf-file={config_dir / 'labfoundry.conf'}" in dropin
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
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "dnsmasq"
    state_dir = tmp_path / "var" / "lib" / "labfoundry" / "dnsmasq"
    config_dir = tmp_path / "etc" / "labfoundry" / "dnsmasq.d"
    dropin_dir = tmp_path / "etc" / "systemd" / "system" / "dnsmasq.service.d"
    tftp_root = tmp_path / "var" / "lib" / "labfoundry" / "pxe" / "tftp"
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "labfoundry.conf"
    config_path.write_text(f"enable-tftp\ntftp-root={tftp_root}\n", encoding="utf-8")
    commands: list[list[str]] = []
    chowned: list[Path] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "DNSMASQ_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "DNSMASQ_STATE_DIR", state_dir)
    monkeypatch.setattr(helper, "DNSMASQ_CONFIG_DIR", config_dir)
    monkeypatch.setattr(helper, "DNSMASQ_CONFIG_PATH", config_dir / "labfoundry.conf")
    monkeypatch.setattr(helper, "DNSMASQ_SERVICE_DROPIN_DIR", dropin_dir)
    monkeypatch.setattr(helper, "DNSMASQ_SERVICE_DROPIN_PATH", dropin_dir / "labfoundry.conf")
    monkeypatch.setattr(helper, "ESXI_TFTP_ROOT", tftp_root)
    monkeypatch.setattr(helper.shutil, "which", lambda command: "/usr/sbin/dnsmasq" if command == "dnsmasq" else None)
    monkeypatch.setattr(helper.shutil, "chown", lambda path, user, group: chowned.append(Path(path)))
    monkeypatch.setattr(helper, "_run", fake_run)

    assert helper._handle_dnsmasq("apply", [str(config_path)]) == 0

    assert tftp_root.is_dir()
    assert chowned == [tftp_root]
    assert ["systemctl", "reload-or-restart", "dnsmasq"] in commands


def test_dnsmasq_helper_apply_rejects_unexpected_tftp_root(monkeypatch, tmp_path, capsys):
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "dnsmasq"
    allowed_root = tmp_path / "var" / "lib" / "labfoundry" / "pxe" / "tftp"
    unexpected_root = tmp_path / "tmp" / "not-labfoundry"
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "labfoundry.conf"
    config_path.write_text(f"enable-tftp\ntftp-root={unexpected_root}\n", encoding="utf-8")
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
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
    helper = load_helper_module()
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "_run", fake_run)

    assert helper._handle_dnsmasq("reload", []) == 0

    assert commands == [
        ["systemctl", "daemon-reload"],
        ["systemctl", "reload-or-restart", "dnsmasq"],
    ]


def test_dnsmasq_helper_reads_allowlisted_lease_file(monkeypatch, tmp_path, capsys):
    helper = load_helper_module()
    state_dir = tmp_path / "var" / "lib" / "labfoundry" / "dnsmasq"
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
    helper = load_helper_module()
    state_dir = tmp_path / "var" / "lib" / "labfoundry" / "dnsmasq"
    state_dir.mkdir(parents=True)

    monkeypatch.setattr(helper, "DNSMASQ_STATE_DIR", state_dir)
    monkeypatch.setattr(helper, "DNSMASQ_LEASE_FILE_PATH", state_dir / "dhcp.leases")

    assert helper._handle_dnsmasq("leases", []) == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_dnsmasq_helper_rejects_lease_paths_outside_allowlisted_state(monkeypatch, tmp_path, capsys):
    helper = load_helper_module()
    state_dir = tmp_path / "var" / "lib" / "labfoundry" / "dnsmasq"
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
    row = {
        "username": username,
        "role": "viewer",
        "enabled": enabled,
        "home": f"/var/lib/labfoundry/users/{username}",
        "shell": "/sbin/nologin",
        "password_pending": bool(password),
        "password_pending_since": "2026-06-23T12:00:00+00:00" if password else "",
    }
    if password:
        row["password"] = password
    return json.dumps({"managed_by": "LabFoundry", "version": 1, "scope": "Photon OS local users", "users": [row]})


def test_local_users_helper_validates_staged_config(monkeypatch, tmp_path, capsys):
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "local-users"
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "labfoundry-users.json"
    config_path.write_text(local_users_json(), encoding="utf-8")

    monkeypatch.setattr(helper, "LOCAL_USERS_APPLY_DIR", apply_dir)

    assert helper._handle_local_users("validate", [str(config_path)]) == 0
    captured = capsys.readouterr()
    assert '"local_users": "validation ok"' in captured.out
    assert '"passwords_pending": 1' in captured.out
    assert "BridgeStrong1!" not in captured.out


def test_local_users_helper_rejects_reserved_username(monkeypatch, tmp_path, capsys):
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "local-users"
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "labfoundry-users.json"
    config_path.write_text(local_users_json(username="root"), encoding="utf-8")

    monkeypatch.setattr(helper, "LOCAL_USERS_APPLY_DIR", apply_dir)

    assert helper._handle_local_users("validate", [str(config_path)]) == 2
    captured = capsys.readouterr()
    assert "local user root is reserved" in captured.err


def test_local_users_helper_creates_deletes_and_sets_password_without_leaking(monkeypatch, tmp_path, capsys):
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "local-users"
    home_base = tmp_path / "users"
    pwquality_path = tmp_path / "etc" / "security" / "pwquality.conf"
    pam_path = tmp_path / "etc" / "pam.d" / "system-password"
    pam_path.parent.mkdir(parents=True)
    pam_path.write_text("password  required    pam_unix.so       sha512 shadow use_authtok\n", encoding="utf-8")
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "labfoundry-users.json"
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
        commands.append(command)
        if command == ["id", "sync-user"]:
            return subprocess.CompletedProcess(command, 1, "", "")
        return subprocess.CompletedProcess(command, 0, "", "")

    def fake_run_with_input(command: list[str], input_text: str) -> subprocess.CompletedProcess[str]:
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


def test_local_users_helper_authenticates_shadow_password_without_leaking(monkeypatch, capsys):
    helper = load_helper_module()

    class FakeCrypt:
        argtypes = None
        restype = None

        def __call__(self, password: bytes, password_hash: bytes) -> bytes:
            return password_hash if password == b"Depot-user1!" else b"$6$not-a-match"

    class FakeCryptLibrary:
        crypt = FakeCrypt()

    monkeypatch.setattr(helper, "_shadow_hash_for_user", lambda username: "$6$rounds=5000$valid-hash")
    monkeypatch.setattr(helper.ctypes.util, "find_library", lambda name: "libcrypt.so.1")
    monkeypatch.setattr(helper.ctypes, "CDLL", lambda name: FakeCryptLibrary())

    monkeypatch.setattr(helper.sys, "stdin", io.StringIO("Depot-user1!\n"))
    assert helper.main(["labfoundry-helper", "local-users", "authenticate", "--real", "vcf-depot"]) == 0
    valid_output = capsys.readouterr()
    assert "Depot-user1!" not in valid_output.out
    assert "valid-hash" not in valid_output.out

    monkeypatch.setattr(helper.sys, "stdin", io.StringIO("wrong-password\n"))
    assert helper.main(["labfoundry-helper", "local-users", "authenticate", "--real", "vcf-depot"]) == 1
    invalid_output = capsys.readouterr()
    assert "wrong-password" not in invalid_output.out
    assert "valid-hash" not in invalid_output.out


def test_ldap_helper_authenticates_with_mode_0600_password_file_and_redacts(monkeypatch, tmp_path, capsys):
    helper = load_helper_module()
    seen: dict[str, object] = {}

    class ManagedTemporaryFile:
        def __init__(self, **_kwargs):
            self.path = tmp_path / "ldap-password"
            self.handle = self.path.open("w", encoding="utf-8")
            self.name = str(self.path)

        def __enter__(self):
            return self.handle

        def __exit__(self, *_args):
            self.handle.close()

    def fake_run(command, **_kwargs):
        password_path = Path(command[command.index("-y") + 1])
        seen["command"] = command
        seen["mode"] = stat.S_IMODE(password_path.stat().st_mode)
        seen["password"] = password_path.read_text(encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "dn:uid=alice,ou=users,dc=example,dc=test\n", "")

    real_chmod = helper.os.chmod

    def capture_chmod(path, mode):
        seen["chmod"] = (Path(path), mode)
        real_chmod(path, mode)

    monkeypatch.setattr(helper.tempfile, "NamedTemporaryFile", ManagedTemporaryFile)
    monkeypatch.setattr(helper.shutil, "which", lambda command: "/usr/bin/ldapwhoami" if command == "ldapwhoami" else None)
    monkeypatch.setattr(helper.os, "chmod", capture_chmod)
    monkeypatch.setattr(helper, "_run", fake_run)
    monkeypatch.setattr(helper.sys, "stdin", io.StringIO("Secret-Ldap-Password!\n"))

    assert helper.main(
        [
            "labfoundry-helper",
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
    helper = load_helper_module()

    for error in (
        "VCF Offline Depot OS user is locked.",
        "VCF Offline Depot OS user is missing.",
    ):
        def reject_shadow(username: str, message: str = error) -> str:
            raise ValueError(message)

        monkeypatch.setattr(helper, "_shadow_hash_for_user", reject_shadow)
        monkeypatch.setattr(helper.sys, "stdin", io.StringIO("Depot-user1!\n"))
        assert helper.main(["labfoundry-helper", "local-users", "authenticate", "--real", "vcf-depot"]) == 1

    class UnsupportedCrypt:
        argtypes = None
        restype = None

        def __call__(self, password: bytes, password_hash: bytes) -> bytes:
            return b"*0"

    monkeypatch.setattr(helper, "_shadow_hash_for_user", lambda username: "$y$unsupported")
    monkeypatch.setattr(helper.ctypes.util, "find_library", lambda name: "libcrypt.so.1")
    monkeypatch.setattr(helper.ctypes, "CDLL", lambda name: type("Library", (), {"crypt": UnsupportedCrypt()})())
    monkeypatch.setattr(helper.sys, "stdin", io.StringIO("Depot-user1!\n"))
    assert helper.main(["labfoundry-helper", "local-users", "authenticate", "--real", "vcf-depot"]) == 1


def test_local_users_helper_refreshes_existing_depot_htpasswd_and_fails_closed(monkeypatch, tmp_path):
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
        raise ValueError("locked")

    monkeypatch.setattr(helper, "_shadow_hash_for_user", locked_user)
    assert helper._refresh_existing_vcf_depot_htpasswd() == 0
    assert htpasswd_path.read_text(encoding="utf-8") == "vcf-depot:!\n"


def test_local_users_helper_applies_per_user_shell(monkeypatch, tmp_path):
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "local-users"
    home_base = tmp_path / "users"
    pwquality_path = tmp_path / "etc" / "security" / "pwquality.conf"
    pam_path = tmp_path / "etc" / "pam.d" / "system-password"
    pam_path.parent.mkdir(parents=True)
    pam_path.write_text("password  required    pam_pwquality.so  retry=3\npassword  required    pam_unix.so\n", encoding="utf-8")
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "labfoundry-users.json"
    payload = json.loads(local_users_json(password=None))
    payload["users"][0]["home"] = (home_base / "sync-user").as_posix()
    payload["users"][0]["shell"] = "/bin/bash"
    config_path.write_text(json.dumps(payload), encoding="utf-8")
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
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
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "local-users"
    home_base = tmp_path / "users"
    pwquality_path = tmp_path / "etc" / "security" / "pwquality.conf"
    pam_path = tmp_path / "etc" / "pam.d" / "system-password"
    pam_path.parent.mkdir(parents=True)
    pam_path.write_text("password  required    pam_pwquality.so  retry=3\npassword  required    pam_unix.so\n", encoding="utf-8")
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "labfoundry-users.json"
    payload = json.loads(local_users_json(username="admin", password=None))
    payload["users"][0]["role"] = "admin"
    payload["users"][0]["home"] = (home_base / "admin").as_posix()
    config_path.write_text(json.dumps(payload), encoding="utf-8")
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
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
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "local-users"
    home_base = tmp_path / "users"
    pwquality_path = tmp_path / "etc" / "security" / "pwquality.conf"
    pam_path = tmp_path / "etc" / "pam.d" / "system-password"
    pam_path.parent.mkdir(parents=True)
    pam_path.write_text("password  required    pam_pwquality.so  retry=3\npassword  required    pam_unix.so\n", encoding="utf-8")
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "labfoundry-users.json"
    payload = json.loads(local_users_json(username="downgraded-user", password=None))
    payload["users"][0]["role"] = "viewer"
    payload["users"][0]["home"] = (home_base / "downgraded-user").as_posix()
    config_path.write_text(json.dumps(payload), encoding="utf-8")
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
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
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "local-users"
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "labfoundry-users.json"
    payload = json.loads(local_users_json(password=None))
    payload["users"][0]["shell"] = "/usr/bin/pwsh"
    config_path.write_text(json.dumps(payload), encoding="utf-8")

    monkeypatch.setattr(helper, "LOCAL_USERS_APPLY_DIR", apply_dir)

    assert helper._handle_local_users("validate", [str(config_path)]) == 0
    captured = capsys.readouterr()
    assert '"local_users": "validation ok"' in captured.out


def test_local_users_helper_unlock_request_resets_passwd_and_faillock(monkeypatch, tmp_path):
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "local-users"
    home_base = tmp_path / "users"
    pwquality_path = tmp_path / "etc" / "security" / "pwquality.conf"
    pam_path = tmp_path / "etc" / "pam.d" / "system-password"
    pam_path.parent.mkdir(parents=True)
    pam_path.write_text("password  required    pam_pwquality.so  retry=3\npassword  required    pam_unix.so\n", encoding="utf-8")
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "labfoundry-users.json"
    payload = json.loads(local_users_json(password=None))
    payload["users"][0]["home"] = (home_base / "sync-user").as_posix()
    payload["users"][0]["unlock_requested"] = True
    config_path.write_text(json.dumps(payload), encoding="utf-8")
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
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
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "local-users"
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "labfoundry-users.json"
    config_path.write_text(local_users_json(password=None), encoding="utf-8")

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
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
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "local-users"
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "labfoundry-users.json"
    config_path.write_text(local_users_json(password=None), encoding="utf-8")

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
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
    if not enabled:
        return "\n".join(
            [
                "# Managed by LabFoundry. Local changes may be overwritten.",
                "# LabFoundry VCF Backups enabled: false",
                "# LabFoundry VCF Backups user: vcf-backup",
                "# Backup volume mount: /mnt/labfoundry-vcf-backups",
                "# VCF remote directory: /backups",
                "# VCF Backup SFTP desired state is disabled.",
                "",
            ]
        )
    return "\n".join(
        [
            "# Managed by LabFoundry. Local changes may be overwritten.",
            "# LabFoundry VCF Backups enabled: true",
            "# LabFoundry VCF Backups user: vcf-backup",
            "# Backup volume mount: /mnt/labfoundry-vcf-backups",
            "# VCF remote directory: /backups",
            "# The selected listen target is enforced by the LabFoundry firewall apply unit.",
            "",
            "# Service listener target: 192.168.50.1:22",
            "Match User vcf-backup",
            "  AuthorizedKeysFile /etc/labfoundry/ssh/authorized_keys/%u",
            "  ChrootDirectory /mnt/labfoundry-vcf-backups",
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
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "vcf-backups"
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "labfoundry-vcf-backups-sshd.conf"
    config_path.write_text(vcf_backups_config_text(), encoding="utf-8")

    monkeypatch.setattr(helper, "VCF_BACKUPS_APPLY_DIR", apply_dir)

    assert helper._handle_vcf_backups("validate", [str(config_path)]) == 0
    captured = capsys.readouterr()
    assert '"vcf_backups": "validation ok"' in captured.out
    assert '"username": "vcf-backup"' in captured.out


def test_vcf_backups_helper_rejects_unmanaged_config(tmp_path):
    helper = load_helper_module()
    config_path = tmp_path / "labfoundry-vcf-backups-sshd.conf"
    config_path.write_text("Match User root\n", encoding="utf-8")

    errors = helper._vcf_backups_config_errors(config_path)

    assert "VCF backups config must be rendered by LabFoundry." in errors


def test_vcf_backups_helper_apply_installs_sshd_dropin_and_storage(monkeypatch, tmp_path):
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "vcf-backups"
    config_dir = tmp_path / "etc" / "ssh" / "sshd_config.d"
    labfoundry_ssh_dir = tmp_path / "etc" / "labfoundry" / "ssh" / "authorized_keys"
    storage_path = tmp_path / "mnt" / "labfoundry-vcf-backups"
    sshd_config = tmp_path / "etc" / "ssh" / "sshd_config"
    apply_dir.mkdir(parents=True)
    sshd_config.parent.mkdir(parents=True)
    sshd_config.write_text("Subsystem sftp internal-sftp\n", encoding="utf-8")
    config_path = apply_dir / "labfoundry-vcf-backups-sshd.conf"
    config_path.write_text(vcf_backups_config_text(), encoding="utf-8")
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "VCF_BACKUPS_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "VCF_BACKUPS_CONFIG_DIR", config_dir)
    monkeypatch.setattr(helper, "VCF_BACKUPS_CONFIG_PATH", config_dir / "labfoundry-vcf-backups.conf")
    monkeypatch.setattr(helper, "VCF_BACKUPS_AUTHORIZED_KEYS_DIR", labfoundry_ssh_dir)
    def fake_path(value):
        if value == "/etc/ssh/sshd_config":
            return sshd_config
        if value == "/mnt/labfoundry-vcf-backups":
            return storage_path
        return Path(value)

    monkeypatch.setattr(helper, "Path", fake_path)
    monkeypatch.setattr(helper, "_chown_path", lambda path, uid, gid: None)
    monkeypatch.setattr(helper.shutil, "which", lambda command: {"id": "id", "sshd": "sshd"}.get(command))
    monkeypatch.setattr(helper, "_run", fake_run)

    assert helper._handle_vcf_backups("apply", [str(config_path)]) == 0

    assert (config_dir / "labfoundry-vcf-backups.conf").is_file()
    assert "Match User vcf-backup" in (config_dir / "labfoundry-vcf-backups.conf").read_text(encoding="utf-8")
    assert (storage_path / "backups").is_dir()
    assert (labfoundry_ssh_dir / "vcf-backup").is_file()
    assert sshd_config.read_text(encoding="utf-8").startswith("Include /etc/ssh/sshd_config.d/*.conf\n")
    assert ["id", "vcf-backup"] in commands
    assert all(arg != "labfoundry-vcf-backup" for command in commands for arg in command)
    assert ["sshd", "-t"] in commands
    assert ["systemctl", "restart", "sshd"] in commands


def test_vcf_backups_helper_apply_requires_existing_os_user(monkeypatch, tmp_path, capsys):
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "vcf-backups"
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "labfoundry-vcf-backups-sshd.conf"
    config_path.write_text(vcf_backups_config_text(), encoding="utf-8")

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
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
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "vcf-offline-depot"
    managed_root = tmp_path / "etc" / "labfoundry"
    site_dir = managed_root / "nginx" / "sites.d"
    cert_path = managed_root / "vcf-offline-depot" / "certs" / "depot.crt"
    key_path = managed_root / "vcf-offline-depot" / "certs" / "depot.key"
    nginx_include = tmp_path / "nginx" / "conf.d" / "labfoundry.conf"
    apply_dir.mkdir(parents=True)
    cert_path.parent.mkdir(parents=True)
    cert_path.write_text("-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n", encoding="utf-8")
    key_path.write_text("-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n", encoding="utf-8")
    config_path = apply_dir / "labfoundry-vcf-offline-depot.conf"
    config_path.write_text(
        "\n".join(
            [
                "# Managed by LabFoundry. Local changes may be overwritten.",
                "server {",
                "  listen 192.168.50.1:443 ssl;",
                "  server_name depot.labfoundry.internal;",
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
                "    alias /mnt/labfoundry-vcf-offline-depot/PROD/$1;",
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
    assert "server_name depot.labfoundry.internal;" in site_text
    assert "alias /mnt/labfoundry-vcf-offline-depot/PROD/$1;" in site_text
    assert "root /mnt/labfoundry-vcf-offline-depot;" not in site_text
    assert "sendfile on;" in site_text
    assert nginx_include.read_text(encoding="utf-8").strip().endswith(f"include {site_dir}/*.conf;")
    assert ["/usr/sbin/nginx", "-t"] in commands
    assert ["systemctl", "enable", "--now", "nginx"] in commands


def test_vcf_offline_depot_helper_uses_browser_session_or_basic_auth_for_authenticated_site(monkeypatch, tmp_path):
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "vcf-offline-depot"
    managed_root = tmp_path / "etc" / "labfoundry"
    site_dir = managed_root / "nginx" / "sites.d"
    cert_path = managed_root / "vcf-offline-depot" / "certs" / "depot.crt"
    key_path = managed_root / "vcf-offline-depot" / "certs" / "depot.key"
    htpasswd_path = managed_root / "nginx" / "htpasswd" / "vcf-offline-depot.htpasswd"
    nginx_include = tmp_path / "nginx" / "conf.d" / "labfoundry.conf"
    apply_dir.mkdir(parents=True)
    cert_path.parent.mkdir(parents=True)
    cert_path.write_text("-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n", encoding="utf-8")
    key_path.write_text("-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n", encoding="utf-8")
    htpasswd_path.parent.mkdir(parents=True)
    htpasswd_path.write_text("vcf-depot:stale-basic-auth-hash\n", encoding="utf-8")
    config_path = apply_dir / "labfoundry-vcf-offline-depot.conf"
    config_path.write_text(
        "\n".join(
            [
                "# Managed by LabFoundry. Local changes may be overwritten.",
                "# LabFoundry VCF Offline Depot unauthenticated access: false",
                "# LabFoundry VCF Offline Depot user: vcf-depot",
                "server {",
                "  listen 192.168.50.1:443 ssl;",
                "  server_name depot.labfoundry.internal;",
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
                "  location = /_labfoundry_depot_auth {",
                "    internal;",
                "    proxy_pass http://127.0.0.1:8000/PROD/auth-check;",
                "    proxy_pass_request_body off;",
                "    proxy_set_header Content-Length \"\";",
                "    proxy_set_header Host $host;",
                "    proxy_set_header X-Original-URI $request_uri;",
                "  }",
                "",
                "  location = /_labfoundry_depot_login {",
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
                "    auth_request /_labfoundry_depot_auth;",
                "    error_page 401 = /_labfoundry_depot_login;",
                "    proxy_pass http://127.0.0.1:8000;",
                "  }",
                "",
                "  location ~ ^/PROD/.*/$ {",
                "    satisfy any;",
                '    auth_basic "VCF Offline Depot";',
                f"    auth_basic_user_file {htpasswd_path};",
                "    auth_request /_labfoundry_depot_auth;",
                "    error_page 401 = /_labfoundry_depot_login;",
                "    proxy_pass http://127.0.0.1:8000;",
                "  }",
                "",
                "  location ~ ^/PROD/(?!login$|logout$|auth-check$)(.+[^/])$ {",
                "    satisfy any;",
                '    auth_basic "VCF Offline Depot";',
                f"    auth_basic_user_file {htpasswd_path};",
                "    auth_request /_labfoundry_depot_auth;",
                "    error_page 401 = /_labfoundry_depot_login;",
                "    alias /mnt/labfoundry-vcf-offline-depot/PROD/$1;",
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
    assert "auth_request /_labfoundry_depot_auth;" in site_text
    assert "error_page 401 = /_labfoundry_depot_login;" in site_text
    assert "proxy_pass http://127.0.0.1:8000/PROD/auth-failure;" in site_text
    assert "satisfy any;" in site_text
    assert 'auth_basic "VCF Offline Depot";' in site_text
    assert f"auth_basic_user_file {htpasswd_path};" in site_text


def test_vcf_offline_depot_helper_prepares_prod_tree_permissions(monkeypatch, tmp_path):
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
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "vcf-offline-depot"
    managed_root = tmp_path / "etc" / "labfoundry"
    cert_path = managed_root / "vcf-offline-depot" / "certs" / "depot.crt"
    key_path = managed_root / "vcf-offline-depot" / "certs" / "depot.key"
    apply_dir.mkdir(parents=True)
    cert_path.parent.mkdir(parents=True)
    cert_path.write_text("-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n", encoding="utf-8")
    key_path.write_text("-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n", encoding="utf-8")
    config_path = apply_dir / "labfoundry-vcf-offline-depot.conf"
    config_path.write_text(
        "\n".join(
            [
                "server {",
                "  listen 192.168.50.1:443 ssl;",
                "  server_name depot.labfoundry.internal;",
                "  root /mnt/labfoundry-vcf-offline-depot;",
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

    tool_dir = tmp_path / "opt" / "labfoundry" / "vcf-download-tool"
    runtime_tool_dir = tmp_path / "var" / "lib" / "labfoundry" / "vcfDownloadTool" / "active-tool"
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
    helper = load_helper_module()
    archive_path = tmp_path / "vcf-download-tool-9.1.0.renew.tar.gz"
    tool_payload = b"#!/bin/sh\necho 'vcf-download-tool 9.1.0'\n"
    with tarfile.open(archive_path, "w:gz") as archive:
        info = tarfile.TarInfo("vcfdt/bin/vcf-download-tool")
        info.mode = 0o750
        info.size = len(tool_payload)
        archive.addfile(info, io.BytesIO(tool_payload))

    tool_dir = tmp_path / "opt" / "labfoundry" / "vcf-download-tool"
    runtime_tool_dir = tmp_path / "var" / "lib" / "labfoundry" / "vcfDownloadTool" / "active-tool"
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
    helper = load_helper_module()
    archive_path = tmp_path / "vcf-download-tool-9.1.0.root.tar.gz"
    payload = b"#!/bin/sh\necho 'vcf-download-tool 9.1.0'\n"
    with tarfile.open(archive_path, "w:gz") as archive:
        info = tarfile.TarInfo("vcf-download-tool")
        info.mode = 0o750
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))

    tool_dir = tmp_path / "opt" / "labfoundry" / "vcf-download-tool"
    runtime_tool_dir = tmp_path / "var" / "lib" / "labfoundry" / "vcfDownloadTool" / "active-tool"
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
    helper = load_helper_module()
    tool_dir = tmp_path / "opt" / "labfoundry" / "vcf-download-tool"
    runtime_tool_dir = tmp_path / "var" / "lib" / "labfoundry" / "vcfDownloadTool" / "active-tool"
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


def test_vcf_offline_depot_helper_prepares_labfoundry_vcfdt_home(monkeypatch, tmp_path):
    helper = load_helper_module()
    state_home = tmp_path / "var" / "lib" / "labfoundry"
    chowned: list[tuple[Path, int, int]] = []

    class Account:
        pw_dir = str(state_home)
        pw_uid = 1200
        pw_gid = 1200

    monkeypatch.setattr(helper.pwd, "getpwnam", lambda username: Account())
    monkeypatch.setattr(helper, "_chown_path", lambda path, uid, gid: chowned.append((path, uid, gid)))

    env, uid, gid = helper._vcfdt_labfoundry_environment()

    assert uid == 1200
    assert gid == 1200
    assert env["HOME"] == str(state_home)
    assert env["XDG_DATA_HOME"] == str(state_home / ".local" / "share")
    assert (state_home / ".local" / "share" / "vmware" / "vdt").is_dir()
    assert (state_home / ".local" / "share" / "vmware" / "vdt", 1200, 1200) in chowned


def test_vcf_offline_depot_helper_generates_software_depot_id(monkeypatch, tmp_path, capsys):
    helper = load_helper_module()
    runtime_tool_dir = tmp_path / "var" / "lib" / "labfoundry" / "vcfDownloadTool" / "active-tool"
    wrapper = runtime_tool_dir / "vcf-download-tool"
    wrapper.parent.mkdir(parents=True)
    wrapper.write_text("#!/bin/sh\n", encoding="utf-8")
    wrapper.chmod(0o755)
    commands: list[tuple[list[str], str]] = []

    def fake_run_vcfdt(command: list[str], *, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
        commands.append((command, input_text or ""))
        return subprocess.CompletedProcess(command, 0, "Software Depot ID: 8c9506c6-7bdf-44d5-b2e9-50d829d66b99\n", "")

    monkeypatch.setattr(helper, "VCF_DEPOT_RUNTIME_TOOL_DIR", runtime_tool_dir)
    monkeypatch.setattr(helper, "_run_vcfdt_user_command", fake_run_vcfdt)

    assert helper._handle_vcf_offline_depot("generate-software-depot-id", []) == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert commands == [([str(wrapper), "configuration", "generate", "--software-depot-id"], "Y\n")]
    assert payload["software_depot_id"] == "8c9506c6-7bdf-44d5-b2e9-50d829d66b99"
    assert payload["command"] == "vcf-download-tool configuration generate --software-depot-id"


def test_vcf_offline_depot_generate_software_depot_id_main_allows_no_path(monkeypatch):
    helper = load_helper_module()
    calls: list[tuple[str, list[str]]] = []

    def fake_handle(action: str, args: list[str]) -> int:
        calls.append((action, args))
        return 0

    monkeypatch.delenv("LABFOUNDRY_HELPER_USE_SYSTEMD_RUN", raising=False)
    monkeypatch.setattr(helper, "_handle_vcf_offline_depot", fake_handle)

    assert helper.main(["labfoundry-helper", "vcf-offline-depot", "generate-software-depot-id", "--real"]) == 0
    assert calls == [("generate-software-depot-id", [])]


def test_vcf_offline_depot_helper_applies_vcfdt_application_properties(monkeypatch, tmp_path, capsys):
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "vcf-offline-depot"
    properties_path = apply_dir / "application-prodv2.properties"
    apply_dir.mkdir(parents=True)
    properties_path.write_text("spring.profiles.active=depot\nlcm.depot.adapter.host=stage.example.test\n", encoding="utf-8")
    tool_dir = tmp_path / "opt" / "labfoundry" / "vcf-download-tool"
    tool_bin = tool_dir / "extracted" / "vcfdt" / "bin" / "vcf-download-tool"
    tool_bin.parent.mkdir(parents=True)
    tool_bin.write_text("#!/bin/sh\n", encoding="utf-8")
    runtime_tool_dir = tmp_path / "var" / "lib" / "labfoundry" / "vcfDownloadTool" / "active-tool"
    chowned: list[tuple[Path, int, int]] = []
    chmodded: list[tuple[Path, int]] = []

    class Account:
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
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "vcf-offline-depot"
    site_dir = tmp_path / "sites.d"
    config_path = apply_dir / "labfoundry-vcf-offline-depot.conf"
    site_path = site_dir / "vcf-offline-depot.conf"
    apply_dir.mkdir(parents=True)
    site_dir.mkdir(parents=True)
    config_path.write_text("# VCF Offline Depot HTTPS endpoint is disabled.\n", encoding="utf-8")
    site_path.write_text("server { listen 443 ssl; }\n", encoding="utf-8")
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "VCF_DEPOT_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "NGINX_CONF_INCLUDE_PATH", tmp_path / "nginx" / "conf.d" / "labfoundry.conf")
    monkeypatch.setattr(helper, "NGINX_MAIN_CONFIG_PATH", tmp_path / "nginx" / "nginx.conf")
    monkeypatch.setattr(helper, "NGINX_SITES_DIR", site_dir)
    monkeypatch.setattr(helper, "VCF_DEPOT_SITE_PATH", site_path)
    monkeypatch.setattr(helper, "_run", fake_run)
    monkeypatch.setattr(helper.shutil, "which", lambda command: "/usr/sbin/nginx" if command == "nginx" else None)

    assert helper._handle_vcf_offline_depot("apply-https", [str(config_path)]) == 0

    assert not site_path.exists()
    assert ["/usr/sbin/nginx", "-t"] in commands


def patch_appliance_settings_nginx_paths(monkeypatch, helper, tmp_path):
    nginx_include = tmp_path / "nginx" / "conf.d" / "labfoundry.conf"
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
    sshd_root_login = sshd_config_dir / "labfoundry-root-login.conf"
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
    import json

    payload = {
        "fqdn": "labfoundry.labfoundry.internal",
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
            "# Managed by LabFoundry. Local changes may be overwritten.",
            f"# LabFoundry NTP enabled: {str(enabled).lower()}",
            "# LabFoundry NTP hostname: ntp.labfoundry.internal",
            "# LabFoundry NTP listen interfaces: eth2.50",
            f"# LabFoundry NTP listen addresses: {listen_address if listen_address else 'none'}",
            f"# LabFoundry NTP client allow list: {allow_clients}",
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
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "appliance-settings"
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "labfoundry-settings.json"
    config_path.write_text(appliance_settings_json(), encoding="utf-8")

    monkeypatch.setattr(helper, "APPLIANCE_SETTINGS_APPLY_DIR", apply_dir)

    assert helper._handle_appliance_settings("validate", [str(config_path)]) == 0


def test_powercli_ceip_uses_all_users_scope_and_verifies_choice(monkeypatch):
    import base64

    helper = load_helper_module()
    captured = {}

    def fake_run(command):
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
    helper = load_helper_module()
    monkeypatch.setattr(helper.shutil, "which", lambda name: "/usr/bin/pwsh" if name == "pwsh" else None)
    monkeypatch.setattr(
        helper,
        "_run",
        lambda command: subprocess.CompletedProcess(command, 3, "VCF.PowerCLI is not installed\n", ""),
    )

    assert helper._configure_powercli_ceip(False) == (0, "skipped: VCF.PowerCLI is not installed")


def test_vcfdt_ceip_writes_service_owned_runtime_flag(monkeypatch, tmp_path):
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
    helper = load_helper_module()

    assert helper._apply_vcf_download_tool_ceip_choice("NOT_PROVIDED") == 2


def test_appliance_settings_helper_requires_https_cert_files(tmp_path):
    helper = load_helper_module()
    config_path = tmp_path / "labfoundry-settings.json"
    config_path.write_text(appliance_settings_json(management_https_enabled=True), encoding="utf-8")

    errors = helper._appliance_settings_config_errors(config_path)

    assert "management_https_cert_path is required when management HTTPS is enabled." in errors
    assert "management_https_key_path is required when management HTTPS is enabled." in errors


def test_appliance_settings_helper_requires_https_and_management_for_web_terminal(tmp_path):
    helper = load_helper_module()
    config_path = tmp_path / "labfoundry-settings.json"
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
    helper = load_helper_module()
    ssh_dir = tmp_path / "ssh" / "sshd_config.d"
    ssh_main = tmp_path / "ssh" / "sshd_config"
    config_dir = tmp_path / "etc" / "labfoundry" / "ssh"
    runtime_dir = tmp_path / "var" / "lib" / "labfoundry" / "web-terminal"
    request_dir = runtime_dir / "requests"
    dropin = ssh_dir / "labfoundry-web-terminal.conf"
    ca_key = config_dir / "web-terminal-ca"
    ca_public = config_dir / "web-terminal-ca.pub"
    ssh_main.parent.mkdir(parents=True)
    ssh_main.write_text("PasswordAuthentication no\n", encoding="utf-8")
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
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
    helper = load_helper_module()
    request_dir = tmp_path / "requests"
    request_dir.mkdir()
    dropin = tmp_path / "labfoundry-web-terminal.conf"
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
    proxy_set_header X-LabFoundry-Listener-Address $server_addr;
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
    helper = load_helper_module()
    config_path = tmp_path / "labfoundry-settings.json"
    config_path.write_text('{"fqdn": "bad name"}', encoding="utf-8")

    errors = helper._appliance_settings_config_errors(config_path)

    assert "fqdn must be a valid fully qualified DNS name." in errors
    assert "resolver_mode must be local_dns, external, or dhcp." in errors


def test_appliance_settings_helper_accepts_dhcp_resolver_mode(tmp_path):
    helper = load_helper_module()
    config_path = tmp_path / "labfoundry-settings.json"
    config_path.write_text(
        appliance_settings_json(resolver_mode="dhcp", resolver_servers=[], local_dns_enabled=False),
        encoding="utf-8",
    )

    errors = helper._appliance_settings_config_errors(config_path)

    assert errors == []


def test_appliance_settings_helper_writes_management_nginx_proxy(monkeypatch, tmp_path):
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "appliance-settings"
    managed_root = tmp_path / "etc" / "labfoundry"
    cert_path = managed_root / "https" / "certs" / "labfoundry.labfoundry.internal.crt"
    key_path = managed_root / "https" / "certs" / "labfoundry.labfoundry.internal.key"
    dropin_dir = tmp_path / "systemd" / "labfoundry.service.d"
    redirect_script = tmp_path / "bin" / "labfoundry-http-redirect"
    redirect_service = tmp_path / "systemd" / "labfoundry-http-redirect.service"
    nginx_include = tmp_path / "nginx" / "conf.d" / "labfoundry.conf"
    nginx_main = tmp_path / "nginx" / "nginx.conf"
    nginx_sites = tmp_path / "nginx" / "sites.d"
    nginx_management_site = nginx_sites / "management.conf"
    sshd_config_dir = tmp_path / "ssh" / "sshd_config.d"
    sshd_root_login = sshd_config_dir / "labfoundry-root-login.conf"
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
    redirect_script.parent.mkdir(parents=True)
    redirect_script.write_text("legacy redirect", encoding="utf-8")
    redirect_service.parent.mkdir(parents=True)
    redirect_service.write_text("legacy redirect service", encoding="utf-8")
    cert_path.write_text("-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n", encoding="utf-8")
    key_path.write_text("-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n", encoding="utf-8")
    config_path = apply_dir / "labfoundry-settings.json"
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
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "APPLIANCE_SETTINGS_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "CA_MANAGED_PATH_BASE", managed_root)
    monkeypatch.setattr(helper, "LABFOUNDRY_SERVICE_DROPIN_DIR", dropin_dir)
    monkeypatch.setattr(helper, "LABFOUNDRY_SERVICE_HTTPS_DROPIN_PATH", dropin_dir / "management-https.conf")
    monkeypatch.setattr(helper, "LABFOUNDRY_HTTP_REDIRECT_SCRIPT_PATH", redirect_script)
    monkeypatch.setattr(helper, "LABFOUNDRY_HTTP_REDIRECT_SERVICE_PATH", redirect_service)
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
    assert 'proxy_set_header X-LabFoundry-Depot-Basic-User "";' in management_site
    root_login = sshd_root_login.read_text(encoding="utf-8")
    assert "PermitRootLogin yes" in root_login
    assert "PasswordAuthentication yes" in root_login
    sshd_main_text = sshd_main.read_text(encoding="utf-8")
    assert "Include /etc/ssh/sshd_config.d/*.conf" in sshd_main_text
    assert "# LabFoundry manages this directive through labfoundry-root-login.conf: PermitRootLogin no" in sshd_main_text
    assert "# LabFoundry manages this directive through labfoundry-root-login.conf: PasswordAuthentication no" in sshd_main_text
    assert not redirect_script.exists()
    assert not redirect_service.exists()
    assert ["systemctl", "daemon-reload"] in commands
    assert ["systemctl", "disable", "--now", "labfoundry-http-redirect.service"] in commands
    assert ["systemctl", "enable", "--now", "nginx"] in commands
    assert ["/usr/sbin/nginx", "-t"] in commands
    assert ["/usr/sbin/sshd", "-t"] in commands
    assert ["systemctl", "restart", "sshd"] in commands
    assert any(command[:5] == ["/usr/bin/systemd-run", "--quiet", "--collect", "--on-active=3", "--unit=labfoundry-management-ui-restart"] for command in commands)


def test_appliance_settings_helper_writes_http_management_proxy_without_https(monkeypatch, tmp_path):
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "appliance-settings"
    dropin_dir = tmp_path / "systemd" / "labfoundry.service.d"
    apply_dir.mkdir(parents=True)
    nginx_paths = patch_appliance_settings_nginx_paths(monkeypatch, helper, tmp_path)
    config_path = apply_dir / "labfoundry-settings.json"
    config_path.write_text(appliance_settings_json(management_https_enabled=False), encoding="utf-8")
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "APPLIANCE_SETTINGS_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "LABFOUNDRY_SERVICE_DROPIN_DIR", dropin_dir)
    monkeypatch.setattr(helper, "LABFOUNDRY_SERVICE_HTTPS_DROPIN_PATH", dropin_dir / "management-https.conf")
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
    assert 'proxy_set_header X-LabFoundry-Depot-Basic-User "";' in management_site
    root_login = nginx_paths["sshd_root_login"].read_text(encoding="utf-8")
    assert "PermitRootLogin no" in root_login
    assert "PasswordAuthentication yes" not in root_login
    assert "Include /etc/ssh/sshd_config.d/*.conf" in nginx_paths["sshd_main"].read_text(encoding="utf-8")
    assert ["systemctl", "enable", "--now", "nginx"] in commands
    assert ["/usr/sbin/nginx", "-t"] in commands
    assert ["/usr/sbin/sshd", "-t"] in commands
    assert ["systemctl", "restart", "sshd"] in commands
    assert any(command[:5] == ["/usr/bin/systemd-run", "--quiet", "--collect", "--on-active=3", "--unit=labfoundry-management-ui-restart"] for command in commands)


def test_appliance_settings_helper_applies_local_resolver_without_timesyncd(monkeypatch, tmp_path):
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "appliance-settings"
    networkd_dir = tmp_path / "etc" / "systemd" / "network"
    dropin_dir = tmp_path / "systemd" / "labfoundry.service.d"
    apply_dir.mkdir(parents=True)
    networkd_dir.mkdir(parents=True)
    mgmt_network = networkd_dir / "00-labfoundry-mgmt.network"
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
    config_path = apply_dir / "labfoundry-settings.json"
    config_path.write_text(appliance_settings_json(), encoding="utf-8")
    patch_appliance_settings_nginx_paths(monkeypatch, helper, tmp_path)
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "APPLIANCE_SETTINGS_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "NETWORKD_MGMT_CONFIG_PATH", mgmt_network)
    monkeypatch.setattr(helper, "LABFOUNDRY_SERVICE_DROPIN_DIR", dropin_dir)
    monkeypatch.setattr(helper, "LABFOUNDRY_SERVICE_HTTPS_DROPIN_PATH", dropin_dir / "management-https.conf")
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

    assert ["/usr/bin/hostnamectl", "set-hostname", "labfoundry.labfoundry.internal"] in commands
    assert ["resolvectl", "dns", "eth0", "127.0.0.1"] in commands
    assert ["resolvectl", "domain", "eth0", "~."] in commands
    assert ["systemctl", "enable", "--now", "systemd-timesyncd"] not in commands
    assert ["systemctl", "restart", "systemd-timesyncd"] not in commands
    network_text = mgmt_network.read_text(encoding="utf-8")
    assert "DNS=1.1.1.1" not in network_text
    assert "DNS=127.0.0.1" in network_text
    assert "Domains=~." in network_text


def test_appliance_settings_helper_applies_external_resolver_without_catchall(monkeypatch, tmp_path):
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "appliance-settings"
    networkd_dir = tmp_path / "etc" / "systemd" / "network"
    dropin_dir = tmp_path / "systemd" / "labfoundry.service.d"
    apply_dir.mkdir(parents=True)
    networkd_dir.mkdir(parents=True)
    mgmt_network = networkd_dir / "00-labfoundry-mgmt.network"
    mgmt_network.write_text(
        "\n".join(["[Match]", "Name=eth0", "", "[Network]", "Address=192.168.49.1/24", "DNS=127.0.0.1", "Domains=~."]) + "\n",
        encoding="utf-8",
    )
    config_path = apply_dir / "labfoundry-settings.json"
    config_path.write_text(
        appliance_settings_json(resolver_mode="external", resolver_servers=["1.1.1.1", "9.9.9.9"], local_dns_enabled=False),
        encoding="utf-8",
    )
    patch_appliance_settings_nginx_paths(monkeypatch, helper, tmp_path)
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "APPLIANCE_SETTINGS_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "NETWORKD_MGMT_CONFIG_PATH", mgmt_network)
    monkeypatch.setattr(helper, "LABFOUNDRY_SERVICE_DROPIN_DIR", dropin_dir)
    monkeypatch.setattr(helper, "LABFOUNDRY_SERVICE_HTTPS_DROPIN_PATH", dropin_dir / "management-https.conf")
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

    assert ["/usr/bin/hostnamectl", "set-hostname", "labfoundry.labfoundry.internal"] in commands
    assert ["resolvectl", "dns", "eth0", "1.1.1.1", "9.9.9.9"] in commands
    assert ["resolvectl", "domain", "eth0", ""] in commands
    network_text = mgmt_network.read_text(encoding="utf-8")
    assert "DNS=127.0.0.1" not in network_text
    assert "Domains=~." not in network_text
    assert "DNS=1.1.1.1" in network_text
    assert "DNS=9.9.9.9" in network_text


def test_ntpd_helper_rejects_invalid_staged_config(monkeypatch, tmp_path):
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "ntpd"
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "labfoundry-ntp.conf"
    config_path.write_text(ntpd_config_text(server="bad_name", listen_address="not-an-ip", allow_clients="any, 192.168.50.0/24"), encoding="utf-8")

    monkeypatch.setattr(helper, "NTP_APPLY_DIR", apply_dir)

    errors = helper._ntpd_config_errors(config_path)

    assert "ntpd server bad_name must be an IPv4 address, IPv6 address, or fully qualified DNS name with an optional port." in errors
    assert "ntpd interface listen address not-an-ip must be a valid IP address." in errors
    assert "ntpd client allow list can use 'any' only by itself." in errors


def test_ntpd_helper_accepts_source_ports_and_rejects_invalid_or_nts_ip_sources(monkeypatch, tmp_path):
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
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "ntpd"
    config_path = apply_dir / "labfoundry-ntp.conf"
    ntp_conf = tmp_path / "etc" / "ntp.conf"
    state_dir = tmp_path / "var" / "lib" / "ntp"
    apply_dir.mkdir(parents=True)
    config_path.write_text(ntpd_config_text(), encoding="utf-8")
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "NTP_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "NTP_CONFIG_PATH", ntp_conf)
    monkeypatch.setattr(helper, "NTP_STATE_DIR", state_dir)
    monkeypatch.setattr(helper, "NTP_DRIFT_PATH", state_dir / "ntp.drift")
    monkeypatch.setattr(helper, "NTP_NTS_COOKIE_PATH", state_dir / "nts-keys")
    monkeypatch.setattr(helper, "_ntpd_runtime_identity_errors", lambda: [])
    monkeypatch.setattr(helper.pwd, "getpwnam", lambda name: type("NtpUser", (), {"pw_uid": 123})())
    monkeypatch.setattr(helper.grp, "getgrnam", lambda name: type("NtpGroup", (), {"gr_gid": 44})())
    monkeypatch.setattr(helper.os, "chown", lambda *args: None, raising=False)
    monkeypatch.setattr(helper, "_run", fake_run)
    (state_dir / "nts-keys").mkdir(parents=True)

    assert helper._handle_ntpd("apply", [str(config_path)]) == 0

    assert ntp_conf.read_text(encoding="utf-8") == config_path.read_text(encoding="utf-8")
    assert state_dir.exists()
    assert (state_dir / "ntp.drift").read_text(encoding="utf-8") == "0.0\n"
    assert not (state_dir / "nts-keys").exists()
    assert ["systemctl", "disable", "--now", "systemd-timesyncd"] in commands
    assert ["systemctl", "disable", "--now", "chronyd.service"] in commands
    assert ["systemctl", "enable", "ntpd.service"] in commands
    assert ["systemctl", "restart", "ntpd.service"] in commands


def test_ntpd_helper_apply_grants_ntp_group_read_to_nts_key(monkeypatch, tmp_path):
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "ntpd"
    managed_root = tmp_path / "etc" / "labfoundry"
    config_path = apply_dir / "labfoundry-ntp.conf"
    ntp_conf = tmp_path / "etc" / "ntp.conf"
    state_dir = tmp_path / "var" / "lib" / "ntp"
    cert_path = managed_root / "ntp" / "certs" / "ntp.labfoundry.internal.crt"
    key_path = managed_root / "ntp" / "certs" / "ntp.labfoundry.internal.key"
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
        gr_gid = 44

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "NTP_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "NTP_CONFIG_PATH", ntp_conf)
    monkeypatch.setattr(helper, "NTP_STATE_DIR", state_dir)
    monkeypatch.setattr(helper, "NTP_DRIFT_PATH", state_dir / "ntp.drift")
    monkeypatch.setattr(helper, "NTP_NTS_COOKIE_PATH", state_dir / "nts-keys")
    monkeypatch.setattr(helper.grp, "getgrnam", lambda name: NTPsecGroup())
    monkeypatch.setattr(helper.pwd, "getpwnam", lambda name: type("NtpUser", (), {"pw_uid": 123})())
    monkeypatch.setattr(helper.os, "chown", lambda path, uid, gid: chown_calls.append((Path(path), uid, gid)), raising=False)
    monkeypatch.setattr(helper, "_ntpd_supports_nts", lambda: True)
    monkeypatch.setattr(helper, "_ntpd_runtime_identity_errors", lambda: [])
    monkeypatch.setattr(helper, "_run", fake_run)

    assert helper._handle_ntpd("apply", [str(config_path)]) == 0

    assert (key_path, 0, 44) in chown_calls
    if os.name != "nt":
        assert oct(key_path.stat().st_mode & 0o777) == "0o640"
    assert ["systemctl", "restart", "ntpd.service"] in commands


def test_ntpd_helper_rejects_missing_nts_certificate_files(monkeypatch, tmp_path):
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "ntpd"
    config_path = apply_dir / "labfoundry-ntp.conf"
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


def test_ntpd_helper_rejects_nts_when_installed_binary_lacks_support(monkeypatch, tmp_path):
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "ntpd"
    config_path = apply_dir / "labfoundry-ntp.conf"
    apply_dir.mkdir(parents=True)
    config_path.write_text(ntpd_config_text(server="time.cloudflare.com").replace(" iburst", " iburst nts"), encoding="utf-8")
    monkeypatch.setattr(helper, "NTP_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "_ntpd_supports_nts", lambda: False)

    errors = helper._ntpd_config_errors(config_path)

    assert "required NTPsec implementation with NTS support" in "\n".join(errors)


def test_ntpd_helper_rejects_remote_control_or_blocked_time_service(monkeypatch, tmp_path):
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "ntpd"
    config_path = apply_dir / "labfoundry-ntp.conf"
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
    helper = load_helper_module()
    commands: list[list[str]] = []

    monkeypatch.setattr(helper.shutil, "which", lambda command: "/usr/bin/journalctl" if command == "journalctl" else None)

    def fake_run(command, **_kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "nginx ready\n", "")

    monkeypatch.setattr(helper, "_run", fake_run)

    assert helper._handle_nginx("logs", []) == 0
    assert capsys.readouterr().out == "nginx ready\n"
    assert commands == [["/usr/bin/journalctl", "-u", "nginx.service", "-n", "500", "--no-pager", "--output=short-iso"]]


def test_nginx_helper_reads_only_fixed_http_log_files(monkeypatch, tmp_path, capsys):
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


def test_ntpd_helper_capabilities_reports_missing_nts(monkeypatch, capsys):
    helper = load_helper_module()
    monkeypatch.setattr(helper.shutil, "which", lambda command: {"ntpd": "/usr/sbin/ntpd", "rpm": "/usr/bin/rpm"}.get(command))
    monkeypatch.setattr(
        helper,
        "_run",
        lambda command, timeout=None: subprocess.CompletedProcess(command, 0, "ntpd ntpsec-1.2.3\n" if "--version" in command else "ntpsec-1.2.3-15.ph5\n", ""),
    )

    assert helper._handle_ntpd("capabilities", []) == 0
    assert json.loads(capsys.readouterr().out)["nts"] is True


def test_ntpd_helper_requires_photon_package_and_ntpsec_binary_identity(monkeypatch):
    helper = load_helper_module()
    monkeypatch.setattr(helper.shutil, "which", lambda command: {"ntpd": "/usr/sbin/ntpd", "rpm": "/usr/bin/rpm"}.get(command))

    def fake_run(command, timeout=None):
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
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "ntpd"
    config_path = apply_dir / "labfoundry-ntp.conf"
    ntp_conf = tmp_path / "etc" / "ntp.conf"
    apply_dir.mkdir(parents=True)
    config_path.write_text(ntpd_config_text(enabled=False, listen_address="", allow_clients="any"), encoding="utf-8")
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "NTP_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "NTP_CONFIG_PATH", ntp_conf)
    monkeypatch.setattr(helper, "_run", fake_run)

    assert helper._handle_ntpd("apply", [str(config_path)]) == 0

    assert not ntp_conf.exists()
    assert commands == [["systemctl", "disable", "--now", "ntpd.service"]]


def test_ntpd_helper_disabled_apply_allows_empty_upstream_list(monkeypatch, tmp_path):
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "ntpd"
    config_path = apply_dir / "labfoundry-ntp.conf"
    ntp_conf = tmp_path / "etc" / "ntp.conf"
    apply_dir.mkdir(parents=True)
    config_path.write_text(ntpd_config_text(enabled=False, server="", listen_address="", allow_clients="any"), encoding="utf-8")
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "NTP_APPLY_DIR", apply_dir)
    monkeypatch.setattr(helper, "NTP_CONFIG_PATH", ntp_conf)
    monkeypatch.setattr(helper, "_run", fake_run)

    assert helper._handle_ntpd("apply", [str(config_path)]) == 0

    assert not ntp_conf.exists()
    assert commands == [["systemctl", "disable", "--now", "ntpd.service"]]


def test_ntpd_helper_status_reads_peers_variables_and_nts(monkeypatch, capsys):
    helper = load_helper_module()
    commands: list[tuple[list[str], float | None]] = []

    def fake_run(command: list[str], *, timeout: float | None = None) -> subprocess.CompletedProcess[str]:
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
    helper = load_helper_module()

    def fake_run(command: list[str], *, timeout: float | None = None) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(command, timeout)

    monkeypatch.setattr(helper.shutil, "which", lambda command: "/usr/bin/ntpq" if command == "ntpq" else None)
    monkeypatch.setattr(helper, "_run", fake_run)

    assert helper._handle_ntpd("status", []) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["peers"]["returncode"] == 124
    assert payload["variables"]["returncode"] == 124
    assert payload["nts"]["stderr"] == "ntpq status command timed out after 1.5 seconds"


def test_appliance_settings_hostname_fallback_writes_etc_hostname(monkeypatch, tmp_path):
    helper = load_helper_module()
    hostname_path = tmp_path / "hostname"
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper.shutil, "which", lambda command: "/usr/bin/hostname" if command == "hostname" else None)
    monkeypatch.setattr(helper, "_run", fake_run)
    monkeypatch.setattr(helper, "Path", lambda value: hostname_path if value == "/etc/hostname" else Path(value))

    assert helper._apply_hostname("fallback.labfoundry.internal") == 0

    assert hostname_path.read_text(encoding="utf-8") == "fallback.labfoundry.internal\n"
    assert commands == [["/usr/bin/hostname", "fallback.labfoundry.internal"]]


def test_esx_storage_existing_bind_mount_is_recognized_by_inode(monkeypatch):
    helper = load_helper_module()
    source = Path("/mnt/labfoundry-esx-storage/data/share")
    target = Path("/srv/labfoundry/esx-storage/share")
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, str(target), "")

    def fake_stat(path: os.PathLike[str], *, follow_symlinks: bool = True) -> SimpleNamespace:
        assert follow_symlinks is True
        assert Path(path) in {source, target}
        return SimpleNamespace(st_dev=2049, st_ino=8192)

    monkeypatch.setattr(helper, "_run", fake_run)
    monkeypatch.setattr(helper.os, "stat", fake_stat)

    assert helper._esx_storage_bind_mount_matches("/usr/bin/findmnt", source, target) is True
    assert commands == [["/usr/bin/findmnt", "-n", "--mountpoint", str(target)]]


def test_esx_storage_rejects_wrong_mount_at_bind_target(monkeypatch):
    helper = load_helper_module()
    source = Path("/mnt/labfoundry-esx-storage/data/share")
    target = Path("/srv/labfoundry/esx-storage/share")

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
