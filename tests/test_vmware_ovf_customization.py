"""Test vmware ovf customization behavior."""

import base64
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

VALID_ED25519_PUBLIC_KEY = (
    "ssh-ed25519 "
    "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f "
    "atlaso-test"
)


def load_customizer():
    """Return customizer."""
    path = Path("scripts/appliance/atlaso-vmware-ovf-customize.py")
    spec = importlib.util.spec_from_file_location("atlaso_vmware_ovf_customize", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["atlaso_vmware_ovf_customize"] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("platform", ("vmware", "qemu", "hyperv", "baremetal"))
def test_portable_first_boot_uses_verified_guest_agent_platform_marker(tmp_path: Path, platform: str) -> None:
    """The OVF handoff consumes the prerequisite provider-neutral platform result."""

    customizer = load_customizer()
    marker = tmp_path / "guest-agent.applied"
    marker.write_text(f"platform={platform}\n", encoding="utf-8")
    customizer.GUEST_AGENT_MARKER_PATH = marker

    assert customizer.detect_virtualization_platform() == platform


def test_portable_first_boot_rejects_invalid_guest_agent_platform_marker(tmp_path: Path) -> None:
    """Unknown or malformed prerequisite state cannot fall through to OVF polling."""

    customizer = load_customizer()
    marker = tmp_path / "guest-agent.applied"
    marker.write_text("platform=xen\n", encoding="utf-8")
    customizer.GUEST_AGENT_MARKER_PATH = marker

    with pytest.raises(customizer.OvfCustomizationError, match="platform marker is invalid"):
        customizer.detect_virtualization_platform()


OVF_ENV = """<?xml version="1.0" encoding="UTF-8"?>
<Environment
  xmlns="http://schemas.dmtf.org/ovf/environment/1"
  xmlns:oe="http://schemas.dmtf.org/ovf/environment/1">
  <PropertySection>
    <Property oe:key="atlaso.management_mode" oe:value="static" />
    <Property oe:key="atlaso.cidr" oe:value="192.168.10.10/24" />
    <Property oe:key="atlaso.gateway" oe:value="192.168.10.1" />
    <Property oe:key="atlaso.fqdn" oe:value="appliance.atlaso.internal" />
    <Property oe:key="atlaso.dns_servers" oe:value="192.168.10.2,192.168.10.3" />
    <Property oe:key="atlaso.admin_password" oe:value="admin-secret" />
    <Property oe:key="atlaso.root_password" oe:value="root-secret1" />
  </PropertySection>
</Environment>
"""


def test_vmware_ovf_customizer_parses_and_validates_properties_without_logging_secrets():
    """Verify that vmware ovf customizer parses and validates properties without logging secrets."""
    customizer = load_customizer()

    properties = customizer.parse_ovf_environment(OVF_ENV)
    config = customizer.validate_properties(properties)
    summary = customizer.redacted_summary(config)

    assert config["management_mode"] == "static"
    assert config["cidr"] == "192.168.10.10/24"
    assert config["gateway"] == "192.168.10.1"
    assert config["fqdn"] == "appliance.atlaso.internal"
    assert config["dns_servers"] == ["192.168.10.2", "192.168.10.3"]
    assert config["management_source_cidr"] == "192.168.10.0/24"
    assert summary["admin_password_set"] is True
    assert summary["root_password_set"] is True
    assert "admin-secret" not in str(summary)
    assert "root-secret1" not in str(summary)


def test_vmware_ovf_customizer_supports_dhcp_management_by_default():
    """Verify that vmware ovf customizer supports dhcp management by default."""
    customizer = load_customizer()
    properties = customizer.parse_ovf_environment(OVF_ENV)
    properties.pop("atlaso.management_mode")
    properties.pop("atlaso.cidr")
    properties.pop("atlaso.gateway")
    properties.pop("atlaso.dns_servers")

    config = customizer.validate_properties(properties)

    assert config["management_mode"] == "dhcp"
    assert config["cidr"] == "dhcp"
    assert config["gateway"] == ""
    assert config["dns_servers"] == []
    assert config["management_source_cidr"] == ""


@pytest.mark.parametrize(
    ("overrides", "removed_properties", "expected"),
    [
        (
            {},
            (),
            {
                "ATLASO_APPLIANCE_MANAGEMENT_CIDR": "192.168.10.10/24",
                "ATLASO_APPLIANCE_MANAGEMENT_GATEWAY": "192.168.10.1",
                "ATLASO_APPLIANCE_MANAGEMENT_IPV6_GATEWAY": "",
            },
        ),
        (
            {
                "atlaso.management_mode": "dhcp",
                "atlaso.ipv6_enabled": "true",
                "atlaso.ipv6_cidr": "fd00:10::10/64",
                "atlaso.ipv6_gateway": "fe80::1",
            },
            ("atlaso.cidr", "atlaso.gateway"),
            {
                "ATLASO_APPLIANCE_MANAGEMENT_CIDR": "dhcp",
                "ATLASO_APPLIANCE_MANAGEMENT_GATEWAY": "",
                "ATLASO_APPLIANCE_MANAGEMENT_IPV6_GATEWAY": "fe80::1",
            },
        ),
        (
            {
                "atlaso.ipv6_enabled": "true",
                "atlaso.ipv6_cidr": "fd00:10::10/64",
                "atlaso.ipv6_gateway": "fe80::1",
            },
            (),
            {
                "ATLASO_APPLIANCE_MANAGEMENT_CIDR": "192.168.10.10/24",
                "ATLASO_APPLIANCE_MANAGEMENT_GATEWAY": "192.168.10.1",
                "ATLASO_APPLIANCE_MANAGEMENT_IPV6_GATEWAY": "fe80::1",
            },
        ),
    ],
)
def test_vmware_ovf_customizer_preserves_management_gateway_environment_handoff(
    overrides, removed_properties, expected
):
    """Preserve IPv4-only, IPv6-only, and dual-stack gateway handoff to Atlaso.

    Args:
        overrides: OVF property overrides for one address-family scenario.
        removed_properties: Properties omitted for one address-family scenario.
        expected: Expected non-secret management environment values.
    """
    customizer = load_customizer()
    properties = customizer.parse_ovf_environment(OVF_ENV)
    for property_name in removed_properties:
        properties.pop(property_name)
    properties.update(overrides)

    environment = customizer.appliance_environment_values(customizer.validate_properties(properties))

    for key, value in expected.items():
        assert environment[key] == value


def test_vmware_ovf_customizer_validates_optional_development_admin_key():
    """Accept exactly one canonical Ed25519 key without affecting ordinary OVF inputs."""
    customizer = load_customizer()
    properties = customizer.parse_ovf_environment(OVF_ENV)

    assert customizer.validate_properties(properties)["development_admin_ssh_public_key"] == ""
    assert customizer.validate_properties(properties)["normal_test_vm"] is False

    properties[customizer.PROPERTY_DEVELOPMENT_ADMIN_SSH_PUBLIC_KEY] = VALID_ED25519_PUBLIC_KEY
    properties[customizer.PROPERTY_NORMAL_TEST_VM] = "true"
    config = customizer.validate_properties(properties)
    summary = customizer.redacted_summary(config)

    assert config["development_admin_ssh_public_key"] == VALID_ED25519_PUBLIC_KEY
    assert config["normal_test_vm"] is True
    assert summary["development_admin_ssh_key_set"] is True
    assert summary["development_admin_passwordless_sudo"] is True
    assert VALID_ED25519_PUBLIC_KEY not in str(summary)


def test_vmware_ovf_customizer_stages_and_scrubs_development_root_key(
    tmp_path, monkeypatch
):
    """Stage the shared signer mode 0600 without exposing it in summaries.

    Args:
        tmp_path: Isolated staging root.
        monkeypatch: Pytest fixture used to replace VMware guest-info access.
    """
    customizer = load_customizer()
    customizer.DEVELOPMENT_ROOT_CA_STAGING_PATH = tmp_path / "ca" / "development.json"
    certificate_pem = (
        "-----BEGIN CERTIFICATE-----\nY2VydGlmaWNhdGU=\n-----END CERTIFICATE-----\n"
    )
    private_key_pem = (
        "-----BEGIN PRIVATE KEY-----\ncHJpdmF0ZS1rZXk=\n-----END PRIVATE KEY-----\n"
    )
    properties = customizer.parse_ovf_environment(OVF_ENV)
    properties[customizer.PROPERTY_DEVELOPMENT_TEST_VM] = "true"
    properties[customizer.PROPERTY_DEVELOPMENT_ROOT_CA_CERTIFICATE] = base64.b64encode(
        certificate_pem.encode("ascii")
    ).decode("ascii")
    config = customizer.validate_properties(properties)
    clears = []
    monkeypatch.setattr(
        customizer,
        "try_read_guestinfo_value",
        lambda name: (
            True,
            base64.b64encode(private_key_pem.encode("ascii")).decode("ascii"),
        ),
    )
    monkeypatch.setattr(
        customizer,
        "clear_guestinfo_value",
        lambda name: clears.append(name),
    )

    customizer.stage_development_root_ca(config)

    staged = json.loads(
        customizer.DEVELOPMENT_ROOT_CA_STAGING_PATH.read_text(encoding="utf-8")
    )
    assert staged == {
        "certificate_pem": certificate_pem,
        "private_key_pem": private_key_pem,
    }
    if os.name == "posix":
        assert customizer.DEVELOPMENT_ROOT_CA_STAGING_PATH.stat().st_mode & 0o777 == 0o600
    assert clears == [customizer.DEVELOPMENT_ROOT_CA_PRIVATE_KEY_GUESTINFO]
    summary = customizer.redacted_summary(config)
    assert summary["development_root_ca_staged"] is True
    assert private_key_pem not in str(summary)


def test_atomic_json_applies_secret_mode_before_opening_payload(tmp_path, monkeypatch):
    """Apply the requested staging mode before a shared signer can be written.

    Args:
        tmp_path: Isolated destination directory.
        monkeypatch: Pytest fixture used to observe descriptor setup order.
    """
    customizer = load_customizer()
    destination = tmp_path / "development-root.json"
    events = []
    original_fchmod = customizer.os.fchmod
    original_fdopen = customizer.os.fdopen

    def record_fchmod(descriptor, mode):
        """Record mode ordering while delegating to the real descriptor helper.

        Args:
            descriptor: Open temporary-file descriptor.
            mode: Requested POSIX file mode.
        """
        events.append(("fchmod", mode))
        return original_fchmod(descriptor, mode)

    def record_fdopen(descriptor, *args, **kwargs):
        """Record open ordering while delegating to the real descriptor helper.

        Args:
            descriptor: Open temporary-file descriptor.
            *args: Positional arguments forwarded to ``os.fdopen``.
            **kwargs: Keyword arguments forwarded to ``os.fdopen``.
        """
        events.append(("fdopen", None))
        return original_fdopen(descriptor, *args, **kwargs)

    monkeypatch.setattr(customizer.os, "fchmod", record_fchmod)
    monkeypatch.setattr(customizer.os, "fdopen", record_fdopen)
    customizer.write_json_atomic(destination, {"private_key_pem": "redacted"}, mode=0o600)

    assert events[:2] == [("fchmod", 0o600), ("fdopen", None)]


def test_vmware_ovf_customizer_rejects_development_root_without_test_access():
    """Keep the development trust field out of lifecycle and exported inputs."""
    customizer = load_customizer()
    properties = customizer.parse_ovf_environment(OVF_ENV)
    properties[customizer.PROPERTY_DEVELOPMENT_ROOT_CA_CERTIFICATE] = base64.b64encode(
        b"-----BEGIN CERTIFICATE-----\nYQ==\n-----END CERTIFICATE-----\n"
    ).decode("ascii")

    with pytest.raises(customizer.OvfCustomizationError, match="normal test wrapper"):
        customizer.validate_properties(properties)


def test_vmware_ovf_customizer_requires_proven_guestinfo_scrub(monkeypatch):
    """Fail when VMware Tools accepts a clear but cannot prove the value is empty.

    Args:
        monkeypatch: Pytest fixture used to replace VMware Tools subprocesses.
    """
    customizer = load_customizer()
    monkeypatch.setattr(customizer.shutil, "which", lambda command: f"/usr/bin/{command}")
    monkeypatch.setattr(
        customizer.subprocess,
        "run",
        lambda *args, **kwargs: type(
            "Result", (), {"returncode": 0, "stdout": "still-present"}
        )(),
    )

    with pytest.raises(customizer.OvfCustomizationError, match="could not prove"):
        customizer.clear_guestinfo_value(
            customizer.DEVELOPMENT_ROOT_CA_PRIVATE_KEY_GUESTINFO
        )


@pytest.mark.parametrize(
    "candidate",
    [
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ==",
        "ssh-ed25519 not-base64",
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAHw==",
        f"{VALID_ED25519_PUBLIC_KEY}\nsecond-key",
        f" {VALID_ED25519_PUBLIC_KEY}",
        "x" * 4097,
    ],
)
def test_vmware_ovf_customizer_rejects_unsafe_development_admin_keys(candidate):
    """Reject malformed, non-Ed25519, multiline, and unbounded development keys.

    Args:
        candidate: Invalid public-key input under test.
    """
    customizer = load_customizer()

    with pytest.raises(customizer.OvfCustomizationError, match="development_admin_ssh_public_key"):
        customizer.validate_ed25519_public_key(candidate)


def test_vmware_ovf_customizer_installs_development_key_and_validated_sudoers(
    tmp_path, monkeypatch
):
    """Install exact key access idempotently with constrained ownership and modes.

    Args:
        tmp_path: Isolated filesystem root.
        monkeypatch: Pytest monkeypatch fixture.
    """
    customizer = load_customizer()
    home = tmp_path / "admin"
    home.mkdir()
    sudoers_directory = tmp_path / "sudoers.d"
    sudoers_directory.mkdir()
    customizer.DEVELOPMENT_ADMIN_SUDOERS_PATH = sudoers_directory / "atlaso-test-vm-admin"
    account = type(
        "Account",
        (),
        {"pw_dir": str(home), "pw_uid": 1001, "pw_gid": 1001},
    )()
    monkeypatch.setattr(customizer, "resolve_os_account", lambda username: account)
    chowns = []
    monkeypatch.setattr(
        customizer,
        "chown_path",
        lambda path, uid, gid: chowns.append((Path(path), uid, gid)),
    )
    chmods = []

    def record_chmod(path, mode):
        """Record and emulate one POSIX mode change.

        Args:
            path: Exact path whose mode changes.
            mode: Requested POSIX mode.
        """
        chmods.append((Path(path), mode))
        Path(path).chmod(mode)

    monkeypatch.setattr(customizer, "chmod_path", record_chmod)
    if sys.platform == "win32":
        def replace_readonly_file(source, destination):
            """Emulate POSIX replacement despite Windows read-only attributes.

            Args:
                source: Prepared source file.
                destination: Destination file to replace.
            """
            final_mode = source.stat().st_mode & 0o777
            source.chmod(0o600)
            if destination.exists():
                destination.chmod(0o600)
            source.replace(destination)
            destination.chmod(final_mode)

        def unlink_readonly_file(path):
            """Remove a POSIX-read-only test file on Windows.

            Args:
                path: Exact test file to remove.
            """
            if path.exists():
                path.chmod(0o600)
                path.unlink()

        monkeypatch.setattr(customizer, "replace_path_atomic", replace_readonly_file)
        monkeypatch.setattr(customizer, "unlink_path", unlink_readonly_file)
    monkeypatch.setattr(customizer.shutil, "which", lambda command: "/usr/sbin/visudo" if command == "visudo" else None)
    visudo_calls = []

    def run_visudo(command, **kwargs):
        """Validate the generated sudoers candidate without invoking Linux visudo.

        Args:
            command: Requested visudo command line.
            **kwargs: Subprocess options supplied by the customizer.

        Returns:
            A successful simulated subprocess result.
        """
        assert command[:2] == ["/usr/sbin/visudo", "-cf"]
        candidate = Path(command[2])
        assert candidate.read_text(encoding="utf-8").endswith(
            "admin ALL=(ALL) NOPASSWD: ALL\n"
        )
        visudo_calls.append(candidate)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(customizer.subprocess, "run", run_visudo)

    customizer.configure_development_admin_ssh("admin", VALID_ED25519_PUBLIC_KEY)
    customizer.configure_development_admin_ssh("admin", VALID_ED25519_PUBLIC_KEY)

    authorized_keys = home / ".ssh" / "authorized_keys"
    assert authorized_keys.read_text(encoding="utf-8") == f"{VALID_ED25519_PUBLIC_KEY}\n"
    if sys.platform == "win32":
        assert (home / ".ssh", 0o700) in chmods
        assert any(path.name.startswith(".authorized_keys.") and mode == 0o600 for path, mode in chmods)
        assert any(path.name.startswith(".atlaso-test-vm-admin.") and mode == 0o440 for path, mode in chmods)
    else:
        assert authorized_keys.stat().st_mode & 0o777 == 0o600
        assert (home / ".ssh").stat().st_mode & 0o777 == 0o700
        assert customizer.DEVELOPMENT_ADMIN_SUDOERS_PATH.stat().st_mode & 0o777 == 0o440
    assert len(visudo_calls) == 2
    assert any(
        path.name.startswith(".authorized_keys.") and uid == 1001 and gid == 1001
        for path, uid, gid in chowns
    )


def test_vmware_ovf_customizer_restores_authorized_keys_when_sudoers_validation_fails(
    tmp_path, monkeypatch
):
    """Leave prior administrator access unchanged when the sudoers candidate is invalid.

    Args:
        tmp_path: Isolated filesystem root.
        monkeypatch: Pytest monkeypatch fixture.
    """
    customizer = load_customizer()
    home = tmp_path / "admin"
    ssh_directory = home / ".ssh"
    ssh_directory.mkdir(parents=True)
    authorized_keys = ssh_directory / "authorized_keys"
    authorized_keys.write_text("prior-key\n", encoding="utf-8")
    sudoers_directory = tmp_path / "sudoers.d"
    sudoers_directory.mkdir()
    customizer.DEVELOPMENT_ADMIN_SUDOERS_PATH = sudoers_directory / "atlaso-test-vm-admin"
    account = type(
        "Account",
        (),
        {"pw_dir": str(home), "pw_uid": 1001, "pw_gid": 1001},
    )()
    monkeypatch.setattr(customizer, "resolve_os_account", lambda username: account)
    monkeypatch.setattr(customizer, "chown_path", lambda path, uid, gid: None)
    if sys.platform == "win32":
        def unlink_readonly_file(path):
            """Remove a POSIX-read-only test file on Windows.

            Args:
                path: Exact test file to remove.
            """
            if path.exists():
                path.chmod(0o600)
                path.unlink()

        monkeypatch.setattr(customizer, "unlink_path", unlink_readonly_file)
    monkeypatch.setattr(customizer.shutil, "which", lambda command: "/usr/sbin/visudo")

    def reject_sudoers(command, **kwargs):
        """Simulate a sudoers syntax-validation failure.

        Args:
            command: Requested visudo command line.
            **kwargs: Subprocess options supplied by the customizer.

        Raises:
            subprocess.CalledProcessError: Always, to exercise rollback.
        """
        raise subprocess.CalledProcessError(1, command)

    monkeypatch.setattr(customizer.subprocess, "run", reject_sudoers)

    with pytest.raises(customizer.OvfCustomizationError, match="passwordless sudo validation failed"):
        customizer.configure_development_admin_ssh("admin", VALID_ED25519_PUBLIC_KEY)

    assert authorized_keys.read_text(encoding="utf-8") == "prior-key\n"
    assert not customizer.DEVELOPMENT_ADMIN_SUDOERS_PATH.exists()


def test_vmware_ovf_customizer_restores_authorized_keys_when_key_directory_sync_fails(
    tmp_path, monkeypatch
):
    """Restore prior administrator access if the new key is not durably installed.

    Args:
        tmp_path: Isolated filesystem root.
        monkeypatch: Pytest monkeypatch fixture.
    """
    customizer = load_customizer()
    home = tmp_path / "admin"
    ssh_directory = home / ".ssh"
    ssh_directory.mkdir(parents=True)
    authorized_keys = ssh_directory / "authorized_keys"
    authorized_keys.write_text("prior-key\n", encoding="utf-8")
    sudoers_directory = tmp_path / "sudoers.d"
    sudoers_directory.mkdir()
    customizer.DEVELOPMENT_ADMIN_SUDOERS_PATH = sudoers_directory / "atlaso-test-vm-admin"
    account = type(
        "Account",
        (),
        {"pw_dir": str(home), "pw_uid": 1001, "pw_gid": 1001},
    )()
    monkeypatch.setattr(customizer, "resolve_os_account", lambda username: account)
    monkeypatch.setattr(customizer, "chown_path", lambda path, uid, gid: None)
    monkeypatch.setattr(customizer.shutil, "which", lambda command: "/usr/sbin/visudo")
    monkeypatch.setattr(
        customizer.subprocess,
        "run",
        lambda command, **kwargs: subprocess.CompletedProcess(command, 0),
    )
    original_fsync_parent = customizer.fsync_parent_directory
    failed = False

    def fail_first_new_key_sync(path):
        """Fail once after the replacement key reaches its final pathname.

        Args:
            path: Destination whose parent is being synchronized.

        Raises:
            OSError: Once, after the new authorized key has been installed.
        """
        nonlocal failed
        candidate = Path(path)
        if (
            candidate == authorized_keys
            and not failed
            and candidate.read_text(encoding="utf-8") == f"{VALID_ED25519_PUBLIC_KEY}\n"
        ):
            failed = True
            raise OSError("simulated authorized_keys directory sync failure")
        original_fsync_parent(candidate)

    monkeypatch.setattr(customizer, "fsync_parent_directory", fail_first_new_key_sync)

    with pytest.raises(customizer.OvfCustomizationError, match="passwordless sudo validation failed"):
        customizer.configure_development_admin_ssh("admin", VALID_ED25519_PUBLIC_KEY)

    assert failed is True
    assert authorized_keys.read_text(encoding="utf-8") == "prior-key\n"
    assert not customizer.DEVELOPMENT_ADMIN_SUDOERS_PATH.exists()


def test_vmware_ovf_customizer_rolls_back_both_files_after_sudoers_replace_failure(
    tmp_path, monkeypatch
):
    """Restore prior key and sudoers content if post-replacement persistence fails.

    Args:
        tmp_path: Isolated filesystem root.
        monkeypatch: Pytest monkeypatch fixture.
    """
    customizer = load_customizer()
    home = tmp_path / "admin"
    ssh_directory = home / ".ssh"
    ssh_directory.mkdir(parents=True)
    authorized_keys = ssh_directory / "authorized_keys"
    authorized_keys.write_text("prior-key\n", encoding="utf-8")
    sudoers_directory = tmp_path / "sudoers.d"
    sudoers_directory.mkdir()
    sudoers_path = sudoers_directory / "atlaso-test-vm-admin"
    sudoers_path.write_text("prior sudoers\n", encoding="utf-8")
    customizer.DEVELOPMENT_ADMIN_SUDOERS_PATH = sudoers_path
    account = type(
        "Account",
        (),
        {"pw_dir": str(home), "pw_uid": 1001, "pw_gid": 1001},
    )()
    monkeypatch.setattr(customizer, "resolve_os_account", lambda username: account)
    monkeypatch.setattr(customizer, "chown_path", lambda path, uid, gid: None)
    monkeypatch.setattr(customizer.shutil, "which", lambda command: "/usr/sbin/visudo")
    monkeypatch.setattr(
        customizer.subprocess,
        "run",
        lambda command, **kwargs: subprocess.CompletedProcess(command, 0),
    )

    if sys.platform == "win32":
        def replace_readonly_file(source, destination):
            """Emulate POSIX replacement despite Windows read-only attributes.

            Args:
                source: Prepared source file.
                destination: Destination file to replace.
            """
            final_mode = source.stat().st_mode & 0o777
            source.chmod(0o600)
            if destination.exists():
                destination.chmod(0o600)
            source.replace(destination)
            destination.chmod(final_mode)

        def unlink_readonly_file(path):
            """Remove a POSIX-read-only test file on Windows.

            Args:
                path: Exact test file to remove.
            """
            if path.exists():
                path.chmod(0o600)
                path.unlink()

        monkeypatch.setattr(customizer, "replace_path_atomic", replace_readonly_file)
        monkeypatch.setattr(customizer, "unlink_path", unlink_readonly_file)

    original_fsync_parent = customizer.fsync_parent_directory
    failed = False

    def fail_first_new_sudoers_sync(path):
        """Fail only the first directory sync after new sudoers replacement.

        Args:
            path: Destination whose parent is being synchronized.

        Raises:
            OSError: Once, after the new sudoers content has been installed.
        """
        nonlocal failed
        candidate = Path(path)
        if candidate == sudoers_path and not failed and b"NOPASSWD" in candidate.read_bytes():
            failed = True
            raise OSError("simulated sudoers directory sync failure")
        original_fsync_parent(candidate)

    monkeypatch.setattr(customizer, "fsync_parent_directory", fail_first_new_sudoers_sync)

    with pytest.raises(customizer.OvfCustomizationError, match="passwordless sudo validation failed"):
        customizer.configure_development_admin_ssh("admin", VALID_ED25519_PUBLIC_KEY)

    assert failed is True
    assert authorized_keys.read_text(encoding="utf-8") == "prior-key\n"
    assert sudoers_path.read_text(encoding="utf-8") == "prior sudoers\n"


def test_vmware_ovf_customizer_rejects_empty_or_whitespace_passwords():
    """Verify that vmware ovf customizer rejects empty or whitespace passwords.

    Raises:
        AssertionError: If an expected invariant is not satisfied.
    """
    customizer = load_customizer()

    for key, value in (
        ("atlaso.admin_password", ""),
        ("atlaso.admin_password", "   "),
        ("atlaso.root_password", ""),
        ("atlaso.root_password", "   "),
        ("atlaso.admin_password", "Short1!"),
        ("atlaso.root_password", "Short1!"),
    ):
        properties = customizer.parse_ovf_environment(OVF_ENV)
        properties[key] = value

        try:
            customizer.validate_properties(properties)
        except customizer.OvfCustomizationError as exc:
            assert key in str(exc)
        else:
            raise AssertionError(f"Expected an empty {key} value to be rejected")


def test_vmware_ovf_customizer_preserves_release_ovf_password_whitespace():
    """Verify XML password attributes are consumed without destructive trimming."""
    customizer = load_customizer()
    admin_password = "  admin-secret  "
    root_password = "root-secret1  "
    ovf_environment = OVF_ENV.replace("admin-secret", admin_password).replace(
        "root-secret1",
        root_password,
    )

    properties = customizer.parse_ovf_environment(ovf_environment)
    config = customizer.validate_properties(properties)

    assert properties[customizer.PROPERTY_ADMIN_PASSWORD] == admin_password
    assert properties[customizer.PROPERTY_ROOT_PASSWORD] == root_password
    assert config["admin_password"] == admin_password
    assert config["root_password"] == root_password


def test_vmware_ovf_customizer_ignores_legacy_mode_and_derives_ipv4_from_cidr():
    """Verify that vmware ovf customizer ignores legacy mode and derives ipv4 from cidr."""
    customizer = load_customizer()
    properties = customizer.parse_ovf_environment(OVF_ENV)
    properties["atlaso.management_mode"] = "dhcp"

    config = customizer.validate_properties(properties)

    assert config["management_mode"] == "static"
    properties.pop("atlaso.cidr")
    properties.pop("atlaso.gateway")
    assert customizer.validate_properties(properties)["management_mode"] == "dhcp"


def test_vmware_ovf_customizer_rejects_incomplete_ipv4_pairs():
    """Verify that vmware ovf customizer rejects incomplete ipv4 pairs.

    Raises:
        AssertionError: If an expected invariant is not satisfied.
    """
    customizer = load_customizer()
    properties = customizer.parse_ovf_environment(OVF_ENV)
    properties.pop("atlaso.gateway")
    try:
        customizer.validate_properties(properties)
    except customizer.OvfCustomizationError as exc:
        assert "requires an IPv4 gateway" in str(exc)
    else:
        raise AssertionError("static IPv4 without a gateway should fail")

    properties.pop("atlaso.cidr")
    properties["atlaso.gateway"] = "192.168.10.1"
    try:
        customizer.validate_properties(properties)
    except customizer.OvfCustomizationError as exc:
        assert "requires an address and prefix" in str(exc)
    else:
        raise AssertionError("IPv4 gateway without a CIDR should fail")


@pytest.mark.parametrize(
    ("cidr", "gateway", "message"),
    [
        ("192.168.1.254/32", "192.168.1.1", "on-link"),
        ("192.168.1.254/24", "192.168.1.254", "cannot equal"),
        ("192.168.10.10/24", "192.168.10.0", "usable host"),
        ("192.168.10.10/24", "192.168.10.255", "usable host"),
        ("192.168.10.0/24", "192.168.10.1", "address must be a usable host"),
    ],
)
def test_vmware_ovf_customizer_rejects_invalid_ipv4_gateway_relationships(cidr, gateway, message):
    """Verify OVF IPv4 validation uses the shared cross-field contract.

    Args:
        cidr: Candidate management IPv4 address and prefix.
        gateway: Candidate management IPv4 gateway.
        message: Expected validation-message fragment.
    """
    customizer = load_customizer()
    properties = customizer.parse_ovf_environment(OVF_ENV)
    properties["atlaso.cidr"] = cidr
    properties["atlaso.gateway"] = gateway

    with pytest.raises(customizer.OvfManagementNetworkError, match=message):
        customizer.validate_properties(properties)


@pytest.mark.parametrize(
    ("cidr", "gateway", "message"),
    [
        ("127.0.0.2/8", "127.0.0.1", "Management IPv4 address must be a unicast address"),
        ("192.168.10.10/24", "127.0.0.1", "Management IPv4 gateway must be a unicast address"),
        ("224.0.0.2/24", "224.0.0.1", "Management IPv4 address must be a unicast address"),
    ],
)
def test_vmware_ovf_customizer_rejects_non_unicast_ipv4_values(cidr, gateway, message):
    """Verify OVF and tty1 share rejection of non-unicast IPv4 values.

    Args:
        cidr: Candidate management IPv4 address and prefix.
        gateway: Candidate management IPv4 gateway.
        message: Expected validation-message fragment.
    """
    customizer = load_customizer()
    properties = customizer.parse_ovf_environment(OVF_ENV)
    properties["atlaso.cidr"] = cidr
    properties["atlaso.gateway"] = gateway

    with pytest.raises(customizer.OvfManagementNetworkError, match=message):
        customizer.validate_properties(properties)


@pytest.mark.parametrize(
    ("cidr", "gateway", "message"),
    [
        ("::/64", "::2", "Management IPv6 address must be a unicast address"),
        ("fd00:49::10/64", "::1", "Management IPv6 gateway must be a unicast address"),
        ("ff02::2/64", "fe80::1", "Management IPv6 address must be a unicast address"),
    ],
)
def test_vmware_ovf_customizer_rejects_non_unicast_ipv6_values(cidr, gateway, message):
    """Verify OVF and tty1 share rejection of non-unicast IPv6 values.

    Args:
        cidr: Candidate management IPv6 address and prefix.
        gateway: Candidate management IPv6 gateway.
        message: Expected validation-message fragment.
    """
    customizer = load_customizer()
    properties = customizer.parse_ovf_environment(OVF_ENV)
    properties["atlaso.ipv6_enabled"] = "true"
    properties["atlaso.ipv6_cidr"] = cidr
    properties["atlaso.ipv6_gateway"] = gateway

    with pytest.raises(customizer.OvfManagementNetworkError, match=message):
        customizer.validate_properties(properties)


def test_vmware_ovf_customizer_accepts_ipv4_point_to_point_gateway_peers():
    """Verify both addresses in an IPv4 /31 remain usable point-to-point hosts."""
    customizer = load_customizer()
    properties = customizer.parse_ovf_environment(OVF_ENV)
    properties["atlaso.cidr"] = "192.0.2.0/31"
    properties["atlaso.gateway"] = "192.0.2.1"

    config = customizer.validate_properties(properties)

    assert config["cidr"] == "192.0.2.0/31"
    assert config["gateway"] == "192.0.2.1"


def test_vmware_ovf_customizer_routes_invalid_ipv6_mode_to_network_review():
    """Verify malformed IPv6 enablement remains recoverable from tty1."""
    customizer = load_customizer()
    properties = customizer.parse_ovf_environment(OVF_ENV)
    properties["atlaso.ipv6_enabled"] = "sometimes"

    with pytest.raises(customizer.OvfManagementNetworkError, match="must be true or false"):
        customizer.validate_properties(properties)


def test_vmware_ovf_customizer_validates_uncorrectable_fields_before_network():
    """Verify invalid non-network OVF fields never enter network-only recovery."""
    customizer = load_customizer()
    properties = customizer.parse_ovf_environment(OVF_ENV)
    properties["atlaso.cidr"] = "192.168.1.254/32"
    properties["atlaso.gateway"] = "192.168.1.1"
    properties["atlaso.fqdn"] = "not-an-fqdn"

    with pytest.raises(customizer.OvfCustomizationError) as exc_info:
        customizer.validate_properties(properties)

    assert not isinstance(exc_info.value, customizer.OvfManagementNetworkError)
    assert "fully qualified" in str(exc_info.value)


def test_vmware_ovf_customizer_rejects_non_network_correction_fields(tmp_path):
    """Verify the correction handshake rejects fields outside its safe allowlist.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    customizer = load_customizer()
    customizer.NETWORK_CORRECTION_PATH = tmp_path / "network-correction.json"
    customizer.write_json_atomic(
        customizer.NETWORK_CORRECTION_PATH,
        {"version": 1, "ipv4_method": "dhcp", "root_password": "not-accepted"},
        mode=0o600,
    )

    with pytest.raises(customizer.OvfManagementNetworkError, match="unsupported fields"):
        customizer.read_network_correction()


def test_vmware_ovf_customizer_waits_for_nonsecret_console_correction(tmp_path, monkeypatch):
    """Verify invalid networking pauses before mutation and resumes from tty1 correction.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest helper used to replace first-boot state and actions.
    """
    customizer = load_customizer()
    customizer.NETWORK_REVIEW_PATH = tmp_path / "network-review.json"
    customizer.NETWORK_CORRECTION_PATH = tmp_path / "network-correction.json"
    customizer.MARKER_PATH = tmp_path / "customization.applied"
    customizer.INITIALIZATION_LOCK_PATH = tmp_path / "initializing"
    customizer.INITIALIZATION_LOCK_PATH.touch()
    properties = customizer.parse_ovf_environment(OVF_ENV)
    properties["atlaso.cidr"] = "192.168.1.254/32"
    properties["atlaso.gateway"] = "192.168.1.1"
    captured_review: list[str] = []
    applied: list[dict[str, object]] = []

    def supply_correction(_seconds):
        """Supply one safe console correction after observing the review state.

        Args:
            _seconds: Requested polling delay, unused by the test.
        """
        assert applied == []
        assert not customizer.MARKER_PATH.exists()
        captured_review.append(customizer.NETWORK_REVIEW_PATH.read_text(encoding="utf-8"))
        customizer.write_json_atomic(
            customizer.NETWORK_CORRECTION_PATH,
            {
                "version": 1,
                "ipv4_method": "static",
                "ipv4_cidr": "192.168.1.254/24",
                "ipv4_gateway": "192.168.1.1",
                "ipv6_mode": "disabled",
                "ipv6_cidr": "",
                "ipv6_gateway": "",
                "dns_servers": "192.168.10.2,192.168.10.3",
            },
            mode=0o600,
        )

    def apply_correction(config, *, dry_run=False):
        """Record the first mutation and create the marker as the real apply does.

        Args:
            config: Validated corrected OVF customization values.
            dry_run: Whether mutation should be suppressed.

        Returns:
            The safe customization summary written to the marker.
        """
        assert dry_run is False
        applied.append(config)
        summary = customizer.redacted_summary(config)
        customizer.write_json_atomic(customizer.MARKER_PATH, summary)
        return summary

    monkeypatch.setattr(customizer.time, "sleep", supply_correction)
    monkeypatch.setattr(customizer, "apply_customization", apply_correction)

    assert customizer.wait_for_network_review(properties, "Management gateway must be on-link.") == 0

    assert applied[0]["cidr"] == "192.168.1.254/24"
    assert applied[0]["gateway"] == "192.168.1.1"
    assert customizer.MARKER_PATH.exists()
    assert not customizer.NETWORK_REVIEW_PATH.exists()
    assert not customizer.NETWORK_CORRECTION_PATH.exists()
    assert not customizer.INITIALIZATION_LOCK_PATH.exists()
    assert "admin-secret" not in captured_review[0]
    assert "root-secret1" not in captured_review[0]


def test_vmware_ovf_customizer_keeps_waiter_after_corrected_apply_failure(tmp_path, monkeypatch):
    """Verify a post-validation failure never leaves tty1 without a correction consumer.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest helper used to replace first-boot state and actions.
    """
    customizer = load_customizer()
    customizer.NETWORK_REVIEW_PATH = tmp_path / "network-review.json"
    customizer.NETWORK_CORRECTION_PATH = tmp_path / "network-correction.json"
    customizer.PENDING_MARKER_PATH = tmp_path / "customization.pending"
    customizer.MARKER_PATH = tmp_path / "customization.applied"
    customizer.INITIALIZATION_LOCK_PATH = tmp_path / "initializing"
    customizer.INITIALIZATION_LOCK_PATH.touch()
    synchronized_paths = []
    monkeypatch.setattr(customizer, "fsync_parent_directory", synchronized_paths.append)
    properties = customizer.parse_ovf_environment(OVF_ENV)
    properties["atlaso.cidr"] = "192.168.1.254/32"
    properties["atlaso.gateway"] = "192.168.1.1"
    apply_attempts: list[dict[str, object]] = []
    retry_review: list[dict[str, object]] = []

    def supply_correction(_seconds):
        """Submit the same valid correction for the initial attempt and retry.

        Args:
            _seconds: Requested polling delay, unused by the test.
        """
        if apply_attempts:
            retry_review.append(
                json.loads(customizer.NETWORK_REVIEW_PATH.read_text(encoding="utf-8"))
            )
        customizer.write_json_atomic(
            customizer.NETWORK_CORRECTION_PATH,
            {
                "version": 1,
                "ipv4_method": "static",
                "ipv4_cidr": "192.168.1.254/24",
                "ipv4_gateway": "192.168.1.1",
                "ipv6_mode": "disabled",
                "ipv6_cidr": "",
                "ipv6_gateway": "",
                "dns_servers": "192.168.10.2",
            },
            mode=0o600,
        )

    def apply_correction(config, *, dry_run=False):
        """Fail once after validation, then complete the retained retry.

        Args:
            config: Validated corrected OVF customization values.
            dry_run: Whether mutation should be suppressed.

        Returns:
            The safe customization summary written on the second attempt.

        Raises:
            OvfCustomizationError: On the intentional first apply attempt.
        """
        assert dry_run is False
        apply_attempts.append(config)
        if len(apply_attempts) == 1:
            customizer.write_json_atomic(
                customizer.PENDING_MARKER_PATH,
                {"cidr": "stale-attempt"},
            )
            raise customizer.OvfCustomizationError("Photon sshd configuration validation failed")
        assert not customizer.PENDING_MARKER_PATH.exists()
        summary = customizer.redacted_summary(config)
        customizer.write_json_atomic(customizer.MARKER_PATH, summary)
        return summary

    monkeypatch.setattr(customizer.time, "sleep", supply_correction)
    monkeypatch.setattr(customizer, "apply_customization", apply_correction)
    monkeypatch.setattr(customizer, "log", lambda _message: None)

    assert customizer.wait_for_network_review(properties, "Management gateway must be on-link.") == 0
    assert len(apply_attempts) == 2
    assert retry_review[0]["state"] == "network_review"
    assert "customization log" in retry_review[0]["error"]
    assert "sshd" not in retry_review[0]["error"]
    assert customizer.MARKER_PATH.exists()
    assert not customizer.PENDING_MARKER_PATH.exists()
    assert synchronized_paths.count(customizer.PENDING_MARKER_PATH) == 2
    assert not customizer.NETWORK_REVIEW_PATH.exists()
    assert not customizer.NETWORK_CORRECTION_PATH.exists()
    assert not customizer.INITIALIZATION_LOCK_PATH.exists()


def test_vmware_ovf_customizer_names_pending_invalidation_failure(tmp_path, monkeypatch):
    """Verify retry invalidation failures expose only their stable layer name.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest helper used to replace first-boot state and actions.
    """
    customizer = load_customizer()
    customizer.NETWORK_REVIEW_PATH = tmp_path / "network-review.json"
    customizer.NETWORK_CORRECTION_PATH = tmp_path / "network-correction.json"
    customizer.PENDING_MARKER_PATH = tmp_path / "customization.pending"
    customizer.PENDING_MARKER_PATH.write_text("{}\n", encoding="utf-8")
    properties = customizer.parse_ovf_environment(OVF_ENV)
    customizer.write_json_atomic(
        customizer.NETWORK_CORRECTION_PATH,
        {
            "version": 1,
            "ipv4_method": "static",
            "ipv4_cidr": "192.168.10.10/24",
            "ipv4_gateway": "192.168.10.1",
            "ipv6_mode": "disabled",
            "ipv6_cidr": "",
            "ipv6_gateway": "",
            "dns_servers": "192.168.10.2",
        },
        mode=0o600,
    )

    class StopPolling(BaseException):
        """Stop the retained review loop after observing the failure state."""

    monkeypatch.setattr(
        customizer,
        "invalidate_pending_marker",
        lambda: (_ for _ in ()).throw(OSError("secret-bearing filesystem detail")),
    )
    monkeypatch.setattr(
        customizer,
        "apply_customization",
        lambda config: pytest.fail("mutation started before pending-state invalidation"),
    )
    monkeypatch.setattr(
        customizer.time,
        "sleep",
        lambda seconds: (_ for _ in ()).throw(StopPolling()),
    )
    messages = []
    monkeypatch.setattr(customizer, "log", messages.append)

    with pytest.raises(StopPolling):
        customizer.wait_for_network_review(properties, "Retry initialization.")

    rendered = " ".join(messages)
    assert "pending success marker invalidation layer" in rendered
    assert "secret-bearing filesystem detail" not in rendered
    assert customizer.PENDING_MARKER_PATH.exists()


def test_vmware_ovf_customizer_routes_initial_apply_failure_to_waiter(tmp_path, monkeypatch):
    """Verify valid original networking retains a consumer when its first apply fails.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest helper used to replace first-boot state and actions.
    """
    customizer = load_customizer()
    ovf_path = tmp_path / "ovf-env.xml"
    ovf_path.write_text(OVF_ENV, encoding="utf-8")
    customizer.NETWORK_REVIEW_PATH = tmp_path / "network-review.json"
    customizer.NETWORK_CORRECTION_PATH = tmp_path / "network-correction.json"
    customizer.MARKER_PATH = tmp_path / "customization.applied"
    customizer.INITIALIZATION_LOCK_PATH = tmp_path / "initializing"
    customizer.INITIALIZATION_LOCK_PATH.touch()
    apply_attempts: list[dict[str, object]] = []
    review_states: list[dict[str, object]] = []

    def supply_correction(_seconds):
        """Resubmit the already-valid management values to the retained waiter.

        Args:
            _seconds: Requested polling delay, unused by the test.
        """
        review_states.append(
            json.loads(customizer.NETWORK_REVIEW_PATH.read_text(encoding="utf-8"))
        )
        customizer.write_json_atomic(
            customizer.NETWORK_CORRECTION_PATH,
            {
                "version": 1,
                "ipv4_method": "static",
                "ipv4_cidr": "192.168.10.10/24",
                "ipv4_gateway": "192.168.10.1",
                "ipv6_mode": "disabled",
                "ipv6_cidr": "",
                "ipv6_gateway": "",
                "dns_servers": "192.168.10.2,192.168.10.3",
            },
            mode=0o600,
        )

    def apply_customization(config, *, dry_run=False):
        """Fail the original apply, then complete the waiter-owned retry.

        Args:
            config: Validated OVF customization values.
            dry_run: Whether mutation should be suppressed.

        Returns:
            The safe customization summary written on retry.

        Raises:
            OvfCustomizationError: On the intentional original apply attempt.
        """
        assert dry_run is False
        apply_attempts.append(config)
        if len(apply_attempts) == 1:
            raise customizer.OvfCustomizationError("Photon sshd configuration validation failed")
        summary = customizer.redacted_summary(config)
        customizer.write_json_atomic(customizer.MARKER_PATH, summary)
        return summary

    monkeypatch.setattr(customizer.time, "sleep", supply_correction)
    monkeypatch.setattr(customizer, "apply_customization", apply_customization)
    monkeypatch.setattr(customizer, "log", lambda _message: None)

    assert customizer.main(["--ovf-env-file", str(ovf_path)]) == 0
    assert len(apply_attempts) == 2
    assert review_states[0]["state"] == "network_review"
    assert "management network validated" in review_states[0]["error"]
    assert "sshd" not in review_states[0]["error"]
    assert customizer.MARKER_PATH.exists()
    assert not customizer.NETWORK_REVIEW_PATH.exists()
    assert not customizer.NETWORK_CORRECTION_PATH.exists()
    assert not customizer.INITIALIZATION_LOCK_PATH.exists()


def test_vmware_ovf_customizer_retries_scrub_failure_without_network_review(
    tmp_path,
    monkeypatch,
):
    """Verify post-apply finalization cannot masquerade as a DHCP review loop.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest helper used to replace first-boot finalization.
    """
    customizer = load_customizer()
    ovf_path = tmp_path / "ovf-env.xml"
    ovf_path.write_text(OVF_ENV, encoding="utf-8")
    customizer.PENDING_MARKER_PATH = tmp_path / "customization.pending"
    customizer.MARKER_PATH = tmp_path / "customization.applied"
    customizer.NETWORK_REVIEW_PATH = tmp_path / "network-review.json"
    customizer.NETWORK_CORRECTION_PATH = tmp_path / "network-correction.json"
    recovered = []

    def fail_scrub(config, *, dry_run=False):
        """Persist pending success, then simulate the observed scrub failure.

        Args:
            config: Validated OVF customization values.
            dry_run: Whether host mutation is disabled.

        Raises:
            OvfFinalizationError: Always, after pending state is durable.
        """
        assert dry_run is False
        customizer.write_json_atomic(
            customizer.PENDING_MARKER_PATH,
            customizer.redacted_summary(config),
        )
        raise customizer.OvfFinalizationError(
            "First-time initialization failed in the OVF credential scrub layer."
        )

    def recover_pending():
        """Record that finalization owns the retry instead of network review."""
        assert customizer.PENDING_MARKER_PATH.exists()
        assert not customizer.NETWORK_REVIEW_PATH.exists()
        recovered.append(True)
        return 0

    monkeypatch.setattr(customizer, "apply_customization", fail_scrub)
    monkeypatch.setattr(customizer, "recover_pending_customization", recover_pending)
    monkeypatch.setattr(
        customizer,
        "wait_for_network_review",
        lambda *_args: pytest.fail("credential scrub failure entered network review"),
    )
    monkeypatch.setattr(customizer, "log", lambda _message: None)

    assert customizer.main(["--ovf-env-file", str(ovf_path)]) == 0
    assert recovered == [True]


def test_vmware_ovf_customizer_waits_locked_for_delayed_ovf_properties(tmp_path, monkeypatch):
    """Verify an empty OVF environment never exposes image-build credentials.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest helper used to replace first-boot state and actions.
    """
    customizer = load_customizer()
    ovf_path = tmp_path / "ovf-env.xml"
    ovf_path.write_text("", encoding="utf-8")
    customizer.MARKER_PATH = tmp_path / "customization.applied"
    customizer.INITIALIZATION_LOCK_PATH = tmp_path / "initializing"
    customizer.NETWORK_REVIEW_PATH = tmp_path / "network-review.json"
    customizer.NETWORK_CORRECTION_PATH = tmp_path / "network-correction.json"
    customizer.INITIALIZATION_LOCK_PATH.touch()
    lock_observations: list[bool] = []
    apply_attempts: list[dict[str, object]] = []

    def supply_ovf_properties(_seconds):
        """Advance VMware properties through malformed and incomplete XML.

        Args:
            _seconds: Requested polling delay, unused by the test.
        """
        lock_observations.append(customizer.INITIALIZATION_LOCK_PATH.exists())
        assert not customizer.MARKER_PATH.exists()
        if len(lock_observations) == 1:
            content = "<Environment>"
        elif len(lock_observations) == 2:
            content = (
                '<Environment xmlns:oe="http://schemas.dmtf.org/ovf/environment/1">'
                '<Property oe:key="atlaso.fqdn" oe:value="appliance.atlaso.internal" />'
                "</Environment>"
            )
        else:
            content = OVF_ENV
        ovf_path.write_text(content, encoding="utf-8")

    def apply_customization(config, *, dry_run=False):
        """Complete customization after delayed properties become available.

        Args:
            config: Validated OVF customization values.
            dry_run: Whether mutation should be suppressed.

        Returns:
            The safe customization summary written to the marker.
        """
        assert dry_run is False
        apply_attempts.append(config)
        summary = customizer.redacted_summary(config)
        customizer.write_json_atomic(customizer.MARKER_PATH, summary)
        return summary

    monkeypatch.setattr(customizer.time, "sleep", supply_ovf_properties)
    monkeypatch.setattr(customizer, "apply_customization", apply_customization)
    monkeypatch.setattr(customizer, "log", lambda _message: None)

    assert customizer.main(["--ovf-env-file", str(ovf_path)]) == 0
    assert lock_observations == [True, True, True]
    assert len(apply_attempts) == 1
    assert customizer.MARKER_PATH.exists()
    assert not customizer.INITIALIZATION_LOCK_PATH.exists()
    assert not customizer.NETWORK_REVIEW_PATH.exists()
    assert not customizer.NETWORK_CORRECTION_PATH.exists()


def test_vmware_ovf_customizer_completes_answered_empty_boot_with_image_defaults(
    tmp_path,
    monkeypatch,
):
    """Verify a stable answered-empty Tools channel completes without OVF review.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest helper used to replace VMware reads and polling.
    """
    customizer = load_customizer()
    customizer.MARKER_PATH = tmp_path / "customization.applied"
    customizer.PENDING_MARKER_PATH = tmp_path / "customization.pending"
    customizer.NO_OVF_MARKER_PATH = tmp_path / "no-ovf.applied"
    customizer.INITIALIZATION_LOCK_PATH = tmp_path / "initializing"
    customizer.NETWORK_REVIEW_PATH = tmp_path / "network-review.json"
    customizer.NETWORK_CORRECTION_PATH = tmp_path / "network-correction.json"
    customizer.INITIALIZATION_LOCK_PATH.touch()
    customizer.write_json_atomic(
        customizer.NETWORK_REVIEW_PATH,
        {"version": 1, "state": "network_review", "error": "Review management networking."},
    )
    customizer.write_json_atomic(
        customizer.NETWORK_CORRECTION_PATH,
        {
            "version": 1,
            "ipv4_method": "dhcp",
            "ipv4_cidr": "",
            "ipv4_gateway": "",
            "ipv6_mode": "disabled",
            "ipv6_cidr": "",
            "ipv6_gateway": "",
            "dns_servers": "",
        },
        mode=0o600,
    )
    reads = []
    sleeps = []
    messages = []

    def read_empty_environment():
        """Return one authoritative empty VMware Tools response."""
        reads.append(True)
        return True, ""

    monkeypatch.setattr(customizer, "try_read_ovf_environment", read_empty_environment)
    monkeypatch.setattr(customizer.time, "sleep", sleeps.append)
    monkeypatch.setattr(customizer, "log", messages.append)
    monkeypatch.setattr(
        customizer,
        "apply_customization",
        lambda *_args, **_kwargs: pytest.fail("OVF customization ran for a no-envelope boot"),
    )

    assert customizer.main([]) == 0

    assert len(reads) == customizer.PENDING_EMPTY_CONFIRMATION_READS
    assert len(sleeps) == customizer.PENDING_EMPTY_CONFIRMATION_READS - 1
    assert json.loads(customizer.NO_OVF_MARKER_PATH.read_text(encoding="utf-8"))["source"] == "image_defaults"
    assert not customizer.MARKER_PATH.exists()
    assert not customizer.PENDING_MARKER_PATH.exists()
    assert not customizer.INITIALIZATION_LOCK_PATH.exists()
    assert not customizer.NETWORK_REVIEW_PATH.exists()
    assert not customizer.NETWORK_CORRECTION_PATH.exists()
    assert messages[-1] == "No OVF deployment properties supplied; using image defaults."
    assert "OVF management values" not in " ".join(messages)


def test_vmware_ovf_customizer_normalizes_tools_empty_string_readback(monkeypatch):
    """Verify VMware's quoted empty sentinel remains an answered-empty read.

    Args:
        monkeypatch: Pytest helper used to replace the VMware RPC process.
    """
    customizer = load_customizer()
    monkeypatch.setattr(customizer.shutil, "which", lambda command: f"/usr/bin/{command}")
    monkeypatch.setattr(
        customizer.subprocess,
        "run",
        lambda *_args, **_kwargs: type(
            "Result",
            (),
            {"returncode": 0, "stdout": '""\n'},
        )(),
    )

    assert customizer.try_read_ovf_environment() == (True, "")


def test_vmware_ovf_customizer_non_ovf_reboot_is_idempotent(tmp_path, monkeypatch):
    """Verify completed non-OVF boots do not repeat the confirmation wait.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest helper used to replace VMware reads and polling.
    """
    customizer = load_customizer()
    customizer.NO_OVF_MARKER_PATH = tmp_path / "no-ovf.applied"
    customizer.INITIALIZATION_LOCK_PATH = tmp_path / "initializing"
    customizer.NETWORK_REVIEW_PATH = tmp_path / "network-review.json"
    customizer.NETWORK_CORRECTION_PATH = tmp_path / "network-correction.json"
    customizer.write_json_atomic(
        customizer.NO_OVF_MARKER_PATH,
        {"completed_at": "2026-08-12T00:00:00Z", "source": "image_defaults"},
    )
    customizer.INITIALIZATION_LOCK_PATH.touch()
    reads = []

    def read_empty_environment():
        """Return the current deployment's authoritative empty environment."""
        reads.append(True)
        return True, ""

    monkeypatch.setattr(customizer, "try_read_ovf_environment", read_empty_environment)
    monkeypatch.setattr(
        customizer.time,
        "sleep",
        lambda _seconds: pytest.fail("completed non-OVF boot re-entered the wait loop"),
    )
    messages = []
    monkeypatch.setattr(customizer, "log", messages.append)

    assert customizer.main([]) == 0

    assert reads == [True]
    assert customizer.NO_OVF_MARKER_PATH.exists()
    assert not customizer.INITIALIZATION_LOCK_PATH.exists()
    assert messages[-1] == "VMware non-OVF initialization already completed; using image defaults."


def test_vmware_ovf_customizer_replaces_non_ovf_marker_when_envelope_arrives(
    tmp_path,
    monkeypatch,
):
    """Verify a later real envelope is applied instead of ignored as image defaults.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest helper used to replace customization mutations.
    """
    customizer = load_customizer()
    customizer.MARKER_PATH = tmp_path / "customization.applied"
    customizer.PENDING_MARKER_PATH = tmp_path / "customization.pending"
    customizer.NO_OVF_MARKER_PATH = tmp_path / "no-ovf.applied"
    customizer.INITIALIZATION_LOCK_PATH = tmp_path / "initializing"
    customizer.NETWORK_REVIEW_PATH = tmp_path / "network-review.json"
    customizer.NETWORK_CORRECTION_PATH = tmp_path / "network-correction.json"
    customizer.write_json_atomic(
        customizer.NO_OVF_MARKER_PATH,
        {"completed_at": "2026-08-12T00:00:00Z", "source": "image_defaults"},
    )
    applied = []
    monkeypatch.setattr(customizer, "try_read_ovf_environment", lambda: (True, OVF_ENV))

    def apply_replacement(config, *, dry_run=False):
        """Record and mark the replacement OVF deployment.

        Args:
            config: Validated replacement customization values.
            dry_run: Whether host mutation is disabled.

        Returns:
            The redacted replacement-deployment summary.
        """
        assert dry_run is False
        assert not customizer.NO_OVF_MARKER_PATH.exists()
        applied.append(config)
        summary = customizer.redacted_summary(config)
        customizer.write_json_atomic(customizer.MARKER_PATH, summary)
        return summary

    monkeypatch.setattr(customizer, "apply_customization", apply_replacement)
    monkeypatch.setattr(customizer, "log", lambda _message: None)

    assert customizer.main([]) == 0

    assert len(applied) == 1
    assert applied[0]["fqdn"] == "appliance.atlaso.internal"
    assert customizer.MARKER_PATH.exists()
    assert not customizer.NO_OVF_MARKER_PATH.exists()


def test_vmware_ovf_customizer_waits_for_answer_before_replacing_non_ovf_marker(
    tmp_path,
    monkeypatch,
):
    """Verify a transient unanswered read cannot skip a later OVF envelope.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest helper used to replace VMware reads and customization mutations.
    """
    customizer = load_customizer()
    customizer.MARKER_PATH = tmp_path / "customization.applied"
    customizer.PENDING_MARKER_PATH = tmp_path / "customization.pending"
    customizer.NO_OVF_MARKER_PATH = tmp_path / "no-ovf.applied"
    customizer.INITIALIZATION_LOCK_PATH = tmp_path / "initializing"
    customizer.NETWORK_REVIEW_PATH = tmp_path / "network-review.json"
    customizer.NETWORK_CORRECTION_PATH = tmp_path / "network-correction.json"
    customizer.write_json_atomic(
        customizer.NO_OVF_MARKER_PATH,
        {"completed_at": "2026-08-12T00:00:00Z", "source": "image_defaults"},
    )
    reads = iter([(False, ""), (True, OVF_ENV)])
    read_count = []
    sleeps = []
    applied = []

    def read_environment():
        """Return one unanswered read followed by the persistent OVF envelope."""
        read_count.append(True)
        return next(reads, (True, OVF_ENV))

    def apply_replacement(config, *, dry_run=False):
        """Record and mark the replacement OVF deployment.

        Args:
            config: Validated replacement customization values.
            dry_run: Whether host mutation is disabled.

        Returns:
            The redacted replacement-deployment summary.
        """
        assert dry_run is False
        applied.append(config)
        summary = customizer.redacted_summary(config)
        customizer.write_json_atomic(customizer.MARKER_PATH, summary)
        return summary

    monkeypatch.setattr(customizer, "try_read_ovf_environment", read_environment)
    monkeypatch.setattr(customizer.time, "sleep", sleeps.append)
    monkeypatch.setattr(customizer, "apply_customization", apply_replacement)
    monkeypatch.setattr(customizer, "log", lambda _message: None)

    assert customizer.main([]) == 0

    assert len(read_count) == 3
    assert sleeps == [customizer.OVF_ENVIRONMENT_POLL_SECONDS]
    assert len(applied) == 1
    assert applied[0]["fqdn"] == "appliance.atlaso.internal"
    assert customizer.MARKER_PATH.exists()
    assert not customizer.NO_OVF_MARKER_PATH.exists()


def test_vmware_ovf_customizer_keeps_unanswered_tools_channel_fail_closed(
    tmp_path,
    monkeypatch,
):
    """Verify an unanswered Tools channel cannot select image defaults.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest helper used to stop the intentional wait loop.
    """
    customizer = load_customizer()
    customizer.NO_OVF_MARKER_PATH = tmp_path / "no-ovf.applied"
    customizer.INITIALIZATION_LOCK_PATH = tmp_path / "initializing"
    customizer.INITIALIZATION_LOCK_PATH.touch()
    messages = []

    class StopPolling(BaseException):
        """Stop the intentional fail-closed polling loop."""

    monkeypatch.setattr(customizer, "try_read_ovf_environment", lambda: (False, ""))
    monkeypatch.setattr(
        customizer.time,
        "sleep",
        lambda _seconds: (_ for _ in ()).throw(StopPolling()),
    )
    monkeypatch.setattr(customizer, "log", messages.append)

    with pytest.raises(StopPolling):
        customizer.main([])

    assert customizer.INITIALIZATION_LOCK_PATH.exists()
    assert not customizer.NO_OVF_MARKER_PATH.exists()
    assert messages == [
        "Atlaso VMware OVF deployment properties are unavailable; waiting with tty1 locked."
    ]


def test_vmware_ovf_customizer_keeps_present_empty_envelope_fail_closed(
    tmp_path,
    monkeypatch,
):
    """Verify a present but incomplete envelope is not classified as no OVF.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest helper used to stop the intentional wait loop.
    """
    customizer = load_customizer()
    customizer.NO_OVF_MARKER_PATH = tmp_path / "no-ovf.applied"
    customizer.INITIALIZATION_LOCK_PATH = tmp_path / "initializing"
    customizer.INITIALIZATION_LOCK_PATH.touch()
    empty_envelope = (
        '<Environment xmlns="http://schemas.dmtf.org/ovf/environment/1">'
        "<PropertySection />"
        "</Environment>"
    )
    messages = []

    class StopPolling(BaseException):
        """Stop the intentional fail-closed polling loop."""

    monkeypatch.setattr(customizer, "try_read_ovf_environment", lambda: (True, empty_envelope))
    monkeypatch.setattr(
        customizer.time,
        "sleep",
        lambda _seconds: (_ for _ in ()).throw(StopPolling()),
    )
    monkeypatch.setattr(customizer, "log", messages.append)

    with pytest.raises(StopPolling):
        customizer.main([])

    assert customizer.INITIALIZATION_LOCK_PATH.exists()
    assert not customizer.NO_OVF_MARKER_PATH.exists()
    assert messages == [
        "Atlaso VMware OVF deployment properties are incomplete or invalid; waiting with tty1 locked."
    ]


def test_vmware_ovf_customizer_marker_recovers_interrupted_review_cleanup(tmp_path, monkeypatch):
    """Verify an applied marker clears stale review and tty1 lock on restart.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest helper used to suppress the customization log.
    """
    customizer = load_customizer()
    customizer.MARKER_PATH = tmp_path / "customization.applied"
    customizer.PENDING_MARKER_PATH = tmp_path / "customization.pending"
    customizer.INITIALIZATION_LOCK_PATH = tmp_path / "initializing"
    customizer.NETWORK_REVIEW_PATH = tmp_path / "network-review.json"
    customizer.NETWORK_CORRECTION_PATH = tmp_path / "network-correction.json"
    for path in (
        customizer.MARKER_PATH,
        customizer.INITIALIZATION_LOCK_PATH,
        customizer.NETWORK_REVIEW_PATH,
        customizer.NETWORK_CORRECTION_PATH,
    ):
        path.write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(customizer, "log", lambda _message: None)
    empty_reads = []

    def read_empty_environment():
        """Return one conclusive empty value and record the cleanup check."""
        empty_reads.append(True)
        return True, ""

    monkeypatch.setattr(customizer, "try_read_ovf_environment", read_empty_environment)
    monkeypatch.setattr(customizer.time, "sleep", lambda seconds: None)

    assert customizer.main([]) == 0
    assert customizer.MARKER_PATH.exists()
    assert not customizer.INITIALIZATION_LOCK_PATH.exists()
    assert not customizer.NETWORK_REVIEW_PATH.exists()
    assert not customizer.NETWORK_CORRECTION_PATH.exists()
    assert len(empty_reads) == customizer.PENDING_EMPTY_CONFIRMATION_READS


def test_vmware_ovf_customizer_marker_scrubs_properties_injected_into_reused_source(tmp_path, monkeypatch):
    """Verify an already-customized raw source cannot retain newly injected credentials.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    customizer = load_customizer()
    customizer.MARKER_PATH = tmp_path / "customization.applied"
    customizer.PENDING_MARKER_PATH = tmp_path / "customization.pending"
    customizer.INITIALIZATION_LOCK_PATH = tmp_path / "initializing"
    customizer.NETWORK_REVIEW_PATH = tmp_path / "network-review.json"
    customizer.NETWORK_CORRECTION_PATH = tmp_path / "network-correction.json"
    customizer.MARKER_PATH.write_text("{}\n", encoding="utf-8")
    customizer.INITIALIZATION_LOCK_PATH.write_text("\n", encoding="utf-8")
    reads = iter([(False, ""), (True, OVF_ENV)])
    monkeypatch.setattr(customizer, "try_read_ovf_environment", lambda: next(reads))
    scrubbed = []
    monkeypatch.setattr(customizer, "clear_ovf_environment", lambda: scrubbed.append(True))
    monkeypatch.setattr(customizer.time, "sleep", lambda seconds: None)
    messages = []
    monkeypatch.setattr(customizer, "log", messages.append)

    assert customizer.main([]) == 0

    assert scrubbed == [True]
    assert customizer.MARKER_PATH.exists()
    assert not customizer.INITIALIZATION_LOCK_PATH.exists()
    assert "admin-secret" not in " ".join(messages)
    assert "root-secret1" not in " ".join(messages)
    assert "inconclusive deployment-property read" in " ".join(messages)


def test_vmware_ovf_customizer_durably_persists_atomic_marker_before_scrub(tmp_path, monkeypatch):
    """Verify atomic marker writes synchronize file content and the rename directory.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    customizer = load_customizer()
    destination = tmp_path / "customization.pending"
    fsync_calls = []
    synchronized_parents = []
    monkeypatch.setattr(customizer.os, "fsync", fsync_calls.append)
    monkeypatch.setattr(
        customizer,
        "fsync_parent_directory",
        lambda path: synchronized_parents.append(path.parent),
    )

    customizer.write_json_atomic(destination, {"fqdn": "appliance.atlaso.internal"})

    assert destination.exists()
    assert len(fsync_calls) == 1
    assert synchronized_parents == [destination.parent]


def test_vmware_ovf_customizer_supports_disabled_auto_and_static_ipv6(tmp_path):
    """Verify that vmware ovf customizer supports disabled auto and static ipv6.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    customizer = load_customizer()
    customizer.NETWORKD_PATH = tmp_path / "management.network"
    properties = customizer.parse_ovf_environment(OVF_ENV)

    disabled = customizer.validate_properties(properties)
    customizer.write_networkd_config(disabled)
    assert "IPv6AcceptRA=no" in customizer.NETWORKD_PATH.read_text(encoding="utf-8")
    assert "LinkLocalAddressing=no" in customizer.NETWORKD_PATH.read_text(encoding="utf-8")

    properties["atlaso.ipv6_enabled"] = "true"
    automatic = customizer.validate_properties(properties)
    customizer.write_networkd_config(automatic)
    assert automatic["ipv6_mode"] == "auto"
    assert "IPv6AcceptRA=yes" in customizer.NETWORKD_PATH.read_text(encoding="utf-8")

    properties["atlaso.ipv6_cidr"] = "fd00:10::10/64"
    properties["atlaso.ipv6_gateway"] = "fe80::1"
    static = customizer.validate_properties(properties)
    customizer.write_networkd_config(static)
    rendered = customizer.NETWORKD_PATH.read_text(encoding="utf-8")
    assert static["ipv6_mode"] == "static"
    assert "Address=fd00:10::10/64" in rendered
    assert "Gateway=fe80::1" in rendered
    assert "IPv6AcceptRA=no" in rendered

    properties["atlaso.ipv6_gateway"] = ""
    static_without_gateway = customizer.validate_properties(properties)
    customizer.write_networkd_config(static_without_gateway)
    assert "Address=fd00:10::10/64" in customizer.NETWORKD_PATH.read_text(encoding="utf-8")
    assert "Gateway=fe80::1" not in customizer.NETWORKD_PATH.read_text(encoding="utf-8")


def test_vmware_ovf_customizer_rejects_contradictory_or_incomplete_ipv6():
    """Verify that vmware ovf customizer rejects contradictory or incomplete ipv6.

    Raises:
        AssertionError: If an expected invariant is not satisfied.
    """
    customizer = load_customizer()
    properties = customizer.parse_ovf_environment(OVF_ENV)
    properties["atlaso.ipv6_cidr"] = "fd00:10::10/64"
    try:
        customizer.validate_properties(properties)
    except customizer.OvfCustomizationError as exc:
        assert "Disabled or automatic IPv6 cannot include" in str(exc)
    else:
        raise AssertionError("disabled IPv6 with a CIDR should fail")

    properties["atlaso.ipv6_enabled"] = "true"
    static_without_gateway = customizer.validate_properties(properties)
    assert static_without_gateway["ipv6_gateway"] == ""

    properties["atlaso.ipv6_gateway"] = "fd00:20::1"
    with pytest.raises(customizer.OvfCustomizationError, match="link-local or on-link"):
        customizer.validate_properties(properties)

    properties["atlaso.ipv6_gateway"] = "fd00:10::10"
    with pytest.raises(customizer.OvfCustomizationError, match="cannot equal"):
        customizer.validate_properties(properties)


def test_vmware_ovf_customizer_renders_family_specific_management_firewall(tmp_path):
    """Verify that vmware ovf customizer renders family specific management firewall.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    customizer = load_customizer()
    customizer.FIREWALL_CONFIG_PATH = tmp_path / "atlaso.nft"
    properties = customizer.parse_ovf_environment(OVF_ENV)
    properties["atlaso.ipv6_enabled"] = "true"
    properties["atlaso.ipv6_cidr"] = "fd00:10::10/64"
    properties["atlaso.ipv6_gateway"] = "fe80::1"

    customizer.write_initial_firewall_config(customizer.validate_properties(properties))

    rendered = customizer.FIREWALL_CONFIG_PATH.read_text(encoding="utf-8")
    assert "ip saddr 192.168.10.0/24" in rendered
    assert "ip6 saddr fd00:10::/64" in rendered


def test_vmware_ovf_customizer_configures_and_validates_root_ssh(tmp_path, monkeypatch):
    """Verify that vmware ovf customizer configures and validates root ssh.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    customizer = load_customizer()
    customizer.SSHD_ROOT_LOGIN_CONFIG_PATH = tmp_path / "sshd_config.d" / "atlaso-root-login.conf"
    commands = []

    def fake_run(command, **kwargs):
        """Return fake run.

        Args:
            command: Command and arguments to execute.
            **kwargs: Additional keyword arguments accepted by the callable.
        """
        commands.append(command)
        return type("Result", (), {"returncode": 0})()

    monkeypatch.setattr(customizer.shutil, "which", lambda command: "/usr/sbin/sshd" if command == "sshd" else None)
    monkeypatch.setattr(customizer.subprocess, "run", fake_run)

    customizer.configure_root_ssh(True)

    rendered = customizer.SSHD_ROOT_LOGIN_CONFIG_PATH.read_text(encoding="utf-8")
    assert "PermitRootLogin yes" in rendered
    assert "PasswordAuthentication yes" in rendered
    assert commands == [["/usr/sbin/sshd", "-t"]]


def test_vmware_ovf_customizer_scrubs_consumed_guestinfo_credentials(monkeypatch):
    """Verify successful first boot clears the secret-bearing VMware guest property.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    customizer = load_customizer()
    commands = []

    def fake_run(command, **kwargs):
        """Record a sanitized VMware RPC command.

        Args:
            command: Command and arguments to execute.
            **kwargs: Additional keyword arguments accepted by subprocess.run.

        Returns:
            A successful bounded command result.
        """
        commands.append((command, kwargs))
        return type("Result", (), {"returncode": 0})()

    monkeypatch.setattr(customizer.shutil, "which", lambda command: f"/usr/bin/{command}")
    monkeypatch.setattr(customizer.subprocess, "run", fake_run)

    customizer.clear_ovf_environment()

    assert commands == [
        (
            ["/usr/bin/vmware-rpctool", 'info-set guestinfo.ovfEnv ""'],
            {"check": False, "text": True, "capture_output": True},
        )
    ]
    assert "admin-secret" not in str(commands)
    assert "root-secret1" not in str(commands)


def test_normal_test_vm_first_boot_publishes_host_key_without_client_key(
    tmp_path, monkeypatch
):
    """Publish only the normal test VM's canonical key through guest-info.

    Args:
        tmp_path: Isolated filesystem root.
        monkeypatch: Pytest fixture used to replace VMware Tools.
    """
    customizer = load_customizer()
    customizer.SSH_HOST_ED25519_PUBLIC_KEY_PATH = tmp_path / "ssh_host_ed25519_key.pub"
    customizer.SSH_HOST_ED25519_PUBLIC_KEY_PATH.write_text(
        f"{VALID_ED25519_PUBLIC_KEY}\n",
        encoding="utf-8",
    )
    commands = []

    def fake_run(command, **kwargs):
        """Record one VMware guest-info publication.

        Args:
            command: Command and arguments to execute.
            **kwargs: Additional subprocess options.

        Returns:
            A successful bounded command result.
        """
        commands.append((command, kwargs))
        return type("Result", (), {"returncode": 0})()

    monkeypatch.setattr(customizer.shutil, "which", lambda command: f"/usr/bin/{command}")
    monkeypatch.setattr(customizer.subprocess, "run", fake_run)

    customizer.publish_test_vm_ssh_host_key()

    expected_host_key = " ".join(VALID_ED25519_PUBLIC_KEY.split()[:2])
    assert commands == [
        (
            [
                "/usr/bin/vmware-rpctool",
                f'info-set {customizer.TEST_VM_SSH_HOST_KEY_GUESTINFO} "{expected_host_key}"',
            ],
            {"check": False, "text": True, "capture_output": True},
        )
    ]
    assert "atlaso-test" not in str(commands)


def test_normal_test_vm_first_boot_publishes_actual_hostname(monkeypatch):
    """Publish the hostname observed inside the guest through guest-info.

    Args:
        monkeypatch: Pytest fixture used to replace VMware Tools and hostname evidence.
    """
    customizer = load_customizer()
    commands = []

    def fake_run(command, **kwargs):
        """Record one VMware guest-info publication.

        Args:
            command: Command and arguments to execute.
            **kwargs: Additional subprocess options.

        Returns:
            A successful bounded command result.
        """
        commands.append((command, kwargs))
        return type("Result", (), {"returncode": 0})()

    monkeypatch.setattr(customizer.socket, "gethostname", lambda: "issue-535.atlaso.internal")
    monkeypatch.setattr(customizer.shutil, "which", lambda command: f"/usr/bin/{command}")
    monkeypatch.setattr(customizer.subprocess, "run", fake_run)

    customizer.publish_test_vm_hostname()

    assert commands == [
        (
            [
                "/usr/bin/vmware-rpctool",
                f'info-set {customizer.TEST_VM_HOSTNAME_GUESTINFO} "issue-535.atlaso.internal"',
            ],
            {"check": False, "text": True, "capture_output": True},
        )
    ]


@pytest.mark.parametrize("host_key", ["ssh-rsa invalid\n", "\n"])
def test_normal_test_vm_first_boot_rejects_invalid_host_key(tmp_path, host_key):
    """Fail test-only publication when the installed host key is invalid or empty.

    Args:
        tmp_path: Isolated filesystem root.
        host_key: Invalid or empty installed host-key content.
    """
    customizer = load_customizer()
    customizer.SSH_HOST_ED25519_PUBLIC_KEY_PATH = tmp_path / "ssh_host_ed25519_key.pub"
    customizer.SSH_HOST_ED25519_PUBLIC_KEY_PATH.write_text(
        host_key,
        encoding="utf-8",
    )

    with pytest.raises(customizer.OvfCustomizationError, match="test_vm_ssh_host"):
        customizer.publish_test_vm_ssh_host_key()


def test_vmware_ovf_customizer_recovers_pending_marker_after_scrub_interruption(tmp_path, monkeypatch):
    """Verify a crash between credential scrub and marker promotion remains recoverable.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    customizer = load_customizer()
    customizer.PENDING_MARKER_PATH = tmp_path / "customization.pending"
    customizer.MARKER_PATH = tmp_path / "customization.applied"
    summary = {"fqdn": "appliance.atlaso.internal", "admin_password_set": True}
    customizer.write_json_atomic(customizer.PENDING_MARKER_PATH, summary)
    attempts = []
    completed = []

    def clear_ovf_environment():
        """Fail once, then prove the pending scrub is safely retryable."""
        attempts.append(True)
        if len(attempts) == 1:
            raise customizer.OvfCustomizationError("unsafe implementation detail")

    monkeypatch.setattr(customizer, "clear_ovf_environment", clear_ovf_environment)
    monkeypatch.setattr(customizer, "complete_first_boot_initialization", lambda: completed.append(True))
    monkeypatch.setattr(customizer.time, "sleep", lambda seconds: None)
    messages = []
    monkeypatch.setattr(customizer, "log", messages.append)

    assert customizer.recover_pending_customization() == 0

    assert attempts == [True, True]
    assert completed == [True]
    assert customizer.MARKER_PATH.exists()
    assert not customizer.PENDING_MARKER_PATH.exists()
    assert json.loads(customizer.MARKER_PATH.read_text(encoding="utf-8")) == summary
    assert "unsafe implementation detail" not in " ".join(messages)
    assert "credential scrub and applied-marker finalization" in " ".join(messages)


@pytest.mark.parametrize(
    ("source_deployment_id", "replacement_deployment_id"),
    [
        (
            "11111111-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222",
        ),
        ("", ""),
    ],
)
def test_vmware_ovf_customizer_reapplies_new_deployment_over_pending_source(
    tmp_path,
    monkeypatch,
    source_deployment_id,
    replacement_deployment_id,
):
    """Verify a new raw-clone or ID-less OVA deployment cannot promote source state.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        source_deployment_id: Non-secret identifier recorded by the interrupted source.
        replacement_deployment_id: Identifier supplied by the replacement, or blank for OVA.
    """
    customizer = load_customizer()
    customizer.PENDING_MARKER_PATH = tmp_path / "customization.pending"
    customizer.MARKER_PATH = tmp_path / "customization.applied"
    customizer.INITIALIZATION_LOCK_PATH = tmp_path / "initializing"
    customizer.NETWORK_REVIEW_PATH = tmp_path / "network-review.json"
    customizer.NETWORK_CORRECTION_PATH = tmp_path / "network-correction.json"
    customizer.write_json_atomic(
        customizer.PENDING_MARKER_PATH,
        {"fqdn": "source.atlaso.internal", "deployment_id": source_deployment_id},
    )
    replacement_ovf = OVF_ENV
    if replacement_deployment_id:
        replacement_ovf = replacement_ovf.replace(
            "  <PropertySection>\n",
            "  <PropertySection>\n"
            f'    <Property oe:key="atlaso.deployment_id" oe:value="{replacement_deployment_id}" />\n',
    )
    ovf_reads = iter([(True, ""), (True, ""), (True, replacement_ovf)])
    monkeypatch.setattr(
        customizer,
        "try_read_ovf_environment",
        lambda: next(ovf_reads, (True, replacement_ovf)),
    )
    monkeypatch.setattr(customizer.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(
        customizer,
        "recover_pending_customization",
        lambda: pytest.fail("the source deployment was incorrectly recovered"),
    )
    applied = []

    def apply_customization(config, *, dry_run=False):
        """Record the replacement deployment after stale state is invalidated.

        Args:
            config: Validated replacement deployment settings.
            dry_run: Whether host mutation is disabled.

        Returns:
            The redacted replacement-deployment summary.
        """
        assert dry_run is False
        assert not customizer.PENDING_MARKER_PATH.exists()
        applied.append(config)
        summary = customizer.redacted_summary(config)
        customizer.write_json_atomic(customizer.MARKER_PATH, summary)
        return summary

    monkeypatch.setattr(customizer, "apply_customization", apply_customization)
    monkeypatch.setattr(customizer, "log", lambda message: None)

    assert customizer.main([]) == 0

    assert len(applied) == 1
    assert applied[0]["deployment_id"] == replacement_deployment_id
    assert customizer.MARKER_PATH.exists()
    assert not customizer.PENDING_MARKER_PATH.exists()


def test_vmware_ovf_customizer_requires_stable_empty_ovf_before_pending_recovery(tmp_path, monkeypatch):
    """Verify one transient empty guestinfo read cannot promote pending state.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace VMware reads and polling.
    """
    customizer = load_customizer()
    customizer.PENDING_MARKER_PATH = tmp_path / "customization.pending"
    customizer.write_json_atomic(customizer.PENDING_MARKER_PATH, {"deployment_id": ""})
    reads = []
    sleeps = []

    def read_empty_environment():
        """Interrupt one empty sequence, then return a complete stable sequence."""
        reads.append(True)
        if len(reads) == 11:
            return False, ""
        return True, ""

    monkeypatch.setattr(customizer, "try_read_ovf_environment", read_empty_environment)
    monkeypatch.setattr(customizer.time, "sleep", sleeps.append)
    monkeypatch.setattr(customizer, "log", lambda message: None)

    assert customizer.pending_marker_matches_current_deployment("") is True

    assert len(reads) == customizer.PENDING_EMPTY_CONFIRMATION_READS + 11
    assert len(sleeps) == customizer.PENDING_EMPTY_CONFIRMATION_READS + 10


def test_vmware_ovf_customizer_reports_safe_failing_initialization_layer(monkeypatch):
    """Verify mutation failures identify a safe layer without exception-derived text.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    customizer = load_customizer()
    config = customizer.validate_properties(customizer.parse_ovf_environment(OVF_ENV))
    monkeypatch.setattr(
        customizer,
        "write_networkd_config",
        lambda candidate: (_ for _ in ()).throw(OSError("secret-bearing implementation detail")),
    )

    with pytest.raises(customizer.OvfCustomizationError) as failure:
        customizer.apply_customization(config)

    assert str(failure.value) == "First-time initialization failed in the management network layer."
    assert "secret-bearing implementation detail" not in str(failure.value)


def test_vmware_ovf_customizer_requires_static_network_properties_only_for_static_mode():
    """Verify that vmware ovf customizer requires static network properties only for static mode.

    Raises:
        AssertionError: If an expected invariant is not satisfied.
    """
    customizer = load_customizer()
    properties = customizer.parse_ovf_environment(OVF_ENV)

    properties.pop("atlaso.cidr")
    try:
        customizer.validate_properties(properties)
    except customizer.OvfCustomizationError as exc:
        assert "address and prefix" in str(exc)
    else:
        raise AssertionError("missing static CIDR should fail validation")


def test_vmware_ovf_customizer_renders_initial_firewall_for_ovf_subnet(tmp_path):
    """Verify that vmware ovf customizer renders initial firewall for ovf subnet.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    customizer = load_customizer()
    firewall_path = tmp_path / "atlaso.nft"
    customizer.FIREWALL_CONFIG_PATH = firewall_path
    properties = customizer.parse_ovf_environment(OVF_ENV)
    config = customizer.validate_properties(properties)

    customizer.write_initial_firewall_config(config)

    rendered = firewall_path.read_text(encoding="utf-8")
    assert "ip saddr 192.168.10.0/24 tcp dport { 22, 80, 443 } accept" in rendered
    assert "192.168.49.0/24" not in rendered
    assert "flush ruleset" in rendered
    assert "policy drop" in rendered


def test_vmware_ovf_customizer_renders_dhcp_network_and_interface_scoped_firewall(tmp_path):
    """Verify that vmware ovf customizer renders dhcp network and interface scoped firewall.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    customizer = load_customizer()
    customizer.NETWORKD_PATH = tmp_path / "00-atlaso-mgmt.network"
    customizer.FIREWALL_CONFIG_PATH = tmp_path / "atlaso.nft"
    properties = customizer.parse_ovf_environment(OVF_ENV)
    properties["atlaso.management_mode"] = "dhcp"
    properties.pop("atlaso.cidr")
    properties.pop("atlaso.gateway")
    config = customizer.validate_properties(properties)

    customizer.write_networkd_config(config)
    customizer.write_initial_firewall_config(config)

    networkd = customizer.NETWORKD_PATH.read_text(encoding="utf-8")
    firewall = customizer.FIREWALL_CONFIG_PATH.read_text(encoding="utf-8")
    assert "DHCP=ipv4" in networkd
    assert "Address=" not in networkd
    assert 'iifname "eth0" meta nfproto ipv4 tcp dport { 22, 80, 443 } accept' in firewall


def test_vmware_ovf_customizer_rotates_clone_specific_env_secrets(tmp_path, monkeypatch):
    """Verify that vmware ovf customizer rotates clone specific env secrets.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace the host sync primitive.
    """
    customizer = load_customizer()
    customizer.ENV_PATH = tmp_path / "atlaso.env"
    customizer.NETWORKD_PATH = tmp_path / "00-atlaso-mgmt.network"
    customizer.RESOLV_CONF_PATH = tmp_path / "resolv.conf"
    customizer.NGINX_MANAGEMENT_PATH = tmp_path / "management.conf"
    customizer.FIREWALL_CONFIG_PATH = tmp_path / "atlaso.nft"
    customizer.MARKER_PATH = tmp_path / "marker.json"
    customizer.PENDING_MARKER_PATH = tmp_path / "marker.pending.json"
    customizer.NGINX_MANAGEMENT_PATH.write_text("server_name atlaso.internal _;\n", encoding="utf-8")
    console_restarted = []
    monkeypatch.setattr(customizer, "restart_console", lambda: console_restarted.append(True))
    synchronized = []

    def sync_host_state():
        """Prove the console refresh precedes the host durability barrier."""
        assert console_restarted == [True]
        synchronized.append(True)

    monkeypatch.setattr(customizer.os, "sync", sync_host_state, raising=False)
    generated = iter(["rotated-secret-key", "rotated-secrets-key"])
    customizer.generate_secret_key = lambda: next(generated)
    customizer.set_password = lambda username, password: None
    customizer.set_hostname = lambda fqdn: None
    customizer.configure_root_ssh = lambda enabled: None
    development_ssh = []
    customizer.configure_development_admin_ssh = lambda username, key: development_ssh.append(
        (username, key)
    )
    published_host_keys = []
    customizer.publish_test_vm_ssh_host_key = lambda: published_host_keys.append(True)
    published_hostnames = []
    customizer.publish_test_vm_hostname = lambda: published_hostnames.append(True)
    scrubbed = []

    def clear_ovf_environment():
        """Record that credentials are scrubbed before the success marker."""
        assert synchronized == [True]
        assert not customizer.MARKER_PATH.exists()
        assert customizer.PENDING_MARKER_PATH.exists()
        scrubbed.append(True)

    customizer.clear_ovf_environment = clear_ovf_environment
    customizer.ENV_PATH.write_text(
        "\n".join(
            [
                'ATLASO_SECRET_KEY="baked-secret"',
                'ATLASO_SECRETS_KEY="baked-secrets-key"',
                'ATLASO_BOOTSTRAP_ADMIN_USERNAME="admin"',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    properties = customizer.parse_ovf_environment(OVF_ENV)
    properties["atlaso.ipv6_enabled"] = "true"
    properties["atlaso.ipv6_cidr"] = "fd00:10::10/64"
    properties["atlaso.ipv6_gateway"] = "fe80::1"
    properties["atlaso.root_ssh_enabled"] = "true"
    properties[customizer.PROPERTY_DEVELOPMENT_ADMIN_SSH_PUBLIC_KEY] = VALID_ED25519_PUBLIC_KEY
    properties[customizer.PROPERTY_NORMAL_TEST_VM] = "true"
    config = customizer.validate_properties(properties)

    summary = customizer.apply_customization(config)

    rendered = customizer.ENV_PATH.read_text(encoding="utf-8")
    assert 'ATLASO_SECRET_KEY="rotated-secret-key"' in rendered
    assert 'ATLASO_SECRETS_KEY="rotated-secrets-key"' in rendered
    assert "baked-secret" not in rendered
    assert "baked-secrets-key" not in rendered
    assert "rotated-secret-key" not in str(summary)
    assert "rotated-secrets-key" not in str(summary)
    assert 'ATLASO_APPLIANCE_MANAGEMENT_GATEWAY="192.168.10.1"' in rendered
    assert 'ATLASO_APPLIANCE_MANAGEMENT_IPV6_ENABLED="true"' in rendered
    assert 'ATLASO_APPLIANCE_MANAGEMENT_IPV6_GATEWAY="fe80::1"' in rendered
    assert 'ATLASO_APPLIANCE_ROOT_SSH_ENABLED="true"' in rendered
    marker = json.loads(customizer.MARKER_PATH.read_text(encoding="utf-8"))
    assert console_restarted == [True]
    assert synchronized == [True]
    assert scrubbed == [True]
    assert development_ssh == [("admin", VALID_ED25519_PUBLIC_KEY)]
    assert published_host_keys == [True]
    assert published_hostnames == [True]
    assert marker["cidr"] == "192.168.10.10/24"
    assert "admin-secret" not in str(marker)
    assert "root-secret1" not in str(marker)
    assert VALID_ED25519_PUBLIC_KEY not in str(marker)
    assert marker["development_admin_ssh_key_set"] is True


def test_vmware_ovf_export_and_image_plumbing_are_present():
    """Verify that vmware ovf export and image plumbing are present."""
    export_script = Path("scripts/windows/vmware/export-ovf.ps1").read_text(encoding="utf-8")
    payload_module = Path("scripts/windows/vmware/Atlaso.VmwarePayload.psm1").read_text(
        encoding="utf-8"
    )
    packer_template = Path("image/vmware-workstation/atlaso-photon.pkr.hcl").read_text(encoding="utf-8")
    provision_script = Path("image/common/scripts/provision-atlaso.sh").read_text(encoding="utf-8")
    bootstrap_script = Path("scripts/appliance/atlaso-bootstrap-https").read_text(encoding="utf-8")
    vmware_unit = Path("image/vmware-workstation/systemd/atlaso-vmware-ovf-customize.service").read_text(encoding="utf-8")
    docs = Path("image/vmware-workstation/README.md").read_text(encoding="utf-8")
    gitignore = Path(".gitignore").read_text(encoding="utf-8")

    for key in (
        "cidr",
        "gateway",
        "ipv6_enabled",
        "ipv6_cidr",
        "ipv6_gateway",
        "fqdn",
        "dns_servers",
        "admin_password",
        "root_password",
        "root_ssh_enabled",
    ):
        assert f"-Key '{key}'" in export_script
        assert f"-Key 'atlaso.{key}'" not in export_script
        assert f"`atlaso.{key}`" in docs

    assert "-Key 'management_mode'" not in export_script
    assert "PROPERTY_MANAGEMENT_MODE" in Path("scripts/appliance/atlaso-vmware-ovf-customize.py").read_text(encoding="utf-8")
    assert 'install -o root -g root -m 0640 /dev/null "$ATLASO_STATE/vmware-ovf-initializing"' in provision_script
    assert "-Boolean $true -DefaultValue 'false'" in export_script

    assert "ovftool was not found" in export_script
    assert "VMware Workstation\\OVFTool\\ovftool.exe" in export_script
    assert "Join-Path $Path 'ovftool.exe'" in export_script
    assert "Add-AtlasoOvfProperties" in export_script
    assert "Set-AtlasoOvfHardware" in export_script
    assert "Ensure-AtlasoOvfEmptyDataDisks" in export_script
    assert "Assert-AtlasoOvfDiskTopology" in export_script
    assert "exactly four disks (Photon OS, Atlaso System Content, VCF Offline Depot, and VCF Backups)" in export_script
    assert "Hard disk 2 - Atlaso System Content" in export_script
    assert "Hard disk 3 - VCF Offline Depot" in export_script
    assert "Hard disk 4 - VCF Backups" in export_script
    assert "Atlaso system-content disk must retain its file-backed payload" in export_script
    assert "atlaso-depot" in export_script
    assert "atlaso-backups" in export_script
    assert "RemoveAttribute('fileRef', $ovfNamespace)" in export_script
    assert "Set-OvfAttribute -Document $Document -Element $disk -Name 'format' -Value $diskFormat" in export_script
    assert "@('fileRef', 'parentRef', 'populatedSize')" in export_script
    assert "Write-AtlasoOvaProvenance" in export_script
    assert "atlaso-provenance.json" in export_script
    assert "Assert-AtlasoCanonicalOva" in export_script
    assert "Atlaso.OvfExport.psm1" in export_script
    assert "Clear-AtlasoOvfOutputDirectory" in export_script
    assert "$PSBoundParameters.ContainsKey('OutputDirectory')" in export_script
    assert "[switch]$Release" not in export_script
    assert "[string]$ReleaseTag" not in export_script
    assert "[string]$Repository" not in export_script
    assert "[string]$RepositoryName" not in export_script
    assert "Publish-AtlasoReleaseAssets" not in export_script
    assert "Resolve-AtlasoReleaseTag" not in export_script
    assert "VMware build provenance does not match the source VMX bytes" in payload_module
    assert "Atlaso.VmwarePayload.psm1" in export_script
    assert "Assert-AtlasoVmwarePayloadProvenance" in export_script
    assert export_script.index(
        "Assert-AtlasoVmwarePayloadProvenance -VmxPath $resolvedSourceVmx"
    ) < export_script.index("Clear-AtlasoOvfOutputDirectory")
    assert "--clobber" not in export_script
    assert "'osType' -Value 'vmwarePhoton64Guest'" in export_script
    assert "'id' -Value '36'" in export_script
    assert "'ResourceSubType' -Value 'VirtualSCSI'" in export_script
    assert "'ResourceType') -eq '15'" in export_script
    assert "ResourceType') -in @('5', '20')" in export_script
    assert "Ensure-AtlasoOvfNetworks" in export_script
    assert "SelectSingleNode('/ovf:Envelope/ovf:NetworkSection'" in export_script
    assert "envelope.InsertBefore($networkSection, $VirtualSystem)" in export_script
    assert "VirtualSystem.InsertBefore($networkSection, $HardwareSection)" not in export_script
    assert "Add-AtlasoOvfCategory" in export_script
    assert "Management network" in export_script
    assert "Appliance identity" in export_script
    assert "Initial credentials" in export_script
    assert "Leave blank to use DHCPv4" in export_script
    assert "-Name 'class' -Value 'atlaso'" in export_script
    assert "$propertyType = if ($Password) { 'password' } elseif ($Boolean) { 'boolean' } else { 'string' }" in export_script
    assert "$property.RemoveAttribute('password', $vmwNamespace)" in export_script
    assert "-Key 'admin_password'" in export_script and "-Password $true -MinLength 12" in export_script
    assert "-Key 'root_password'" in export_script and "-Password $true -MinLength 12" in export_script
    assert "development_admin_ssh_public_key" not in export_script
    assert "development_test_vm" not in export_script
    assert "development_root_ca_certificate" not in export_script
    assert "-Name 'qualifiers' -Value \"MinLen($MinLength)\"" in export_script
    assert "Atlaso Management Network" in export_script
    assert "Atlaso Services Network" in export_script
    assert "$serviceAdapter = $networkAdapters[1]" in export_script
    assert "Network adapter 2" in export_script
    assert "Remove-NamespacedChildElement -Parent $serviceAdapter -LocalName 'Address'" in export_script
    assert "Update-OvfManifest" in export_script
    assert "New-OvaArchive" in export_script
    assert "Get-OvfDescriptorPath" in export_script
    assert "-Recurse" in export_script
    assert "$ovfPackageDirectory = Split-Path -Parent $ovfPath" in export_script
    assert "New-OvaArchive -OvfDirectory $ovfPackageDirectory" in export_script
    assert "'transport' -Value 'com.vmware.guestInfo'" in export_script
    assert "com.vmware.guestInfo" in export_script
    assert "vmw:password" not in docs
    assert "atlaso-vmware-ovf-customize.py" in provision_script
    assert "atlaso-bootstrap-https" in provision_script
    assert "atlaso-bootstrap-https.service" in provision_script
    assert 'for action in ("validate", "apply")' in bootstrap_script
    assert 'str(HELPER_PATH), "ca", action, str(CA_STAGED_CONFIG_PATH), "--real"' in bootstrap_script
    assert "systemctl enable atlaso-vmware-ovf-customize.service" in provision_script
    assert "systemctl enable atlaso-bootstrap-https.service" in provision_script
    assert "Before=network-pre.target" in vmware_unit
    assert "After=local-fs.target atlaso-console.service" in vmware_unit
    assert "Wants=atlaso-console.service" in vmware_unit
    assert "atlaso-data-disks.service" in vmware_unit
    assert "atlaso-bootstrap-https.service" in vmware_unit
    assert "ExecStart=/opt/atlaso/.venv/bin/python /opt/atlaso/bin/atlaso-vmware-ovf-customize.py" in vmware_unit
    assert "TimeoutStartSec=infinity" in vmware_unit
    assert "/image/vmware-workstation/ovf" in gitignore
    assert "VMware Workstation\\OVFTool" in docs
    assert "Atlaso Management Network" in docs
    assert "Atlaso Services Network" in docs
    assert 'guest_os_type        = "vmware-photon-64"' in packer_template
    assert 'disk_adapter_type    = "pvscsi"' in packer_template
    assert '"sata0:0.present" = "FALSE"' in packer_template


def test_vmware_ovf_export_replacement_boundaries():
    """Verify OVF export replacement stays inside its approved temporary boundary."""
    pwsh = shutil.which("pwsh")
    if pwsh is None:
        pytest.skip("PowerShell 7 is not available")

    result = subprocess.run(
        [
            pwsh,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            "tests/powershell/Test-AtlasoOvfExport.ps1",
            "-RepositoryRoot",
            str(Path.cwd()),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr
