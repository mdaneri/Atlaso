from pathlib import Path
import importlib.util
import sys

import pytest


def load_customizer():
    path = Path("scripts/appliance/atlaso-vmware-ovf-customize.py")
    spec = importlib.util.spec_from_file_location("atlaso_vmware_ovf_customize", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["atlaso_vmware_ovf_customize"] = module
    spec.loader.exec_module(module)
    return module


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


def test_vmware_ovf_customizer_rejects_empty_or_whitespace_passwords():
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


def test_vmware_ovf_customizer_ignores_legacy_mode_and_derives_ipv4_from_cidr():
    customizer = load_customizer()
    properties = customizer.parse_ovf_environment(OVF_ENV)
    properties["atlaso.management_mode"] = "dhcp"

    config = customizer.validate_properties(properties)

    assert config["management_mode"] == "static"
    properties.pop("atlaso.cidr")
    properties.pop("atlaso.gateway")
    assert customizer.validate_properties(properties)["management_mode"] == "dhcp"


def test_vmware_ovf_customizer_rejects_incomplete_ipv4_pairs():
    customizer = load_customizer()
    properties = customizer.parse_ovf_environment(OVF_ENV)
    properties.pop("atlaso.gateway")
    try:
        customizer.validate_properties(properties)
    except customizer.OvfCustomizationError as exc:
        assert "gateway is required" in str(exc)
    else:
        raise AssertionError("static IPv4 without a gateway should fail")

    properties.pop("atlaso.cidr")
    properties["atlaso.gateway"] = "192.168.10.1"
    try:
        customizer.validate_properties(properties)
    except customizer.OvfCustomizationError as exc:
        assert "cannot be supplied" in str(exc)
    else:
        raise AssertionError("IPv4 gateway without a CIDR should fail")


def test_vmware_ovf_customizer_supports_disabled_auto_and_static_ipv6(tmp_path):
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
    customizer = load_customizer()
    properties = customizer.parse_ovf_environment(OVF_ENV)
    properties["atlaso.ipv6_cidr"] = "fd00:10::10/64"
    try:
        customizer.validate_properties(properties)
    except customizer.OvfCustomizationError as exc:
        assert "ipv6_enabled=true" in str(exc)
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
    customizer = load_customizer()
    customizer.SSHD_ROOT_LOGIN_CONFIG_PATH = tmp_path / "sshd_config.d" / "atlaso-root-login.conf"
    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)
        return type("Result", (), {"returncode": 0})()

    monkeypatch.setattr(customizer.shutil, "which", lambda command: "/usr/sbin/sshd" if command == "sshd" else None)
    monkeypatch.setattr(customizer.subprocess, "run", fake_run)

    customizer.configure_root_ssh(True)

    rendered = customizer.SSHD_ROOT_LOGIN_CONFIG_PATH.read_text(encoding="utf-8")
    assert "PermitRootLogin yes" in rendered
    assert "PasswordAuthentication yes" in rendered
    assert commands == [["/usr/sbin/sshd", "-t"]]


def test_vmware_ovf_customizer_requires_static_network_properties_only_for_static_mode():
    customizer = load_customizer()
    properties = customizer.parse_ovf_environment(OVF_ENV)

    properties.pop("atlaso.cidr")
    try:
        customizer.validate_properties(properties)
    except customizer.OvfCustomizationError as exc:
        assert "atlaso.cidr" in str(exc)
    else:
        raise AssertionError("missing static CIDR should fail validation")


def test_vmware_ovf_customizer_renders_initial_firewall_for_ovf_subnet(tmp_path):
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


def test_vmware_ovf_customizer_rotates_clone_specific_env_secrets(tmp_path):
    customizer = load_customizer()
    customizer.ENV_PATH = tmp_path / "atlaso.env"
    customizer.NETWORKD_PATH = tmp_path / "00-atlaso-mgmt.network"
    customizer.RESOLV_CONF_PATH = tmp_path / "resolv.conf"
    customizer.NGINX_MANAGEMENT_PATH = tmp_path / "management.conf"
    customizer.FIREWALL_CONFIG_PATH = tmp_path / "atlaso.nft"
    customizer.MARKER_PATH = tmp_path / "marker.json"
    customizer.NGINX_MANAGEMENT_PATH.write_text("server_name atlaso.internal _;\n", encoding="utf-8")
    generated = iter(["rotated-secret-key", "rotated-secrets-key"])
    customizer.generate_secret_key = lambda: next(generated)
    customizer.set_password = lambda username, password: None
    customizer.set_hostname = lambda fqdn: None
    customizer.configure_root_ssh = lambda enabled: None
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
    properties["atlaso.root_ssh_enabled"] = "true"
    config = customizer.validate_properties(properties)

    summary = customizer.apply_customization(config)

    rendered = customizer.ENV_PATH.read_text(encoding="utf-8")
    assert 'ATLASO_SECRET_KEY="rotated-secret-key"' in rendered
    assert 'ATLASO_SECRETS_KEY="rotated-secrets-key"' in rendered
    assert "baked-secret" not in rendered
    assert "baked-secrets-key" not in rendered
    assert "rotated-secret-key" not in str(summary)
    assert "rotated-secrets-key" not in str(summary)
    assert 'ATLASO_APPLIANCE_MANAGEMENT_IPV6_ENABLED="true"' in rendered
    assert 'ATLASO_APPLIANCE_ROOT_SSH_ENABLED="true"' in rendered


def test_vmware_ovf_export_and_image_plumbing_are_present():
    export_script = Path("scripts/windows/vmware/export-ovf.ps1").read_text(encoding="utf-8")
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
    assert "MaximumReleaseAssetBytes = 2147483647" in export_script
    assert "Publish-AtlasoReleaseAssets" in export_script
    assert "Assert-AtlasoReleaseProvenance" in export_script
    assert "Release publication requires a clean tracked worktree" in export_script
    assert 'rev-parse "$Tag^{}"' in export_script
    assert "Skipping OVA release asset" in export_script
    assert "--clobber" not in export_script
    assert "release upload $Tag @uploadAssets @repositoryArguments" in export_script
    assert "already contains different bytes" in export_script
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
    assert "atlaso-bootstrap-https.service" in vmware_unit
    assert "/image/vmware-workstation/ovf" in gitignore
    assert "VMware Workstation\\OVFTool" in docs
    assert "Atlaso Management Network" in docs
    assert "Atlaso Services Network" in docs
    assert 'guest_os_type        = "vmware-photon-64"' in packer_template
    assert 'disk_adapter_type    = "pvscsi"' in packer_template
    assert '"sata0:0.present" = "FALSE"' in packer_template
