"""Focused safety checks for the isolated certificate DHCP peer seed."""

from __future__ import annotations

import argparse
import hashlib
import io
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts" / "interop"))
from create_certificate_peer_seed_iso import (
    build_argument_parser,  # noqa: E402 - Local interop import after path setup.
    peer_files,
)


def _args(**overrides: object) -> argparse.Namespace:
    """Handle args for certificate handoff verification.

    Args:
        **overrides: Overrides used by this operation."""
    values = {
        "server_cidr": "192.168.77.1/24",
        "lease_address": "192.168.77.10",
        "client_mac": "00:50:56:2a:11:22",
        "hostname": "certificate-peer",
        "user": "alpine",
        "public_key": "ssh-ed25519 " + "A" * 44 + " test-key",
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def test_seed_serializes_valid_nocloud_image_through_its_exclusive_output(monkeypatch, tmp_path):
    """Read the generated ISO back instead of inferring success from its filename.

    Args:
        monkeypatch: Supply the public command-line inputs.
        tmp_path: Originally owned pytest output directory.
    """
    import create_certificate_peer_seed_iso as seed
    import pycdlib

    target = tmp_path / "peer-seed.iso"
    args = _args()
    monkeypatch.setattr(sys, "argv", ["seed", "--output", str(target), "--hostname", args.hostname,
                        "--server-cidr", args.server_cidr, "--lease-address", args.lease_address,
                        "--client-mac", args.client_mac, "--public-key", args.public_key])
    assert seed.main() == 0
    iso = pycdlib.PyCdlib()
    iso.open(str(target))
    try:
        contents = io.BytesIO()
        iso.get_file_from_iso_fp(contents, joliet_path="/user-data")
        assert contents.getvalue().decode() == peer_files(args)["user-data"]
    finally:
        iso.close()


def test_seed_serialization_preserves_a_concurrent_output_insertion(monkeypatch, tmp_path):
    """An output created after inspection is never overwritten by ISO serialization.

    Args:
        monkeypatch: Substitute the exact insertion boundary in the real ISO builder.
        tmp_path: Originally owned pytest output directory.
    """
    import create_certificate_peer_seed_iso as seed
    import pycdlib

    target = tmp_path / "peer-seed.iso"
    original_new = pycdlib.PyCdlib.new

    def insert_before_serialization(iso, **kwargs):
        """Create a competing file after the builder's initial absence check.

        Args:
            iso: Actual pycdlib image being prepared.
            **kwargs: Normal new-image parameters.
        """
        original_new(iso, **kwargs)
        target.write_bytes(b"preserve concurrent output")

    monkeypatch.setattr(pycdlib.PyCdlib, "new", insert_before_serialization)
    args = _args()
    monkeypatch.setattr(sys, "argv", ["seed", "--output", str(target), "--hostname", args.hostname,
                        "--server-cidr", args.server_cidr, "--lease-address", args.lease_address,
                        "--client-mac", args.client_mac, "--public-key", args.public_key])
    with pytest.raises(FileExistsError):
        seed.main()
    assert target.read_bytes() == b"preserve concurrent output"


def test_peer_has_exact_mac_static_only_dhcp_on_private_interface() -> None:
    files = peer_files(_args())
    config = files["user-data"]
    assert "interface=eth1\n" in config
    assert "except-interface=eth0\n" in config
    assert "dhcp-range=192.168.77.0,static,255.255.255.0,12h\n" in config
    assert "dhcp-host=00:50:56:2a:11:22,192.168.77.10,12h\n" in config
    parsed = yaml.safe_load(config)
    assert parsed["ssh_pwauth"] is False
    assert "chpasswd" not in parsed
    assert parsed["users"][1]["lock_passwd"] is True
    assert parsed["users"][1]["ssh_authorized_keys"] == ["ssh-ed25519 " + "A" * 44 + " test-key"]
    assert parsed["write_files"][0]["path"] == "/usr/local/etc/atlaso-certificate-peer.conf"
    probe = parsed["write_files"][1]["content"]
    assert "--cacert \"$1\"" in probe
    assert "--noproxy '*'" in probe
    assert "https://$2/openapi.json" in probe
    assert "--insecure" not in probe and " -k" not in probe
    assert "dhcp4: true" in files["network-config"].split("  eth1:")[0]
    assert "dhcp4: false" in files["network-config"].split("  eth1:")[1]
    assert files["network-config"] == (
        "version: 2\nethernets:\n  eth0:\n    dhcp4: true\n"
        "  eth1:\n    dhcp4: false\n    addresses:\n      - 192.168.77.1/24\n"
    )
    assert files["meta-data"] == "instance-id: certificate-peer\nlocal-hostname: certificate-peer\n"
    assert "open-vm-tools" not in config
    assert "open-vm-tools-vix" not in config
    assert "publish-host-key" not in config
    assert "ATLASO_CERTIFICATE_PEER_ED25519_HOST_KEY_V1" not in config


def test_optional_bootstrap_installs_tools_and_publishes_only_public_host_key() -> None:
    args = _args(publish_host_key_to_serial=True)

    files = peer_files(args)

    parsed = yaml.safe_load(files["user-data"])
    assert "open-vm-tools" in parsed["packages"]
    assert "open-vm-tools-openrc" in parsed["packages"]
    assert "open-vm-tools-guestinfo" in parsed["packages"]
    assert "open-vm-tools-vix" not in parsed["packages"]
    assert "open-vm-tools-timesync" not in parsed["packages"]
    commands = parsed["runcmd"]
    assert commands == [
        "rc-update add sshd default",
        "rc-service sshd restart",
        "mkdir -p /var/lib/misc",
        "cp /usr/local/etc/atlaso-certificate-peer.conf /etc/dnsmasq.conf",
        "dnsmasq --test --conf-file=/etc/dnsmasq.conf",
        "rc-update add dnsmasq default",
        "rc-service dnsmasq restart",
        "rc-update add open-vm-tools default",
        "rc-service open-vm-tools start",
        "/usr/local/sbin/atlaso-certificate-peer-publish-host-key",
    ]
    assert commands.index("rc-service sshd restart") < commands.index("rc-service dnsmasq restart")
    assert commands.index("rc-service dnsmasq restart") < commands.index("rc-service open-vm-tools start")
    assert commands.index("rc-update add open-vm-tools default") < commands.index(
        "/usr/local/sbin/atlaso-certificate-peer-publish-host-key"
    )

    publisher = next(
        item["content"] for item in parsed["write_files"]
        if item["path"] == "/usr/local/sbin/atlaso-certificate-peer-publish-host-key"
    )
    assert publisher.startswith("#!/bin/sh\n")
    assert "key_file=/etc/ssh/ssh_host_ed25519_key.pub" in publisher
    assert "ATLASO_CERTIFICATE_PEER_ED25519_HOST_KEY_V1 " in publisher
    assert "> /dev/ttyS0" in publisher
    assert "-le 512" in publisher and '"$attempt" -lt 30' in publisher
    assert "ssh-keygen -lf \"$key_file\"" in publisher
    assert args.public_key not in publisher
    assert "/etc/ssh/ssh_host_ed25519_key \"" not in publisher


@pytest.mark.parametrize(
    ("overrides", "expected_digest"),
    # Digests of peer_files outputs from the task's original HEAD a3165c1fa.
    [
        ({}, "0560c712955b1918616a1016802fb181847838e4f351131d3b1fae3e2a364667"),
        ({"publish_host_key_to_serial": True}, "e1639ade3764d9ecf81d2eaf40c138c07b6b55bc5136aafffbbb737cd3b2d78d"),
        ({"publish_host_key_to_serial": True,
          "management_addresses": ["192.168.77.10", "192.168.77.30", "192.168.77.40"]},
         "2093b390d7afb8785cf5e9ceb460d6343f4c7531cc2243647261ab1bf8c82b8b"),
        ({"publish_host_key_to_serial": True, "serve_ntp": True,
          "management_addresses": ["192.168.77.10", "192.168.77.30", "192.168.77.40"],
          "ntp_probe_cidr": "192.168.78.1/24"},
         "a3ab3f770b003638bcac842373a00908da6206632b508bf4d31646f98cac1fc2"),
    ],
    ids=["plain", "host-key", "private-ssh", "ntp-peer"],
)
def test_non_vix_modes_render_byte_for_byte_like_original_seed(
    overrides: dict[str, object], expected_digest: str
) -> None:
    """Keep opt-in bootstrap changes out of existing seed modes from HEAD a3165c1fa.

    Args:
        overrides: Seed-generator options for one legacy mode.
        expected_digest: SHA-256 of the expected concatenated seed files.
    """
    files = peer_files(_args(**overrides))
    joined = b"\0".join(files[key].encode() for key in ("user-data", "meta-data", "network-config"))

    assert hashlib.sha256(joined).hexdigest() == expected_digest


def test_ntp_vmware_vix_mode_installs_and_verifies_tools_before_public_marker() -> None:
    args = _args(
        publish_host_key_to_serial=True,
        vmware_vix=True,
        serve_ntp=True,
        management_addresses=["192.168.77.10", "192.168.77.30", "192.168.77.40"],
        ntp_probe_cidr="192.168.78.1/24",
    )

    parsed = yaml.safe_load(peer_files(args)["user-data"])
    packages = parsed["packages"]
    commands = parsed["runcmd"]
    marker = "/usr/local/sbin/atlaso-certificate-peer-publish-host-key"

    assert "open-vm-tools-vix" in packages
    assert "open-vm-tools-guestinfo" in packages
    assert "open-vm-tools-timesync" not in packages
    assert "open-vm-tools-plugins-all" not in packages
    assert len(commands) == 1
    vix_bootstrap = commands[0]
    guestinfo_check = "test -s /usr/lib/open-vm-tools/plugins/vmsvc/libguestInfo.so"
    vix_check = "test -s /usr/lib/open-vm-tools/plugins/common/libvix.so"
    restart = "rc-service open-vm-tools restart"
    ordered_steps = [
        "/usr/local/sbin/atlaso-certificate-peer-sshd",
        "rc-update add sshd default",
        "rc-service sshd restart",
        "rc-service sshd status",
        "mkdir -p /var/lib/misc",
        "cp /usr/local/etc/atlaso-certificate-peer.conf /etc/dnsmasq.conf",
        "dnsmasq --test --conf-file=/etc/dnsmasq.conf",
        "rc-update add dnsmasq default",
        "rc-service dnsmasq restart",
        "rc-service dnsmasq status",
        guestinfo_check,
        vix_check,
        "rc-update add open-vm-tools default",
        restart,
        "rc-service open-vm-tools status",
        "/usr/local/sbin/atlaso-certificate-peer-chrony",
        marker,
    ]
    assert vix_bootstrap.startswith("set -eu\n")
    assert [vix_bootstrap.index(step) for step in ordered_steps] == sorted(
        vix_bootstrap.index(step) for step in ordered_steps
    )
    assert vix_bootstrap.splitlines()[-1] == marker
    assert "||" not in vix_bootstrap
    assert vix_bootstrap.count("/usr/local/sbin/atlaso-certificate-peer-chrony") == 1


def test_vmware_vix_option_requires_public_host_key_marker() -> None:
    with pytest.raises(ValueError, match="serial host-key publication"):
        peer_files(_args(vmware_vix=True))


def test_vmware_vix_cli_flag_is_explicit_and_opt_in() -> None:
    parser = build_argument_parser()
    base = [
        "--output", "peer.iso", "--hostname", "peer", "--public-key", "ssh-ed25519 key",
        "--server-cidr", "192.168.77.1/24", "--lease-address", "192.168.77.10",
        "--client-mac", "00:50:56:2a:11:22",
    ]

    default_args = parser.parse_args(base)
    assert default_args.vmware_vix is False
    assert default_args.retain_instance_cache is False
    parsed_args = parser.parse_args(
        [
            *base,
            "--publish-host-key-to-serial",
            "--vmware-vix",
            "--serve-ntp",
            "--instance-id", "ntp-peer-unique-fixture-01",
            "--retain-instance-cache",
            "--management-address", "192.168.77.10",
            "--management-address", "192.168.77.30",
            "--management-address", "192.168.77.40",
            "--ntp-probe-cidr", "192.168.78.1/24",
        ]
    )
    assert parsed_args.vmware_vix is True
    assert parsed_args.retain_instance_cache is True
    rendered = yaml.safe_load(peer_files(parsed_args)["user-data"])
    assert "open-vm-tools-vix" in rendered["packages"]
    assert len(rendered["runcmd"]) == 1
    vix_bootstrap = rendered["runcmd"][0]
    assert "set -eu" in vix_bootstrap
    assert vix_bootstrap.index("rc-service open-vm-tools status") < vix_bootstrap.index(
        "/usr/local/sbin/atlaso-certificate-peer-publish-host-key"
    )


def test_seed_removal_preserves_provisioned_host_keys_and_network_without_optional_console_helper() -> None:
    """Keep the same trusted peer after detaching its original public NoCloud seed."""
    parsed = yaml.safe_load(peer_files(_args())['user-data'])
    assert parsed["ssh"] == {"emit_keys_to_console": False}
    policy = next(item for item in parsed["write_files"]
                  if item["path"] == "/etc/cloud/cloud.cfg.d/99-atlaso-certificate-retained-peer.cfg")
    assert policy["permissions"] == '0644'
    retained = yaml.safe_load(policy["content"])
    assert retained == {"datasource_list": ["NoCloud", "None"], "ssh_deletekeys": False,
                        "ssh": {"emit_keys_to_console": False}, "network": {"config": "disabled"}}
    assert "ssh_deletekeys" not in parsed  # The first boot still generates fresh host keys.
    assert "manual_cache_clean" not in retained


def test_ntp_retained_instance_cache_is_opt_in_and_limited_to_qualified_peer_mode() -> None:
    """Render manual cache trust only for an explicit, unique NTP peer identity.

    Args:
        None.
    """
    common = {
        "publish_host_key_to_serial": True,
        "instance_id": "ntp-peer-unique-fixture-01",
        "serve_ntp": True,
        "vmware_vix": True,
        "management_addresses": ["192.168.77.10", "192.168.77.30", "192.168.77.40"],
        "ntp_probe_cidr": "192.168.78.1/24",
        "retain_instance_cache": True,
    }
    files = peer_files(_args(**common))
    user_data = yaml.safe_load(files["user-data"])
    policy = next(
        item["content"] for item in user_data["write_files"]
        if item["path"] == "/etc/cloud/cloud.cfg.d/99-atlaso-certificate-retained-peer.cfg"
    )
    assert yaml.safe_load(policy) == {
        "datasource_list": ["NoCloud", "None"],
        "ssh_deletekeys": False,
        "manual_cache_clean": True,
        "ssh": {"emit_keys_to_console": False},
        "network": {"config": "disabled"},
    }
    assert "manual_cache_clean" not in user_data
    assert yaml.safe_load(files["meta-data"])["instance-id"] == common["instance_id"]

    invalid_modes = (
        {key: value for key, value in common.items() if key != "instance_id"},
        {**common, "publish_host_key_to_serial": False, "vmware_vix": False},
        {**common, "vmware_vix": False},
        {**common, "serve_ntp": False},
    )
    for mode in invalid_modes:
        with pytest.raises(ValueError, match="Retaining the NoCloud instance cache requires"):
            peer_files(_args(**mode))

    with pytest.raises(ValueError, match="instance-cache option must be boolean"):
        peer_files(_args(**{**common, "retain_instance_cache": "yes"}))


def test_optional_instance_id_is_quoted_and_safe_for_cloud_init() -> None:
    files = peer_files(_args(instance_id="certificate-peer-rerun-001"))

    metadata = yaml.safe_load(files["meta-data"])

    assert metadata == {
        "instance-id": "certificate-peer-rerun-001",
        "local-hostname": "certificate-peer",
    }


def test_authorized_reseed_preserves_original_console_host_key() -> None:
    parsed = yaml.safe_load(peer_files(_args(preserve_host_keys=True, publish_host_key_to_serial=True))["user-data"])
    assert parsed["ssh_deletekeys"] is False
    assert parsed["ssh_pwauth"] is False
    assert "iproute2" in parsed["packages"] and "sudo" in parsed["packages"]
    assert "ssh_deletekeys" not in yaml.safe_load(peer_files(_args())["user-data"])


def test_management_channels_are_limited_to_three_addresses_before_sshd_restart() -> None:
    """Configure the private SSH destinations without enabling remote forwarding."""
    parsed = yaml.safe_load(peer_files(_args(management_addresses=[
        "192.168.77.40", "192.168.77.10", "192.168.77.30",
    ]))["user-data"])
    files = {item["path"]: item["content"] for item in parsed["write_files"]}
    policy = files["/etc/ssh/sshd_config.d/00-atlaso-certificate-peer.conf"]
    assert policy == (
        "DisableForwarding no\nAllowTcpForwarding local\nGatewayPorts no\n"
        "AllowAgentForwarding no\nX11Forwarding no\n"
        "PermitOpen 192.168.77.10:22 192.168.77.10:443 192.168.77.30:22 "
        "192.168.77.30:443 192.168.77.40:22 192.168.77.40:443\n"
    )
    installer = "/usr/local/sbin/atlaso-certificate-peer-sshd"
    assert 'sshd -t\n' in files[installer]
    assert parsed["runcmd"].index(installer) < parsed["runcmd"].index("rc-service sshd restart")
    assert "AllowTcpForwarding" not in peer_files(_args())["user-data"]


def test_optional_ntp_uses_the_same_peer_after_public_ssh_admission():
    """Add real time serving without adding a VM or changing upstream sources."""
    parsed = yaml.safe_load(peer_files(_args(serve_ntp=True, publish_host_key_to_serial=True,
                                           management_addresses=["192.168.77.10", "192.168.77.30", "192.168.77.40"]))["user-data"])
    assert "chrony" in parsed["packages"]
    assert parsed["runcmd"].index("/usr/local/sbin/atlaso-certificate-peer-publish-host-key") < parsed["runcmd"].index(
        "/usr/local/sbin/atlaso-certificate-peer-chrony")
    config = next(row["content"] for row in parsed["write_files"] if row["path"].endswith("peer-chrony.conf"))
    assert "bindaddress 192.168.77.1" in config and "allow 192.168.77.40/32" in config
    assert "local stratum" not in config and "server " not in config
    with pytest.raises(ValueError):
        peer_files(_args(serve_ntp=True))


def test_ntp_probe_adds_only_a_disjoint_private_address_to_eth1():
    args = _args(
        serve_ntp=True,
        publish_host_key_to_serial=True,
        management_addresses=["192.168.77.10", "192.168.77.30", "192.168.77.40"],
        ntp_probe_cidr="192.168.78.1/24",
    )

    files = peer_files(args)
    network = yaml.safe_load(files["network-config"])["ethernets"]
    assert set(network) == {"eth0", "eth1"}
    assert network["eth0"] == {"dhcp4": True}
    assert network["eth1"] == {"dhcp4": False, "addresses": ["192.168.77.1/24", "192.168.78.1/24"]}
    assert files["user-data"].count("interface=eth1") == 1

    parsed = yaml.safe_load(files["user-data"])
    chrony = next(
        row["content"] for row in parsed["write_files"] if row["path"].endswith("peer-chrony.conf")
    )
    assert "bindaddress 192.168.77.1" in chrony
    assert "bindaddress 192.168.78.1" not in chrony
    assert "allow 192.168.78.1/32" not in chrony
    assert "local stratum" not in chrony and "server " not in chrony


@pytest.mark.parametrize(
    "overrides",
    [
        {"serve_ntp": False, "publish_host_key_to_serial": True},
        {"serve_ntp": True, "publish_host_key_to_serial": False},
    ],
)
def test_ntp_probe_requires_ntp_and_public_host_key_admission(overrides: dict[str, bool]) -> None:
    """Require NTP serving and public host-key admission for the probe address.

    Args:
        overrides: Admission-flag combination with one required option disabled.
    """
    with pytest.raises(ValueError, match="NTP serving and public host-key admission"):
        peer_files(
            _args(
                management_addresses=["192.168.77.10", "192.168.77.30", "192.168.77.40"],
                ntp_probe_cidr="192.168.78.1/24",
                **overrides,
            )
        )


@pytest.mark.parametrize(
    "probe_cidr",
    [
        "192.168.77.50/24",  # overlaps the DHCP network
        "fd12:3456::1/24",  # IPv6 is outside this appliance fixture
        "8.8.8.1/24",  # public
        "192.168.78.1/25",  # not a /24
        "192.168.78.0/24",  # network address
        "192.168.78.255/24",  # broadcast address
        "127.0.0.1/24",  # loopback
        "169.254.0.1/24",  # link-local
    ],
)
def test_ntp_probe_rejects_non_private_or_unusable_interfaces(probe_cidr: str) -> None:
    """Reject probe addresses outside the supported usable private /24 range.

    Args:
        probe_cidr: Probe-interface CIDR candidate to reject.
    """
    with pytest.raises(ValueError):
        peer_files(
            _args(
                serve_ntp=True,
                publish_host_key_to_serial=True,
                management_addresses=["192.168.77.10", "192.168.77.30", "192.168.77.40"],
                ntp_probe_cidr=probe_cidr,
            )
        )


@pytest.mark.parametrize("addresses", [
    ["192.168.78.10"], ["192.168.77.1"], ["192.168.77.0"], ["192.168.77.255"],
    ["192.168.77.30"], ["192.168.77.10", "192.168.77.10"], ["any"],
    ["192.168.77.10", "192.168.77.30", "192.168.77.40", "192.168.77.50"],
])
def test_management_channels_reject_ambiguous_or_external_destinations(addresses: list[str]) -> None:
    """Reject tunnel destinations outside the exact appliance address set.

    Args:
        addresses: Invalid destination list supplied to the seed generator.
    """
    with pytest.raises(ValueError):
        peer_files(_args(management_addresses=addresses))


@pytest.mark.parametrize(
    "bad",
    [
        {"lease_address": "192.168.78.10"},
        {"lease_address": "192.168.77.1"},
        {"lease_address": "192.168.77.255"},
        {"client_mac": "00:50:56:*"},
        {"client_mac": "01:50:56:2a:11:22"},
        {"server_cidr": "192.168.77.1/16"},
        {"server_cidr": "192.168.77.0/24"},
        {"hostname": "bad\nconfig"},
        {"public_key": "ssh-rsa " + "A" * 44},
        {"instance_id": "bad\nlocal-hostname: attacker"},
        {"instance_id": ""},
        {"publish_host_key_to_serial": "yes"},
    ],
)
def test_peer_rejects_ambiguous_or_external_input(bad: dict[str, str]) -> None:
    """Handle test peer rejects ambiguous or external input for certificate handoff verification.

    Args:
        bad: Bad used by this operation."""
    with pytest.raises(ValueError):
        peer_files(_args(**bad))
