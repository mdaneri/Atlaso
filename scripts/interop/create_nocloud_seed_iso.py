#!/usr/bin/env python3
"""Create a NoCloud seed ISO for Atlaso lifecycle client VMs."""

from __future__ import annotations

import argparse
import io
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    """Parse args.

    Returns:
        The parsed args.
    """
    parser = argparse.ArgumentParser(description="Create a NoCloud cidata ISO.")
    parser.add_argument("--output", required=True)
    parser.add_argument("--hostname", required=True)
    parser.add_argument("--user", default="alpine")
    parser.add_argument("--public-key", default="")
    parser.add_argument("--password", default="")
    parser.add_argument(
        "--password-stdin",
        action="store_true",
        help="Read the client password from standard input instead of argv.",
    )
    parser.add_argument("--routing-overlap-guest", action="store_true",
                        help="Install private routing-fixture tools without starting a DHCP/RA service.")
    return parser.parse_args()


def load_password_from_stdin(args: argparse.Namespace, stream: io.TextIOBase) -> None:
    """Load one bounded client password from standard input when requested.

    Args:
        args: Parsed command-line options updated with the supplied password.
        stream: Text stream containing exactly one password line.

    Raises:
        ValueError: If stdin password input is empty, multiline, or oversized.
    """
    if not args.password_stdin:
        return
    if args.password:
        raise ValueError("--password and --password-stdin cannot be used together.")

    password_input = stream.read(4097)
    if len(password_input) > 4096:
        raise ValueError("The stdin password exceeds the 4096-character limit.")
    password = password_input.removesuffix("\n").removesuffix("\r")
    if not password or "\n" in password or "\r" in password:
        raise ValueError("--password-stdin requires exactly one non-empty password line.")
    args.password = password


def cloud_init_files(args: argparse.Namespace) -> dict[str, str]:
    """Return cloud init files.

    Args:
        args: Parsed command-line options consumed by the operation.


    Raises:
        ValueError: If an input value is invalid.
    """
    if not args.public_key and not args.password:
        raise ValueError("Either --public-key or --password is required for client SSH access.")

    password_block = "ssh_pwauth: false"
    if args.password:
        password_block = f"""chpasswd:
  expire: false
  users:
    - name: {args.user}
      password: {args.password}
      type: text
ssh_pwauth: true"""

    key_block = ""
    if args.public_key:
        key_block = f"""
    ssh_authorized_keys:
      - {args.public_key}"""

    fixture_mode = bool(getattr(args, "routing_overlap_guest", False))
    # Alpine cloud-init 26.1 may warn when its optional console-fingerprint
    # helper is absent; the private fixture never needs to print host keys.
    fixture_ssh_policy = "\nssh:\n  emit_keys_to_console: false" if fixture_mode else ""
    fixture_packages = (
        "\n  - dnsmasq\n  - radvd\n  - python3\n  - nftables\n  - ethtool"
        "\n  - sudo\n  - open-vm-tools\n  - open-vm-tools-openrc\n  - open-vm-tools-vix"
        if fixture_mode else ""
    )
    fixture_services = (
        "\n  - rc-update add open-vm-tools default\n  - rc-service open-vm-tools start"
        "\n  - ethtool -K eth0 lro off\n  - ethtool -K eth1 lro off"
        if fixture_mode else ""
    )
    # The credential-bearing seed is detached after the first boot. Restrict
    # subsequent boots to the now-absent NoCloud source and its immediate None
    # fallback instead of probing EC2 metadata for four minutes.
    fixture_datasources = (
        "\n  - path: /etc/cloud/cloud.cfg.d/99-atlaso-fixture-datasources.cfg"
        "\n    permissions: '0644'"
        "\n    content: |"
        "\n      datasource_list: [ NoCloud, None ]"
        if fixture_mode else ""
    )
    fixture_forwarding = (
        "\n  - path: /etc/ssh/sshd_config.d/99-atlaso-private-fixture.conf"
        "\n    permissions: '0644'"
        "\n    content: |"
        "\n      DisableForwarding no"
        "\n      AllowTcpForwarding local"
        "\n      PermitOpen 192.0.2.10:22 192.0.2.10:443"
        "\n      GatewayPorts no"
        "\n  - path: /usr/local/sbin/atlaso-private-fixture-sshd"
        "\n    permissions: '0755'"
        "\n    content: |"
        "\n      #!/bin/sh"
        "\n      set -eu"
        "\n      config=/etc/ssh/sshd_config"
        "\n      grep -q '^Include /etc/ssh/sshd_config.d/\\*.conf' \"$config\" || sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' \"$config\""
        "\n      sshd -t"
        "\n      sshd -T | grep -q '^disableforwarding no$'"
        "\n      sshd -T | grep -q '^allowtcpforwarding local$'"
        "\n      sshd -T | grep -q 'permitopen .*192.0.2.10:22'"
        "\n      sshd -T | grep -q 'permitopen .*192.0.2.10:443'"
        if fixture_mode else ""
    )
    fixture_forwarding_command = "\n  - /usr/local/sbin/atlaso-private-fixture-sshd" if fixture_mode else ""
    # YAML treats a bare `true` as a boolean; cloud-init runcmd requires strings.
    refresh_command = "'true'" if fixture_mode else "/usr/local/sbin/atlaso-refresh-test-dhcp || true"

    user_data = f"""#cloud-config
hostname: {args.hostname}
manage_etc_hosts: true
disable_root: true
{password_block}{fixture_ssh_policy}
users:
  - default
  - name: {args.user}
    groups: wheel
    shell: /bin/ash
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock_passwd: false
{key_block}
package_update: true
growpart:
  mode: auto
  devices: ['/']
resize_rootfs: true
packages:
  - bind-tools
  - chrony-nts
  - curl
  - iproute2
  - iputils
  - openssl
  - openssh-client
  - sshpass{fixture_packages}
write_files:
  - path: /usr/local/sbin/atlaso-refresh-test-dhcp
    permissions: '0755'
    content: |
      #!/bin/sh
      for iface in eth1 eth2; do
        ip link set "$iface" up 2>/dev/null || true
        udhcpc -i "$iface" -H "$(hostname -s)" -q -n -t 5 2>/dev/null || true
      done{fixture_datasources}{fixture_forwarding}
runcmd:{fixture_forwarding_command}
  - rc-update add sshd default || true
  - rc-service sshd restart || true{fixture_services}
  - {refresh_command}
"""

    return {
        "user-data": user_data,
        "meta-data": f"instance-id: {args.hostname}\nlocal-hostname: {args.hostname}\n",
        "network-config": ("""version: 2
ethernets:
  eth0:
    dhcp4: true
  eth1:
    dhcp4: false
    dhcp6: false
    accept-ra: false
    optional: true
""" if fixture_mode else """version: 2
ethernets:
  eth0:
    dhcp4: true
  eth1:
    dhcp4: true
    optional: true
  eth2:
    dhcp4: true
    optional: true
"""),
    }


def add_file(iso, name: str, content: str, iso_name: str) -> None:  # type: ignore[no-untyped-def]  # Pycdlib has no typed public ISO object protocol.
    """Create file.

    Args:
        iso: Iso consumed by add file.
        name: Stable name identifying the resource or operation.
        content: Content processed or persisted by the operation.
        iso_name: Iso name consumed by add file.
    """
    data = content.encode("utf-8")
    iso.add_fp(io.BytesIO(data), len(data), iso_path=f"/{iso_name}.;1", joliet_path=f"/{name}")


def main() -> int:
    """Run the command-line entry point.

    Returns:
        The main result.
    """
    try:
        import pycdlib
    except ImportError:
        print("pycdlib is required. Install it with: python -m pip install pycdlib", file=sys.stderr)
        return 2

    args = parse_args()
    # Resolve stdin before creating or deleting the output so invalid secret
    # transport cannot disturb an existing seed artifact.
    load_password_from_stdin(args, sys.stdin)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        output.unlink()

    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, joliet=3, vol_ident="cidata")
    files = cloud_init_files(args)
    add_file(iso, "user-data", files["user-data"], "USERDATA")
    add_file(iso, "meta-data", files["meta-data"], "METADATA")
    add_file(iso, "network-config", files["network-config"], "NETCFG")
    iso.write(str(output))
    iso.close()
    print(output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
