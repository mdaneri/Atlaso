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

    user_data = f"""#cloud-config
hostname: {args.hostname}
manage_etc_hosts: true
disable_root: true
{password_block}
users:
  - default
  - name: {args.user}
    groups: wheel
    shell: /bin/ash
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock_passwd: false
{key_block}
package_update: true
packages:
  - bind-tools
  - chrony-nts
  - curl
  - iproute2
  - iputils
  - openssl
  - openssh-client
  - sshpass
write_files:
  - path: /usr/local/sbin/atlaso-refresh-test-dhcp
    permissions: '0755'
    content: |
      #!/bin/sh
      for iface in eth1 eth2; do
        ip link set "$iface" up 2>/dev/null || true
        udhcpc -i "$iface" -q -n -t 5 2>/dev/null || true
      done
runcmd:
  - rc-update add sshd default || true
  - rc-service sshd restart || true
  - /usr/local/sbin/atlaso-refresh-test-dhcp || true
"""

    return {
        "user-data": user_data,
        "meta-data": f"instance-id: {args.hostname}\nlocal-hostname: {args.hostname}\n",
        "network-config": """version: 2
ethernets:
  eth0:
    dhcp4: true
  eth1:
    dhcp4: true
    optional: true
  eth2:
    dhcp4: true
    optional: true
""",
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
