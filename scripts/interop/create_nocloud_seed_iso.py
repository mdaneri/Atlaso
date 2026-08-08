#!/usr/bin/env python3
"""Create a NoCloud seed ISO for Atlaso lifecycle client VMs."""

from __future__ import annotations

import argparse
import io
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create a NoCloud cidata ISO.")
    parser.add_argument("--output", required=True)
    parser.add_argument("--hostname", required=True)
    parser.add_argument("--user", default="alpine")
    parser.add_argument("--public-key", default="")
    parser.add_argument("--password", default="")
    return parser.parse_args()


def cloud_init_files(args: argparse.Namespace) -> dict[str, str]:
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
  - chrony
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


def add_file(iso, name: str, content: str, iso_name: str) -> None:  # type: ignore[no-untyped-def]
    data = content.encode("utf-8")
    iso.add_fp(io.BytesIO(data), len(data), iso_path=f"/{iso_name}.;1", joliet_path=f"/{name}")


def main() -> int:
    try:
        import pycdlib
    except ImportError:
        print("pycdlib is required. Install it with: python -m pip install pycdlib", file=sys.stderr)
        return 2

    args = parse_args()
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
