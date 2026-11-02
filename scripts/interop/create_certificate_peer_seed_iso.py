#!/usr/bin/env python3
"""Build the isolated, MAC-bound DHCP peer for certificate lifecycle acceptance."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from pathlib import Path

from create_nocloud_seed_iso import add_file


def _host_key_serial_script() -> str:
    """Return the bounded public-key-only serial publisher used by bootstrap mode."""
    return """#!/bin/sh
set -eu
key_file=/etc/ssh/ssh_host_ed25519_key.pub
attempt=0
while [ "$attempt" -lt 30 ]; do
  [ -s "$key_file" ] && break
  sleep 1
  attempt=$((attempt + 1))
done
[ -s "$key_file" ] || exit 1
size=$(wc -c < "$key_file")
case "$size" in ''|*[!0-9]*) exit 1;; esac
[ "$size" -le 512 ] || exit 1
ssh-keygen -lf "$key_file" >/dev/null 2>&1 || exit 1
public_line=$(awk '
  NR == 1 && NF >= 2 && NF <= 3 && $1 == "ssh-ed25519" && $2 ~ /^[A-Za-z0-9+\\/]+={0,2}$/ {
    line = "ATLASO_CERTIFICATE_PEER_ED25519_HOST_KEY_V1 " $1 " " $2
    valid = 1
    next
  }
  { valid = 0 }
  END {
    if (NR != 1 || !valid) exit 1
    print line
  }
' "$key_file") || exit 1
printf '%s\\n' "$public_line" > /dev/ttyS0
"""


def peer_files(args: argparse.Namespace) -> dict[str, str]:
    """Render a peer whose DHCP listener is confined to its private eth1.

    Args:
        args: Args used by this operation."""
    network = ipaddress.IPv4Interface(args.server_cidr)
    lease = ipaddress.IPv4Address(args.lease_address)
    if lease not in network.network or lease in (network.network.network_address, network.network.broadcast_address) or lease == network.ip:
        raise ValueError("The lease must be a distinct address in the private peer subnet.")
    if network.ip in (network.network.network_address, network.network.broadcast_address):
        raise ValueError("The peer server address must be a usable host address.")
    if network.network.prefixlen < 24 or network.network.prefixlen > 29:
        raise ValueError("The peer subnet must be a small /24 through /29 IPv4 network.")
    if not re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", args.client_mac):
        raise ValueError("The appliance eth0 MAC must have six exact hexadecimal octets.")
    if int(args.client_mac[:2], 16) & 1:
        raise ValueError("The appliance eth0 MAC must be unicast.")
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,62}", args.hostname):
        raise ValueError("The peer hostname is invalid.")
    if not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", args.user):
        raise ValueError("The peer SSH user is invalid.")
    if not re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/]+={0,2}(?: [^\r\n]{1,128})?", args.public_key):
        raise ValueError("An exact Ed25519 peer SSH public key is required.")
    publish_host_key = getattr(args, "publish_host_key_to_serial", False)
    preserve_host_keys = getattr(args, "preserve_host_keys", False)
    if not isinstance(preserve_host_keys, bool):
        raise ValueError("The host-key preservation option must be boolean.")
    if not isinstance(publish_host_key, bool):
        raise ValueError("The serial host-key publication option must be boolean.")
    instance_id = getattr(args, "instance_id", None)
    if instance_id is None:
        metadata_instance_id = args.hostname
    elif not isinstance(instance_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", instance_id):
        raise ValueError("The NoCloud instance ID is invalid.")
    else:
        metadata_instance_id = json.dumps(instance_id, ensure_ascii=True)

    # dnsmasq's static range has no dynamic pool: only this exact MAC receives
    # the reservation. eth0 stays on the management network for SSH control.
    dnsmasq = (
        "port=0\ninterface=eth1\nbind-interfaces\nexcept-interface=eth0\n"
        f"dhcp-range={network.network.network_address},static,{network.network.netmask},12h\n"
        f"dhcp-host={args.client_mac.lower()},{lease},12h\n"
        "dhcp-leasefile=/var/lib/misc/dnsmasq.leases\n"
        "dhcp-authoritative\n"
    )
    extra_packages = ""
    extra_write_files = ""
    extra_commands = ""
    if publish_host_key:
        extra_packages = "  - open-vm-tools\n  - open-vm-tools-openrc\n  - open-vm-tools-guestinfo\n  - iproute2\n  - sudo\n"
        publisher = _host_key_serial_script()
        extra_write_files = (
            "  - path: /usr/local/sbin/atlaso-certificate-peer-publish-host-key\n"
            "    permissions: '0755'\n"
            "    content: |\n"
            + "".join(f"      {line}\n" for line in publisher.splitlines())
        )
        extra_commands = (
            "  - rc-update add open-vm-tools default\n"
            "  - rc-service open-vm-tools start\n"
            "  - /usr/local/sbin/atlaso-certificate-peer-publish-host-key\n"
        )
    host_key_policy = "ssh_deletekeys: false\n" if preserve_host_keys else ""
    user_data = f"""#cloud-config
{host_key_policy}hostname: {args.hostname}
manage_etc_hosts: true
disable_root: true
ssh_pwauth: false
users:
  - default
  - name: {args.user}
    groups: wheel
    shell: /bin/ash
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock_passwd: true
    ssh_authorized_keys:
      - {json.dumps(args.public_key, ensure_ascii=True)}
package_update: true
packages:
  - curl
  - dnsmasq
  - openssl
  - openssh-client
{extra_packages}write_files:
  - path: /usr/local/etc/atlaso-certificate-peer.conf
    permissions: '0644'
    content: |
""" + "".join(f"      {line}\n" for line in dnsmasq.splitlines()) + f"""  - path: /usr/local/sbin/atlaso-certificate-https-probe
    permissions: '0755'
    content: |
      #!/bin/sh
      set -eu
      if [ "$#" -ne 2 ] || [ ! -s "$1" ]; then exit 2; fi
      case "$2" in ''|*[!0-9.]*) exit 2;; esac
      curl --fail --silent --show-error --max-time 20 --noproxy '*' \\
        --proto '=https' --cacert "$1" "https://$2/openapi.json" >/dev/null
{extra_write_files}runcmd:
  - rc-update add sshd default
  - rc-service sshd restart
  - mkdir -p /var/lib/misc
  - cp /usr/local/etc/atlaso-certificate-peer.conf /etc/dnsmasq.conf
  - dnsmasq --test --conf-file=/etc/dnsmasq.conf
  - rc-update add dnsmasq default
  - rc-service dnsmasq restart
{extra_commands}"""
    network_config = f"""version: 2
ethernets:
  eth0:
    dhcp4: true
  eth1:
    dhcp4: false
    addresses:
      - {network}
"""
    return {
        "user-data": user_data,
        "meta-data": f"instance-id: {metadata_instance_id}\nlocal-hostname: {args.hostname}\n",
        "network-config": network_config,
    }


def main() -> int:
    """Create a NoCloud seed ISO; the password is accepted on stdin only."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--hostname", required=True)
    parser.add_argument("--user", default="alpine")
    parser.add_argument("--public-key", required=True)
    parser.add_argument("--server-cidr", required=True)
    parser.add_argument("--lease-address", required=True)
    parser.add_argument("--client-mac", required=True)
    parser.add_argument("--publish-host-key-to-serial", action="store_true")
    parser.add_argument("--preserve-host-keys", action="store_true")
    parser.add_argument("--instance-id")
    args = parser.parse_args()
    files = peer_files(args)
    try:
        import pycdlib
    except ImportError:
        print("pycdlib is required", file=sys.stderr)
        return 2
    output = Path(args.output)
    if output.exists():
        raise FileExistsError(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, joliet=3, vol_ident="cidata")
    for name, iso_name in (("user-data", "USERDATA"), ("meta-data", "METADATA"), ("network-config", "NETCFG")):
        add_file(iso, name, files[name], iso_name)
    iso.write(str(output))
    iso.close()
    print(output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
