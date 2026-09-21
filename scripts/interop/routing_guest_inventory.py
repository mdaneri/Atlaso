"""Read public guest NIC and trust identities through owned VMware guest operations."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any


def inventory() -> dict[str, Any]:
    """Return actual public link, address, SSH key and optional HTTPS CA data."""
    response = subprocess.run(['ip', '-j', 'address', 'show'], capture_output=True, text=True, timeout=10, check=True)
    if len(response.stdout) > 262144:
        raise ValueError('guest interface inventory exceeds bound')
    rows = json.loads(response.stdout)
    if not isinstance(rows, list) or len(rows) > 128:
        raise ValueError('guest interface inventory is invalid')
    links = []
    for row in rows:
        name, mac = row.get('ifname'), row.get('address')
        if name == 'lo':
            continue
        if (not isinstance(name, str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,14}', name)
                or not isinstance(mac, str) or not re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', mac)):
            raise ValueError('guest link identity is invalid')
        addresses = []
        for address in row.get('addr_info', []):
            parsed = ipaddress.ip_interface(f"{address['local']}/{address['prefixlen']}")
            addresses.append(str(parsed))
        links.append({'interface': name, 'mac': mac, 'addresses': addresses})
    public_key = Path('/etc/ssh/ssh_host_ed25519_key.pub').read_text().strip()
    fields = public_key.split()
    if len(public_key) > 16384 or len(fields) < 2 or fields[0] != 'ssh-ed25519' or not re.fullmatch(r'[A-Za-z0-9+/=]+', fields[1]):
        raise ValueError('guest SSH public key is invalid')
    ca_path = Path('/etc/atlaso/ca/root.crt')
    certificate = None
    if ca_path.exists():
        if ca_path.is_symlink() or ca_path.stat().st_size > 65536:
            raise ValueError('guest public CA path is invalid')
        certificate = ca_path.read_text()
        if not re.fullmatch(r'\s*-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----\s*', certificate):
            raise ValueError('guest public CA material is invalid')
    return {'schema': 1, 'links': links, 'ssh_public_key': ' '.join(fields[:2]), 'ca_pem': certificate}


def main() -> int:
    """Publish one new bounded public guest observation without replacing old files."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = inventory()
    descriptor = os.open(args.output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
        json.dump(result, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
