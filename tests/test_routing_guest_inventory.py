"""Keep guest observations public and bounded before using their trust material."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.interop import routing_guest_inventory


@pytest.mark.parametrize('fault', [None, 'private-material', 'invalid-mac', 'oversized-links'])
def test_inventory_admits_only_public_bounded_observations(monkeypatch, fault):
    """Reject secret-shaped trust and malformed native observations.

    Args:
        monkeypatch: Replace read-only native and filesystem boundaries.
        fault: One invalid public observation.
    """
    rows = [{'ifname': 'eth0', 'address': '00:50:56:20:00:01',
        'addr_info': [{'local': '192.0.2.10', 'prefixlen': 24}]}]
    if fault == 'invalid-mac':
        rows[0]['address'] = 'unexpected'
    output = 'x' * 262145 if fault == 'oversized-links' else json.dumps(rows)
    monkeypatch.setattr(routing_guest_inventory.subprocess, 'run', lambda *args, **kwargs: SimpleNamespace(stdout=output))

    def read(path, *args, **kwargs):
        """Return synthetic public key or certificate material.

        Args:
            path: Fixed public observation path.
            *args: Unused filesystem call arguments.
            **kwargs: Unused filesystem call options.
        """
        if str(path).endswith('.pub'):
            return 'ssh-ed25519 AAAA fixture'
        return '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----' if fault == 'private-material' else '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----'

    monkeypatch.setattr(Path, 'read_text', read)
    monkeypatch.setattr(Path, 'exists', lambda self: True)
    monkeypatch.setattr(Path, 'is_symlink', lambda self: False)
    monkeypatch.setattr(Path, 'stat', lambda self: SimpleNamespace(st_size=100))
    if fault:
        with pytest.raises(ValueError):
            routing_guest_inventory.inventory()
    else:
        value = routing_guest_inventory.inventory()
        assert value['ssh_public_key'] == 'ssh-ed25519 AAAA'
        assert value['links'][0]['addresses'] == ['192.0.2.10/24']
