"""Measure installed lifecycle runtime bytes against the uploaded immutable wheel."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import ipaddress
import json
import os
import stat
import subprocess
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any


def file_digest(path: Path, maximum: int) -> str:
    """Hash a bounded ordinary file without following its final symlink.

    Args:
        path: Admitted artifact or installed payload path.
        maximum: Maximum accepted byte count.
    """
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise ValueError('deployment identity requires a bounded ordinary file')
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def installed_payload(wheel: Path, installed_root: Path) -> dict[str, Any]:
    """Compare every wheel member and reject stale installed Atlaso payload files.

    Args:
        wheel: Uploaded wheel whose digest is checked independently by the host.
        installed_root: Distribution root reported by installed package metadata.
    """
    expected = hashlib.sha256()
    observed = hashlib.sha256()
    payload_names = set()
    with zipfile.ZipFile(wheel) as archive:
        entries = archive.infolist()
        if len(entries) > 10000 or sum(entry.file_size for entry in entries) > 268435456:
            raise ValueError('wheel payload exceeds the inspection bound')
        names = [entry.filename for entry in entries if not entry.is_dir()]
        if len(names) != len(set(names)):
            raise ValueError('wheel payload contains duplicate names')
        checked = 0
        for name in sorted(names):
            relative = PurePosixPath(name)
            if relative.is_absolute() or '..' in relative.parts or '\\' in name or '.data' in relative.parts[0]:
                raise ValueError('unsupported wheel payload layout')
            if name.endswith('.dist-info/RECORD'):
                continue
            if relative.parts[0] == 'atlaso':
                payload_names.add(name)
            target = installed_root.joinpath(*relative.parts)
            if not target.resolve().is_relative_to(installed_root.resolve()):
                raise ValueError('installed payload escaped the distribution root')
            wanted = hashlib.sha256(archive.read(name)).hexdigest()
            actual = file_digest(target, 16777216)
            expected.update(f'{name}\0{wanted}\n'.encode())
            observed.update(f'{name}\0{actual}\n'.encode())
            checked += 1
    actual_names = set()
    for target in (installed_root / 'atlaso').rglob('*'):
        if len(actual_names) > 10000:
            raise ValueError('installed payload inventory exceeds the inspection bound')
        if target.is_symlink():
            raise ValueError('installed payload contains a symlink')
        if target.is_file() and '__pycache__' not in target.parts and target.suffix != '.pyc':
            actual_names.add(target.relative_to(installed_root).as_posix())
    if not payload_names or actual_names != payload_names or expected.digest() != observed.digest():
        raise ValueError('installed runtime bytes differ from the uploaded wheel')
    return {'wheel_payload_sha256': expected.hexdigest(), 'installed_payload_sha256': observed.hexdigest(),
            'verified_payload_files': checked}


def deployment_evidence(wheel: Path, address: str) -> dict[str, Any]:
    """Measure fixed runtime/helper paths and the actual interface owning the target.

    Args:
        wheel: Uploaded immutable wheel retained by the canonical deployer.
        address: Independently discovered appliance management address.
    """
    target = str(ipaddress.ip_address(address))
    distribution = importlib.metadata.distribution('atlaso')
    payload = installed_payload(wheel, Path(distribution.locate_file('')))
    native = subprocess.run(['ip', '-j', 'address', 'show'], capture_output=True, text=True, timeout=10, check=True)
    if len(native.stdout) > 262144:
        raise ValueError('native interface inventory exceeds the inspection bound')
    interfaces = [row for row in json.loads(native.stdout)
                  if any(item.get('local') == target for item in row.get('addr_info', []))]
    if len(interfaces) != 1:
        raise ValueError('deployed target does not have one native interface owner')
    interface = interfaces[0]
    return {'schema': 1, **payload, 'wheel_sha256': file_digest(wheel, 268435456),
            'helper_sha256': file_digest(Path('/opt/atlaso/bin/atlaso-helper'), 16777216),
            'interface': interface['ifname'], 'mac': interface['address'], 'address': target}


def main() -> int:
    """Write a new measured public report without replacing prior evidence."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wheel', type=Path, required=True)
    parser.add_argument('--address', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    evidence = deployment_evidence(args.wheel, args.address)
    descriptor = os.open(args.output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
        json.dump(evidence, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
