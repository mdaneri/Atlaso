"""Read public source-image routing prerequisites before lifecycle deployment."""

from __future__ import annotations

import argparse
import importlib.metadata
import ipaddress
import json
import os
import re
import stat
import subprocess
from pathlib import Path
from typing import Any

INTENT = Path('/etc/atlaso/route-domains.json')
SERVICE = 'atlaso-route-domains.service'


def public_intent(path: Path = INTENT) -> dict[str, Any] | None:
    """Read only bounded validated public routing intent, preserving missing state.

    Args:
        path: Fixed routing-domain intent location or isolated test fixture.
    """
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 65536:
            raise ValueError('source routing intent is not a bounded ordinary file')
        data = json.loads(stream.read(65537))
    if (not isinstance(data, dict) or set(data) - {'schema', 'interfaces', 'held_addresses'}
            or data.get('schema') != 1):
        raise ValueError('source routing intent schema is invalid')
    result: dict[str, Any] = {'schema': 1}
    for field in ('interfaces', 'held_addresses'):
        rows = data.get(field, [])
        if not isinstance(rows, list) or len(rows) > 256:
            raise ValueError('source routing intent inventory is invalid')
        checked = []
        for row in rows:
            keys = {'name', 'mac', 'table'} | ({'address'} if field == 'held_addresses' else set())
            allowed_keys = (keys, keys | {'management_ui'}) if field == 'interfaces' else (keys,)
            if (not isinstance(row, dict) or set(row) not in allowed_keys
                    or not isinstance(row['name'], str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', row['name'])
                    or not isinstance(row['mac'], str) or not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', row['mac'])
                    or type(row['table']) is not int or row['table'] not in {100, 200}):
                raise ValueError('source routing intent row is invalid')
            item = {key: row[key] for key in ('name', 'mac', 'table')}
            if 'management_ui' in row:
                if type(row['management_ui']) is not bool:
                    raise ValueError('source routing management eligibility is invalid')
                item['management_ui'] = row['management_ui']
            if 'address' in keys:
                item['address'] = str(ipaddress.ip_address(row['address']))
            checked.append(item)
        result[field] = checked
    return result


def source_evidence() -> dict[str, Any]:
    """Collect fixed service metadata and applied intent without application imports."""
    result = subprocess.run(
        ['systemctl', 'show', SERVICE, '--property=Id,LoadState,ActiveState,SubState,UnitFileState'],
        capture_output=True, text=True, timeout=10, check=False,
    )
    if len(result.stdout) > 4096:
        raise ValueError('source service metadata is oversized')
    fields = {}
    for line in result.stdout.splitlines():
        key, separator, value = line.partition('=')
        if separator and key in {'Id', 'LoadState', 'ActiveState', 'SubState', 'UnitFileState'}:
            if (key == 'Id' and value != SERVICE) or (key != 'Id' and not re.fullmatch(r'[a-z-]{0,40}', value)):
                raise ValueError('source service metadata is invalid')
            fields[key] = value
    if 'LoadState' not in fields:
        raise ValueError('source service metadata is incomplete')
    try:
        version = importlib.metadata.version('atlaso')
    except importlib.metadata.PackageNotFoundError:
        version = 'not-installed'
    if not re.fullmatch(r'[A-Za-z0-9.+_-]{1,80}', version):
        raise ValueError('source package version is invalid')
    return {'schema': 1, 'phase': 'before-lifecycle-deployment', 'package_version': version,
            'routing_service': fields, 'routing_intent': public_intent()}


def main() -> int:
    """Write one newly created public evidence file without replacing old output."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    evidence = source_evidence()
    descriptor = os.open(args.output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
        json.dump(evidence, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
