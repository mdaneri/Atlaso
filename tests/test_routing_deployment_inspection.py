"""Verify installed bytes rather than treating wheel filenames as runtime proof."""

import zipfile

import pytest

from scripts.interop import routing_deployment_inspection as inspection


@pytest.mark.parametrize('fault', [None, 'modified', 'stale-module', 'wheel-traversal'])
def test_installed_payload_proves_wheel_bytes_and_no_stale_modules(tmp_path, monkeypatch, fault):
    """Installed payload differences and unsupported archive paths fail admission.

    Args:
        tmp_path: Owned validation subtree.
        monkeypatch: Supply Linux no-follow flag for ordinary Windows fixture files.
        fault: Deliberate artifact mismatch.
    """
    monkeypatch.setattr(inspection.os, 'O_NOFOLLOW', getattr(inspection.os, 'O_NOFOLLOW', 0), raising=False)
    payload = {'atlaso/__init__.py': b'__version__ = "0.9.367"\n',
               'atlaso/routes.py': b'route = "ordinary"\n',
               'atlaso-0.9.367.dist-info/METADATA': b'Name: atlaso\nVersion: 0.9.367\n'}
    installed = tmp_path / 'installed'
    for name, content in payload.items():
        target = installed / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    wheel = tmp_path / 'atlaso-0.9.367-py3-none-any.whl'
    with zipfile.ZipFile(wheel, 'w') as archive:
        for name, content in payload.items():
            archive.writestr(name, content)
        archive.writestr('atlaso-0.9.367.dist-info/RECORD', b'generated during installation')
        if fault == 'wheel-traversal':
            archive.writestr('../outside.py', b'refuse')
    if fault == 'modified':
        (installed / 'atlaso/routes.py').write_bytes(b'wrong runtime')
    elif fault == 'stale-module':
        (installed / 'atlaso/route_domains.py').write_bytes(b'stale old implementation')
    if fault:
        with pytest.raises(ValueError):
            inspection.installed_payload(wheel, installed)
    else:
        result = inspection.installed_payload(wheel, installed)
        assert result['verified_payload_files'] == len(payload)
        assert result['wheel_payload_sha256'] == result['installed_payload_sha256']
