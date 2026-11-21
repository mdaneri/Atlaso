"""Exercise approved Photon snapshot admission and compatibility checks."""

import base64
import gzip
import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from scripts.installation import photon_snapshot
from scripts.installation.manifest import canonical_json


def snapshot_bytes(captured_utc: str) -> bytes:
    """Build a bounded synthetic snapshot with every expected repository document."""
    primary = b"""<metadata xmlns="http://linux.duke.edu/metadata/common">
        <package><name>bash</name><arch>x86_64</arch>
        <version epoch="0" ver="5.2.37" rel="1.ph5"/>
        <checksum type="sha256">""" + b"a" * 64 + b"""</checksum></package></metadata>"""
    compressed = gzip.compress(primary, mtime=0)
    repomd = f"""<repomd xmlns="http://linux.duke.edu/metadata/repo">
        <data type="primary">
        <location href="repodata/primary.xml.gz"/>
        <checksum type="sha256">{hashlib.sha256(compressed).hexdigest()}</checksum>
        <open-checksum type="sha256">{hashlib.sha256(primary).hexdigest()}</open-checksum>
        <open-size>{len(primary)}</open-size>
        </data></repomd>""".encode()
    documents = {
        repository + name: base64.b64encode(content).decode("ascii")
        for repository in photon_snapshot.PHOTON_REPOSITORY_URLS
        for name, content in (
            ("repodata/repomd.xml", repomd),
            ("repodata/primary.xml.gz", compressed),
        )
    }
    return canonical_json(
        {"schema": 1, "captured_utc": captured_utc, "documents": documents}
    )


def test_snapshot_membership_matches_captured_rpm_hashes():
    """Bind captured RPMs to exact package identities present in snapshot metadata."""
    rpm = ("bash", "0", "5.2.37", "1.ph5", "x86_64", "a" * 64)
    now = datetime(2026, 11, 20, tzinfo=UTC)
    snapshot = snapshot_bytes((now - timedelta(days=1)).isoformat())

    packages = photon_snapshot.read_snapshot(snapshot, now=now)
    captured = photon_snapshot.captured_packages(
        packages,
        [
            {"path": "bash-5.2.37-1.ph5.x86_64.rpm", "sha256": "a" * 64},
            {
                "path": "guest-tools/qemu/atlaso-qemu-guest-agent-1.0.0.rpm",
                "sha256": "b" * 64,
            },
        ],
    )

    assert captured == {rpm}
    with pytest.raises(ValueError, match="does not cover"):
        photon_snapshot.captured_packages(
            packages,
            [{"path": "bash-5.2.37-1.ph5.x86_64.rpm", "sha256": "c" * 64}],
        )


def test_snapshot_expires_at_30_days():
    """Accept recent captures and refuse captures at the 30-day boundary."""
    now = datetime(2026, 11, 20, tzinfo=UTC)

    assert photon_snapshot.read_snapshot(
        snapshot_bytes((now - timedelta(days=29)).isoformat()), now=now
    )
    with pytest.raises(ValueError, match="expired"):
        photon_snapshot.read_snapshot(
            snapshot_bytes((now - timedelta(days=30)).isoformat()), now=now
        )


def test_snapshot_file_must_match_the_protected_digest_pin(tmp_path, monkeypatch):
    """Reject a local snapshot whose bytes differ from the protected digest."""
    path = tmp_path / photon_snapshot.SNAPSHOT
    path.write_bytes(b"original snapshot")
    expected = hashlib.sha256(path.read_bytes()).hexdigest()
    monkeypatch.setattr(photon_snapshot, "read_snapshot", lambda content: set())
    photon_snapshot.read_pinned_snapshot(path, expected)

    path.write_bytes(b"changed snapshot")
    with pytest.raises(ValueError, match="differs from the admitted capture"):
        photon_snapshot.read_pinned_snapshot(path, expected)


def write_requirement_source(root: Path) -> None:
    """Create the minimal source files consumed by the capture fingerprint."""
    contents = {
        "image/common/powershell/powercli-lock.json": "{}\n",
        "image/common/scripts/build-qemu-guest-agent-rpm.sh": "build\n",
        "image/common/guest-agents/atlaso-qemu-guest-agent.spec": "spec\n",
        "image/common/guest-agents/qemu-guest-agent.service": "unit\n",
        "scripts/installation/guest_tools.py": "profiles = {}\n",
        "scripts/installation/content_inspection.py": 'PHOTON_SYSTEMD_SHA256 = "' + "d" * 64 + '"\n',
        "scripts/installation/manifest.py": 'SOURCE_ISO_SHA512 = "' + "e" * 128 + '"\n',
        "scripts/installation/build.py": 'BASE_PACKAGES = {"filesystem"}\n',
        "image/common/scripts/provision-atlaso.sh": (
            'run_tdnf "Photon appliance package installation" \\\n  install filesystem bash\n'
        ),
        "image/common/photon-rpm-gpg/VMWARE-RPM-GPG-KEY": "public key\n",
    }
    for name, content in contents.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def test_capture_fingerprint_tracks_requirements_and_reviewed_rpm_pins(tmp_path):
    """Ignore unrelated provisioning edits while tracking reviewed package identities."""
    write_requirement_source(tmp_path)

    baseline = photon_snapshot.requirements_sha256(tmp_path)
    provisioning = tmp_path / "image/common/scripts/provision-atlaso.sh"
    provisioning.write_text(
        provisioning.read_text(encoding="utf-8") + "# unrelated service configuration\n",
        encoding="utf-8",
    )
    assert photon_snapshot.requirements_sha256(tmp_path) == baseline

    profile = tmp_path / "scripts/installation/content_inspection.py"
    profile.write_text('PHOTON_SYSTEMD_SHA256 = "' + "f" * 64 + '"\n', encoding="utf-8")
    assert photon_snapshot.requirements_sha256(tmp_path) != baseline
