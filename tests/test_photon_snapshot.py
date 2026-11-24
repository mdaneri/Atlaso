"""Exercise approved Photon snapshot admission and compatibility checks."""

import base64
import gzip
import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from scripts.installation import photon_preflight, photon_snapshot
from scripts.installation.manifest import canonical_json


def snapshot_bytes(captured_utc: str) -> bytes:
    """Build a bounded synthetic snapshot with every expected repository document.

    Args:
        captured_utc: Synthetic original capture timestamp in UTC.
    """
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
    """Reject a local snapshot whose bytes differ from the protected digest.

    Args:
        tmp_path: Fixture directory for the bounded snapshot.
        monkeypatch: Replace metadata parsing to isolate the digest boundary.
    """
    path = tmp_path / photon_snapshot.SNAPSHOT
    path.write_bytes(b"original snapshot")
    expected = hashlib.sha256(path.read_bytes()).hexdigest()
    monkeypatch.setattr(photon_snapshot, "read_snapshot", lambda content: set())
    photon_snapshot.read_pinned_snapshot(path, expected)

    path.write_bytes(b"changed snapshot")
    with pytest.raises(ValueError, match="differs from the admitted capture"):
        photon_snapshot.read_pinned_snapshot(path, expected)


def write_requirement_source(root: Path) -> None:
    """Create the minimal source files consumed by the capture fingerprint.

    Args:
        root: Fixture checkout containing just the relevant capture inputs.
    """
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
    """Ignore unrelated provisioning edits while tracking reviewed package identities.

    Args:
        tmp_path: Fixture checkout for independent provisioning and runtime edits.
    """
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


def test_preflight_reports_changes_to_canonical_capture_inputs(tmp_path):
    """Show a PR's package, installer pin, and input file changes."""
    base = tmp_path / "base"
    candidate = tmp_path / "candidate"
    write_requirement_source(base)
    write_requirement_source(candidate)

    unrelated = candidate / "scripts/installation/other.py"
    unrelated.write_text("# unrelated source file\n", encoding="utf-8")
    assert "no new capture requirement" in photon_preflight.summarize(base, candidate)

    provision = candidate / "image/common/scripts/provision-atlaso.sh"
    provision.write_text(
        provision.read_text(encoding="utf-8").replace("filesystem bash", "filesystem iputils traceroute"),
        encoding="utf-8",
    )
    (candidate / "image/common/powershell/powercli-lock.json").write_text('{"version":"9.1.2"}\n', encoding="utf-8")
    pin = candidate / "scripts/installation/content_inspection.py"
    pin.write_text('PHOTON_SYSTEMD_SHA256 = "' + "f" * 64 + '"\n', encoding="utf-8")

    report = photon_preflight.summarize(base, candidate)
    assert "Prepare a fresh capture unless one has already been approved" in report
    assert "Added packages: <code>iputils</code>, <code>traceroute</code>" in report
    assert "Removed packages: <code>bash</code>" in report
    assert "content_inspection.py / PHOTON_SYSTEMD_SHA256</code>" in report
    assert "Changed input files: <code>image/common/powershell/powercli-lock.json</code>" in report
    assert photon_snapshot.requirements_sha256(base) != photon_snapshot.requirements_sha256(candidate)



def test_preflight_detects_changed_fingerprint_definition(tmp_path):
    """Use the base's own fingerprint to detect a changed definition."""
    write_requirement_source(tmp_path)

    report = photon_preflight.summarize(tmp_path, tmp_path, base_fingerprint="0" * 64)

    assert "A compatible Photon capture is needed" in report
    assert "fingerprint definition also changed" in report


def test_preflight_failure_cannot_report_an_unchanged_fingerprint(tmp_path, monkeypatch, capsys):
    """Surface an unparseable baseline as a failed comparison."""
    base = tmp_path / "base"
    candidate = tmp_path / "candidate"
    write_requirement_source(base)
    write_requirement_source(candidate)
    (base / "scripts/installation/build.py").write_text("BASE_PACKAGES = {\n", encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["photon_preflight", "--base", str(base), "--candidate", str(candidate)])

    assert photon_preflight.main() == 1
    output = capsys.readouterr()
    assert "Unable to compare" in output.out
    assert "Unable to compare" in output.err
    assert "no new capture requirement" not in output.out
