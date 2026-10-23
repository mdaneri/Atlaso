"""Tests for installation input packaging and build-time RPM closure capture."""

from __future__ import annotations

import gzip
import io
import tarfile
from pathlib import Path

import pytest

from scripts.installation import build
from scripts.installation.manifest import MANIFEST


def _source(tmp_path: Path, package_line: str | None = None) -> Path:
    """Create a source-shaped fixture with the shared install package command.

Args:
    tmp_path: Temporary directory for this test's filesystem fixtures.
    package_line: Shared package-install command included in the fixture.
"""
    source = tmp_path / "source"
    script = source / "image/common/scripts/provision-atlaso.sh"
    script.parent.mkdir(parents=True)
    command = package_line or (
        'run_tdnf "Photon appliance package installation" \\\n  install python3 linux-api-headers $GUEST_INTEGRATION_PACKAGES linux-firmware'
    )
    script.write_text(command + "\n", encoding="utf-8")
    return source


def _archive(path: Path, entries: list[tuple[str, bytes, str]]) -> None:
    """Write a gzip tar archive with ordinary files or selected special entries.

Args:
    path: Path to the fixture or file being tested.
    entries: Archive entries to place in the fixture.
"""
    with path.open("wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as stream:
            for name, content, kind in entries:
                info = tarfile.TarInfo(name)
                if kind == "file":
                    info.size = len(content)
                    stream.addfile(info, io.BytesIO(content))
                elif kind == "symlink":
                    info.type = tarfile.SYMTYPE
                    info.linkname = "target"
                    stream.addfile(info)


def test_package_selection_reuses_shared_packages_and_adds_offline_boot_assets(tmp_path: Path) -> None:
    """
    Args:
        tmp_path: Temporary directory for this test's filesystem fixtures.
    """
    source = _source(tmp_path)

    packages = build.package_selection(source)

    assert {"python3", "linux-api-headers", "linux-firmware", "linux", "filesystem"} <= set(packages)
    assert "open-vm-tools" not in packages
    assert packages == sorted(set(packages))


@pytest.mark.parametrize(
    "text",
    [
        'run_tdnf "Photon appliance package installation" \\\n  install python3\nrun_tdnf "Photon appliance package installation" \\\n  install bash',
        'run_tdnf "Photon appliance package installation" \\\n  install python3;touch /tmp/owned',
        'run_tdnf "Photon appliance package installation" \\\n  install python3 $(curl https://example.invalid)',
        'run_tdnf "Photon appliance package installation" \\\n  install $GUEST_INTEGRATION_PACKAGES',
    ],
    ids=["ambiguous-command", "shell-separator", "command-substitution", "empty-package-list"],
)
def test_package_selection_rejects_ambiguous_or_nonliteral_shared_packages(tmp_path: Path, text: str) -> None:
    """
    Args:
        tmp_path: Temporary directory for this test's filesystem fixtures.
        text: Source text supplied to the package-selection parser.
    """
    with pytest.raises(ValueError, match="ambiguous|invalid"):
        build.package_selection(_source(tmp_path, text))


def test_pack_and_unpack_inputs_roundtrip_manifest_and_payload(tmp_path: Path) -> None:
    """
    Args:
        tmp_path: Temporary directory for this test's filesystem fixtures.
    """
    payload = tmp_path / "payload"
    payload.mkdir()
    (payload / MANIFEST).write_text('{"schema":1}\n', encoding="utf-8")
    (payload / "ordinary.txt").write_bytes(b"payload bytes\x00\n")
    packed = tmp_path / "inputs.tar.gz"
    destination = tmp_path / "unpacked"

    build.pack_inputs(payload, packed)
    build.unpack_inputs(packed, destination)

    assert (destination / MANIFEST).read_bytes() == (payload / MANIFEST).read_bytes()
    assert (destination / "ordinary.txt").read_bytes() == b"payload bytes\x00\n"


@pytest.mark.parametrize(
    "entries",
    [
        [("../escape", b"unsafe", "file")],
        [("/absolute", b"unsafe", "file")],
        [("C:/escape", b"unsafe", "file")],
        [("C:escape", b"unsafe", "file")],
        [("ordinary:stream", b"unsafe", "file")],
        [(".. /escape", b"unsafe", "file")],
        [("NUL.txt", b"unsafe", "file")],
        [("duplicate", b"first", "file"), ("duplicate", b"second", "file")],
        [("linked", b"", "symlink")],
    ],
    ids=["traversal", "absolute-path", "windows-absolute", "windows-drive-relative", "windows-stream", "windows-normalization", "windows-device", "duplicate-name", "symlink"],
)
def test_unpack_inputs_rejects_unsafe_archive_before_creating_destination(
    tmp_path: Path, entries: list[tuple[str, bytes, str]]
) -> None:
    """
    Args:
        tmp_path: Temporary directory for this test's filesystem fixtures.
        entries: Archive entries to place in the fixture.
    """
    archive = tmp_path / "bad.tar.gz"
    destination = tmp_path / "must-not-exist"
    _archive(archive, entries)

    with pytest.raises(ValueError):
        build.unpack_inputs(archive, destination)

    assert not destination.exists()


def test_unpack_inputs_rejects_expansion_bound_before_creating_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    Args:
        tmp_path: Temporary directory for this test's filesystem fixtures.
        monkeypatch: Pytest fixture for replacing controlled dependencies.
    """
    archive = tmp_path / "large.tar.gz"
    _archive(archive, [("large", b"x", "file")])
    destination = tmp_path / "must-not-exist"

    class LargeMember:
        name = "large"
        size = 16 * 1024**3 + 1

        @staticmethod
        def isfile() -> bool:
            return True

    class ArchiveStub:
        def __enter__(self) -> "ArchiveStub":
            return self

        def __exit__(self, *_args: object) -> None:
            """
            Args:
                *_args: Additional positional arguments supplied to the test double.
            """
            return None

        def __iter__(self):
            return iter([LargeMember()])

    monkeypatch.setattr(build.tarfile, "open", lambda *_args, **_kwargs: ArchiveStub())

    with pytest.raises(ValueError, match="capacity admission"):
        build.unpack_inputs(archive, destination)

    assert not destination.exists()


def test_unpack_inputs_rejects_capacity_and_destination_collisions_preflight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    Args:
        tmp_path: Temporary directory for this test's filesystem fixtures.
        monkeypatch: Pytest fixture for replacing controlled dependencies.
    """
    archive = tmp_path / "candidate.tar.gz"
    _archive(archive, [("one", b"payload", "file")])
    destination = tmp_path / "capacity-denied"
    monkeypatch.setattr(build.shutil, "disk_usage", lambda _path: type("Usage", (), {"free": 1})())

    with pytest.raises(ValueError, match="capacity admission"):
        build.unpack_inputs(archive, destination)
    assert not destination.exists()

    occupied = tmp_path / "occupied"
    occupied.mkdir()
    with pytest.raises(ValueError, match="destination must be absent"):
        build.unpack_inputs(archive, occupied)


def test_pack_inputs_rejects_existing_output_without_replacing_it(tmp_path: Path) -> None:
    """
    Args:
        tmp_path: Temporary directory for this test's filesystem fixtures.
    """
    payload = tmp_path / "payload"
    payload.mkdir()
    (payload / MANIFEST).write_text("{}", encoding="utf-8")
    output = tmp_path / "existing.tar.gz"
    output.write_bytes(b"preserve")

    with pytest.raises(FileExistsError):
        build.pack_inputs(payload, output)

    assert output.read_bytes() == b"preserve"


def test_capture_packages_uses_current_closure_without_install_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    Args:
        tmp_path: Temporary directory for this test's filesystem fixtures.
        monkeypatch: Pytest fixture for replacing controlled dependencies.
    """
    repository = _source(tmp_path)
    output = tmp_path / "rpms"
    commands: list[list[str]] = []
    packages = build.package_selection(repository)

    def run(command: list[str], *, check: bool) -> None:
        """
        Args:
            command: Subprocess argument vector received by the test double.
            check: Whether the caller requested subprocess failure checking.
        """
        assert check is True
        commands.append(command)
        if "--downloadonly" in command:
            output.joinpath("linux.rpm").write_bytes(b"rpm")

    monkeypatch.setattr(build.subprocess, "run", run)

    build.capture_packages(repository, output)

    assert len(commands) == 2
    assert "configure_photon_repositories.py" in commands[0][1]
    tdnf = commands[1]
    assert tdnf[tdnf.index("--") + 1] == "tdnf"
    assert "--downloadonly" in tdnf and "--alldeps" in tdnf
    assert "install" in tdnf
    assert not {"--installroot", "--root", "--releasever"} & set(tdnf)
    assert set(tdnf[-len(packages) :]) == set(packages)


def _rpm_repository(tmp_path: Path) -> tuple[Path, Path]:
    """
    Args:
        tmp_path: Temporary directory for this test's filesystem fixtures.
    """
    rpms = tmp_path / "rpms"
    scratch = tmp_path / "scratch"
    rpms.mkdir()
    scratch.mkdir()
    (rpms / "package.rpm").write_bytes(b"signed RPM payload")
    (scratch / "rpmdb").mkdir()
    (scratch / "rpmdb" / "Packages").write_bytes(b"validation database")
    return rpms, scratch


def _mock_createrepo(monkeypatch: pytest.MonkeyPatch, *, metadata: bytes = b"fresh metadata") -> list[list[str]]:
    """
    Args:
        monkeypatch: Pytest fixture for replacing controlled dependencies.
        metadata: Generated repository metadata emitted by the test double.
    """
    calls: list[list[str]] = []

    def run(command: list[str], *, check: bool) -> None:
        """
        Args:
            command: Subprocess argument vector received by the test double.
            check: Whether the caller requested subprocess failure checking.
        """
        assert check is True
        calls.append(command)
        output = Path(command[command.index("--outputdir") + 1])
        assert not output.exists()
        generated_metadata = output / "repodata"
        generated_metadata.mkdir(parents=True)
        (generated_metadata / "repomd.xml").write_bytes(metadata)

    monkeypatch.setattr(build.subprocess, "run", run)
    return calls


def test_rebuild_repository_replaces_candidate_metadata_and_keeps_rpmdb(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    Args:
        tmp_path: Temporary directory for this test's filesystem fixtures.
        monkeypatch: Pytest fixture for replacing controlled dependencies.
    """
    rpms, scratch = _rpm_repository(tmp_path)
    old = rpms / "repodata"
    old.mkdir()
    (old / "repomd.xml").write_bytes(b"untrusted metadata")
    calls = _mock_createrepo(monkeypatch)

    build.rebuild_repository(rpms, scratch)

    assert calls == [[
        "createrepo_c", "--checksum", "sha256", "--outputdir", str((scratch / "rpm-metadata").absolute()),
        str(rpms.absolute()),
    ]]
    assert (scratch / "untrusted-rpm-metadata/repomd.xml").read_bytes() == b"untrusted metadata"
    assert (rpms / "repodata/repomd.xml").read_bytes() == b"fresh metadata"
    assert (scratch / "rpmdb/Packages").read_bytes() == b"validation database"


def test_rebuild_repository_accepts_missing_old_metadata(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Args:
        tmp_path: Temporary directory for this test's filesystem fixtures.
        monkeypatch: Pytest fixture for replacing controlled dependencies.
    """
    rpms, scratch = _rpm_repository(tmp_path)
    calls = _mock_createrepo(monkeypatch)

    build.rebuild_repository(rpms, scratch)

    assert len(calls) == 1
    assert (rpms / "repodata/repomd.xml").read_bytes() == b"fresh metadata"
    assert not (scratch / "untrusted-rpm-metadata").exists()


def test_rebuild_repository_rejects_extra_createrepo_output_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    Args:
        tmp_path: Temporary directory for this test's filesystem fixtures.
        monkeypatch: Pytest fixture for replacing controlled dependencies.
    """
    rpms, scratch = _rpm_repository(tmp_path)
    calls = _mock_createrepo(monkeypatch)
    original_run = build.subprocess.run

    def run_with_extra_entry(command: list[str], *, check: bool) -> None:
        """
        Args:
            command: Subprocess argument vector received by the test double.
            check: Whether the caller requested subprocess failure checking.
        """
        original_run(command, check=check)
        (Path(command[command.index("--outputdir") + 1]) / "unexpected.txt").write_bytes(b"extra")

    monkeypatch.setattr(build.subprocess, "run", run_with_extra_entry)

    with pytest.raises(ValueError, match="only an ordinary repodata directory"):
        build.rebuild_repository(rpms, scratch)

    assert len(calls) == 1
    assert not (rpms / "repodata").exists()


@pytest.mark.parametrize("collision", ["rpm-metadata", "untrusted-rpm-metadata"])
def test_rebuild_repository_rejects_scratch_collisions_before_moving_old_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, collision: str
) -> None:
    """
    Args:
        tmp_path: Temporary directory for this test's filesystem fixtures.
        monkeypatch: Pytest fixture for replacing controlled dependencies.
        collision: Filesystem entry that should collide with the rebuild operation.
    """
    rpms, scratch = _rpm_repository(tmp_path)
    old = rpms / "repodata"
    old.mkdir()
    (old / "repomd.xml").write_bytes(b"preserve")
    (scratch / collision).mkdir()
    monkeypatch.setattr(build.subprocess, "run", lambda *_args, **_kwargs: pytest.fail("generator should not run"))

    with pytest.raises(ValueError, match="must be absent"):
        build.rebuild_repository(rpms, scratch)

    assert (old / "repomd.xml").read_bytes() == b"preserve"
    assert not (scratch / "untrusted-rpm-metadata/repomd.xml").exists()


def test_rebuild_repository_rejects_non_directory_repodata_without_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    Args:
        tmp_path: Temporary directory for this test's filesystem fixtures.
        monkeypatch: Pytest fixture for replacing controlled dependencies.
    """
    rpms, scratch = _rpm_repository(tmp_path)
    old = rpms / "repodata"
    old.write_bytes(b"ambiguous metadata")
    monkeypatch.setattr(build.subprocess, "run", lambda *_args, **_kwargs: pytest.fail("generator should not run"))

    with pytest.raises(ValueError, match="ordinary directory"):
        build.rebuild_repository(rpms, scratch)

    assert old.read_bytes() == b"ambiguous metadata"


def test_rebuild_repository_preserves_untrusted_metadata_if_generation_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    Args:
        tmp_path: Temporary directory for this test's filesystem fixtures.
        monkeypatch: Pytest fixture for replacing controlled dependencies.
    """
    rpms, scratch = _rpm_repository(tmp_path)
    old = rpms / "repodata"
    old.mkdir()
    (old / "repomd.xml").write_bytes(b"old metadata")

    def fail(*_args: object, **_kwargs: object) -> None:
        """
        Args:
            *_args: Additional positional arguments supplied to the test double.
            **_kwargs: Additional keyword arguments supplied to the test double.
        """
        raise build.subprocess.CalledProcessError(1, "createrepo_c")

    monkeypatch.setattr(build.subprocess, "run", fail)

    with pytest.raises(build.subprocess.CalledProcessError):
        build.rebuild_repository(rpms, scratch)

    assert (scratch / "untrusted-rpm-metadata/repomd.xml").read_bytes() == b"old metadata"
    assert not old.exists()


def test_rebuild_repository_rejects_symlinked_input_before_moving_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    Args:
        tmp_path: Temporary directory for this test's filesystem fixtures.
        monkeypatch: Pytest fixture for replacing controlled dependencies.
    """
    rpms, scratch = _rpm_repository(tmp_path)
    old = rpms / "repodata"
    old.mkdir()
    (old / "repomd.xml").write_bytes(b"preserve")
    try:
        (rpms / "linked").symlink_to(rpms / "package.rpm")
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable")
    monkeypatch.setattr(build.subprocess, "run", lambda *_args, **_kwargs: pytest.fail("generator should not run"))

    with pytest.raises(ValueError, match="link"):
        build.rebuild_repository(rpms, scratch)

    assert (old / "repomd.xml").read_bytes() == b"preserve"
    assert not (scratch / "untrusted-rpm-metadata").exists()
