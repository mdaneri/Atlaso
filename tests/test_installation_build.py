"""Tests for installation input packaging and build-time RPM closure capture."""

from __future__ import annotations

import gzip
import io
import tarfile
from pathlib import Path

import pytest

from scripts import verify_virtualization_guest_wheel
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


def _mock_rpm_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    summary: str,
    *,
    key_names: tuple[str, ...] = ("VMWARE-RPM-GPG-KEY-test",),
    unsupported_keys: frozenset[str] = frozenset(),
    metadata_output: str = "ATLASO\tpython3\t3.14.1-1\tx86_64\n",
) -> tuple[Path, Path, Path, list[list[str]]]:
    """Create a minimal signed-RPM fixture and stub the shared runtime boundary.

    Args:
        tmp_path: Pytest-owned fixture directory.
        monkeypatch: Pytest fixture for replacing controlled dependencies.
        summary: Text returned from the mocked non-verbose rpmkeys command.
        key_names: Admitted Photon key basenames available to the verifier.
        unsupported_keys: Key basenames rejected by the host RPM import command.
        metadata_output: Text returned from the mocked RPM metadata query.
    """
    root = tmp_path / "rpms"
    root.mkdir()
    package = root / "python3-3.14.1-1.x86_64.rpm"
    package.write_bytes(b"fixture RPM bytes")
    source = tmp_path / "source"
    key_dir = source / "image/common/photon-rpm-gpg"
    key_dir.mkdir(parents=True)
    for key_name in key_names:
        (key_dir / key_name).write_text("public test key", encoding="utf-8")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    commands: list[list[str]] = []

    def run_runtime_tool(command: list[str]) -> str:
        commands.append(command)
        if command[0] == "rpm" and "--import" in command:
            if Path(command[-1]).name in unsupported_keys:
                raise SystemExit("unsupported RPM public key")
            return ""
        if command[0] == "rpmkeys":
            return summary
        if command[0] == "rpm" and "-qp" in command:
            return metadata_output
        return ""

    monkeypatch.setattr(verify_virtualization_guest_wheel, "_run_runtime_tool", run_runtime_tool)
    monkeypatch.setattr(verify_virtualization_guest_wheel, "_photon_repository_inventory", lambda: {})
    monkeypatch.setattr(
        verify_virtualization_guest_wheel,
        "_require_admitted_runtime_package",
        lambda *_args: None,
    )
    monkeypatch.setattr(build, "package_selection", lambda _source: ["python3"])
    return root, source, scratch, commands


def test_verify_rpms_accepts_signed_summary_without_verbose_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Require rpmkeys' signed summary format without the unstable verbose flag.

    Args:
        tmp_path: Pytest-owned fixture directory.
        monkeypatch: Pytest fixture for replacing controlled dependencies.
    """
    root, source, scratch, commands = _mock_rpm_verification(
        tmp_path, monkeypatch, "python3-3.14.1-1.x86_64.rpm: digests signatures OK"
    )

    records = build.verify_rpms(root, source, scratch)

    signature_commands = [command for command in commands if command[0] == "rpmkeys"]
    assert len(signature_commands) == 1
    assert signature_commands[0][3:] == [
        "--checksig",
        str(root / "python3-3.14.1-1.x86_64.rpm"),
    ]
    assert "--verbose" not in signature_commands[0]
    metadata_commands = [command for command in commands if command[0] == "rpm" and "-qp" in command]
    assert len(metadata_commands) == 1
    assert metadata_commands[0][metadata_commands[0].index("--dbpath") + 1] == signature_commands[0][2]
    assert records == [{
        "file": "python3-3.14.1-1.x86_64.rpm",
        "name": "python3",
        "version": "3.14.1-1",
        "architecture": "x86_64",
        "sha256": build.digest(root / "python3-3.14.1-1.x86_64.rpm"),
    }]


def test_verify_rpms_parses_tagged_metadata_after_diagnostic_lines(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ignore benign RPM diagnostics while parsing the explicit metadata row.

    Args:
        tmp_path: Pytest-owned fixture directory.
        monkeypatch: Pytest fixture for replacing controlled dependencies.
    """
    root, source, scratch, _commands = _mock_rpm_verification(
        tmp_path,
        monkeypatch,
        "python3-3.14.1-1.x86_64.rpm: digests signatures OK",
        metadata_output="warning: host RPM database warning\nATLASO\tpython3\t3.14.1-1\tx86_64\n",
    )

    records = build.verify_rpms(root, source, scratch)

    assert records[0]["name"] == "python3"
    assert records[0]["architecture"] == "x86_64"


@pytest.mark.parametrize(
    "metadata_output",
    [
        "warning: RPM query returned no package row\n",
        "ATLASO\tpython3\t3.14.1-1\tx86_64\nATLASO\tpython3\t3.14.1-1\tx86_64\n",
    ],
    ids=["missing-row", "duplicate-rows"],
)
def test_verify_rpms_rejects_missing_or_duplicate_tagged_metadata_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, metadata_output: str
) -> None:
    """RPM metadata parsing requires exactly one explicitly tagged row.

    Args:
        tmp_path: Pytest-owned fixture directory.
        monkeypatch: Pytest fixture for replacing controlled dependencies.
        metadata_output: Text returned from the mocked RPM metadata query.
    """
    root, source, scratch, _commands = _mock_rpm_verification(
        tmp_path,
        monkeypatch,
        "python3-3.14.1-1.x86_64.rpm: digests signatures OK",
        metadata_output=metadata_output,
    )

    with pytest.raises(ValueError, match="architecture is unsupported"):
        build.verify_rpms(root, source, scratch)


@pytest.mark.parametrize(
    "summary",
    [
        "python3-3.14.1-1.x86_64.rpm: digests OK",
        "python3-3.14.1-1.x86_64.rpm: NOKEY",
    ],
    ids=["digest-only", "missing-key"],
)
def test_verify_rpms_rejects_missing_signature_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, summary: str
) -> None:
    """Digest integrity without RPM signature success is not admitted.

    Args:
        tmp_path: Pytest-owned fixture directory.
        monkeypatch: Pytest fixture for replacing controlled dependencies.
        summary: Text returned from the mocked non-verbose rpmkeys command.
    """
    root, source, scratch, commands = _mock_rpm_verification(tmp_path, monkeypatch, summary)

    with pytest.raises(ValueError, match="not signed"):
        build.verify_rpms(root, source, scratch)

    signature_commands = [command for command in commands if command[0] == "rpmkeys"]
    assert len(signature_commands) == 1
    assert "--verbose" not in signature_commands[0]
    assert not any(command[0] == "rpm" and "-qp" in command for command in commands)


def test_verify_rpms_skips_unsupported_legacy_key_when_current_key_imports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A host may reject a legacy key while accepting the current admitted key.

    Args:
        tmp_path: Pytest-owned fixture directory.
        monkeypatch: Pytest fixture for replacing controlled dependencies.
    """
    names = ("VMWARE-RPM-GPG-KEY-legacy", "VMWARE-RPM-GPG-KEY-current")
    root, source, scratch, commands = _mock_rpm_verification(
        tmp_path,
        monkeypatch,
        "python3-3.14.1-1.x86_64.rpm: digests signatures OK",
        key_names=names,
        unsupported_keys=frozenset({names[0]}),
    )

    records = build.verify_rpms(root, source, scratch)

    imports = [command[-1] for command in commands if command[0] == "rpm" and "--import" in command]
    assert [Path(path).name for path in imports] == sorted(names)
    assert len(records) == 1
    assert len([command for command in commands if command[0] == "rpmkeys"]) == 1


def test_verify_rpms_rejects_when_no_admitted_key_imports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verification stops before package checks when every key is unsupported.

    Args:
        tmp_path: Pytest-owned fixture directory.
        monkeypatch: Pytest fixture for replacing controlled dependencies.
    """
    names = ("VMWARE-RPM-GPG-KEY-legacy", "VMWARE-RPM-GPG-KEY-current")
    root, source, scratch, commands = _mock_rpm_verification(
        tmp_path,
        monkeypatch,
        "python3-3.14.1-1.x86_64.rpm: digests signatures OK",
        key_names=names,
        unsupported_keys=frozenset(names),
    )

    with pytest.raises(ValueError, match="no admitted Photon RPM key is supported"):
        build.verify_rpms(root, source, scratch)

    assert len([command for command in commands if command[0] == "rpm" and "--import" in command]) == 2
    assert not any(command[0] == "rpmkeys" for command in commands)
    assert not any(command[0] == "rpm" and "-qp" in command for command in commands)


def test_verify_rpms_still_rejects_unsigned_package_with_supported_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A supported key does not weaken per-package signature verification.

    Args:
        tmp_path: Pytest-owned fixture directory.
        monkeypatch: Pytest fixture for replacing controlled dependencies.
    """
    names = ("VMWARE-RPM-GPG-KEY-legacy", "VMWARE-RPM-GPG-KEY-current")
    root, source, scratch, commands = _mock_rpm_verification(
        tmp_path,
        monkeypatch,
        "python3-3.14.1-1.x86_64.rpm: digests OK",
        key_names=names,
        unsupported_keys=frozenset({names[0]}),
    )

    with pytest.raises(ValueError, match="not signed"):
        build.verify_rpms(root, source, scratch)

    assert len([command for command in commands if command[0] == "rpm" and "--import" in command]) == 2
    assert len([command for command in commands if command[0] == "rpmkeys"]) == 1
    assert not any(command[0] == "rpm" and "-qp" in command for command in commands)
