"""Test Photon package cleanup runtime verification."""

from __future__ import annotations

import hashlib
import importlib.util
import os
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


def load_verifier():
    """Load the image-time Photon package-state verifier."""

    path = Path("image/common/scripts/verify-photon-package-state.py")
    spec = importlib.util.spec_from_file_location("verify_photon_package_state", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["verify_photon_package_state"] = module
    spec.loader.exec_module(module)
    return module


def write_release_state(root: Path) -> tuple[Path, Path, Path]:
    """Write one valid isolated Photon release and TDNF configuration.

    Args:
        root: Temporary filesystem root for the release files.
    """

    etc = root / "etc"
    (etc / "tdnf").mkdir(parents=True)
    os_release = etc / "os-release"
    photon_release = etc / "photon-release"
    tdnf_config = etc / "tdnf" / "tdnf.conf"
    os_release.write_text(
        'NAME="VMware Photon OS"\nID=photon\nVERSION_ID="5.0"\n',
        encoding="utf-8",
    )
    photon_release.write_text(
        "VMware Photon OS 5.0\nPHOTON_BUILD_NUMBER=isolated-test\n",
        encoding="utf-8",
    )
    tdnf_config.write_text(
        "[main]\nclean_requirements_on_remove=1\n"
        "distroverpkg=photon-release-5.0-6.ph5.noarch\n",
        encoding="utf-8",
    )
    return os_release, photon_release, tdnf_config


def test_package_cleanup_transaction_preserves_runtime_with_noautoremove(
    tmp_path: Path,
) -> None:
    """Execute an isolated package transaction and retain the runtime closure.

    Args:
        tmp_path: Temporary filesystem root for the package transaction.
    """

    verifier = load_verifier()
    os_release, photon_release, tdnf_config = write_release_state(tmp_path)
    installed = {
        "photon-release-5.0-6.ph5.noarch",
        "photon-release",
        "rpm",
        "tdnf",
        "python3",
        "powershell",
        "ntpsec",
        "python3-ntp",
        "open-vm-tools",
        "rpm-build",
        "glib-devel",
        "systemd-devel",
        "pkg-config",
    }

    def remove_build_packages(*, noautoremove: bool) -> None:
        """Remove the simulated build closure.

        Args:
            noautoremove: Whether to preserve runtime dependency packages.
        """
        installed.difference_update(
            {"rpm-build", "glib-devel", "systemd-devel", "pkg-config"}
        )
        if not noautoremove:
            installed.difference_update({"rpm", "tdnf", "photon-release"})
            os_release.unlink()
            photon_release.unlink()

    def fake_rpm(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        """Return simulated RPM query results.

        Args:
            command: RPM command and queried package identity.
            **_: Unused subprocess keyword arguments.
        """
        package = command[-1]
        return subprocess.CompletedProcess(
            command,
            0 if package in installed else 1,
            stdout=f"{package}\n" if package in installed else "",
            stderr="" if package in installed else "not installed\n",
        )

    remove_build_packages(noautoremove=True)
    distroverpkg = verifier.verify_photon_package_state(
        os_release_path=os_release,
        photon_release_path=photon_release,
        tdnf_config_path=tdnf_config,
        guest_platform="vmware",
        image_root=tmp_path,
        runner=fake_rpm,
    )
    assert distroverpkg == "photon-release-5.0-6.ph5.noarch"
    assert not {"rpm-build", "glib-devel", "systemd-devel", "pkg-config"} & installed


@pytest.mark.parametrize("missing_package", ["ntpsec", "python3-ntp"])
def test_package_cleanup_rejects_missing_ntpsec_runtime(
    tmp_path: Path, missing_package: str
) -> None:
    """Reject an image that lost either required NTPsec runtime package.

    Args:
        tmp_path: Temporary filesystem root for the package transaction.
        missing_package: Required NTPsec package omitted from the image.
    """

    verifier = load_verifier()
    os_release, photon_release, tdnf_config = write_release_state(tmp_path)
    installed = {
        "photon-release-5.0-6.ph5.noarch",
        "photon-release",
        "rpm",
        "tdnf",
        "python3",
        "powershell",
        "ntpsec",
        "python3-ntp",
        "open-vm-tools",
    }
    installed.remove(missing_package)

    def fake_rpm(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        """Return simulated RPM query results.

        Args:
            command: RPM command and queried package identity.
            **_: Unused subprocess keyword arguments.
        """
        package = command[-1]
        return subprocess.CompletedProcess(
            command,
            0 if package in installed else 1,
            stdout=f"{package}\n" if package in installed else "",
            stderr="" if package in installed else "not installed\n",
        )

    with pytest.raises(
        ValueError,
        match=f"Required Photon runtime package is not installed: {missing_package}",
    ):
        verifier.verify_photon_package_state(
            os_release_path=os_release,
            photon_release_path=photon_release,
            tdnf_config_path=tdnf_config,
            guest_platform="vmware",
            image_root=tmp_path,
            runner=fake_rpm,
        )


def test_package_cleanup_rejects_installed_cloud_init(tmp_path: Path) -> None:
    """Reject an image that retains the unsupported cloud-init lifecycle.

    Args:
        tmp_path: Temporary filesystem root for the package transaction.
    """

    verifier = load_verifier()
    os_release, photon_release, tdnf_config = write_release_state(tmp_path)
    installed = {
        "photon-release-5.0-6.ph5.noarch",
        "photon-release",
        "rpm",
        "tdnf",
        "python3",
        "powershell",
        "ntpsec",
        "python3-ntp",
        "open-vm-tools",
        "cloud-init",
    }

    def fake_rpm(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        """Return simulated RPM query results.

        Args:
            command: RPM command and queried package identity.
            **_: Unused subprocess keyword arguments.
        """

        package = command[-1]
        return subprocess.CompletedProcess(command, 0 if package in installed else 1)

    with pytest.raises(
        ValueError,
        match="Unsupported Photon runtime package is installed: cloud-init",
    ):
        verifier.verify_photon_package_state(
            os_release_path=os_release,
            photon_release_path=photon_release,
            tdnf_config_path=tdnf_config,
            guest_platform="vmware",
            image_root=tmp_path,
            runner=fake_rpm,
        )


@pytest.mark.parametrize(
    "relative_path",
    (
        "usr/lib/systemd/system-generators/cloud-init-generator",
        "usr/lib/systemd/system/cloud-config.service",
    ),
)
def test_package_cleanup_rejects_cloud_init_runtime_path(
    tmp_path: Path, relative_path: str
) -> None:
    """Reject a stale cloud-init runtime path after package removal.

    Args:
        tmp_path: Temporary filesystem root for the simulated runtime path.
        relative_path: Unsupported path retained beneath the image root.
    """

    verifier = load_verifier()
    os_release, photon_release, tdnf_config = write_release_state(tmp_path)
    runtime_path = tmp_path / relative_path
    runtime_path.parent.mkdir(parents=True)
    runtime_path.write_text("stale", encoding="utf-8")
    installed = {
        "photon-release-5.0-6.ph5.noarch",
        "photon-release",
        "rpm",
        "tdnf",
        "python3",
        "powershell",
        "ntpsec",
        "python3-ntp",
        "open-vm-tools",
    }

    def fake_rpm(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        """Return simulated RPM query results.

        Args:
            command: RPM command and queried package identity.
            **_: Unused subprocess keyword arguments.
        """

        package = command[-1]
        return subprocess.CompletedProcess(command, 0 if package in installed else 1)

    with pytest.raises(ValueError, match="cloud-init runtime path remains"):
        verifier.verify_photon_package_state(
            os_release_path=os_release,
            photon_release_path=photon_release,
            tdnf_config_path=tdnf_config,
            guest_platform="vmware",
            image_root=tmp_path,
            runner=fake_rpm,
        )


def test_package_cleanup_rejects_dangling_cloud_init_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reject a dangling symlink at a forbidden cloud-init runtime path.

    Args:
        tmp_path: Temporary filesystem root for the simulated runtime path.
        monkeypatch: Pytest helper used to simulate link-aware metadata.
    """

    verifier = load_verifier()
    runtime_path = tmp_path / "usr/lib/cloud-init"
    original_lstat = Path.lstat

    def fake_lstat(path: Path):
        """Report the forbidden path as a dangling link directory entry.

        Args:
            path: Filesystem path inspected by the verifier.
        """

        if path == runtime_path:
            return original_lstat(tmp_path)
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", fake_lstat)

    with pytest.raises(ValueError, match="cloud-init runtime path remains"):
        verifier.verify_paths_absent((runtime_path,))


def test_package_cleanup_transaction_rejects_autoremoved_release_identity(
    tmp_path: Path,
) -> None:
    """Reject the regression produced by Photon's automatic dependency removal.

    Args:
        tmp_path: Temporary filesystem root for the regressed release state.
    """

    verifier = load_verifier()
    os_release, photon_release, tdnf_config = write_release_state(tmp_path)
    os_release.unlink()
    photon_release.unlink()

    with pytest.raises(ValueError, match="release identity file is missing or empty"):
        verifier.verify_photon_package_state(
            os_release_path=os_release,
            photon_release_path=photon_release,
            tdnf_config_path=tdnf_config,
            guest_platform="vmware",
            image_root=tmp_path,
        )


@pytest.mark.parametrize(
    ("config", "expected"),
    [
        ("[main]\n", "photon-release"),
        (
            "[main]\ndistroverpkg=photon-release-5.0-6.ph5.noarch\n",
            "photon-release-5.0-6.ph5.noarch",
        ),
    ],
)
def test_package_cleanup_resolves_effective_distroverpkg(
    tmp_path: Path, config: str, expected: str
) -> None:
    """Resolve an explicit package or Photon's shipped default.

    Args:
        tmp_path: Temporary filesystem root for the TDNF configuration.
        config: TDNF configuration content to inspect.
        expected: Expected effective distro version package.
    """

    verifier = load_verifier()
    _, _, tdnf_config = write_release_state(tmp_path)
    tdnf_config.write_text(config, encoding="utf-8")

    assert verifier.read_distroverpkg(tdnf_config) == expected


def test_package_cleanup_rejects_unsafe_distroverpkg(tmp_path: Path) -> None:
    """Reject an explicit package identity that cannot be queried safely.

    Args:
        tmp_path: Temporary filesystem root for the unsafe configuration.
    """

    verifier = load_verifier()
    _, _, tdnf_config = write_release_state(tmp_path)
    tdnf_config.write_text("[main]\ndistroverpkg=../../unsafe\n", encoding="utf-8")

    with pytest.raises(ValueError, match="not a valid RPM package identity"):
        verifier.read_distroverpkg(tdnf_config)


_FILESYSTEM_SHA256 = "7f5bba3e84f6eb50f6e5e311325089bc642549469d83793e0ba5f40d74ec6024"
_UTMP_GID = 22


def _mountinfo(
    *,
    proc_type: str = "proc",
    proc_root: str = "/",
    run_type: str = "tmpfs",
    run_root: str = "/",
    duplicate_proc: bool = False,
    duplicate_run: bool = False,
) -> str:
    """Build a small public mountinfo sample for the two protected mounts.

    Args:
        proc_type: Filesystem type for the simulated proc mount.
        proc_root: Mount root for the simulated proc mount.
        run_type: Filesystem type for the simulated run mount.
        run_root: Mount root for the simulated run mount.
        duplicate_proc: Whether to include a duplicate proc mount.
        duplicate_run: Whether to include a duplicate run mount.
    """
    proc = f"31 25 0:26 {proc_root} /proc rw,nosuid,nodev,noexec - {proc_type} proc rw\n"
    run = f"32 25 0:27 {run_root} /run rw,nosuid,nodev - {run_type} tmpfs rw\n"
    return proc * (2 if duplicate_proc else 1) + run * (2 if duplicate_run else 1)


def _runtime_paths() -> dict[str, SimpleNamespace]:
    """Return valid synthetic metadata for the required Photon runtime paths."""
    return {
        "/proc": SimpleNamespace(st_mode=stat.S_IFDIR | 0o555, st_uid=0, st_gid=0, st_nlink=2),
        "/run": SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0, st_nlink=2),
        "/var/log/btmp": SimpleNamespace(st_mode=stat.S_IFREG | 0o660, st_uid=0, st_gid=_UTMP_GID, st_nlink=1),
        "/var/log/wtmp": SimpleNamespace(st_mode=stat.S_IFREG | 0o664, st_uid=0, st_gid=_UTMP_GID, st_nlink=1),
        "/var/mail": SimpleNamespace(st_mode=stat.S_IFDIR | 0o1755, st_uid=0, st_gid=34, st_nlink=2),
    }


def _runtime_verifier(monkeypatch, mountinfo: str, paths: dict[str, SimpleNamespace]):
    """Load the package verifier with isolated mount, metadata, and group reads.

    Args:
        monkeypatch: Pytest fixture for replacing controlled dependencies.
        mountinfo: Synthetic mountinfo content to provide to the verifier.
        paths: Synthetic lstat results for protected runtime paths.
    """
    group_queries = []

    def getgrnam(name: str):
        """Record the group lookup made by the runtime metadata check.

        Args:
            name: Public package or parameter name used by the helper.
        """
        group_queries.append(name)
        if name != "utmp":
            raise KeyError(name)
        return SimpleNamespace(gr_gid=_UTMP_GID)

    monkeypatch.setitem(sys.modules, "grp", SimpleNamespace(getgrnam=getgrnam))
    verifier = load_verifier()
    mount_reads = []

    def read_mountinfo(path=Path("/proc/self/mountinfo")):
        """Provide the synthetic mount table to the runtime metadata check.

        Args:
            path: Filesystem path used by the isolated fixture.
        """
        mount_reads.append(path)
        return mountinfo

    def fake_lstat(path: Path):
        """Return metadata only for paths in the isolated fixture.

        Args:
            path: Filesystem path used by the isolated fixture.
        """
        entry = paths.get(path.as_posix())
        if entry is None:
            raise AssertionError(f"unexpected metadata path: {path}")
        return entry

    monkeypatch.setattr(verifier, "_read_installation_mountinfo", read_mountinfo)
    monkeypatch.setattr(Path, "lstat", fake_lstat)
    return verifier, mount_reads, group_queries


def test_installation_runtime_metadata_accepts_exact_photon_state(monkeypatch):
    """Accept the expected proc/run mounts and protected login/mail metadata.

    Args:
        monkeypatch: Pytest fixture for replacing controlled dependencies.
    """
    paths = _runtime_paths()
    verifier, mount_reads, group_queries = _runtime_verifier(
        monkeypatch, _mountinfo(), paths
    )

    result = verifier.verify_installation_runtime_metadata(_FILESYSTEM_SHA256)

    assert result == {
        "runtime_proc_verified": True,
        "runtime_run_verified": True,
        "runtime_login_metadata_verified": True,
        "runtime_mail_spool_verified": True,
    }
    assert mount_reads == [Path("/proc/self/mountinfo")]
    assert group_queries == ["utmp"]


@pytest.mark.parametrize(
    "mutation",
    [
        "proc-type",
        "malformed-table",
        "proc-root",
        "duplicate-proc",
        "run-type",
        "run-root",
        "duplicate-run",
        "proc-mode",
        "proc-owner",
        "run-mode",
        "run-group",
        "btmp-mode",
        "btmp-owner",
        "btmp-group",
        "btmp-symlink",
        "btmp-hardlink",
        "wtmp-mode",
        "wtmp-owner",
        "wtmp-group",
        "wtmp-symlink",
        "wtmp-hardlink",
        "mail-mode",
        "mail-owner",
        "mail-group",
        "mail-symlink",
    ],
)
def test_installation_runtime_metadata_rejects_mount_and_path_drift(
    monkeypatch, mutation: str
):
    """Reject mount topology, type, ownership, group, link, and mode defects.

    Args:
        monkeypatch: Pytest fixture for replacing controlled dependencies.
        mutation: Runtime metadata change to reject.
    """
    paths = _runtime_paths()
    mountinfo = _mountinfo()
    if mutation == "malformed-table":
        mountinfo = "private-fixture-malformed\n"
    elif mutation == "proc-type":
        mountinfo = _mountinfo(proc_type="tmpfs")
    elif mutation == "proc-root":
        mountinfo = _mountinfo(proc_root="/subtree")
    elif mutation == "duplicate-proc":
        mountinfo = _mountinfo(duplicate_proc=True)
    elif mutation == "run-type":
        mountinfo = _mountinfo(run_type="proc")
    elif mutation == "run-root":
        mountinfo = _mountinfo(run_root="/subtree")
    elif mutation == "duplicate-run":
        mountinfo = _mountinfo(duplicate_run=True)
    else:
        path_name, defect = mutation.split("-", 1)
        path = {"btmp": "/var/log/btmp", "wtmp": "/var/log/wtmp", "mail": "/var/mail", "proc": "/proc", "run": "/run"}[path_name]
        current = paths[path]
        if defect == "mode":
            replacement = {"proc": stat.S_IFDIR | 0o755, "run": stat.S_IFDIR | 0o700, "btmp": stat.S_IFREG | 0o600, "wtmp": stat.S_IFREG | 0o600, "mail": stat.S_IFDIR | 0o755}[path_name]
            current.st_mode = replacement
        elif defect == "owner":
            current.st_uid = 1000
        elif defect == "group":
            current.st_gid = _UTMP_GID + 1 if path_name in {"btmp", "wtmp"} else 35
        elif defect == "symlink":
            current.st_mode = stat.S_IFLNK | 0o777
        elif defect == "hardlink":
            current.st_nlink = 2

    verifier, _mount_reads, _group_queries = _runtime_verifier(
        monkeypatch, mountinfo, paths
    )
    with pytest.raises(ValueError):
        verifier.verify_installation_runtime_metadata(_FILESYSTEM_SHA256)


def test_installation_runtime_metadata_rejects_unknown_filesystem_profile(monkeypatch):
    """Unknown signed media never triggers runtime filesystem inspection.

    Args:
        monkeypatch: Pytest fixture for replacing controlled dependencies.
    """
    paths = _runtime_paths()
    verifier, mount_reads, group_queries = _runtime_verifier(
        monkeypatch, _mountinfo(), paths
    )

    with pytest.raises(ValueError):
        verifier.verify_installation_runtime_metadata("0" * 64)

    assert mount_reads == []
    assert group_queries == []


def test_mountinfo_reader_rejects_input_over_one_mib(tmp_path: Path):
    """Mountinfo input is bounded before it can drive topology checks.

    Args:
        tmp_path: Pytest temporary directory for isolated filesystem fixtures.
    """
    verifier = load_verifier()
    oversized = tmp_path / "mountinfo"
    oversized.write_bytes(b"x" * (1024 * 1024 + 1))

    with pytest.raises(ValueError):
        verifier._read_installation_mountinfo(oversized)


@pytest.mark.parametrize("link_kind", ["symlink", "hardlink"])
def test_mountinfo_reader_rejects_links(tmp_path: Path, link_kind: str):
    """Mountinfo must be read from an ordinary single-link file.

    Args:
        tmp_path: Pytest temporary directory for isolated filesystem fixtures.
        link_kind: Link type to exercise.
    """
    if link_kind == "symlink" and not getattr(os, "O_NOFOLLOW", 0):
        pytest.skip("host does not provide an O_NOFOLLOW open flag")
    verifier = load_verifier()
    source = tmp_path / "mountinfo-source"
    source.write_text(_mountinfo(), encoding="utf-8")
    linked = tmp_path / "mountinfo-linked"
    try:
        if link_kind == "symlink":
            linked.symlink_to(source)
        else:
            os.link(source, linked)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"host does not permit this local link fixture: {error}")

    with pytest.raises((OSError, ValueError)):
        verifier._read_installation_mountinfo(linked)


def _journal_policy_fixture(verifier, monkeypatch, tmp_path: Path):
    """Prepare public native-policy and journal metadata fixtures.

    Args:
        verifier: Loaded Photon package-state verifier module.
        monkeypatch: Pytest fixture for controlled dependency replacement.
        tmp_path: Pytest temporary directory for isolated fixture files.
    """
    policy = tmp_path / "systemd.conf"
    policy_bytes = (
        "a+ /var/log/journal - - - - -\n"
        "z /var/log/journal/%m 2755 root systemd-journal - -\n"
        "z /var/log/journal/%m/system.journal 0640 root systemd-journal - -\n"
        + verifier.INSTALLATION_SYSTEMD_JOURNAL_TMPFILES_ROW
        + "\n"
    ).encode("utf-8")
    policy.write_bytes(policy_bytes)
    journal = tmp_path / "journal"
    journal.mkdir()
    monkeypatch.setattr(verifier, "INSTALLATION_SYSTEMD_TMPFILES_PATH", policy)
    monkeypatch.setattr(verifier, "INSTALLATION_SYSTEMD_JOURNAL_PATH", journal)
    monkeypatch.setattr(
        verifier,
        "INSTALLATION_SYSTEMD_TMPFILES_SHA256",
        hashlib.sha256(policy_bytes).hexdigest(),
    )
    monkeypatch.setitem(
        sys.modules,
        "grp",
        SimpleNamespace(
            getgrnam=lambda name: SimpleNamespace(gr_gid=190)
            if name == "systemd-journal"
            else (_ for _ in ()).throw(KeyError(name))
        ),
    )
    return policy, policy_bytes, journal


def _journal_directory_metadata(monkeypatch, journal: Path, *, mode=None, uid=0, gid=190):
    """Supply controlled lstat metadata for only the journal directory.

    Args:
        monkeypatch: Pytest fixture for replacing Path.lstat.
        journal: Exact fixture directory checked by the verifier.
        mode: Optional file type and permission bits to expose.
        uid: Owner id to expose.
        gid: Group id to expose.
    """
    original_lstat = Path.lstat
    metadata = SimpleNamespace(
        st_mode=stat.S_IFDIR | 0o2755 if mode is None else mode,
        st_uid=uid,
        st_gid=gid,
    )

    def fake_lstat(path: Path):
        """Return fixture metadata only for the selected journal path.

        Args:
            path: Filesystem path being inspected.
        """
        if path == journal:
            return metadata
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", fake_lstat)
    return metadata


def _root_owned_policy_stat(real_metadata, *, mode=None, uid=0, gid=0, size=None):
    """Return synthetic metadata for the open policy file.

    Args:
        real_metadata: Actual stat result used for stable file identity fields.
        mode: Optional file type and permission bits to expose.
        uid: Owner id to expose.
        gid: Group id to expose.
        size: Optional file size to expose.
    """
    return SimpleNamespace(
        st_dev=real_metadata.st_dev,
        st_ino=real_metadata.st_ino,
        st_mode=stat.S_IFREG | 0o644 if mode is None else mode,
        st_nlink=real_metadata.st_nlink,
        st_uid=uid,
        st_gid=gid,
        st_size=real_metadata.st_size if size is None else size,
        st_mtime_ns=real_metadata.st_mtime_ns,
        st_ctime_ns=real_metadata.st_ctime_ns,
    )


def _enable_policy_stat_overrides(monkeypatch, verifier, *, mode=None, uid=0, gid=0, size=None):
    """Present deterministic root-owned policy metadata without host chown.

    Args:
        monkeypatch: Pytest fixture for replacing controlled dependencies.
        verifier: Loaded Photon package-state verifier module.
        mode: Optional file type and permission bits to expose.
        uid: Owner id to expose.
        gid: Group id to expose.
        size: Optional file size to expose.
    """
    original_fstat = verifier.os.fstat

    def fake_fstat(descriptor: int):
        """Return deterministic policy metadata for the fixture descriptor.

        Args:
            descriptor: Open policy file descriptor.
        """
        return _root_owned_policy_stat(
            original_fstat(descriptor), mode=mode, uid=uid, gid=gid, size=size
        )

    monkeypatch.setattr(verifier.os, "fstat", fake_fstat)


def test_installation_journal_metadata_accepts_native_policy_and_directory(
    monkeypatch, tmp_path: Path
):
    """Accept the pinned tmpfiles rule and root-owned 2755 journal directory.

    Args:
        monkeypatch: Pytest fixture for replacing controlled dependencies.
        tmp_path: Pytest temporary directory for isolated filesystem fixtures.
    """
    if not getattr(os, "O_NOFOLLOW", 0):
        pytest.skip("host does not provide an O_NOFOLLOW open flag")
    verifier = load_verifier()
    _policy, _policy_bytes, journal = _journal_policy_fixture(
        verifier, monkeypatch, tmp_path
    )
    _enable_policy_stat_overrides(monkeypatch, verifier)
    _journal_directory_metadata(monkeypatch, journal)

    assert verifier.verify_installation_journal_metadata(
        verifier.INSTALLATION_SYSTEMD_SHA256
    ) == {"runtime_journal_metadata_verified": True}


@pytest.mark.parametrize(
    "mutation",
    [
        "bytes",
        "directory",
        "symlink",
        "hardlink",
        "mode",
        "owner",
        "group",
        "size",
    ],
)
def test_installation_journal_metadata_rejects_policy_file_drift(
    monkeypatch, tmp_path: Path, mutation: str
):
    """Reject changed or unsafe public native tmpfiles policy files.

    Args:
        monkeypatch: Pytest fixture for replacing controlled dependencies.
        tmp_path: Pytest temporary directory for isolated filesystem fixtures.
        mutation: Policy file defect to exercise.
    """
    if not getattr(os, "O_NOFOLLOW", 0):
        pytest.skip("host does not provide an O_NOFOLLOW open flag")
    verifier = load_verifier()
    policy, _policy_bytes, journal = _journal_policy_fixture(
        verifier, monkeypatch, tmp_path
    )
    _enable_policy_stat_overrides(monkeypatch, verifier)
    _journal_directory_metadata(monkeypatch, journal)
    if mutation == "bytes":
        policy.write_bytes(b"# changed package policy\n" + _policy_bytes)
    elif mutation == "directory":
        policy.unlink()
        policy.mkdir()
    elif mutation == "symlink":
        policy.unlink()
        policy.symlink_to(tmp_path / "missing-target")
    elif mutation == "hardlink":
        os.link(policy, tmp_path / "policy-link")
    elif mutation in {"mode", "owner", "group", "size"}:
        if mutation == "size":
            _enable_policy_stat_overrides(
                monkeypatch,
                verifier,
                size=verifier.INSTALLATION_SYSTEMD_TMPFILES_MAX_BYTES + 1,
            )
        else:
            mode = stat.S_IFREG | 0o600 if mutation == "mode" else None
            uid = 1000 if mutation == "owner" else 0
            gid = 1000 if mutation == "group" else 0
            _enable_policy_stat_overrides(
                monkeypatch, verifier, mode=mode, uid=uid, gid=gid
            )

    with pytest.raises(ValueError, match="checksum differs" if mutation == "bytes" else None):
        verifier.verify_installation_journal_metadata(
            verifier.INSTALLATION_SYSTEMD_SHA256
        )


@pytest.mark.parametrize(
    "mutation",
    ["mode", "type", "owner", "group", "missing"],
)
def test_installation_journal_metadata_rejects_directory_drift(
    monkeypatch, tmp_path: Path, mutation: str
):
    """Reject journal directory type, mode, owner, group, or presence drift.

    Args:
        monkeypatch: Pytest fixture for replacing controlled dependencies.
        tmp_path: Pytest temporary directory for isolated filesystem fixtures.
        mutation: Journal directory defect to exercise.
    """
    verifier = load_verifier()
    _policy, policy_bytes, journal = _journal_policy_fixture(
        verifier, monkeypatch, tmp_path
    )
    monkeypatch.setattr(verifier, "_read_installation_systemd_tmpfiles", lambda: policy_bytes)
    if mutation == "missing":
        original_lstat = Path.lstat

        def missing_lstat(path: Path):
            """Report the journal fixture missing while preserving other paths.

            Args:
                path: Filesystem path being inspected.
            """
            if path == journal:
                raise FileNotFoundError(path)
            return original_lstat(path)

        monkeypatch.setattr(Path, "lstat", missing_lstat)
    else:
        mode = stat.S_IFREG | 0o2755 if mutation == "type" else None
        uid = 1000 if mutation == "owner" else 0
        gid = 191 if mutation == "group" else 190
        if mutation == "mode":
            mode = stat.S_IFDIR | 0o755
        _journal_directory_metadata(
            monkeypatch, journal, mode=mode, uid=uid, gid=gid
        )

    with pytest.raises(ValueError):
        verifier.verify_installation_journal_metadata(
            verifier.INSTALLATION_SYSTEMD_SHA256
        )


def test_installation_journal_metadata_rejects_unknown_systemd_before_reads(
    monkeypatch,
):
    """Reject unreviewed systemd package identity before policy or path reads.

    Args:
        monkeypatch: Pytest fixture for replacing controlled dependencies.
    """
    verifier = load_verifier()
    reads = []

    def unexpected_policy_read() -> bytes:
        """Record that the guarded policy read was attempted."""
        reads.append(True)
        raise AssertionError("unreviewed systemd package caused a policy read")

    monkeypatch.setattr(verifier, "_read_installation_systemd_tmpfiles", unexpected_policy_read)
    with pytest.raises(ValueError, match="profile is not admitted"):
        verifier.verify_installation_journal_metadata("0" * 64)
    assert reads == []


def _audit_policy_fixture(verifier, monkeypatch, tmp_path: Path):
    """Prepare the pinned audit tmpfiles rule and runtime directory fixture.

    Args:
        verifier: Loaded Photon package-state verifier module.
        monkeypatch: Pytest fixture for controlled dependency replacement.
        tmp_path: Pytest temporary directory for isolated fixture files.
    """
    policy = tmp_path / "audit.conf"
    policy_bytes = b"d /var/log/audit 0700 root root - -\n"
    policy.write_bytes(policy_bytes)
    audit = tmp_path / "audit"
    audit.mkdir()
    monkeypatch.setattr(verifier, "INSTALLATION_AUDIT_TMPFILES_PATH", policy)
    monkeypatch.setattr(verifier, "INSTALLATION_AUDIT_PATH", audit)
    return policy, policy_bytes, audit


def test_installation_audit_metadata_accepts_native_policy_and_directory(
    monkeypatch, tmp_path: Path
):
    """Accept the exact pinned audit policy and root-owned 0700 directory.

    Args:
        monkeypatch: Pytest fixture for replacing controlled dependencies.
        tmp_path: Pytest temporary directory for isolated filesystem fixtures.
    """
    if not getattr(os, "O_NOFOLLOW", 0):
        pytest.skip("host does not provide an O_NOFOLLOW open flag")
    verifier = load_verifier()
    _policy, _policy_bytes, audit = _audit_policy_fixture(
        verifier, monkeypatch, tmp_path
    )
    _enable_policy_stat_overrides(
        monkeypatch, verifier, mode=stat.S_IFREG | 0o640
    )
    _journal_directory_metadata(
        monkeypatch, audit, mode=stat.S_IFDIR | 0o700, uid=0, gid=0
    )
    assert verifier.verify_installation_audit_metadata(
        verifier.INSTALLATION_AUDIT_SHA256
    ) == {"runtime_audit_metadata_verified": True}


@pytest.mark.parametrize(
    "mutation",
    ["bytes", "directory", "symlink", "hardlink", "mode", "owner", "group", "size"],
)
def test_installation_audit_metadata_rejects_policy_file_drift(
    monkeypatch, tmp_path: Path, mutation: str
):
    """Reject audit policy content, type, link, and metadata changes.

    Args:
        monkeypatch: Pytest fixture for replacing controlled dependencies.
        tmp_path: Pytest temporary directory for isolated filesystem fixtures.
        mutation: Policy file defect to exercise.
    """
    if not getattr(os, "O_NOFOLLOW", 0):
        pytest.skip("host does not provide an O_NOFOLLOW open flag")
    verifier = load_verifier()
    policy, policy_bytes, audit = _audit_policy_fixture(
        verifier, monkeypatch, tmp_path
    )
    _enable_policy_stat_overrides(
        monkeypatch, verifier, mode=stat.S_IFREG | 0o640
    )
    _journal_directory_metadata(
        monkeypatch, audit, mode=stat.S_IFDIR | 0o700, uid=0, gid=0
    )
    if mutation == "bytes":
        policy.write_bytes(b"# changed audit policy\n" + policy_bytes)
    elif mutation == "directory":
        policy.unlink()
        policy.mkdir()
    elif mutation == "symlink":
        policy.unlink()
        policy.symlink_to(tmp_path / "missing-target")
    elif mutation == "hardlink":
        os.link(policy, tmp_path / "policy-link")
    elif mutation in {"mode", "owner", "group", "size"}:
        if mutation == "size":
            _enable_policy_stat_overrides(
                monkeypatch,
                verifier,
                mode=stat.S_IFREG | 0o640,
                size=verifier.INSTALLATION_AUDIT_TMPFILES_MAX_BYTES + 1,
            )
        else:
            mode = stat.S_IFREG | 0o600 if mutation == "mode" else stat.S_IFREG | 0o640
            uid = 1000 if mutation == "owner" else 0
            gid = 1000 if mutation == "group" else 0
            _enable_policy_stat_overrides(
                monkeypatch, verifier, mode=mode, uid=uid, gid=gid
            )

    with pytest.raises(ValueError, match="checksum differs" if mutation == "bytes" else None):
        verifier.verify_installation_audit_metadata(
            verifier.INSTALLATION_AUDIT_SHA256
        )


@pytest.mark.parametrize("mutation", ["mode", "type", "owner", "group", "missing"])
def test_installation_audit_metadata_rejects_directory_drift(
    monkeypatch, tmp_path: Path, mutation: str
):
    """Reject missing or incorrectly typed/owned audit directories.

    Args:
        monkeypatch: Pytest fixture for replacing controlled dependencies.
        tmp_path: Pytest temporary directory for isolated filesystem fixtures.
        mutation: Directory defect to exercise.
    """
    verifier = load_verifier()
    _policy, policy_bytes, audit = _audit_policy_fixture(
        verifier, monkeypatch, tmp_path
    )
    monkeypatch.setattr(
        verifier, "_read_installation_audit_tmpfiles", lambda: policy_bytes
    )
    if mutation == "missing":
        original_lstat = Path.lstat

        def missing_lstat(path: Path):
            """Report only the audit fixture missing.

            Args:
                path: Filesystem path being inspected.
            """
            if path == audit:
                raise FileNotFoundError(path)
            return original_lstat(path)

        monkeypatch.setattr(Path, "lstat", missing_lstat)
    else:
        mode = stat.S_IFDIR | 0o700
        uid = 0
        gid = 0
        if mutation == "mode":
            mode = stat.S_IFDIR | 0o750
        elif mutation == "type":
            mode = stat.S_IFREG | 0o700
        elif mutation == "owner":
            uid = 1000
        elif mutation == "group":
            gid = 1000
        _journal_directory_metadata(
            monkeypatch, audit, mode=mode, uid=uid, gid=gid
        )

    with pytest.raises(ValueError):
        verifier.verify_installation_audit_metadata(
            verifier.INSTALLATION_AUDIT_SHA256
        )


def test_installation_audit_metadata_rejects_unknown_package_before_reads(
    monkeypatch,
):
    """Reject unreviewed package identity before policy or directory reads.

    Args:
        monkeypatch: Pytest fixture for replacing controlled dependencies.
    """
    verifier = load_verifier()
    reads = []

    def unexpected_policy_read() -> bytes:
        """Record forbidden policy reads for an unknown package checksum."""
        reads.append("policy")
        raise AssertionError("unreviewed package caused an audit policy read")

    def unexpected_directory_stat(path: Path):
        """Record forbidden metadata reads for an unknown package checksum.

        Args:
            path: Filesystem path being inspected.
        """
        reads.append("directory")
        raise AssertionError("unreviewed package caused an audit path read")

    monkeypatch.setattr(verifier, "_read_installation_audit_tmpfiles", unexpected_policy_read)
    monkeypatch.setattr(Path, "lstat", unexpected_directory_stat)
    with pytest.raises(ValueError, match="profile is not admitted"):
        verifier.verify_installation_audit_metadata("0" * 64)
    assert reads == []


@pytest.mark.parametrize("defect", [None, "mode", "owner", "group", "type", "missing", "group-name", "group-id"])
@pytest.mark.parametrize("profile", ["rpcbind", "openssh"])
def test_installation_sys_directory_matches_native_post_script(monkeypatch, defect, profile):
    """Admit only the pinned initial-install directory ownership, without children.

    Args:
        monkeypatch: Replace only fixed public metadata observations.
        defect: Native directory or group identity drift to reject.
        profile: Fixed native package profile under test.
    """
    verifier = load_verifier()
    path = Path("/var/lib/rpcbind" if profile == "rpcbind" else "/usr/share/empty.sshd")
    mode = 0o755 if profile == "rpcbind" else 0o711
    verify = getattr(verifier, f"verify_installation_{profile}_metadata")
    checksum = getattr(verifier, f"INSTALLATION_{profile.upper()}_SHA256")
    metadata = SimpleNamespace(st_mode=stat.S_IFDIR | mode, st_uid=0, st_gid=2)
    if defect == "mode":
        metadata.st_mode = stat.S_IFDIR | 0o750
    elif defect == "owner":
        metadata.st_uid = 31
    elif defect == "group":
        metadata.st_gid = 0
    elif defect == "type":
        metadata.st_mode = stat.S_IFLNK | 0o755
    reads = []

    def group(name):
        """Resolve only the fixed group declared by the native script.

        Args:
            name: Group name requested by the verifier.
        """
        assert name == "sys"
        if defect == "group-name":
            raise KeyError(name)
        return SimpleNamespace(gr_gid=3 if defect == "group-id" else 2)

    def metadata_only(requested):
        """Reject child or content inspection while observing the directory.

        Args:
            requested: Fixed public directory path requested by the verifier.
        """
        assert requested == path
        reads.append(path)
        if defect == "missing":
            raise FileNotFoundError(path)
        return metadata

    monkeypatch.setitem(sys.modules, "grp", SimpleNamespace(getgrnam=group))
    monkeypatch.setattr(Path, "lstat", metadata_only)
    if defect:
        with pytest.raises(ValueError):
            verify(checksum)
    else:
        assert verify(checksum) == {
            f"runtime_{profile}_metadata_verified": True
        }
    assert reads == ([] if defect == "group-name" else [path])


@pytest.mark.parametrize("profile", ["rpcbind", "openssh"])
def test_installation_sys_directory_rejects_unknown_package_before_metadata(monkeypatch, profile):
    """Refuse unknown package identity before touching the group or directory.

    Args:
        monkeypatch: Intercept any forbidden metadata lookup.
        profile: Fixed native package profile under test.
    """
    verifier = load_verifier()

    def forbidden(*_args):
        """Refuse metadata access for an unreviewed package.

        Args:
            *_args: Any attempted lookup arguments.
        """
        raise AssertionError("unknown package caused metadata access")

    monkeypatch.setitem(sys.modules, "grp", SimpleNamespace(getgrnam=forbidden))
    monkeypatch.setattr(Path, "lstat", forbidden)
    with pytest.raises(ValueError, match="profile is not admitted"):
        getattr(verifier, f"verify_installation_{profile}_metadata")("0" * 64)


@pytest.mark.parametrize("defect", [
    None, "package", "grub-package", "layout-identity", "layout-filesystem", "missing-mount", "duplicate-mount", "subroot",
    "filesystem", "nested-mount", "mask", "duplicate-mask", "root-mode", "root-owner", "root-group", "root-type",
    "file-mode", "file-owner", "file-group", "file-type", "file-link", "size", "bytes", "timestamp", "fraction",
    "device", "replacement", "missing-file", "malformed-mount",
])
def test_installation_efi_profile_requires_native_mount_and_exact_files(monkeypatch, defect):
    """Keep immutable EFI bytes strict while proving native VFAT metadata.

    Args:
        monkeypatch: Replace only the public file and mount observations.
        defect: Mount, file, identity or package drift to reject.
    """
    verifier = load_verifier()
    payloads = {"EFI/BOOT/bootx64.efi": b"public loader", "EFI/BOOT/revocations.efi": b"public revocations",
                "EFI/BOOT/grubx64.efi": b"public grub"}
    records = tuple((name, len(data), hashlib.sha256(data).hexdigest(), modified)
                    for (name, data), modified in zip(payloads.items(), (1781509843, 1781509848, 1788335074), strict=True))
    monkeypatch.setattr(verifier, "INSTALLATION_EFI_FILES", records)
    root = Path("/boot/efi")
    observations = []

    def layout():
        """Stand in for the existing UUID-backed, no-format mount verifier."""
        observations.append("layout")
        if defect == "layout-identity":
            raise ValueError("recorded UUID differs")
        return {"mounts": [{"target": "/boot/efi", "filesystem": "ext4" if defect == "layout-filesystem" else "vfat"}]}

    kind = "ext4" if defect == "filesystem" else "vfat"
    mount_root = "/subroot" if defect == "subroot" else "/"
    options = "rw,fmask=0022,dmask=0022"
    if defect == "mask":
        options = "rw,fmask=0000,dmask=0022"
    elif defect == "duplicate-mask":
        options += ",fmask=0022"
    rows = f"31 1 8:1 {mount_root} /boot/efi rw - {kind} /dev/fixture {options}\n"
    if defect == "duplicate-mount":
        rows *= 2
    elif defect == "missing-mount":
        rows = ""
    elif defect == "nested-mount":
        rows += "32 31 8:2 / /boot/efi/EFI rw - vfat /dev/other rw,fmask=0022,dmask=0022\n"
    elif defect == "malformed-mount":
        rows = "malformed private mount row"
    monkeypatch.setattr(verifier, "_verified_installation_layout", layout)
    monkeypatch.setattr(verifier, "_read_installation_mountinfo", lambda: rows)
    calls = {}

    def metadata(path):
        """Refuse all observation outside the fixed public EFI file inventory.

        Args:
            path: Fixed root or public package file being inspected.
        """
        observations.append("metadata")
        if path == root:
            return SimpleNamespace(st_mode=(stat.S_IFREG if defect == "root-type" else stat.S_IFDIR)
                                   | (0o777 if defect == "root-mode" else 0o755), st_uid=int(defect == "root-owner"),
                                   st_gid=int(defect == "root-group"), st_dev=31)
        name = path.relative_to(root).as_posix()
        assert name in payloads
        if defect == "missing-file":
            raise FileNotFoundError()
        calls[name] = calls.get(name, 0) + 1
        modified = next(item[3] for item in records if item[0] == name)
        return SimpleNamespace(st_mode=(stat.S_IFLNK if defect == "file-type" else stat.S_IFREG)
                               | (0o777 if defect == "file-mode" else 0o755), st_uid=int(defect == "file-owner"),
                               st_gid=int(defect == "file-group"), st_dev=32 if defect == "device" else 31,
                               st_ino=calls[name] if defect == "replacement" else 8, st_nlink=2 if defect == "file-link" else 1,
                               st_size=len(payloads[name]) + int(defect == "size"), st_ctime_ns=9,
                               st_mtime_ns=(modified // 2 * 2 + 2 * int(defect == "timestamp")) * 1_000_000_000
                               + int(defect == "fraction"))

    def public_bytes(path, mode, maximum, _label):
        """Return only the fixed public bytes normally read with no-follow checks.

        Args:
            path: Fixed public EFI file.
            mode: Required native file mode.
            maximum: Exact original file size used as the read bound.
            _label: Fixed error label, never console contents.
        """
        name = path.relative_to(root).as_posix()
        assert name in payloads and mode == 0o755 and maximum == len(payloads[name])
        return b"changed public bytes" if defect == "bytes" else payloads[name]

    monkeypatch.setattr(Path, "lstat", metadata)
    monkeypatch.setattr(verifier, "_read_installation_tmpfiles", public_bytes)
    checksum = "0" * 64 if defect == "package" else verifier.INSTALLATION_SHIM_SHA256
    grub_checksum = "0" * 64 if defect == "grub-package" else verifier.INSTALLATION_GRUB_EFI_SHA256
    if defect:
        with pytest.raises((ValueError, FileNotFoundError)):
            verifier.verify_installation_efi_metadata(checksum, grub_checksum)
    else:
        assert verifier.verify_installation_efi_metadata(checksum, grub_checksum) == {"runtime_efi_metadata_verified": True}
        assert set(calls) == set(payloads)
    if defect in {"package", "grub-package"}:
        assert observations == []


@pytest.mark.parametrize("defect", [None, "bytes", "profile"])
def test_installation_layout_reuses_only_checked_helper_bytes(monkeypatch, defect):
    """Compile the authenticated shared helper bytes without reopening its path.

    Args:
        monkeypatch: Provide an isolated authenticated source fixture.
        defect: Helper-byte or installed-profile drift to reject.
    """
    verifier = load_verifier()
    raw = b"def installation_profile(): return True\ndef verify_layout(): return {'mounts': []}\n"
    monkeypatch.setattr(verifier, "INSTALLATION_LAYOUT_HELPER_SHA256", hashlib.sha256(raw).hexdigest())
    if defect == "bytes":
        raw += b"raise AssertionError('changed helper executed')\n"
    elif defect == "profile":
        raw = raw.replace(b"return True", b"return False")
        monkeypatch.setattr(verifier, "INSTALLATION_LAYOUT_HELPER_SHA256", hashlib.sha256(raw).hexdigest())
    monkeypatch.setattr(verifier, "_read_installation_tmpfiles", lambda *_args: raw)
    if defect:
        with pytest.raises(ValueError):
            verifier._verified_installation_layout()
    else:
        assert verifier._verified_installation_layout() == {"mounts": []}


def test_installation_efi_layout_pin_matches_shared_helper():
    """Require explicit profile review when the reused mount-verifier source changes."""
    verifier = load_verifier()
    assert hashlib.sha256(Path("scripts/installation/layout.py").read_bytes()).hexdigest() == (
        verifier.INSTALLATION_LAYOUT_HELPER_SHA256
    )
