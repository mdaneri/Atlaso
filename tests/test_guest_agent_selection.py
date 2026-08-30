"""Focused coverage for provider-neutral offline guest-agent selection."""

from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SELECTOR = ROOT / "scripts" / "appliance" / "atlaso-select-guest-agent"


pytestmark = pytest.mark.skipif(os.name == "nt", reason="The selector runs inside the Photon Linux guest.")


def _write_executable(path: Path, content: str) -> None:
    """Write one executable test double.

    Args:
        path: Test-double destination.
        content: Shell script content.
    """

    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


def _prepare_runtime(tmp_path: Path, *, platform: str, dmi: str, packages: tuple[str, ...]) -> dict[str, str]:
    """Prepare an isolated command and filesystem boundary for the selector.

    Args:
        tmp_path: Temporary directory provided by pytest.
        platform: Simulated systemd virtualization value.
        dmi: Simulated DMI vendor evidence.
        packages: Initially installed package names.
    """

    tmp_path.chmod(0o700)
    command_dir = tmp_path / "bin"
    command_dir.mkdir()
    state_path = tmp_path / "packages.txt"
    state_path.write_text("".join(f"{package}\n" for package in packages), encoding="utf-8")
    log_path = tmp_path / "systemctl.log"
    rpm_log_path = tmp_path / "rpm.log"
    package_cache = tmp_path / "tdnf-cache"
    package_cache.mkdir()
    (package_cache / "metadata").write_text("first-boot-cache\n", encoding="utf-8")

    _write_executable(
        command_dir / "systemd-detect-virt",
        "#!/bin/sh\nprintf '%s\\n' \"$FAKE_VIRTUALIZATION\"\n",
    )
    _write_executable(
        command_dir / "systemctl",
        """#!/bin/sh
set -eu
printf '%s\n' "$*" >>"$FAKE_SYSTEMCTL_LOG"
if [ "${1:-}" = "is-active" ] || [ "${1:-}" = "is-enabled" ]; then
  service="${3:-}"
  case "$FAKE_VIRTUALIZATION:$service" in
    vmware:vmtoolsd.service|kvm:qemu-guest-agent.service|qemu:qemu-guest-agent.service|microsoft:hv_kvp_daemon.service|microsoft:hv_fcopy_daemon.service|microsoft:hv_vss_daemon.service)
      exit 0
      ;;
    *) exit 1 ;;
  esac
fi
""",
    )
    _write_executable(
        command_dir / "rpm",
        """#!/bin/sh
set -eu
state="$FAKE_PACKAGE_STATE"
printf '%s\n' "$*" >>"$FAKE_RPM_LOG"
case "${1:-}" in
  -qa)
    cat "$state"
    ;;
  -q)
    grep -Fx -- "$2" "$state" >/dev/null
    ;;
  -e)
    shift
    for package in "$@"; do
      grep -Fvx -- "$package" "$state" >"$state.next" || true
      mv "$state.next" "$state"
    done
    ;;
  -Uvh)
    shift
    for rpm_path in "$@"; do
      case "$rpm_path" in
        */qemu/*) package=atlaso-qemu-guest-agent ;;
        */hyperv/*) package=hyper-v ;;
        *) continue ;;
      esac
      grep -Fx -- "$package" "$state" >/dev/null 2>&1 || printf '%s\n' "$package" >>"$state"
    done
    ;;
  *)
    printf 'unexpected rpm invocation: %s\n' "$*" >&2
    exit 90
    ;;
esac
""",
    )
    _write_executable(command_dir / "tdnf", "#!/bin/sh\nexit 91\n")
    _write_executable(
        command_dir / "find",
        """#!/bin/sh
set -eu
if [ -n "${FAKE_REJECT_RECURSIVE_CLEANUP:-}" ]; then
  for argument in "$@"; do
    [ "$argument" != "-delete" ] || exit 94
  done
fi
exec /usr/bin/find "$@"
""",
    )
    _write_executable(
        command_dir / "rm",
        """#!/bin/sh
set -eu
if [ -n "${FAKE_REJECT_RECURSIVE_CLEANUP:-}" ]; then
  for argument in "$@"; do
    case "$argument" in
      -r|-R|-rf|-fr|-r[f]*) exit 95 ;;
    esac
  done
fi
exec /usr/bin/rm "$@"
""",
    )
    _write_executable(
        command_dir / "python3",
        """#!/bin/sh
set -eu
if [ -n "${FAKE_SWAP_TEST_ROOT_TARGET:-}" ]; then
  /usr/bin/mv -- "$ATLASO_GUEST_AGENT_TEST_ROOT" "$FAKE_SWAP_TEST_ROOT_ORIGINAL"
  /usr/bin/ln -s -- "$FAKE_SWAP_TEST_ROOT_TARGET" "$ATLASO_GUEST_AGENT_TEST_ROOT"
fi
exec /usr/bin/python3 "$@"
""",
    )
    _write_executable(
        command_dir / "shred",
        """#!/bin/sh
set -eu
if [ -n "${FAKE_SHRED_LINK_TARGET:-}" ]; then
  after_separator=0
  for argument in "$@"; do
    if [ "$after_separator" -eq 1 ]; then
      ln -- "$argument" "$FAKE_SHRED_LINK_TARGET"
      printf 'overwritten by shred\\n' >"$argument"
      rm -f -- "$argument"
      exit 0
    fi
    [ "$argument" = "--" ] && after_separator=1
  done
  exit 93
fi
exec /usr/bin/shred "$@"
""",
    )
    _write_executable(
        command_dir / "mountpoint",
        """#!/bin/sh
set -eu
candidate=""
for argument in "$@"; do
  candidate="$argument"
done
[ -n "${FAKE_MOUNT_TARGET:-}" ] && [ "$candidate" = "$FAKE_MOUNT_TARGET" ]
""",
    )
    initializer = tmp_path / "atlaso-initialize-machine-identity"
    _write_executable(
        initializer,
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >\"$FAKE_MACHINE_IDENTITY_LOG\"\nprintf 'initialize %s\\n' \"$*\" >>\"$FAKE_SYSTEMCTL_LOG\"\n",
    )

    staging = tmp_path / "first-boot-packages"
    for profile in ("hyperv", "qemu"):
        profile_dir = staging / profile
        profile_dir.mkdir(parents=True, exist_ok=True)
        rpm_path = profile_dir / f"{profile}.rpm"
        rpm_path.write_bytes(profile.encode("ascii"))
        rpm_path.chmod(0o600)
    manifest_lines = []
    for rpm_path in sorted(staging.glob("*/*.rpm")):
        digest = hashlib.sha256(rpm_path.read_bytes()).hexdigest()
        manifest_lines.append(f"{digest}  {rpm_path.relative_to(staging).as_posix()}\n")
    manifest = staging / "SHA256SUMS"
    manifest.write_text("".join(manifest_lines), encoding="utf-8")
    manifest.chmod(0o600)
    for profile_dir in staging.iterdir():
        if profile_dir.is_dir():
            profile_dir.chmod(0o700)
    staging.chmod(0o700)

    dmi_root = tmp_path / "dmi"
    dmi_root.mkdir()
    (dmi_root / "sys_vendor").write_text(dmi, encoding="utf-8")
    (dmi_root / "product_name").write_text("Virtual Machine", encoding="utf-8")
    (dmi_root / "board_vendor").write_text(dmi, encoding="utf-8")

    owner = subprocess.run(["id", "-un"], check=True, capture_output=True, text=True).stdout.strip()
    group = subprocess.run(["id", "-gn"], check=True, capture_output=True, text=True).stdout.strip()
    return {
        "PATH": f"{command_dir}:{os.environ['PATH']}",
        "FAKE_VIRTUALIZATION": platform,
        "FAKE_PACKAGE_STATE": str(state_path),
        "FAKE_RPM_LOG": str(rpm_log_path),
        "FAKE_SYSTEMCTL_LOG": str(log_path),
        "ATLASO_GUEST_AGENT_STAGING": str(staging),
        "ATLASO_GUEST_AGENT_RUNTIME": str(tmp_path / "runtime"),
        "ATLASO_GUEST_AGENT_MARKER": str(tmp_path / "guest-agent.applied"),
        "ATLASO_GUEST_AGENT_TEST_ROOT": str(tmp_path),
        "ATLASO_DMI_ROOT": str(dmi_root),
        "ATLASO_GUEST_AGENT_STAGING_IDENTITY": f"{owner}:{group}:700",
        "ATLASO_GUEST_AGENT_PACKAGE_CACHE": str(package_cache),
        "ATLASO_MACHINE_IDENTITY_INITIALIZER": str(initializer),
        "FAKE_MACHINE_IDENTITY_LOG": str(tmp_path / "machine-identity.log"),
    }


def _run_selector(
    environment: dict[str, str],
    *arguments: str,
) -> subprocess.CompletedProcess[str]:
    """Run the selector inside its isolated test boundary.

    Args:
        environment: Isolated selector environment.
        arguments: Optional selector command-line arguments.
    """

    return subprocess.run(
        ["sh", str(SELECTOR), *arguments],
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, **environment},
    )


@pytest.mark.parametrize(
    ("detected", "dmi", "initial", "expected", "service"),
    [
        (
            "vmware",
            "VMware, Inc.",
            ("open-vm-tools", "qemu-guest-agent"),
            {"open-vm-tools"},
            "vmtoolsd.service",
        ),
        ("kvm", "QEMU", ("open-vm-tools",), {"atlaso-qemu-guest-agent"}, "qemu-guest-agent.service"),
        ("microsoft", "Microsoft Corporation", ("open-vm-tools",), {"hyper-v"}, "hv_kvp_daemon.service"),
        ("none", "Physical Vendor", ("open-vm-tools",), set(), "vmtoolsd.service"),
    ],
)
def test_selects_one_provider_then_erases_staging_at_cleanup_gate(
    tmp_path: Path,
    detected: str,
    dmi: str,
    initial: tuple[str, ...],
    expected: set[str],
    service: str,
) -> None:
    """Each supported platform retains exactly its intended guest agent.

    Args:
        tmp_path: Temporary directory provided by pytest.
        detected: Simulated systemd virtualization value.
        dmi: Simulated DMI vendor evidence.
        initial: Initially installed package names.
        expected: Expected final package set.
        service: Expected active guest-agent service.
    """

    environment = _prepare_runtime(tmp_path, platform=detected, dmi=dmi, packages=initial)
    result = _run_selector(environment)

    assert result.returncode == 0, result.stderr
    assert set(Path(environment["FAKE_PACKAGE_STATE"]).read_text(encoding="utf-8").splitlines()) == expected
    assert f"platform={'qemu' if detected == 'kvm' else 'hyperv' if detected == 'microsoft' else 'baremetal' if detected == 'none' else detected}" in Path(
        environment["ATLASO_GUEST_AGENT_MARKER"]
    ).read_text(encoding="utf-8")
    assert Path(environment["ATLASO_GUEST_AGENT_STAGING"]).is_dir()
    assert any(Path(environment["ATLASO_GUEST_AGENT_PACKAGE_CACHE"]).iterdir())
    assert service in Path(environment["FAKE_SYSTEMCTL_LOG"]).read_text(encoding="utf-8")
    expected_platform = "qemu" if detected == "kvm" else "hyperv" if detected == "microsoft" else "baremetal" if detected == "none" else detected
    assert Path(environment["FAKE_MACHINE_IDENTITY_LOG"]).read_text(encoding="utf-8") == f"--platform {expected_platform}\n"
    if detected in {"kvm", "microsoft"}:
        rpm_log = Path(environment["FAKE_RPM_LOG"]).read_text(encoding="utf-8")
        assert rpm_log.index("-e open-vm-tools") < rpm_log.index("-Uvh")
    if detected == "microsoft":
        service_log = Path(environment["FAKE_SYSTEMCTL_LOG"]).read_text(encoding="utf-8")
        assert "enable --now hv_kvp_daemon.service" not in service_log
        assert service_log.index("enable hv_kvp_daemon.service") < service_log.index("initialize --platform hyperv")
        assert service_log.index("initialize --platform hyperv") < service_log.index("start hv_kvp_daemon.service")

    cleanup = _run_selector(environment, "--cleanup-only")

    assert cleanup.returncode == 0, cleanup.stderr
    assert not Path(environment["ATLASO_GUEST_AGENT_STAGING"]).exists()
    assert not any(Path(environment["ATLASO_GUEST_AGENT_PACKAGE_CACHE"]).iterdir())


@pytest.mark.parametrize(
    ("detected", "dmi", "message"),
    [
        ("xen", "Xen", "Unsupported virtualization identifier"),
        ("vmware", "Microsoft Corporation", "Contradictory virtualization evidence"),
    ],
)
def test_unknown_or_contradictory_evidence_blocks_and_retains_payload(
    tmp_path: Path,
    detected: str,
    dmi: str,
    message: str,
) -> None:
    """Unsafe evidence preserves the offline closure and leaves no success marker.

    Args:
        tmp_path: Temporary directory provided by pytest.
        detected: Simulated unsupported or conflicting platform.
        dmi: Simulated DMI vendor evidence.
        message: Expected fail-closed diagnostic.
    """

    environment = _prepare_runtime(tmp_path, platform=detected, dmi=dmi, packages=("open-vm-tools",))
    result = _run_selector(environment)

    assert result.returncode == 2
    assert message in result.stderr
    assert Path(environment["ATLASO_GUEST_AGENT_STAGING"]).is_dir()
    assert not Path(environment["ATLASO_GUEST_AGENT_MARKER"]).exists()


def test_checksum_failure_is_retryable_without_network_access(tmp_path: Path) -> None:
    """A damaged payload is retained, then succeeds after an operator restores it.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    environment = _prepare_runtime(tmp_path, platform="kvm", dmi="QEMU", packages=("open-vm-tools",))
    qemu_rpm = Path(environment["ATLASO_GUEST_AGENT_STAGING"]) / "qemu" / "qemu.rpm"
    qemu_rpm.write_bytes(b"damaged")

    failed = _run_selector(environment)
    assert failed.returncode != 0
    assert Path(environment["ATLASO_GUEST_AGENT_STAGING"]).is_dir()
    assert not Path(environment["ATLASO_GUEST_AGENT_MARKER"]).exists()

    qemu_rpm.write_bytes(b"qemu")
    retried = _run_selector(environment)
    assert retried.returncode == 0, retried.stderr
    assert Path(environment["ATLASO_GUEST_AGENT_STAGING"]).is_dir()
    assert "atlaso-qemu-guest-agent" in Path(environment["FAKE_PACKAGE_STATE"]).read_text(encoding="utf-8")

    cleanup = _run_selector(environment, "--cleanup-only")
    assert cleanup.returncode == 0, cleanup.stderr
    assert not Path(environment["ATLASO_GUEST_AGENT_STAGING"]).exists()


def test_unlisted_rpm_is_rejected_without_package_mutation(tmp_path: Path) -> None:
    """The manifest must cover the exact closure, not merely a valid subset.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    environment = _prepare_runtime(tmp_path, platform="kvm", dmi="QEMU", packages=("open-vm-tools",))
    extra = Path(environment["ATLASO_GUEST_AGENT_STAGING"]) / "qemu" / "unlisted.rpm"
    extra.write_bytes(b"untrusted")
    extra.chmod(0o600)

    result = _run_selector(environment)

    assert result.returncode == 2
    assert "does not cover the exact RPM closure" in result.stderr
    assert Path(environment["FAKE_PACKAGE_STATE"]).read_text(encoding="utf-8").splitlines() == ["open-vm-tools"]
    assert Path(environment["ATLASO_GUEST_AGENT_STAGING"]).is_dir()


def test_cleanup_requires_completed_provider_selection(tmp_path: Path) -> None:
    """Deferred cleanup cannot erase staging before provider selection commits.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    environment = _prepare_runtime(tmp_path, platform="kvm", dmi="QEMU", packages=("open-vm-tools",))

    result = _run_selector(environment, "--cleanup-only")

    assert result.returncode == 2
    assert "requires a completed provider-selection marker" in result.stderr
    assert Path(environment["ATLASO_GUEST_AGENT_STAGING"]).is_dir()
    assert not Path(environment["ATLASO_GUEST_AGENT_MARKER"]).exists()


def test_success_marker_is_revalidated_against_current_platform(tmp_path: Path) -> None:
    """A stale or unsafe marker cannot bypass provider detection on a cloned appliance.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    environment = _prepare_runtime(tmp_path, platform="kvm", dmi="QEMU", packages=("open-vm-tools",))
    result = _run_selector(environment)
    assert result.returncode == 0, result.stderr
    marker = Path(environment["ATLASO_GUEST_AGENT_MARKER"])

    second = _run_selector(environment)
    assert second.returncode == 0, second.stderr
    assert "already completed" in second.stdout

    cache = Path(environment["ATLASO_GUEST_AGENT_PACKAGE_CACHE"])
    (cache / "post-first-boot").write_text("preserve\n", encoding="utf-8")
    third = _run_selector(environment)
    assert third.returncode == 0, third.stderr
    assert (cache / "post-first-boot").is_file()

    marker.write_text("platform=vmware\n", encoding="utf-8")
    conflict = _run_selector(environment)
    assert conflict.returncode == 2
    assert "conflicts with current evidence" in conflict.stderr


@pytest.mark.parametrize(
    "override_name",
    [
        "ATLASO_GUEST_AGENT_STAGING",
        "ATLASO_GUEST_AGENT_RUNTIME",
        "ATLASO_GUEST_AGENT_PACKAGE_CACHE",
    ],
)
def test_success_marker_retry_rejects_unrelated_cleanup_target(tmp_path: Path, override_name: str) -> None:
    """A durable marker cannot authorize cleanup outside the isolated root.

    Args:
        tmp_path: Temporary directory provided by pytest.
        override_name: Destructive selector path redirected outside the admitted root.
    """

    isolated_root = tmp_path / "isolated"
    isolated_root.mkdir(mode=0o700)
    environment = _prepare_runtime(isolated_root, platform="kvm", dmi="QEMU", packages=("open-vm-tools",))
    first = _run_selector(environment)
    assert first.returncode == 0, first.stderr

    victim = tmp_path / f"victim-{override_name.lower()}"
    victim.mkdir(mode=0o700)
    sentinel = victim / "preserve.txt"
    sentinel.write_text("preserve\n", encoding="utf-8")
    environment[override_name] = str(victim)

    retry = _run_selector(environment, "--cleanup-only")

    assert retry.returncode == 2
    assert "strict descendants" in retry.stderr
    assert sentinel.read_text(encoding="utf-8") == "preserve\n"


def test_cleanup_targets_cannot_overlap(tmp_path: Path) -> None:
    """Nested cleanup boundaries are rejected before selector mutation.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    environment = _prepare_runtime(tmp_path, platform="kvm", dmi="QEMU", packages=("open-vm-tools",))
    staging = Path(environment["ATLASO_GUEST_AGENT_STAGING"])
    environment["ATLASO_GUEST_AGENT_RUNTIME"] = str(staging / "runtime")

    result = _run_selector(environment)

    assert result.returncode == 2
    assert "must not overlap" in result.stderr
    assert staging.is_dir()
    assert Path(environment["FAKE_PACKAGE_STATE"]).read_text(encoding="utf-8").splitlines() == ["open-vm-tools"]


def test_cleanup_target_cannot_equal_isolated_root(tmp_path: Path) -> None:
    """The admitted root itself is never a destructive target.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    environment = _prepare_runtime(tmp_path, platform="kvm", dmi="QEMU", packages=("open-vm-tools",))
    sentinel = tmp_path / "preserve.txt"
    sentinel.write_text("preserve\n", encoding="utf-8")
    environment["ATLASO_GUEST_AGENT_PACKAGE_CACHE"] = str(tmp_path)

    result = _run_selector(environment)

    assert result.returncode == 2
    assert "strict descendants" in result.stderr
    assert sentinel.read_text(encoding="utf-8") == "preserve\n"


def test_cleanup_target_rejects_symlinked_ancestry(tmp_path: Path) -> None:
    """A symlinked parent cannot redirect cleanup inside or outside the test root.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    environment = _prepare_runtime(tmp_path, platform="kvm", dmi="QEMU", packages=("open-vm-tools",))
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir(mode=0o700)
    victim = real_parent / "runtime"
    victim.mkdir(mode=0o700)
    sentinel = victim / "preserve.txt"
    sentinel.write_text("preserve\n", encoding="utf-8")
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    environment["ATLASO_GUEST_AGENT_RUNTIME"] = str(linked_parent / "runtime")

    result = _run_selector(environment)

    assert result.returncode == 2
    assert "parent is missing or unsafe" in result.stderr
    assert sentinel.read_text(encoding="utf-8") == "preserve\n"


def test_success_marker_retry_rejects_mount_backed_cleanup_target(tmp_path: Path) -> None:
    """A mount boundary cannot redirect cleanup to unrelated backing storage.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    environment = _prepare_runtime(tmp_path, platform="kvm", dmi="QEMU", packages=("open-vm-tools",))
    first = _run_selector(environment)
    assert first.returncode == 0, first.stderr

    runtime = Path(environment["ATLASO_GUEST_AGENT_RUNTIME"])
    runtime.mkdir(mode=0o700)
    sentinel = runtime / "preserve.txt"
    sentinel.write_text("preserve\n", encoding="utf-8")
    environment["FAKE_MOUNT_TARGET"] = str(runtime)

    retry = _run_selector(environment, "--cleanup-only")

    assert retry.returncode == 2
    assert "cannot contain a mount point" in retry.stderr
    assert sentinel.read_text(encoding="utf-8") == "preserve\n"


def test_success_marker_retry_rejects_mounted_cleanup_ancestor(tmp_path: Path) -> None:
    """A mounted ancestor between the test root and target blocks cleanup.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    environment = _prepare_runtime(tmp_path, platform="kvm", dmi="QEMU", packages=("open-vm-tools",))
    first = _run_selector(environment)
    assert first.returncode == 0, first.stderr

    mounted_ancestor = tmp_path / "mounted-backing"
    mounted_ancestor.mkdir(mode=0o700)
    staging = mounted_ancestor / "staging"
    staging.mkdir(mode=0o700)
    sentinel = staging / "preserve.rpm"
    sentinel.write_text("preserve\n", encoding="utf-8")
    environment["ATLASO_GUEST_AGENT_STAGING"] = str(staging)
    environment["FAKE_MOUNT_TARGET"] = str(mounted_ancestor)

    retry = _run_selector(environment, "--cleanup-only")

    assert retry.returncode == 2
    assert "isolated test root cannot contain a mount point" in retry.stderr
    assert sentinel.read_text(encoding="utf-8") == "preserve\n"


def test_success_marker_retry_rejects_mount_backed_cleanup_file(tmp_path: Path) -> None:
    """A mounted file cannot redirect shredding to unrelated backing storage.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    environment = _prepare_runtime(tmp_path, platform="kvm", dmi="QEMU", packages=("open-vm-tools",))
    first = _run_selector(environment)
    assert first.returncode == 0, first.stderr

    staging = Path(environment["ATLASO_GUEST_AGENT_STAGING"])
    staging.mkdir(mode=0o700)
    sentinel = staging / "preserve.rpm"
    sentinel.write_text("preserve\n", encoding="utf-8")
    environment["FAKE_MOUNT_TARGET"] = str(sentinel)

    retry = _run_selector(environment, "--cleanup-only")

    assert retry.returncode == 2
    assert "cannot contain a mount point" in retry.stderr
    assert sentinel.read_text(encoding="utf-8") == "preserve\n"


def test_success_marker_retry_rejects_hard_linked_cleanup_file(tmp_path: Path) -> None:
    """A hard link cannot redirect shredding to an inode outside the test root.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    environment = _prepare_runtime(tmp_path, platform="kvm", dmi="QEMU", packages=("open-vm-tools",))
    first = _run_selector(environment)
    assert first.returncode == 0, first.stderr

    outside = tmp_path / "outside.rpm"
    outside.write_text("preserve\n", encoding="utf-8")
    staging = Path(environment["ATLASO_GUEST_AGENT_STAGING"])
    staging.mkdir(mode=0o700)
    alias = staging / "linked.rpm"
    os.link(outside, alias)

    retry = _run_selector(environment, "--cleanup-only")

    assert retry.returncode == 2
    assert "cannot contain hard-linked files" in retry.stderr
    assert outside.read_text(encoding="utf-8") == "preserve\n"
    assert alias.read_text(encoding="utf-8") == "preserve\n"


def test_test_override_cleanup_never_shreds_after_link_count_validation(tmp_path: Path) -> None:
    """A post-validation hard link cannot turn cleanup into an inode overwrite.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    environment = _prepare_runtime(tmp_path, platform="kvm", dmi="QEMU", packages=("open-vm-tools",))
    first = _run_selector(environment)
    assert first.returncode == 0, first.stderr

    staging = Path(environment["ATLASO_GUEST_AGENT_STAGING"])
    staging.mkdir(mode=0o700)
    sentinel = staging / "preserve.rpm"
    sentinel.write_text("preserve\n", encoding="utf-8")
    outside_alias = tmp_path.parent / f"{tmp_path.name}-outside.rpm"
    environment["FAKE_SHRED_LINK_TARGET"] = str(outside_alias)

    retry = _run_selector(environment, "--cleanup-only")

    assert retry.returncode == 0, retry.stderr
    assert not outside_alias.exists()
    assert not staging.exists()


def test_test_override_cleanup_quarantines_without_recursive_deletion(tmp_path: Path) -> None:
    """A post-validation mount race cannot redirect recursive cleanup.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    environment = _prepare_runtime(tmp_path, platform="kvm", dmi="QEMU", packages=("open-vm-tools",))
    environment["FAKE_REJECT_RECURSIVE_CLEANUP"] = "1"

    selected = _run_selector(environment)
    assert selected.returncode == 0, selected.stderr

    result = _run_selector(environment, "--cleanup-only")

    assert result.returncode == 0, result.stderr
    retained_staging = list(tmp_path.glob(".first-boot-packages.atlaso-retained.*"))
    retained_runtime = list(tmp_path.glob(".runtime.atlaso-retained.*"))
    retained_cache = list(tmp_path.glob(".tdnf-cache.atlaso-retained.*"))
    assert len(retained_staging) == 1
    assert len(retained_runtime) == 1
    assert len(retained_cache) == 1
    assert (retained_staging[0] / "qemu" / "qemu.rpm").is_file()
    assert retained_runtime[0].is_dir()
    assert (retained_cache[0] / "metadata").read_text(encoding="utf-8") == "first-boot-cache\n"
    assert not Path(environment["ATLASO_GUEST_AGENT_STAGING"]).exists()
    assert not any(Path(environment["ATLASO_GUEST_AGENT_PACKAGE_CACHE"]).iterdir())


def test_test_override_cleanup_uses_pinned_root_after_path_swap(tmp_path: Path) -> None:
    """A root-path replacement cannot redirect retained-artifact renames.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    environment = _prepare_runtime(tmp_path, platform="kvm", dmi="QEMU", packages=("open-vm-tools",))
    first = _run_selector(environment)
    assert first.returncode == 0, first.stderr

    staging = Path(environment["ATLASO_GUEST_AGENT_STAGING"])
    staging.mkdir(mode=0o700)
    (staging / "retry.rpm").write_text("retry\n", encoding="utf-8")
    replacement = tmp_path.parent / f"{tmp_path.name}-replacement"
    replacement.mkdir(mode=0o700)
    replacement_staging = replacement / staging.name
    replacement_staging.mkdir(mode=0o700)
    sentinel = replacement_staging / "preserve.rpm"
    sentinel.write_text("preserve\n", encoding="utf-8")
    original = tmp_path.parent / f"{tmp_path.name}-pinned"
    environment["FAKE_SWAP_TEST_ROOT_TARGET"] = str(replacement)
    environment["FAKE_SWAP_TEST_ROOT_ORIGINAL"] = str(original)

    try:
        retry = _run_selector(environment, "--cleanup-only")

        assert retry.returncode == 0, retry.stderr
        assert sentinel.read_text(encoding="utf-8") == "preserve\n"
        assert replacement_staging.is_dir()
        assert list(original.glob(".first-boot-packages.atlaso-retained.*"))
    finally:
        if tmp_path.is_symlink():
            tmp_path.unlink()
        if original.exists():
            original.rename(tmp_path)


def test_hyperv_access_cleanup_reloads_kvp_after_record_removal(tmp_path: Path) -> None:
    """A completed Hyper-V boot reloads KVP only after access is cleared.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    environment = _prepare_runtime(
        tmp_path,
        platform="microsoft",
        dmi="Microsoft Corporation",
        packages=("open-vm-tools",),
    )
    first = _run_selector(environment)
    assert first.returncode == 0, first.stderr
    log_path = Path(environment["FAKE_SYSTEMCTL_LOG"])
    log_path.write_text("", encoding="utf-8")

    second = _run_selector(environment, "--cleanup-only")

    assert second.returncode == 0, second.stderr
    service_log = log_path.read_text(encoding="utf-8")
    assert service_log.index("stop hv_kvp_daemon.service") < service_log.index(
        "initialize --platform hyperv --clear-access"
    )
    assert service_log.index("initialize --platform hyperv --clear-access") < service_log.index(
        "start hv_kvp_daemon.service"
    )
