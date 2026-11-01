"""Receipt-bound offline ISO refresh phases, invoked by the Windows job owner.

The JSON plan contains identities and paths, never commands or credentials. Native
resource ownership remains with the canonical builder and installation harness.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tomllib
import uuid
from contextlib import ExitStack
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath

from scripts.completed_task_files import (
    WindowsFiles,
    publish_durable_file,
    read_bounded_regular,
)
from scripts.installation.manifest import digest, inventory
from scripts.installation.refresh_plan import (
    PHASES,
    authorize_phase,
    canonical_plan_sha256,
    next_phase,
    validate_plan,
)

ROOT = Path(__file__).resolve().parents[2]
MAX_STATE = 16 * 1024**2


class RefreshRefusal(ValueError):
    """Expose only workflow-owned fixed refusal messages, never raw tool diagnostics."""


def captured_root(state: Path, plan: dict) -> Path:
    """Keep reusable inputs beside, never under, their durable evidence directory.

    Args:
        state: Durable operation evidence directory outside disposable output roots.
        plan: Validated immutable operation plan with distinct task and input identities.
    """
    root = state.parent / ("iso-inputs-" + plan["operation_id"])
    if root == state or state.is_relative_to(root):
        raise RefreshRefusal("capture inputs must not contain their durable creation evidence")
    return root


def supported_root() -> Path:
    """Independently resolve the active supported setting, without a fallback root."""
    home = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex")))
    configuration = tomllib.loads(read_bounded_regular(home / "config.toml", 1024**2).decode("utf-8"))
    desktop = configuration.get("desktop")
    if not isinstance(desktop, dict) or not isinstance(desktop.get("git-worktree-root"), str):
        raise RefreshRefusal("configure one supported desktop.git-worktree-root")
    from scripts.installation.iso import _checked_path

    root = Path(desktop["git-worktree-root"])
    if not root.is_absolute() or root.parent == root:
        raise RefreshRefusal("configured worktree root is unsafe")
    return _checked_path(root, final_kind="directory")


def publish(path: Path, value: dict) -> None:
    """Flush a new immutable evidence file; retain incomplete publication stages.

    Args:
        path: Absent durable evidence filename to publish without replacement.
        value: Bounded non-secret phase or resource evidence to publish.
    """
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(raw) > MAX_STATE:
        raise RefreshRefusal("refresh evidence exceeds its bound")
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.pending")
    with temporary.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    publish_durable_file(temporary, path)


def read(path: Path) -> dict:
    """Read only bounded, ordinary, identity-checked JSON evidence.

    Args:
        path: Exact ordinary single-link durable JSON evidence file.
    """
    def unique(pairs):
        """Reject duplicate JSON object keys before trusting durable evidence.

        Args:
            pairs: Decoded JSON key/value pairs, including any duplicate keys.
        """
        result = {}
        for key, value in pairs:
            if key in result:
                raise RefreshRefusal("refresh evidence contains duplicate keys")
            result[key] = value
        return result

    value = json.loads(read_bounded_regular(path, MAX_STATE), object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise RefreshRefusal("refresh evidence must be an object")
    return value


def context(plan_path: Path, configured_root: Path) -> tuple[dict, Path, str]:
    """Bind one plan to this actual task and an external durable evidence root.

    Args:
        plan_path: Absolute path of the original durable plan.json file.
        configured_root: Independently resolved supported Codex worktree root.
    """
    plan_path = plan_path.absolute()
    if plan_path.name != "plan.json":
        raise RefreshRefusal("refresh plan must use the fixed plan.json name")
    state = plan_path.parent
    if (not state.is_relative_to(configured_root) or state == configured_root
            or state.is_relative_to(ROOT) or ROOT.is_relative_to(state)):
        raise RefreshRefusal("refresh evidence must be outside the worktree under the configured root")
    plan = validate_plan(read(plan_path), configured_root=str(configured_root), worktree=str(ROOT))
    if plan["task_id"] != os.environ.get("CODEX_THREAD_ID"):
        raise RefreshRefusal("refresh plan belongs to a different task")
    if plan["capture_receipt"] is None and any(
            plan[name] != str(captured_root(state, plan) / name) for name in ("rpms", "powercli")):
        raise RefreshRefusal("fresh capture destinations must belong to this operation's original retained capture root")
    return plan, state, canonical_plan_sha256(plan)


def initialize(plan: dict, state: Path, plan_sha256: str) -> dict:
    """Receipt the empty native-created output before any phase can consume it.

    Args:
        plan: Validated immutable operation plan with distinct task and input identities.
        state: Durable operation evidence directory outside disposable output roots.
        plan_sha256: Digest binding evidence to the exact immutable operation plan.
    """
    original = read(state / "output-native-original.json")
    root = Path(plan["output_root"])
    if (original.get("plan_sha256") != plan_sha256 or original.get("path") != str(root)
            or original.get("task_id") != plan["task_id"] or any(root.iterdir())):
        raise RefreshRefusal("initial output must be empty and originally created for this plan")
    info = root.stat()
    record = {"schema": 1, "plan_sha256": plan_sha256, "task_id": plan["task_id"],
              "source_commit": plan["installer_commit"], "path": str(root),
              "worktree": str(ROOT), "repository": "mdaneri/Atlaso",
              "root_identity": WindowsFiles().snapshot(root)["."]["identity"],
              "stat_identity": [info.st_dev, info.st_ino], "kind": "generated_tree",
              "cleanup_tool": "scripts/cleanup-completed-task.ps1",
              "original_native_receipt_sha256": digest(state / "output-native-original.json"),
              "protected_files": protected_files(plan)}
    publish(state / "output-original.json", record)
    return record


def history(state: Path, plan_sha256: str) -> tuple[dict, dict]:
    """Refuse mismatched, pending or interrupted consumers before admitting another.

    Args:
        state: Durable operation evidence directory outside disposable output roots.
        plan_sha256: Digest binding evidence to the exact immutable operation plan.
    """
    results, starts = {}, {}
    for phase in PHASES:
        start, result = state / f"{phase}-intent.json", state / f"{phase}-result.json"
        if start.exists():
            starts[phase] = read(start)
        if result.exists():
            results[phase] = read(result)
            if results[phase].get("status") == "succeeded":
                report = state / f"{phase}-report.json"
                if digest(report) != results[phase].get("report_sha256"):
                    raise RefreshRefusal("successful phase report changed after original result publication")
        for value in (starts.get(phase), results.get(phase)):
            if value is not None and value.get("plan_sha256") != plan_sha256:
                raise RefreshRefusal("phase history belongs to another immutable plan")
        if phase in starts and (phase not in results or results[phase].get("whole_job_quiescent") is not True):
            raise RefreshRefusal("original phase has no proven terminal whole-job result; preserve and reconcile it")
    return results, starts


def source_input_sha256(repository: Path = ROOT) -> str:
    """Fingerprint capture requirements without conflating them with installer source.

    Args:
        repository: Trusted Atlaso checkout containing the admitted source files.
    """
    from scripts.installation.build import package_selection
    from scripts.installation.manifest import SOURCE_ISO_SHA512

    paths = ["image/common/powershell/powercli-lock.json", "image/common/scripts/configure_photon_repositories.py",
             "image/common/scripts/provision-atlaso.sh", "image/common/scripts/build-qemu-guest-agent-rpm.sh",
             "image/common/guest-agents/atlaso-qemu-guest-agent.spec", "image/common/guest-agents/qemu-guest-agent.service",
             "scripts/installation/guest_tools.py", "image/vmware-workstation/atlaso-photon.pkr.hcl"]
    paths += sorted(p.relative_to(repository).as_posix() for p in (repository / "image/common/photon-rpm-gpg").iterdir())
    value = {"files": {p: digest(repository / p) for p in paths},
             "packages": package_selection(repository), "photon_iso_sha512": SOURCE_ISO_SHA512}
    # Unrelated installer/UI/source edits do not invalidate unchanged captures.
    # New source still re-admits every signature, current identity and complete
    # transaction before reuse; this fingerprint is never a substitute for that.
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def protected_files(plan: dict) -> list[dict]:
    """Independently re-read the explicit protected file set without exposing contents.

    Args:
        plan: Validated immutable operation plan with distinct task and input identities.
    """
    records = []
    for item in plan["protected_files"]:
        if digest(Path(item["path"])) != item["sha256"]:
            raise RefreshRefusal("protected input file changed; preserve resources")
        info = Path(item["path"]).stat()
        records.append({**item, "identity": [info.st_dev, info.st_ino]})
    return records


def input_inventory(plan: dict) -> dict:
    """Bind the complete unchanged capture, rather than a subset of packages.

    Args:
        plan: Validated immutable operation plan with distinct task and input identities.
    """
    return {name: inventory(Path(plan[name])) for name in ("rpms", "powercli")}


def verify_protected_files(plan: dict, state: Path) -> list[dict]:
    """Compare content and original filesystem identity, including same-byte replacement.

    Args:
        plan: Validated immutable operation plan with distinct task and input identities.
        state: Durable operation evidence directory outside disposable output roots.
    """
    observed = protected_files(plan)
    if observed != read(state / "output-original.json").get("protected_files"):
        raise RefreshRefusal("protected input identity changed; preserve resources")
    return observed


def check_capture(plan: dict, state: Path) -> None:
    """Require genuine original capture provenance and source-compatible bytes.

    Args:
        plan: Validated immutable operation plan with distinct task and input identities.
        state: Durable operation evidence directory outside disposable output roots.
    """
    selector = plan["capture_receipt"]
    path = Path(selector["path"]) if selector else state / "capture-inputs.json"
    if selector and digest(path) != selector["sha256"]:
        raise RefreshRefusal("original capture receipt changed")
    receipt = read(path)
    original_path = Path(receipt["original_root_receipt"]["path"])
    if digest(original_path) != receipt["original_root_receipt"]["sha256"]:
        raise RefreshRefusal("original capture creation receipt changed")
    original = read(original_path)
    if (receipt.get("kind") != "installation-refresh-capture" or receipt.get("schema") != 1
            or original.get("source_commit") != receipt.get("source_commit")
            or original.get("task_id") != receipt.get("task_id")
            or receipt.get("repository") != "mdaneri/Atlaso"
            or receipt.get("source_input_sha256") != source_input_sha256()
            or receipt.get("rpms") != plan["rpms"] or receipt.get("powercli") != plan["powercli"]
            or receipt.get("inventory") != input_inventory(plan)):
        raise RefreshRefusal("capture provenance, complete bytes or source compatibility differs")
    capture_root = Path(original["path"])
    if any(Path(plan[name]) != capture_root / name for name in ("rpms", "powercli")):
        raise RefreshRefusal("capture input paths differ from their original retained root")
    with WindowsFiles().ancestors(capture_root), WindowsFiles().opened(capture_root, directory=True) as (_, identity, _):
        native_identity = f"{identity[0]:08X}:{identity[1]:08X}{identity[2]:08X}"
        if native_identity != original.get("native_identity"):
            raise RefreshRefusal("original capture root identity changed")
    completion = read(original_path.parent / "capture-result.json")
    report_path = original_path.parent / "capture-report.json"
    if (completion.get("status") != "succeeded" or completion.get("whole_job_quiescent") is not True
            or completion.get("plan_sha256") != original.get("plan_sha256")
            or completion.get("task_id") != receipt.get("task_id")
            or completion.get("installer_commit") != receipt.get("source_commit")
            or completion.get("report_sha256") != digest(report_path)
            or read(report_path).get("capture_receipt") != {"path": str(path), "sha256": digest(path)}):
        raise RefreshRefusal("capture original consumer has no matching proven terminal result")
    # Reuse reads the original owner's immutable evidence. It does not transfer
    # ownership or grant this workflow permission to remove those inputs.


def preflight(plan: dict, state: Path, plan_sha256: str, phase: str,
              *, old_rpm: Path | None = None, new_rpm: Path | None = None) -> dict:
    """Authorize one phase, reserve its original deadline and never replay it.

    Args:
        plan: Validated immutable operation plan with distinct task and input identities.
        state: Durable operation evidence directory outside disposable output roots.
        plan_sha256: Digest binding evidence to the exact immutable operation plan.
        phase: Fixed workflow phase whose original intent or result is being checked.
        old_rpm: Exact existing old package selected for diagnostic comparison only.
        new_rpm: Exact existing new package selected for diagnostic comparison only.
    """
    results, starts = history(state, plan_sha256)
    authorization = authorize_phase(phase, results, starts, plan=plan)
    if authorization["status"] != "authorized":
        raise RefreshRefusal(authorization["reason"])
    root = Path(plan["output_root"])
    resource = read(state / "output-original.json")
    if (resource.get("plan_sha256") != plan_sha256 or resource.get("path") != str(root)
            or resource.get("task_id") != plan["task_id"]):
        raise RefreshRefusal("output root lacks original before-use provenance")
    with WindowsFiles().opened(root, directory=True) as (_, native, _):
        native = list(native)
    if native != resource.get("root_identity"):
        raise RefreshRefusal("output root identity changed")
    if phase == "capture" and plan["capture_receipt"] is not None:
        raise RefreshRefusal("invalidated retained inputs require a distinct fresh-capture operation; preserve original capture")
    free = shutil.disk_usage(root).free
    if free < authorization["minimum_free_gib"] * 1024**3:
        raise RefreshRefusal(f"capacity_refusal: phase requires {authorization['minimum_free_gib']} GiB free")
    verify_protected_files(plan, state)
    now = datetime.now(UTC)
    intent = {
        "schema": 1, "intent_id": uuid.uuid4().hex, "phase": phase, "plan_sha256": plan_sha256,
        "operation_id": plan["operation_id"], "task_id": plan["task_id"],
        "installer_commit": plan["installer_commit"], "repository": "mdaneri/Atlaso",
        "source_input_sha256": source_input_sha256(), "started_utc": now.isoformat(),
        "deadline_utc": (now + timedelta(seconds=authorization["timeout_seconds"])).isoformat(),
        **authorization,
    }
    if phase == "compare":
        if old_rpm is None or new_rpm is None:
            raise RefreshRefusal("native comparison requires both exact original package paths")
        intent["comparison"] = {label: {"path": str(path.absolute()), "sha256": digest(path.absolute())}
                                for label, path in (("old", old_rpm), ("new", new_rpm))}
    publish(state / f"{phase}-intent.json", intent)
    return intent


def _call(script: str, arguments: list[str], *, powershell: bool = False) -> None:
    """Call only a checked-in canonical entry point inside the outer Windows job.

    Args:
        script: Repository-relative checked-in entry point selected by this workflow.
        arguments: Individual fixed-tool arguments passed without shell interpolation.
        powershell: Whether the checked-in entry point is a PowerShell script.
    """
    command = ["pwsh", "-NoProfile", "-File"] if powershell else [sys.executable, "-I", "-B"]
    subprocess.run([*command, str(ROOT / script), *arguments], check=True, cwd=ROOT)


def _capture_member_path(member: tarfile.TarInfo, prefix: str) -> PurePosixPath:
    """Validate one archive path independently of native extraction handles.

    Args:
        member: Untrusted archive member whose type, name and size must be admitted.
        prefix: Exact expected top-level directory in the captured archive.
    """
    name = PurePosixPath(member.name)
    if (name.is_absolute() or ".." in name.parts or "\\" in member.name or not name.parts
            or any(re.search(r'[<>:"|?*\x00-\x1f]', part) or part.endswith((".", " "))
                   or part.split(".", 1)[0].upper() in {
                       "CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
                       *(f"LPT{i}" for i in range(1, 10)),
                   } for part in name.parts)
            or name.parts[0] != prefix or not (member.isfile() or member.isdir())
            or member.size < 0 or member.size > 2 * 1024**3):
        raise RefreshRefusal("capture archive has an unsafe entry")
    return name


def _unpack(archive: Path, destination: Path, prefix: str) -> None:
    """Unpack a complete capture without links, replacement or unbounded extraction.

    Args:
        archive: Existing complete capture tar archive pinned before extraction.
        destination: Absent task-owned extraction directory under the original capture root.
        prefix: Exact expected top-level directory in the capture archive.
    """
    if destination.exists():
        raise RefreshRefusal("capture extraction destination already exists")
    from scripts.installation.iso import _checked_path, _open_pinned, _verify_pinned

    files = WindowsFiles()
    archive_pin = _open_pinned(archive)
    names, total = set(), 0
    with ExitStack() as pins:
        pins.callback(archive_pin.stream.close)
        pins.enter_context(files.ancestors(destination))
        destination.mkdir()
        pins.enter_context(files.opened(destination, directory=True))
        directories = {destination}
        stream = pins.enter_context(tarfile.open(fileobj=archive_pin.stream, mode="r:"))
        for member in stream:
            name = _capture_member_path(member, prefix)
            if member.name in names:
                raise RefreshRefusal("capture archive has an unsafe entry")
            names.add(member.name)
            total += member.size
            if len(names) > 100_000 or total > 16 * 1024**3:
                raise RefreshRefusal("capture archive exceeds its bound")
            relative = Path(*name.parts[1:])
            target = destination / relative
            required = [*reversed(target.parent.parents), target.parent]
            if member.isdir():
                required.append(target)
            for directory in required:
                if directory == destination or not directory.is_relative_to(destination):
                    continue
                if directory not in directories:
                    directory.mkdir()
                    pins.enter_context(files.opened(directory, directory=True))
                    directories.add(directory)
            _checked_path(target.parent, final_kind="directory")
            if member.isdir():
                continue
            elif member.isfile():
                source = stream.extractfile(member)
                if source is None:
                    raise RefreshRefusal("capture archive member is unreadable")
                with source, target.open("xb") as output:
                    shutil.copyfileobj(source, output, 1024**2)
                if target.stat().st_size != member.size:
                    raise RefreshRefusal("capture archive member was truncated")
        _verify_pinned(archive_pin)


def vm_arguments(plan: dict, state: Path) -> list[str]:
    """Use original emitted selectors, never discover or reconstruct ownership.

    Args:
        plan: Validated immutable operation plan with distinct task and input identities.
        state: Durable operation evidence directory outside disposable output roots.
    """
    documents = [read(state / "vm-selectors.json")]
    if (state / "boot-selectors.json").exists():
        documents.append(read(state / "boot-selectors.json"))
    built = read(state / "build-report.json")
    for document in documents:
        if (document.get("task_id") != plan["task_id"] or document.get("repository") != "mdaneri/Atlaso"
                or document.get("source_commit") != plan["installer_commit"]
                or document.get("worktree") != str(ROOT)
                or document.get("media", {}).get("path") != str(Path(plan["output_root"]) / "development.iso")
                or document.get("media", {}).get("sha256") != built["iso_sha256"]):
            raise RefreshRefusal("original VM selectors differ from this task, installer source or media")
    vm = documents[0]["selectors"]
    boot = documents[1]["selectors"] if len(documents) == 2 else None
    if boot and any(vm[key] != boot.get(key) for key in vm):
        raise RefreshRefusal("boot selectors differ from original VM and baseline selectors")
    arguments = [
        "-OutputDirectory", str(vm_root(plan)), "-PullRequestNumber", str(plan["pull_request_number"]),
        "-CollisionSuffix", plan["operation_id"], "-OriginalReceiptPath", vm["OriginalReceiptPath"],
        "-OriginalReceiptSha256", vm["OriginalReceiptSha256"], "-BaselineReceiptPath", vm["BaselineReceiptPath"],
        "-BaselineReceiptSha256", vm["BaselineReceiptSha256"],
    ]
    if boot:
        arguments += ["-BootReceiptPath", boot["BootReceiptPath"], "-BootReceiptSha256", boot["BootReceiptSha256"]]
    return arguments


def vm_root(plan: dict) -> Path:
    """Derive the same canonical identity as the owning installation harness.

    Args:
        plan: Validated immutable operation plan with distinct task and input identities.
    """
    return Path(plan["output_root"]) / f"Atlaso-PR-{plan['pull_request_number']}-installation-iso-{plan['operation_id']}"


def execute(plan: dict, state: Path, phase: str) -> dict:
    """Run exactly one fixed phase; errors preserve its resources and original intent.

    Args:
        plan: Validated immutable operation plan with distinct task and input identities.
        state: Durable operation evidence directory outside disposable output roots.
        phase: Fixed workflow phase whose original intent or result is being checked.
    """
    root = Path(plan["output_root"])
    iso = root / "development.iso"
    capabilities = {}
    if phase in {"capture", "admit", "build"}:
        if plan.get("native_distribution"):
            from scripts.native_rpm_tools import run

            for name in ("rpm", "rpmkeys", "createrepo_c"):
                capabilities[name] = run([name, "--version"], byte_limit=8192).strip()
        elif any(shutil.which(name) is None for name in ("rpm", "rpmkeys", "createrepo_c")):
            raise RefreshRefusal("native RPM tools missing; select a preconfigured native_distribution before capture")
    if phase == "compare":
        from scripts.installation.refresh_drift import (
            compare_native_packages,
            inspect_native_package,
        )

        selection = read(state / "compare-intent.json")["comparison"]
        for item in selection.values():
            if digest(Path(item["path"])) != item["sha256"]:
                raise RefreshRefusal("native review input changed after original admission")
        return compare_native_packages(inspect_native_package(Path(selection["old"]["path"])),
                                       inspect_native_package(Path(selection["new"]["path"])))
    if phase in {"drift", "admit"}:
        from scripts.installation.refresh_drift import inspect_capture
        report = inspect_capture(ROOT, Path(plan["rpms"]))
        report["native_capabilities"] = capabilities
        disposition = {"current": "reuse", "stale_metadata": "requires_capture",
                       "requires_capture": "requires_capture", "requires_review": "requires_review"}[report["status"]]
        if phase == "admit":
            if disposition != "reuse":
                raise RefreshRefusal("current metadata or runtime profile changed; new reviewed operation required")
            check_capture(plan, state)
            from scripts.installation.build import verify_rpms
            scratch = root / "admission"
            scratch.mkdir()
            report["authenticated_rpm_inventory"] = verify_rpms(Path(plan["rpms"]), ROOT, scratch)
            report["authenticated_transaction_validated"] = True
        return {"disposition": disposition, "report": report}
    if phase == "capture":
        # Root creation and its original receipt are emitted by the native adapter
        # before the canonical credential-consuming builder can see this directory.
        _call("scripts/windows/vmware/invoke-installation-refresh-capture.ps1", [
            "-Plan", str(state / "plan.json"), "-StateDirectory", str(state),
        ], powershell=True)
        original = state / "capture-root-original.json"
        capture = captured_root(state, plan)
        creation = read(original)
        files = WindowsFiles()
        with files.ancestors(capture), files.opened(capture, directory=True) as (_, identity, _):
            native_identity = f"{identity[0]:08X}:{identity[1]:08X}{identity[2]:08X}"
            if creation.get("path") != str(capture) or creation.get("native_identity") != native_identity:
                raise RefreshRefusal("original capture root changed before extraction")
            _unpack(capture / "installation-rpms.tar", Path(plan["rpms"]), "atlaso-installation-rpms")
            _unpack(capture / "installation-powercli.tar", Path(plan["powercli"]), "Modules")
        receipt = {"schema": 1, "kind": "installation-refresh-capture", "repository": "mdaneri/Atlaso",
                   "task_id": plan["task_id"], "source_commit": plan["installer_commit"],
                   "source_input_sha256": source_input_sha256(), "rpms": plan["rpms"], "powercli": plan["powercli"],
                   "original_root_receipt": {"path": str(original), "sha256": digest(original)},
                   "inventory": input_inventory(plan)}
        publish(state / "capture-inputs.json", receipt)
        return {"capture_receipt": {"path": str(state / "capture-inputs.json"), "sha256": digest(state / "capture-inputs.json")},
                "native_capabilities": capabilities}
    if phase == "build":
        check_capture(plan, state)
        scratch = root / "build-scratch"
        scratch.mkdir()
        software = plan["software"]
        _call("scripts/build_development_installation_iso.py", [
            "--commit", plan["installer_commit"], "--software-version", software["version"],
            "--software-commit", software["source_commit"], "--software", software["path"],
            "--rpms", plan["rpms"], "--powercli", plan["powercli"], "--payload", str(root / "payload"),
            "--scratch", str(scratch), "--source-iso", plan["source_iso"], "--output", str(iso), "--serial-console",
        ])
        check_capture(plan, state)
        return {"iso_sha256": digest(iso), "installer_commit": plan["installer_commit"], "software": software,
                "native_capabilities": capabilities}
    if phase == "readback":
        from scripts.installation.readback import full_readback
        built = read(state / "build-report.json")
        check_capture(plan, state)
        selector = plan["capture_receipt"]
        capture = read(Path(selector["path"]) if selector else state / "capture-inputs.json")
        return full_readback(iso, built["iso_sha256"], installer_commit=plan["installer_commit"],
                             software_commit=plan["software"]["source_commit"], software_version=plan["software"]["version"],
                             capture_inventory=capture["inventory"])
    if phase == "install":
        built = read(state / "build-report.json")
        _call("scripts/windows/vmware/invoke-installation-iso-test.ps1", [
            "-IsoPath", str(iso), "-IsoSha256", built["iso_sha256"], "-OutputDirectory", str(vm_root(plan)),
            "-PullRequestNumber", str(plan["pull_request_number"]), "-CollisionSuffix", plan["operation_id"],
            "-Scenario", "AutoReboot", "-InspectInstalled", "-InspectContent", "-InspectionPythonPath", sys.executable,
            "-TimeoutSeconds", "3500", "-ReceiptDirectory", str(state),
        ], powershell=True)
        return {"native_install_reboot_accounts_and_content": "passed", "vm": str(vm_root(plan))}
    if phase in {"verify", "cleanup"}:
        _call("scripts/windows/vmware/test-installation-iso.ps1", [
            "-Mode", "Verify" if phase == "verify" else "Cleanup", *vm_arguments(plan, state), "-Confirm:$false",
        ], powershell=True)
        if phase == "cleanup" and vm_root(plan).exists():
            raise RefreshRefusal("owning cleanup returned with VM output still present")
        if phase == "cleanup" and (state / "capture-result.json").exists():
            _call("scripts/windows/vmware/invoke-installation-refresh-capture.ps1", [
                "-Plan", str(state / "plan.json"), "-StateDirectory", str(state), "-Cleanup",
            ], powershell=True)
        return {"canonical_vm_phase": phase, "vm_output_absent": not vm_root(plan).exists()}
    if phase == "protected":
        if vm_root(plan).exists():
            raise RefreshRefusal("cleaned VM output reappeared")
        return {"protected_files": verify_protected_files(plan, state), "scope": "explicit file identities and content; no unrelated VM operations",
                "vm_output_absent": not vm_root(plan).exists(), "source_inputs": "retained under original owner"}
    raise RefreshRefusal("unsupported refresh phase")


def assert_native_child(path: Path, plan: dict, plan_sha256: str, phase: str, state: Path) -> None:
    """Require the exact suspended child and named Windows job, never a raw replay.

    Args:
        path: Original native child receipt selected for this exact phase.
        plan: Validated immutable operation plan with distinct task and input identities.
        plan_sha256: Digest binding evidence to the exact immutable operation plan.
        phase: Fixed workflow phase whose original intent or result is being checked.
        state: Durable operation evidence directory outside disposable output roots.
    """
    if os.name != "nt" or path != state / f"{phase}-child.json":
        raise RefreshRefusal("refresh consumers require the native Windows job owner")
    record = read(path)
    if (record.get("pid") != os.getpid() or record.get("task_id") != plan["task_id"]
            or record.get("phase") != phase or record.get("plan_sha256") != plan_sha256):
        raise RefreshRefusal("refresh worker differs from its original native child")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenJobObjectW.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_wchar_p]
    kernel.OpenJobObjectW.restype = ctypes.c_void_p
    kernel.GetCurrentProcess.restype = ctypes.c_void_p
    kernel.IsProcessInJob.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    handle = kernel.OpenJobObjectW(4, False, record["job_name"])
    if not handle:
        raise RefreshRefusal("original refresh process job is unavailable")
    try:
        member = ctypes.c_int()
        if not kernel.IsProcessInJob(kernel.GetCurrentProcess(), handle, ctypes.byref(member)) or not member.value:
            raise RefreshRefusal("refresh worker is outside its originally published process job")
    finally:
        kernel.CloseHandle(handle)


def main(argv: list[str] | None = None) -> int:
    """Serve the fixed native launcher protocol; never accept caller command text.

    Args:
        argv: Optional command-line argument list; None uses the process arguments.
    """
    for name in list(os.environ):
        if name.upper().startswith("GIT_") and name.upper() != "GIT_ASKPASS":
            os.environ.pop(name)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("create-plan", "describe", "initialize", "preflight", "run", "status"))
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--configured-root", type=Path)
    parser.add_argument("--phase", choices=PHASES)
    parser.add_argument("--child-receipt", type=Path)
    parser.add_argument("--old-rpm", type=Path)
    parser.add_argument("--new-rpm", type=Path)
    for name in ("software", "source-iso", "output-root", "rpms", "powercli", "capture-receipt"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--software-version")
    parser.add_argument("--software-commit")
    parser.add_argument("--pull-request-number", type=int)
    parser.add_argument("--capture-receipt-sha256")
    parser.add_argument("--native-distribution")
    parser.add_argument("--protected-file", type=Path, action="append", default=[])
    args = parser.parse_args(argv)
    configured_root = supported_root()
    if args.configured_root is not None and args.configured_root != configured_root:
        raise RefreshRefusal("caller root differs from the active supported configuration")
    if args.action == "create-plan":
        if any(value is None for value in (args.software, args.source_iso, args.output_root,
                                           args.software_version, args.software_commit, args.pull_request_number)):
            raise RefreshRefusal("plan creation requires exact software, source ISO, capture, output and PR selectors")
        if args.plan.name != "plan.json" or not args.plan.is_absolute() or args.output_root.exists():
            raise RefreshRefusal("select a new absolute plan.json and absent output root")
        state = args.plan.parent
        if (not state.is_relative_to(configured_root) or state.is_relative_to(ROOT)
                or ROOT.is_relative_to(state) or not state.is_dir()):
            raise RefreshRefusal("plan requires an existing external durable state directory")
        if bool(args.capture_receipt) != bool(args.capture_receipt_sha256):
            raise RefreshRefusal("reuse requires both original capture receipt selectors")
        if args.capture_receipt is not None and (args.rpms is None or args.powercli is None):
            raise RefreshRefusal("reuse requires both original retained capture directories")
        operation_id = uuid.uuid4().hex
        if args.capture_receipt is None:
            capture = captured_root(state, {"operation_id": operation_id})
            expected = {name: capture / name for name in ("rpms", "powercli")}
            if args.rpms not in (None, expected["rpms"]) or args.powercli not in (None, expected["powercli"]):
                raise RefreshRefusal("fresh capture paths are derived from the original durable operation root")
            args.rpms, args.powercli = expected["rpms"], expected["powercli"]
        value = {
            "schema": 1, "operation_id": operation_id,
            "task_id": os.environ.get("CODEX_THREAD_ID"),
            "installer_commit": subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip(),
            "software": {"path": str(args.software), "version": args.software_version, "source_commit": args.software_commit},
            "source_iso": str(args.source_iso), "rpms": str(args.rpms), "powercli": str(args.powercli),
            "native_distribution": args.native_distribution,
            "output_root": str(args.output_root), "pull_request_number": args.pull_request_number,
            "protected_files": [{"path": str(path), "sha256": digest(path)} for path in args.protected_file],
            "capture_receipt": {"path": str(args.capture_receipt), "sha256": args.capture_receipt_sha256} if args.capture_receipt else None,
        }
        validate_plan(value, configured_root=str(configured_root), worktree=str(ROOT))
        publish(args.plan, value)
        print(json.dumps({"plan": str(args.plan), "plan_sha256": canonical_plan_sha256(value)}))
        return 0
    plan, state, plan_hash = context(args.plan, configured_root)
    if args.action == "describe":
        print(json.dumps({"plan": plan, "plan_sha256": plan_hash, "state": str(state)}))
    elif args.action == "initialize":
        print(json.dumps(initialize(plan, state, plan_hash)))
    elif args.action == "status":
        results, starts = history(state, plan_hash)
        print(json.dumps({"phases": results, "next": next_phase(results, starts, plan=plan)}))
    elif args.action == "preflight":
        if args.phase is None:
            raise RefreshRefusal("preflight requires a phase")
        print(json.dumps(preflight(plan, state, plan_hash, args.phase, old_rpm=args.old_rpm, new_rpm=args.new_rpm)))
    else:
        if args.phase is None or args.child_receipt is None:
            raise RefreshRefusal("run requires its original phase and native child selectors")
        assert_native_child(args.child_receipt, plan, plan_hash, args.phase, state)
        intent = read(state / f"{args.phase}-intent.json")
        if (intent.get("plan_sha256") != plan_hash or (state / f"{args.phase}-result.json").exists()
                or datetime.now(UTC) >= datetime.fromisoformat(intent["deadline_utc"])):
            raise RefreshRefusal("phase original identity or deadline is invalid")
        temporary = Path(plan["output_root"]) / (args.phase + "-temporary")
        temporary.mkdir()
        for variable in ("TMP", "TEMP", "TMPDIR", "XDG_CACHE_HOME"):
            os.environ[variable] = str(temporary)
        os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
        os.environ.pop("ATLASO_NATIVE_RPM_CONTEXT", None)
        if plan.get("native_distribution"):
            native_directory = temporary / "native-tools"
            native_directory.mkdir()
            native_context = temporary / "native-context.json"
            publish(native_context, {"task_id": plan["task_id"], "source_commit": plan["installer_commit"],
                                    "directory": str(native_directory), "distribution": plan["native_distribution"],
                                    "deadline_epoch": datetime.fromisoformat(intent["deadline_utc"]).timestamp()})
            os.environ["ATLASO_NATIVE_RPM_CONTEXT"] = str(native_context)
        if os.name == "nt" and shutil.which("openssl") is None:
            git = shutil.which("git")
            if git:
                directory = Path(git).parent.parent / "mingw64/bin"
                if (directory / "openssl.exe").is_file():
                    os.environ["PATH"] = str(directory) + os.pathsep + os.environ["PATH"]
        report = execute(plan, state, args.phase)
        publish(state / f"{args.phase}-report.json", report)
        print(json.dumps({"phase": args.phase, "report_published": True}))
    return 0
