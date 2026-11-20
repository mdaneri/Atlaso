"""Receipt-bound Windows-to-Linux native RPM tool adapter for ISO refreshes."""

from __future__ import annotations

import atexit
import base64
import hashlib
import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path, PureWindowsPath

from scripts.completed_task_files import publish_durable_file, read_bounded_regular

CONTEXT = "ATLASO_NATIVE_RPM_CONTEXT"
MAX_OUTPUT = 4 * 1024**2
ROOT = Path(__file__).resolve().parents[1]
_SSH: dict = {}


def close_ssh() -> None:
    """Close the phase proxy only after Linux child completion and remote-root removal."""
    if not _SSH:
        return
    state = dict(_SSH)
    _SSH.clear()
    process = state["process"]
    try:
        if process.poll() is not None:
            raise RuntimeError("native_ssh_proxy_already_exited")
        process.stdin.write(b'{"close":true}\n')
        process.stdin.flush()
        raw = process.stdout.readline(65537)
        if len(raw) > 65536:
            raise RuntimeError("native_ssh_session_result_limit")
        result = json.loads(raw)
        context = state["context"]
        if (result.get("kind") != "native-ssh-result" or result.get("scope") != context["remote_id"]
                or result.get("task_id") != context["task_id"]
                or result.get("source_commit") != context["source_commit"]
                or result.get("whole_group_quiescent") is not True or result.get("remote_root_absent") is not True):
            raise RuntimeError("native_ssh_session_completion_unproven")
        process.stdin.close()
        if process.wait(timeout=10) != 0:
            raise RuntimeError("native_ssh_proxy_completion_unproven")
        publish(state["result_path"], result)
    finally:
        if process.stdin and not process.stdin.closed:
            try:
                process.stdin.close()
            except OSError:
                pass
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
        process.stdout.close()


def _ssh_proxy(context: dict) -> subprocess.Popen:
    """Start one credential-isolated proxy and durably admit its new remote root.

    Args:
        context: Original phase context, with public SSH and path selectors.
    """
    if _SSH:
        if _SSH["binding"] != context:
            raise ValueError("native_ssh_context_changed")
        return _SSH["process"]
    identifier = uuid.uuid4().hex
    selected = {**context, "remote_id": identifier + "-" + context["phase"]}
    directory = Path(context["directory"])
    path = directory / (identifier + "-ssh-context.json")
    publish(path, selected)
    process = subprocess.Popen([
        "pwsh", "-NoProfile", "-File", str(ROOT / "scripts/windows/vmware/Invoke-AtlasoNativeRpmSsh.ps1"),
        "-ContextPath", str(path), "-PythonPath", sys.executable,
    ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    _SSH.update(process=process, binding=context, context=selected,
                result_path=directory / (identifier + "-ssh-result.json"))
    raw = process.stdout.readline(65537)
    if not raw or len(raw) > 65536:
        raise RuntimeError("native_ssh_session_original_limit")
    original = json.loads(raw)
    if original.get("kind") == "native-ssh-start-failure":
        stage = original.get("stage")
        if stage not in {"context", "job", "credential-configuration", "runtime", "dpapi", "proxy"}:
            stage = "unknown"
        raise RuntimeError("native_ssh_start_failed_" + stage)
    if (original.get("kind") != "native-ssh-original" or original.get("scope") != selected["remote_id"]
            or original.get("path") != "/var/tmp/atlaso-rpm-" + selected["remote_id"]
            or original.get("task_id") != context["task_id"]
            or original.get("source_commit") != context["source_commit"]
            or not isinstance(original.get("identity"), list) or len(original["identity"]) != 2
            or not all(type(item) is int for item in original["identity"])
            or not isinstance(original.get("boot_id"), str)):
        raise RuntimeError("native_ssh_session_original_invalid")
    publish(directory / (identifier + "-ssh-original.json"), original)
    process.stdin.write(json.dumps({"release_session": selected["remote_id"]}).encode() + b"\n")
    process.stdin.flush()
    return process


def _run_ssh(context: dict, request: dict, byte_limit: int) -> str:
    """Use the same original-publication and release barrier over an admitted SSH session.

    Args:
        context: Original immutable phase context.
        request: Bounded fixed-tool request with Windows path selectors.
        byte_limit: Maximum accepted native stdout.
    """
    process = _ssh_proxy(context)
    directory = Path(context["directory"])
    identifier = request["request_id"]
    publish(directory / (identifier + "-intent.json"), {**request, "ssh": context["ssh"]})
    process.stdin.write(json.dumps(request).encode() + b"\n")
    process.stdin.flush()
    raw = process.stdout.readline(65537)
    if len(raw) > 65536:
        raise RuntimeError("native_tool_original_output_limit")
    original = json.loads(raw)
    if (original.get("kind") != "native-tool-original" or original.get("request_id") != identifier
            or original.get("task_id") != request["task_id"] or original.get("source_commit") != request["source_commit"]
            or type(original.get("pid")) is not int or original["pid"] <= 1
            or original.get("group") != original["pid"] or not str(original.get("start_ticks", "")).isdecimal()
            or original.get("deadline_epoch") != request["deadline_epoch"]):
        raise RuntimeError("native_tool_original_binding_invalid")
    publish(directory / (identifier + "-original.json"), original)
    process.stdin.write(json.dumps({"release": identifier}).encode() + b"\n")
    process.stdin.flush()
    raw = process.stdout.readline(2 * MAX_OUTPUT + 65537)
    if len(raw) > 2 * MAX_OUTPUT + 65536:
        raise RuntimeError("native_tool_result_output_limit")
    result = json.loads(raw)
    if (result.get("kind") != "native-tool-result" or result.get("request_id") != identifier
            or result.get("pid") != original["pid"] or result.get("start_ticks") != original["start_ticks"]
            or result.get("whole_group_quiescent") is not True):
        raise RuntimeError("native_tool_quiescence_unproven")
    output = base64.b64decode(result.pop("output"), validate=True)
    if len(output) > byte_limit:
        raise RuntimeError("native_tool_output_limit")
    result.update(output_bytes=len(output), output_sha256=hashlib.sha256(output).hexdigest())
    publish(directory / (identifier + "-result.json"), result)
    if result["returncode"] != 0:
        raise SystemExit("Native RPM tool failed after proven Linux group quiescence")
    return output.decode("utf-8", "strict")


atexit.register(close_ssh)


def linux_path(value: str) -> str:
    """Translate an absolute local drive path without invoking a shell or distro mutation.

    Args:
        value: Single native argument; absolute local drive paths are translated to /mnt.
    """
    path = PureWindowsPath(value)
    if path.drive and path.is_absolute():
        if len(path.drive) != 2 or path.drive[1] != ":":
            raise ValueError("native_tool_unc_path_refused")
        return "/mnt/" + path.drive[0].lower() + "/" + "/".join(path.parts[1:])
    return value


def publish(path: Path, value: dict) -> None:
    """Publish native selector/result evidence through Windows write-through rename.

    Args:
        path: Absent durable native invocation evidence filename.
        value: Bounded non-secret original selector or terminal result object.
    """
    stage = path.with_name("." + path.name + ".pending")
    with stage.open("xb") as stream:
        stream.write(json.dumps(value, separators=(",", ":")).encode("utf-8"))
        stream.flush()
        os.fsync(stream.fileno())
    publish_durable_file(stage, path)


def run(arguments: list[str], *, cwd: Path | None = None, byte_limit: int = MAX_OUTPUT,
        timeout_seconds: int = 120) -> str:
    """Execute only a fixed native utility after preserving its original Linux selectors.

    Args:
        arguments: Individual fixed-tool arguments passed without shell interpolation.
        cwd: Exact working directory translated for the selected existing Linux distribution.
        byte_limit: Hard maximum combined native diagnostic output size in bytes.
        timeout_seconds: Fixed native invocation budget clipped to the original phase deadline.
    """
    context = json.loads(read_bounded_regular(Path(os.environ[CONTEXT]), 65536))
    if context["task_id"] != os.environ.get("CODEX_THREAD_ID") or not arguments:
        raise ValueError("native_tool_task_binding_invalid")
    tool = arguments[0]
    if tool not in {"rpm", "rpmkeys", "createrepo_c"}:
        raise ValueError("native_tool_not_allowlisted")
    request_id = uuid.uuid4().hex
    directory = Path(context["directory"])
    if type(timeout_seconds) is not int or not 7 <= timeout_seconds <= 120:
        raise ValueError("native_tool_timeout_invalid")
    deadline = min(time.time() + timeout_seconds, context["deadline_epoch"])
    if deadline - time.time() < 7:
        raise ValueError("native_tool_original_deadline_expired")
    if context.get("ssh"):
        # SDK preparation and host admission use the phase budget. The native
        # command gets its original, bounded deadline only after proxy admission.
        _ssh_proxy(context)
        deadline = min(time.time() + timeout_seconds, context["deadline_epoch"])
        return _run_ssh(context, {"schema": 1, "request_id": request_id, "tool": tool,
                                 "arguments": arguments[1:], "cwd": str(cwd or ROOT),
                                 "deadline_epoch": deadline, "task_id": context["task_id"],
                                 "source_commit": context["source_commit"]}, byte_limit)
    request = {"schema": 1, "request_id": request_id, "tool": tool,
               "arguments": [linux_path(item) for item in arguments[1:]],
               "cwd": linux_path(str(cwd or ROOT)), "deadline_epoch": deadline,
               "task_id": context["task_id"], "source_commit": context["source_commit"]}
    publish(directory / (request_id + "-intent.json"), {**request, "distribution": context["distribution"]})
    wsl = Path(os.environ["SystemRoot"]) / "System32/wsl.exe"
    command = [str(wsl), "--distribution", context["distribution"], "--exec", "/usr/bin/python3", "-I", "-S", "-B",
               linux_path(str(ROOT / "scripts/native_rpm_tools_guest.py"))]
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        if process.stdin is None or process.stdout is None:
            raise RuntimeError("native_tool_protocol_unavailable")
        process.stdin.write(json.dumps(request).encode("utf-8") + b"\n")
        process.stdin.flush()
        raw = process.stdout.readline(65537)
        if len(raw) > 65536:
            raise RuntimeError("native_tool_original_output_limit")
        original = json.loads(raw)
        if (original.get("kind") != "native-tool-original" or original.get("request_id") != request_id
                or original.get("task_id") != context["task_id"] or original.get("source_commit") != context["source_commit"]
                or type(original.get("pid")) is not int or original["pid"] <= 1
                or original.get("group") != original["pid"] or not str(original.get("start_ticks", "")).isdecimal()
                or original.get("deadline_epoch") != deadline):
            raise RuntimeError("native_tool_original_binding_invalid")
        publish(directory / (request_id + "-original.json"), original)
        # The Linux child remains behind its pipe barrier until the preceding
        # native selector publication is durable on the Windows host.
        process.stdin.write(json.dumps({"release": request_id}).encode("utf-8") + b"\n")
        process.stdin.flush()
        raw_result = process.stdout.readline(2 * MAX_OUTPUT + 65537)
        if len(raw_result) > 2 * MAX_OUTPUT + 65536:
            raise RuntimeError("native_tool_result_output_limit")
        result = json.loads(raw_result)
        if (result.get("kind") != "native-tool-result" or result.get("request_id") != request_id
                or result.get("pid") != original["pid"] or result.get("start_ticks") != original["start_ticks"]
                or result.get("whole_group_quiescent") is not True):
            raise RuntimeError("native_tool_quiescence_unproven")
        output = base64.b64decode(result.pop("output"), validate=True)
        if len(output) > byte_limit:
            raise RuntimeError("native_tool_output_limit")
        process.stdin.close()
        if process.wait(timeout=10) != 0:
            raise RuntimeError("native_tool_supervisor_completion_unproven")
        result.update(output_bytes=len(output), output_sha256=hashlib.sha256(output).hexdigest())
        publish(directory / (request_id + "-result.json"), result)
        if result["returncode"] != 0:
            raise SystemExit("Native RPM tool failed after proven Linux group quiescence")
        return output.decode("utf-8", "strict")
    finally:
        if process.stdin and not process.stdin.closed:
            process.stdin.close()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            # Windows job containment still owns this launcher. Missing Linux
            # results remain actionable; never infer Linux cleanup from this kill.
            process.kill()
            process.wait(timeout=10)
        if process.stdout:
            process.stdout.close()


def quiescent(directory: Path) -> bool:
    """Require an original, matching terminal Linux result for every native intent.

    Args:
        directory: Phase-owned native protocol directory containing original selectors and results.
    """
    for original in directory.glob("*-ssh-original.json"):
        path = original.with_name(original.name.removesuffix("-original.json") + "-result.json")
        if not path.is_file():
            return False
        binding = json.loads(read_bounded_regular(original, 65536))
        result = json.loads(read_bounded_regular(path, 65536))
        if (result.get("whole_group_quiescent") is not True or result.get("remote_root_absent") is not True
                or any(result.get(key) != binding.get(key) for key in ("scope", "task_id", "source_commit"))):
            return False
    for intent in directory.glob("*-intent.json"):
        name = intent.name.removesuffix("-intent.json")
        original_path, result_path = directory / (name + "-original.json"), directory / (name + "-result.json")
        if not original_path.is_file() or not result_path.is_file():
            return False
        original = json.loads(read_bounded_regular(original_path, 65536))
        result = json.loads(read_bounded_regular(result_path, 65536))
        if (result.get("whole_group_quiescent") is not True or result.get("request_id") != original.get("request_id")
                or result.get("pid") != original.get("pid") or result.get("start_ticks") != original.get("start_ticks")):
            return False
    return True
