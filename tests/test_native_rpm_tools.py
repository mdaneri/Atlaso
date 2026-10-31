"""Native tool protocol admission, original publication ordering and interruption checks."""

from __future__ import annotations

import base64
import io
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from scripts import native_rpm_tools as native


@pytest.fixture
def native_context(tmp_path, monkeypatch):
    """Create a bound native-tool protocol context for one test.

    Args:
        tmp_path: Isolated root for the context and native evidence files.
        monkeypatch: Pytest patcher for the protocol environment variables.
    """
    directory = tmp_path / "native"
    directory.mkdir()
    context = tmp_path / "context.json"
    context.write_text(json.dumps({"task_id": "actual-task", "source_commit": "a" * 40,
                                  "directory": str(directory), "distribution": "FixtureLinux",
                                  "deadline_epoch": time.time() + 90}))
    monkeypatch.setenv(native.CONTEXT, str(context))
    monkeypatch.setenv("CODEX_THREAD_ID", "actual-task")
    monkeypatch.setenv("SystemRoot", r"C:\Windows")
    return directory


def test_drive_paths_are_translated_without_shell_interpretation():
    assert native.linux_path(r"E:\source with spaces\package.rpm") == "/mnt/e/source with spaces/package.rpm"
    assert native.linux_path("--qf") == "--qf"
    assert native.linux_path("%{NAME}\\n") == "%{NAME}\\n"
    with pytest.raises(ValueError, match="unc"):
        native.linux_path(r"\\host\share\package.rpm")


class GuestProtocol:
    """Model the two-sided pipe barrier without executing a native utility."""

    def __init__(self, directory: Path, *, pending: bool = False):
        """Initialize a fake native guest protocol endpoint.

        Args:
            directory: Root where the parent publishes original evidence.
            pending: Whether the guest reports unproven process-group completion.
        """
        self.stdin = io.BytesIO()
        self.stdout = self
        self.directory = directory
        self.pending = pending
        self.step = 0

    def readline(self, maximum):
        """Return the next synthetic guest protocol message.

        Args:
            maximum: Maximum requested line length from the protocol reader.
        """
        self.step += 1
        lines = self.stdin.getvalue().splitlines()
        request = json.loads(lines[0])
        original = {"schema": 1, "kind": "native-tool-original", "request_id": request["request_id"],
                    "task_id": request["task_id"], "source_commit": request["source_commit"],
                    "pid": 123, "group": 123, "start_ticks": "1000", "deadline_epoch": request["deadline_epoch"]}
        if self.step == 1:
            assert len(lines) == 1
            return json.dumps(original).encode() + b"\n"
        original_path = self.directory / (request["request_id"] + "-original.json")
        assert original_path.is_file(), "Linux tool released before its original selector was durable"
        assert json.loads(lines[1]) == {"release": request["request_id"]}
        if self.pending:
            return b'{"kind":"native-tool-failure","whole_group_quiescent":false}\n'
        return json.dumps({"kind": "native-tool-result", "request_id": request["request_id"],
                           "pid": 123, "start_ticks": "1000", "returncode": 0, "whole_group_quiescent": True,
                           "output": base64.b64encode(b"rpm version fixture\n").decode()}).encode() + b"\n"

    def wait(self, timeout):
        """Report fake process completion to the parent protocol.

        Args:
            timeout: Maximum wait requested by the protocol caller.
        """
        return 0

    def close(self):
        pass


def test_native_tool_cannot_execute_until_original_publication(native_context, monkeypatch):
    """Require durable Linux identity publication before tool execution.

    Args:
        native_context: Isolated context and evidence directory fixture.
        monkeypatch: Pytest patcher for the fake guest process.
    """
    monkeypatch.setattr(native.subprocess, "Popen", lambda *args, **kwargs: GuestProtocol(native_context))
    assert native.run(["rpm", "--version"]) == "rpm version fixture\n"
    assert native.quiescent(native_context) is True
    result = json.loads(next(native_context.glob("*-result.json")).read_bytes())
    assert result["whole_group_quiescent"] is True
    assert "output" not in result


def test_missing_linux_completion_is_preserved_and_never_assumed_quiescent(native_context, monkeypatch):
    """Preserve missing guest completion evidence and refuse quiescence.

    Args:
        native_context: Isolated context and evidence directory fixture.
        monkeypatch: Pytest patcher for the pending guest process.
    """
    monkeypatch.setattr(native.subprocess, "Popen", lambda *args, **kwargs: GuestProtocol(native_context, pending=True))
    with pytest.raises(RuntimeError, match="quiescence_unproven"):
        native.run(["rpm", "--version"])
    assert list(native_context.glob("*-original.json"))
    assert not list(native_context.glob("*-result.json"))
    assert native.quiescent(native_context) is False


def test_tool_allowlist_refuses_an_arbitrary_command_before_process_creation(native_context, monkeypatch):
    """Reject commands outside the fixed native-tool allowlist before spawning.

    Args:
        native_context: Isolated context and evidence directory fixture.
        monkeypatch: Pytest patcher that detects attempted process creation.
    """
    def forbidden(*args, **kwargs):
        """Fail if the native protocol attempts to create a process.

        Args:
            *args: Positional process-creation arguments.
            **kwargs: Keyword process-creation options.
        """
        raise AssertionError("Process creation must not occur")

    monkeypatch.setattr(native.subprocess, "Popen", forbidden)
    with pytest.raises(ValueError, match="allowlisted"):
        native.run(["sh", "-c", "arbitrary"])
    assert list(native_context.iterdir()) == []


@pytest.mark.skipif(os.name == "nt", reason="Linux process birth and session proof")
def test_guest_group_inspection_does_not_include_an_unrelated_session():
    from scripts.native_rpm_tools_guest import birth, live_group

    assert birth(os.getpid()).isdecimal()
    assert os.getpid() in live_group(os.getpgrp())
    assert os.getpid() not in live_group(2**30)


@pytest.mark.skipif(os.name == "nt", reason="Linux fork, timeout and process-group integration")
@pytest.mark.parametrize("release", [True, False])
def test_real_linux_child_waits_for_original_receipt_and_is_quiescent_after_owner_exit(tmp_path, release):
    """Verify the Linux child waits for its selector and exits its process group.

    Args:
        tmp_path: Isolated working directory for the child process fixture.
        release: Whether to release the child after publishing its original selector.
    """
    from scripts.native_rpm_tools_guest import live_group

    executable = "/usr/bin/printf" if release else "/usr/bin/touch"
    marker = tmp_path / "must-not-exist"
    code = (
        "from pathlib import Path;from scripts import native_rpm_tools_guest as g;"
        f"g.TOOLS['rpm']=Path({executable!r});raise SystemExit(g.main())"
    )
    child = subprocess.Popen([sys.executable, "-B", "-c", code], cwd=native.ROOT,
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        request = {"request_id": "fixture", "tool": "rpm", "arguments": ["fixture-output"] if release else [str(marker)],
                   "cwd": str(tmp_path), "task_id": "fixture-task", "source_commit": "a" * 40,
                   "deadline_epoch": time.time() + 20}
        child.stdin.write(json.dumps(request).encode() + b"\n")
        child.stdin.flush()
        original = json.loads(child.stdout.readline(65536))
        assert original["kind"] == "native-tool-original"
        assert original["pid"] in live_group(original["group"])
        assert not marker.exists()
        (tmp_path / "original.json").write_text(json.dumps(original))
        if release:
            child.stdin.write(b'{"release":"fixture"}\n')
            child.stdin.flush()
            result = json.loads(child.stdout.readline(65536))
            assert result["whole_group_quiescent"] is True
            assert base64.b64decode(result["output"]) == b"fixture-output"
            assert result["pid"] == original["pid"]
        child.stdin.close()
        child.wait(timeout=20)
        assert not live_group(original["group"])
        assert not marker.exists()
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=10)
        for stream in (child.stdin, child.stdout, child.stderr):
            if stream and not stream.closed:
                stream.close()
