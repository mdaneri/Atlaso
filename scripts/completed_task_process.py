"""Contain cleanup children so a refusal cannot leave a mutating helper running."""

from __future__ import annotations

import ctypes
import os
import signal
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path

from scripts.completed_task_files import FileRefusal


class BasicLimits(ctypes.Structure):
    """Documented JOBOBJECT_BASIC_LIMIT_INFORMATION layout."""

    _fields_ = [("process_time", ctypes.c_int64), ("job_time", ctypes.c_int64), ("flags", ctypes.c_uint32),
                ("minimum", ctypes.c_size_t), ("maximum", ctypes.c_size_t), ("active", ctypes.c_uint32),
                ("affinity", ctypes.c_size_t), ("priority", ctypes.c_uint32), ("scheduling", ctypes.c_uint32)]


class ExtendedLimits(ctypes.Structure):
    """Documented JOBOBJECT_EXTENDED_LIMIT_INFORMATION layout."""

    _fields_ = [("basic", BasicLimits), ("io", ctypes.c_uint64 * 6), ("process_memory", ctypes.c_size_t),
                ("job_memory", ctypes.c_size_t), ("peak_process", ctypes.c_size_t), ("peak_job", ctypes.c_size_t)]


class Accounting(ctypes.Structure):
    """Documented JOBOBJECT_BASIC_ACCOUNTING_INFORMATION layout."""

    _fields_ = [("times", ctypes.c_int64 * 4), ("faults", ctypes.c_uint32), ("total", ctypes.c_uint32),
                ("active", ctypes.c_uint32), ("terminated", ctypes.c_uint32)]


class WindowsJob:
    """Own a non-breakaway, kill-on-close job and verify every contained process has exited."""

    def __init__(self) -> None:
        """Prepare containment before any executable child can start work."""
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
        self.kernel.CreateJobObjectW.restype = ctypes.c_void_p
        self.kernel.SetInformationJobObject.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
        self.kernel.QueryInformationJobObject.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p,
                                                        ctypes.c_uint32, ctypes.c_void_p]
        self.kernel.AssignProcessToJobObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        self.kernel.TerminateJobObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        self.kernel.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        self.kernel.OpenProcess.restype = ctypes.c_void_p
        self.kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        self.handle = self.kernel.CreateJobObjectW(None, None)
        if not self.handle:
            raise FileRefusal("Cannot establish child job containment; preserve resources.")
        limits = ExtendedLimits()
        limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE; do not permit breakaway.
        if not self.kernel.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            self.kernel.CloseHandle(self.handle)
            raise FileRefusal("Cannot configure child job containment; preserve resources.")

    def assign(self, pid: int) -> None:
        """Contain the bootstrap while it is still waiting for authorization to spawn the command.

        Args:
            pid: Exact freshly created bootstrap process identifier.
        """
        handle = self.kernel.OpenProcess(0x0101, False, pid)  # SET_QUOTA | TERMINATE
        if not handle:
            raise FileRefusal("Cannot open child for job assignment; command was not authorized to start.")
        try:
            if not self.kernel.AssignProcessToJobObject(self.handle, handle):
                raise FileRefusal("Cannot assign child to job; command was not authorized to start.")
        finally:
            self.kernel.CloseHandle(handle)

    def close(self) -> None:
        """Terminate the entire job and require zero active processes before returning."""
        try:
            if not self.kernel.TerminateJobObject(self.handle, 1):
                raise FileRefusal("Child job termination failed; reconcile helper processes before retry.")
            deadline = time.monotonic() + 5
            while True:
                accounting = Accounting()
                if not self.kernel.QueryInformationJobObject(self.handle, 1, ctypes.byref(accounting),
                                                             ctypes.sizeof(accounting), None):
                    raise FileRefusal("Cannot verify child job quiescence; reconcile helpers before retry.")
                if accounting.active == 0:
                    return
                if time.monotonic() >= deadline:
                    raise FileRefusal("Child job remains active; reconcile helpers before retry.")
                time.sleep(0.02)
        finally:
            self.kernel.CloseHandle(self.handle)


@contextmanager
def contained_child(args: list[str], cwd: Path, env: dict[str, str]):
    """Keep all command descendants contained until output processing and termination finish.

    Args:
        args: Exact executable and argument array, without shell interpolation.
        cwd: Independently verified primary checkout for the command.
        env: Sanitized environment with repository-shaping overrides removed.
    """
    job = WindowsJob() if os.name == "nt" else None
    process = None
    try:
        if job:
            # The trusted bootstrap cannot spawn Git before successful job assignment.
            bootstrap = "import subprocess,sys; token=sys.stdin.buffer.read(1); sys.exit(subprocess.call(sys.argv[1:], stdin=subprocess.DEVNULL) if token==b'1' else 125)"
            process = subprocess.Popen([sys.executable, "-I", "-S", "-B", "-c", bootstrap, *args], cwd=cwd,
                                       env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            job.assign(process.pid)
            assert process.stdin is not None
            process.stdin.write(b"1")
            process.stdin.close()
        else:
            process = subprocess.Popen(args, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        yield process
    finally:
        try:
            if job:
                job.close()
            elif process:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                # A surviving group can still own helpers after its leader exits.
                deadline = time.monotonic() + 5
                while True:
                    process.poll()
                    try:
                        os.killpg(process.pid, 0)
                    except ProcessLookupError:
                        break
                    if time.monotonic() >= deadline:
                        raise FileRefusal("Child process group remains; reconcile helper processes before retry.")
                    time.sleep(0.02)
        finally:
            if process:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)
