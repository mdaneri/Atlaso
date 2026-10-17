"""Capture authenticated UI frames inside a bounded Windows process job."""

from __future__ import annotations

import ctypes
import json
import os
import subprocess
import time
from ctypes import wintypes
from pathlib import Path
from typing import Any


def capture_ui(client: Any, args: Any) -> dict[str, Any]:
    """Pass session cookies through stdin only after assigning the child job.

    Args:
        client: Authenticated management client; cookies remain in memory.
        args: Owned lifecycle output and installed browser tooling selections.
    """
    if os.name != "nt":
        raise RuntimeError("Browser evidence requires the Windows process-job boundary.")
    result_root = Path(args.result_dir).resolve(strict=True)
    output = Path(args.reverse_proxy_screenshot_dir)
    if output.parent.resolve(strict=True) != result_root or output.name != "screenshots" or output.exists():
        raise RuntimeError("Browser evidence requires a new owned screenshots child.")
    output.mkdir()
    # This child is contained by the lifecycle root's original ownership receipt.
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel.CreateJobObjectW.restype = wintypes.HANDLE
    kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel.TerminateJobObject.restype = wintypes.BOOL
    kernel.QueryInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p]
    kernel.QueryInformationJobObject.restype = wintypes.BOOL
    kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    kernel.SetInformationJobObject.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL

    class Accounting(ctypes.Structure):
        """Read the documented basic accounting active-process count."""

        _fields_ = [("total_user", ctypes.c_int64), ("total_kernel", ctypes.c_int64),
                    ("period_user", ctypes.c_int64), ("period_kernel", ctypes.c_int64),
                    ("faults", wintypes.DWORD), ("total", wintypes.DWORD),
                    ("active", wintypes.DWORD), ("terminated", wintypes.DWORD)]

    class BasicLimits(ctypes.Structure):
        """Represent the documented job basic-limit structure."""

        _fields_ = [("process_time", ctypes.c_int64), ("job_time", ctypes.c_int64),
                    ("flags", wintypes.DWORD), ("min_working", ctypes.c_size_t),
                    ("max_working", ctypes.c_size_t), ("active_limit", wintypes.DWORD),
                    ("affinity", ctypes.c_size_t), ("priority", wintypes.DWORD),
                    ("scheduling", wintypes.DWORD)]

    class ExtendedLimits(ctypes.Structure):
        """Include IO counters and memory limits for job kill-on-close."""

        _fields_ = [("basic", BasicLimits), ("io", ctypes.c_uint64 * 6),
                    ("process_memory", ctypes.c_size_t), ("job_memory", ctypes.c_size_t),
                    ("peak_process", ctypes.c_size_t), ("peak_job", ctypes.c_size_t)]

    job = kernel.CreateJobObjectW(None, None)
    if not job:
        raise RuntimeError("Browser process job could not be created.")
    limits = ExtendedLimits()
    limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE; no breakaway.
    if not kernel.SetInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
        kernel.CloseHandle(job)
        raise RuntimeError("Browser kill-on-close boundary could not be established.")
    process = None
    assigned = False
    envelope = ""
    try:
        process = subprocess.Popen([args.reverse_proxy_screenshot_node, str(Path(__file__).with_name("capture_reverse_proxy_ui.mjs"))], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # The admitted Node source blocks on stdin before loading packages or
        # launching any descendant. No secret is supplied until job assignment.
        if not kernel.AssignProcessToJobObject(job, int(process._handle)):
            raise RuntimeError("Browser process job assignment failed.")
        assigned = True
        cookies = [{"name": cookie.name, "value": cookie.value, "url": client.base_url,
                    "secure": cookie.secure, "httpOnly": cookie.has_nonstandard_attr("HttpOnly")}
                   for cookie in client.cookie_jar]
        envelope = json.dumps({"base_url": client.base_url, "cookies": cookies, "output_dir": str(output),
                               "packages_root": args.reverse_proxy_screenshot_packages,
                               "executable_path": args.reverse_proxy_screenshot_browser})
        if len(envelope.encode()) > 65536:
            raise RuntimeError("Browser input exceeded its bound.")
        process.communicate(envelope.encode(), timeout=90)
        envelope = ""
        if process.returncode != 0:
            raise RuntimeError("Reverse-proxy browser capture failed.")
    except subprocess.TimeoutExpired:
        raise RuntimeError("Reverse-proxy browser capture exceeded its deadline.") from None
    finally:
        envelope = ""
        if process is not None:
            if assigned:
                if not kernel.TerminateJobObject(job, 1):
                    raise RuntimeError("Browser process-tree termination could not be proven.")
                deadline = time.monotonic() + 10
                accounting = Accounting()
                while time.monotonic() < deadline:
                    if not kernel.QueryInformationJobObject(job, 1, ctypes.byref(accounting), ctypes.sizeof(accounting), None):
                        raise RuntimeError("Browser process-tree state could not be proven.")
                    if accounting.active == 0:
                        break
                    time.sleep(0.1)
                else:
                    raise RuntimeError("Browser process tree remained active; preserve evidence.")
            elif process.poll() is None:
                process.kill()
            process.wait(timeout=10)
        kernel.CloseHandle(job)
    frames = ["reverse-proxies.webp", "reverse-proxies-responsive.webp", "reverse-proxy-wizard.webp"]
    if any(not (output / name).is_file() for name in frames):
        raise RuntimeError("Browser capture did not produce all required frames.")
    return {"frames": frames, "session_storage": "memory only", "process_tree": "inactive"}
