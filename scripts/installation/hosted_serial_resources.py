"""Sample the Linux runner during the bounded serial diagnostic."""

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path


def pressure_us(kind):
    """Return kernel PSI some-stall wall time, in microseconds, if exported."""
    path = Path("/proc/pressure") / kind
    if path.is_file():
        for line in path.read_text().splitlines():
            if line.startswith("some "):
                return int(line.split("total=")[1])
    return None


def meminfo_kib():
    """Read memory capacity and current available memory from the runner."""
    return {
        key.rstrip(":"): int(value)
        for key, value, *_ in (line.split() for line in Path("/proc/meminfo").read_text().splitlines())
        if key in {"MemTotal:", "MemAvailable:"}
    }


def cpu_ticks():
    """Get aggregate busy and total CPU ticks on this runner, excluding guest double counts."""
    fields = [int(value) for value in Path("/proc/stat").read_text().splitlines()[0].split()[1:9]]
    total = sum(fields)
    return total - fields[3] - fields[4], total


def oom_kills():
    """Read OOM kills in this runner process's cgroup when the kernel exports them."""
    for line in Path("/proc/self/cgroup").read_text().splitlines():
        if line.startswith("0::"):
            path = Path("/sys/fs/cgroup") / line[3:].lstrip("/") / "memory.events"
            if path.is_file():
                return int(dict(item.split() for item in path.read_text().splitlines())["oom_kill"])
    return None


def main(command):
    """Run the fixture and emit a compact sample summary even when its check fails."""
    info = meminfo_kib()
    minimum = info["MemAvailable"]
    start = time.monotonic()
    kinds = ("cpu", "memory", "io")
    initial = {kind: pressure_us(kind) for kind in kinds}
    busy_before, total_before = cpu_ticks()
    kills_before = oom_kills()
    samples = 0
    with subprocess.Popen(command) as child:
        while child.poll() is None:
            minimum = min(minimum, meminfo_kib()["MemAvailable"])
            samples += 1
            try:
                child.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
    elapsed = time.monotonic() - start
    result = {
        "elapsed_s": round(elapsed, 2),
        "samples": samples,
        "available_cpus": len(os.sched_getaffinity(0)),
        "total_memory_mib": info["MemTotal"] // 1024,
        "minimum_available_memory_mib": minimum // 1024,
        "free_disk_mib_at_end": shutil.disk_usage(os.environ["RUNNER_TEMP"]).free // 2**20,
    }
    busy_after, total_after = cpu_ticks()
    if total_after > total_before:
        result["host_busy_cpu_pct"] = round(100 * (busy_after - busy_before) / (total_after - total_before), 2)
    for kind in kinds:
        end = pressure_us(kind)
        if end is not None and initial[kind] is not None:
            result[f"{kind}_some_stall_pct"] = round((end - initial[kind]) / (elapsed * 10000), 2)
    kills_after = oom_kills()
    if kills_before is not None and kills_after is not None:
        result["cgroup_oom_kills_during_test"] = kills_after - kills_before
    print("HOST_RESOURCES " + json.dumps(result, sort_keys=True), flush=True)
    return child.returncode


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
