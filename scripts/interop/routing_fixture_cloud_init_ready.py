"""Verify isolated routing client provisioning without exposing cloud-init logs.

The credential-bearing NoCloud seed is removed after first boot. A later boot
may use the fixture's explicit None fallback, which cloud-init reports as a
recoverable warning even though its one-time provisioning already completed.
"""

from __future__ import annotations

import json
import subprocess
import sys
from typing import Any


def provisioned(returncode: int, output: str) -> bool:
    """Accept clean completion or only the known seed-detachment fallback.

    Args:
        returncode: Cloud-init status exit code.
        output: Bounded JSON status output.
    """
    if returncode not in (0, 2) or len(output) > 65536:
        return False
    try:
        status: Any = json.loads(output)
    except (TypeError, ValueError):
        return False
    if not isinstance(status, dict) or status.get("status") != "done" or status.get("errors") != []:
        return False
    warnings = status.get("recoverable_errors")
    if returncode == 0:
        return warnings in ({}, None) and status.get("extended_status") == "done"
    return (
        status.get("extended_status") == "degraded done"
        and status.get("datasource") == "none"
        and warnings == {"WARNING": ["Used fallback datasource"]}
    )


def main() -> int:
    """Wait for cloud-init, then publish only a success/failure exit code."""
    try:
        result = subprocess.run(  # noqa: S603 - fixed guest command and no shell
            ["sudo", "-n", "cloud-init", "status", "--wait", "--format", "json"],
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return 1
    return 0 if provisioned(result.returncode, result.stdout) else 1


if __name__ == "__main__":
    sys.exit(main())
