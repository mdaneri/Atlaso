#!/usr/bin/env python3
"""Offline ISO refresh protocol and bounded native package review.

Use invoke-installation-refresh.ps1 for resource-consuming phases. Direct run
admission requires that launcher's exact originally published Windows job.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.installation import (  # noqa: E402 - direct-script repository bootstrap.
    refresh,
)

if __name__ == "__main__":
    try:
        raise SystemExit(refresh.main())
    except refresh.RefreshRefusal as exc:
        print(f"ISO refresh refused: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
    except (OSError, ValueError, RuntimeError) as exc:
        # The workflow does not print tool output, private files or exception
        # arguments from credential-consuming subprocesses on this channel.
        print(f"ISO refresh refused ({type(exc).__name__}); preserve original phase evidence.", file=sys.stderr)
        raise SystemExit(2) from None
