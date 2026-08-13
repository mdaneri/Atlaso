#!/usr/bin/env python3
"""Validate a redacted VCF 9.1 KMIP interoperability trace."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from atlaso.app.kmip.trace import (  # noqa: E402 - repository root is added before importing Atlaso.
    main,  # noqa: E402 - repository root is added before importing Atlaso.
)

if __name__ == "__main__":
    raise SystemExit(main())
