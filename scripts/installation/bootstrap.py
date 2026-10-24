#!/usr/bin/env python3
"""Authenticate removable media from initrd before executing any media code."""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from pathlib import Path

# The ISO assembler embeds both files into this root-owned initrd directory.
# Never add the unverified media tree to this interpreter's import search path.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from manifest import (  # noqa: E402 - only the initrd-pinned verifier is imported here.
    installer_key_id,
    verify_media,
)


def main() -> None:
    """Verify first, then replace this process with the authenticated installer."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--media", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="atlaso-installer-verify-", dir="/run") as temporary:
        verify_media(args.media, Path("/etc/atlaso-installer/trust.pem"), scratch=Path(temporary), expected_key_id=installer_key_id(), boot_crypto=True)
    os.execv(sys.executable, [sys.executable, str(args.media / "source/scripts/installation/installer.py"), "--media", str(args.media)])


if __name__ == "__main__":
    main()
