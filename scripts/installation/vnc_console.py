"""Send one concealed installer field through an admitted development VNC connection.

The owning PowerShell consumer pins source/runtime inputs, admits the original VM,
checks the loopback peer, and supplies a password only through the contained child's
stdin. This module never retrieves credentials or creates a VM.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.installation.vnc_frame import (  # noqa: E402 - isolated direct-script bootstrap.
    frames_match,
)

READY = "ATLASO-VNC-CREDENTIAL-READY"
SENT = "ATLASO-VNC-CREDENTIAL-SENT"
FAILED = "ATLASO-VNC-CREDENTIAL-REFUSED"
_NATIVE_FIELD_LIMIT = 255


class _Discard(io.TextIOBase):
    """Discard library diagnostics that might describe individual typed keys."""

    def write(self, text: str) -> int:
        """Discard one diagnostic fragment.

        Args:
            text: Library output that must never reach the parent or disk.
        """
        return len(text)


def read_password(stream) -> str:
    """Read one bounded ASCII field from the parent's private stdin pipe.

    Args:
        stream: Contained child's text stdin stream.
    """
    line = stream.readline(4097)
    if not line.endswith("\n") or len(line) > 4096:
        raise ValueError("invalid private input")

    def request_object(pairs: list[tuple[str, object]]) -> dict:
        """Reject duplicate or unexpected keys before constructing the request.

        Args:
            pairs: Private JSON object entries, never diagnostic output.
        """
        if len(pairs) != 1 or pairs[0][0] != "password":
            raise ValueError("invalid private input")
        return dict(pairs)

    value = json.loads(line, object_pairs_hook=request_object)
    if not isinstance(value, dict) or set(value) != {"password"}:
        raise ValueError("invalid private input")
    password = value["password"]
    if not isinstance(password, str) or not 1 <= len(password) <= _NATIVE_FIELD_LIMIT:
        raise ValueError("invalid private input")
    if any(not 32 <= ord(character) <= 126 for character in password):
        raise ValueError("invalid private input")
    return password


def send_field(client, expected: bytes, digest: str, rectangle: tuple[int, int, int, int], stdin, stdout) -> None:
    """Type only after the caller-observed concealed dialog still matches.

    Args:
        client: Existing vncdotool connection on the admitted loopback socket.
        expected: Caller-observed empty concealed-field screenshot.
        digest: Independently admitted screenshot digest.
        rectangle: Single input-row rectangle excluded from cursor comparison.
        stdin: Private password pipe from the containing PowerShell process.
        stdout: Parent protocol stream accepting only fixed checkpoints.
    """
    def check_frame() -> None:
        """Recheck the complete dialog without storing live pixels on disk."""
        image = io.BytesIO()
        client.captureScreen(image, format="PNG")
        if not frames_match(expected, image.getvalue(), digest, rectangle):
            raise ValueError("concealed dialog changed")

    check_frame()
    print(READY, file=stdout, flush=True)
    password = read_password(stdin)
    try:
        # The parent rechecks the connected provider before supplying this line.
        # Revalidate the UI as well, after any SDK or scheduling delay.
        check_frame()
        # The pinned Photon ReadText field accepts at most 255 characters and
        # Backspace on an empty field stays in that field. Clear retry text
        # without assuming a platform-specific line-kill shortcut.
        for _ in range(_NATIVE_FIELD_LIMIT):
            client.keyPress("backspace")
            client.pause(0.001)
        check_frame()
        for character in password:
            client.keyPress(character)
            client.pause(0.01)
        client.keyPress("enter")
        print(SENT, file=stdout, flush=True)
    finally:
        password = ""


def main(argv: list[str] | None = None) -> int:
    """Run one bounded, parent-admitted concealed-field operation.

    Args:
        argv: Public transport and observed-frame arguments only.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--expected-screen", type=Path, required=True)
    parser.add_argument("--expected-screen-sha256", required=True)
    parser.add_argument("--field-rectangle", required=True)
    args = parser.parse_args(argv)
    output = sys.stdout
    old_logging = logging.root.manager.disable
    api = None
    client = None
    try:
        logging.disable(logging.CRITICAL)
        with contextlib.redirect_stdout(_Discard()), contextlib.redirect_stderr(_Discard()):
            if not 1024 <= args.port <= 65535:
                raise ValueError("invalid loopback port")
            rectangle = tuple(int(value) for value in args.field_rectangle.split(","))
            if len(rectangle) != 4 or args.expected_screen.stat().st_size > 8 * 1024**2:
                raise ValueError("invalid observed frame")
            expected = args.expected_screen.read_bytes()
            # Validate every public admission before loading or connecting the client.
            if not frames_match(expected, expected, args.expected_screen_sha256, rectangle):
                raise ValueError("invalid observed frame")
            import vncdotool
            from vncdotool import api as client_api

            if vncdotool.__version__ != "1.4.2":
                raise ValueError("unsupported development VNC client")
            api = client_api
            client = api.connect(f"127.0.0.1::{args.port}", timeout=10)
            send_field(client, expected, args.expected_screen_sha256, rectangle, sys.stdin, output)
        return 0
    except Exception:  # noqa: BLE001 - Third-party diagnostics must never disclose typed keys.
        # Neither a protocol/library exception nor its traceback may disclose keys.
        print(FAILED, file=output, flush=True)
        return 1
    finally:
        with contextlib.redirect_stdout(_Discard()), contextlib.redirect_stderr(_Discard()):
            with contextlib.suppress(Exception):
                if client is not None:
                    client.disconnect()
            with contextlib.suppress(Exception):
                if api is not None:
                    api.shutdown()
        logging.disable(old_logging)


if __name__ == "__main__":
    raise SystemExit(main())
