"""Exercise the bounded development VNC field adapter using public synthetic data."""

from __future__ import annotations

import hashlib
import io
import json
import sys
import types
from pathlib import Path

import pytest

from scripts.installation.vnc_console import (
    FAILED,
    READY,
    SENT,
    main,
    read_password,
    send_field,
)


def png() -> bytes:
    """Create a small public synthetic console frame."""
    buffer = io.BytesIO()
    image = pytest.importorskip("PIL.Image")
    image.new("RGB", (100, 60), "navy").save(buffer, format="PNG")
    return buffer.getvalue()


class Client:
    """Stand in for an existing, already admitted VNC connection."""

    def __init__(self, frame: bytes) -> None:
        """Bind public synthetic pixels.

        Args:
            frame: Mocked live PNG frame.
        """
        self.frame = frame
        self.keys: list[str] = []
        self.closed = False
        self.factory = types.SimpleNamespace(force_caps=False)
        self.captures = 0
        self.one_capture = False

    def captureScreen(self, stream, *, format: str) -> None:
        """Supply a frame without writing files.

        Args:
            stream: In-memory destination from the adapter.
            format: Explicit PNG encoding selected by the adapter.
        """
        assert format == "PNG"
        assert not self.closed
        self.captures += 1
        if self.one_capture:
            assert self.captures == 1, "The static-screen observer cannot refresh twice."
        stream.write(self.frame)

    def keyPress(self, key: str) -> None:
        """Record a synthetic keystroke.

        Args:
            key: Public test key.
        """
        self.keys.append(key)

    def pause(self, duration: float) -> None:
        """Assert finite per-character pacing.

        Args:
            duration: Delay requested between keys.
        """
        assert 0 < duration <= 0.02

    def disconnect(self) -> None:
        """Record connection teardown."""
        self.closed = True


def observed_api(typing_client: Client, frame: bytes):
    """Model one fixed typing connection and fresh static-screen observers.

    Args:
        typing_client: Original peer that alone may receive keys.
        frame: Public synthetic frame returned once by each observer.
    """
    clients = []

    def connect(*args, **kwargs):
        """Return a distinct observer after the original typing peer.

        Args:
            *args: Public loopback endpoint.
            **kwargs: Public connection timeout.
        """
        peer = Client(frame) if clients else typing_client
        peer.one_capture = True
        clients.append(peer)
        return peer

    return types.SimpleNamespace(connect=connect, shutdown=lambda: None, clients=clients)


@pytest.mark.parametrize("value", ['"not-object"\n', '{}\n', '{"password":"x","extra":1}\n',
                                   '{"password":"line\\nfeed"}\n', '{"password":""}\n',
                                   '{"password":"x","password":"y"}\n',
                                   '{"password":"x"}', 'x' * 4097])
def test_private_input_refuses_invalid_requests(value: str) -> None:
    """Reject unbounded, non-object, control-bearing or incomplete input.

    Args:
        value: Public invalid protocol fixture.
    """
    with pytest.raises(ValueError):
        read_password(io.StringIO(value))


def test_field_requires_matching_frame_before_reading() -> None:
    """A changed title cannot trigger password input or a keystroke."""
    expected = png()
    other = io.BytesIO()
    pytest.importorskip("PIL.Image").new("RGB", (100, 60), "red").save(other, format="PNG")
    client = Client(other.getvalue())
    stdin = io.StringIO(json.dumps({"password": "Public-fixture-42"}) + "\n")
    stdout = io.StringIO()
    with pytest.raises(ValueError):
        send_field(client, expected, hashlib.sha256(expected).hexdigest(), (5, 20, 70, 30), stdin, stdout)
    assert stdin.tell() == 0 and client.keys == [] and stdout.getvalue() == ""


def test_field_uses_only_private_stdin_and_fixed_checkpoints() -> None:
    """A matched field receives exact public test bytes and one Enter."""
    expected = png()
    client = Client(expected)
    value = 'Public-"quoted"-\\-fixture-42'
    output = io.StringIO()
    send_field(client, expected, hashlib.sha256(expected).hexdigest(), (5, 20, 70, 30),
               io.StringIO(json.dumps({"password": value}) + "\n"), output)
    assert client.keys == [*(["bsp"] * 255), *value, "enter"]
    assert output.getvalue() == READY + "\n" + SENT + "\n"
    assert value not in output.getvalue()


def test_field_controls_exist_in_pinned_client_keymap() -> None:
    """Check control names against the optional real client's keyboard vocabulary."""
    library = pytest.importorskip("vncdotool.keys")
    expected = png()
    client = Client(expected)
    value = 'Public-"quoted"-\\-fixture-42'
    send_field(client, expected, hashlib.sha256(expected).hexdigest(), (5, 20, 70, 30),
               io.StringIO(json.dumps({"password": value}) + "\n"), io.StringIO())
    assert [library.KEYMAP[key] for key in client.keys[:255]] == [library.Key.BackSpace] * 255
    assert library.KEYMAP[client.keys[-1]] == library.Key.Return
    assert client.keys[255:-1] == list(value)


def test_changed_frame_after_private_input_sends_no_keys() -> None:
    """Recheck the screen after the parent has performed its provider checks."""
    expected = png()
    changed = io.BytesIO()
    pytest.importorskip("PIL.Image").new("RGB", (100, 60), "red").save(changed, format="PNG")
    client = Client(expected)
    captures = 0

    def capture(stream, *, format: str) -> None:
        """Change the public dialog while the parent admits its peer.

        Args:
            stream: In-memory capture destination.
            format: Explicit image format supplied by the adapter.
        """
        nonlocal captures
        assert format == "PNG"
        stream.write(expected if captures == 0 else changed.getvalue())
        captures += 1

    client.captureScreen = capture
    output = io.StringIO()
    with pytest.raises(ValueError):
        send_field(client, expected, hashlib.sha256(expected).hexdigest(), (5, 20, 70, 30),
                   io.StringIO('{"password":"Public-fixture-42"}\n'), output)
    assert client.keys == [] and output.getvalue() == READY + "\n"


def test_invalid_private_input_sends_no_clearing_or_typing() -> None:
    """Do not mutate even the field until the private request is validated."""
    expected = png()
    client = Client(expected)
    with pytest.raises(ValueError):
        send_field(client, expected, hashlib.sha256(expected).hexdigest(), (5, 20, 70, 30),
                   io.StringIO('{"password":"bad\\nvalue"}\n'), io.StringIO())
    assert client.keys == []


def test_cli_sanitizes_client_failures_and_disconnects(tmp_path: Path, monkeypatch, capsys) -> None:
    """Do not expose library exception text or leave the transport connected.

    Args:
        tmp_path: Pytest-owned image fixture directory.
        monkeypatch: Scoped module and input substitutions.
        capsys: Captured public protocol output.
    """
    expected = png()
    screen = tmp_path / "expected.png"
    screen.write_bytes(expected)
    client = Client(expected)
    sentinel = "PUBLIC-SENTINEL-MUST-NOT-APPEAR"

    def fail_key(key: str) -> None:
        """Simulate an unsafe third-party diagnostic.

        Args:
            key: Public synthetic key sent by the adapter.
        """
        print(sentinel, file=sys.stderr)
        raise RuntimeError(sentinel)

    client.keyPress = fail_key
    api = observed_api(client, expected)
    monkeypatch.setitem(sys.modules, "vncdotool", types.SimpleNamespace(__version__="1.4.2", api=api))
    monkeypatch.setattr(sys, "stdin", io.StringIO('{"password":"Public-fixture-42"}\n'))
    result = main(["--port", "6093", "--expected-screen", str(screen), "--expected-screen-sha256",
                   hashlib.sha256(expected).hexdigest(), "--field-rectangle", "5,20,70,30"])
    captured = capsys.readouterr()
    assert result == 1 and client.closed
    assert captured.out == READY + "\n" + FAILED + "\n"
    assert captured.err == "" and sentinel not in captured.out
    assert client.factory.force_caps is True


def test_cli_enables_shift_before_sending_printable_keys(tmp_path: Path, monkeypatch, capsys) -> None:
    """Use the existing client's physical Shift behavior for VMware consoles.

    Args:
        tmp_path: Pytest-owned image fixture directory.
        monkeypatch: Scoped client and private-input substitutions.
        capsys: Fixed public protocol output.
    """
    expected = png()
    screen = tmp_path / "expected.png"
    screen.write_bytes(expected)
    client = Client(expected)
    original_key = client.keyPress

    def key_with_shift(key: str) -> None:
        """Require the real client option before any control or printable key.

        Args:
            key: Public synthetic test key.
        """
        assert client.factory.force_caps is True
        original_key(key)

    client.keyPress = key_with_shift
    api = observed_api(client, expected)
    monkeypatch.setitem(sys.modules, "vncdotool", types.SimpleNamespace(__version__="1.4.2", api=api))
    monkeypatch.setattr(sys, "stdin", io.StringIO('{"password":"Public-fixture-42!"}\n'))
    assert main(["--port", "6093", "--expected-screen", str(screen), "--expected-screen-sha256",
                 hashlib.sha256(expected).hexdigest(), "--field-rectangle", "5,20,70,30"]) == 0
    assert client.closed and client.keys[-1] == "enter"
    assert len(api.clients) == 4 and client.captures == 0
    assert all(peer.closed and peer.captures == 1 and peer.keys == [] for peer in api.clients[1:])
    assert capsys.readouterr().out == READY + "\n" + SENT + "\n"
