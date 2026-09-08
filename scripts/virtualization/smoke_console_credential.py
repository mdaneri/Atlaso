"""Publish one disposable console credential through the installed 1Password MCP.

Run only inside the bounded Windows process job. The only local output is current-
user DPAPI ciphertext; RPC streams, exceptions, and secret values are never logged.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import re
import secrets
import subprocess
from pathlib import Path
from typing import Any

ENVIRONMENT_DIGEST = "fe14b62fb2d23460202299784cb1080b9e0fcf202ed5d75b4843202cd68bdf06"


class Plugin:
    """A private stdio session to the installed, authenticated 1Password plugin."""

    def __init__(self, executable: str) -> None:
        """Start the plugin inside the caller's non-breakaway Windows job.

        Args:
            executable: Installed 1Password MCP executable to launch privately.
        """
        self.process = subprocess.Popen(
            [executable],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        self.sequence = 0
        self.rpc(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "Atlaso smoke console", "version": "1"},
            },
        )
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def send(self, message: dict[str, Any]) -> None:
        """Send protocol data privately, including concealed variable values.

        Args:
            message: JSON-RPC envelope written only to the private plugin pipe.
        """
        assert self.process.stdin is not None
        self.process.stdin.write(json.dumps(message) + "\n")
        self.process.stdin.flush()

    def rpc(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        """Read one bounded response; the Windows job owns the wall-clock limit.

        Args:
            method: JSON-RPC method expected to return the matching response.
            params: Private parameters for the requested protocol method.
        """
        self.sequence += 1
        self.send(
            {"jsonrpc": "2.0", "id": self.sequence, "method": method, "params": params}
        )
        assert self.process.stdout is not None
        while True:
            line = self.process.stdout.readline(1_048_577)
            if not line or len(line) > 1_048_576:
                raise RuntimeError("1Password protocol unavailable")
            result = json.loads(line)
            if result.get("id") != self.sequence:
                continue
            if "error" in result or not isinstance(result.get("result"), dict):
                raise RuntimeError("1Password operation failed")
            return result["result"]

    def tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Decode a supported plugin tool without exposing its raw response.

        Args:
            name: Supported 1Password tool name to invoke.
            arguments: Tool arguments, which may contain a concealed credential.
        """
        result = self.rpc("tools/call", {"name": name, "arguments": arguments})
        if result.get("isError"):
            raise RuntimeError("1Password operation failed")
        if name == "append_variables":
            return {}  # The separate names readback confirms publication.
        texts = [
            item["text"]
            for item in result.get("content", [])
            if item.get("type") == "text"
        ]
        if len(texts) != 1:
            raise RuntimeError("1Password response unavailable")
        decoded = json.loads(texts[0])
        if not isinstance(decoded, dict):
            raise RuntimeError("1Password response invalid")
        return decoded

    def close(self) -> None:
        """Stop the private server; job teardown additionally covers descendants."""
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait(timeout=10)


def verify_environment(plugin: Plugin, environment_id: str) -> str:
    """Prove plugin authorization and exact Environment identity without mutation.

    Args:
        plugin: Isolated plugin session used for Environment admission and publication.
        environment_id: Pinned Atlaso Environment identifier to verify before use.
    """
    if hashlib.sha256(environment_id.encode()).hexdigest() != ENVIRONMENT_DIGEST:
        raise ValueError("Unexpected Environment")
    account_id = plugin.tool("authenticate", {})["account_id"]
    environments = plugin.tool("list_environments", {"accountId": account_id})[
        "environments"
    ]
    matches = [item for item in environments if item.get("name") == "Atlaso"]
    if len(matches) != 1 or matches[0].get("environmentId") != environment_id:
        raise ValueError("Exact Atlaso Environment unavailable")
    return account_id


def publish(plugin: Plugin, environment_id: str, run_id: str) -> str:
    """Create an isolated concealed variable after exact Environment admission.

    Args:
        plugin: Isolated plugin session used for Environment admission and publication.
        environment_id: Pinned Atlaso Environment identifier to verify before use.
        run_id: Fresh lowercase UUID without separators for the disposable VM run.
    """
    if not re.fullmatch(r"[0-9a-f]{32}", run_id):
        raise ValueError("Invalid run identity")
    account_id = verify_environment(plugin, environment_id)
    arguments = {"accountId": account_id, "environmentId": environment_id}
    variable_name = "ATLASO_SMOKE_CONSOLE_" + run_id.upper()
    names = plugin.tool("list_variables", arguments)["variableNames"]
    if variable_name in names:
        raise ValueError("Console variable already exists")
    value = "A!a1" + secrets.token_urlsafe(32)
    plugin.tool(
        "append_variables",
        {
            **arguments,
            "variables": [{"name": variable_name, "value": value, "concealed": True}],
        },
    )
    names = plugin.tool("list_variables", arguments)["variableNames"]
    if names.count(variable_name) != 1:
        raise ValueError("Console variable publication unconfirmed")
    return value


def protect(value: str) -> str:
    """Encrypt the credential for the current Windows user without disk plaintext.

    Args:
        value: Generated credential to protect for the current Windows identity.
    """

    class Blob(ctypes.Structure):
        """Windows DATA_BLOB layout."""

        _fields_ = [("size", ctypes.c_uint32), ("data", ctypes.POINTER(ctypes.c_ubyte))]

    raw = value.encode("utf-16-le")
    buffer = ctypes.create_string_buffer(raw)
    source = Blob(len(raw), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
    target = Blob()
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(Blob),
        ctypes.c_wchar_p,
        ctypes.POINTER(Blob),
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(Blob),
    ]
    crypt32.CryptProtectData.restype = ctypes.c_bool
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    try:
        if not crypt32.CryptProtectData(
            ctypes.byref(source), None, None, None, None, 1, ctypes.byref(target)
        ):
            raise RuntimeError("DPAPI unavailable")
        try:
            return ctypes.string_at(target.data, target.size).hex()
        finally:
            kernel32.LocalFree(ctypes.cast(target.data, ctypes.c_void_p))
    finally:
        ctypes.memset(buffer, 0, len(raw))


def main() -> int:
    """Publish and protect one credential, exposing only a fixed failure message."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plugin", required=True)
    parser.add_argument("--environment-id", required=True)
    parser.add_argument("--run-id", default="")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    plugin = None
    try:
        # Refuse before publication when a prior output could be mistaken for ours.
        if not args.check and (args.output is None or args.output.exists()):
            raise ValueError("Output already exists")
        plugin = Plugin(args.plugin)
        if args.check:
            verify_environment(plugin, args.environment_id)
            return 0
        value = publish(plugin, args.environment_id, args.run_id)
        ciphertext = protect(value)
        value = None
        with args.output.open("x", encoding="utf-8") as output:
            json.dump({"ciphertext": ciphertext}, output)
        return 0
    except Exception:  # noqa: BLE001 - never expose secret-bearing provider exception details.
        print(
            "Console credential handoff failed; inspect 1Password availability and the recorded run identity."
        )
        return 1
    finally:
        if plugin is not None:
            plugin.close()


if __name__ == "__main__":
    raise SystemExit(main())
