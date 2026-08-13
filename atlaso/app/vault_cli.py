"""Implement vault cli behavior."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

VAULT_CREDENTIAL_NAME = "atlaso-vault"


def _credential_path() -> Path:
    """Return credential path.

    Raises:
        ValueError: If an input value is invalid.
    """
    directory = os.environ.get("CREDENTIALS_DIRECTORY", "")
    if not directory:
        raise ValueError("Atlaso vault access is available only inside a scoped managed-script run.")
    root = Path(directory).resolve(strict=True)
    path = (root / VAULT_CREDENTIAL_NAME).resolve(strict=True)
    if not path.is_relative_to(root) or not path.is_file():
        raise ValueError("The scoped Atlaso vault credential is unavailable.")
    return path


def _values() -> dict[str, str]:
    """Return values.

    Raises:
        ValueError: If an input value is invalid.
    """
    payload = json.loads(_credential_path().read_text(encoding="utf-8"))
    values = payload.get("values")
    if payload.get("version") != 1 or not isinstance(values, dict):
        raise ValueError("The scoped Atlaso vault credential is invalid.")
    if any(not isinstance(key, str) or not isinstance(value, str) for key, value in values.items()):
        raise ValueError("The scoped Atlaso vault credential contains invalid values.")
    return values


def main() -> int:
    """Run the command-line entry point.

    Returns:
        The main result.

    Raises:
        ValueError: If an input value is invalid.
    """
    parser = argparse.ArgumentParser(prog="atlaso-vault")
    subparsers = parser.add_subparsers(dest="command", required=True)
    get_parser = subparsers.add_parser("get", help="retrieve one value from the run-scoped vault")
    get_parser.add_argument("--key", required=True)
    keys_parser = subparsers.add_parser("keys", help="list keys in the run-scoped vault")
    keys_parser.set_defaults(command="keys")
    args = parser.parse_args()
    try:
        values = _values()
        if args.command == "keys":
            for key in sorted(values):
                print(key)
            return 0
        if args.key not in values:
            raise ValueError(f"Atlaso vault key not found: {args.key}")
        print(values[args.key], end="")
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
