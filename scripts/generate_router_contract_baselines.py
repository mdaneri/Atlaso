"""Generate or verify checked-in route and OpenAPI contract baselines."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

ROUTE_BASELINE = ROOT / "tests" / "contracts" / "route_inventory.json"
OPENAPI_BASELINE = ROOT / "tests" / "contracts" / "openapi_v1.json"


def _render(value: object) -> str:
    """Return deterministic formatted JSON.

    Args:
        value: JSON-serializable contract value.

    Returns:
        Sorted, indented JSON ending with one newline.
    """
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _contract_documents() -> dict[Path, Any]:
    """Return current contract documents keyed by baseline path."""
    from atlaso.app.main import app
    from atlaso.app.routers.contracts import build_route_inventory, normalized_openapi

    return {
        ROUTE_BASELINE: build_route_inventory(app),
        OPENAPI_BASELINE: normalized_openapi(app),
    }


def generate(*, check: bool) -> list[str]:
    """Generate baselines or report stale files.

    Args:
        check: Whether to compare without writing files.

    Returns:
        Human-readable stale or updated path messages.
    """
    messages: list[str] = []
    for path, document in _contract_documents().items():
        rendered = _render(document)
        relative_path = path.relative_to(ROOT).as_posix()
        if check:
            current = path.read_text(encoding="utf-8") if path.exists() else ""
            if current != rendered:
                messages.append(f"stale router contract baseline: {relative_path}")
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered, encoding="utf-8", newline="\n")
        messages.append(f"updated router contract baseline: {relative_path}")
    return messages


def main() -> int:
    """Generate baselines or verify that checked-in files are current."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify baselines without writing them")
    args = parser.parse_args()
    messages = generate(check=args.check)
    for message in messages:
        print(message)
    return 1 if args.check and messages else 0


if __name__ == "__main__":
    raise SystemExit(main())
