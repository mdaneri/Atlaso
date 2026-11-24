"""Report which installer requirements changed between two source trees."""

from __future__ import annotations

import argparse
import sys
from html import escape
from pathlib import Path

from scripts.installation.manifest import canonical_json
from scripts.installation.photon_snapshot import (
    requirements_inputs,
    requirements_sha256,
)


def summarize(base: Path, candidate: Path, *, base_fingerprint: str | None = None) -> str:
    """Compare the canonical capture inputs without reading any approved capture.

    Args:
        base: Checkout of the exact pull request base.
        candidate: Checkout of the candidate installer source.
        base_fingerprint: Fingerprint evaluated with the base's own implementation.
    """
    baseline = requirements_inputs(base)
    proposed = requirements_inputs(candidate)
    evaluated_base = requirements_sha256(base)
    if (base_fingerprint or evaluated_base) == requirements_sha256(candidate):
        return "Installer requirements are unchanged. This PR introduces no new capture requirement."

    lines = [
        "**A compatible Photon capture is needed for these requirements.**",
        "",
        "Prepare a fresh capture unless one has already been approved for the new requirements.",
        "This comparison does not verify the capture currently configured for release staging.",
        "",
    ]
    before_packages = set(baseline["packages"])
    after_packages = set(proposed["packages"])
    before_pins, after_pins = (
        {
            f"scripts/installation/{file} / {name}": canonical_json({"value": value})
            for file, pins in snapshot["pins"].items()
            for name, value in pins.items()
        }
        for snapshot in (baseline, proposed)
    )
    before_files = baseline["files"]
    after_files = proposed["files"]
    changes = (
        ("Added packages", after_packages - before_packages),
        ("Removed packages", before_packages - after_packages),
        (
            "Changed pins",
            {pin for pin in before_pins.keys() | after_pins.keys() if before_pins.get(pin) != after_pins.get(pin)},
        ),
        (
            "Changed input files",
            {path for path in before_files.keys() | after_files.keys() if before_files.get(path) != after_files.get(path)},
        ),
    )
    for label, items in changes:
        if items:
            lines.append(f"- {label}: " + ", ".join(f"<code>{escape(item)}</code>" for item in sorted(items)))
    if base_fingerprint and base_fingerprint != evaluated_base:
        lines.append("- The fingerprint definition also changed relative to the PR base.")
    lines += [
        "",
        "[Photon capture and admission runbook]"
        "(https://github.com/mdaneri/Atlaso/blob/main/docs/reference/installation-iso-refresh.md#run-the-phases)",
    ]
    return "\n".join(lines)


def main() -> int:
    """Print a Markdown summary for the read-only CI preflight."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--base-fingerprint", help="Fingerprint computed by the PR base checkout")
    args = parser.parse_args()

    print("## Photon snapshot preflight\n")
    try:
        print(summarize(args.base, args.candidate, base_fingerprint=args.base_fingerprint))
    except (OSError, SyntaxError, TypeError, ValueError) as error:
        message = f"Unable to compare Photon snapshot requirements ({type(error).__name__})."
        print(message)
        print(message, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
