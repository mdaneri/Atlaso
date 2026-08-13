#!/usr/bin/env python3
"""Generate deterministic Atlaso brand surfaces from the canonical kit."""

from __future__ import annotations

import argparse
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

NAVY = "#071A3A"
BLUE = "#1769E0"
TEAL = "#16C7BC"
WHITE = "#FFFFFF"


def _font(size: int, *, bold: bool = False) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    """Return font.

    Args:
        size: Size consumed by font.
        bold: Whether bold applies to the operation.
    """
    candidates = (
        Path("C:/Windows/Fonts/segoeuib.ttf" if bold else "C:/Windows/Fonts/segoeui.ttf"),
        Path(
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
            if bold
            else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
        ),
    )
    for candidate in candidates:
        if candidate.is_file():
            return ImageFont.truetype(str(candidate), size)
    return ImageFont.load_default()


def _fit_font(
    draw: ImageDraw.ImageDraw,
    text: str,
    *,
    max_width: int,
    start_size: int,
    minimum_size: int,
    bold: bool = False,
) -> ImageFont.ImageFont:
    """Return fit font.

    Args:
        draw: Draw supplied by the caller.
        text: Text to parse, render, or persist.
        max_width: Max width supplied by the caller.
        start_size: Start size supplied by the caller.
        minimum_size: Minimum size supplied by the caller.
        bold: Bold supplied by the caller.
    """
    for size in range(start_size, minimum_size - 1, -1):
        font = _font(size, bold=bold)
        box = draw.textbbox((0, 0), text, font=font)
        if box[2] - box[0] <= max_width:
            return font
    return _font(minimum_size, bold=bold)


def generate_social_preview(output: Path, icon_path: Path) -> None:
    """Build social preview.

    Args:
        output: Filesystem path associated with output.
        icon_path: Filesystem path used for icon.
    """
    image = Image.new("RGB", (1200, 630), NAVY)
    draw = ImageDraw.Draw(image)

    icon = Image.open(icon_path).convert("RGBA")
    icon.thumbnail((330, 330), Image.Resampling.LANCZOS)
    image.paste(icon, (62, 150), icon)

    text_left = 430
    content_width = 710
    draw.text((text_left, 154), "ATLASO", font=_font(92, bold=True), fill=WHITE)
    draw.text(
        (text_left, 282),
        "Everything your virtualization lab needs.",
        font=_fit_font(
            draw,
            "Everything your virtualization lab needs.",
            max_width=content_width,
            start_size=38,
            minimum_size=28,
            bold=True,
        ),
        fill=TEAL,
    )
    capabilities = "Infrastructure • Storage • Identity • Networking • Lifecycle"
    draw.text(
        (text_left, 352),
        capabilities,
        font=_fit_font(
            draw,
            capabilities,
            max_width=content_width,
            start_size=30,
            minimum_size=20,
        ),
        fill=WHITE,
    )
    draw.text(
        (text_left, 416),
        "Infrastructure • Connectivity • Automation",
        font=_fit_font(
            draw,
            "Infrastructure • Connectivity • Automation",
            max_width=content_width,
            start_size=27,
            minimum_size=20,
            bold=True,
        ),
        fill=TEAL,
    )

    for y, start in ((78, 815), (530, 760)):
        draw.line((start, y, 1138, y), fill=TEAL, width=3)
        draw.ellipse((1129, y - 8, 1145, y + 8), outline=TEAL, width=3)
    draw.line((text_left, 500, 1138, 500), fill=BLUE, width=4)
    draw.line((800, 500, 1138, 500), fill=TEAL, width=4)

    output.parent.mkdir(parents=True, exist_ok=True)
    image.save(output, format="PNG", optimize=True)


def main() -> int:
    """Run the command-line entry point.

    Returns:
        The main result.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--social-preview",
        type=Path,
        default=Path(__file__).resolve().parents[1]
        / "docs/assets/brand/atlaso-social-preview-1200x630.png",
    )
    parser.add_argument(
        "--icon",
        type=Path,
        default=Path(__file__).resolve().parents[1]
        / "docs/assets/brand/atlaso-app-icon-dark-512.png",
    )
    args = parser.parse_args()
    generate_social_preview(args.social_preview, args.icon)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
