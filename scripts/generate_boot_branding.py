#!/usr/bin/env python3
"""Generate the fixed-size Atlaso GRUB background from the product mark."""

from __future__ import annotations

import argparse
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

WIDTH = 640
HEIGHT = 480
SCALE = 2


def _font(size: int, *, bold: bool = False) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    """Return font.

    Args:
        size: Size consumed by font.
        bold: Whether bold applies to the operation.
    """
    candidates = (
        Path("C:/Windows/Fonts/segoeuib.ttf" if bold else "C:/Windows/Fonts/segoeui.ttf"),
        Path("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if bold else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
    )
    for candidate in candidates:
        if candidate.is_file():
            return ImageFont.truetype(str(candidate), size * SCALE)
    return ImageFont.load_default()


def _centered(draw: ImageDraw.ImageDraw, y: int, text: str, font: ImageFont.ImageFont, fill: str) -> None:
    """Handle centered.

    Args:
        draw: Draw supplied by the caller.
        y: Y supplied by the caller.
        text: Text to parse, render, or persist.
        font: Font supplied by the caller.
        fill: Fill supplied by the caller.
    """
    box = draw.textbbox((0, 0), text, font=font)
    draw.text(((WIDTH * SCALE - (box[2] - box[0])) / 2, y * SCALE), text, font=font, fill=fill)


def _scaled_asset(path: Path, max_width: int, max_height: int) -> Image.Image:
    """Return scaled asset.

    Args:
        path: Filesystem or URL path to read, validate, or update.
        max_width: Max width supplied by the caller.
        max_height: Max height supplied by the caller.
    """
    asset = Image.open(path).convert("RGBA")
    alpha_box = asset.getchannel("A").point(lambda alpha: 255 if alpha >= 16 else 0).getbbox()
    if alpha_box:
        asset = asset.crop(alpha_box)
    asset_scale = min(
        max_width * SCALE / asset.width,
        max_height * SCALE / asset.height,
    )
    return asset.resize(
        (
            max(1, round(asset.width * asset_scale)),
            max(1, round(asset.height * asset_scale)),
        ),
        Image.Resampling.LANCZOS,
    )


def generate(output: Path, photon_logo_path: Path, brand_icon_path: Path) -> None:
    """Build operation.

    Args:
        output: Filesystem path associated with output.
        photon_logo_path: Filesystem path used for photon logo.
        brand_icon_path: Filesystem path used for brand icon.
    """
    width = WIDTH * SCALE
    height = HEIGHT * SCALE
    image = Image.new("RGB", (width, height), "#071A3A")
    pixels = image.load()
    for y in range(height):
        progress = y / max(height - 1, 1)
        for x in range(width):
            glow = max(0.0, 1.0 - (((x - width / 2) / (width * 0.7)) ** 2 + ((y - height * 0.32) / (height * 0.8)) ** 2))
            pixels[x, y] = (
                int(7 + 8 * glow),
                int(26 + 24 * glow),
                int(58 + 44 * glow + 4 * progress),
            )

    draw = ImageDraw.Draw(image)
    brand_icon = _scaled_asset(brand_icon_path, 112, 112)
    image.paste(
        brand_icon,
        (int((width - brand_icon.width) / 2), 32 * SCALE),
        brand_icon,
    )

    _centered(draw, 156, "ATLASO", _font(42, bold=True), "#FFFFFF")
    _centered(
        draw,
        216,
        "Everything your virtualization lab needs.",
        _font(17, bold=True),
        "#16C7BC",
    )
    draw.rounded_rectangle(
        (154 * SCALE, 262 * SCALE, 486 * SCALE, 266 * SCALE),
        radius=2 * SCALE,
        fill="#1769E0",
    )
    draw.rounded_rectangle(
        (320 * SCALE, 262 * SCALE, 486 * SCALE, 266 * SCALE),
        radius=2 * SCALE,
        fill="#16C7BC",
    )

    _centered(draw, 404, "Powered by", _font(13), "#FFFFFF")
    photon_logo = _scaled_asset(photon_logo_path, 210, 34)
    logo_x = int((width - photon_logo.width) / 2)
    logo_y = int(427 * SCALE + (42 * SCALE - photon_logo.height) / 2)
    badge_padding = 14 * SCALE
    badge = (
        logo_x - badge_padding,
        426 * SCALE,
        logo_x + photon_logo.width + badge_padding,
        470 * SCALE,
    )
    draw.rounded_rectangle(badge, radius=12 * SCALE, fill="#f8fafc", outline="#bfdbfe", width=2 * SCALE)
    image.paste(photon_logo, (logo_x, logo_y), photon_logo)

    image = image.resize((WIDTH, HEIGHT), Image.Resampling.LANCZOS)
    output.parent.mkdir(parents=True, exist_ok=True)
    image.save(output, format="PNG", optimize=True)


def main() -> int:
    """Run the command-line entry point.

    Returns:
        The main result.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument(
        "--photon-logo",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "image/common/boot/grub/photon-os-logo.png",
    )
    parser.add_argument(
        "--brand-icon",
        type=Path,
        default=Path(__file__).resolve().parents[1]
        / "docs/assets/brand/atlaso-app-icon-dark-512.png",
    )
    args = parser.parse_args()
    generate(args.output, args.photon_logo, args.brand_icon)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
