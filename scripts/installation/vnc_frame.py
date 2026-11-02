"""Compare bounded PNG console frames while allowing one concealed field region."""

from __future__ import annotations

import hashlib
import hmac
import io
import re
import warnings
from typing import Any

_MAX_PNG_BYTES = 8 * 1024 * 1024
_MAX_PIXELS = 4_000_000
_MAX_FIELD_HEIGHT = 32


def frames_match(
    expected: bytes,
    current: bytes,
    digest: str,
    rectangle: tuple[int, int, int, int],
) -> bool:
    """Compare two PNG frames outside one bounded concealed input rectangle.

    Both images are decoded as RGB. The digest binds the expected frame to its
    caller-admitted file, while exact pixel comparison ensures the complete
    screen outside ``rectangle`` stayed unchanged.

    Args:
        expected: Caller-admitted PNG bytes whose digest is checked.
        current: PNG bytes captured from the live console in memory.
        digest: Lowercase or uppercase hexadecimal SHA-256 digest of
            ``expected``.
        rectangle: Half-open pixel rectangle ``(x0, y0, x1, y1)`` containing
            only the concealed input field.

    Returns:
        ``True`` when all RGB pixels outside the rectangle match, otherwise
        ``False``.

    Raises:
        ValueError: If either PNG, its digest, its dimensions, or the rectangle
            violates the bounded validation rules.
    """
    _validate_png_bytes(expected)
    _validate_png_bytes(current)
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-fA-F]{64}", digest) is None:
        raise ValueError("Expected image digest is invalid.")
    if not hmac.compare_digest(hashlib.sha256(expected).hexdigest(), digest.lower()):
        raise ValueError("Expected image digest does not match.")

    expected_rgb = _decode_rgb_png(expected)
    current_rgb = _decode_rgb_png(current)
    if expected_rgb.size != current_rgb.size:
        raise ValueError("PNG frame dimensions do not match.")

    width, height = expected_rgb.size
    x0, y0, x1, y1 = _validate_rectangle(rectangle, width, height)
    expected_pixels = expected_rgb.tobytes()
    current_pixels = current_rgb.tobytes()
    row_bytes = width * 3
    left_bytes = x0 * 3
    right_start = x1 * 3

    for y in range(height):
        row_start = y * row_bytes
        expected_row = expected_pixels[row_start : row_start + row_bytes]
        current_row = current_pixels[row_start : row_start + row_bytes]
        if y0 <= y < y1:
            if expected_row[:left_bytes] != current_row[:left_bytes]:
                return False
            if expected_row[right_start:] != current_row[right_start:]:
                return False
        elif expected_row != current_row:
            return False
    return True


def _validate_png_bytes(image_bytes: bytes) -> None:
    """Validate the type and encoded-size bound for PNG input.

    Args:
        image_bytes: Encoded image data to validate.

    Raises:
        ValueError: If the value is not nonempty bytes within the size limit.
    """
    if not isinstance(image_bytes, bytes) or not image_bytes or len(image_bytes) > _MAX_PNG_BYTES:
        raise ValueError("PNG input is invalid or exceeds the size limit.")


def _decode_rgb_png(image_bytes: bytes) -> Any:
    """Decode one bounded PNG and return its RGB pixels.

    Args:
        image_bytes: Encoded PNG data already checked for a byte-size bound.

    Returns:
        A detached Pillow RGB image with no more than the allowed pixel count.

    Raises:
        ValueError: If Pillow is unavailable or the PNG is malformed, oversized,
            or exceeds the pixel bound.
    """
    try:
        from PIL import Image
    except ImportError as exc:
        raise ValueError("PNG validation support is unavailable.") from exc

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(image_bytes)) as image:
                if image.format != "PNG":
                    raise ValueError("PNG input is invalid.")
                width, height = image.size
                if width <= 0 or height <= 0 or width * height > _MAX_PIXELS:
                    raise ValueError("PNG dimensions exceed the pixel limit.")
                image.verify()
            with Image.open(io.BytesIO(image_bytes)) as image:
                if image.format != "PNG" or image.size != (width, height):
                    raise ValueError("PNG input is invalid.")
                image.load()
                return image.convert("RGB")
    except Exception as exc:
        if isinstance(exc, ValueError) and str(exc) in {
            "PNG input is invalid.",
            "PNG dimensions exceed the pixel limit.",
        }:
            raise
        raise ValueError("PNG input is invalid.") from None


def _validate_rectangle(
    rectangle: tuple[int, int, int, int],
    frame_width: int,
    frame_height: int,
) -> tuple[int, int, int, int]:
    """Validate a half-open concealed-field rectangle against frame bounds.

    Args:
        rectangle: Candidate ``(x0, y0, x1, y1)`` pixel coordinates.
        frame_width: Width of the decoded RGB frame in pixels.
        frame_height: Height of the decoded RGB frame in pixels.

    Returns:
        The validated coordinates.

    Raises:
        ValueError: If the rectangle is malformed, outside the frame, too tall,
            or wider than 80 percent of the frame.
    """
    if (
        not isinstance(rectangle, tuple)
        or len(rectangle) != 4
        or any(type(coordinate) is not int for coordinate in rectangle)
    ):
        raise ValueError("Input rectangle is invalid.")
    x0, y0, x1, y1 = rectangle
    rectangle_width = x1 - x0
    rectangle_height = y1 - y0
    if (
        x0 < 0
        or y0 < 0
        or x1 > frame_width
        or y1 > frame_height
        or rectangle_width <= 0
        or rectangle_height <= 0
        or rectangle_height > _MAX_FIELD_HEIGHT
        or rectangle_width * 5 > frame_width * 4
    ):
        raise ValueError("Input rectangle is outside the allowed bounds.")
    return x0, y0, x1, y1
