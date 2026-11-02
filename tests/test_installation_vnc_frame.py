"""Tests for the pure, bounded VNC frame comparison helper."""

from __future__ import annotations

import hashlib
import io

import pytest

from scripts.installation.vnc_frame import frames_match

PIL_IMAGE = pytest.importorskip("PIL.Image")


def _png(size: tuple[int, int], color: tuple[int, int, int] = (12, 34, 56)) -> bytes:
    """Encode a synthetic RGB PNG for comparison tests.

    Args:
        size: Public synthetic image dimensions in pixels.
        color: Public RGB color used to fill the image.

    Returns:
        Encoded PNG bytes.
    """
    image = PIL_IMAGE.new("RGB", size, color)
    output = io.BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def _sha256(data: bytes) -> str:
    """Return the digest for public synthetic image bytes.

    Args:
        data: Public test bytes.

    Returns:
        Lowercase SHA-256 hexadecimal digest.
    """
    return hashlib.sha256(data).hexdigest()


def test_frame_matches_when_only_concealed_input_row_changes() -> None:
    """Permit variations confined to the caller-selected field rectangle."""
    expected = PIL_IMAGE.new("RGB", (120, 60), (12, 34, 56))
    current = expected.copy()
    current.putpixel((18, 25), (220, 221, 222))
    current.putpixel((48, 31), (230, 231, 232))
    expected_bytes = _encode(expected)

    assert frames_match(
        expected_bytes,
        _encode(current),
        _sha256(expected_bytes),
        (10, 20, 50, 32),
    )


def test_frame_rejects_title_change_outside_concealed_field() -> None:
    """Reject a changed title or other pixel outside the field rectangle."""
    expected = PIL_IMAGE.new("RGB", (120, 60), (12, 34, 56))
    current = expected.copy()
    current.putpixel((80, 5), (255, 0, 0))
    expected_bytes = _encode(expected)

    assert not frames_match(
        expected_bytes,
        _encode(current),
        _sha256(expected_bytes),
        (10, 20, 50, 32),
    )


def test_frame_rejects_digest_mismatch() -> None:
    """Require the admitted expected PNG digest to match its bytes."""
    expected = _png((120, 60))

    with pytest.raises(ValueError, match="Expected image digest does not match"):
        frames_match(expected, expected, "0" * 64, (10, 20, 50, 32))


def test_frame_rejects_invalid_digest_format() -> None:
    """Reject malformed expected digest text before image processing."""
    expected = _png((120, 60))

    with pytest.raises(ValueError, match="Expected image digest is invalid"):
        frames_match(expected, expected, "not-a-digest", (10, 20, 50, 32))


def test_frame_rejects_oversized_png_bytes() -> None:
    """Apply the encoded PNG size cap before hashing or decoding."""
    oversized = b"x" * (8 * 1024 * 1024 + 1)
    current = _png((120, 60))

    with pytest.raises(ValueError, match="PNG input is invalid or exceeds the size limit"):
        frames_match(oversized, current, _sha256(oversized), (10, 20, 50, 32))

    with pytest.raises(ValueError, match="PNG input is invalid or exceeds the size limit"):
        frames_match(current, oversized, _sha256(current), (10, 20, 50, 32))


def test_frame_rejects_malformed_png_data() -> None:
    """Reject malformed image bytes with a sanitized validation error."""
    malformed = b"not a PNG"
    current = _png((120, 60))

    with pytest.raises(ValueError, match="PNG input is invalid"):
        frames_match(malformed, current, _sha256(malformed), (10, 20, 50, 32))

    with pytest.raises(ValueError, match="PNG input is invalid"):
        frames_match(current, malformed, _sha256(current), (10, 20, 50, 32))


def test_frame_rejects_non_png_encoding() -> None:
    """Require PNG encoding even when another image format is decodable."""
    image = PIL_IMAGE.new("RGB", (120, 60), (12, 34, 56))
    output = io.BytesIO()
    image.save(output, format="JPEG")
    jpeg = output.getvalue()

    with pytest.raises(ValueError, match="PNG input is invalid"):
        frames_match(jpeg, _png((120, 60)), _sha256(jpeg), (10, 20, 50, 32))


def test_frame_rejects_pixel_count_above_limit() -> None:
    """Reject image dimensions above the decoded-pixel cap before loading pixels."""
    oversized = _png((2001, 2000))

    with pytest.raises(ValueError, match="PNG dimensions exceed the pixel limit"):
        frames_match(oversized, _png((120, 60)), _sha256(oversized), (10, 20, 50, 32))


@pytest.mark.parametrize(
    "rectangle",
    [
        (-1, 0, 20, 10),
        (0, 0, 121, 10),
        (10, 10, 10, 20),
        (0, 0, 97, 10),
        (10, 10, 20, 43),
        [10, 10, 20, 20],
        (10, 10, 20, True),
    ],
)
def test_frame_rejects_invalid_or_oversized_rectangles(
    rectangle: tuple[int, int, int, int] | list[int],
) -> None:
    """Reject malformed, out-of-frame, too-wide, or too-tall field regions.

    Args:
        rectangle: Candidate rectangle expected to fail validation.
    """
    expected = _png((120, 60))

    with pytest.raises(ValueError, match="Input rectangle"):
        frames_match(expected, expected, _sha256(expected), rectangle)  # type: ignore[arg-type]  # Invalid candidates intentionally exercise runtime validation.


def test_frame_rejects_dimension_mismatch() -> None:
    """Reject live frames whose dimensions differ from the admitted image."""
    expected = _png((120, 60))
    current = _png((121, 60))

    with pytest.raises(ValueError, match="PNG frame dimensions do not match"):
        frames_match(expected, current, _sha256(expected), (10, 20, 50, 32))


def _encode(image: object) -> bytes:
    """Encode a synthetic Pillow image as PNG bytes.

    Args:
        image: Synthetic image created by the test module.

    Returns:
        Encoded PNG bytes.
    """
    output = io.BytesIO()
    image.save(output, format="PNG")  # type: ignore[attr-defined]  # Pillow is optional in the project runtime.
    return output.getvalue()
