"""Read-only USB comparison tests including corrupt, short and oversized devices."""

import hashlib
import io

import pytest

from scripts.verify_installation_usb import compare_prefix, verify_written


@pytest.mark.parametrize("trailing", [b"", b"unallocated capacity"])
def test_readback_compares_image_prefix_without_writing(tmp_path, trailing):
    """A larger stick is verified against exactly the authenticated image bytes.

    Args:
        tmp_path: Separate image and raw-device fixtures.
        trailing: Unused bytes beyond the image extent.
    """
    content = b"offline image sector".ljust(512, b"\0") * 4097
    image = tmp_path / "image.iso"
    device = tmp_path / "device.raw"
    image.write_bytes(content)
    device.write_bytes(content + trailing)
    assert verify_written(image, device) == hashlib.sha256(content).hexdigest()
    assert device.read_bytes() == content + trailing


@pytest.mark.parametrize("actual", [b"", b"x" * 511, b"x" * 512, b"x" * 1024])
def test_short_or_corrupt_device_refuses(actual):
    """Never report a partial read or a one-byte difference as verification.

    Args:
        actual: Corrupt or truncated raw device bytes.
    """
    with pytest.raises(ValueError, match="differs"):
        compare_prefix(io.BytesIO(b"a" * 1024), io.BytesIO(actual), 1024)


def test_readback_refuses_image_as_its_own_device(tmp_path):
    """Comparing the source against itself is not USB verification.

    Args:
        tmp_path: Isolated image file.
    """
    image = tmp_path / "image.iso"
    image.write_bytes(bytes(512))
    with pytest.raises(ValueError, match="separate"):
        verify_written(image, image)
