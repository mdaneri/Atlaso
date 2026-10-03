"""Test bounded CA certificate filenames."""

import hashlib

from atlaso.app.services.ca import safe_certificate_name


def test_safe_certificate_name_preserves_names_through_245_ascii_bytes():
    """Keep existing short sanitized names unchanged up to the chain filename limit."""
    for length in (1, 245):
        value = "a" * length
        assert safe_certificate_name(value) == value


def test_safe_certificate_name_hashes_names_longer_than_245_ascii_bytes():
    """Reserve the full chain suffix and use a digest when truncation is needed."""
    for length in (246, 253):
        value = "a" * length
        result = safe_certificate_name(value)

        assert result == f"{'a' * 180}-{hashlib.sha256(value.encode('utf-8')).hexdigest()}"
        assert len(result.encode("ascii")) == 245
        assert len(f"{result}-chain.pem".encode("ascii")) == 255


def test_safe_certificate_name_distinguishes_long_names_with_same_prefix():
    """Keep identities with a shared readable prefix collision resistant."""
    first = "service-" + "a" * 240 + "-one"
    second = "service-" + "a" * 240 + "-two"

    first_name = safe_certificate_name(first)
    second_name = safe_certificate_name(second)

    assert first_name[:180] == second_name[:180]
    assert first_name != second_name
    assert first_name.endswith(hashlib.sha256(first.encode("utf-8")).hexdigest())
    assert second_name.endswith(hashlib.sha256(second.encode("utf-8")).hexdigest())


def test_safe_certificate_name_sanitizes_empty_and_unicode_inputs():
    """Retain the existing ASCII filename sanitization and fallback behavior."""
    assert safe_certificate_name("api.example.test") == "api.example.test"
    assert safe_certificate_name("  api name  ") == "api-name"
    assert safe_certificate_name("") == "certificate"
    assert safe_certificate_name("☃") == "certificate"
    assert safe_certificate_name("münich.example") == "m-nich.example"
