"""Implement secrets behavior."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from hashlib import sha256

from cryptography.fernet import Fernet, InvalidToken

from atlaso.app.config import Settings, get_settings


ENCRYPTED_VALUE_PREFIX = "fernet:v1:"


@dataclass(frozen=True)
class SecretKeyStatus:
    """Represent secret key status.

    Attributes:
        dedicated: Dedicated maintained by this secretkeystatus.
        source: Source maintained by this secretkeystatus.
    """
    dedicated: bool
    source: str


def secret_key_status(settings: Settings | None = None) -> SecretKeyStatus:
    """Return secret key status."""
    settings = settings or get_settings()
    if settings.secrets_key:
        return SecretKeyStatus(dedicated=True, source="ATLASO_SECRETS_KEY")
    return SecretKeyStatus(dedicated=False, source="ATLASO_SECRET_KEY development fallback")


def _fernet(settings: Settings | None = None) -> Fernet:
    """Return fernet."""
    settings = settings or get_settings()
    source = settings.secrets_key or settings.secret_key
    key = base64.urlsafe_b64encode(sha256(source.encode("utf-8")).digest())
    return Fernet(key)


def encrypt_secret(value: str, settings: Settings | None = None) -> str:
    """Return encrypt secret."""
    if not value:
        return ""
    token = _fernet(settings).encrypt(value.encode("utf-8")).decode("ascii")
    return f"{ENCRYPTED_VALUE_PREFIX}{token}"


def decrypt_secret(value: str, settings: Settings | None = None) -> str:
    """Return decrypt secret.

    Raises:
        ValueError: If an input value is invalid.
    """
    if not value:
        return ""
    token = value.removeprefix(ENCRYPTED_VALUE_PREFIX)
    try:
        return _fernet(settings).decrypt(token.encode("ascii")).decode("utf-8")
    except InvalidToken as exc:
        raise ValueError("Encrypted Atlaso secret could not be decrypted with the configured secrets key.") from exc
