"""Standard-library local user password policy shared by installer and appliance."""

from __future__ import annotations

DEFAULT_PASSWORD_POLICY: dict[str, bool | int] = {
    "min_length": 12,
    "require_uppercase": True,
    "require_lowercase": True,
    "require_number": True,
    "require_special": True,
    "disallow_username": True,
}


def validate_password(password: str, username: str, policy: dict[str, bool | int]) -> list[str]:
    """Validate password.

    Args:
        password: Candidate password whose contents are checked against the policy.
        username: Account name that must not appear in the password when prohibited.
        policy: Minimum-length and character-class requirements to enforce.

    Returns:
        Human-readable policy violations; an empty list means the password is acceptable.
    """
    errors: list[str] = []
    min_length = int(policy.get("min_length") or DEFAULT_PASSWORD_POLICY["min_length"])
    if len(password) < min_length:
        errors.append(f"Password must be at least {min_length} characters.")
    if policy.get("require_uppercase") and not any(character.isupper() for character in password):
        errors.append("Password must include an uppercase letter.")
    if policy.get("require_lowercase") and not any(character.islower() for character in password):
        errors.append("Password must include a lowercase letter.")
    if policy.get("require_number") and not any(character.isdigit() for character in password):
        errors.append("Password must include a number.")
    if policy.get("require_special") and not any(not character.isalnum() for character in password):
        errors.append("Password must include a special character.")
    normalized_username = username.strip().lower()
    if policy.get("disallow_username") and normalized_username and normalized_username in password.lower():
        errors.append("Password must not contain the username.")
    return errors
