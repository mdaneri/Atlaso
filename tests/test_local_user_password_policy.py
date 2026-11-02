"""Tests for the standard-library local user password policy."""

from atlaso.local_user_password_policy import DEFAULT_PASSWORD_POLICY, validate_password


def test_default_password_policy_is_shared_shape() -> None:
    assert DEFAULT_PASSWORD_POLICY == {
        "min_length": 12,
        "require_uppercase": True,
        "require_lowercase": True,
        "require_number": True,
        "require_special": True,
        "disallow_username": True,
    }


def test_default_policy_accepts_compliant_password() -> None:
    assert validate_password("Good-Password42!", "admin", DEFAULT_PASSWORD_POLICY) == []


def test_default_policy_reports_failures_in_existing_order() -> None:
    assert validate_password("admin", " admin ", DEFAULT_PASSWORD_POLICY) == [
        "Password must be at least 12 characters.",
        "Password must include an uppercase letter.",
        "Password must include a number.",
        "Password must include a special character.",
        "Password must not contain the username.",
    ]


def test_username_match_is_case_insensitive() -> None:
    policy = dict(DEFAULT_PASSWORD_POLICY)

    assert validate_password("AdMiN-Strong42!", " admin ", policy) == [
        "Password must not contain the username."
    ]


def test_disabled_rules_are_not_reported() -> None:
    policy = {
        "min_length": 8,
        "require_uppercase": False,
        "require_lowercase": False,
        "require_number": False,
        "require_special": False,
        "disallow_username": False,
    }

    assert validate_password("admin12x", "admin", policy) == []


def test_falsey_minimum_length_uses_existing_default() -> None:
    policy = {**DEFAULT_PASSWORD_POLICY, "min_length": 0}

    assert validate_password("Short1!", "user", policy) == [
        "Password must be at least 12 characters."
    ]
