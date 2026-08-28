"""Define the persisted authentication-lifetime policy contract."""

BROWSER_SESSION_IDLE_TIMEOUT_DEFAULT_MINUTES = 30
BROWSER_SESSION_IDLE_TIMEOUT_MINUTES = (5, 1440)
API_TOKEN_MAX_LIFETIME_DEFAULT_DAYS = 90
API_TOKEN_MAX_LIFETIME_DAYS = (1, 365)


def authentication_lifetime_validation_error(
    *, browser_idle_minutes: int, api_token_days: int
) -> str | None:
    """Return the first validation error for persisted authentication policy."""
    idle_minimum, idle_maximum = BROWSER_SESSION_IDLE_TIMEOUT_MINUTES
    if not idle_minimum <= browser_idle_minutes <= idle_maximum:
        return (
            "Browser session inactivity timeout must be between "
            f"{idle_minimum} and {idle_maximum} minutes."
        )
    token_minimum, token_maximum = API_TOKEN_MAX_LIFETIME_DAYS
    if not token_minimum <= api_token_days <= token_maximum:
        return (
            "Maximum API token lifetime must be between "
            f"{token_minimum} and {token_maximum} days."
        )
    return None
