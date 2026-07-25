from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any

from atlaso.app.models import User, utcnow


LOCAL_USERS_PASSWORD_POLICY_KEY = "local_users.password_policy.v1"
LOCAL_USERS_STAGED_CONFIG_PATH = "/var/lib/atlaso/apply/local-users/atlaso-users.json"
LOCAL_USERS_CONFIG_VERSION = 1
DEFAULT_LOCAL_USER_SHELL = "/sbin/nologin"
POWERSHELL_LOCAL_USER_SHELL = "/usr/bin/pwsh"
LOCAL_USER_SHELLS = [DEFAULT_LOCAL_USER_SHELL, "/bin/bash", "/bin/sh", POWERSHELL_LOCAL_USER_SHELL]

USERNAME_PATTERN = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
RESERVED_USERNAMES = {
    "adm",
    "bin",
    "daemon",
    "dbus",
    "games",
    "halt",
    "atlaso",
    "lp",
    "mail",
    "nfsnobody",
    "nobody",
    "operator",
    "root",
    "shutdown",
    "sshd",
    "sync",
    "systemd-network",
    "systemd-resolve",
}

DEFAULT_PASSWORD_POLICY: dict[str, bool | int] = {
    "min_length": 12,
    "require_uppercase": True,
    "require_lowercase": True,
    "require_number": True,
    "require_special": True,
    "disallow_username": True,
}

_PENDING_OS_PASSWORDS: dict[str, tuple[str, datetime]] = {}


def _pending_key(user: User | str) -> str:
    if isinstance(user, User):
        return user.username.strip().lower()
    return str(user).strip().lower()


def has_pending_os_password(user: User) -> bool:
    return _pending_key(user) in _PENDING_OS_PASSWORDS


def pending_os_password_since(user: User) -> datetime | None:
    pending = _PENDING_OS_PASSWORDS.get(_pending_key(user))
    if pending:
        return pending[1]
    return None


def pending_os_password_count(users: list[User]) -> int:
    keys = {_pending_key(user) for user in users}
    return sum(1 for key in keys if key in _PENDING_OS_PASSWORDS)


def clear_pending_os_password(user: User | str) -> None:
    _PENDING_OS_PASSWORDS.pop(_pending_key(user), None)


def rename_pending_os_password(old_username: str, new_username: str) -> None:
    pending = _PENDING_OS_PASSWORDS.pop(_pending_key(old_username), None)
    if pending:
        _PENDING_OS_PASSWORDS[_pending_key(new_username)] = pending


def password_policy_from_json(raw_value: str | None) -> dict[str, bool | int]:
    policy = dict(DEFAULT_PASSWORD_POLICY)
    if raw_value:
        try:
            payload = json.loads(raw_value)
        except json.JSONDecodeError:
            payload = {}
        if isinstance(payload, dict):
            if "min_length" in payload:
                try:
                    policy["min_length"] = max(8, min(128, int(payload["min_length"])))
                except (TypeError, ValueError):
                    pass
            for key in ("require_uppercase", "require_lowercase", "require_number", "require_special", "disallow_username"):
                if key in payload:
                    policy[key] = bool(payload[key])
    return policy


def password_policy_to_json(policy: dict[str, bool | int]) -> str:
    normalized = password_policy_from_json(json.dumps(policy))
    return json.dumps(normalized, indent=2, sort_keys=True)


def password_policy_summary(policy: dict[str, bool | int]) -> str:
    parts = [f"minimum {int(policy['min_length'])} characters"]
    if policy.get("require_uppercase"):
        parts.append("uppercase")
    if policy.get("require_lowercase"):
        parts.append("lowercase")
    if policy.get("require_number"):
        parts.append("number")
    if policy.get("require_special"):
        parts.append("special")
    if policy.get("disallow_username"):
        parts.append("no username")
    return ", ".join(parts)


def validate_password(password: str, username: str, policy: dict[str, bool | int]) -> list[str]:
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


def validate_local_usernames(users: list[User]) -> list[str]:
    errors: list[str] = []
    seen: set[str] = set()
    for user in users:
        username = user.username.strip().lower()
        if username in seen:
            errors.append(f"Duplicate local user {username}.")
        seen.add(username)
        if not USERNAME_PATTERN.fullmatch(username):
            errors.append(f"Local user {username or user.id} is not a valid Photon OS username.")
        if username in RESERVED_USERNAMES:
            errors.append(f"Local user {username} is reserved by Photon OS or Atlaso.")
        if not is_valid_user_shell(user.shell):
            errors.append(f"Local user {username} shell must be one of {', '.join(LOCAL_USER_SHELLS)}.")
    return errors


def is_valid_user_shell(shell: str | None) -> bool:
    return (shell or DEFAULT_LOCAL_USER_SHELL).strip() in LOCAL_USER_SHELLS


def normalize_user_shell(shell: str | None) -> str:
    value = (shell or DEFAULT_LOCAL_USER_SHELL).strip()
    return value if value in LOCAL_USER_SHELLS else DEFAULT_LOCAL_USER_SHELL


def os_sync_status_label(user: User) -> str:
    if has_pending_os_password(user):
        return "password staged"
    if user.os_password_applied_at:
        return "synced"
    if user.os_sync_status == "failed":
        return "sync failed"
    return "password not staged; reset to sync"


def local_user_sync_rows(users: list[User]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for user in users:
        rows.append(
            {
                "username": user.username,
                "role": user.role,
                "shell": normalize_user_shell(user.shell),
                "enabled": bool(user.enabled),
                "os_state": "desired present" if user.enabled else "desired absent",
                "password_pending": has_pending_os_password(user),
                "password_pending_since": pending_os_password_since(user).isoformat() if pending_os_password_since(user) else "",
                "password_synced_at": user.os_password_applied_at.isoformat() if user.os_password_applied_at else "",
                "last_applied_at": user.os_sync_applied_at.isoformat() if user.os_sync_applied_at else "",
                "sync_status": os_sync_status_label(user),
                "unlock_requested": bool(user.os_unlock_requested_at),
                "unlock_requested_at": user.os_unlock_requested_at.isoformat() if user.os_unlock_requested_at else "",
            }
        )
    return rows


def _normalized_removed_users(removed_users: list[str] | None = None) -> list[str]:
    normalized: list[str] = []
    for username in removed_users or []:
        value = username.strip().lower()
        if value and value not in normalized:
            normalized.append(value)
    return normalized


def local_users_payload(
    users: list[User],
    *,
    password_policy: dict[str, bool | int] | None = None,
    removed_users: list[str] | None = None,
    include_passwords: bool = False,
) -> dict[str, Any]:
    rows = local_user_sync_rows(users)
    payload = {
        "managed_by": "Atlaso",
        "version": LOCAL_USERS_CONFIG_VERSION,
        "scope": "Photon OS local users",
        "passwords_pending": sum(1 for row in rows if row["password_pending"]),
        "password_policy": password_policy_from_json(json.dumps(password_policy or DEFAULT_PASSWORD_POLICY)),
        "removed_users": _normalized_removed_users(removed_users),
        "users": [],
    }
    for user, display_row in zip(users, rows, strict=False):
        row: dict[str, Any] = {
            "username": user.username,
            "role": user.role,
            "enabled": bool(user.enabled),
            "home": f"/var/lib/atlaso/users/{user.username}",
            "shell": normalize_user_shell(user.shell),
            "password_pending": has_pending_os_password(user),
            "password_pending_since": pending_os_password_since(user).isoformat() if pending_os_password_since(user) else "",
            "password_synced_at": user.os_password_applied_at.isoformat() if user.os_password_applied_at else "",
            "unlock_requested": bool(user.os_unlock_requested_at),
            "unlock_requested_at": user.os_unlock_requested_at.isoformat() if user.os_unlock_requested_at else "",
            "sync_status": display_row["sync_status"],
        }
        if include_passwords:
            pending = _PENDING_OS_PASSWORDS.get(_pending_key(user))
            if pending:
                row["password"] = pending[0]
        payload["users"].append(row)
    return payload


def render_local_users_preview(
    users: list[User],
    *,
    password_policy: dict[str, bool | int] | None = None,
    removed_users: list[str] | None = None,
) -> str:
    return json.dumps(
        local_users_payload(users, password_policy=password_policy, removed_users=removed_users, include_passwords=False),
        indent=2,
        sort_keys=True,
    )


def render_local_users_apply_config(
    users: list[User],
    *,
    password_policy: dict[str, bool | int] | None = None,
    removed_users: list[str] | None = None,
) -> str:
    payload = local_users_payload(
        users,
        password_policy=password_policy,
        removed_users=removed_users,
        include_passwords=True,
    )
    return json.dumps(payload, indent=2, sort_keys=True)


def stage_user_os_password(user: User, password: str) -> None:
    _PENDING_OS_PASSWORDS[_pending_key(user)] = (password, utcnow())
    user.os_sync_status = "pending"
    user.os_sync_error = None


def mark_local_users_applied(users: list[User], *, applied_at: datetime | None = None) -> None:
    timestamp = applied_at or utcnow()
    for user in users:
        password_was_pending = has_pending_os_password(user)
        clear_pending_os_password(user)
        if password_was_pending:
            user.os_password_applied_at = timestamp
        if not user.enabled:
            user.os_password_applied_at = None
        user.os_sync_applied_at = timestamp
        user.os_sync_status = "applied"
        user.os_sync_error = None
        user.os_unlock_requested_at = None


def mark_local_users_failed(users: list[User], error: str) -> None:
    for user in users:
        user.os_sync_status = "failed"
        user.os_sync_error = error[:1000]
