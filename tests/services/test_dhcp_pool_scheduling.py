"""Test DHCP pool verification schedule admission rules."""

import json
from datetime import datetime, timezone

import pytest

from atlaso.app.services.automation import validate_schedule_values


@pytest.mark.parametrize(
    "expression", ["0 * * * *", "15 2 * * *", "59 23 1 * 0", "0 0,12 * * *"]
)
def test_dhcp_pool_schedule_accepts_fixed_minute_cron(expression: str) -> None:
    """Accept recurring schedules with at most one run in each hour."""
    assert validate_schedule_values(
        task_type="dhcp_pool_verify",
        task_config_json=json.dumps({"scope_id": 7}),
        schedule_kind="cron",
        cron_expression=expression,
        run_once_at=None,
        timezone_name="UTC",
    ) == []


@pytest.mark.parametrize(
    "expression",
    ["*/15 * * * *", "0,30 * * * *", "0-30 * * * *"],
)
def test_dhcp_pool_schedule_rejects_frequent_or_multiple_minute_runs(expression: str) -> None:
    """Reject minute fields that can queue verification more than hourly."""
    errors = validate_schedule_values(
        task_type="dhcp_pool_verify",
        task_config_json=json.dumps({"scope_id": 7}),
        schedule_kind="cron",
        cron_expression=expression,
        run_once_at=None,
        timezone_name="UTC",
    )
    assert "DHCP pool verification schedules must recur hourly or less often." in errors


def test_dhcp_pool_schedule_rejects_one_time_run() -> None:
    """Require explicit recurring cadence for DHCP verification schedules."""
    errors = validate_schedule_values(
        task_type="dhcp_pool_verify",
        task_config_json=json.dumps({"scope_id": 7}),
        schedule_kind="once",
        cron_expression="",
        run_once_at=datetime(2030, 1, 1, tzinfo=timezone.utc),
        timezone_name="UTC",
    )
    assert "DHCP pool verification schedules must recur hourly or less often." in errors


@pytest.mark.parametrize("scope_id", [None, "7", 0, -1, True])
def test_dhcp_pool_schedule_requires_positive_integer_scope_id(scope_id: object) -> None:
    """Reject missing, coerced, non-positive, and boolean scope identities."""
    errors = validate_schedule_values(
        task_type="dhcp_pool_verify",
        task_config_json=json.dumps({"scope_id": scope_id}),
        schedule_kind="cron",
        cron_expression="0 2 * * *",
        run_once_at=None,
        timezone_name="UTC",
    )
    assert "DHCP pool verification schedules require a positive integer scope_id." in errors
