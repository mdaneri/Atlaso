"""Only completed, specifically understood cloud-init states admit clients."""

from __future__ import annotations

import json

from scripts.interop.routing_fixture_cloud_init_ready import provisioned


def status(**changes):
    """Build a minimal cloud-init status document.

    Args:
        **changes: Status fields that replace the default document values.
    """
    document = {
        "status": "done",
        "extended_status": "done",
        "datasource": "DataSourceNoCloud",
        "errors": [],
        "recoverable_errors": {},
    }
    document.update(changes)
    return json.dumps(document)


def test_clean_nocloud_boot_is_ready():
    assert provisioned(0, status())


def test_detached_seed_fallback_is_ready_only_with_exact_warning():
    fallback = status(
        datasource="none",
        extended_status="degraded done",
        recoverable_errors={"WARNING": ["Used fallback datasource"]},
    )
    assert provisioned(2, fallback)
    assert not provisioned(1, fallback)
    assert not provisioned(2, status(**{"datasource": "DataSourceEC2", "extended_status": "degraded done",
                                        "recoverable_errors": {"WARNING": ["Used fallback datasource"]}}))


def test_other_warnings_errors_or_incomplete_status_refuse():
    assert not provisioned(2, status(extended_status="degraded done",
                                     recoverable_errors={"WARNING": ["Package installation failed"]}))
    assert not provisioned(0, status(errors=["failed to apply networking"]))
    assert not provisioned(0, status(status="running"))
    assert not provisioned(0, "{not json")
