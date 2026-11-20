"""Test the immutable network comparison retained around Appliance Updates."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from types import ModuleType

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from atlaso.app.database import Base
from atlaso.app.models import ApplianceUpdateNetworkSnapshot, Job
from atlaso.app.security import Identity
from atlaso.app.services.monitor_update_comparison import (
    _compare_rows,
    capture_snapshot,
    get_comparison,
)
from atlaso.app.ui import _task_row


def test_capture_comparison_projects_and_classifies_network_changes(monkeypatch):
    """Verify capture persistence and projected network changes.

    Args:
        monkeypatch: Fixture that supplies deterministic before and after captures.
    """
    before = {
        "captured_at": "2026-11-18T10:00:00+00:00",
        "sections": {
            "routes": {
                "state": "ok",
                "rows": [
                    {"family": 4, "table": 254, "destination": "0.0.0.0/0", "gateway": "192.0.2.1", "interface": "eth1", "metric": 100, "rx_secret": "discard"},
                    {"family": 6, "table": 200, "destination": "::/0", "gateway": "2001:db8::1", "interface": "eth1", "metric": 100},
                ],
            },
            "rules": {"state": "ok", "rows": [{"family": 4, "priority": 100, "table": 200}]},
            "interfaces": {
                "state": "ok",
                "rows": [{"interface": "eth1", "carrier": True, "mtu": 1500, "rx_errors": 5, "tx_errors": 1}],
            },
            "forwarding": {"state": "ok", "rows": [{"family": 4, "enabled": True}]},
        },
    }
    after = {
        "captured_at": "2026-11-18T10:05:00+00:00",
        "sections": {
            "routes": {
                "state": "ok",
                "rows": [
                    {"family": 4, "table": 254, "destination": "0.0.0.0/0", "gateway": "192.0.2.2", "interface": "eth1", "metric": 50},
                ],
            },
            "rules": {"state": "unavailable", "rows": []},
            "interfaces": {
                "state": "ok",
                "rows": [{"interface": "eth1", "carrier": True, "mtu": 9000, "rx_errors": 500, "tx_errors": 100}],
            },
            "forwarding": {"state": "ok", "rows": [{"family": 4, "enabled": False}]},
        },
    }
    observations = iter((before, after))
    module = ModuleType("atlaso.app.services.monitor_runtime")
    module.collect_network = lambda *, include_neighbors: next(observations)
    monkeypatch.setitem(sys.modules, "atlaso.app.services.monitor_runtime", module)

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        job = Job(
            id="job_012345abcdef",
            type="appliance-update",
            created_by="admin",
            task_config_json=json.dumps({"mode": "run", "status_transaction_id": "transaction-1"}),
        )
        db.add(job)
        db.commit()

        assert capture_snapshot(db, job=job, phase="before") is True
        assert capture_snapshot(db, job=job, phase="before") is True
        assert capture_snapshot(db, job=job, phase="after") is True

        snapshots = db.query(ApplianceUpdateNetworkSnapshot).order_by(ApplianceUpdateNetworkSnapshot.phase).all()
        assert len(snapshots) == 2
        stored_before = json.loads(next(row.snapshot_json for row in snapshots if row.phase == "before"))
        assert "rx_errors" not in stored_before["sections"]["interfaces"]["rows"][0]
        assert "rx_secret" not in stored_before["sections"]["routes"]["rows"][0]

        comparison = get_comparison(db, job.id)
        assert comparison is not None
        assert comparison["state"] == "partial"
        assert comparison["phases"]["before"]["captured_at"] == "2026-11-18T10:00:00+00:00"
        assert comparison["sections"]["routes"]["state"] == "ok"
        assert comparison["sections"]["routes"]["changed"] == [
            {
                "before": {
                    "family": 4,
                    "table": 254,
                    "destination": "0.0.0.0/0",
                    "gateway": "192.0.2.1",
                    "interface": "eth1",
                    "metric": 100,
                },
                "after": {
                    "family": 4,
                    "table": 254,
                    "destination": "0.0.0.0/0",
                    "gateway": "192.0.2.2",
                    "interface": "eth1",
                    "metric": 50,
                },
            }
        ]
        assert len(comparison["sections"]["routes"]["removed"]) == 1
        assert comparison["sections"]["rules"]["state"] == "unavailable"
        assert comparison["sections"]["rules"]["changed"] == []
        assert comparison["sections"]["interfaces"]["changed"][0]["after"]["mtu"] == 9000
        assert comparison["sections"]["forwarding"]["changed"][0]["after"]["enabled"] is False


def test_comparison_requires_an_install_task_and_matching_transaction():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        check = Job(
            id="job_112345abcdef",
            type="appliance-update",
            created_by="admin",
            task_config_json=json.dumps({"mode": "check", "status_transaction_id": "transaction-2"}),
        )
        db.add(check)
        install = Job(
            id="job_212345abcdef",
            type="appliance-update",
            status="succeeded",
            created_by="admin",
            task_config_json=json.dumps({"mode": "run", "status_transaction_id": "transaction-3"}),
        )
        db.add(install)
        legacy = Job(
            id="job_412345abcdef",
            type="appliance-update",
            created_by="admin",
            task_config_json=json.dumps({"mode": "run"}),
        )
        db.add(legacy)
        db.commit()
        assert get_comparison(db, check.id) is None
        assert get_comparison(db, "job_missing") is None
        assert get_comparison(db, install.id)["state"] == "unrecorded"
        assert get_comparison(db, legacy.id)["state"] == "unrecorded"
        network_reader = Identity(
            "operator", "network-admin", {"read:monitoring", "read:routes"}
        )
        assert _task_row(install, network_reader)["network_comparison_available"] is True
        monitoring_reader = Identity("viewer", "viewer", {"read:monitoring"})
        assert "network_comparison_available" not in _task_row(install, monitoring_reader)
        assert "network_comparison_available" not in _task_row(check, network_reader)


def test_native_capture_failure_is_retained_as_unavailable(monkeypatch):
    """Record native capture failure without failing the update.

    Args:
        monkeypatch: Fixture that substitutes a failing native capture.
    """
    module = ModuleType("atlaso.app.services.monitor_runtime")

    def fail_capture(*, include_neighbors):
        """Simulate native collection failure.

        Args:
            include_neighbors: Whether the capture requested gateway neighbors.
        """
        assert include_neighbors is False
        raise RuntimeError("native output is deliberately omitted")

    module.collect_network = fail_capture
    monkeypatch.setitem(sys.modules, "atlaso.app.services.monitor_runtime", module)
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        job = Job(
            id="job_312345abcdef",
            type="appliance-update",
            created_by="admin",
            task_config_json=json.dumps({"mode": "run", "status_transaction_id": "transaction-4"}),
        )
        db.add(job)
        db.commit()

        assert capture_snapshot(db, job=job, phase="before") is True
        comparison = get_comparison(db, job.id)

        assert comparison is not None
        assert comparison["phases"]["before"]["captured_at"]
        assert comparison["sections"]["routes"]["state"] == "unavailable"
        assert comparison["sections"]["routes"]["added"] == []


def test_duplicate_identity_comparison_preserves_unchanged_siblings():
    before = [
        {"family": 4, "priority": 100, "table": 200, "protocol": 2},
        {"family": 4, "priority": 100, "table": 201, "protocol": 2},
    ]
    after = [
        {"family": 4, "priority": 100, "table": 200, "protocol": 2},
        {"family": 4, "priority": 100, "table": 202, "protocol": 2},
    ]

    diff = _compare_rows("rules", before, after)

    assert diff == {
        "added": [],
        "removed": [],
        "changed": [{"before": before[1], "after": after[1]}],
    }


def test_corrupt_snapshot_keeps_its_recorded_capture_time():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    captured_at = datetime(2026, 11, 18, 10, 15, tzinfo=timezone.utc)
    with Session(engine) as db:
        job = Job(
            id="job_512345abcdef",
            type="appliance-update",
            created_by="admin",
            task_config_json=json.dumps({"mode": "run", "status_transaction_id": "transaction-5"}),
        )
        db.add(job)
        db.flush()
        db.add(
            ApplianceUpdateNetworkSnapshot(
                job_id=job.id,
                phase="before",
                transaction_id="transaction-5",
                captured_at=captured_at,
                snapshot_json="{malformed",
            )
        )
        db.commit()

        comparison = get_comparison(db, job.id)

        assert comparison is not None
        assert comparison["phases"]["before"]["captured_at"] == captured_at.isoformat()
        assert comparison["sections"]["routes"]["state"] == "unavailable"
