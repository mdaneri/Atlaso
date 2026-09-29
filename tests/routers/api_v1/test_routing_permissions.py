"""Exercise Routing Permission API authorization and desired-state behavior."""

from sqlalchemy import select

from tests.routers.api_v1.helpers import create_token


def _permission_payload(**overrides: object) -> dict[str, object]:
    """Return one valid complete permission request body."""
    return {
        "name": "API permission",
        "enabled": True,
        "source_interface": "eth2",
        "destination_interface": "eth1.20",
        "priority": 100,
        "description": "Reviewed test rule",
        "policy": "deny",
        "ip_family": 4,
        **overrides,
    }


def _prepare_targets() -> None:
    """Make two isolated lab targets available to current API validation."""
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface, VlanInterface

    with SessionLocal() as db:
        source = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        destination = db.scalar(select(VlanInterface).where(VlanInterface.name == "eth1.20"))
        assert source is not None and destination is not None
        source.role = "access"
        source.mode = "access"
        source.admin_state = "up"
        source.oper_state = "up"
        source.ip_cidr = "192.0.2.1/24"
        destination.role = "access"
        destination.enabled = True
        destination.ip_cidr = "198.51.100.1/24"
        db.commit()


def _prepare_generated_targets() -> None:
    """Create two route-role targets that produce generated permissions."""
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface, VlanInterface

    with SessionLocal() as db:
        source = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        destination = db.scalar(select(VlanInterface).where(VlanInterface.name == "eth1.20"))
        assert source is not None and destination is not None
        source.role = "route"
        source.mode = "access"
        source.admin_state = "up"
        source.oper_state = "up"
        source.ip_cidr = "192.0.2.1/24"
        destination.role = "route"
        destination.enabled = True
        destination.ip_cidr = "198.51.100.1/24"
        db.commit()


def test_routing_permission_crud_requires_routes_scope_and_preserves_policy(client):
    """Save, replace and remove desired state under Routes scopes only.

    Args:
        client: Isolated Atlaso HTTP client.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import AuditEvent

    _prepare_targets()
    reader, _ = create_token(client, scopes=["read:routes"])
    writer, _ = create_token(client, scopes=["read:routes", "write:routes"])
    other_writer, _ = create_token(client, scopes=["read:firewall", "write:firewall"])
    headers = {"Authorization": f"Bearer {writer}"}
    path = "/api/v1/routing-permissions"

    assert client.post(path, json=_permission_payload(), headers={"Authorization": f"Bearer {other_writer}"}).status_code == 403
    assert client.post(path, json=_permission_payload(), headers={"Authorization": f"Bearer {reader}"}).status_code == 403
    created = client.post(path, json=_permission_payload(), headers=headers)
    assert created.status_code == 201, created.text
    saved = created.json()
    assert saved["generated"] is False
    assert saved["policy"] == "deny"
    assert saved["ip_family"] == 4

    rule_path = f"{path}/{saved['id']}"
    assert client.get(path, headers={"Authorization": f"Bearer {reader}"}).status_code == 200
    replacement = client.put(rule_path, json=_permission_payload(policy="automatic", ip_family=0), headers=headers)
    assert replacement.status_code == 200, replacement.text
    assert replacement.json()["policy"] == "automatic"
    assert replacement.json()["ip_family"] == 0
    assert replacement.json()["apply_state"] == "pending"
    assert client.delete(rule_path, headers=headers).status_code == 204

    with SessionLocal() as db:
        actions = list(db.scalars(
            select(AuditEvent.action)
            .where(AuditEvent.resource_type == "routing_permission")
            .order_by(AuditEvent.id)
        ))
    assert actions == ["create_routing_permission", "update_routing_permission", "delete_routing_permission"]


def test_routing_permission_management_target_is_rejected(client):
    """Reject a management interface even when paired with a valid lab target.

    Args:
        client: Isolated Atlaso HTTP client.
    """
    _prepare_targets()
    writer, _ = create_token(client, scopes=["write:routes"])
    response = client.post(
        "/api/v1/routing-permissions",
        json=_permission_payload(source_interface="eth0"),
        headers={"Authorization": f"Bearer {writer}"},
    )
    assert response.status_code == 422, response.text
    assert response.json()["status"] == 422
    assert response.json()["error_code"] == "HTTP_ERROR"


def test_generated_routing_permissions_are_read_only(client):
    """Reject update and delete attempts against generated permission rows.

    Args:
        client: Isolated Atlaso HTTP client.
    """
    _prepare_generated_targets()
    reader, _ = create_token(client, scopes=["read:routes"])
    writer, _ = create_token(client, scopes=["write:routes"])
    path = "/api/v1/routing-permissions"
    rows = client.get(path, headers={"Authorization": f"Bearer {reader}"})
    assert rows.status_code == 200, rows.text
    generated = next(row for row in rows.json() if row["generated"])
    generated_path = f"{path}/{generated['id']}"

    replaced = client.put(
        generated_path,
        json=_permission_payload(name="Generated replacement"),
        headers={"Authorization": f"Bearer {writer}"},
    )
    assert replaced.status_code == 409, replaced.text
    assert replaced.json()["error_code"] == "HTTP_ERROR"
    deleted = client.delete(generated_path, headers={"Authorization": f"Bearer {writer}"})
    assert deleted.status_code == 409, deleted.text
    assert deleted.json()["error_code"] == "HTTP_ERROR"


def test_routing_permission_rejects_unknown_policy_and_boolean_family(client):
    """Reject enum violations and bool values masquerading as integer families.

    Args:
        client: Isolated Atlaso HTTP client.
    """
    _prepare_targets()
    writer, _ = create_token(client, scopes=["write:routes"])
    headers = {"Authorization": f"Bearer {writer}"}
    path = "/api/v1/routing-permissions"
    for invalid in (
        _permission_payload(policy="accept"),
        _permission_payload(ip_family=True),
    ):
        response = client.post(path, json=invalid, headers=headers)
        assert response.status_code == 422, response.text
        assert response.json()["error_code"] == "VALIDATION_ERROR"


def test_duplicate_routing_permission_name_returns_conflict_without_partial_audit(client):
    """Roll back duplicate desired state without adding a second audit event.

    Args:
        client: Isolated Atlaso HTTP client.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import AuditEvent, RoutingRule

    _prepare_targets()
    writer, _ = create_token(client, scopes=["write:routes"])
    headers = {"Authorization": f"Bearer {writer}"}
    path = "/api/v1/routing-permissions"
    payload = _permission_payload()
    created = client.post(path, json=payload, headers=headers)
    assert created.status_code == 201, created.text
    duplicate = client.post(path, json=payload, headers=headers)
    assert duplicate.status_code == 409, duplicate.text
    assert duplicate.json()["error_code"] == "HTTP_ERROR"

    with SessionLocal() as db:
        assert db.scalar(select(RoutingRule.id).where(RoutingRule.name == payload["name"])) is not None
        assert db.scalar(select(AuditEvent.id).where(AuditEvent.action == "create_routing_permission")) is not None
        assert len(list(db.scalars(select(RoutingRule).where(RoutingRule.name == payload["name"])))) == 1
        assert len(list(db.scalars(select(AuditEvent).where(AuditEvent.action == "create_routing_permission")))) == 1
