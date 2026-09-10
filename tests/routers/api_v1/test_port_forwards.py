"""Exercise Firewall authorization and desired-only destination translations."""

from sqlalchemy import select

from tests.routers.api_v1.helpers import create_token
from tests.services.test_port_forwarding import payload


def test_port_forward_crud_requires_firewall_scope_and_preserves_rejected_intent(client, monkeypatch):
    """Route through the real API contract without allowing appliance enforcement.

    Args:
        client: Isolated Atlaso HTTP client.
        monkeypatch: Forbid helper execution during desired-state CRUD.
    """
    from atlaso.app.adapters.system import SystemAdapter
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface

    def forbidden(*args, **kwargs):
        """Fail any attempt to mutate or query the host during a desired-state save.

        Args:
            *args: Unexpected helper arguments.
            **kwargs: Unexpected helper options.
        """
        raise AssertionError("CRUD invoked the host helper")

    with SessionLocal() as db:
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth1"))
        assert interface is not None
        interface.role = "access"
        interface.mode = "access"
        interface.admin_state = "up"
        interface.oper_state = "up"
        interface.ip_cidr = "192.0.2.1/24"
        db.commit()
    writer, _ = create_token(client, scopes=["read:firewall", "write:firewall"])
    wan, _ = create_token(client, scopes=["read:wan", "write:wan"])
    reader, _ = create_token(client, scopes=["read:firewall"])
    monkeypatch.setattr(SystemAdapter, "_helper_result", forbidden)
    path = "/api/v1/traffic-publishing/port-forwards"
    headers = {"Authorization": f"Bearer {writer}"}
    assert client.post(path, json=payload(), headers={"Authorization": f"Bearer {wan}"}).status_code == 403
    assert client.post(path, json=payload(), headers={"Authorization": f"Bearer {reader}"}).status_code == 403
    response = client.post(path, json=payload(), headers=headers)
    assert response.status_code == 201, response.text
    saved = response.json()
    assert saved["apply_required"] is True
    assert "acknowledge_source_loss" not in saved
    rule_path = f"{path}/{saved['id']}"
    assert client.get(rule_path, headers=headers).json()["name"] == "web"
    invalid = client.put(rule_path, json=payload(target_port_end=13003), headers=headers)
    assert invalid.status_code == 422
    assert invalid.json()["status"] == 422
    assert invalid.json()["error_code"] == "VALIDATION_ERROR"
    assert client.get(rule_path, headers=headers).json()["target_port_end"] == 13002
    updated = client.put(rule_path, json=payload(enabled=False), headers=headers)
    assert updated.status_code == 200, updated.text
    assert updated.json()["enabled"] is False
    assert client.delete(rule_path, headers=headers).status_code == 204
    assert client.get(rule_path, headers=headers).status_code == 404
