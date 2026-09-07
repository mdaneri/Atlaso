"""Exercise canonical Traffic Publishing browser state and legacy bridges."""

from sqlalchemy import select

from atlaso.app.database import SessionLocal
from atlaso.app.models import NatRule, PhysicalInterface, Role, User
from atlaso.app.security import roles_to_json
from tests.routers.ui.helpers import login


def test_nat_browser_autosave_and_safe_legacy_bookmarks(client):
    """Keep Routing independent and redirect only safe legacy reads.

    Args:
        client: Isolated management browser fixture.
    """
    login(client)
    page = client.get("/ui/management/traffic-publishing")
    assert page.status_code == 200
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    for method in (client.get, client.head):
        response = method("/ui/management/routes-wan/nat-rules", follow_redirects=False)
        assert response.status_code == 302
        assert response.headers["location"] == "/ui/management/traffic-publishing"
    response = client.post("/ui/management/traffic-publishing/settings", data={"csrf": csrf, "nat_enabled": "on"},
                           headers={"X-Atlaso-Autosave": "1"})
    assert response.status_code == 200
    assert response.json()["suspended"] and not response.json()["routing_enabled"]
    assert "nat_enabled=true" in response.json()["config_preview"]
    assert "NAT is suspended until Routing is enabled." in client.get("/traffic-publishing").text
    assert 'name="nat_enabled"' not in client.get("/routes-wan").text


def test_nat_browser_fixed_translation_can_change_to_masquerade(client):
    """Switching mode clears the inactive fixed field without losing ingress.

    Args:
        client: Browser and desired-state fixture.
    """
    with SessionLocal() as db:
        for name, address in (("eth2", "2001:db8:2::1/64"), ("eth3", "2001:db8:3::1/64")):
            row = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == name))
            if row is None:
                row = PhysicalInterface(name=name, mac_address="00:11:22:33:44:33")
                db.add(row)
            row.role, row.mode, row.admin_state, row.oper_state = "access", "access", "up", "up"
            row.ipv6_cidr = address
        db.commit()
    login(client)
    page = client.get("/traffic-publishing")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    body = {"csrf": csrf, "name": "Browser NAT66", "ip_family": "6", "translation_mode": "snat",
            "translated_address": "2001:db8:3::1", "inbound_interfaces": ["eth2"],
            "outbound_interface": "eth3", "source": "any", "enabled": "on", "priority": "100"}
    created = client.post("/ui/management/traffic-publishing/nat-rules", data=body, follow_redirects=False)
    assert created.status_code == 303, created.text
    with SessionLocal() as db:
        rule = db.scalar(select(NatRule).where(NatRule.name == body["name"]))
        assert rule is not None
        rule_id = rule.id
    body.pop("translated_address")
    body["translation_mode"] = "masquerade"
    edited = client.post(f"/ui/management/routes-wan/nat-rules/{rule_id}/edit", data=body, follow_redirects=False)
    assert edited.status_code == 303
    assert edited.headers["location"] == "/ui/management/traffic-publishing"
    with SessionLocal() as db:
        rule = db.get(NatRule, rule_id)
        assert rule.translated_address == "" and rule.masquerade and rule.ip_family == 6
        assert rule.inbound_interfaces == ["eth2"]


def test_nat_viewer_has_read_only_fallback_and_cannot_write(client):
    """Hide fallback mutation controls and enforce server-side write permission.

    Args:
        client: Session fixture with a viewer identity.
    """
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.username == "admin"))
        user.role = Role.VIEWER.value
        user.roles_json = roles_to_json([Role.VIEWER.value])
        db.commit()
    login(client)
    page = client.get("/traffic-publishing")
    assert page.status_code == 200
    assert 'data-can-write="false"' in page.text
    assert 'id="routes-wan-nat-dialog"' not in page.text
    assert 'data-confirm-title="Delete NAT rule' not in page.text
    assert client.post("/ui/management/traffic-publishing/settings", data={"nat_enabled": "on"}).status_code == 403


def test_suspended_nat_apply_keeps_routing_baseline_independent(client):
    """Applying suspended NAT cannot apply an unrelated pending Routing edit.

    Args:
        client: Synchronous dry-run Apply fixture.
    """
    import json

    from atlaso.app.models import Job
    from atlaso.app.services.traffic_publishing import save_traffic_publishing_settings
    from atlaso.app.ui import load_appliance_apply_baselines

    with SessionLocal() as db:
        save_traffic_publishing_settings(db, nat_enabled=True)
        db.commit()
        previous_wan = load_appliance_apply_baselines(db).get("wan")
    login(client)
    page = client.get("/traffic-publishing")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    result = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": "nat"},
                         headers={"Accept": "application/json"})
    assert result.status_code == 202
    with SessionLocal() as db:
        job = db.get(Job, result.json()["job_id"])
        payload = json.loads(job.result)
        assert job.status == "succeeded"
        assert payload["selected_units"] == ["nat"]
        baseline = load_appliance_apply_baselines(db)
        assert baseline.get("wan") == previous_wan
        assert "routing_enabled=false" in baseline["nat"]["config_preview"]
