"""Keep IP SAN rejection atomic when browser validation is bypassed."""

import pytest
from sqlalchemy import select

from atlaso.app.database import SessionLocal
from atlaso.app.models import CaCertificate, CaProfile
from tests.routers.ui.helpers import login


@pytest.mark.parametrize("editing", [False, True], ids=["create", "edit"])
def test_ip_san_validation_preserves_saved_requests(client, editing):
    """Reject mixed malformed literals and retain the prior desired state.

    Args:
        client: Isolated HTTP test client.
        editing: Whether to update an existing unissued manual request.
    """
    login(client)
    page = client.get("/ui/management/certificate-authority")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    with SessionLocal() as db:
        profile = db.execute(select(CaProfile).where(CaProfile.enabled)).scalars().first()
        assert profile is not None
        profile_id = profile.id
        original = CaCertificate(
            common_name="ip-san-before.example.test",
            profile_id=profile_id,
            subject_alt_names="ip-san-before.example.test",
            ip_addresses="192.0.2.1",
            status="planned",
            enabled=False,
        )
        db.add(original)
        db.commit()
        certificate_id = original.id
        original_ids = set(db.scalars(select(CaCertificate.id)))

    url = "/ui/management/certificate-authority/certificates"
    if editing:
        url += f"/{certificate_id}/edit"
    data = {
        "csrf": csrf,
        "common_name": "ip-san-after.example.test",
        "profile_id": str(profile_id),
        "subject_alt_names": "ip-san-after.example.test",
    }
    headers = {"Accept": "application/json", "X-Atlaso-Grid": "1"}
    for malformed in ("192.0.2.999", "2001:db8:::1", "192.0.2.01", "2001:db8::1/64"):
        response = client.post(
            url,
            data={**data, "ip_addresses": f"192.0.2.10,\n{malformed}\n2001:db8::10"},
            headers=headers,
            follow_redirects=False,
        )
        assert response.status_code == 422
        assert f"invalid IP SAN {malformed}" in response.json()["detail"]
        with SessionLocal() as db:
            assert set(db.scalars(select(CaCertificate.id))) == original_ids
            saved = db.get(CaCertificate, certificate_id)
            assert saved.common_name == "ip-san-before.example.test"
            assert saved.ip_addresses == "192.0.2.1"

    valid = "0.0.0.0, 255.255.255.255\r\n::\nffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff\n::ffff:192.0.2.10"
    response = client.post(url, data={**data, "ip_addresses": valid}, headers=headers)
    assert response.status_code == 200
    saved_id = response.json()["certificate"]["id"]
    with SessionLocal() as db:
        saved = db.get(CaCertificate, saved_id)
        assert saved.ip_addresses == valid.replace(", ", "\n").replace("\r\n", "\n")
        assert saved.status == "planned"
        assert not saved.certificate_pem

    # DNS SANs satisfy the profile: clearing the optional IP list stays valid.
    response = client.post(
        f"/ui/management/certificate-authority/certificates/{saved_id}/edit",
        data={**data, "ip_addresses": " \r\n, "},
        headers=headers,
    )
    assert response.status_code == 200
    with SessionLocal() as db:
        assert db.get(CaCertificate, saved_id).ip_addresses == ""
