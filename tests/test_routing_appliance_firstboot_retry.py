"""Keep the private first-boot retry limited to the admitted DHCP fixture."""

from __future__ import annotations

from types import SimpleNamespace

from scripts.interop.routing_appliance_firstboot_retry import eligible_review


def test_retry_requires_expected_review_and_actual_fixture_address():
    """Reject unrelated console reviews and DHCP addresses before mutation."""
    review = SimpleNamespace(
        error="Native management addresses did not activate; review conflicts and network connectivity.",
        ipv4_method="dhcp", ipv4_cidr="", gateway="", ipv6_mode="disabled",
        ipv6_cidr="", ipv6_gateway="",
    )
    assigned = [{"ifname": "eth0", "addr_info": [{"family": "inet", "local": "192.0.2.10"}]}]
    assert eligible_review(review, assigned)
    assert not eligible_review(review, [{"ifname": "eth0", "addr_info": [{"family": "inet", "local": "192.0.2.11"}]}])
    assert not eligible_review(SimpleNamespace(**{**vars(review), "ipv4_method": "static"}), assigned)
    assert not eligible_review(SimpleNamespace(**{**vars(review), "error": "Unrelated network error"}), assigned)
    assert not eligible_review(None, assigned)
