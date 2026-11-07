"""NTP admits only fixed roots and server-required disabled network enforcement."""

import copy
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
from urllib.parse import parse_qs, urlsplit

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts/interop"))
import certificate_fixture_init as certificate  # noqa: E402 - Unchanged legacy admission.
import ntp_cold_start_native as fixture  # noqa: E402 - Local NTP consumer.

EXPECTED_ROOTS = {"appliance_settings", "network", "ca", "firewall", "public_services", "dnsmasq", "ntpd"}


@pytest.fixture
def apply_client():
    """Model the actual cold-review shape, including changed required NAT.

    The seven roots are selected by the request; WAN/NAT are selected only by
    the server as required network dependencies. No real HTTP call is made.
    """
    roots = sorted(EXPECTED_ROOTS)
    root_rows = [{"id": key, "changed": True, "valid": True, "selected": True,
                  "required_dependency": False} for key in roots]
    dependencies = [{"id": "wan", "changed": False, "valid": True, "selected": True, "required_dependency": True},
                    {"id": "nat", "changed": True, "valid": True, "selected": True, "required_dependency": True}]
    state = SimpleNamespace(
        original={"active_task": None, "units": copy.deepcopy(root_rows + dependencies)},
        filtered={"active_task": None, "plan_error": "", "plan_token": "synthetic-reviewed-token",
                  "requested_units": roots, "units": copy.deepcopy(root_rows + dependencies)},
        posts=[], expected_query_roots=roots,
        response=(202, {"job_id": "original-job", "status_url": "/tasks/original-job/status"}),
    )

    def json_request(path, form=None):
        """Serve the two actual review requests and record the single POST.

        Args:
            path: Management request path.
            form: Optional Apply submission, never passed for review GETs.
        """
        if path == "/ui/management/appliance-apply/review":
            assert form is None
            return 200, state.original
        if path.startswith("/ui/management/appliance-apply/review?"):
            assert form is None
            assert parse_qs(urlsplit(path).query) == {"selected_units": state.expected_query_roots}
            return 200, state.filtered
        assert path == "/ui/management/appliance-apply"
        state.posts.append(form)
        return state.response

    state.client = SimpleNamespace(json=Mock(side_effect=json_request), request=Mock(
        return_value=(200, '<input name="csrf" value="synthetic-csrf">')))
    return state


def test_cold_nat_dependency_is_admitted_only_as_server_selected_dependency(apply_client):
    """The observed N12 review can submit without broadening requested roots.

    Args:
        apply_client: Actual-shaped synthetic original and filtered reviews.
    """
    assert fixture.submit_initialization(apply_client.client) == ("original-job", "/tasks/original-job/status")
    assert len(apply_client.posts) == 1
    form = apply_client.posts[0]
    assert set(form["requested_units"]) == EXPECTED_ROOTS
    assert set(form["selected_units"]) == EXPECTED_ROOTS | {"wan", "nat"}
    assert form["reviewed_plan"] == "synthetic-reviewed-token"
    apply_client.client.request.assert_called_once_with("/ui/management/physical-interfaces")


def test_certificate_root_only_preflight_still_refuses_the_same_changed_nat(apply_client):
    """NTP-specific admission leaves the certificate fixture's policy unchanged.

    Args:
        apply_client: Review containing the observed changed NAT dependency.
    """
    with pytest.raises(certificate.Refusal, match="fixture_unrelated_pending_units"):
        certificate.validate_review(apply_client.original)
    assert apply_client.posts == []


@pytest.mark.parametrize("unrelated_pending", [False, True])
def test_later_transitions_select_only_firewall_ntp_and_public_services(apply_client, unrelated_pending):
    """Later NTP cases cannot replay initial Network/CA or accept their pending changes.

    Args:
        apply_client: Synthetic server-side selection reviews.
        unrelated_pending: Whether a later unrelated CA edit must stop submission.
    """
    roots = {"firewall", "ntpd", "public_services"}
    apply_client.expected_query_roots = sorted(roots)
    apply_client.filtered["requested_units"] = sorted(roots)
    rows = [row for row in apply_client.filtered["units"] if row["id"] in roots]
    apply_client.filtered["units"] = rows
    apply_client.original["units"] = copy.deepcopy(rows)
    if unrelated_pending:
        apply_client.original["units"].append({"id": "ca", "changed": True})
        with pytest.raises(fixture.Refusal, match="unrelated_pending_units"):
            fixture.submit_initialization(apply_client.client, cold_start=False)
        assert apply_client.posts == []
    else:
        fixture.submit_initialization(apply_client.client, cold_start=False)
        assert set(apply_client.posts[0]["requested_units"]) == roots
        assert set(apply_client.posts[0]["selected_units"]) == roots


@pytest.mark.parametrize("mutation", [
    "unrelated-pending", "extra-root", "extra-selected", "missing-root", "unrequired-nat", "unrequired-wan",
    "missing-dependency", "duplicate-row", "invalid-unit", "missing-token", "missing-csrf", "plan-error", "active-original", "active-filtered",
])
def test_ambiguous_or_expanded_admission_never_posts(apply_client, mutation):
    """Required dependency admission must not weaken any neighboring scope guard.

    Args:
        apply_client: Synthetic server-owned review sequence.
        mutation: Invalid review fact to substitute.
    """
    review = apply_client.filtered
    if mutation == "unrelated-pending":
        apply_client.original["units"].append({"id": "ldap", "changed": True})
    elif mutation == "extra-root":
        review["requested_units"] = [*review["requested_units"], "nat"]
    elif mutation == "extra-selected":
        review["units"].append({"id": "ldap", "valid": True, "selected": True})
    elif mutation == "missing-root":
        next(row for row in review["units"] if row["id"] == "ntpd")["selected"] = False
    elif mutation.startswith("unrequired-"):
        next(row for row in review["units"] if row["id"] == mutation.split("-", 1)[1])["required_dependency"] = False
    elif mutation == "missing-dependency":
        next(row for row in review["units"] if row["id"] == "nat")["selected"] = False
    elif mutation == "duplicate-row":
        review["units"].append(copy.deepcopy(review["units"][0]))
    elif mutation == "invalid-unit":
        review["units"][0]["valid"] = False
    elif mutation == "missing-token":
        review["plan_token"] = ""
    elif mutation == "missing-csrf":
        apply_client.client.request.return_value = (200, "missing form token")
    elif mutation == "plan-error":
        review["plan_error"] = "synthetic invalid plan"
    elif mutation == "active-original":
        apply_client.original["active_task"] = {"id": "existing"}
    else:
        review["active_task"] = {"id": "existing"}
    with pytest.raises(fixture.Refusal):
        fixture.submit_initialization(apply_client.client)
    assert apply_client.posts == []


@pytest.mark.parametrize("response", [(200, {}), (202, {"job_id": "original-job", "status_url": "/foreign"}),
                                      (202, {"job_id": "", "status_url": "/tasks//status"})])
def test_uncertain_submission_response_never_causes_another_post(apply_client, response):
    """Unknown submission outcomes remain failures requiring read-only reconciliation.

    Args:
        apply_client: Fake management transport recording the actual POST count.
        response: Unacceptable response to the original single submission.
    """
    apply_client.response = response
    with pytest.raises(fixture.Refusal, match="ntp_fixture_apply_not_admitted"):
        fixture.submit_initialization(apply_client.client)
    assert len(apply_client.posts) == 1
