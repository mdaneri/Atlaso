"""Exercise reviewed consent through each repository-owned Apply transport."""

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

from scripts.interop import lifecycle_test as lifecycle
from scripts.interop import routing_overlap_scenario as routing
from scripts.interop import time_source_guest as guest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts" / "interop"))
import certificate_handoff_native as certificate  # noqa: E402 - Standalone native runner.


def review(roots: list[str]) -> dict:
    """Provide a dependency-expanded server review.

    Args:
        roots: Explicit reviewed choices.
    """
    return {"requested_units": roots, "plan_token": "review-token", "units": [
        {"id": root, "selected": True, "valid": True, "changed": True} for root in roots
    ] + [{"id": "nat", "selected": True, "valid": True, "changed": False}]}


@pytest.mark.parametrize("caller", ["lifecycle", "routing", "guest", "certificate"])
@pytest.mark.parametrize("invalid", [None, "token", "active", "unit", "plan"])
def test_clients_bind_submission_to_selection_review(monkeypatch, caller, invalid):
    """All clients submit the reviewed dependencies and refuse unavailable consent.

    Args:
        monkeypatch: Replace only transport boundaries.
        caller: Repository-owned validation client.
        invalid: Whether the server review lacks its consent token.
    """
    roots = (["network", "ca", "firewall", "appliance_settings", "public_services"]
             if caller == "certificate" else ["ntpd"] if caller == "guest" else ["network"])
    payload = review(roots)
    if invalid == "token":
        payload["plan_token"] = ""
    elif invalid == "active":
        payload["active_task"] = {"job_id": "job_busy"}
    elif invalid == "unit":
        payload["units"][0]["valid"] = False
    elif invalid == "plan":
        payload["plan_error"] = "Unavailable execution plan."
    submissions = []
    paths = []

    def json_request(method, path):
        """Return the review or a completed task.

        Args:
            method: HTTP method.
            path: Requested URL.
        """
        paths.append(path)
        if "/review?" in path:
            assert set(parse_qs(urlsplit(path).query)["selected_units"]) == set(roots)
            return payload
        return {"task": {"status": "succeeded", "result": {"units": []}}}

    def request(method, path, **kwargs):
        """Capture admitted submission fields.

        Args:
            method: HTTP method.
            path: Requested endpoint.
            **kwargs: Transport options and form fields.
        """
        if method == "GET":
            return 200, '<input name="csrf" value="synthetic">', {}
        submissions.append(kwargs["form"])
        return 202, '{"job_id":"job_abc","status_url":"/tasks/job_abc/status"}', {}

    client = SimpleNamespace(request=request, json_request=json_request)
    if caller == "guest":
        def guest_request(opener, path, **kwargs):
            """Adapt the standalone guest transport.

            Args:
                opener: Synthetic opener.
                path: Requested endpoint.
                **kwargs: Encoded submission options.
            """
            if kwargs.get("data"):
                submissions.append([(key, value) for key, values in parse_qs(kwargs["data"].decode()).items()
                                    for value in values])
                return 303, "/?job_id=job_abc", {}, b""
            return 200, "", {}, json.dumps(json_request("GET", path)).encode()
        monkeypatch.setattr(guest, "request", guest_request)
        def invoke():
            """Run the selected mocked client."""
            return guest.apply_unit(None, "ntpd", "synthetic")
        error = guest.SafeFailure
    elif caller == "certificate":
        def certificate_json(path, form=None):
            """Adapt native review and submission transport.

            Args:
                path: Requested endpoint.
                form: Optional submitted fields.
            """
            if form is not None:
                submissions.append([(key, value) for key, values in form.items()
                                    for value in (values if isinstance(values, list) else [values])])
                return 202, {"job_id": "job_abc", "status_url": "/tasks/job_abc/status"}
            return 200, payload if "?" in path else review(roots)
        client = SimpleNamespace(json=certificate_json, request=lambda path: (200, '<input name="csrf" value="synthetic">'))
        def invoke():
            """Run the selected mocked client."""
            return certificate.submit(client)
        error = certificate.Refusal
    elif caller == "lifecycle":
        def invoke():
            """Run the selected mocked client."""
            return lifecycle.apply_units(client, roots, SimpleNamespace(allow_dry_run=True))
        error = lifecycle.LifecycleError
    else:
        def invoke():
            """Run the selected mocked client."""
            return routing._apply(client, roots)
        error = routing.OverlapPrerequisiteError
    if invalid:
        with pytest.raises(error):
            invoke()
        assert submissions == []
    else:
        invoke()
        fields = submissions[0]
        assert ("reviewed_plan", "review-token") in fields
        assert {value for key, value in fields if key == "requested_units"} == set(roots)
        assert {value for key, value in fields if key == "selected_units"} == {*roots, "nat"}
