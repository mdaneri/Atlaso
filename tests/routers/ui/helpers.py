"""Share UI transport test helpers across domain modules."""


def login(client):
    """Authenticate the shared HTTP test client.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    page = client.get("/ui/management/login")
    assert page.status_code == 200
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/ui/management/login",
        data={"username": "admin", "password": "atlaso-admin", "csrf": csrf},
        follow_redirects=False,
    )
    assert response.status_code == 303


def assert_apply_redirect(response):
    """Check the standard Appliance Apply task redirect.

    Args:
        response: HTTP or command response being inspected.
    """
    assert response.status_code == 200
    assert response.url.path == "/ui/management/tasks"
    assert response.history
    assert response.history[0].status_code == 303
    assert response.history[0].headers["location"].startswith(
        "/ui/management/tasks?job_id=job_"
    )
    assert "Appliance Apply" in response.text


def submit_reviewed_appliance_apply(client, url, *, data, **kwargs):
    """Bind legacy execution tests to a current reviewed plan before submission.

    These tests exercise execution rather than HTTP review rendering. Plan with
    their explicit selections and original consent checks, then consent to the
    complete effective plan. Refused planning keeps its refusal under test.

    Args:
        client: Isolated HTTP client submitting the apply request.
        url: Existing management Apply endpoint.
        data: Form fields containing the explicit component selection.
        **kwargs: HTTP request options passed to the client.

    Returns:
        The Apply submission response.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal

    form = dict(data)
    selected = form.get("selected_units", [])
    roots = [selected] if isinstance(selected, str) else list(selected)
    form["requested_units"] = roots
    with SessionLocal() as db:
        try:
            plan = ui.appliance_apply_execution_plan(db, ui.appliance_apply_units(db), set(roots))
        except ui.ApplianceApplyPlanError:
            form["reviewed_plan"] = "planning-refused"
        else:
            form["reviewed_plan"] = ui.appliance_apply_plan_token(plan)
            form["selected_units"] = [unit["id"] for unit in plan["selected_ordered_units"]]
    return client.post(url, data=form, **kwargs)
