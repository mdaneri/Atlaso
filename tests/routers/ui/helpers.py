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
