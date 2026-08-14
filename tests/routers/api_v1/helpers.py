"""Share API v1 transport test helpers across domain modules."""


def create_token(client, scopes=None):
    """Create an API token for transport tests.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        scopes: Normalized authorization scopes granted or required by the operation.

    Returns:
        The raw token and safe token metadata.
    """
    response = client.post(
        "/api/v1/auth/login?username=admin&password=atlaso-admin",
        json={
            "name": "test token",
            "scopes": scopes
            or ["read:dashboard", "read:wan", "write:wan", "read:audit"],
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["raw_token"]
    return body["raw_token"], body["token"]
