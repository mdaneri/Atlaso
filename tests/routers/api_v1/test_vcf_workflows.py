"""Test VCF workflow API v1 status transports."""

import pytest

from tests.routers.api_v1.helpers import create_token


@pytest.mark.parametrize(
    ("path", "scope", "expected_keys"),
    [
        (
            "/api/v1/vcf-backups/status",
            "read:vcf-backups",
            {"enabled", "storage_path", "remote_directory", "dry_run"},
        ),
        (
            "/api/v1/vcf-offline-depot/status",
            "read:repository",
            {"enabled", "profile_count", "tool_version", "dry_run"},
        ),
        (
            "/api/v1/vcf-private-registry/status",
            "read:vcf-registry",
            {"enabled", "endpoint", "bundle_count", "valid", "dry_run"},
        ),
    ],
)
def test_vcf_workflow_status_transports_keep_scope_and_schema(
    client, path, scope, expected_keys
):
    """Verify each extracted status transport retains authorization and schema.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        path: Stable API status path under test.
        scope: Authorization scope required by the status transport.
        expected_keys: Response fields retained by the extracted transport.
    """
    raw_token, _token = create_token(client, [scope])

    response = client.get(path, headers={"Authorization": f"Bearer {raw_token}"})

    assert response.status_code == 200, response.text
    assert expected_keys <= response.json().keys()


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/vcf-backups/status",
        "/api/v1/vcf-offline-depot/status",
        "/api/v1/vcf-private-registry/status",
    ],
)
def test_vcf_workflow_status_transports_reject_wrong_scope(client, path):
    """Verify VCF status transports reject a token without their required scope.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        path: Stable API status path under test.
    """
    raw_token, _token = create_token(client, ["read:dashboard"])

    response = client.get(path, headers={"Authorization": f"Bearer {raw_token}"})

    assert response.status_code == 403
