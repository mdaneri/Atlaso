"""Keep authenticated CA artifacts reachable through the restricted setup listener."""

import re
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from atlaso.app.ui_routes import is_protocol_path
from tests.test_appliance_helper import load_helper_module

ARTIFACT_PATHS = (
    "/certificate-authority/downloads/root-ca.pem",
    "/certificate-authority/downloads/ca-bundle.pem",
    "/certificate-authority/certificates/7/downloads/certificate.pem",
    "/certificate-authority/certificates/7/downloads/chain.pem",
    "/certificate-authority/certificates/7/downloads/private-key.pem",
)
PUBLIC_CA_PATHS = ("/ca/downloads/root-ca.pem", "/ca/downloads/ca-bundle.pem")


def _proxy_for_request(config: str, uri: str) -> str | None:
    """Find a generated exact, prefix or case-sensitive regex proxy for a request.

    Args:
        config: Actual nginx output from the privileged helper renderer.
        uri: Browser request URI, including any optional download query.
    """
    path = urlsplit(uri).path
    for match in re.finditer(r"  location (=|\^~|~) ([^{}\n]+) \{\n(.*?)\n  \}", config, re.S):
        modifier, pattern, body = match.groups()
        if "proxy_pass " not in body:
            continue
        if ((modifier == "=" and path == pattern)
                or (modifier == "^~" and path.startswith(pattern))
                or (modifier == "~" and re.search(pattern, path))):
            return body
    return None


@pytest.mark.parametrize("tls_port, upstream_host, upstream_port", [(443, "127.0.0.1", 8000), (9443, "127.0.0.2", 9080)])
@pytest.mark.parametrize("https_allowed", [False, True])
def test_setup_http_preserves_exact_public_ca_bootstrap(tls_port, upstream_host, upstream_port, https_allowed):
    """Serve public trust material before HTTPS trust without exposing other HTTP paths.

    Args:
        tls_port: Applied HTTPS destination retained by the catch-all redirect.
        upstream_host: Existing validated loopback backend selected by the applied plan.
        upstream_port: Applied backend port used for public CA downloads.
        https_allowed: Whether this site also owns its HTTPS socket during handoff.
    """
    helper = load_helper_module()
    config = helper._ipv4ll_setup_nginx_server(
        {"fqdn": "core.atlaso.internal", "management_https_enabled": True,
         "management_public_https_port": tls_port, "management_upstream_host": upstream_host,
         "management_upstream_port": upstream_port},
        "169.254.20.10", Path("/etc/atlaso/https/certs/core.pem"), Path("/etc/atlaso/https/certs/core.key"),
        https_allowed=https_allowed,
    )
    http = config.split("\nserver {", 1)[0]
    assert "listen 169.254.20.10:80 default_server;" in http
    for path in PUBLIC_CA_PATHS:
        assert _proxy_for_request(http, path + "?download=1") is not None, path
    # Use the shared public-download contract, rather than the authenticated
    # setup proxy helper or a broad /ca/ prefix that opens other HTTP routes.
    expected = "\n".join(helper._management_ca_download_locations(upstream_host, upstream_port))
    assert expected in http
    source_guard = 'if ($remote_addr !~ "^169\\.254\\.") { return 403; }'
    maintenance = helper._release_maintenance_condition()
    assert http.count(source_guard) == http.count(maintenance) == 1
    assert http.index(source_guard) < http.index(maintenance) < http.index("  location ")
    assert "return 308" not in http.split("  location ", 1)[0]
    assert f"  location / {{\n    return 308 https://$host:{tls_port}$request_uri;\n  }}" in http
    assert "ssl_certificate" not in http
    assert "location ^~" not in http
    for path in (*ARTIFACT_PATHS, "/ca/downloads/unknown.pem", "/ca/downloads/root-ca.pem/extra",
                 "/ca/downloads/root-ca.pem.bak", "/terminal/ws", "/api/v1/settings", "/identity", "/PROD/test"):
        assert _proxy_for_request(http, path) is None, path
    assert ("listen 169.254.20.10:9443 ssl" in config or "listen 169.254.20.10:443 ssl" in config) is https_allowed


def test_setup_http_exclusion_still_omits_bootstrap_socket():
    """An excluded HTTP socket cannot be restored just to serve CA bootstrap."""
    helper = load_helper_module()
    config = helper._ipv4ll_setup_nginx_server(
        {"fqdn": "core.atlaso.internal", "management_https_enabled": True},
        "169.254.20.10", Path("/etc/atlaso/https/certs/core.pem"), Path("/etc/atlaso/https/certs/core.key"),
        http_allowed=False,
    )
    assert "listen 169.254.20.10:80 " not in config
    assert "listen 169.254.20.10:443 ssl" in config
    for path in PUBLIC_CA_PATHS:
        assert f"location = {path}" not in config


@pytest.mark.parametrize("https", [False, True])
def test_setup_listener_proxies_only_real_ca_artifact_downloads(https):
    """Resolve actual unprefixed browser dependencies without opening the CA prefix.

    Args:
        https: Applied management listener protocol to render.
    """
    helper = load_helper_module()
    config = helper._ipv4ll_setup_nginx_server(
        {"fqdn": "core.atlaso.internal", "management_https_enabled": https},
        "169.254.20.10", Path("/etc/atlaso/https/certs/core.pem"),
        Path("/etc/atlaso/https/certs/core.key"), http_allowed=not https,
    )
    guard = 'if ($remote_addr !~ "^169\\.254\\.") { return 403; }'
    assert config.index(guard) < config.index("  location ")
    for path in ARTIFACT_PATHS:
        assert is_protocol_path(path), path
        proxy = _proxy_for_request(config, path + "?download=1")
        assert proxy is not None, path
        assert "proxy_pass http://127.0.0.1:8000;" in proxy
        assert "proxy_set_header X-Atlaso-Listener-Address $server_addr;" in proxy
        assert f"proxy_set_header X-Forwarded-Proto {'https' if https else 'http'};" in proxy
        assert "proxy_set_header Cookie" not in proxy
        assert "proxy_set_header Authorization" not in proxy
    for excluded in (
        "/certificate-authority/downloads/unknown.pem",
        "/certificate-authority/certificates/7/downloads/unknown.pem",
        "/certificate-authority/certificates/not-an-id/downloads/private-key.pem",
        "/certificate-authority/certificates/7/downloads/private-key.pem/extra",
        "/certificate-authority/certificates/7/delete",
        "/certificate-authority/settings", "/identity", "/PROD/test", "/pxe/boot", "/registry/v2/",
    ):
        assert _proxy_for_request(config, excluded) is None, excluded
    assert "location / { return 404; }" in config


@pytest.mark.parametrize("path", ARTIFACT_PATHS)
@pytest.mark.parametrize("accept, status", [("application/json", 401), ("text/html", 303)])
def test_management_ca_artifact_downloads_still_require_a_session(client, path, accept, status):
    """Reject anonymous artifact requests before accessing any certificate material.

    Args:
        client: Isolated application client with no authenticated session.
        path: Real management CA download endpoint used by the browser.
        accept: Request's API or browser response preference.
        status: Existing unauthenticated response for that request preference.
    """
    response = client.get(path, headers={"accept": accept}, follow_redirects=False)
    assert response.status_code == status
    if status == 303:
        assert urlsplit(response.headers["location"]).path == "/ui/management/login"
    assert "content-disposition" not in response.headers
