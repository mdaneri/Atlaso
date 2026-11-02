"""Operations proxy login, context binding, and no-replay contracts."""

from __future__ import annotations

import hashlib
import http.client
import io
import json
from typing import Any
from unittest.mock import Mock

import pytest

from atlaso.app.services import vcf_operations_proxy as proxy
from atlaso.app.services.vcf_certificate_remote import Credentials, RemoteError, Target

RESOURCE = "d9e6cb38-4aad-4d70-863a-0d09b5536059"
SECRET = "request-local-token-and-password"


def test_operations_transport_reads_connection_close_response_without_using_detached_socket(monkeypatch):
    """Keep the native HTTP error body readable after its connection is detached.

    Args:
        monkeypatch: Fixture replacing the TLS socket and connection.
    """
    certificate = b"confirmed certificate"
    tls = Mock()
    tls.getpeercert.return_value = certificate
    payload = b'{"errorCode":"NATIVE_VALIDATION_FAILED"}'
    tls.makefile.return_value = io.BytesIO(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: "
                                         + str(len(payload)).encode() + b"\r\n\r\n" + payload)
    response = http.client.HTTPResponse(tls)
    response.begin()
    connection = Mock(sock=tls)

    def detached_response():
        """Simulate HTTPConnection closing its descriptor after receiving headers."""
        connection.sock = None
        tls.settimeout.side_effect = OSError("detached descriptor")
        return response

    connection.getresponse.side_effect = detached_response
    monkeypatch.setattr(proxy, "_PinnedConnection", lambda _target, _context: connection)
    web = proxy.PinnedWebSession(Target("ops.example.test", 443, hashlib.sha256(certificate).hexdigest()))
    result = web.request("POST", "/vcf-operations/plug/sddc-99/plugin/api/v1/system/backup-configuration/validations", body={})
    assert result.status == 400
    assert result.body == payload
    assert response.isclosed()
    assert tls.settimeout.call_count == 1
    connection.close.assert_called_once()


def test_operations_relative_login_redirect_preserves_context_without_sending_fragment():
    """Support the real Operations legacy bridge while retaining its origin pin."""
    adapter = proxy.OperationsProxy(Target("ops.example.test", 443, "a" * 64), Credentials("admin", SECRET))
    assert adapter._relative("../vcf-operations/ui/operate?resourceId=example#bridge", "/ui/login.action?vcf=1") == "/vcf-operations/ui/operate?resourceId=example"


def reply(value: Any, status: int = 200) -> proxy.WebResponse:
    """Create a bounded fake JSON response.

    Args:
        value: Synthetic native response body.
        status: HTTP response status.
    """
    return proxy.WebResponse(status, json.dumps(value).encode())


class FakeWeb:
    def __init__(self, responses: list[proxy.WebResponse]) -> None:
        """Bind responses without accessing a browser or the lab.

        Args:
            responses: Exact ordered responses consumed by the session.
        """
        self.responses = list(responses)
        self.requests: list[tuple[str, str, dict[str, Any]]] = []
        self.cleared = False

    def request(self, method: str, path: str, **kwargs: Any) -> proxy.WebResponse:
        """Record one ephemeral request and return its expected response.

        Args:
            method: Requested HTTP method.
            path: Relative Operations route.
            **kwargs: Request-local headers or payloads.
        """
        self.requests.append((method, path, kwargs))
        assert self.responses, f"Unexpected request {method} {path}"
        return self.responses.pop(0)

    def clear(self) -> None:
        """Forget the fake session after explicit close."""
        self.cleared = True


def session(services: list[dict[str, Any]] | None = None) -> tuple[proxy.OperationsProxy, FakeWeb]:
    """Build the observed bootstrap and login exchange with an alternate plugin key.

    Args:
        services: Optional configured plugin descriptors for refusal cases.
    """
    web = FakeWeb([
        proxy.WebResponse(302, b"", "/ui/login.action?vcf=1&uri=dmNmLW9wZXJhdGlvbnMv"),
        proxy.WebResponse(200, b"login form"), proxy.WebResponse(200, b"ok"),
        proxy.WebResponse(302, b"", "/vcf-operations/"), proxy.WebResponse(200, b"app shell"),
        reply({"csrfToken": SECRET}),
        reply({"serviceTypes": services if services is not None else [
            {"serviceKey": "sddc-999", "configured": True},
            {"serviceKey": "sddc-77", "configured": False},
        ]}),
    ])
    adapter = proxy.OperationsProxy(Target("ops.example.test", 443, "a" * 64),
                                    Credentials("admin", SECRET), web_factory=lambda _target: web)
    return adapter, web


def test_operations_manager_proxy_uses_registered_key_context_and_vendor_header() -> None:
    adapter, web = session()
    adapter.login()
    web.responses += [reply({"accessToken": SECRET, "ttl": 300000}), reply({"isConfigured": False}), reply({})]
    status, data = adapter.request(RESOURCE, "GET", "/v1/system/backup-configuration")
    assert status == 200 and data == {"isConfigured": False}
    assert web.requests[2][2]["form"]["forceLogin"] == "false"
    token_request, native_request = web.requests[-2:]
    assert token_request[2]["body"] == {"pluginKey": "sddc-999", "resourceId": RESOURCE}
    assert native_request[1] == "/vcf-operations/plug/sddc-999/plugin/api/v1/system/backup-configuration"
    assert native_request[2]["headers"]["vmware-vrops-token"] == SECRET
    assert "Authorization" not in native_request[2]["headers"]
    assert native_request[2]["headers"]["Csrf-Token"] == SECRET
    assert SECRET not in repr(reply({"token": SECRET}))
    adapter.close()
    assert web.requests[-1][1] == "/vcf-operations/logout"
    assert web.cleared and adapter._tokens == {} and adapter._csrf == ""


def test_operations_login_never_displaces_an_existing_user_session() -> None:
    adapter, web = session()
    web.responses = web.responses[:2] + [proxy.WebResponse(200, b"concurrentSessionDetected")]
    with pytest.raises(RemoteError, match="active web session"):
        adapter.login()
    assert len(web.requests) == 3
    assert web.requests[-1][2]["form"]["forceLogin"] == "false"
    adapter.close()
    assert len(web.requests) == 3 and web.cleared


@pytest.mark.parametrize("location", ["https://other.example.test/ui/login.action", "http://ops.example.test/ui/login.action", "//other.example.test/ui/login.action"])
def test_operations_login_refuses_cross_origin_redirect_before_credentials(location: str) -> None:
    """Keep credentials and cookies at the explicitly confirmed origin.

    Args:
        location: Unsafe server-provided redirect.
    """
    adapter, web = session()
    web.responses = [proxy.WebResponse(302, b"", location)]
    with pytest.raises(RemoteError):
        adapter.login()
    assert len(web.requests) == 1


@pytest.mark.parametrize("services", [[], [{"serviceKey": "sddc-1", "configured": True}, {"serviceKey": "sddc-2", "configured": True}]])
def test_operations_plugin_registration_must_be_unambiguous(services: list[dict[str, Any]]) -> None:
    """Refuse missing or competing registered plugin identities.

    Args:
        services: Incomplete or ambiguous Operations registration.
    """
    adapter, web = session(services)
    with pytest.raises(RemoteError, match="exactly one"):
        adapter.login()
    assert not any("getTokenInfo" in path for _, path, _ in web.requests)


def test_operations_proxy_never_retries_an_uncertain_native_write() -> None:
    adapter, web = session()
    adapter.login()
    web.responses += [reply({"accessToken": SECRET, "ttl": 300000}), reply({"password": SECRET}, 401)]
    result = adapter.request(RESOURCE, "PUT", "/v1/system/backup-configuration", {"password": SECRET})
    assert result == (401, None)
    assert SECRET not in str(result)
    assert len([item for item in web.requests if item[0] == "PUT"]) == 1
    assert not web.responses


def test_operations_proxy_preserves_temporary_native_poll_status_without_error_body():
    """A managed backup's temporary outage reaches the existing native poll guard."""
    from atlaso.app.services.vcf_operations_backup import ManagedSddcBackup

    adapter, web = session()
    adapter.login()
    web.responses += [reply({"accessToken": SECRET, "ttl": 300000}), reply({"password": SECRET}, 503)]
    child = ManagedSddcBackup({"kind": "fleet", "address": "ops.example.test", "port": 443, "fingerprint": "a" * 64},
                              Credentials("admin", SECRET), adapter, {"resource_id": RESOURCE})
    child._session = "operations-proxy"
    child._version = "9.1.1"
    child._inventory = {"groups": [{"id": "sddc-manager", "component_ids": ["sddc-manager"]}]}
    result = child.backup_status("sddc-manager", {"kind": "sddc", "group_id": "sddc-manager",
        "component_ids": ["sddc-manager"], "started_at": "2026-11-02T22:00:00Z", "native_task_id": "backup-1"})
    assert result["state"] == "running" and SECRET not in str(result)
    assert sum(method == "GET" and "/v1/tasks/backup-1" in path for method, path, _ in web.requests) == 1
    web.responses.append(reply({"password": SECRET}, 503))
    result = child.configuration_status("sddc-manager", {"kind": "sddc", "group_id": "sddc-manager", "native_task_id": "configuration-1"})
    assert result["state"] == "running" and SECRET not in str(result)
    assert sum(method == "GET" and "/v1/tasks/configuration-1" in path for method, path, _ in web.requests) == 1


def test_operations_transport_checks_certificate_before_sending_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    """A replaced certificate cannot receive the login form.

    Args:
        monkeypatch: Isolated fake connection installation.
    """
    class Socket:
        def getpeercert(self, *, binary_form: bool) -> bytes:
            """Return an unrelated certificate.

            Args:
                binary_form: Requested certificate encoding.
            """
            assert binary_form
            return b"different certificate"

    class Connection:
        sock = Socket()
        closed = False

        def connect(self) -> None:
            """Simulate TLS connection establishment only."""

        def request(self, *_args: Any, **_kwargs: Any) -> None:
            """Fail if any HTTP request escapes before pin verification.

            Args:
                *_args: Unexpected HTTP arguments.
                **_kwargs: Unexpected HTTP arguments.
            """
            raise AssertionError("Credentials sent to an unconfirmed certificate")

        def close(self) -> None:
            """Record connection cleanup."""
            self.closed = True

    connection = Connection()
    monkeypatch.setattr(proxy, "_PinnedConnection", lambda _target, _context: connection)
    web = proxy.PinnedWebSession(Target("ops.example.test", 443, "a" * 64))
    with pytest.raises(RemoteError, match="fingerprint"):
        web.request("POST", "/ui/login.action", form={"password": SECRET})
    assert connection.closed
