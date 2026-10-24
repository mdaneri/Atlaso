import hashlib
from unittest.mock import patch

import pytest

import atlaso.app.services.vcf_certificate_remote as remote
from atlaso.app.services.vcf_certificate_remote import (
    Credentials,
    NativeAdapter,
    PinnedHTTPS,
    RemoteError,
    Target,
)

SERVICE = """<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:vim25="urn:vim25"><soapenv:Body><vim25:RetrieveServiceContentResponse><returnval><sessionManager type="SessionManager">SessionManager</sessionManager><rootFolder type="Folder">group-d1</rootFolder><authorizationManager type="AuthorizationManager">AuthorizationManager</authorizationManager></returnval></vim25:RetrieveServiceContentResponse></soapenv:Body></soapenv:Envelope>"""
LOGIN = """<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:vim25="urn:vim25"><soapenv:Body><vim25:LoginResponse><returnval><key>soap-key</key></returnval></vim25:LoginResponse></soapenv:Body></soapenv:Envelope>"""


def _adapter(responses: list[str], privileges: tuple[str, str] = ("true", "true")):
    """Provide adapter.

    Args:
        responses: Ordered native responses supplied by the test adapter.
        privileges: Native privilege results supplied by the permission fixture.
    """
    adapter = NativeAdapter(Target("vc.example.test", 443, "a" * 64), "vcenter")
    calls: list[tuple[str, str, dict]] = []

    def request(method, path, **kwargs):
        """Provide request.

        Args:
            method: Native API HTTP method.
            path: Native API path on the already confirmed appliance.
            **kwargs: Keyword callback arguments supplied by the caller.
        """
        calls.append((method, path, kwargs))
        xml = kwargs.get("xml_body", "")
        if "<vim25:Login>" in xml:
            adapter.transport._soap_cookie = "request-cookie"
            return 200, LOGIN
        if "HasPrivilegeOnEntity" in xml:
            values = "".join(f"<returnval>{value}</returnval>" for value in privileges)
            return (
                200,
                f'<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:vim25="urn:vim25"><soapenv:Body><vim25:HasPrivilegeOnEntityResponse>{values}</vim25:HasPrivilegeOnEntityResponse></soapenv:Body></soapenv:Envelope>',
            )
        if "Logout" in xml:
            return 200, None
        return 200, responses.pop(0)

    adapter.transport.request = request
    return adapter, calls


def test_permission_preflight_uses_escaped_temporary_soap_session_and_logs_out():
    adapter, calls = _adapter([SERVICE])
    assert adapter.vcenter_permissions(Credentials("a<&user", "p<&\"'"))
    assert [call[2]["soap_namespace"] for call in calls] == ["vim25"] * 4
    assert calls[0][1] == calls[1][1] == calls[2][1] == calls[3][1] == "/sdk"
    login_xml = calls[1][2]["xml_body"]
    assert "a&lt;&amp;user" in login_xml and "p&lt;&amp;&quot;&apos;" in login_xml
    check_xml = calls[2][2]["xml_body"]
    assert (
        "CertificateManagement.Manage" in check_xml
        and "CertificateManagement.Administer" in check_xml
    )
    assert "soap-key" in check_xml and "group-d1" in check_xml
    assert "Logout" in calls[3][2]["xml_body"]
    assert adapter.transport._soap_cookie is None


@pytest.mark.parametrize(
    "values", [("false", "true"), ("true", "false"), ("false", "false")]
)
def test_permission_preflight_rejects_partial_or_denied_privileges(values):
    """Verify permission preflight rejects partial or denied privileges.

    Args:
        values: Validated browser workflow input values.
    """
    adapter, _ = _adapter([SERVICE], values)
    assert not adapter.vcenter_permissions(Credentials("user", "secret"))


@pytest.mark.parametrize(
    "bad_service",
    [
        '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:vim25="urn:vim25"><soapenv:Body><vim25:RetrieveServiceContentResponse/></soapenv:Body></soapenv:Envelope>',
        '<!DOCTYPE x [<!ENTITY e SYSTEM "file:///secret">]><x>&e;</x>',
        '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body><soapenv:Fault/></soapenv:Body></soapenv:Envelope>',
    ],
)
def test_permission_preflight_rejects_malformed_fault_or_incomplete_service_content(
    bad_service,
):
    """Verify permission preflight rejects malformed fault or incomplete service content.

    Args:
        bad_service: Service health variant that must be rejected.
    """
    adapter, calls = _adapter([bad_service])
    with pytest.raises(RemoteError):
        adapter.vcenter_permissions(Credentials("user", "secret"))
    assert adapter.transport._soap_cookie is None
    assert not any("Login" in call[2].get("xml_body", "") for call in calls)


def test_logout_failure_still_clears_request_local_cookie():
    adapter, calls = _adapter([SERVICE])
    calls_mock = adapter.transport.request

    def fail_logout(method, path, **kwargs):
        """Provide fail logout.

        Args:
            method: Native API HTTP method.
            path: Native API path on the already confirmed appliance.
            **kwargs: Keyword callback arguments supplied by the caller.
        """
        if "Logout" in kwargs.get("xml_body", ""):
            raise RemoteError("sanitized logout failure")
        return calls_mock(method, path, **kwargs)

    adapter.transport.request = fail_logout
    with pytest.raises(RemoteError, match="sanitized logout failure"):
        adapter.vcenter_permissions(Credentials("user", "secret"))
    assert adapter.transport._soap_cookie is None


def test_malformed_login_response_still_logs_out_and_clears_cookie():
    adapter, calls = _adapter([SERVICE])
    original = adapter.transport.request

    def malformed_login(method, path, **kwargs):
        """Provide malformed login.

        Args:
            method: Native API HTTP method.
            path: Native API path on the already confirmed appliance.
            **kwargs: Keyword callback arguments supplied by the caller.
        """
        if "<vim25:Login>" in kwargs.get("xml_body", ""):
            calls.append((method, path, kwargs))
            adapter.transport._soap_cookie = "temporary-cookie"
            return 200, "<malformed"
        return original(method, path, **kwargs)

    adapter.transport.request = malformed_login
    with pytest.raises(RemoteError):
        adapter.vcenter_permissions(Credentials("user", "secret"))
    assert any("Logout" in call[2].get("xml_body", "") for call in calls)
    assert adapter.transport._soap_cookie is None


def test_pinned_transport_captures_and_sends_cookie_only_for_vim25_xml():
    cert_bytes = b"pinned leaf"
    target = Target("vc.example.test", 443, hashlib.sha256(cert_bytes).hexdigest())
    transport = PinnedHTTPS(target)
    sent: list[dict[str, str]] = []

    class Socket:
        def getpeercert(self, binary_form=False):
            """Provide getpeercert.

            Args:
                binary_form: Whether the caller requests the DER certificate representation.
            """
            return cert_bytes

        def shutdown(self, _how):
            """Provide shutdown.

            Args:
                _how: Socket shutdown mode accepted by the test double.
            """
            pass

    class Response:
        status = 200
        length = 0

        def __init__(self, cookie=""):
            """Provide init.

            Args:
                cookie: Synthetic native SOAP session cookie.
            """
            self.cookie = cookie

        def getheader(self, name, default=""):
            """Provide getheader.

            Args:
                name: Requested XML element or response-header name.
                default: Fallback value when a response header is absent.
            """
            return self.cookie if name == "Set-Cookie" else default

        def read(self, _size):
            """Provide read.

            Args:
                _size: Requested read bound accepted by the response test double.
            """
            return b"ok"

        def close(self):
            pass

    class Connection:
        def __init__(self, _target, _context):
            """Provide init.

            Args:
                _target: Confirmed endpoint unused by this connection test double.
                _context: TLS context unused by this connection test double.
            """
            self.sock = Socket()
            self.response = Response()

        def connect(self):
            pass

        def request(self, _method, _path, body=None, headers=None):
            """Provide request.

            Args:
                _method: HTTP method accepted by the connection test double.
                _path: Native path accepted by the connection test double.
                body: JSON request body for the native operation.
                headers: HTTP headers captured for credential and cookie assertions.
            """
            sent.append(headers or {})

        def getresponse(self):
            return self.response

        def close(self):
            pass

    def create_connection(_target, _context):
        """Provide create connection.

        Args:
            _target: Confirmed endpoint unused by this connection test double.
            _context: TLS context unused by this connection test double.
        """
        connection = Connection(_target, _context)
        if len(sent) == 0:
            connection.response = Response(
                'vmware_soap_session="cookie-value"; Path=/sdk; Secure; HttpOnly'
            )
        return connection

    with patch.object(remote, "_PinnedConnection", create_connection):
        transport.request(
            "POST",
            "/sdk",
            xml_body="<Login/>",
            soap_namespace="vim25",
            capture_soap_cookie=True,
        )
        transport.request(
            "POST", "/sdk", xml_body="<HasPrivilegeOnEntity/>", soap_namespace="vim25"
        )
        transport.request("POST", "/lookupservice/sdk", xml_body="<Lookup/>")
    assert sent[1].get("Cookie") == "vmware_soap_session=cookie-value"
    assert "Cookie" not in sent[0] and "Cookie" not in sent[2]
    transport.clear_soap_cookie()
    assert transport._soap_cookie is None
