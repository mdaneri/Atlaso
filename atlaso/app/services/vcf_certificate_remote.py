"""Native certificate APIs with connection-bound TLS identity confirmation."""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import socket
import ssl
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from http.cookies import CookieError, SimpleCookie
from typing import Any
from urllib.parse import quote

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

_MAX_RESPONSE = 1024 * 1024
_TIMEOUT = 30
_VIM25_NAMESPACE = "urn:vim25"


class RemoteError(RuntimeError):
    """Sanitized error from a remote appliance."""


@dataclass(frozen=True)
class Target:
    host: str
    port: int
    fingerprint: str
    connect_host: str | None = None
    strict_tls: bool = False
    ca_pem: str | None = None
    deadline: float | None = None

    def __post_init__(self) -> None:
        if not self.host or any(c.isspace() or c in "/@?#" for c in self.host):
            raise ValueError("Enter a host or IP address without a URL scheme")
        normalized = self.fingerprint.replace(":", "").lower()
        if len(normalized) != 64 or any(
            c not in "0123456789abcdef" for c in normalized
        ):
            raise ValueError("Expected a SHA-256 certificate fingerprint")
        object.__setattr__(self, "fingerprint", normalized)
        if not 1 <= self.port <= 65535:
            raise ValueError("Invalid port")


@dataclass(frozen=True)
class Credentials:
    username: str
    password: str = field(repr=False)


class _PinnedConnection(http.client.HTTPSConnection):
    def __init__(self, target: Target, context: ssl.SSLContext):
        """Bind the confirmed target and initialize request-local transport state.

        Args:
            target: Confirmed appliance endpoint and connection identity.
            context: TLS context for the pinned connection.
        """
        super().__init__(target.host, target.port, timeout=_TIMEOUT, context=context)
        self._connect_host = target.connect_host or target.host
        self._context = context
        self.deadline = min(
            time.monotonic() + _TIMEOUT, target.deadline or float("inf")
        )

    def connect(self) -> None:
        raw = socket.create_connection(
            (self._connect_host, self.port), _remaining(self.deadline)
        )
        try:
            raw.settimeout(_remaining(self.deadline))
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


def _remaining(deadline: float) -> float:
    """Return the bounded time remaining or reject an expired deadline.

    Args:
        deadline: Absolute monotonic deadline bounding remote work.
    """
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("Appliance request deadline exceeded")
    return min(_TIMEOUT, remaining)


class PinnedHTTPS:
    """One-request HTTPS transport that checks the leaf pin before sending HTTP."""

    def __init__(self, target: Target):
        """Bind the confirmed target and initialize request-local transport state.

        Args:
            target: Confirmed appliance endpoint and connection identity.
        """
        self.target = target
        self._soap_cookie: str | None = None
        self.server_time: float | None = None

    def clear_soap_cookie(self) -> None:
        """Discard the request-local SOAP session cookie."""
        self._soap_cookie = None

    def probe(self) -> dict[str, Any]:
        """Read the unauthenticated TLS leaf directly; sends no HTTP bytes."""
        if self.target.strict_tls and not self.target.ca_pem:
            raise RemoteError("Strict TLS requires the reviewed CA certificate")
        context = (
            ssl.create_default_context(cadata=self.target.ca_pem)
            if self.target.strict_tls
            else ssl._create_unverified_context()
        )
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        try:
            deadline = min(
                time.monotonic() + _TIMEOUT, self.target.deadline or float("inf")
            )
            with socket.create_connection(
                (self.target.connect_host or self.target.host, self.target.port),
                timeout=_remaining(deadline),
            ) as raw:
                raw.settimeout(_remaining(deadline))
                with context.wrap_socket(raw, server_hostname=self.target.host) as tls:
                    der = tls.getpeercert(binary_form=True)
            if der is None:
                raise ValueError("missing certificate")
            cert = x509.load_der_x509_certificate(der)
            return {
                "certificate_pem": cert.public_bytes(serialization.Encoding.PEM).decode(
                    "ascii"
                ),
                "sha256": cert.fingerprint(hashes.SHA256()).hex(),
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
            }
        except (OSError, ssl.SSLError, ValueError) as exc:
            raise RemoteError(
                f"Appliance TLS probe failed ({type(exc).__name__})"
            ) from None

    def request(
        self,
        method: str,
        path: str,
        *,
        credentials: Credentials | None = None,
        session_header: tuple[str, str] | None = None,
        body: Any = None,
        xml_body: str | None = None,
        soap_namespace: str = "lookup",
        capture_soap_cookie: bool = False,
    ) -> tuple[int, Any]:
        """Send one bounded native request over the confirmed TLS connection.

        Args:
            method: Native API HTTP method.
            path: Native API path on the already confirmed appliance.
            credentials: Request-local administrator credentials, never persisted.
            session_header: Request-local native API authentication header.
            body: JSON request body for the native operation.
            xml_body: SOAP request document, when required by the native API.
            soap_namespace: Supported SOAP namespace selecting the native service.
            capture_soap_cookie: Whether to retain the temporary vCenter SOAP session cookie.
        """
        if (
            not path.startswith("/")
            or "#" in path
            or "\r" in path
            or "\n" in path
            or "\\" in path
        ):
            raise RemoteError("Invalid appliance API path")
        if session_header and (
            not session_header[0].isascii()
            or any(c in session_header[0] + session_header[1] for c in "\r\n")
        ):
            raise RemoteError("Invalid appliance session header")
        if self.target.strict_tls and not self.target.ca_pem:
            raise RemoteError("Strict TLS requires the reviewed CA certificate")
        if body is not None and xml_body is not None:
            raise RemoteError("Choose one request body format")
        if soap_namespace not in {"lookup", "vim25"} or (
            soap_namespace == "vim25" and xml_body is None
        ):
            raise RemoteError("Invalid SOAP namespace")
        context = (
            ssl.create_default_context(cadata=self.target.ca_pem)
            if self.target.strict_tls
            else ssl._create_unverified_context()
        )
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        conn = _PinnedConnection(self.target, context)
        connected_socket: ssl.SSLSocket | None = None
        response: http.client.HTTPResponse | None = None

        def abort() -> None:
            # Shutdown interrupts a slow response read even if it keeps sending
            # occasional bytes inside an ordinary socket inactivity timeout.
            if connected_socket is not None:
                try:
                    connected_socket.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

        deadline = min(
            time.monotonic() + _TIMEOUT, self.target.deadline or float("inf")
        )
        try:
            timeout = _remaining(deadline)
        except TimeoutError:
            raise RemoteError("Appliance request deadline exceeded") from None
        timer = threading.Timer(timeout, abort)
        timer.daemon = True
        timer.start()
        try:
            conn.connect()
            connected_socket = conn.sock
            _remaining(deadline)
            cert = connected_socket.getpeercert(binary_form=True)
            if (
                cert is None
                or hashlib.sha256(cert).hexdigest() != self.target.fingerprint
            ):
                raise RemoteError(
                    "Appliance certificate fingerprint does not match confirmation"
                )
            headers = {"Accept": "application/json"}
            if credentials:
                token = base64.b64encode(
                    f"{credentials.username}:{credentials.password}".encode()
                ).decode()
                headers["Authorization"] = f"Basic {token}"
            if session_header:
                headers[session_header[0]] = session_header[1]
            if soap_namespace == "vim25" and self._soap_cookie:
                headers["Cookie"] = f"vmware_soap_session={self._soap_cookie}"
            payload = None
            if body is not None:
                payload = json.dumps(body).encode()
                headers["Content-Type"] = "application/json"
            if xml_body is not None:
                payload = xml_body.encode("utf-8")
                headers["Content-Type"] = "text/xml; charset=utf-8"
                headers["SOAPAction"] = (
                    "urn:lookup/2.0"
                    if soap_namespace == "lookup"
                    else "urn:vim25/8.0.0.0"
                )
            conn.request(method, path, body=payload, headers=headers)
            response = conn.getresponse()
            self.server_time = None
            date_header = response.getheader("Date")
            if isinstance(date_header, str):
                try:
                    server_date = parsedate_to_datetime(date_header)
                    if server_date.tzinfo is not None:
                        self.server_time = server_date.timestamp()
                except ValueError, TypeError, OverflowError:
                    pass
            if capture_soap_cookie:
                raw_cookie = response.getheader("Set-Cookie", "")
                parsed_cookie = SimpleCookie()
                try:
                    if (
                        not raw_cookie
                        or len(raw_cookie) > 4096
                        or any(char in raw_cookie for char in "\r\n")
                    ):
                        raise ValueError
                    parsed_cookie.load(raw_cookie)
                    morsel = parsed_cookie.get("vmware_soap_session")
                except CookieError, ValueError:
                    morsel = None
                if (
                    morsel is None
                    or not morsel.value
                    or len(morsel.value) > 2048
                    or any(char in morsel.value for char in "\r\n;,")
                ):
                    raise RemoteError(
                        "vCenter SOAP login returned an invalid session cookie"
                    )
                self._soap_cookie = morsel.value
            if response.length is not None and response.length > _MAX_RESPONSE:
                raise RemoteError("Appliance response exceeds size limit")
            data = response.read(_MAX_RESPONSE + 1)
            _remaining(deadline)
            if len(data) > _MAX_RESPONSE:
                raise RemoteError("Appliance response exceeds size limit")
            if response.status >= 300:
                raise RemoteError(f"Appliance API returned HTTP {response.status}")
            if not data:
                return response.status, None
            if xml_body is not None:
                try:
                    return response.status, data.decode("utf-8", "strict")
                except UnicodeDecodeError:
                    raise RemoteError("Lookup service returned invalid UTF-8") from None
            try:
                return response.status, json.loads(data)
            except ValueError, UnicodeDecodeError:
                raise RemoteError(
                    "Appliance returned an invalid JSON response"
                ) from None
        except RemoteError:
            raise
        except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
            raise RemoteError(
                f"Appliance request failed ({type(exc).__name__})"
            ) from None
        finally:
            timer.cancel()
            if response is not None:
                response.close()
            conn.close()


def _xml_escape(value: str) -> str:
    """Escape native identifiers before embedding them in SOAP XML.

    Args:
        value: Candidate native value to normalize or validate.
    """
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def _parse_lookup_xml(content: str, expected: str) -> ET.Element:
    """Parse bounded native XML while rejecting entities and SOAP faults.

    Args:
        content: Bounded native response content.
        expected: Expected accepted value or response used by the assertion.
    """
    if "<!DOCTYPE" in content.upper() or "<!ENTITY" in content.upper():
        raise RemoteError("Lookup service XML declarations are not allowed")
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        raise RemoteError("Lookup service returned malformed XML") from None
    if root.find(".//{http://schemas.xmlsoap.org/soap/envelope/}Fault") is not None:
        raise RemoteError("Lookup service returned a SOAP fault")
    result = root.find(f".//{{urn:lookup}}{expected}")
    if result is None:
        raise RemoteError("Lookup service response is missing required data")
    return result


def _required_text(element: ET.Element, name: str) -> str:
    """Require a nonempty text field from the native response.

    Args:
        element: Parsed XML element being inspected.
        name: Requested XML element or response-header name.
    """
    child = element.find(name)
    value = (child.text or "").strip() if child is not None else ""
    if not value:
        raise RemoteError("Lookup registration is missing required identity")
    return value


def _parse_vim25_xml(content: str, response_name: str) -> ET.Element:
    """Parse bounded vSphere SOAP XML without DTDs, entities, or SOAP faults.

    Args:
        content: Bounded native response content.
        response_name: Expected native SOAP response element.
    """
    if (
        len(content.encode("utf-8")) > _MAX_RESPONSE
        or "<!DOCTYPE" in content.upper()
        or "<!ENTITY" in content.upper()
    ):
        raise RemoteError("vCenter SOAP response is invalid")
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        raise RemoteError("vCenter SOAP response is malformed") from None
    if root.find(".//{http://schemas.xmlsoap.org/soap/envelope/}Fault") is not None:
        raise RemoteError("vCenter SOAP request was rejected")
    response = root.find(f".//{{{_VIM25_NAMESPACE}}}{response_name}")
    if response is None:
        raise RemoteError("vCenter SOAP response is missing required data")
    return response


class NativeAdapter:
    def __init__(self, target: Target, product: str):
        """Bind the confirmed target and initialize request-local transport state.

        Args:
            target: Confirmed appliance endpoint and connection identity.
            product: Detected appliance product identifier.
        """
        if product not in {"srm", "vcenter"}:
            raise ValueError("Unsupported appliance product")
        self.target, self.product = target, product
        self.transport = PinnedHTTPS(target)
        self.session: str | None = None

    def _request(
        self,
        method: str,
        path: str,
        body: Any = None,
        *,
        expected_status: int | None = None,
    ) -> Any:
        """Send one bounded native request over the confirmed TLS connection.

        Args:
            method: Native API HTTP method.
            path: Native API path on the already confirmed appliance.
            body: JSON request body for the native operation.
            expected_status: Required native success status code.
        """
        if self.product == "srm" and not path.startswith("/api/rest/configure/v2/"):
            path = "/api/rest/configure/v2" + path
        if not self.session:
            raise RemoteError("Authenticate before requesting appliance state")
        header = (
            ("x-dr-session", self.session)
            if self.product == "srm" and self.session
            else (("vmware-api-session-id", self.session) if self.session else None)
        )
        code, result = self.transport.request(
            method,
            path,
            credentials=None,
            session_header=header,
            body=body,
        )
        if expected_status is not None and code != expected_status:
            raise RemoteError(
                "Appliance returned an unexpected native operation status"
            )
        return result

    def login(self, credentials: Credentials) -> str:
        """Authenticate only after this connection proves its confirmed pin.

        Args:
            credentials: Request-local administrator credentials, never persisted.
        """
        path = (
            "/api/rest/configure/v2/session"
            if self.product == "srm"
            else "/api/session"
        )
        code, result = self.transport.request("POST", path, credentials=credentials)
        value = (
            result.get("session_id")
            if self.product == "srm" and isinstance(result, dict)
            else result
        )
        if (
            code != (200 if self.product == "srm" else 201)
            or not isinstance(value, str)
            or not 0 < len(value) <= 4096
            or "\r" in value
            or "\r\n" in value
        ):
            raise RemoteError("Appliance login returned an invalid session")
        self.session = value
        return value

    def logout(self) -> None:
        if self.session:
            try:
                self._request(
                    "DELETE",
                    "/api/rest/configure/v2/session"
                    if self.product == "srm"
                    else "/api/session",
                )
            finally:
                self.session = None

    def __enter__(self) -> NativeAdapter:
        return self

    def __exit__(self, *error: Any) -> None:
        """Discard temporary native sessions when leaving the adapter context.

        Args:
            *error: Context-manager exception details; session cleanup still runs.
        """
        try:
            self.logout()
        except RemoteError:
            if not error or error[0] is None:
                raise

    def product_info(self) -> Any:
        return self._request(
            "GET",
            "/appliance" if self.product == "srm" else "/api/appliance/system/version",
        )

    def current_certificate(self) -> Any:
        return self._request(
            "GET",
            "/appliance/certificates/server"
            if self.product == "srm"
            else "/api/vcenter/certificate-management/vcenter/tls",
        )

    def generate_csr(self, spec: dict[str, Any]) -> Any:
        """Request a target-owned CSR using the supported native API.

        Args:
            spec: Validated product-specific CSR generation request.
        """
        result = self._request(
            "POST",
            "/appliance/certificates/actions/generate-csr"
            if self.product == "srm"
            else "/api/vcenter/certificate-management/vcenter/tls-csr",
            spec,
            expected_status=200 if self.product == "srm" else 201,
        )
        if not isinstance(result, dict):
            raise RemoteError("Appliance returned an invalid CSR response")
        pem = result.get("value" if self.product == "srm" else "csr")
        if not isinstance(pem, str) or len(pem.encode()) > 65536:
            raise RemoteError("Appliance returned an invalid CSR response")
        return pem

    def install_csr(self, leaf: str, chain: list[str]) -> Any:
        """Install the reviewed public leaf and chain using the native API.

        Args:
            leaf: Reviewed public replacement leaf certificate.
            chain: Reviewed public issuing certificate chain.
        """
        if self.product == "srm":
            return self._request(
                "POST",
                "/appliance/certificates/server",
                {"csr_format": {"certificate": leaf, "ca_chain": chain}},
                expected_status=204,
            )
        return self._request(
            "PUT",
            "/api/vcenter/certificate-management/vcenter/tls",
            {"cert": leaf},
            expected_status=204,
        )

    def import_and_verify_root(self, root: str, expected_sha256: str) -> bool:
        """Import a missing public CA root once and verify native readback.

        Args:
            root: Reviewed public CA root certificate.
            expected_sha256: Exact reviewed public certificate SHA-256 fingerprint.
        """
        expected = expected_sha256.replace(":", "").lower()
        if (
            x509.load_pem_x509_certificate(root.encode())
            .fingerprint(hashes.SHA256())
            .hex()
            != expected
        ):
            raise RemoteError("Root certificate differs from the reviewed issuer")
        if self.trusted_root_present(expected):
            return True
        self._request(
            "POST",
            "/api/vcenter/certificate-management/vcenter/trusted-root-chains",
            {"cert_chain": {"cert_chain": [root]}},
            expected_status=201,
        )
        if self.trusted_root_present(expected):
            return True
        raise RemoteError(
            "Imported root certificate was not found on independent readback"
        )

    def trusted_root_present(self, expected_sha256: str) -> bool:
        """Compare public DER fingerprints without following inventory URLs.

        Args:
            expected_sha256: Exact reviewed public certificate SHA-256 fingerprint.
        """
        expected = expected_sha256.replace(":", "").lower()
        items = self._request(
            "GET", "/api/vcenter/certificate-management/vcenter/trusted-root-chains"
        )
        if not isinstance(items, list) or len(items) > 256:
            raise RemoteError("Appliance returned an invalid trust inventory")
        for item in items:
            if not isinstance(item, dict) or not isinstance(item.get("chain"), str):
                raise RemoteError("Appliance returned an invalid trust inventory")
            chain = self._request(
                "GET",
                "/api/vcenter/certificate-management/vcenter/trusted-root-chains/"
                + quote(item["chain"], safe=""),
            )
            try:
                values = chain["cert_chain"]["cert_chain"]
                if not isinstance(values, list) or len(values) > 16:
                    raise ValueError
                for pem in values:
                    if (
                        x509.load_pem_x509_certificate(pem.encode())
                        .fingerprint(hashes.SHA256())
                        .hex()
                        == expected
                    ):
                        return True
            except KeyError, TypeError, ValueError, AttributeError:
                raise RemoteError(
                    "Appliance returned an invalid public trust chain"
                ) from None
        return False

    def health(self) -> Any:
        if self.product == "vcenter":
            return self._request("GET", "/api/appliance/health/system")
        return self._request("GET", "/services")

    def srm_dns_settings(self) -> Any:
        if self.product != "srm":
            raise ValueError("DNS settings are available only for SRM")
        return self._request("GET", "/appliance/settings/network/dns")

    def vcenter_registrations(self) -> list[dict[str, str]]:
        if self.product != "vcenter":
            raise ValueError("Lookup registrations are available only for vCenter")
        envelope = """<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:lookup="urn:lookup"><soapenv:Body><lookup:RetrieveServiceContent><_this type="LookupServiceInstance">ServiceInstance</_this></lookup:RetrieveServiceContent></soapenv:Body></soapenv:Envelope>"""
        _, content = self.transport.request(
            "POST",
            "/lookupservice/sdk",
            session_header=("vmware-api-session-id", self.session or ""),
            xml_body=envelope,
        )
        if not isinstance(content, str):
            raise RemoteError("Lookup service returned an invalid service response")
        service = _parse_lookup_xml(content, "RetrieveServiceContentResponse")
        reg_ref = service.find(".//{urn:lookup}serviceRegistration")
        if (
            reg_ref is None
            or not reg_ref.attrib.get("type")
            or not (reg_ref.text or "").strip()
        ):
            raise RemoteError("Lookup service registration reference is missing")
        reg_type, reg_id = reg_ref.attrib["type"], (reg_ref.text or "").strip()
        list_envelope = f"""<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:lookup="urn:lookup"><soapenv:Body><lookup:List><_this type="{_xml_escape(reg_type)}">{_xml_escape(reg_id)}</_this><filterCriteria><serviceType><product>com.vmware.cis</product><type>vcenterserver</type></serviceType></filterCriteria></lookup:List></soapenv:Body></soapenv:Envelope>"""
        _, listed = self.transport.request(
            "POST",
            "/lookupservice/sdk",
            session_header=("vmware-api-session-id", self.session or ""),
            xml_body=list_envelope,
        )
        if not isinstance(listed, str):
            raise RemoteError("Lookup service returned an invalid registration list")
        root = _parse_lookup_xml(listed, "ListResponse")
        results: list[dict[str, str]] = []
        for item in root.findall(".//{urn:lookup}returnval"):
            service_id = _required_text(item, "{urn:lookup}serviceId")
            site_id = _required_text(item, "{urn:lookup}siteId")
            owner_id = _required_text(item, "{urn:lookup}ownerId")
            node_id = _required_text(item, "{urn:lookup}nodeId")
            endpoints = item.findall(".//{urn:lookup}serviceEndpoints/{urn:lookup}url")
            if not endpoints or any(
                not (endpoint.text or "").strip() for endpoint in endpoints
            ):
                raise RemoteError("Lookup registration endpoint is missing")
            results.append(
                {
                    "service_id": service_id,
                    "site_id": site_id,
                    "owner_id": owner_id,
                    "node_id": node_id,
                    "endpoints": ",".join((e.text or "").strip() for e in endpoints),
                }
            )
        if not results:
            raise RemoteError("Lookup service returned no vCenter registrations")
        return results

    def vcenter_permissions(self, credentials: Credentials) -> bool:
        """Check native TLS CSR privileges before preparation, using a temporary SOAP login.

        The check targets vCenter's root folder because certificate-management privileges
        are global. Native CSR generation remains authoritative and may still reject it.

        Args:
            credentials: Request-local administrator credentials, never persisted.
        """
        if self.product != "vcenter":
            raise ValueError(
                "Certificate permission checks are available only for vCenter"
            )
        service_envelope = f'''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:vim25="{_VIM25_NAMESPACE}"><soapenv:Body><vim25:RetrieveServiceContent><_this type="ServiceInstance">ServiceInstance</_this></vim25:RetrieveServiceContent></soapenv:Body></soapenv:Envelope>'''
        session_manager_ref: tuple[str, str] | None = None
        try:
            _, content = self.transport.request(
                "POST", "/sdk", xml_body=service_envelope, soap_namespace="vim25"
            )
            if not isinstance(content, str):
                raise RemoteError("vCenter service content is invalid")
            service = _parse_vim25_xml(content, "RetrieveServiceContentResponse")
            content_node = next(
                (
                    item
                    for item in service.iter()
                    if item.tag.rsplit("}", 1)[-1] == "returnval"
                ),
                None,
            )
            if content_node is None:
                raise RemoteError("vCenter service content is missing references")
            refs: dict[str, tuple[str, str]] = {}
            for name in ("sessionManager", "rootFolder", "authorizationManager"):
                ref = next(
                    (
                        item
                        for item in content_node.iter()
                        if item.tag.rsplit("}", 1)[-1] == name
                    ),
                    None,
                )
                if (
                    ref is None
                    or not ref.attrib.get("type")
                    or not (ref.text or "").strip()
                ):
                    raise RemoteError("vCenter service content is missing references")
                refs[name] = (ref.attrib["type"], (ref.text or "").strip())
            session_manager_ref = refs["sessionManager"]
            login_envelope = f'''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:vim25="{_VIM25_NAMESPACE}"><soapenv:Body><vim25:Login><_this type="{_xml_escape(refs["sessionManager"][0])}">{_xml_escape(refs["sessionManager"][1])}</_this><userName>{_xml_escape(credentials.username)}</userName><password>{_xml_escape(credentials.password)}</password></vim25:Login></soapenv:Body></soapenv:Envelope>'''
            _, login_content = self.transport.request(
                "POST",
                "/sdk",
                xml_body=login_envelope,
                soap_namespace="vim25",
                capture_soap_cookie=True,
            )
            if not isinstance(login_content, str):
                raise RemoteError("vCenter SOAP login response is invalid")
            login = _parse_vim25_xml(login_content, "LoginResponse")
            user_session = next(
                (
                    item
                    for item in login.iter()
                    if item.tag.rsplit("}", 1)[-1] == "returnval"
                ),
                None,
            )
            session_key_node = (
                next(
                    (
                        item
                        for item in user_session.iter()
                        if item.tag.rsplit("}", 1)[-1] == "key"
                    ),
                    None,
                )
                if user_session is not None
                else None
            )
            if (
                user_session is None
                or session_key_node is None
                or not (session_key_node.text or "").strip()
            ):
                raise RemoteError("vCenter SOAP login response is invalid")
            session_key = (session_key_node.text or "").strip()
            entity_type, entity_id = refs["rootFolder"]
            manager_type, manager_id = refs["authorizationManager"]
            privilege_ids = (
                "CertificateManagement.Manage",
                "CertificateManagement.Administer",
            )
            privileges = "".join(f"<privId>{value}</privId>" for value in privilege_ids)
            check_envelope = f'''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:vim25="{_VIM25_NAMESPACE}"><soapenv:Body><vim25:HasPrivilegeOnEntity><_this type="{_xml_escape(manager_type)}">{_xml_escape(manager_id)}</_this><entity type="{_xml_escape(entity_type)}">{_xml_escape(entity_id)}</entity><sessionId>{_xml_escape(session_key)}</sessionId>{privileges}</vim25:HasPrivilegeOnEntity></soapenv:Body></soapenv:Envelope>'''
            _, check_content = self.transport.request(
                "POST", "/sdk", xml_body=check_envelope, soap_namespace="vim25"
            )
            if not isinstance(check_content, str):
                raise RemoteError("vCenter privilege response is invalid")
            checked = _parse_vim25_xml(check_content, "HasPrivilegeOnEntityResponse")
            values = [
                item
                for item in checked.iter()
                if item.tag.rsplit("}", 1)[-1] == "returnval"
            ]
            if len(values) != 2 or any(
                (item.text or "").strip().lower() not in {"true", "false"}
                for item in values
            ):
                raise RemoteError("vCenter privilege response is invalid")
            return all((item.text or "").strip().lower() == "true" for item in values)
        finally:
            if self.transport._soap_cookie:
                try:
                    if session_manager_ref is not None:
                        logout_envelope = f'''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:vim25="{_VIM25_NAMESPACE}"><soapenv:Body><vim25:Logout><_this type="{_xml_escape(session_manager_ref[0])}">{_xml_escape(session_manager_ref[1])}</_this></vim25:Logout></soapenv:Body></soapenv:Envelope>'''
                        self.transport.request(
                            "POST",
                            "/sdk",
                            xml_body=logout_envelope,
                            soap_namespace="vim25",
                        )
                finally:
                    self.transport.clear_soap_cookie()

    def vcenter_ha(self) -> Any:
        if self.product != "vcenter":
            raise ValueError("HA status is available only for vCenter")
        return self._request(
            "POST", "/api/vcenter/vcha/cluster?action=get", {"partial": True}
        )
