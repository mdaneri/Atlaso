"""Request-local, pinned Operations sessions for its managed SDDC backup proxy."""

from __future__ import annotations

import hashlib
import http.client
import json
import math
import re
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from http.cookiejar import CookieJar
from typing import Any, Callable
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit
from urllib.request import Request
from uuid import UUID

from atlaso.app.services.vcf_certificate_remote import (
    Credentials,
    RemoteError,
    Target,
    _PinnedConnection,
    _remaining,
)

_MAX_BODY = 1024 * 1024


@dataclass(frozen=True)
class WebResponse:
    """Bounded response; authentication-bearing bytes never appear in repr."""

    status: int
    body: bytes = field(repr=False)
    location: str | None = None


class PinnedWebSession:
    """Keep cookies in memory and pin every connection before sending HTTP."""

    def __init__(self, target: Target) -> None:
        """Initialize an ephemeral session at one previously confirmed origin.

        Args:
            target: Exact HTTPS origin and confirmed leaf certificate.
        """
        self.target = target
        self.cookies = CookieJar()

    def request(
        self, method: str, path: str, *, headers: dict[str, str] | None = None,
        body: Any = None, form: dict[str, str] | None = None,
    ) -> WebResponse:
        """Send one bounded request without following redirects or retrying it.

        Args:
            method: HTTP method admitted by the calling workflow.
            path: Relative path at the confirmed Operations origin.
            headers: Request-local session or proxy headers, never logged.
            body: Optional JSON payload, possibly containing transient secrets.
            form: Optional login form, mutually exclusive with the JSON body.
        """
        if (
            not path.startswith("/") or path.startswith("//")
            or any(char in path for char in "\r\n\\#")
            or body is not None and form is not None
        ):
            raise RemoteError("Invalid Operations request")
        values = {"Accept": "application/json", **(headers or {})}
        if any(
            not key.isascii() or any(char in key + value for char in "\r\n")
            for key, value in values.items()
        ):
            raise RemoteError("Invalid Operations session header")
        payload = None
        if form is not None:
            payload = urlencode(form).encode()
            values["Content-Type"] = "application/x-www-form-urlencoded; charset=UTF-8"
        elif body is not None:
            payload = json.dumps(body).encode()
            values["Content-Type"] = "application/json"
        if payload is not None and len(payload) > _MAX_BODY:
            raise RemoteError("Operations request exceeds the size limit")
        if self.target.strict_tls and not self.target.ca_pem:
            raise RemoteError("Strict TLS requires the reviewed CA certificate")
        context = (
            ssl.create_default_context(cadata=self.target.ca_pem)
            if self.target.strict_tls else ssl._create_unverified_context()
        )
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        connection = _PinnedConnection(self.target, context)
        deadline = min(time.monotonic() + 30, self.target.deadline or float("inf"))
        connected: ssl.SSLSocket | None = None
        response: http.client.HTTPResponse | None = None

        def abort() -> None:
            """Interrupt a slow read at the request's whole-operation deadline."""
            if connected is not None:
                try:
                    connected.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

        timer = threading.Timer(_remaining(deadline), abort)
        timer.daemon = True
        timer.start()
        try:
            connection.connect()
            connected = connection.sock
            if connected is None:
                raise RemoteError("Operations TLS connection is unavailable")
            certificate = connected.getpeercert(binary_form=True)
            if not certificate or hashlib.sha256(certificate).hexdigest() != self.target.fingerprint:
                raise RemoteError("Operations certificate fingerprint does not match confirmation")
            host = f"[{self.target.host}]" if ":" in self.target.host else self.target.host
            request = Request(f"https://{host}:{self.target.port}{path}", headers=values, method=method)
            self.cookies.add_cookie_header(request)
            connected.settimeout(_remaining(deadline))
            connection.request(method, path, body=payload, headers=dict(request.header_items()))
            response = connection.getresponse()
            self.cookies.extract_cookies(response, request)
            if len(self.cookies) > 32:
                raise RemoteError("Operations returned too many session cookies")
            # HTTPResponse retains its reader when Connection: close detaches
            # the connection socket. Do not operate on that detached descriptor.
            data = response.read(_MAX_BODY + 1)
            if len(data) > _MAX_BODY:
                raise RemoteError("Operations response exceeds the size limit")
            return WebResponse(response.status, data, response.getheader("Location"))
        except RemoteError:
            raise
        except (OSError, TimeoutError, ValueError, http.client.HTTPException) as error:
            if time.monotonic() >= deadline:
                raise RemoteError("Operations session request exceeded its deadline") from None
            raise RemoteError(f"Operations session request failed ({type(error).__name__})") from None
        finally:
            timer.cancel()
            if response is not None:
                response.close()
            connection.close()

    def clear(self) -> None:
        """Forget all ephemeral cookies without writing them to disk."""
        self.cookies.clear()


class OperationsProxy:
    """Use the Operations account and selected resource context, never manager credentials."""

    def __init__(
        self, target: Target, credentials: Credentials, *,
        web_factory: Callable[[Target], Any] = PinnedWebSession,
    ) -> None:
        """Bind this request-local proxy to the approved Operations identity.

        Args:
            target: Confirmed Operations host and TLS fingerprint.
            credentials: Request-local local Operations administrator credential.
            web_factory: Pinned session factory, injectable for contract tests.
        """
        self.target = target
        self.credentials = credentials
        self.web = web_factory(target)
        self.plugin_key = ""
        self._csrf = ""
        self._logged_in = False
        self._tokens: dict[str, tuple[str, float]] = {}

    def _relative(self, location: str, base_path: str) -> str:
        """Reject redirects to another origin or malformed paths.

        Args:
            location: Server-provided same-origin login redirect.
            base_path: Current request path used to resolve relative redirects.
        """
        host = f"[{self.target.host}]" if ":" in self.target.host else self.target.host
        parsed = urlsplit(urljoin(f"https://{host}:{self.target.port}{base_path}", location))
        if parsed.scheme or parsed.netloc:
            if (
                parsed.scheme != "https" or parsed.hostname != self.target.host
                or (parsed.port or 443) != self.target.port
                or parsed.username is not None or parsed.password is not None
            ):
                raise RemoteError("Operations redirected to another origin")
        path = parsed.path
        if (
            not path.startswith(("/ui/", "/vcf-operations/"))
            or any(char in location for char in "\r\n\\")
        ):
            raise RemoteError("Operations returned an invalid login redirect")
        # Operations' legacy session bridge appends a client-side hash route.
        # Fragments are never part of an HTTP request or authentication header.
        return path + ("?" + parsed.query if parsed.query else "")

    def _follow(self, path: str) -> tuple[str, WebResponse]:
        """Follow only a bounded chain of same-origin GET login redirects.

        Args:
            path: Known bootstrap or login path on Operations.
        """
        for _ in range(6):
            response = self.web.request("GET", path)
            if response.status not in (301, 302, 303, 307, 308):
                return path, response
            if not response.location:
                raise RemoteError("Operations returned an incomplete login redirect")
            path = self._relative(response.location, path)
        raise RemoteError("Operations login redirect limit exceeded")

    def _headers(self) -> dict[str, str]:
        """Build request-local UI headers without returning them to the browser."""
        return {"X-Requested-With": "XMLHttpRequest", **({"Csrf-Token": self._csrf} if self._csrf else {})}

    @staticmethod
    def _json(response: WebResponse) -> Any:
        """Decode successful JSON without exposing native error bodies.

        Args:
            response: Bounded response from the pinned origin.
        """
        if not 200 <= response.status < 300:
            raise RemoteError(f"Operations proxy returned HTTP {response.status}")
        if not response.body:
            return None
        try:
            return json.loads(response.body)
        except (ValueError, UnicodeDecodeError):
            raise RemoteError("Operations returned invalid proxy data") from None

    def login(self) -> None:
        """Open an ordinary local-account session; never displace another session."""
        login_path, response = self._follow("/vcf-operations/ui/operate/administration/sddc-administration")
        if response.status != 200 or urlsplit(login_path).path != "/ui/login.action":
            raise RemoteError("Operations local login is unavailable")
        query = parse_qs(urlsplit(login_path).query)
        uri = query.get("uri", [])
        if len(uri) != 1 or not 1 <= len(uri[0]) <= 4096:
            raise RemoteError("Operations login context is unavailable")
        host = f"[{self.target.host}]" if ":" in self.target.host else self.target.host
        origin = f"https://{host}" + (f":{self.target.port}" if self.target.port != 443 else "")
        result = self.web.request("POST", "/ui/login.action", headers={
            "X-Requested-With": "XMLHttpRequest",
            "Origin": origin, "Referer": origin + login_path,
        }, form={
            "mainAction": "login", "userName": self.credentials.username,
            "password": self.credentials.password, "authSourceId": "localItem",
            "authSourceName": "Local Account", "authSourceType": "LOCAL",
            "uri": uri[0], "forceLogin": "false", "timezone": "0", "languageCode": "us", "vcf": "1",
        })
        if result.status != 200 or result.body.strip() != b"ok":
            if result.body.strip() == b"concurrentSessionDetected":
                raise RemoteError("This Operations account has an active web session. Sign out in Operations or choose another local administrator account.")
            raise RemoteError("Operations local administrator login failed")
        self._logged_in = True
        # The SPA's route may return 404 after the session handoff. The settings
        # read below, rather than HTML content, proves that authentication worked.
        _, transition = self._follow(login_path)
        if transition.status not in (200, 404):
            raise RemoteError("Operations session handoff failed")
        settings = self._json(self.web.request("GET", "/vcf-operations/getUserSettings", headers=self._headers()))
        csrf = settings.get("csrfToken") if isinstance(settings, dict) else None
        if not isinstance(csrf, str) or not 1 <= len(csrf) <= 8192 or any(char in csrf for char in "\r\n"):
            raise RemoteError("Operations session confirmation is unavailable")
        self._csrf = csrf
        info = self._json(self.web.request("GET", "/vcf-operations/getUserBaseInfo", headers=self._headers()))
        services = info.get("serviceTypes") if isinstance(info, dict) else None
        if not isinstance(services, list) or len(services) > 1000:
            raise RemoteError("Operations plugin registration is unavailable")
        matches = [item["serviceKey"] for item in services if isinstance(item, dict)
                   and item.get("configured") is True and isinstance(item.get("serviceKey"), str)
                   and re.fullmatch(r"sddc-[0-9]+", item["serviceKey"])]
        if len(matches) != 1:
            raise RemoteError("Operations must advertise exactly one configured SDDC plugin")
        self.plugin_key = matches[0]

    def request(self, resource_id: str, method: str, path: str, body: Any = None) -> tuple[int, Any]:
        """Call one manager's proxy with its Operations resource-bound token.

        Args:
            resource_id: Confirmed Operations manager resource UUID.
            method: Explicit native read, validation, or reviewed write method.
            path: Native SDDC API path under /v1/.
            body: Request-local native payload, never persisted here.
        """
        try:
            if str(UUID(resource_id)) != resource_id:
                raise ValueError
        except (ValueError, AttributeError):
            raise RemoteError("Operations manager resource identity is invalid") from None
        if not self.plugin_key or not path.startswith("/v1/") or any(char in path for char in "\r\n\\#"):
            raise RemoteError("Operations manager proxy is unavailable")
        cached = self._tokens.get(resource_id)
        if cached is None or cached[1] <= time.monotonic():
            token_info = self._json(self.web.request("POST", "/vcf-operations/getTokenInfo", headers=self._headers(),
                                                  body={"pluginKey": self.plugin_key, "resourceId": resource_id}))
            token = token_info.get("accessToken") if isinstance(token_info, dict) else None
            ttl = token_info.get("ttl") if isinstance(token_info, dict) else None
            if (
                not isinstance(token, str) or not 1 <= len(token) <= 16384
                or any(char in token for char in "\r\n")
                or not isinstance(ttl, (int, float)) or isinstance(ttl, bool)
                or not math.isfinite(ttl) or ttl <= 0
            ):
                raise RemoteError("Operations returned an invalid manager proxy token")
            cached = (token, time.monotonic() + min(max(float(ttl) / 1000 - 30, 1), 900))
            self._tokens[resource_id] = cached
        response = self.web.request(method, f"/vcf-operations/plug/{self.plugin_key}/plugin/api{path}",
                                    headers={**self._headers(), "vmware-vrops-token": cached[0], "Accept-Language": "en-US"}, body=body)
        # Native adapters classify retryable read-only statuses. Do not decode
        # error bodies (which may echo secrets), or replay a failed write.
        return response.status, self._json(response) if 200 <= response.status < 300 else None

    def close(self) -> None:
        """Close only this owned session and forget all cookies and tokens."""
        try:
            if self._logged_in:
                self.web.request("GET", "/vcf-operations/logout", headers=self._headers())
        except RemoteError:
            pass  # A disconnected owned session expires remotely; never replay native writes.
        finally:
            self._tokens.clear()
            self._csrf = ""
            self.plugin_key = ""
            self._logged_in = False
            self.web.clear()
