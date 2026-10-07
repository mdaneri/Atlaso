"""Describe desired-state contracts for managed reverse proxies."""

import ipaddress
import re
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from atlaso.app.schemas import validate_firewall_description


class ReverseProxyListener(BaseModel):
    """Select one exact eligible appliance interface address."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, strict=True)

    interface: str = Field(
        min_length=1,
        max_length=80,
        pattern=r"^[A-Za-z0-9_.:-]+$",
        description="Exact saved non-management access or route interface or VLAN name.",
    )
    address: str = Field(
        min_length=2,
        max_length=45,
        description="Exact canonical IPv4 or IPv6 address saved on the selected interface.",
    )


class ReverseProxyRouteInput(BaseModel):
    """Describe one ordered route mapping in a complete proxy replacement."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, strict=True)

    id: int | None = Field(
        default=None,
        ge=1,
        description="Existing route identity to retain; omit for a newly added route.",
    )
    path_prefix: str = Field(
        min_length=1,
        max_length=1024,
        description="Absolute unambiguous URL path prefix matched by this route; '/' matches the whole host.",
    )
    upstream_scheme: Literal["http", "https"] = Field(
        default="http", description="Transport used to connect to this upstream host and port."
    )
    upstream_host: str = Field(
        min_length=1,
        max_length=253,
        description="Separate DNS hostname or IP literal for the upstream; URLs and credentials are not accepted.",
    )
    upstream_port: int = Field(
        ge=1,
        le=65535,
        description="TCP port on the upstream host.",
    )
    path_behavior: Literal["preserve", "strip"] = Field(
        default="preserve",
        description="Preserve the matched prefix upstream or remove it before forwarding the remaining path.",
    )
    trust_mode: Literal["trusted_ca", "fingerprint", "insecure"] = Field(
        default="trusted_ca",
        description="HTTPS upstream verification mode; insecure disables certificate verification.",
    )
    fingerprint: str = Field(
        default="",
        max_length=95,
        description="Canonical lowercase SHA-256 certificate fingerprint required by fingerprint trust mode.",
    )
    insecure_acknowledged: bool = Field(
        default=False,
        description="Explicitly acknowledge disabled upstream certificate verification when trust mode is insecure; request-only.",
    )

    @field_validator("path_prefix")
    @classmethod
    def validate_path_prefix(cls, value: str) -> str:
        """Reject path encodings and segments whose nginx interpretation can differ."""
        if (
            not value.startswith("/")
            or "\\" in value
            or "%" in value
            or "?" in value
            or "#" in value
            or any(character.isspace() for character in value)
            or any(character in value for character in ";{}$\"'")
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
            or "//" in value
            or any(segment in {".", ".."} for segment in value.split("/"))
        ):
            raise ValueError("Use an absolute path prefix without encoded, dot, backslash or ambiguous path segments.")
        return value

    @field_validator("fingerprint")
    @classmethod
    def normalize_fingerprint(cls, value: str) -> str:
        """Canonicalize a SHA-256 hexadecimal fingerprint."""
        normalized = value.replace(":", "").strip().lower()
        if normalized and (len(normalized) != 64 or any(character not in "0123456789abcdef" for character in normalized)):
            raise ValueError("Enter a SHA-256 fingerprint as 64 hexadecimal characters.")
        return normalized

    @field_validator("upstream_host")
    @classmethod
    def normalize_upstream_host(cls, value: str) -> str:
        """Canonicalize a separate upstream DNS hostname or IP literal."""
        candidate = value.strip()
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            normalized = candidate.rstrip(".").lower()
            labels = normalized.split(".")
            if len(normalized) > 253 or any(
                not re.fullmatch(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", label)
                for label in labels
            ):
                raise ValueError("Enter an upstream DNS hostname or IP literal without a URL, port, or credentials.") from None
            return normalized

    @model_validator(mode="after")
    def validate_trust_choice(self) -> "ReverseProxyRouteInput":
        """Require the selected HTTPS trust mode's reviewed fields."""
        if self.trust_mode == "fingerprint" and not self.fingerprint:
            raise ValueError("Fingerprint trust mode requires a SHA-256 certificate fingerprint.")
        if self.trust_mode != "fingerprint" and self.fingerprint:
            raise ValueError("A certificate fingerprint is allowed only with fingerprint trust mode.")
        if self.trust_mode == "insecure" and not self.insecure_acknowledged:
            raise ValueError("Acknowledge disabled upstream certificate verification before saving.")
        if self.trust_mode != "insecure" and self.insecure_acknowledged:
            raise ValueError("The insecure verification acknowledgement applies only to insecure trust mode.")
        if self.upstream_scheme == "http" and self.trust_mode != "trusted_ca":
            raise ValueError("HTTP upstreams do not use HTTPS certificate trust settings.")
        return self


class ReverseProxyCreate(BaseModel):
    """Describe a complete reverse-proxy desired-state replacement."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, strict=True)

    name: str = Field(
        min_length=1,
        max_length=120,
        description="Unique operator-facing name for this reverse proxy.",
    )
    description: Annotated[str, AfterValidator(validate_firewall_description)] = Field(
        default="",
        description="Operator purpose, at most 1,000 UTF-16 code units.",
        json_schema_extra={"x-maxLengthUtf16CodeUnits": 1000},
    )
    hostname: str = Field(
        min_length=1,
        max_length=253,
        description="Unique fully qualified DNS hostname served by this virtual host.",
    )
    scheme: Literal["http", "https"] = Field(
        default="https", description="Client-facing protocol served by this virtual host."
    )
    port: int = Field(
        default=443,
        ge=1,
        le=65535,
        description="Client-facing TCP listener port for the selected protocol.",
    )
    redirect_http: bool = Field(
        default=False,
        description="Redirect this hostname from its HTTP listener to the selected HTTPS listener.",
    )
    redirect_port: int = Field(
        default=80,
        ge=1,
        le=65535,
        description="HTTP TCP listener port used when redirect_http is enabled.",
    )
    enabled: bool = Field(
        default=False,
        description="Desired enablement; global Appliance Apply owns listener publication.",
    )
    public_listing: bool = Field(
        default=True,
        description="Include this proxy in the matching interface's public service directory.",
    )
    managed_dns: bool = Field(
        default=False,
        description="Request app-owned DNS management for this hostname; DNS validation and publication remain separate.",
    )
    listeners: list[ReverseProxyListener] = Field(
        min_length=1,
        max_length=64,
        description="Exact interface/address pairs on which nginx may publish this host.",
    )
    connect_timeout: int = Field(
        default=5, ge=1, le=30, description="Maximum seconds nginx waits to connect to an upstream."
    )
    read_timeout: int = Field(
        default=60, ge=1, le=300, description="Maximum seconds nginx waits between upstream reads."
    )
    send_timeout: int = Field(
        default=60, ge=1, le=300, description="Maximum seconds nginx waits while sending a request to an upstream."
    )
    body_limit: int = Field(
        default=16777216,
        ge=1,
        le=1073741824,
        description="Maximum accepted request body size in bytes, from 1 byte through 1 GiB.",
    )
    routes: list[ReverseProxyRouteInput] = Field(
        min_length=1,
        max_length=64,
        description="Ordered path mappings that are replaced atomically with the proxy.",
    )

    @field_validator("hostname")
    @classmethod
    def normalize_hostname(cls, value: str) -> str:
        """Canonicalize a fully qualified DNS hostname without URL delimiters."""
        normalized = value.rstrip(".").lower()
        labels = normalized.split(".")
        label_pattern = r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
        if len(normalized) > 253 or len(labels) < 2 or any(not re.fullmatch(label_pattern, label) for label in labels):
            raise ValueError("Enter a fully qualified DNS hostname without a URL, port, or credentials.")
        return normalized

    @field_validator("connect_timeout")
    @classmethod
    def validate_connect_timeout(cls, value: int) -> int:
        """Keep the upstream connect timeout within its bounded runtime range."""
        if value > 30:
            raise ValueError("Upstream connect timeout may not exceed 30 seconds.")
        return value

    @field_validator("read_timeout", "send_timeout")
    @classmethod
    def validate_io_timeouts(cls, value: int) -> int:
        """Keep upstream read and send timeouts within their bounded runtime range."""
        if value > 300:
            raise ValueError("Upstream read and send timeouts may not exceed 300 seconds.")
        return value

    @field_validator("body_limit")
    @classmethod
    def validate_body_limit(cls, value: int) -> int:
        """Reject unbounded request body settings."""
        if value < 1:
            raise ValueError("Request body limit must be between 1 byte and 1 GiB.")
        return value

class ReverseProxyRouteResponse(BaseModel):
    """Return one saved path mapping without request-only acknowledgement state."""

    model_config = ConfigDict(from_attributes=True)

    id: int = Field(description="Stable saved identity of this route.")
    path_prefix: str = Field(description="Absolute path prefix selected by this route.")
    upstream_scheme: Literal["http", "https"] = Field(description="Transport used for the upstream connection.")
    upstream_host: str = Field(description="Validated upstream DNS hostname or IP literal.")
    upstream_port: int = Field(description="TCP port on the upstream host.")
    path_behavior: Literal["preserve", "strip"] = Field(description="Whether the path prefix is preserved upstream.")
    trust_mode: Literal["trusted_ca", "fingerprint", "insecure"] = Field(description="Saved HTTPS certificate verification mode.")
    fingerprint: str = Field(description="Canonical SHA-256 certificate fingerprint, empty when not used.")
    insecure_acknowledged: bool = Field(description="True when insecure verification was explicitly acknowledged on save.")


class ReverseProxyResponse(BaseModel):
    """Return one proxy's complete saved desired state."""

    model_config = ConfigDict(from_attributes=True)

    id: int = Field(description="Stable database identity of this reverse proxy.")
    name: str = Field(description="Unique operator-facing name.")
    description: str = Field(description="Operator purpose for this reverse proxy.")
    hostname: str = Field(description="Unique fully qualified hostname served by nginx.")
    scheme: Literal["http", "https"] = Field(description="Client-facing protocol.")
    port: int = Field(description="Client-facing TCP listener port.")
    redirect_http: bool = Field(description="Whether the hostname also redirects from HTTP.")
    redirect_port: int = Field(description="TCP port used for HTTP redirection.")
    enabled: bool = Field(description="Desired publication state; effective after global Appliance Apply.")
    public_listing: bool = Field(description="Whether the matching public service directory lists this proxy.")
    managed_dns: bool = Field(description="Whether the hostname is selected for app-owned DNS management.")
    listeners: list[ReverseProxyListener] = Field(description="Saved exact interface/address nginx listeners.")
    connect_timeout: int = Field(description="Maximum upstream connection wait in seconds.")
    read_timeout: int = Field(description="Maximum upstream read wait in seconds.")
    send_timeout: int = Field(description="Maximum upstream send wait in seconds.")
    body_limit: int = Field(description="Maximum request body size in bytes, from 1 byte through 1 GiB.")
    routes: list[ReverseProxyRouteResponse] = Field(description="Ordered saved path mappings.")
    created_at: datetime = Field(description="UTC timestamp when the proxy was created.")
    updated_at: datetime = Field(description="UTC timestamp of its latest desired-state update.")
    apply_required: Literal[True] = Field(default=True, description="Global Appliance Apply owns listener publication.")


def response_for_proxy(proxy: Any) -> ReverseProxyResponse:
    """Build a response including the derived insecure verification acknowledgement."""
    values = {
        field: getattr(proxy, field)
        for field in ReverseProxyResponse.model_fields
        if field not in {"routes", "apply_required"}
    }
    values["listeners"] = [ReverseProxyListener.model_validate(item) for item in values["listeners"]]
    values["routes"] = [
        ReverseProxyRouteResponse(
            id=route.id,
            path_prefix=route.path_prefix,
            upstream_scheme=route.upstream_scheme,
            upstream_host=route.upstream_host,
            upstream_port=route.upstream_port,
            path_behavior=route.path_behavior,
            trust_mode=route.trust_mode,
            fingerprint=route.fingerprint,
            insecure_acknowledged=route.trust_mode == "insecure",
        )
        for route in proxy.routes
    ]
    return ReverseProxyResponse(**values)
