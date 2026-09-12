"""Describe bounded Traffic Publishing destination translation API contracts."""

from datetime import datetime
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

from .schemas import validate_firewall_description


class PortForwardCreate(BaseModel):
    """Review a complete rule; saving never invokes appliance enforcement."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, strict=True)
    name: str = Field(min_length=1, max_length=120, description="Unique stable operator name for this port forward.")
    description: Annotated[str, AfterValidator(validate_firewall_description)] = Field(
        default="", description="Operator purpose, at most 1,000 UTF-16 code units, matching browser maxlength. Enforce x-maxLengthUtf16CodeUnits; JSON Schema maxLength counts code points and is intentionally omitted.",
        json_schema_extra={"x-maxLengthUtf16CodeUnits": 1000})
    priority: int = Field(default=100, ge=0, le=2147483647, description="Non-negative rule ordering; lower values come first.")
    enabled: bool = Field(default=False, description="Desired enablement; global Appliance Apply and Routing govern activation.")
    ip_family: Literal[4, 6] = Field(default=4, description="IPv4 DNAT (4) or stateful IPv6 NAT66 (6); NPTv6 is unsupported.")
    ingress_interface: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,80}$", description="One eligible access or route physical interface or VLAN; dedicated management is excluded.")
    listener_address: str = Field(min_length=2, max_length=45, description="Exact same-family unicast address currently assigned to the ingress listener.")
    protocol: Literal["tcp", "udp"] = Field(description="Transport protocol for the external and target port ranges.")
    external_port_start: int = Field(ge=1, le=65535, description="First external port, inclusive; use the same end for a single port.")
    external_port_end: int = Field(ge=1, le=65535, description="Last external port, inclusive, at least the starting port.")
    target_address: str = Field(min_length=2, max_length=45, description="Same-family unicast destination; cannot be an Atlaso-owned address or dedicated management target.")
    target_port_start: int = Field(ge=1, le=65535, description="First target port; translation preserves each external port's offset.")
    target_port_end: int = Field(ge=1, le=65535, description="Last target port; the inclusive range must have exactly the external range's cardinality.")
    source: str = Field(default="any", min_length=1, max_length=4096, description="Any, a stable group:<id> Source Group, or comma-separated same-family CIDRs inside the exact ingress boundary.")
    reply_mode: Literal["preserve", "masquerade"] = Field(default="preserve", description="Preserve the original client source by default; masquerade explicitly hides that source from the target.")
    acknowledge_source_loss: bool = Field(default=False, description="Required explicit acknowledgement when selecting reply masquerade; request-only, never archived.")

    @model_validator(mode="after")
    def validate_mapping(self) -> "PortForwardCreate":
        """Reject ambiguous mappings and unreviewed loss of upstream visibility."""
        external = self.external_port_end - self.external_port_start
        target = self.target_port_end - self.target_port_start
        if external < 0 or target < 0 or external != target:
            raise ValueError("External and target ports require ordered, equal-length inclusive ranges.")
        if self.reply_mode == "masquerade" and not self.acknowledge_source_loss:
            raise ValueError("Acknowledge that reply masquerade hides the original client address from the target.")
        return self


class PortForwardResponse(BaseModel):
    """Expose saved intent with no raw helper expressions or runtime handles."""

    model_config = ConfigDict(from_attributes=True)
    id: int = Field(description="Stable database identifier of the port forward.")
    name: str = Field(description="Unique operator-facing name.")
    description: str = Field(description="Operator purpose for this rule.")
    priority: int = Field(description="Non-negative evaluation order.")
    enabled: bool = Field(description="Desired enablement, effective only after global Appliance Apply with Routing enabled.")
    ip_family: Literal[4, 6] = Field(description="IPv4 (4) or stateful NAT66 (6).")
    ingress_interface: str = Field(description="Saved exact physical-interface or VLAN ingress identity.")
    listener_address: str = Field(description="Saved exact ingress listener address.")
    protocol: Literal["tcp", "udp"] = Field(description="TCP or UDP transport protocol.")
    external_port_start: int = Field(description="First external port, inclusive.")
    external_port_end: int = Field(description="Last external port, inclusive.")
    target_address: str = Field(description="Same-family target unicast address.")
    target_port_start: int = Field(description="First translated port, inclusive.")
    target_port_end: int = Field(description="Last translated port, inclusive.")
    source: str = Field(description="Saved Any, Source Group reference, or same-family CIDR boundary.")
    reply_mode: Literal["preserve", "masquerade"] = Field(description="Original client source preservation or explicitly reviewed reply masquerade.")
    restore_review_required: bool = Field(description="True when archive restore retained an unavailable binding disabled for explicit review.")
    created_at: datetime = Field(description="UTC creation timestamp.")
    updated_at: datetime = Field(description="UTC latest desired-state update timestamp.")
    apply_required: Literal[True] = Field(default=True, description="All saves change desired state only; global Appliance Apply owns host mutation.")


class PortForwardStatus(BaseModel):
    """Return bounded applied observations without fabricating missing counters."""

    id: int = Field(description="Saved port-forward identifier.")
    state: Literal["disabled", "pending", "suspended", "applied", "degraded"] = Field(description="Desired/applied comparison and observed runtime readiness.")
    packets: int | None = Field(default=None, ge=0, description="Observed matched packets since last activation; null means unavailable, not zero.")
    bytes: int | None = Field(default=None, ge=0, description="Observed matched bytes since last activation; null means unavailable, not zero.")
    detail: str = Field(max_length=500, description="Bounded actionable status without raw command output or nftables handles.")
