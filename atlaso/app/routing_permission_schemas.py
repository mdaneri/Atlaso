"""Request and response contracts for Routing Permissions."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class RoutingPermissionCreate(BaseModel):
    """Complete desired state for one explicit Routing Permission."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, strict=True)

    name: str = Field(min_length=1, max_length=120, description="Unique operator-facing name for this permission.")
    enabled: bool = Field(default=True, description="Whether this saved permission is intended to be active when Routing is enabled and applied.")
    source_interface: str = Field(min_length=1, max_length=80, description="Eligible source interface or VLAN name; management targets are prohibited.")
    destination_interface: str = Field(min_length=1, max_length=80, description="Eligible destination interface or VLAN name; management targets are prohibited.")
    priority: int = Field(default=100, ge=0, le=2147483647, description="Order within one policy phase. Deny always precedes allow and automatic, independent of priority.")
    description: str = Field(default="", max_length=1000, description="Operator purpose or review context for this permission.")
    policy: Literal["automatic", "allow", "deny"] = Field(default="allow", description="Traffic decision: allow, deny, or automatic route-role behavior.")
    ip_family: Literal[0, 4, 6] = Field(default=0, description="Address family governed by this permission: 0 means both IPv4 and IPv6, 4 means IPv4, and 6 means IPv6.")

    @field_validator("ip_family", mode="before")
    @classmethod
    def validate_family(cls, value: object) -> object:
        """Reject boolean values that compare equal to integer family zero.

        Args:
            value: Uncoerced request value.
        """
        if isinstance(value, bool):
            raise ValueError("IP family must be 0, 4, or 6; booleans are not accepted.")
        return value


class RoutingPermissionResponse(BaseModel):
    """Return explicit desired state and generated read-only projections."""

    model_config = ConfigDict(from_attributes=True)

    id: int | str = Field(description="Saved database identifier, or a stable generated identifier for a read-only route-role permission.")
    generated: bool = Field(description="Whether this row is generated from route-role intent and cannot be edited or deleted.")
    name: str = Field(description="Operator-facing permission name.")
    enabled: bool = Field(description="Saved enablement intent for an explicit permission.")
    source_interface: str = Field(description="Source interface or VLAN identity.")
    destination_interface: str = Field(description="Destination interface or VLAN identity.")
    priority: int = Field(description="Permission evaluation order; lower values are evaluated first.")
    description: str = Field(description="Operator purpose or generated-rule explanation.")
    policy: Literal["automatic", "allow", "deny"] = Field(description="Saved or effective traffic decision.")
    ip_family: Literal[0, 4, 6] = Field(description="Address family governed by the permission; 0 means both families.")
    effective_action: str = Field(description="Current projected action after applying saved policy and routing state.")
    family_effective_actions: dict[str, str] = Field(description="Effective action for each address family in this row's scope, keyed by IP version 4 or 6.")
    source_networks: list[str] = Field(description="Source CIDR networks currently represented by this permission.")
    destination_networks: list[str] = Field(description="Destination CIDR networks currently represented by this permission.")
    address_family: str = Field(description="Human-readable address-family projection, including both families when selected.")
    apply_state: Literal["pending", "applied"] = Field(description="Whether both WAN and Firewall Apply baselines match the current Routing Permission desired state.")
