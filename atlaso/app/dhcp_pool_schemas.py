"""Explicit report-only DHCP verification API contracts."""

from pydantic import BaseModel, Field


class DhcpRetainedFinding(BaseModel):
    """Original unresolved finding evidence, distinct from the current observation."""

    status: str = Field(description="Original unexpected occupancy, lease mismatch or confirmed conflict classification.")
    observed_mac_addresses: list[str] = Field(description="ARP responder identities supporting the retained finding, not fresh observations.")
    expected_mac_addresses: list[str] = Field(description="Lease/reservation identities recorded with the original finding.")
    expected_client_ids: list[str] = Field(description="DHCP client identifiers recorded with the original finding.")
    verified_at: str | None = Field(description="Original finding observation UTC time, or null when legacy evidence lacks it.")


class DhcpAddressObservation(BaseModel):
    """Bounded identity evidence for one applied pool address."""

    ip_address: str = Field(description="IPv4 address in the applied pool or its declared reservations.")
    status: str = Field(description="legitimate_use, unexpected_occupancy, occupant_lease_mismatch, confirmed_conflict, no_response, or unknown.")
    reason: str = Field(description="Evidence explanation and observation limitations, without packet payloads.")
    observed_mac_addresses: list[str] = Field(description="Fresh ARP responder identities on the pool interface; proxy ARP may be present.")
    expected_mac_addresses: list[str] = Field(description="Current unexpired lease and declared reservation MAC identities when attributable.")
    expected_client_ids: list[str] = Field(description="Available current DHCP client identifiers; ARP cannot independently authenticate these.")
    first_seen: str = Field(description="UTC time when retained evidence for this address was first recorded.")
    last_seen: str = Field(description="UTC time when the retained finding was last observed; a nonresponse does not resolve a finding.")
    verified_at: str | None = Field(description="UTC time of the current bounded observation, or null when this run has not checked the address.")
    unresolved: bool = Field(description="Whether an observed finding still lacks positive matching identity evidence of resolution.")
    previous_status: str | None = Field(description="Retained prior finding classification, or null when absent.")
    resolved_at: str | None = Field(description="UTC time of positive matching identity evidence resolving the prior finding, or null.")
    retained_finding: DhcpRetainedFinding | None = Field(default=None, description="Original unresolved identity evidence retained through silence or incomplete work, distinct from current observations; null after positive resolution or when absent.")


class DhcpPoolReport(BaseModel):
    """Current pool identity, task progress and bounded observations."""

    scope_id: int = Field(description="Managed DHCP pool identifier.")
    name: str = Field(description="Current managed pool name.")
    interface_name: str = Field(description="Exact network interface or VLAN selected by this pool.")
    state: str = Field(description="not_recorded, pending, running, complete, partial, unknown, or cancelled; none guarantees address availability.")
    reason: str = Field(description="Pool verification summary or reason verification is unavailable.")
    job_id: str | None = Field(description="Durable Tasks job identifier when present, or null.")
    progress_percent: int = Field(description="Current task progress from 0 through 100, independent of evidence completeness.")
    config_hash: str | None = Field(description="SHA256 of the applied client-facing dnsmasq configuration, or null when unverified.")
    verified_at: str | None = Field(description="Latest observed UTC verification time, or null when no probe completed.")
    dnsmasq_version: str | None = Field(description="Native daemon version observed by the helper, or null when unavailable.")
    observations: list[DhcpAddressObservation] = Field(description="At most 1024 address records retained for the current applied pool; incomplete work remains partial.")
    unresolved_count: int = Field(description="Count of unresolved findings; no-response addresses do not establish a healthy pool.")


class DhcpPoolVerificationQueued(BaseModel):
    """Accepted asynchronous verification task."""

    job_id: str = Field(description="Tasks job identifier for progress, retained report and authorized cancellation.")
    scope_id: int = Field(description="Managed applied IPv4 pool selected for verification.")
    status: str = Field(default="pending", description="Queued task state; acceptance does not mean verification has completed.")
