"""Define validated request and response schemas for the Atlaso API."""

from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    ValidationInfo,
    field_validator,
    model_validator,
)


class ProblemDetails(BaseModel):
    """Validated fields used by the Atlaso problem details API contract.

    Attributes:
        type: Stable URI identifying the problem or resource type.
        title: Short human-readable summary of the response or problem.
        status: Returned status value for this problem details resource.
        detail: Human-readable detail explaining the current state or failure.
        instance: Request path associated with this problem response.
        error_code: Stable Atlaso error identifier suitable for programmatic handling.
        request_id: Request correlation identifier included in responses and operational logs.
    """

    type: Annotated[str, Field(description='Stable URI identifying the problem or resource type.')]
    title: Annotated[str, Field(description='Short human-readable summary of the response or problem.')]
    status: Annotated[int, Field(description='Returned status value for this problem details resource.')]
    detail: Annotated[str, Field(description='Human-readable detail explaining the current state or failure.')]
    instance: Annotated[str, Field(description='Request path associated with this problem response.')]
    error_code: Annotated[str, Field(description='Stable Atlaso error identifier suitable for programmatic handling.')]
    request_id: Annotated[str, Field(description='Request correlation identifier included in responses and operational logs.')]


class ApplianceVersionResponse(BaseModel):
    """Public build identity returned by the appliance version endpoint.

    Attributes:
        version: Full Atlaso package version, including build metadata when present.
        base_version: Semantic Atlaso release version without local build metadata.
        git_commit: Source Git commit recorded when this Atlaso build was produced.
        built_at: UTC build timestamp recorded in the installed Atlaso package metadata.
    """

    version: Annotated[str, Field(description='Full Atlaso package version, including build metadata when present.')]
    base_version: Annotated[str, Field(description='Semantic Atlaso release version without local build metadata.')]
    git_commit: Annotated[str, Field(description='Source Git commit recorded when this Atlaso build was produced.')]
    built_at: Annotated[str, Field(description='UTC build timestamp recorded in the installed Atlaso package metadata.')]


class IdentityResponse(BaseModel):
    """Fields returned by the Atlaso identity API.

    Attributes:
        username: Returned username value for this identity resource.
        role: Primary compatibility role for the identity; authorization uses the complete roles
            collection.
        roles: Normalized Atlaso roles assigned to or effective for the identity.
        scopes: Normalized Atlaso API scopes granted to the identity or token.
        auth_type: Authentication mechanism that established the current identity.
    """

    username: Annotated[str, Field(description='Returned username value for this identity resource.')]
    role: Annotated[str, Field(description='Primary compatibility role for the identity; authorization uses the complete roles collection.')]
    roles: Annotated[list[str], Field(description='Normalized Atlaso roles assigned to or effective for the identity.')] = Field(default_factory=list)
    scopes: Annotated[list[str], Field(description='Normalized Atlaso API scopes granted to the identity or token.')]
    auth_type: Annotated[str, Field(description='Authentication mechanism that established the current identity.')]


class ApiTokenCreate(BaseModel):
    """Fields accepted when creating a api token resource.

    Attributes:
        name: Stable operator-facing name of this resource.
        description: Operator-facing purpose or context for this resource.
        expires_at: UTC timestamp after which the resource or credential is no longer accepted.
        scopes: Normalized Atlaso API scopes granted to the identity or token.
    """

    name: Annotated[str, Field(description='Stable operator-facing name of this resource.')] = Field(min_length=1, max_length=120)
    description: Annotated[str | None, Field(description='Operator-facing purpose or context for this resource.')] = None
    expires_at: Annotated[datetime | None, Field(description='UTC timestamp after which the resource or credential is no longer accepted.')] = None
    scopes: Annotated[list[str], Field(description='Normalized Atlaso API scopes granted to the identity or token.')] = Field(default_factory=lambda: ["read:dashboard"])


class ApiTokenResponse(BaseModel):
    """Fields returned by the Atlaso api token API.

    Attributes:
        id: Unique database identifier assigned to this resource.
        jti: Unique JWT identifier used to track and revoke the issued token.
        name: Stable operator-facing name of this resource.
        description: Operator-facing purpose or context for this resource.
        owner_user_id: Stable identifier of the related owner user resource.
        owner_username: Returned owner username value for this api token resource.
        token_type: Returned token type value for this api token resource.
        role: Primary compatibility role for the identity; authorization uses the complete roles
            collection.
        roles: Normalized Atlaso roles assigned to or effective for the identity.
        scopes: Normalized Atlaso API scopes granted to the identity or token.
        created_at: UTC timestamp when the resource was created.
        expires_at: UTC timestamp after which the resource or credential is no longer accepted.
        last_used_at: UTC timestamp of the token's most recent successful use, or null when it has
            never been used.
        revoked_at: UTC timestamp when the credential or resource was revoked, or null while active.
        revoked_by: Atlaso account name that revoked the resource, or null when it remains active.
        enabled: Whether the resource is enabled in saved Atlaso state.
        signing_key_id: Stable identifier of the related signing key resource.
    """

    model_config = ConfigDict(from_attributes=True)

    id: Annotated[int, Field(description='Unique database identifier assigned to this resource.')]
    jti: Annotated[str, Field(description='Unique JWT identifier used to track and revoke the issued token.')]
    name: Annotated[str, Field(description='Stable operator-facing name of this resource.')]
    description: Annotated[str | None, Field(description='Operator-facing purpose or context for this resource.')]
    owner_user_id: Annotated[int, Field(description='Stable identifier of the related owner user resource.')]
    owner_username: Annotated[str, Field(description='Returned owner username value for this api token resource.')]
    token_type: Annotated[str, Field(description='Returned token type value for this api token resource.')]
    role: Annotated[str, Field(description='Primary compatibility role for the identity; authorization uses the complete roles collection.')]
    roles: Annotated[list[str], Field(description='Normalized Atlaso roles assigned to or effective for the identity.')] = Field(default_factory=list)
    scopes: Annotated[list[str], Field(description='Normalized Atlaso API scopes granted to the identity or token.')]
    created_at: Annotated[datetime, Field(description='UTC timestamp when the resource was created.')]
    expires_at: Annotated[datetime, Field(description='UTC timestamp after which the resource or credential is no longer accepted.')]
    last_used_at: Annotated[datetime | None, Field(description="UTC timestamp of the token's most recent successful use, or null when it has never been used.")]
    revoked_at: Annotated[datetime | None, Field(description='UTC timestamp when the credential or resource was revoked, or null while active.')]
    revoked_by: Annotated[str | None, Field(description='Atlaso account name that revoked the resource, or null when it remains active.')]
    enabled: Annotated[bool, Field(description='Whether the resource is enabled in saved Atlaso state.')]
    signing_key_id: Annotated[str | None, Field(description='Stable identifier of the related signing key resource.')]


class ApiTokenCreated(BaseModel):
    """Fields returned by the Atlaso api token API.

    Attributes:
        token: Structured metadata describing the API token associated with this response.
        raw_token: One-time plaintext bearer token returned only at creation; store it securely
            because Atlaso cannot show it again.
    """

    token: Annotated[ApiTokenResponse, Field(description='Structured metadata describing the API token associated with this response.')]
    raw_token: Annotated[str, Field(description='One-time plaintext bearer token returned only at creation; store it securely because Atlaso cannot show it again.')]


class ServiceStateResponse(BaseModel):
    """Fields returned by the Atlaso service state API.

    Attributes:
        service: Returned service value for this service state resource.
        display_name: Returned display name value for this service state resource.
        running: Whether the backing runtime service is currently reported as running.
        enabled: Whether the resource is enabled in saved Atlaso state.
        health: Returned health value for this service state resource.
        detail: Human-readable detail explaining the current state or failure.
    """

    model_config = ConfigDict(from_attributes=True)

    service: Annotated[str, Field(description='Returned service value for this service state resource.')]
    display_name: Annotated[str, Field(description='Returned display name value for this service state resource.')]
    running: Annotated[bool, Field(description='Whether the backing runtime service is currently reported as running.')]
    enabled: Annotated[bool, Field(description='Whether the resource is enabled in saved Atlaso state.')]
    health: Annotated[str, Field(description='Returned health value for this service state resource.')]
    detail: Annotated[str | None, Field(description='Human-readable detail explaining the current state or failure.')]


class FirewallSettingsUpdate(BaseModel):
    """Fields accepted when updating or operating on a firewall settings resource.

    Attributes:
        enabled: Whether the resource is enabled in saved Atlaso state.
        default_input_policy: Requested default input policy value for this firewall settings
            resource.
        default_forward_policy: Requested default forward policy value for this firewall settings
            resource.
        default_output_policy: Requested default output policy value for this firewall settings
            resource.
        allow_established: Whether allow established is enabled for this firewall settings resource.
        allow_loopback: Whether allow loopback is enabled for this firewall settings resource.
        allow_icmp: Whether allow icmp is enabled for this firewall settings resource.
        log_dropped: Whether log dropped is enabled for this firewall settings resource.
    """

    enabled: Annotated[bool, Field(description='Whether the resource is enabled in saved Atlaso state.')] = False
    default_input_policy: Annotated[str, Field(description='Requested default input policy value for this firewall settings resource.')] = "drop"
    default_forward_policy: Annotated[str, Field(description='Requested default forward policy value for this firewall settings resource.')] = "drop"
    default_output_policy: Annotated[str, Field(description='Requested default output policy value for this firewall settings resource.')] = "accept"
    allow_established: Annotated[bool, Field(description='Whether allow established is enabled for this firewall settings resource.')] = True
    allow_loopback: Annotated[bool, Field(description='Whether allow loopback is enabled for this firewall settings resource.')] = True
    allow_icmp: Annotated[bool, Field(description='Whether allow icmp is enabled for this firewall settings resource.')] = True
    log_dropped: Annotated[bool, Field(description='Whether log dropped is enabled for this firewall settings resource.')] = False


class FirewallSettingsResponse(FirewallSettingsUpdate):
    """Fields returned by the Atlaso firewall settings API.

    Attributes:
        id: Unique database identifier assigned to this resource.
        config_path: Appliance path where the rendered configuration is staged or installed; it is
            not a free-form input.
        updated_at: UTC timestamp when the resource was last updated.
    """

    model_config = ConfigDict(from_attributes=True)

    id: Annotated[int, Field(description='Unique database identifier assigned to this resource.')]
    config_path: Annotated[str, Field(description='Appliance path where the rendered configuration is staged or installed; it is not a free-form input.')]
    updated_at: Annotated[datetime, Field(description='UTC timestamp when the resource was last updated.')]


class FirewallRuleCreate(BaseModel):
    """Fields accepted when creating a firewall rule resource.

    Attributes:
        name: Stable operator-facing name of this resource.
        direction: Requested direction value for this firewall rule resource.
        action: Requested action value for this firewall rule resource.
        protocol: Requested protocol value for this firewall rule resource.
        source: Validated network or address value for source in this firewall rule resource.
        destination: Validated network or address value for destination in this firewall rule
            resource.
        destination_port: TCP or UDP destination port in the valid 1 through 65535 range.
        interface_name: Requested interface name value for this firewall rule resource.
        priority: Requested priority value for this firewall rule resource.
        enabled: Whether the resource is enabled in saved Atlaso state.
        description: Operator-facing purpose or context for this resource.
    """

    name: Annotated[str, Field(description='Stable operator-facing name of this resource.')] = Field(min_length=1, max_length=120)
    direction: Annotated[str, Field(description='Requested direction value for this firewall rule resource.')] = "input"
    action: Annotated[str, Field(description='Requested action value for this firewall rule resource.')] = "accept"
    protocol: Annotated[str, Field(description='Requested protocol value for this firewall rule resource.')] = "tcp"
    source: Annotated[str, Field(description='Validated network or address value for source in this firewall rule resource.')] = "any"
    destination: Annotated[str, Field(description='Validated network or address value for destination in this firewall rule resource.')] = "any"
    destination_port: Annotated[str, Field(description='TCP or UDP destination port in the valid 1 through 65535 range.')] = ""
    interface_name: Annotated[str, Field(description='Requested interface name value for this firewall rule resource.')] = ""
    priority: Annotated[int, Field(description='Requested priority value for this firewall rule resource.')] = 100
    enabled: Annotated[bool, Field(description='Whether the resource is enabled in saved Atlaso state.')] = True
    description: Annotated[str | None, Field(description='Operator-facing purpose or context for this resource.')] = None


class FirewallRuleResponse(FirewallRuleCreate):
    """Fields returned by the Atlaso firewall rule API.

    Attributes:
        id: Unique database identifier assigned to this resource.
        created_at: UTC timestamp when the resource was created.
        updated_at: UTC timestamp when the resource was last updated.
    """

    model_config = ConfigDict(from_attributes=True)

    id: Annotated[int, Field(description='Unique database identifier assigned to this resource.')]
    created_at: Annotated[datetime, Field(description='UTC timestamp when the resource was created.')]
    updated_at: Annotated[datetime, Field(description='UTC timestamp when the resource was last updated.')]


class FirewallStatusResponse(BaseModel):
    """Fields returned by the Atlaso firewall status API.

    Attributes:
        enabled: Whether the resource is enabled in saved Atlaso state.
        service: Returned service value for this firewall status resource.
        rule_count: Number of rule records represented by this firewall status response.
        config_path: Appliance path where the rendered configuration is staged or installed; it is
            not a free-form input.
        dry_run: Whether the operation reports command intent without mutating appliance host state.
    """

    enabled: Annotated[bool, Field(description='Whether the resource is enabled in saved Atlaso state.')]
    service: Annotated[ServiceStateResponse | None, Field(description='Returned service value for this firewall status resource.')]
    rule_count: Annotated[int, Field(description='Number of rule records represented by this firewall status response.')]
    config_path: Annotated[str, Field(description='Appliance path where the rendered configuration is staged or installed; it is not a free-form input.')]
    dry_run: Annotated[bool, Field(description='Whether the operation reports command intent without mutating appliance host state.')]


class VcfBackupStatusResponse(BaseModel):
    """Fields returned by the Atlaso vcf backup status API.

    Attributes:
        enabled: Whether the resource is enabled in saved Atlaso state.
        service: Returned service value for this vcf backup status resource.
        listen_interface: Saved access interface or enabled VLAN used as the service bind target.
        listen_address: Derived IP address on which the service listens; operators select an
            interface rather than entering this value directly.
        port: TCP or UDP port in the valid 1 through 65535 range.
        sftp_username: Returned sftp username value for this vcf backup status resource.
        storage_path: Canonical filesystem or HTTP storage path used by Atlaso; callers must not
            treat it as an unrestricted path.
        remote_directory: Returned remote directory value for this vcf backup status resource.
        config_path: Appliance path where the rendered configuration is staged or installed; it is
            not a free-form input.
        dry_run: Whether the operation reports command intent without mutating appliance host state.
    """

    enabled: Annotated[bool, Field(description='Whether the resource is enabled in saved Atlaso state.')]
    service: Annotated[ServiceStateResponse | None, Field(description='Returned service value for this vcf backup status resource.')]
    listen_interface: Annotated[str, Field(description='Saved access interface or enabled VLAN used as the service bind target.')]
    listen_address: Annotated[str, Field(description='Derived IP address on which the service listens; operators select an interface rather than entering this value directly.')]
    port: Annotated[int, Field(description='TCP or UDP port in the valid 1 through 65535 range.')]
    sftp_username: Annotated[str | None, Field(description='Returned sftp username value for this vcf backup status resource.')]
    storage_path: Annotated[str, Field(description='Canonical filesystem or HTTP storage path used by Atlaso; callers must not treat it as an unrestricted path.')]
    remote_directory: Annotated[str, Field(description='Returned remote directory value for this vcf backup status resource.')]
    config_path: Annotated[str, Field(description='Appliance path where the rendered configuration is staged or installed; it is not a free-form input.')]
    dry_run: Annotated[bool, Field(description='Whether the operation reports command intent without mutating appliance host state.')]


class EsxStorageSettingsUpdate(BaseModel):
    """Fields accepted when updating or operating on a esx storage settings resource.

    Attributes:
        enabled: Whether the resource is enabled in saved Atlaso state.
        hostname: DNS hostname associated with the resource, normalized according to the endpoint
            contract.
    """

    enabled: Annotated[bool, Field(description='Whether the resource is enabled in saved Atlaso state.')] = False
    hostname: Annotated[str | None, Field(description='DNS hostname associated with the resource, normalized according to the endpoint contract. Omit it to preserve the current factory-derived or operator-customized hostname.')] = Field(default=None, min_length=1, max_length=253)


class EsxStorageVolumeCreate(BaseModel):
    """Fields accepted when creating a esx storage volume resource.

    Attributes:
        name: Stable operator-facing name of this resource.
        source_type: Requested source type value for this esx storage volume resource.
        stable_device_id: Stable identifier of the related stable device resource.
        mount_path: Canonical filesystem or HTTP mount path used by Atlaso; callers must not treat
            it as an unrestricted path.
    """

    name: Annotated[str, Field(description='Stable operator-facing name of this resource.')] = Field(min_length=1, max_length=120)
    source_type: Annotated[Literal["blank_disk", "mounted_ext4"], Field(description='Requested source type value for this esx storage volume resource.')] = "blank_disk"
    stable_device_id: Annotated[str, Field(description='Stable identifier of the related stable device resource.')] = Field(default="", max_length=500)
    mount_path: Annotated[str, Field(description='Canonical filesystem or HTTP mount path used by Atlaso; callers must not treat it as an unrestricted path.')] = Field(default="", max_length=500)


class EsxStorageVolumeUpdate(BaseModel):
    """Fields accepted when updating or operating on a esx storage volume resource.

    Attributes:
        name: Stable operator-facing name of this resource.
        stable_device_id: Stable identifier of the related stable device resource.
        mount_path: Canonical filesystem or HTTP mount path used by Atlaso; callers must not treat
            it as an unrestricted path.
    """

    name: Annotated[str | None, Field(description='Stable operator-facing name of this resource.')] = Field(default=None, min_length=1, max_length=120)
    stable_device_id: Annotated[str | None, Field(description='Stable identifier of the related stable device resource.')] = Field(default=None, max_length=500)
    mount_path: Annotated[str | None, Field(description='Canonical filesystem or HTTP mount path used by Atlaso; callers must not treat it as an unrestricted path.')] = Field(default=None, max_length=500)


class EsxStorageVolumeResponse(BaseModel):
    """Fields returned by the Atlaso esx storage volume API.

    Attributes:
        id: Unique database identifier assigned to this resource.
        name: Stable operator-facing name of this resource.
        source_type: Returned source type value for this esx storage volume resource.
        stable_device_id: Stable identifier of the related stable device resource.
        device_path: Canonical filesystem or HTTP device path used by Atlaso; callers must not treat
            it as an unrestricted path.
        device_model: Returned device model value for this esx storage volume resource.
        device_serial: Returned device serial value for this esx storage volume resource.
        device_wwn: Returned device wwn value for this esx storage volume resource.
        capacity_bytes: Capacity bytes, measured in bytes.
        filesystem_uuid: Returned filesystem uuid value for this esx storage volume resource.
        filesystem_label: Returned filesystem label value for this esx storage volume resource.
        mount_path: Canonical filesystem or HTTP mount path used by Atlaso; callers must not treat
            it as an unrestricted path.
        state: Returned state value for this esx storage volume resource.
        applied: Whether applied is enabled for this esx storage volume resource.
        created_at: UTC timestamp when the resource was created.
        updated_at: UTC timestamp when the resource was last updated.
    """

    model_config = ConfigDict(from_attributes=True)

    id: Annotated[int, Field(description='Unique database identifier assigned to this resource.')]
    name: Annotated[str, Field(description='Stable operator-facing name of this resource.')]
    source_type: Annotated[str, Field(description='Returned source type value for this esx storage volume resource.')]
    stable_device_id: Annotated[str, Field(description='Stable identifier of the related stable device resource.')]
    device_path: Annotated[str, Field(description='Canonical filesystem or HTTP device path used by Atlaso; callers must not treat it as an unrestricted path.')]
    device_model: Annotated[str, Field(description='Returned device model value for this esx storage volume resource.')]
    device_serial: Annotated[str, Field(description='Returned device serial value for this esx storage volume resource.')]
    device_wwn: Annotated[str, Field(description='Returned device wwn value for this esx storage volume resource.')]
    capacity_bytes: Annotated[int, Field(description='Capacity bytes, measured in bytes.')]
    filesystem_uuid: Annotated[str, Field(description='Returned filesystem uuid value for this esx storage volume resource.')]
    filesystem_label: Annotated[str, Field(description='Returned filesystem label value for this esx storage volume resource.')]
    mount_path: Annotated[str, Field(description='Canonical filesystem or HTTP mount path used by Atlaso; callers must not treat it as an unrestricted path.')]
    state: Annotated[str, Field(description='Returned state value for this esx storage volume resource.')]
    applied: Annotated[bool, Field(description='Whether applied is enabled for this esx storage volume resource.')]
    created_at: Annotated[datetime, Field(description='UTC timestamp when the resource was created.')]
    updated_at: Annotated[datetime, Field(description='UTC timestamp when the resource was last updated.')]


class EsxNfsShareCreate(BaseModel):
    """Fields accepted when creating a esx nfs share resource.

    Attributes:
        datastore_name: Requested datastore name value for this esx nfs share resource.
        volume_id: Stable identifier of the related volume resource.
        relative_path: Canonical filesystem or HTTP relative path used by Atlaso; callers must not
            treat it as an unrestricted path.
        preferred_nfs_version: Requested preferred nfs version value for this esx nfs share
            resource.
        interface_name: Requested interface name value for this esx nfs share resource.
        address_families: Ordered collection of address families values represented by this esx nfs
            share schema.
        ipv4_clients: Ordered collection of ipv4 clients values represented by this esx nfs share
            schema.
        ipv6_clients: Ordered collection of ipv6 clients values represented by this esx nfs share
            schema.
        enabled: Whether the resource is enabled in saved Atlaso state.
    """

    datastore_name: Annotated[str, Field(description='Requested datastore name value for this esx nfs share resource.')] = Field(min_length=1, max_length=120)
    volume_id: Annotated[int, Field(description='Stable identifier of the related volume resource.')]
    relative_path: Annotated[str, Field(description='Canonical filesystem or HTTP relative path used by Atlaso; callers must not treat it as an unrestricted path.')] = Field(min_length=1, max_length=500)
    preferred_nfs_version: Annotated[Literal["3", "4.1"], Field(description='Requested preferred nfs version value for this esx nfs share resource.')] = "4.1"
    interface_name: Annotated[str, Field(description='Requested interface name value for this esx nfs share resource.')] = Field(min_length=1, max_length=80)
    address_families: Annotated[list[Literal["ipv4", "ipv6"]], Field(description='Ordered collection of address families values represented by this esx nfs share schema.')] = Field(default_factory=lambda: ["ipv4", "ipv6"])
    ipv4_clients: Annotated[list[str], Field(description='Ordered collection of ipv4 clients values represented by this esx nfs share schema.')] = Field(default_factory=list)
    ipv6_clients: Annotated[list[str], Field(description='Ordered collection of ipv6 clients values represented by this esx nfs share schema.')] = Field(default_factory=list)
    enabled: Annotated[bool, Field(description='Whether the resource is enabled in saved Atlaso state.')] = True


class EsxNfsShareUpdate(BaseModel):
    """Fields accepted when updating or operating on a esx nfs share resource.

    Attributes:
        datastore_name: Requested datastore name value for this esx nfs share resource.
        volume_id: Stable identifier of the related volume resource.
        relative_path: Canonical filesystem or HTTP relative path used by Atlaso; callers must not
            treat it as an unrestricted path.
        preferred_nfs_version: Requested preferred nfs version value for this esx nfs share
            resource.
        interface_name: Requested interface name value for this esx nfs share resource.
        address_families: Ordered collection of address families values represented by this esx nfs
            share schema.
        ipv4_clients: Ordered collection of ipv4 clients values represented by this esx nfs share
            schema.
        ipv6_clients: Ordered collection of ipv6 clients values represented by this esx nfs share
            schema.
        enabled: Whether the resource is enabled in saved Atlaso state.
    """

    datastore_name: Annotated[str | None, Field(description='Requested datastore name value for this esx nfs share resource.')] = Field(default=None, min_length=1, max_length=120)
    volume_id: Annotated[int | None, Field(description='Stable identifier of the related volume resource.')] = None
    relative_path: Annotated[str | None, Field(description='Canonical filesystem or HTTP relative path used by Atlaso; callers must not treat it as an unrestricted path.')] = Field(default=None, min_length=1, max_length=500)
    preferred_nfs_version: Annotated[Literal["3", "4.1"] | None, Field(description='Requested preferred nfs version value for this esx nfs share resource.')] = None
    interface_name: Annotated[str | None, Field(description='Requested interface name value for this esx nfs share resource.')] = Field(default=None, min_length=1, max_length=80)
    address_families: Annotated[list[Literal["ipv4", "ipv6"]] | None, Field(description='Ordered collection of address families values represented by this esx nfs share schema.')] = None
    ipv4_clients: Annotated[list[str] | None, Field(description='Ordered collection of ipv4 clients values represented by this esx nfs share schema.')] = None
    ipv6_clients: Annotated[list[str] | None, Field(description='Ordered collection of ipv6 clients values represented by this esx nfs share schema.')] = None
    enabled: Annotated[bool | None, Field(description='Whether the resource is enabled in saved Atlaso state.')] = None


class EsxNfsShareResponse(BaseModel):
    """Fields returned by the Atlaso esx nfs share API.

    Attributes:
        id: Unique database identifier assigned to this resource.
        datastore_name: Returned datastore name value for this esx nfs share resource.
        volume_id: Stable identifier of the related volume resource.
        volume_name: Returned volume name value for this esx nfs share resource.
        relative_path: Canonical filesystem or HTTP relative path used by Atlaso; callers must not
            treat it as an unrestricted path.
        preferred_nfs_version: Returned preferred nfs version value for this esx nfs share resource.
        interface_name: Returned interface name value for this esx nfs share resource.
        address_families: Ordered collection of address families values represented by this esx nfs
            share schema.
        ipv4_clients: Ordered collection of ipv4 clients values represented by this esx nfs share
            schema.
        ipv6_clients: Ordered collection of ipv6 clients values represented by this esx nfs share
            schema.
        listeners: Ordered collection of listeners values represented by this esx nfs share schema.
        target_hostnames: Ordered collection of target hostnames values represented by this esx nfs
            share schema.
        local_path: Canonical filesystem or HTTP local path used by Atlaso; callers must not treat
            it as an unrestricted path.
        remote_path: Canonical filesystem or HTTP remote path used by Atlaso; callers must not treat
            it as an unrestricted path.
        connection_commands: Ordered collection of connection commands values represented by this
            esx nfs share schema.
        powercli_commands: Ordered collection of powercli commands values represented by this esx
            nfs share schema.
        enabled: Whether the resource is enabled in saved Atlaso state.
    """

    id: Annotated[int, Field(description='Unique database identifier assigned to this resource.')]
    datastore_name: Annotated[str, Field(description='Returned datastore name value for this esx nfs share resource.')]
    volume_id: Annotated[int, Field(description='Stable identifier of the related volume resource.')]
    volume_name: Annotated[str, Field(description='Returned volume name value for this esx nfs share resource.')]
    relative_path: Annotated[str, Field(description='Canonical filesystem or HTTP relative path used by Atlaso; callers must not treat it as an unrestricted path.')]
    preferred_nfs_version: Annotated[str, Field(description='Returned preferred nfs version value for this esx nfs share resource.')]
    interface_name: Annotated[str, Field(description='Returned interface name value for this esx nfs share resource.')]
    address_families: Annotated[list[str], Field(description='Ordered collection of address families values represented by this esx nfs share schema.')]
    ipv4_clients: Annotated[list[str], Field(description='Ordered collection of ipv4 clients values represented by this esx nfs share schema.')]
    ipv6_clients: Annotated[list[str], Field(description='Ordered collection of ipv6 clients values represented by this esx nfs share schema.')]
    listeners: Annotated[dict[str, list[str]], Field(description='Ordered collection of listeners values represented by this esx nfs share schema.')]
    target_hostnames: Annotated[dict[str, list[str]], Field(description='Ordered collection of target hostnames values represented by this esx nfs share schema.')]
    local_path: Annotated[str, Field(description='Canonical filesystem or HTTP local path used by Atlaso; callers must not treat it as an unrestricted path.')]
    remote_path: Annotated[str, Field(description='Canonical filesystem or HTTP remote path used by Atlaso; callers must not treat it as an unrestricted path.')]
    connection_commands: Annotated[dict[str, list[str]], Field(description='Ordered collection of connection commands values represented by this esx nfs share schema.')]
    powercli_commands: Annotated[dict[str, list[str]], Field(description='Ordered collection of powercli commands values represented by this esx nfs share schema.')]
    enabled: Annotated[bool, Field(description='Whether the resource is enabled in saved Atlaso state.')]


class EsxStorageStatusResponse(BaseModel):
    """Fields returned by the Atlaso esx storage status API.

    Attributes:
        enabled: Whether the resource is enabled in saved Atlaso state.
        hostname: DNS hostname associated with the resource, normalized according to the endpoint
            contract.
        valid: Whether the represented desired state passed Atlaso validation.
        validation_errors: Actionable validation failures that must be corrected before the state
            can be applied.
        validation_warnings: Non-blocking validation warnings that the operator should review.
        volume_count: Number of volume records represented by this esx storage status response.
        share_count: Number of share records represented by this esx storage status response.
        active_share_count: Number of active share records represented by this esx storage status
            response.
        dry_run: Whether the operation reports command intent without mutating appliance host state.
    """

    enabled: Annotated[bool, Field(description='Whether the resource is enabled in saved Atlaso state.')]
    hostname: Annotated[str, Field(description='DNS hostname associated with the resource, normalized according to the endpoint contract.')]
    valid: Annotated[bool, Field(description='Whether the represented desired state passed Atlaso validation.')]
    validation_errors: Annotated[list[str], Field(description='Actionable validation failures that must be corrected before the state can be applied.')]
    validation_warnings: Annotated[list[str], Field(description='Non-blocking validation warnings that the operator should review.')]
    volume_count: Annotated[int, Field(description='Number of volume records represented by this esx storage status response.')]
    share_count: Annotated[int, Field(description='Number of share records represented by this esx storage status response.')]
    active_share_count: Annotated[int, Field(description='Number of active share records represented by this esx storage status response.')]
    dry_run: Annotated[bool, Field(description='Whether the operation reports command intent without mutating appliance host state.')]


class EsxStorageDiskResponse(BaseModel):
    """Fields returned by the Atlaso esx storage disk API.

    Attributes:
        candidate_type: Returned candidate type value for this esx storage disk resource.
        stable_device_id: Stable identifier of the related stable device resource.
        device_path: Canonical filesystem or HTTP device path used by Atlaso; callers must not treat
            it as an unrestricted path.
        model: Returned model value for this esx storage disk resource.
        serial: Returned serial value for this esx storage disk resource.
        wwn: Returned wwn value for this esx storage disk resource.
        size_bytes: Size bytes, measured in bytes.
        filesystem_type: Returned filesystem type value for this esx storage disk resource.
        filesystem_uuid: Returned filesystem uuid value for this esx storage disk resource.
        filesystem_label: Returned filesystem label value for this esx storage disk resource.
        mount_path: Canonical filesystem or HTTP mount path used by Atlaso; callers must not treat
            it as an unrestricted path.
        eligible: Whether eligible is enabled for this esx storage disk resource.
        eligibility_reason: Returned eligibility reason value for this esx storage disk resource.
    """

    candidate_type: Annotated[Literal["blank_disk", "mounted_ext4", ""], Field(description='Returned candidate type value for this esx storage disk resource.')] = ""
    stable_device_id: Annotated[str, Field(description='Stable identifier of the related stable device resource.')]
    device_path: Annotated[str, Field(description='Canonical filesystem or HTTP device path used by Atlaso; callers must not treat it as an unrestricted path.')]
    model: Annotated[str, Field(description='Returned model value for this esx storage disk resource.')] = ""
    serial: Annotated[str, Field(description='Returned serial value for this esx storage disk resource.')] = ""
    wwn: Annotated[str, Field(description='Returned wwn value for this esx storage disk resource.')] = ""
    size_bytes: Annotated[int, Field(description='Size bytes, measured in bytes.')] = 0
    filesystem_type: Annotated[str, Field(description='Returned filesystem type value for this esx storage disk resource.')] = ""
    filesystem_uuid: Annotated[str, Field(description='Returned filesystem uuid value for this esx storage disk resource.')] = ""
    filesystem_label: Annotated[str, Field(description='Returned filesystem label value for this esx storage disk resource.')] = ""
    mount_path: Annotated[str, Field(description='Canonical filesystem or HTTP mount path used by Atlaso; callers must not treat it as an unrestricted path.')] = ""
    eligible: Annotated[bool, Field(description='Whether eligible is enabled for this esx storage disk resource.')]
    eligibility_reason: Annotated[str, Field(description='Returned eligibility reason value for this esx storage disk resource.')] = ""


class VcfPrivateRegistryStatusResponse(BaseModel):
    """Fields returned by the Atlaso vcf private registry status API.

    Attributes:
        enabled: Whether the resource is enabled in saved Atlaso state.
        service: Returned service value for this vcf private registry status resource.
        hostname: DNS hostname associated with the resource, normalized according to the endpoint
            contract.
        endpoint: Validated endpoint used for this vcf private registry status integration.
        listen_interface: Saved access interface or enabled VLAN used as the service bind target.
        listen_address: Derived IP address on which the service listens; operators select an
            interface rather than entering this value directly.
        port: TCP or UDP port in the valid 1 through 65535 range.
        harbor_project: Returned harbor project value for this vcf private registry status resource.
        storage_path: Canonical filesystem or HTTP storage path used by Atlaso; callers must not
            treat it as an unrestricted path.
        config_path: Appliance path where the rendered configuration is staged or installed; it is
            not a free-form input.
        bundle_count: Number of bundle records represented by this vcf private registry status
            response.
        valid: Whether the represented desired state passed Atlaso validation.
        dry_run: Whether the operation reports command intent without mutating appliance host state.
    """

    enabled: Annotated[bool, Field(description='Whether the resource is enabled in saved Atlaso state.')]
    service: Annotated[ServiceStateResponse | None, Field(description='Returned service value for this vcf private registry status resource.')]
    hostname: Annotated[str, Field(description='DNS hostname associated with the resource, normalized according to the endpoint contract.')]
    endpoint: Annotated[str, Field(description='Validated endpoint used for this vcf private registry status integration.')]
    listen_interface: Annotated[str, Field(description='Saved access interface or enabled VLAN used as the service bind target.')]
    listen_address: Annotated[str, Field(description='Derived IP address on which the service listens; operators select an interface rather than entering this value directly.')]
    port: Annotated[int, Field(description='TCP or UDP port in the valid 1 through 65535 range.')]
    harbor_project: Annotated[str, Field(description='Returned harbor project value for this vcf private registry status resource.')]
    storage_path: Annotated[str, Field(description='Canonical filesystem or HTTP storage path used by Atlaso; callers must not treat it as an unrestricted path.')]
    config_path: Annotated[str, Field(description='Appliance path where the rendered configuration is staged or installed; it is not a free-form input.')]
    bundle_count: Annotated[int, Field(description='Number of bundle records represented by this vcf private registry status response.')]
    valid: Annotated[bool, Field(description='Whether the represented desired state passed Atlaso validation.')]
    dry_run: Annotated[bool, Field(description='Whether the operation reports command intent without mutating appliance host state.')]


class VcfOfflineDepotStatusResponse(BaseModel):
    """Fields returned by the Atlaso vcf offline depot status API.

    Attributes:
        enabled: Whether the resource is enabled in saved Atlaso state.
        service: Returned service value for this vcf offline depot status resource.
        hostname: DNS hostname associated with the resource, normalized according to the endpoint
            contract.
        endpoint: Validated endpoint used for this vcf offline depot status integration.
        listen_interface: Saved access interface or enabled VLAN used as the service bind target.
        listen_address: Derived IP address on which the service listens; operators select an
            interface rather than entering this value directly.
        port: TCP or UDP port in the valid 1 through 65535 range.
        http_username: Returned http username value for this vcf offline depot status resource.
        allow_unauthenticated_access: Whether allow unauthenticated access is enabled for this vcf
            offline depot status resource.
        depot_store_path: Canonical filesystem or HTTP depot store path used by Atlaso; callers must
            not treat it as an unrestricted path.
        tool_archive_name: Returned tool archive name value for this vcf offline depot status
            resource.
        tool_version: Returned tool version value for this vcf offline depot status resource.
        software_depot_id: Stable identifier of the related software depot resource.
        software_depot_id_generated_at: UTC timestamp for software depot id generated at on this vcf
            offline depot status resource.
        software_depot_id_error: Returned software depot id error value for this vcf offline depot
            status resource.
        download_token_present: Whether download token is securely staged without exposing its
            value.
        activation_code_present: Whether activation code is securely staged without exposing its
            value.
        application_properties_present: Whether application properties is securely staged without
            exposing its value.
        application_properties_source: Returned application properties source value for this vcf
            offline depot status resource.
        application_properties_updated_at: UTC timestamp for application properties updated at on
            this vcf offline depot status resource.
        profile_count: Number of profile records represented by this vcf offline depot status
            response.
        config_path: Appliance path where the rendered configuration is staged or installed; it is
            not a free-form input.
        valid: Whether the represented desired state passed Atlaso validation.
        dry_run: Whether the operation reports command intent without mutating appliance host state.
    """

    enabled: Annotated[bool, Field(description='Whether the resource is enabled in saved Atlaso state.')]
    service: Annotated[ServiceStateResponse | None, Field(description='Returned service value for this vcf offline depot status resource.')]
    hostname: Annotated[str, Field(description='DNS hostname associated with the resource, normalized according to the endpoint contract.')]
    endpoint: Annotated[str, Field(description='Validated endpoint used for this vcf offline depot status integration.')]
    listen_interface: Annotated[str, Field(description='Saved access interface or enabled VLAN used as the service bind target.')]
    listen_address: Annotated[str, Field(description='Derived IP address on which the service listens; operators select an interface rather than entering this value directly.')]
    port: Annotated[int, Field(description='TCP or UDP port in the valid 1 through 65535 range.')]
    http_username: Annotated[str, Field(description='Returned http username value for this vcf offline depot status resource.')]
    allow_unauthenticated_access: Annotated[bool, Field(description='Whether allow unauthenticated access is enabled for this vcf offline depot status resource.')]
    depot_store_path: Annotated[str, Field(description='Canonical filesystem or HTTP depot store path used by Atlaso; callers must not treat it as an unrestricted path.')]
    tool_archive_name: Annotated[str, Field(description='Returned tool archive name value for this vcf offline depot status resource.')]
    tool_version: Annotated[str, Field(description='Returned tool version value for this vcf offline depot status resource.')]
    software_depot_id: Annotated[str, Field(description='Stable identifier of the related software depot resource.')]
    software_depot_id_generated_at: Annotated[str, Field(description='UTC timestamp for software depot id generated at on this vcf offline depot status resource.')]
    software_depot_id_error: Annotated[str, Field(description='Returned software depot id error value for this vcf offline depot status resource.')]
    download_token_present: Annotated[bool, Field(description='Whether download token is securely staged without exposing its value.')]
    activation_code_present: Annotated[bool, Field(description='Whether activation code is securely staged without exposing its value.')]
    application_properties_present: Annotated[bool, Field(description='Whether application properties is securely staged without exposing its value.')]
    application_properties_source: Annotated[str, Field(description='Returned application properties source value for this vcf offline depot status resource.')]
    application_properties_updated_at: Annotated[str, Field(description='UTC timestamp for application properties updated at on this vcf offline depot status resource.')]
    profile_count: Annotated[int, Field(description='Number of profile records represented by this vcf offline depot status response.')]
    config_path: Annotated[str, Field(description='Appliance path where the rendered configuration is staged or installed; it is not a free-form input.')]
    valid: Annotated[bool, Field(description='Whether the represented desired state passed Atlaso validation.')]
    dry_run: Annotated[bool, Field(description='Whether the operation reports command intent without mutating appliance host state.')]


class LdapPasswordPolicy(BaseModel):
    """Validated fields used by the Atlaso ldap password policy API contract.

    Attributes:
        min_length: Returned min length value for this ldap password policy resource.
        require_uppercase: Whether require uppercase is enabled for this ldap password policy
            resource.
        require_lowercase: Whether require lowercase is enabled for this ldap password policy
            resource.
        require_number: Whether require number is enabled for this ldap password policy resource.
        require_special: Whether require special is enabled for this ldap password policy resource.
        disallow_username: Whether disallow username is enabled for this ldap password policy
            resource.
        max_failures: Returned max failures value for this ldap password policy resource.
        lockout_minutes: Lockout minutes, measured in minutes, for this ldap password policy
            resource.
        failure_window_minutes: Failure window minutes, measured in minutes, for this ldap password
            policy resource.
        history: Returned history value for this ldap password policy resource.
        max_age_days: Max age days, measured in days, for this ldap password policy resource.
    """

    min_length: Annotated[int, Field(description='Returned min length value for this ldap password policy resource.')] = Field(default=14, ge=8, le=128)
    require_uppercase: Annotated[bool, Field(description='Whether require uppercase is enabled for this ldap password policy resource.')] = True
    require_lowercase: Annotated[bool, Field(description='Whether require lowercase is enabled for this ldap password policy resource.')] = True
    require_number: Annotated[bool, Field(description='Whether require number is enabled for this ldap password policy resource.')] = True
    require_special: Annotated[bool, Field(description='Whether require special is enabled for this ldap password policy resource.')] = True
    disallow_username: Annotated[bool, Field(description='Whether disallow username is enabled for this ldap password policy resource.')] = True
    max_failures: Annotated[int, Field(description='Returned max failures value for this ldap password policy resource.')] = Field(default=5, ge=1, le=100)
    lockout_minutes: Annotated[int, Field(description='Lockout minutes, measured in minutes, for this ldap password policy resource.')] = Field(default=15, ge=1, le=1440)
    failure_window_minutes: Annotated[int, Field(description='Failure window minutes, measured in minutes, for this ldap password policy resource.')] = Field(default=15, ge=1, le=1440)
    history: Annotated[int, Field(description='Returned history value for this ldap password policy resource.')] = Field(default=5, ge=0, le=24)
    max_age_days: Annotated[int, Field(description='Max age days, measured in days, for this ldap password policy resource.')] = Field(default=0, ge=0, le=3650)


class LdapSettingsUpdate(BaseModel):
    """Fields accepted when updating or operating on a ldap settings resource.

    Attributes:
        enabled: Whether the resource is enabled in saved Atlaso state.
        hostname: DNS hostname associated with the resource, normalized according to the endpoint
            contract.
        listen_interfaces: Saved access interfaces or enabled VLANs used as service bind targets.
        listen_addresses: Derived IPv4 and IPv6 listener addresses for the selected interfaces.
        ldaps_enabled: Whether LDAPs enabled is enabled for this ldap settings resource.
        port: TCP or UDP port in the valid 1 through 65535 range.
        ldap_enabled: Whether LDAP enabled is enabled for this ldap settings resource.
        ldap_port: TCP or UDP LDAP port in the valid 1 through 65535 range.
        password_policy: Requested password policy value for this ldap settings resource.
    """

    enabled: Annotated[bool, Field(description='Whether the resource is enabled in saved Atlaso state.')] = False
    hostname: Annotated[str | None, Field(description='DNS hostname associated with the resource, normalized according to the endpoint contract. Omit it to preserve the current factory-derived or operator-customized hostname.')] = Field(default=None, min_length=1, max_length=180)
    listen_interfaces: Annotated[list[str], Field(description='Saved access interfaces or enabled VLANs used as service bind targets.')] = Field(default_factory=list)
    listen_addresses: Annotated[list[str], Field(description='Derived IPv4 and IPv6 listener addresses for the selected interfaces.')] = Field(default_factory=list)
    ldaps_enabled: Annotated[bool, Field(description='Whether LDAPs enabled is enabled for this ldap settings resource.')] = True
    port: Annotated[int, Field(description='TCP or UDP port in the valid 1 through 65535 range.')] = Field(default=636, ge=1, le=65535)
    ldap_enabled: Annotated[bool, Field(description='Whether LDAP enabled is enabled for this ldap settings resource.')] = False
    ldap_port: Annotated[int, Field(description='TCP or UDP LDAP port in the valid 1 through 65535 range.')] = Field(default=389, ge=1, le=65535)
    password_policy: Annotated[LdapPasswordPolicy, Field(description='Requested password policy value for this ldap settings resource.')] = Field(default_factory=LdapPasswordPolicy)


class LdapSettingsResponse(LdapSettingsUpdate):
    """Fields returned by the Atlaso ldap settings API.

    Attributes:
        id: Unique database identifier assigned to this resource.
        config_path: Appliance path where the rendered configuration is staged or installed; it is
            not a free-form input.
        certificate_path: Canonical filesystem or HTTP certificate path used by Atlaso; callers must
            not treat it as an unrestricted path.
        key_path: Canonical filesystem or HTTP key path used by Atlaso; callers must not treat it as
            an unrestricted path.
        chain_path: Canonical filesystem or HTTP chain path used by Atlaso; callers must not treat
            it as an unrestricted path.
        root_ca_path: Canonical filesystem or HTTP root ca path used by Atlaso; callers must not
            treat it as an unrestricted path.
        valid: Whether the represented desired state passed Atlaso validation.
        validation_errors: Actionable validation failures that must be corrected before the state
            can be applied.
        validation_warnings: Non-blocking validation warnings that the operator should review.
        updated_at: UTC timestamp when the resource was last updated.
    """

    hostname: Annotated[str, Field(description='Persisted DNS hostname used by the LDAP service response.')] = Field(min_length=1, max_length=180)
    id: Annotated[int, Field(description='Unique database identifier assigned to this resource.')]
    config_path: Annotated[str, Field(description='Appliance path where the rendered configuration is staged or installed; it is not a free-form input.')]
    certificate_path: Annotated[str, Field(description='Canonical filesystem or HTTP certificate path used by Atlaso; callers must not treat it as an unrestricted path.')]
    key_path: Annotated[str, Field(description='Canonical filesystem or HTTP key path used by Atlaso; callers must not treat it as an unrestricted path.')]
    chain_path: Annotated[str, Field(description='Canonical filesystem or HTTP chain path used by Atlaso; callers must not treat it as an unrestricted path.')]
    root_ca_path: Annotated[str, Field(description='Canonical filesystem or HTTP root ca path used by Atlaso; callers must not treat it as an unrestricted path.')]
    valid: Annotated[bool, Field(description='Whether the represented desired state passed Atlaso validation.')]
    validation_errors: Annotated[list[str], Field(description='Actionable validation failures that must be corrected before the state can be applied.')] = Field(default_factory=list)
    validation_warnings: Annotated[list[str], Field(description='Non-blocking validation warnings that the operator should review.')] = Field(default_factory=list)
    updated_at: Annotated[datetime, Field(description='UTC timestamp when the resource was last updated.')]


class LdapOrganizationCreate(BaseModel):
    """Fields accepted when creating a ldap organization resource.

    Attributes:
        name: Stable operator-facing name of this resource.
        slug: Requested slug value for this ldap organization resource.
        suffix_dn: Requested suffix dn value for this ldap organization resource.
        enabled: Whether the resource is enabled in saved Atlaso state.
    """

    name: Annotated[str, Field(description='Stable operator-facing name of this resource.')] = Field(min_length=1, max_length=128)
    slug: Annotated[str, Field(description='Requested slug value for this ldap organization resource.')] = Field(default="", max_length=80)
    suffix_dn: Annotated[str, Field(description='Requested suffix dn value for this ldap organization resource.')] = Field(default="", max_length=500)
    enabled: Annotated[bool, Field(description='Whether the resource is enabled in saved Atlaso state.')] = True


class LdapOrganizationResponse(BaseModel):
    """Fields returned by the Atlaso ldap organization API.

    Attributes:
        id: Unique database identifier assigned to this resource.
        name: Stable operator-facing name of this resource.
        slug: Returned slug value for this ldap organization resource.
        suffix_dn: Returned suffix dn value for this ldap organization resource.
        users_base_dn: Returned users base dn value for this ldap organization resource.
        groups_base_dn: Returned groups base dn value for this ldap organization resource.
        service_accounts_base_dn: Returned service accounts base dn value for this ldap organization
            resource.
        bind_dn: Returned bind dn value for this ldap organization resource.
        bind_secret_present: Whether bind secret is securely staged without exposing its value.
        enabled: Whether the resource is enabled in saved Atlaso state.
        user_count: Number of user records represented by this ldap organization response.
        group_count: Number of group records represented by this ldap organization response.
        vcf_target_url: Validated VCF target url used for this ldap organization integration.
        vcf_org_id: Stable identifier of the related VCF org resource.
        vcf_org_name: Returned VCF org name value for this ldap organization resource.
        vcf_tls_fingerprint: Returned VCF tls fingerprint value for this ldap organization resource.
        vcf_last_status: Returned VCF last status value for this ldap organization resource.
        vcf_last_message: Returned VCF last message value for this ldap organization resource.
        vcf_last_verified_at: UTC timestamp for VCF last verified at on this ldap organization
            resource.
        created_at: UTC timestamp when the resource was created.
        updated_at: UTC timestamp when the resource was last updated.
        raw_bind_password: One-time LDAP bind password returned only by the credential-rotation
            response.
    """

    id: Annotated[int, Field(description='Unique database identifier assigned to this resource.')]
    name: Annotated[str, Field(description='Stable operator-facing name of this resource.')]
    slug: Annotated[str, Field(description='Returned slug value for this ldap organization resource.')]
    suffix_dn: Annotated[str, Field(description='Returned suffix dn value for this ldap organization resource.')]
    users_base_dn: Annotated[str, Field(description='Returned users base dn value for this ldap organization resource.')]
    groups_base_dn: Annotated[str, Field(description='Returned groups base dn value for this ldap organization resource.')]
    service_accounts_base_dn: Annotated[str, Field(description='Returned service accounts base dn value for this ldap organization resource.')]
    bind_dn: Annotated[str, Field(description='Returned bind dn value for this ldap organization resource.')]
    bind_secret_present: Annotated[bool, Field(description='Whether bind secret is securely staged without exposing its value.')]
    enabled: Annotated[bool, Field(description='Whether the resource is enabled in saved Atlaso state.')]
    user_count: Annotated[int, Field(description='Number of user records represented by this ldap organization response.')]
    group_count: Annotated[int, Field(description='Number of group records represented by this ldap organization response.')]
    vcf_target_url: Annotated[str, Field(description='Validated VCF target url used for this ldap organization integration.')]
    vcf_org_id: Annotated[str, Field(description='Stable identifier of the related VCF org resource.')]
    vcf_org_name: Annotated[str, Field(description='Returned VCF org name value for this ldap organization resource.')]
    vcf_tls_fingerprint: Annotated[str, Field(description='Returned VCF tls fingerprint value for this ldap organization resource.')]
    vcf_last_status: Annotated[str, Field(description='Returned VCF last status value for this ldap organization resource.')]
    vcf_last_message: Annotated[str, Field(description='Returned VCF last message value for this ldap organization resource.')]
    vcf_last_verified_at: Annotated[str, Field(description='UTC timestamp for VCF last verified at on this ldap organization resource.')]
    created_at: Annotated[str, Field(description='UTC timestamp when the resource was created.')]
    updated_at: Annotated[str, Field(description='UTC timestamp when the resource was last updated.')]
    raw_bind_password: Annotated[str | None, Field(description='One-time LDAP bind password returned only by the credential-rotation response.')] = None


class LdapUserCreate(BaseModel):
    """Fields accepted when creating a ldap user resource.

    Attributes:
        uid: Requested uid value for this ldap user resource.
        given_name: Requested given name value for this ldap user resource.
        surname: Requested surname value for this ldap user resource.
        display_name: Requested display name value for this ldap user resource.
        email: Requested email value for this ldap user resource.
        telephone: Requested telephone value for this ldap user resource.
        enabled: Whether the resource is enabled in saved Atlaso state.
        password: Sensitive account password accepted only for this request; the plaintext value is
            never returned.
    """

    uid: Annotated[str, Field(description='Requested uid value for this ldap user resource.')] = Field(min_length=1, max_length=100)
    given_name: Annotated[str, Field(description='Requested given name value for this ldap user resource.')] = Field(default="", max_length=120)
    surname: Annotated[str, Field(description='Requested surname value for this ldap user resource.')] = Field(default="", max_length=120)
    display_name: Annotated[str, Field(description='Requested display name value for this ldap user resource.')] = Field(default="", max_length=180)
    email: Annotated[str, Field(description='Requested email value for this ldap user resource.')] = Field(default="", max_length=240)
    telephone: Annotated[str, Field(description='Requested telephone value for this ldap user resource.')] = Field(default="", max_length=80)
    enabled: Annotated[bool, Field(description='Whether the resource is enabled in saved Atlaso state.')] = True
    password: Annotated[str, Field(description='Sensitive account password accepted only for this request; the plaintext value is never returned.')] = Field(default="", max_length=512)


class LdapUserResponse(BaseModel):
    """Fields returned by the Atlaso ldap user API.

    Attributes:
        id: Unique database identifier assigned to this resource.
        organization_id: Stable identifier of the related organization resource.
        uid: Returned uid value for this ldap user resource.
        dn: Returned dn value for this ldap user resource.
        given_name: Returned given name value for this ldap user resource.
        surname: Returned surname value for this ldap user resource.
        display_name: Returned display name value for this ldap user resource.
        email: Returned email value for this ldap user resource.
        telephone: Returned telephone value for this ldap user resource.
        enabled: Whether the resource is enabled in saved Atlaso state.
        password_status: Returned password status value for this ldap user resource.
        password_applied_at: UTC timestamp for password applied at on this ldap user resource.
        unlock_requested: Whether unlock requested is enabled for this ldap user resource.
        created_at: UTC timestamp when the resource was created.
        updated_at: UTC timestamp when the resource was last updated.
    """

    id: Annotated[int, Field(description='Unique database identifier assigned to this resource.')]
    organization_id: Annotated[int, Field(description='Stable identifier of the related organization resource.')]
    uid: Annotated[str, Field(description='Returned uid value for this ldap user resource.')]
    dn: Annotated[str, Field(description='Returned dn value for this ldap user resource.')]
    given_name: Annotated[str, Field(description='Returned given name value for this ldap user resource.')]
    surname: Annotated[str, Field(description='Returned surname value for this ldap user resource.')]
    display_name: Annotated[str, Field(description='Returned display name value for this ldap user resource.')]
    email: Annotated[str, Field(description='Returned email value for this ldap user resource.')]
    telephone: Annotated[str, Field(description='Returned telephone value for this ldap user resource.')]
    enabled: Annotated[bool, Field(description='Whether the resource is enabled in saved Atlaso state.')]
    password_status: Annotated[str, Field(description='Returned password status value for this ldap user resource.')]
    password_applied_at: Annotated[str, Field(description='UTC timestamp for password applied at on this ldap user resource.')]
    unlock_requested: Annotated[bool, Field(description='Whether unlock requested is enabled for this ldap user resource.')]
    created_at: Annotated[str, Field(description='UTC timestamp when the resource was created.')]
    updated_at: Annotated[str, Field(description='UTC timestamp when the resource was last updated.')]


class LdapPasswordResetRequest(BaseModel):
    """Fields accepted when updating or operating on a ldap password reset resource.

    Attributes:
        password: Sensitive account password accepted only for this request; the plaintext value is
            never returned.
    """

    password: Annotated[str, Field(description='Sensitive account password accepted only for this request; the plaintext value is never returned.')] = Field(min_length=1, max_length=512)


class LdapGroupMember(BaseModel):
    """Validated fields used by the Atlaso ldap group member API contract.

    Attributes:
        type: Stable URI identifying the problem or resource type.
        id: Unique database identifier assigned to this resource.
    """

    type: Annotated[Literal["user", "group"], Field(description='Stable URI identifying the problem or resource type.')]
    id: Annotated[int, Field(description='Unique database identifier assigned to this resource.')]


class LdapGroupCreate(BaseModel):
    """Fields accepted when creating a ldap group resource.

    Attributes:
        name: Stable operator-facing name of this resource.
        description: Operator-facing purpose or context for this resource.
        enabled: Whether the resource is enabled in saved Atlaso state.
        members: Ordered collection of members values represented by this ldap group schema.
    """

    name: Annotated[str, Field(description='Stable operator-facing name of this resource.')] = Field(min_length=1, max_length=120)
    description: Annotated[str, Field(description='Operator-facing purpose or context for this resource.')] = ""
    enabled: Annotated[bool, Field(description='Whether the resource is enabled in saved Atlaso state.')] = True
    members: Annotated[list[LdapGroupMember], Field(description='Ordered collection of members values represented by this ldap group schema.')] = Field(default_factory=list)


class LdapGroupResponse(BaseModel):
    """Fields returned by the Atlaso ldap group API.

    Attributes:
        id: Unique database identifier assigned to this resource.
        organization_id: Stable identifier of the related organization resource.
        name: Stable operator-facing name of this resource.
        dn: Returned dn value for this ldap group resource.
        description: Operator-facing purpose or context for this resource.
        enabled: Whether the resource is enabled in saved Atlaso state.
        members: Ordered collection of members values represented by this ldap group schema.
        created_at: UTC timestamp when the resource was created.
        updated_at: UTC timestamp when the resource was last updated.
    """

    id: Annotated[int, Field(description='Unique database identifier assigned to this resource.')]
    organization_id: Annotated[int, Field(description='Stable identifier of the related organization resource.')]
    name: Annotated[str, Field(description='Stable operator-facing name of this resource.')]
    dn: Annotated[str, Field(description='Returned dn value for this ldap group resource.')]
    description: Annotated[str, Field(description='Operator-facing purpose or context for this resource.')]
    enabled: Annotated[bool, Field(description='Whether the resource is enabled in saved Atlaso state.')]
    members: Annotated[list[dict[str, Any]], Field(description='Ordered collection of members values represented by this ldap group schema.')] = Field(default_factory=list)
    created_at: Annotated[str, Field(description='UTC timestamp when the resource was created.')]
    updated_at: Annotated[str, Field(description='UTC timestamp when the resource was last updated.')]


class LdapBindCredentialResponse(BaseModel):
    """Fields returned by the Atlaso ldap bind credential API.

    Attributes:
        organization: Returned organization value for this ldap bind credential resource.
        raw_bind_password: One-time LDAP bind password returned only by the credential-rotation
            response.
    """

    organization: Annotated[LdapOrganizationResponse, Field(description='Returned organization value for this ldap bind credential resource.')]
    raw_bind_password: Annotated[str, Field(description='One-time LDAP bind password returned only by the credential-rotation response.')]


class LdapVcfInspectRequest(BaseModel):
    """Fields accepted when updating or operating on a ldap vcf inspect resource.

    Attributes:
        target_url: Validated target url used for this ldap vcf inspect integration.
        organization_id: Stable identifier of the related organization resource.
        organization_name: Requested organization name value for this ldap vcf inspect resource.
        username: Requested username value for this ldap vcf inspect resource.
        password: Sensitive account password accepted only for this request; the plaintext value is
            never returned.
        confirmed_tls_fingerprint: Requested confirmed tls fingerprint value for this ldap vcf
            inspect resource.
    """

    target_url: Annotated[str, Field(description='Validated target url used for this ldap vcf inspect integration.')] = Field(min_length=1, max_length=500)
    organization_id: Annotated[str, Field(description='Stable identifier of the related organization resource.')] = Field(min_length=1, max_length=240)
    organization_name: Annotated[str, Field(description='Requested organization name value for this ldap vcf inspect resource.')] = Field(default="", max_length=128)
    username: Annotated[str, Field(description='Requested username value for this ldap vcf inspect resource.')] = Field(min_length=1, max_length=240)
    password: Annotated[str, Field(description='Sensitive account password accepted only for this request; the plaintext value is never returned.')] = Field(min_length=1, max_length=512)
    confirmed_tls_fingerprint: Annotated[str, Field(description='Requested confirmed tls fingerprint value for this ldap vcf inspect resource.')] = Field(default="", max_length=160)


class LdapVcfConfigureRequest(LdapVcfInspectRequest):
    """Fields accepted when updating or operating on a ldap vcf configure resource.

    Attributes:
        replace_existing: Whether replace existing is enabled for this ldap vcf configure resource.
    """

    replace_existing: Annotated[bool, Field(description='Whether replace existing is enabled for this ldap vcf configure resource.')] = False


class LdapVcfInspectionResponse(BaseModel):
    """Fields returned by the Atlaso ldap vcf inspection API.

    Attributes:
        target_url: Validated target url used for this ldap vcf inspection integration.
        organization_id: Stable identifier of the related organization resource.
        organization_name: Returned organization name value for this ldap vcf inspection resource.
        tls_fingerprint: Returned tls fingerprint value for this ldap vcf inspection resource.
        current_settings: Structured current settings values represented by this ldap vcf inspection
            schema.
        proposed_settings: Structured proposed settings values represented by this ldap vcf
            inspection schema.
        changed: Whether changed is enabled for this ldap vcf inspection resource.
        test_result: Structured test result values represented by this ldap vcf inspection schema.
        user_count: Number of user records represented by this ldap vcf inspection response.
        group_count: Number of group records represented by this ldap vcf inspection response.
    """

    target_url: Annotated[str, Field(description='Validated target url used for this ldap vcf inspection integration.')]
    organization_id: Annotated[str, Field(description='Stable identifier of the related organization resource.')]
    organization_name: Annotated[str, Field(description='Returned organization name value for this ldap vcf inspection resource.')]
    tls_fingerprint: Annotated[str, Field(description='Returned tls fingerprint value for this ldap vcf inspection resource.')]
    current_settings: Annotated[dict[str, Any], Field(description='Structured current settings values represented by this ldap vcf inspection schema.')]
    proposed_settings: Annotated[dict[str, Any], Field(description='Structured proposed settings values represented by this ldap vcf inspection schema.')]
    changed: Annotated[bool, Field(description='Whether changed is enabled for this ldap vcf inspection resource.')]
    test_result: Annotated[dict[str, Any] | None, Field(description='Structured test result values represented by this ldap vcf inspection schema.')] = None
    user_count: Annotated[int | None, Field(description='Number of user records represented by this ldap vcf inspection response.')] = None
    group_count: Annotated[int | None, Field(description='Number of group records represented by this ldap vcf inspection response.')] = None


class LdapHealthResponse(BaseModel):
    """Fields returned by the Atlaso ldap health API.

    Attributes:
        enabled: Whether the resource is enabled in saved Atlaso state.
        running: Whether the backing runtime service is currently reported as running.
        health: Returned health value for this ldap health resource.
        ldaps_only: Whether LDAPs only is enabled for this ldap health resource.
        ldaps_enabled: Whether LDAPs enabled is enabled for this ldap health resource.
        ldaps_port: TCP or UDP LDAPs port in the valid 1 through 65535 range.
        ldap_enabled: Whether LDAP enabled is enabled for this ldap health resource.
        ldap_port: TCP or UDP LDAP port in the valid 1 through 65535 range.
        hostname: DNS hostname associated with the resource, normalized according to the endpoint
            contract.
        port: TCP or UDP port in the valid 1 through 65535 range.
        organization_count: Number of organization records represented by this ldap health response.
        user_count: Number of user records represented by this ldap health response.
        group_count: Number of group records represented by this ldap health response.
        validation_errors: Actionable validation failures that must be corrected before the state
            can be applied.
        validation_warnings: Non-blocking validation warnings that the operator should review.
    """

    enabled: Annotated[bool, Field(description='Whether the resource is enabled in saved Atlaso state.')]
    running: Annotated[bool, Field(description='Whether the backing runtime service is currently reported as running.')]
    health: Annotated[str, Field(description='Returned health value for this ldap health resource.')]
    ldaps_only: Annotated[bool, Field(description='Whether LDAPs only is enabled for this ldap health resource.')]
    ldaps_enabled: Annotated[bool, Field(description='Whether LDAPs enabled is enabled for this ldap health resource.')]
    ldaps_port: Annotated[int, Field(description='TCP or UDP LDAPs port in the valid 1 through 65535 range.')]
    ldap_enabled: Annotated[bool, Field(description='Whether LDAP enabled is enabled for this ldap health resource.')]
    ldap_port: Annotated[int, Field(description='TCP or UDP LDAP port in the valid 1 through 65535 range.')]
    hostname: Annotated[str, Field(description='DNS hostname associated with the resource, normalized according to the endpoint contract.')]
    port: Annotated[int, Field(description='TCP or UDP port in the valid 1 through 65535 range.')]
    organization_count: Annotated[int, Field(description='Number of organization records represented by this ldap health response.')]
    user_count: Annotated[int, Field(description='Number of user records represented by this ldap health response.')]
    group_count: Annotated[int, Field(description='Number of group records represented by this ldap health response.')]
    validation_errors: Annotated[list[str], Field(description='Actionable validation failures that must be corrected before the state can be applied.')] = Field(default_factory=list)
    validation_warnings: Annotated[list[str], Field(description='Non-blocking validation warnings that the operator should review.')] = Field(default_factory=list)


class LdapRecoveryExportRequest(BaseModel):
    """Fields accepted when updating or operating on a ldap recovery export resource.

    Attributes:
        passphrase: Sensitive passphrase used to encrypt or decrypt the recovery archive; Atlaso
            does not retain it.
    """

    passphrase: Annotated[str, Field(description='Sensitive passphrase used to encrypt or decrypt the recovery archive; Atlaso does not retain it.')] = Field(min_length=12, max_length=512)


class LdapRecoveryImportResponse(BaseModel):
    """Fields returned by the Atlaso ldap recovery import API.

    Attributes:
        id: Unique database identifier assigned to this resource.
        filename: Returned filename value for this ldap recovery import resource.
        sha256: Lowercase SHA-256 content-integrity digest of the referenced artifact.
        state: Returned state value for this ldap recovery import resource.
        organization_count: Number of organization records represented by this ldap recovery import
            response.
        created_at: UTC timestamp when the resource was created.
    """

    id: Annotated[int, Field(description='Unique database identifier assigned to this resource.')]
    filename: Annotated[str, Field(description='Returned filename value for this ldap recovery import resource.')]
    sha256: Annotated[str, Field(description='Lowercase SHA-256 content-integrity digest of the referenced artifact.')]
    state: Annotated[str, Field(description='Returned state value for this ldap recovery import resource.')]
    organization_count: Annotated[int, Field(description='Number of organization records represented by this ldap recovery import response.')]
    created_at: Annotated[datetime, Field(description='UTC timestamp when the resource was created.')]


class EsxiCustomVariableCreate(BaseModel):
    """Fields accepted when creating a esxi custom variable resource.

    Attributes:
        name: Stable operator-facing name of this resource.
        description: Operator-facing purpose or context for this resource.
        default_value: Requested default value value for this esxi custom variable resource.
    """

    name: Annotated[str, Field(description='Stable operator-facing name of this resource.')] = Field(min_length=1, max_length=80)
    description: Annotated[str, Field(description='Operator-facing purpose or context for this resource.')] = Field(default="", max_length=500)
    default_value: Annotated[str, Field(description='Requested default value value for this esxi custom variable resource.')] = Field(default="", max_length=2048)


class EsxiCustomVariableUpdate(EsxiCustomVariableCreate):
    """Fields accepted when updating or operating on a esxi custom variable resource."""

    pass


class EsxiCustomVariableResponse(EsxiCustomVariableCreate):
    """Fields returned by the Atlaso esxi custom variable API.

    Attributes:
        id: Unique database identifier assigned to this resource.
    """

    id: Annotated[str, Field(description='Unique database identifier assigned to this resource.')]


class EsxiKickstartCreate(BaseModel):
    """Fields accepted when creating a esxi kickstart resource.

    Attributes:
        name: Stable operator-facing name of this resource.
        description: Operator-facing purpose or context for this resource.
        content: Configuration or document content governed by the validation and redaction rules
            for this resource.
        enabled: Whether the resource is enabled in saved Atlaso state.
    """

    name: Annotated[str, Field(description='Stable operator-facing name of this resource.')] = Field(min_length=1, max_length=120)
    description: Annotated[str | None, Field(description='Operator-facing purpose or context for this resource.')] = None
    content: Annotated[str, Field(description='Configuration or document content governed by the validation and redaction rules for this resource.')] = Field(min_length=1)
    enabled: Annotated[bool, Field(description='Whether the resource is enabled in saved Atlaso state.')] = True


class EsxiKickstartUpdate(EsxiKickstartCreate):
    """Fields accepted when updating or operating on a esxi kickstart resource."""

    pass


class EsxiKickstartResponse(BaseModel):
    """Fields returned by the Atlaso esxi kickstart API.

    Attributes:
        id: Unique database identifier assigned to this resource.
        name: Stable operator-facing name of this resource.
        description: Operator-facing purpose or context for this resource.
        content_hash: SHA-256 content-integrity digest of the non-secret stored content.
        rendered_hash: Returned rendered hash value for this esxi kickstart resource.
        http_path: Canonical filesystem or HTTP http path used by Atlaso; callers must not treat it
            as an unrestricted path.
        enabled: Whether the resource is enabled in saved Atlaso state.
        created_at: UTC timestamp when the resource was created.
        updated_at: UTC timestamp when the resource was last updated.
        last_rendered_at: UTC timestamp for last rendered at on this esxi kickstart resource.
        last_applied_at: UTC timestamp for last applied at on this esxi kickstart resource.
        redacted_preview: Preview text with credentials and other secret-bearing values removed.
        drift_state: Returned drift state value for this esxi kickstart resource.
        content: Configuration or document content governed by the validation and redaction rules
            for this resource.
    """

    id: Annotated[int, Field(description='Unique database identifier assigned to this resource.')]
    name: Annotated[str, Field(description='Stable operator-facing name of this resource.')]
    description: Annotated[str, Field(description='Operator-facing purpose or context for this resource.')]
    content_hash: Annotated[str, Field(description='SHA-256 content-integrity digest of the non-secret stored content.')]
    rendered_hash: Annotated[str, Field(description='Returned rendered hash value for this esxi kickstart resource.')]
    http_path: Annotated[str, Field(description='Canonical filesystem or HTTP http path used by Atlaso; callers must not treat it as an unrestricted path.')]
    enabled: Annotated[bool, Field(description='Whether the resource is enabled in saved Atlaso state.')]
    created_at: Annotated[datetime, Field(description='UTC timestamp when the resource was created.')]
    updated_at: Annotated[datetime, Field(description='UTC timestamp when the resource was last updated.')]
    last_rendered_at: Annotated[datetime | None, Field(description='UTC timestamp for last rendered at on this esxi kickstart resource.')]
    last_applied_at: Annotated[datetime | None, Field(description='UTC timestamp for last applied at on this esxi kickstart resource.')]
    redacted_preview: Annotated[str, Field(description='Preview text with credentials and other secret-bearing values removed.')]
    drift_state: Annotated[str, Field(description='Returned drift state value for this esxi kickstart resource.')]
    content: Annotated[str | None, Field(description='Configuration or document content governed by the validation and redaction rules for this resource.')] = None


class EsxiKickstartValidationResponse(BaseModel):
    """Fields returned by the Atlaso esxi kickstart validation API.

    Attributes:
        valid: Whether the represented desired state passed Atlaso validation.
        errors: Actionable errors produced while validating or processing the request.
        warnings: Non-blocking warnings produced while validating or processing the request.
        redacted_preview: Preview text with credentials and other secret-bearing values removed.
    """

    valid: Annotated[bool, Field(description='Whether the represented desired state passed Atlaso validation.')]
    errors: Annotated[list[str], Field(description='Actionable errors produced while validating or processing the request.')] = Field(default_factory=list)
    warnings: Annotated[list[str], Field(description='Non-blocking warnings produced while validating or processing the request.')] = Field(default_factory=list)
    redacted_preview: Annotated[str, Field(description='Preview text with credentials and other secret-bearing values removed.')]


class EsxiKickstartPreviewResponse(BaseModel):
    """Fields returned by the Atlaso esxi kickstart preview API.

    Attributes:
        id: Unique database identifier assigned to this resource.
        redacted_preview: Preview text with credentials and other secret-bearing values removed.
        content_hash: SHA-256 content-integrity digest of the non-secret stored content.
        drift_state: Returned drift state value for this esxi kickstart preview resource.
    """

    id: Annotated[int, Field(description='Unique database identifier assigned to this resource.')]
    redacted_preview: Annotated[str, Field(description='Preview text with credentials and other secret-bearing values removed.')]
    content_hash: Annotated[str, Field(description='SHA-256 content-integrity digest of the non-secret stored content.')]
    drift_state: Annotated[str, Field(description='Returned drift state value for this esxi kickstart preview resource.')]


class EsxiKickstartDuplicateRequest(BaseModel):
    """Fields accepted when updating or operating on a esxi kickstart duplicate resource.

    Attributes:
        name: Stable operator-facing name of this resource.
    """

    name: Annotated[str | None, Field(description='Stable operator-facing name of this resource.')] = Field(default=None, max_length=120)


class EsxiPxeHostCreate(BaseModel):
    """Fields accepted when creating a esxi pxe host resource.

    Attributes:
        hostname: DNS hostname associated with the resource, normalized according to the endpoint
            contract.
        mac_address: Normalized hardware MAC address used to identify the network interface or host.
        ip_address: IPv4 or IPv6 address associated with the resource.
        kickstart_id: Stable identifier of the related kickstart resource.
        installer_iso_path: Canonical filesystem or HTTP installer iso path used by Atlaso; callers
            must not treat it as an unrestricted path.
        variables: Structured variables values represented by this esxi pxe host schema.
        enabled: Whether the resource is enabled in saved Atlaso state.
    """

    hostname: Annotated[str, Field(description='DNS hostname associated with the resource, normalized according to the endpoint contract.')] = Field(min_length=1, max_length=120)
    mac_address: Annotated[str, Field(description='Normalized hardware MAC address used to identify the network interface or host.')] = Field(min_length=1, max_length=32)
    ip_address: Annotated[str, Field(description='IPv4 or IPv6 address associated with the resource.')] = Field(default="", max_length=64)
    kickstart_id: Annotated[int | None, Field(description='Stable identifier of the related kickstart resource.')] = None
    installer_iso_path: Annotated[str, Field(description='Canonical filesystem or HTTP installer iso path used by Atlaso; callers must not treat it as an unrestricted path.')] = ""
    variables: Annotated[dict[str, str], Field(description='Structured variables values represented by this esxi pxe host schema.')] = Field(default_factory=dict)
    enabled: Annotated[bool, Field(description='Whether the resource is enabled in saved Atlaso state.')] = True


class EsxiPxeHostResponse(EsxiPxeHostCreate):
    """Fields returned by the Atlaso esxi pxe host API.

    Attributes:
        id: Unique database identifier assigned to this resource.
        kickstart_name: Returned kickstart name value for this esxi pxe host resource.
        installer_iso_name: Returned installer iso name value for this esxi pxe host resource.
        created_at: UTC timestamp when the resource was created.
        updated_at: UTC timestamp when the resource was last updated.
    """

    id: Annotated[int, Field(description='Unique database identifier assigned to this resource.')]
    kickstart_name: Annotated[str, Field(description='Returned kickstart name value for this esxi pxe host resource.')] = ""
    installer_iso_name: Annotated[str, Field(description='Returned installer iso name value for this esxi pxe host resource.')] = ""
    created_at: Annotated[datetime, Field(description='UTC timestamp when the resource was created.')]
    updated_at: Annotated[datetime, Field(description='UTC timestamp when the resource was last updated.')]


class EsxiPxeHostDeleteResponse(BaseModel):
    """Lifecycle counts returned after deleting an ESXi Host Reference.

    Attributes:
        deleted: Whether the Host Reference was deleted.
        discovered_hosts_removed: Number of associated discovered-host rows removed.
        reports: Number of retained inventory reports removed.
        sessions: Number of retained inventory sessions removed.
        commands: Number of retained inventory commands removed.
    """

    deleted: Annotated[bool, Field(description='Whether the ESXi Host Reference was deleted.')]
    discovered_hosts_removed: Annotated[int, Field(description='Number of associated discovered-host rows removed.')]
    reports: Annotated[int, Field(description='Number of retained inventory reports removed.')]
    sessions: Annotated[int, Field(description='Number of retained inventory sessions removed.')]
    commands: Annotated[int, Field(description='Number of retained inventory commands removed.')]


class EsxiBootAuthorizationRequest(BaseModel):
    """Console code identifying the exact pending ESXi boot attempt."""

    boot_code: Annotated[
        str,
        Field(
            min_length=9,
            max_length=9,
            pattern=r"^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$",
            description="One-time code displayed on the intended host console.",
        ),
    ]


class EsxiBootAuthorizationResponse(BaseModel):
    """Secret-free receipt for a one-time applied ESXi boot authorization."""

    host_id: Annotated[int, Field(description="Applied ESXi Host Reference authorized for the next boot attempt.")]
    requested_at: Annotated[datetime, Field(description="UTC timestamp when the authorization was issued.")]
    expires_at: Annotated[datetime, Field(description="UTC timestamp after which the authorization cannot be used.")]
    message: Annotated[str, Field(description="Secret-free operator guidance for the authorized boot attempt.")]


class EsxiInstallerIsoResponse(BaseModel):
    """Fields returned by the Atlaso esxi installer iso API.

    Attributes:
        name: Stable operator-facing name of this resource.
        path: Canonical filesystem or HTTP path used by Atlaso; callers must not treat it as an
            unrestricted path.
        relative_path: Canonical filesystem or HTTP relative path used by Atlaso; callers must not
            treat it as an unrestricted path.
        esx_version: Returned esx version value for this esxi installer iso resource.
        esx_build: Returned esx build value for this esxi installer iso resource.
        size_bytes: Size bytes, measured in bytes.
        updated_at: UTC timestamp when the resource was last updated.
    """

    name: Annotated[str, Field(description='Stable operator-facing name of this resource.')]
    path: Annotated[str, Field(description='Canonical filesystem or HTTP path used by Atlaso; callers must not treat it as an unrestricted path.')]
    relative_path: Annotated[str, Field(description='Canonical filesystem or HTTP relative path used by Atlaso; callers must not treat it as an unrestricted path.')]
    esx_version: Annotated[str, Field(description='Returned esx version value for this esxi installer iso resource.')] = ""
    esx_build: Annotated[str, Field(description='Returned esx build value for this esxi installer iso resource.')] = ""
    size_bytes: Annotated[int, Field(description='Size bytes, measured in bytes.')]
    updated_at: Annotated[str, Field(description='UTC timestamp when the resource was last updated.')]


NetworkRole = Literal["management", "access", "route", "unused"]


class PhysicalInterfaceUpdate(BaseModel):
    """Fields accepted when updating physical-interface desired state.

    Omitted properties retain their current values. CIDR and gateway properties accept an empty
    string or null to clear the saved value. Saving desired state does not mutate the host; the
    global Appliance Apply workflow remains the enforcement boundary.
    """

    model_config = ConfigDict(extra="forbid")

    role: Annotated[
        NetworkRole,
        Field(
            default=None,
            description=(
                "Canonical desired interface purpose: management, access, route, or unused. "
                "Omit to retain the current role."
            ),
        ),
    ]

    @field_validator("role", "mode", "ipv4_method", mode="before")
    @classmethod
    def normalize_legacy_enum_spellings(cls, value: Any, info: ValidationInfo) -> Any:
        """Normalize recognized case-insensitive enum spellings.

        Args:
            value: Incoming field value to normalize when it is a recognized string.
            info: Pydantic validation metadata identifying the current field.
        """
        if not isinstance(value, str):
            return value
        normalized = value.strip().lower()
        if info.field_name == "role" and normalized in {
            "management",
            "access",
            "route",
            "unused",
        }:
            return normalized
        if info.field_name == "mode":
            if normalized == "routed":
                return "access"
            if normalized in {"access", "trunk", "unused"}:
                return normalized
        if info.field_name == "ipv4_method" and normalized in {"static", "dhcp"}:
            return normalized
        return value
    mode: Annotated[
        Literal["access", "trunk", "unused"] | None,
        Field(
            description=(
                "Desired link type. Trunk interfaces host VLAN children and cannot bind services "
                "directly. Omit to retain the current link type."
            )
        ),
    ] = None
    ipv4_method: Annotated[
        Literal["static", "dhcp"] | None,
        Field(
            description=(
                "Desired IPv4 address source. DHCP is supported only by the management interface; "
                "omit to retain the current method."
            )
        ),
    ] = None
    ip_cidr: Annotated[
        str | None,
        Field(
            description=(
                "Desired static IPv4 host address and prefix in CIDR notation, such as "
                "192.168.50.10/24. Empty or null clears the value. When it changes, dependent "
                "listener, DHCP, and Network Boot addresses are reconciled in the same transaction."
            )
        ),
    ] = None
    gateway: Annotated[
        str | None,
        Field(
            description=(
                "Optional on-link IPv4 default gateway for a static management interface. Empty or "
                "null clears the value."
            )
        ),
    ] = None
    ipv6_enabled: Annotated[
        StrictBool | None,
        Field(
            description=(
                "Whether IPv6 desired state is enabled. Disabling IPv6 requires the IPv6 CIDR and "
                "gateway to be cleared; omit to retain the current state."
            )
        ),
    ] = None
    ipv6_cidr: Annotated[
        str | None,
        Field(
            description=(
                "Desired IPv6 host address and prefix in CIDR notation, such as "
                "2001:db8:50::10/64. Empty or null clears the value. Dependent IPv6 listener, DHCP, "
                "and Network Boot addresses follow changes atomically."
            )
        ),
    ] = None
    ipv6_gateway: Annotated[
        str | None,
        Field(
            description=(
                "Optional link-local or on-link IPv6 default gateway for an enabled management "
                "interface. Empty or null clears the value."
            )
        ),
    ] = None
    mtu: Annotated[
        StrictInt | None,
        Field(
            ge=576,
            le=9000,
            description="Desired interface MTU in bytes, from 576 through 9000; omit to retain it.",
        ),
    ] = None
    admin_state: Annotated[
        Literal["up", "down"] | None,
        Field(
            description=(
                "Desired administrative state. The management interface must remain up; omit to "
                "retain the current state."
            )
        ),
    ] = None
    access_management_ui_enabled: Annotated[
        StrictBool | None,
        Field(
            description=(
                "Whether an access-role, access-mode interface also exposes the authenticated "
                "management UI. Management-role exposure is inherent. Omit to retain the current "
                "setting, except a management-to-access conversion enables it to preserve access."
            )
        ),
    ] = None

    @model_validator(mode="after")
    def reject_explicit_null_for_non_nullable_fields(self) -> "PhysicalInterfaceUpdate":
        """Reject null where omission, rather than clearing, is the supported PATCH meaning."""
        non_nullable = {
            "role",
            "mode",
            "ipv4_method",
            "ipv6_enabled",
            "mtu",
            "admin_state",
            "access_management_ui_enabled",
        }
        explicit_nulls = sorted(
            field_name
            for field_name in self.model_fields_set & non_nullable
            if getattr(self, field_name) is None
        )
        if explicit_nulls:
            raise ValueError(
                f"{', '.join(explicit_nulls)} must be omitted instead of set to null."
            )
        return self


class PhysicalInterfaceResponse(BaseModel):
    """Fields returned by the Atlaso physical interface API.

    Attributes:
        id: Unique database identifier assigned to this resource.
        name: Stable operator-facing name of this resource.
        mac_address: Normalized hardware MAC address used to identify the network interface or host.
        driver: Returned driver value for this physical interface resource.
        speed: Returned speed value for this physical interface resource.
        host_ip_cidr: Validated network or address value for host ip cidr in this physical interface
            resource.
        host_ipv6_cidr: Validated network or address value for host ipv6 cidr in this physical
            interface resource.
        host_mtu: Returned host mtu value for this physical interface resource.
        host_admin_state: Returned host admin state value for this physical interface resource.
        ip_cidr: Validated network or address value for ip cidr in this physical interface resource.
        gateway: Returned gateway value for this physical interface resource.
        ipv4_method: Returned ipv4 method value for this physical interface resource.
        ipv6_enabled: Whether ipv6 enabled is enabled for this physical interface resource.
        ipv6_cidr: Validated network or address value for ipv6 cidr in this physical interface
            resource.
        ipv6_gateway: Returned ipv6 gateway value for this physical interface resource.
        mtu: Returned mtu value for this physical interface resource.
        admin_state: Returned admin state value for this physical interface resource.
        oper_state: Returned oper state value for this physical interface resource.
        role: Canonical purpose assigned to this physical interface.
        mode: Returned mode value for this physical interface resource.
        access_management_ui_enabled: Whether this access interface also exposes the management UI.
        inventory_source: Returned inventory source value for this physical interface resource.
        desired_state_source: Returned desired state source value for this physical interface
            resource.
        last_seen_at: UTC timestamp for last seen at on this physical interface resource.
        missing_since: Returned missing since value for this physical interface resource.
    """

    model_config = ConfigDict(from_attributes=True)

    id: Annotated[int, Field(description='Unique database identifier assigned to this resource.')]
    name: Annotated[str, Field(description='Stable operator-facing name of this resource.')]
    mac_address: Annotated[str, Field(description='Normalized hardware MAC address used to identify the network interface or host.')]
    driver: Annotated[str | None, Field(description='Returned driver value for this physical interface resource.')]
    speed: Annotated[str | None, Field(description='Returned speed value for this physical interface resource.')]
    host_ip_cidr: Annotated[str | None, Field(description='Validated network or address value for host ip cidr in this physical interface resource.')]
    host_ipv6_cidr: Annotated[str | None, Field(description='Validated network or address value for host ipv6 cidr in this physical interface resource.')]
    host_mtu: Annotated[int | None, Field(description='Returned host mtu value for this physical interface resource.')]
    host_admin_state: Annotated[str | None, Field(description='Returned host admin state value for this physical interface resource.')]
    ip_cidr: Annotated[str | None, Field(description='Validated network or address value for ip cidr in this physical interface resource.')]
    gateway: Annotated[str | None, Field(description='Returned gateway value for this physical interface resource.')]
    ipv4_method: Annotated[str, Field(description='Returned ipv4 method value for this physical interface resource.')] = "static"
    ipv6_enabled: Annotated[bool, Field(description='Whether ipv6 enabled is enabled for this physical interface resource.')] = False
    ipv6_cidr: Annotated[str | None, Field(description='Validated network or address value for ipv6 cidr in this physical interface resource.')]
    ipv6_gateway: Annotated[str | None, Field(description='Returned ipv6 gateway value for this physical interface resource.')]
    mtu: Annotated[int, Field(description='Returned mtu value for this physical interface resource.')]
    admin_state: Annotated[str, Field(description='Returned admin state value for this physical interface resource.')]
    oper_state: Annotated[str, Field(description='Returned oper state value for this physical interface resource.')]
    role: Annotated[NetworkRole, Field(description='Canonical interface purpose: management, access, route, or unused.')]
    mode: Annotated[str, Field(description='Returned mode value for this physical interface resource.')]
    access_management_ui_enabled: Annotated[bool, Field(description='Whether this access-role physical interface also exposes the management UI. Management-role interfaces expose it inherently.')] = False
    inventory_source: Annotated[str, Field(description='Returned inventory source value for this physical interface resource.')]
    desired_state_source: Annotated[str, Field(description='Returned desired state source value for this physical interface resource.')]
    last_seen_at: Annotated[datetime | None, Field(description='UTC timestamp for last seen at on this physical interface resource.')]
    missing_since: Annotated[datetime | None, Field(description='Returned missing since value for this physical interface resource.')]


class VlanCreate(BaseModel):
    """Fields accepted when creating a vlan resource.

    Attributes:
        parent_interface: Requested parent interface value for this vlan resource.
        vlan_id: Stable identifier of the related vlan resource.
        ip_cidr: Validated network or address value for ip cidr in this vlan resource.
        ipv6_cidr: Validated network or address value for ipv6 cidr in this vlan resource.
        mtu: Requested mtu value for this vlan resource.
        role: Canonical purpose assigned to this VLAN interface.
        enabled: Whether the resource is enabled in saved Atlaso state.
        access_management_ui_enabled: Whether this enabled access VLAN also exposes the management UI.
    """

    parent_interface: Annotated[str, Field(description='Requested parent interface value for this vlan resource.')]
    vlan_id: Annotated[int, Field(description='Stable identifier of the related vlan resource.')] = Field(ge=1, le=4094)
    ip_cidr: Annotated[str, Field(description='Validated network or address value for ip cidr in this vlan resource.')] = ""
    ipv6_cidr: Annotated[str, Field(description='Validated network or address value for ipv6 cidr in this vlan resource.')] = ""
    mtu: Annotated[int, Field(description='Requested mtu value for this vlan resource.')] = Field(default=1500, ge=576, le=9000)
    role: Annotated[NetworkRole, Field(description='Canonical VLAN purpose: management, access, route, or unused.')] = "access"
    enabled: Annotated[bool, Field(description='Whether the resource is enabled in saved Atlaso state.')] = True
    access_management_ui_enabled: Annotated[bool, Field(description='Whether this enabled access-role VLAN also exposes the management UI.')] = False

    @field_validator("role", mode="before")
    @classmethod
    def normalize_canonical_role(cls, value: Any) -> Any:
        """Normalize case-insensitive canonical VLAN role spellings.

        Args:
            value: Incoming VLAN role value to normalize when it is a recognized string.
        """
        if not isinstance(value, str):
            return value
        normalized = value.strip().lower()
        if normalized in {"management", "access", "route", "unused"}:
            return normalized
        return value


class VlanResponse(VlanCreate):
    """Fields returned by the Atlaso vlan API.

    Attributes:
        id: Unique database identifier assigned to this resource.
        name: Stable operator-facing name of this resource.
    """

    model_config = ConfigDict(from_attributes=True)

    id: Annotated[int, Field(description='Unique database identifier assigned to this resource.')]
    name: Annotated[str, Field(description='Stable operator-facing name of this resource.')]


class WanPolicyCreate(BaseModel):
    """Fields accepted when creating a wan policy resource.

    Attributes:
        name: Stable operator-facing name of this resource.
        description: Operator-facing purpose or context for this resource.
        enabled: Whether the resource is enabled in saved Atlaso state.
        latency_ms: Latency ms, measured in milliseconds, for this wan policy resource.
        jitter_ms: Jitter ms, measured in milliseconds, for this wan policy resource.
        packet_loss_percent: Packet loss percent, expressed as a percentage from 0 through 100.
        bandwidth_mbit: Bandwidth mbit, measured in megabits per second.
        corrupt_percent: Corrupt percent, expressed as a percentage from 0 through 100.
        duplicate_percent: Duplicate percent, expressed as a percentage from 0 through 100.
        reorder_percent: Reorder percent, expressed as a percentage from 0 through 100.
    """

    name: Annotated[str, Field(description='Stable operator-facing name of this resource.')] = Field(min_length=1, max_length=120)
    description: Annotated[str | None, Field(description='Operator-facing purpose or context for this resource.')] = None
    enabled: Annotated[bool, Field(description='Whether the resource is enabled in saved Atlaso state.')] = True
    latency_ms: Annotated[int, Field(description='Latency ms, measured in milliseconds, for this wan policy resource.')] = Field(default=0, ge=0)
    jitter_ms: Annotated[int, Field(description='Jitter ms, measured in milliseconds, for this wan policy resource.')] = Field(default=0, ge=0)
    packet_loss_percent: Annotated[float, Field(description='Packet loss percent, expressed as a percentage from 0 through 100.')] = Field(default=0.0, ge=0, le=100)
    bandwidth_mbit: Annotated[int | None, Field(description='Bandwidth mbit, measured in megabits per second.')] = Field(default=None, ge=1)
    corrupt_percent: Annotated[float | None, Field(description='Corrupt percent, expressed as a percentage from 0 through 100.')] = Field(default=0.0, ge=0, le=100)
    duplicate_percent: Annotated[float | None, Field(description='Duplicate percent, expressed as a percentage from 0 through 100.')] = Field(default=0.0, ge=0, le=100)
    reorder_percent: Annotated[float | None, Field(description='Reorder percent, expressed as a percentage from 0 through 100.')] = Field(default=0.0, ge=0, le=100)


class WanPolicyResponse(WanPolicyCreate):
    """Fields returned by the Atlaso wan policy API.

    Attributes:
        id: Unique database identifier assigned to this resource.
    """

    model_config = ConfigDict(from_attributes=True)

    id: Annotated[int, Field(description='Unique database identifier assigned to this resource.')]


class RouteCreate(BaseModel):
    """Fields accepted when creating a route resource.

    Attributes:
        destination_cidr: Destination network CIDR. Canonical IPv4 and IPv6 /0 CIDRs represent
            default routes and remain accepted for API compatibility.
        gateway: Optional next-hop for directly connected destinations and required for a default
            route; it must use the destination's IP family and be on-link for the selected target,
            except that an IPv6 link-local next hop is supported.
        interface_name: Requested interface name value for this route resource.
        metric: Requested metric value for this route resource.
        enabled: Whether the resource is enabled in saved Atlaso state.
        wan_policy_id: Stable identifier of the related wan policy resource.
        wan_mode: Requested wan mode value for this route resource.
    """

    destination_cidr: Annotated[str, Field(description='Destination network CIDR; 0.0.0.0/0 and ::/0 represent IPv4 and IPv6 default routes.')]
    gateway: Annotated[str | None, Field(description='Optional same-family next-hop for an ordinary destination and required for a default route; it must be on-link for the selected target, except that an IPv6 link-local next hop is supported.')] = None
    interface_name: Annotated[str, Field(description='Requested interface name value for this route resource.')]
    metric: Annotated[int, Field(description='Requested metric value for this route resource.')] = Field(default=100, ge=0)
    enabled: Annotated[bool, Field(description='Whether the resource is enabled in saved Atlaso state.')] = True
    wan_policy_id: Annotated[int | None, Field(description='Stable identifier of the related wan policy resource.')] = None
    wan_mode: Annotated[Literal["interface"], Field(description='Requested wan mode value for this route resource.')] = "interface"


class RouteResponse(RouteCreate):
    """Fields returned by the Atlaso route API.

    Attributes:
        id: Unique database identifier assigned to this resource.
        wan_policy: Returned wan policy value for this route resource.
    """

    model_config = ConfigDict(from_attributes=True)

    id: Annotated[int, Field(description='Unique database identifier assigned to this resource.')]
    wan_policy: Annotated[WanPolicyResponse | None, Field(description='Returned wan policy value for this route resource.')] = None


class NatRuleCreate(BaseModel):
    """Fields accepted when creating a nat rule resource.

    Attributes:
        name: Stable operator-facing name of this resource.
        enabled: Whether the resource is enabled in saved Atlaso state.
        source: Validated network or address value for source in this nat rule resource.
        outbound_interface: Requested outbound interface value for this nat rule resource.
        masquerade: Whether masquerade is enabled for this nat rule resource.
        priority: Requested priority value for this nat rule resource.
        description: Operator-facing purpose or context for this resource.
    """

    name: Annotated[str, Field(description='Stable operator-facing name of this resource.')] = Field(min_length=1, max_length=120)
    enabled: Annotated[bool, Field(description='Whether the resource is enabled in saved Atlaso state.')] = True
    source: Annotated[str, Field(description='Validated network or address value for source in this nat rule resource.')] = Field(default="any", min_length=1, max_length=240)
    outbound_interface: Annotated[str, Field(description='Requested outbound interface value for this nat rule resource.')] = Field(min_length=1, max_length=80)
    masquerade: Annotated[bool, Field(description='Whether masquerade is enabled for this nat rule resource.')] = True
    priority: Annotated[int, Field(description='Requested priority value for this nat rule resource.')] = Field(default=100, ge=0)
    description: Annotated[str | None, Field(description='Operator-facing purpose or context for this resource.')] = None


class NatRuleResponse(NatRuleCreate):
    """Fields returned by the Atlaso nat rule API.

    Attributes:
        id: Unique database identifier assigned to this resource.
    """

    model_config = ConfigDict(from_attributes=True)

    id: Annotated[int, Field(description='Unique database identifier assigned to this resource.')]


class WanStatusResponse(BaseModel):
    """Fields returned by the Atlaso wan status API.

    Attributes:
        active_policy_count: Number of active policy records represented by this wan status
            response.
        managed_interfaces: Ordered collection of managed interfaces values represented by this wan
            status schema.
        dry_run: Whether the operation reports command intent without mutating appliance host state.
    """

    active_policy_count: Annotated[int, Field(description='Number of active policy records represented by this wan status response.')]
    managed_interfaces: Annotated[list[str], Field(description='Ordered collection of managed interfaces values represented by this wan status schema.')]
    dry_run: Annotated[bool, Field(description='Whether the operation reports command intent without mutating appliance host state.')]


class DnsConditionalForwarder(BaseModel):
    """Validated fields used by the Atlaso dns conditional forwarder API contract.

    Attributes:
        domain: Returned domain value for this dns conditional forwarder resource.
        server: Validated server used for this dns conditional forwarder integration.
    """

    domain: Annotated[str, Field(description='Returned domain value for this dns conditional forwarder resource.')] = Field(min_length=1, max_length=120)
    server: Annotated[str, Field(description='Validated server used for this dns conditional forwarder integration.')] = Field(min_length=1, max_length=120)


class DnsSettingsUpdate(BaseModel):
    """Fields accepted when updating or operating on a dns settings resource.

    Attributes:
        enabled: Whether the resource is enabled in saved Atlaso state.
        listen_interface: Saved access interface or enabled VLAN used as the service bind target.
        listen_address: Derived IP address on which the service listens; operators select an
            interface rather than entering this value directly.
        domain: Requested domain value for this dns settings resource.
        upstream_servers: Ordered collection of upstream servers values represented by this dns
            settings schema.
        conditional_forwarders: Ordered collection of conditional forwarders values represented by
            this dns settings schema.
        cache_size: Requested cache size value for this dns settings resource.
        expand_hosts: Whether expand hosts is enabled for this dns settings resource.
        authoritative: Whether authoritative is enabled for this dns settings resource.
        authoritative_server: Requested authoritative server value for this dns settings resource.
        authoritative_contact: Requested authoritative contact value for this dns settings resource.
        authoritative_ttl: Requested authoritative ttl value for this dns settings resource.
        authoritative_refresh: Requested authoritative refresh value for this dns settings resource.
        authoritative_retry: Requested authoritative retry value for this dns settings resource.
        authoritative_expire: Requested authoritative expire value for this dns settings resource.
        dnssec_enabled: Whether dnssec enabled is enabled for this dns settings resource.
        rebind_protection_enabled: Whether rebind protection enabled is enabled for this dns
            settings resource.
        rebind_domain_exemptions: Whether rebind domain exemptions is enabled for this dns settings
            resource.
        query_logging_mode: Requested query logging mode value for this dns settings resource.
    """

    enabled: Annotated[bool, Field(description='Whether the resource is enabled in saved Atlaso state.')] = False
    listen_interface: Annotated[str, Field(description='Saved access interface or enabled VLAN used as the service bind target.')] = Field(default="eth2", min_length=1, max_length=80)
    listen_address: Annotated[str | None, Field(description='Derived IP address on which the service listens; operators select an interface rather than entering this value directly.')] = Field(default=None, max_length=240)
    domain: Annotated[str, Field(description='Requested domain value for this dns settings resource.')] = Field(default="atlaso.internal", min_length=1, max_length=500)
    upstream_servers: Annotated[list[str], Field(description='Ordered collection of upstream servers values represented by this dns settings schema.')] = Field(default_factory=lambda: ["1.1.1.1", "9.9.9.9"])
    conditional_forwarders: Annotated[list[DnsConditionalForwarder], Field(description='Ordered collection of conditional forwarders values represented by this dns settings schema.')] = Field(default_factory=list)
    cache_size: Annotated[int, Field(description='Requested cache size value for this dns settings resource.')] = Field(default=1000, ge=0, le=100000)
    expand_hosts: Annotated[bool, Field(description='Whether expand hosts is enabled for this dns settings resource.')] = True
    authoritative: Annotated[bool, Field(description='Whether authoritative is enabled for this dns settings resource.')] = True
    authoritative_server: Annotated[str, Field(description='Requested authoritative server value for this dns settings resource.')] = Field(default="ns1.atlaso.internal", min_length=1, max_length=253)
    authoritative_contact: Annotated[str, Field(description='Requested authoritative contact value for this dns settings resource.')] = Field(default="hostmaster.atlaso.internal", min_length=1, max_length=253)
    authoritative_ttl: Annotated[int, Field(description='Requested authoritative ttl value for this dns settings resource.')] = Field(default=3600, ge=1, le=2147483647)
    authoritative_refresh: Annotated[int, Field(description='Requested authoritative refresh value for this dns settings resource.')] = Field(default=1200, ge=1, le=2147483647)
    authoritative_retry: Annotated[int, Field(description='Requested authoritative retry value for this dns settings resource.')] = Field(default=180, ge=1, le=2147483647)
    authoritative_expire: Annotated[int, Field(description='Requested authoritative expire value for this dns settings resource.')] = Field(default=1209600, ge=1, le=2147483647)
    dnssec_enabled: Annotated[bool, Field(description='Whether dnssec enabled is enabled for this dns settings resource.')] = False
    rebind_protection_enabled: Annotated[bool, Field(description='Whether rebind protection enabled is enabled for this dns settings resource.')] = False
    rebind_domain_exemptions: Annotated[str, Field(description='Whether rebind domain exemptions is enabled for this dns settings resource.')] = ""
    query_logging_mode: Annotated[str, Field(description='Requested query logging mode value for this dns settings resource.')] = "off"


class DnsSettingsResponse(DnsSettingsUpdate):
    """Fields returned by the Atlaso dns settings API.

    Attributes:
        id: Unique database identifier assigned to this resource.
        authoritative_serial: Returned authoritative serial value for this dns settings resource.
        config_path: Appliance path where the rendered configuration is staged or installed; it is
            not a free-form input.
        updated_at: UTC timestamp when the resource was last updated.
    """

    model_config = ConfigDict(from_attributes=True)

    id: Annotated[int, Field(description='Unique database identifier assigned to this resource.')]
    authoritative_serial: Annotated[int, Field(description='Returned authoritative serial value for this dns settings resource.')]
    config_path: Annotated[str, Field(description='Appliance path where the rendered configuration is staged or installed; it is not a free-form input.')]
    updated_at: Annotated[datetime, Field(description='UTC timestamp when the resource was last updated.')]


class DnsRecordCreate(BaseModel):
    """Fields accepted when creating a dns record resource.

    Attributes:
        hostname: DNS hostname associated with the resource, normalized according to the endpoint
            contract.
        record_type: Requested record type value for this dns record resource.
        address: Requested address value for this dns record resource.
        description: Operator-facing purpose or context for this resource.
        enabled: Whether the resource is enabled in saved Atlaso state.
    """

    hostname: Annotated[str, Field(description='DNS hostname associated with the resource, normalized according to the endpoint contract.')] = Field(min_length=1, max_length=120)
    record_type: Annotated[str, Field(description='Requested record type value for this dns record resource.')] = Field(default="A", min_length=1, max_length=20)
    address: Annotated[str, Field(description='Requested address value for this dns record resource.')] = Field(min_length=1, max_length=120)
    description: Annotated[str | None, Field(description='Operator-facing purpose or context for this resource.')] = None
    enabled: Annotated[bool, Field(description='Whether the resource is enabled in saved Atlaso state.')] = True


class DnsRecordResponse(DnsRecordCreate):
    """Fields returned by the Atlaso dns record API.

    Attributes:
        id: Unique database identifier assigned to this resource.
        record_data_json: Returned record data json value for this dns record resource.
        created_at: UTC timestamp when the resource was created.
    """

    model_config = ConfigDict(from_attributes=True)

    id: Annotated[int, Field(description='Unique database identifier assigned to this resource.')]
    record_data_json: Annotated[str, Field(description='Returned record data json value for this dns record resource.')] = ""
    created_at: Annotated[datetime, Field(description='UTC timestamp when the resource was created.')]


class DnsHostsImportRequest(BaseModel):
    """Fields accepted when updating or operating on a dns hosts import resource.

    Attributes:
        hosts_text: Requested hosts text value for this dns hosts import resource.
        replace_existing: Whether replace existing is enabled for this dns hosts import resource.
    """

    hosts_text: Annotated[str, Field(description='Requested hosts text value for this dns hosts import resource.')] = Field(min_length=1)
    replace_existing: Annotated[bool, Field(description='Whether replace existing is enabled for this dns hosts import resource.')] = True


class DnsHostsImportResponse(BaseModel):
    """Fields returned by the Atlaso dns hosts import API.

    Attributes:
        imported_count: Number of imported records represented by this dns hosts import response.
        replaced_existing: Whether replaced existing is enabled for this dns hosts import resource.
        errors: Actionable errors produced while validating or processing the request.
        records: Ordered collection of records values represented by this dns hosts import schema.
    """

    imported_count: Annotated[int, Field(description='Number of imported records represented by this dns hosts import response.')]
    replaced_existing: Annotated[bool, Field(description='Whether replaced existing is enabled for this dns hosts import resource.')]
    errors: Annotated[list[str], Field(description='Actionable errors produced while validating or processing the request.')] = Field(default_factory=list)
    records: Annotated[list[DnsRecordResponse], Field(description='Ordered collection of records values represented by this dns hosts import schema.')]


class DhcpSettingsUpdate(BaseModel):
    """Fields accepted when updating or operating on a dhcp settings resource.

    Attributes:
        enabled: Whether the resource is enabled in saved Atlaso state.
        interface_name: Requested interface name value for this dhcp settings resource.
        site_address: Requested site address value for this dhcp settings resource.
        prefix_length: Requested prefix length value for this dhcp settings resource.
        lease_time: Requested lease time value for this dhcp settings resource.
        domain_name: Requested domain name value for this dhcp settings resource.
        dns_server: Requested dns server value for this dhcp settings resource.
        authoritative: Whether authoritative is enabled for this dhcp settings resource.
    """

    enabled: Annotated[bool, Field(description='Whether the resource is enabled in saved Atlaso state.')] = False
    interface_name: Annotated[str, Field(description='Requested interface name value for this dhcp settings resource.')] = Field(default="eth2", min_length=1, max_length=80)
    site_address: Annotated[str, Field(description='Requested site address value for this dhcp settings resource.')] = Field(default="192.168.50.1", min_length=1, max_length=64)
    prefix_length: Annotated[int, Field(description='Requested prefix length value for this dhcp settings resource.')] = Field(default=24, ge=1, le=32)
    lease_time: Annotated[str, Field(description='Requested lease time value for this dhcp settings resource.')] = Field(default="12h", min_length=1, max_length=40)
    domain_name: Annotated[str, Field(description='Requested domain name value for this dhcp settings resource.')] = Field(default="atlaso.internal", min_length=1, max_length=120)
    dns_server: Annotated[str, Field(description='Requested dns server value for this dhcp settings resource.')] = Field(default="192.168.50.1", min_length=1, max_length=64)
    authoritative: Annotated[bool, Field(description='Whether authoritative is enabled for this dhcp settings resource.')] = True


class DhcpSettingsResponse(DhcpSettingsUpdate):
    """Fields returned by the Atlaso dhcp settings API.

    Attributes:
        id: Unique database identifier assigned to this resource.
        config_path: Appliance path where the rendered configuration is staged or installed; it is
            not a free-form input.
        updated_at: UTC timestamp when the resource was last updated.
    """

    model_config = ConfigDict(from_attributes=True)

    id: Annotated[int, Field(description='Unique database identifier assigned to this resource.')]
    config_path: Annotated[str, Field(description='Appliance path where the rendered configuration is staged or installed; it is not a free-form input.')]
    updated_at: Annotated[datetime, Field(description='UTC timestamp when the resource was last updated.')]


class DhcpScopeCreate(BaseModel):
    """Fields accepted when creating a dhcp scope resource.

    Attributes:
        name: Stable operator-facing name of this resource.
        address_family: Requested address family value for this dhcp scope resource.
        interface_name: Requested interface name value for this dhcp scope resource.
        site_address: Requested site address value for this dhcp scope resource.
        prefix_length: Requested prefix length value for this dhcp scope resource.
        range_expression: Requested range expression value for this dhcp scope resource.
        lease_time: Requested lease time value for this dhcp scope resource.
        domain_name: Requested domain name value for this dhcp scope resource.
        dns_server: Requested dns server value for this dhcp scope resource.
        ntp_server: Requested ntp server value for this dhcp scope resource.
        enabled: Whether the resource is enabled in saved Atlaso state.
        description: Operator-facing purpose or context for this resource.
    """

    name: Annotated[str, Field(description='Stable operator-facing name of this resource.')] = Field(min_length=1, max_length=120)
    address_family: Annotated[str, Field(description='Requested address family value for this dhcp scope resource.')] = Field(default="ipv4", pattern="^(ipv4|ipv6)$")
    interface_name: Annotated[str, Field(description='Requested interface name value for this dhcp scope resource.')]
    site_address: Annotated[str, Field(description='Requested site address value for this dhcp scope resource.')]
    prefix_length: Annotated[int, Field(description='Requested prefix length value for this dhcp scope resource.')] = Field(ge=1, le=128)
    range_expression: Annotated[str, Field(description='Requested range expression value for this dhcp scope resource.')]
    lease_time: Annotated[str, Field(description='Requested lease time value for this dhcp scope resource.')]
    domain_name: Annotated[str, Field(description='Requested domain name value for this dhcp scope resource.')]
    dns_server: Annotated[str, Field(description='Requested dns server value for this dhcp scope resource.')]
    ntp_server: Annotated[str, Field(description='Requested ntp server value for this dhcp scope resource.')] = ""
    enabled: Annotated[bool, Field(description='Whether the resource is enabled in saved Atlaso state.')]
    description: Annotated[str | None, Field(description='Operator-facing purpose or context for this resource.')] = None


class DhcpScopeResponse(DhcpScopeCreate):
    """Fields returned by the Atlaso dhcp scope API.

    Attributes:
        id: Unique database identifier assigned to this resource.
        created_at: UTC timestamp when the resource was created.
        updated_at: UTC timestamp when the resource was last updated.
    """

    model_config = ConfigDict(from_attributes=True)

    id: Annotated[int, Field(description='Unique database identifier assigned to this resource.')]
    created_at: Annotated[datetime, Field(description='UTC timestamp when the resource was created.')]
    updated_at: Annotated[datetime, Field(description='UTC timestamp when the resource was last updated.')]


class DhcpOptionCreate(BaseModel):
    """Fields accepted when creating a dhcp option resource.

    Attributes:
        scope_id: Stable identifier of the related scope resource.
        option_code: Requested option code value for this dhcp option resource.
        value: Requested value value for this dhcp option resource.
        description: Operator-facing purpose or context for this resource.
        enabled: Whether the resource is enabled in saved Atlaso state.
    """

    scope_id: Annotated[int | None, Field(description='Stable identifier of the related scope resource.')] = None
    option_code: Annotated[str, Field(description='Requested option code value for this dhcp option resource.')] = Field(min_length=1, max_length=80)
    value: Annotated[str, Field(description='Requested value value for this dhcp option resource.')] = Field(min_length=1, max_length=240)
    description: Annotated[str | None, Field(description='Operator-facing purpose or context for this resource.')] = None
    enabled: Annotated[bool, Field(description='Whether the resource is enabled in saved Atlaso state.')] = True


class DhcpOptionResponse(DhcpOptionCreate):
    """Fields returned by the Atlaso dhcp option API.

    Attributes:
        id: Unique database identifier assigned to this resource.
        created_at: UTC timestamp when the resource was created.
        updated_at: UTC timestamp when the resource was last updated.
    """

    model_config = ConfigDict(from_attributes=True)

    id: Annotated[int, Field(description='Unique database identifier assigned to this resource.')]
    created_at: Annotated[datetime, Field(description='UTC timestamp when the resource was created.')]
    updated_at: Annotated[datetime, Field(description='UTC timestamp when the resource was last updated.')]


class DhcpReservationCreate(BaseModel):
    """Fields accepted when creating a dhcp reservation resource.

    Attributes:
        hostname: DNS hostname associated with the resource, normalized according to the endpoint
            contract.
        mac_address: Normalized hardware MAC address used to identify the network interface or host.
        ip_address: IPv4 or IPv6 address associated with the resource.
        description: Operator-facing purpose or context for this resource.
        enabled: Whether the resource is enabled in saved Atlaso state.
    """

    hostname: Annotated[str, Field(description='DNS hostname associated with the resource, normalized according to the endpoint contract.')] = Field(min_length=1, max_length=120)
    mac_address: Annotated[str, Field(description='Normalized hardware MAC address used to identify the network interface or host.')] = Field(min_length=1, max_length=32)
    ip_address: Annotated[str, Field(description='IPv4 or IPv6 address associated with the resource.')] = Field(min_length=1, max_length=64)
    description: Annotated[str | None, Field(description='Operator-facing purpose or context for this resource.')] = None
    enabled: Annotated[bool, Field(description='Whether the resource is enabled in saved Atlaso state.')] = True


class DhcpReservationResponse(DhcpReservationCreate):
    """Fields returned by the Atlaso dhcp reservation API.

    Attributes:
        id: Unique database identifier assigned to this resource.
        created_at: UTC timestamp when the resource was created.
    """

    model_config = ConfigDict(from_attributes=True)

    id: Annotated[int, Field(description='Unique database identifier assigned to this resource.')]
    created_at: Annotated[datetime, Field(description='UTC timestamp when the resource was created.')]


class DhcpLeaseResponse(BaseModel):
    """Fields returned by the Atlaso dhcp lease API.

    Attributes:
        expires_at: UTC timestamp after which the resource or credential is no longer accepted.
        mac_address: Normalized hardware MAC address used to identify the network interface or host.
        ip_address: IPv4 or IPv6 address associated with the resource.
        hostname: DNS hostname associated with the resource, normalized according to the endpoint
            contract.
        client_id: Stable identifier of the related client resource.
        status: Returned status value for this dhcp lease resource.
    """

    expires_at: Annotated[datetime | None, Field(description='UTC timestamp after which the resource or credential is no longer accepted.')]
    mac_address: Annotated[str, Field(description='Normalized hardware MAC address used to identify the network interface or host.')]
    ip_address: Annotated[str, Field(description='IPv4 or IPv6 address associated with the resource.')]
    hostname: Annotated[str, Field(description='DNS hostname associated with the resource, normalized according to the endpoint contract.')]
    client_id: Annotated[str, Field(description='Stable identifier of the related client resource.')]
    status: Annotated[str, Field(description='Returned status value for this dhcp lease resource.')]


class ConfigValidationResponse(BaseModel):
    """Fields returned by the Atlaso config validation API.

    Attributes:
        valid: Whether the represented desired state passed Atlaso validation.
        dry_run: Whether the operation reports command intent without mutating appliance host state.
        command: Ordered collection of command values represented by this config validation schema.
        config_path: Appliance path where the rendered configuration is staged or installed; it is
            not a free-form input.
        config_preview: Redacted rendered configuration preview for operator review; secret values
            are never included.
        errors: Actionable errors produced while validating or processing the request.
        warnings: Non-blocking warnings produced while validating or processing the request.
    """

    valid: Annotated[bool, Field(description='Whether the represented desired state passed Atlaso validation.')]
    dry_run: Annotated[bool, Field(description='Whether the operation reports command intent without mutating appliance host state.')]
    command: Annotated[list[str], Field(description='Ordered collection of command values represented by this config validation schema.')]
    config_path: Annotated[str, Field(description='Appliance path where the rendered configuration is staged or installed; it is not a free-form input.')]
    config_preview: Annotated[str, Field(description='Redacted rendered configuration preview for operator review; secret values are never included.')]
    errors: Annotated[list[str], Field(description='Actionable errors produced while validating or processing the request.')] = Field(default_factory=list)
    warnings: Annotated[list[str], Field(description='Non-blocking warnings produced while validating or processing the request.')] = Field(default_factory=list)


class ConfigApplyResponse(ConfigValidationResponse):
    """Fields returned by the Atlaso config apply API.

    Attributes:
        reloaded: Whether reloaded is enabled for this config apply resource.
    """

    reloaded: Annotated[bool, Field(description='Whether reloaded is enabled for this config apply resource.')] = False


class DnsStatusResponse(BaseModel):
    """Fields returned by the Atlaso dns status API.

    Attributes:
        enabled: Whether the resource is enabled in saved Atlaso state.
        service: Returned service value for this dns status resource.
        listen_interface: Saved access interface or enabled VLAN used as the service bind target.
        listen_address: Derived IP address on which the service listens; operators select an
            interface rather than entering this value directly.
        domain: Returned domain value for this dns status resource.
        record_count: Number of record records represented by this dns status response.
        config_path: Appliance path where the rendered configuration is staged or installed; it is
            not a free-form input.
        dry_run: Whether the operation reports command intent without mutating appliance host state.
    """

    enabled: Annotated[bool, Field(description='Whether the resource is enabled in saved Atlaso state.')]
    service: Annotated[ServiceStateResponse | None, Field(description='Returned service value for this dns status resource.')]
    listen_interface: Annotated[str, Field(description='Saved access interface or enabled VLAN used as the service bind target.')]
    listen_address: Annotated[str | None, Field(description='Derived IP address on which the service listens; operators select an interface rather than entering this value directly.')]
    domain: Annotated[str, Field(description='Returned domain value for this dns status resource.')]
    record_count: Annotated[int, Field(description='Number of record records represented by this dns status response.')]
    config_path: Annotated[str, Field(description='Appliance path where the rendered configuration is staged or installed; it is not a free-form input.')]
    dry_run: Annotated[bool, Field(description='Whether the operation reports command intent without mutating appliance host state.')]


class DhcpStatusResponse(BaseModel):
    """Fields returned by the Atlaso dhcp status API.

    Attributes:
        enabled: Whether the resource is enabled in saved Atlaso state.
        service: Returned service value for this dhcp status resource.
        interface_name: Returned interface name value for this dhcp status resource.
        range_expression: Returned range expression value for this dhcp status resource.
        reservation_count: Number of reservation records represented by this dhcp status response.
        config_path: Appliance path where the rendered configuration is staged or installed; it is
            not a free-form input.
        dry_run: Whether the operation reports command intent without mutating appliance host state.
    """

    enabled: Annotated[bool, Field(description='Whether the resource is enabled in saved Atlaso state.')]
    service: Annotated[ServiceStateResponse | None, Field(description='Returned service value for this dhcp status resource.')]
    interface_name: Annotated[str, Field(description='Returned interface name value for this dhcp status resource.')]
    range_expression: Annotated[str, Field(description='Returned range expression value for this dhcp status resource.')]
    reservation_count: Annotated[int, Field(description='Number of reservation records represented by this dhcp status response.')]
    config_path: Annotated[str, Field(description='Appliance path where the rendered configuration is staged or installed; it is not a free-form input.')]
    dry_run: Annotated[bool, Field(description='Whether the operation reports command intent without mutating appliance host state.')]


class DashboardResponse(BaseModel):
    """Fields returned by the Atlaso dashboard API.

    Attributes:
        appliance: Structured appliance values represented by this dashboard schema.
        service_health: Ordered collection of service health values represented by this dashboard
            schema.
        interfaces: Ordered collection of interfaces values represented by this dashboard schema.
        active_wan_policies: Ordered collection of active wan policies values represented by this
            dashboard schema.
        disk_usage: Structured disk usage values represented by this dashboard schema.
        recent_audit_events: Ordered collection of recent audit events values represented by this
            dashboard schema.
    """

    appliance: Annotated[dict[str, Any], Field(description='Structured appliance values represented by this dashboard schema.')]
    service_health: Annotated[list[ServiceStateResponse], Field(description='Ordered collection of service health values represented by this dashboard schema.')]
    interfaces: Annotated[list[PhysicalInterfaceResponse], Field(description='Ordered collection of interfaces values represented by this dashboard schema.')]
    active_wan_policies: Annotated[list[WanPolicyResponse], Field(description='Ordered collection of active wan policies values represented by this dashboard schema.')]
    disk_usage: Annotated[dict[str, Any], Field(description='Structured disk usage values represented by this dashboard schema.')]
    recent_audit_events: Annotated[list[dict[str, Any]], Field(description='Ordered collection of recent audit events values represented by this dashboard schema.')]


class MonitorResponse(BaseModel):
    """Fields returned by the Atlaso monitor API.

    Attributes:
        enabled: Whether the resource is enabled in saved Atlaso state.
        window_hours: Window hours, measured in hours, for this monitor resource.
        sample_interval_seconds: Sample interval seconds, measured in seconds, for this monitor
            resource.
        generated_at: UTC timestamp for generated at on this monitor resource.
        last_sample_at: UTC timestamp for last sample at on this monitor resource.
        sample_count: Number of sample records represented by this monitor response.
        summary: Structured summary values represented by this monitor schema.
        virtualization: Structured virtualization values represented by this monitor schema.
        cpu: Ordered collection of cpu values represented by this monitor schema.
        cpu_cores: Ordered collection of cpu cores values represented by this monitor schema.
        memory: Ordered collection of memory values represented by this monitor schema.
        network_totals: Ordered collection of network totals values represented by this monitor
            schema.
        networks: Ordered collection of networks values represented by this monitor schema.
        disk_io: Ordered collection of disk io values represented by this monitor schema.
        disk_devices: Ordered collection of disk devices values represented by this monitor schema.
        disks: Ordered collection of disks values represented by this monitor schema.
    """

    enabled: Annotated[bool, Field(description='Whether the resource is enabled in saved Atlaso state.')] = True
    window_hours: Annotated[int, Field(description='Window hours, measured in hours, for this monitor resource.')]
    sample_interval_seconds: Annotated[int, Field(description='Sample interval seconds, measured in seconds, for this monitor resource.')]
    generated_at: Annotated[str, Field(description='UTC timestamp for generated at on this monitor resource.')]
    last_sample_at: Annotated[str | None, Field(description='UTC timestamp for last sample at on this monitor resource.')]
    sample_count: Annotated[int, Field(description='Number of sample records represented by this monitor response.')]
    summary: Annotated[dict[str, Any], Field(description='Structured summary values represented by this monitor schema.')]
    virtualization: Annotated[dict[str, Any], Field(description='Structured virtualization values represented by this monitor schema.')]
    cpu: Annotated[list[dict[str, Any]], Field(description='Ordered collection of cpu values represented by this monitor schema.')]
    cpu_cores: Annotated[list[dict[str, Any]], Field(description='Ordered collection of cpu cores values represented by this monitor schema.')]
    memory: Annotated[list[dict[str, Any]], Field(description='Ordered collection of memory values represented by this monitor schema.')]
    network_totals: Annotated[list[dict[str, Any]], Field(description='Ordered collection of network totals values represented by this monitor schema.')]
    networks: Annotated[list[dict[str, Any]], Field(description='Ordered collection of networks values represented by this monitor schema.')]
    disk_io: Annotated[list[dict[str, Any]], Field(description='Ordered collection of disk io values represented by this monitor schema.')]
    disk_devices: Annotated[list[dict[str, Any]], Field(description='Ordered collection of disk devices values represented by this monitor schema.')]
    disks: Annotated[list[dict[str, Any]], Field(description='Ordered collection of disks values represented by this monitor schema.')]


class AuditEventResponse(BaseModel):
    """Fields returned by the Atlaso audit event API.

    Attributes:
        id: Unique database identifier assigned to this resource.
        created_at: UTC timestamp when the resource was created.
        actor: Returned actor value for this audit event resource.
        action: Returned action value for this audit event resource.
        resource_type: Returned resource type value for this audit event resource.
        resource_id: Stable identifier of the related resource resource.
        success: Whether success is enabled for this audit event resource.
        detail: Human-readable detail explaining the current state or failure.
        request_id: Request correlation identifier included in responses and operational logs.
    """

    model_config = ConfigDict(from_attributes=True)

    id: Annotated[int, Field(description='Unique database identifier assigned to this resource.')]
    created_at: Annotated[datetime, Field(description='UTC timestamp when the resource was created.')]
    actor: Annotated[str, Field(description='Returned actor value for this audit event resource.')]
    action: Annotated[str, Field(description='Returned action value for this audit event resource.')]
    resource_type: Annotated[str, Field(description='Returned resource type value for this audit event resource.')]
    resource_id: Annotated[str | None, Field(description='Stable identifier of the related resource resource.')]
    success: Annotated[bool, Field(description='Whether success is enabled for this audit event resource.')]
    detail: Annotated[str | None, Field(description='Human-readable detail explaining the current state or failure.')]
    request_id: Annotated[str | None, Field(description='Request correlation identifier included in responses and operational logs.')]


class JobResponse(BaseModel):
    """Fields returned by the Atlaso job API.

    Attributes:
        id: Unique database identifier assigned to this resource.
        type: Stable URI identifying the problem or resource type.
        status: Returned status value for this job resource.
        created_by: Returned created by value for this job resource.
        created_at: UTC timestamp when the resource was created.
        started_at: UTC timestamp for started at on this job resource.
        finished_at: UTC timestamp for finished at on this job resource.
        progress_percent: Progress percent, expressed as a percentage from 0 through 100.
        result: Returned result value for this job resource.
        error: Returned error value for this job resource.
    """

    model_config = ConfigDict(from_attributes=True)

    id: Annotated[str, Field(description='Unique database identifier assigned to this resource.')]
    type: Annotated[str, Field(description='Stable URI identifying the problem or resource type.')]
    status: Annotated[str, Field(description='Returned status value for this job resource.')]
    created_by: Annotated[str, Field(description='Returned created by value for this job resource.')]
    created_at: Annotated[datetime, Field(description='UTC timestamp when the resource was created.')]
    started_at: Annotated[datetime | None, Field(description='UTC timestamp for started at on this job resource.')]
    finished_at: Annotated[datetime | None, Field(description='UTC timestamp for finished at on this job resource.')]
    progress_percent: Annotated[int, Field(description='Progress percent, expressed as a percentage from 0 through 100.')]
    result: Annotated[str | None, Field(description='Returned result value for this job resource.')]
    error: Annotated[str | None, Field(description='Returned error value for this job resource.')]


class ServiceActionResponse(BaseModel):
    """Fields returned by the Atlaso service action API.

    Attributes:
        service: Returned service value for this service action resource.
        action: Returned action value for this service action resource.
        dry_run: Whether the operation reports command intent without mutating appliance host state.
        command: Ordered collection of command values represented by this service action schema.
    """

    service: Annotated[str, Field(description='Returned service value for this service action resource.')]
    action: Annotated[str, Field(description='Returned action value for this service action resource.')]
    dry_run: Annotated[bool, Field(description='Whether the operation reports command intent without mutating appliance host state.')]
    command: Annotated[list[str], Field(description='Ordered collection of command values represented by this service action schema.')]


class SettingsResponse(BaseModel):
    """Fields returned by the Atlaso settings API.

    Attributes:
        app_name: Returned app name value for this settings resource.
        appliance_hostname: Returned appliance hostname value for this settings resource.
        dry_run_system_adapters: Whether dry run system adapters is enabled for this settings
            resource.
        repository_path: Canonical filesystem or HTTP repository path used by Atlaso; callers must
            not treat it as an unrestricted path.
        vcf_backup_path: Canonical filesystem or HTTP VCF backup path used by Atlaso; callers must
            not treat it as an unrestricted path.
        appliance_fqdn: Returned appliance fqdn value for this settings resource.
        management_https_enabled: Whether management https enabled is enabled for this settings
            resource.
        management_https_cert_available: Whether management https cert available is enabled for this
            settings resource.
        web_terminal_enabled: Whether web terminal enabled is enabled for this settings resource.
        web_terminal_interfaces: Ordered collection of web terminal interfaces values represented by
            this settings schema.
        root_ssh_enabled: Whether root ssh enabled is enabled for this settings resource.
        external_dns_servers: Ordered collection of external dns servers values represented by this
            settings schema.
        appliance_settings_config_path: Canonical filesystem or HTTP appliance settings config path
            used by Atlaso; callers must not treat it as an unrestricted path.
        local_dns_enabled: Whether local dns enabled is enabled for this settings resource.
        management_interface: Returned management interface value for this settings resource.
        management_ip: Returned management ip value for this settings resource.
        valid: Whether the represented desired state passed Atlaso validation.
        validation_errors: Actionable validation failures that must be corrected before the state
            can be applied.
        validation_warnings: Non-blocking validation warnings that the operator should review.
        config_preview: Redacted rendered configuration preview for operator review; secret values
            are never included.
    """

    app_name: Annotated[str, Field(description='Returned app name value for this settings resource.')]
    appliance_hostname: Annotated[str, Field(description='Returned appliance hostname value for this settings resource.')]
    dry_run_system_adapters: Annotated[bool, Field(description='Whether dry run system adapters is enabled for this settings resource.')]
    repository_path: Annotated[str, Field(description='Canonical filesystem or HTTP repository path used by Atlaso; callers must not treat it as an unrestricted path.')]
    vcf_backup_path: Annotated[str, Field(description='Canonical filesystem or HTTP VCF backup path used by Atlaso; callers must not treat it as an unrestricted path.')]
    appliance_fqdn: Annotated[str, Field(description='Returned appliance fqdn value for this settings resource.')]
    management_https_enabled: Annotated[bool, Field(description='Whether management https enabled is enabled for this settings resource.')] = False
    management_https_cert_available: Annotated[bool, Field(description='Whether management https cert available is enabled for this settings resource.')] = False
    web_terminal_enabled: Annotated[bool, Field(description='Whether web terminal enabled is enabled for this settings resource.')] = False
    web_terminal_interfaces: Annotated[list[str], Field(description='Ordered collection of web terminal interfaces values represented by this settings schema.')] = Field(default_factory=list)
    root_ssh_enabled: Annotated[bool, Field(description='Whether root ssh enabled is enabled for this settings resource.')] = False
    external_dns_servers: Annotated[list[str], Field(description='Ordered collection of external dns servers values represented by this settings schema.')]
    appliance_settings_config_path: Annotated[str, Field(description='Canonical filesystem or HTTP appliance settings config path used by Atlaso; callers must not treat it as an unrestricted path.')]
    local_dns_enabled: Annotated[bool, Field(description='Whether local dns enabled is enabled for this settings resource.')]
    management_interface: Annotated[str, Field(description='Returned management interface value for this settings resource.')]
    management_ip: Annotated[str, Field(description='Returned management ip value for this settings resource.')]
    valid: Annotated[bool, Field(description='Whether the represented desired state passed Atlaso validation.')]
    validation_errors: Annotated[list[str], Field(description='Actionable validation failures that must be corrected before the state can be applied.')] = Field(default_factory=list)
    validation_warnings: Annotated[list[str], Field(description='Non-blocking validation warnings that the operator should review.')] = Field(default_factory=list)
    config_preview: Annotated[str, Field(description='Redacted rendered configuration preview for operator review; secret values are never included.')]


class SettingsUpdate(BaseModel):
    """Fields accepted when updating or operating on a settings resource.

    Attributes:
        appliance_fqdn: Requested appliance fqdn value for this settings resource.
        management_https_enabled: Whether management https enabled is enabled for this settings
            resource.
        web_terminal_enabled: Whether web terminal enabled is enabled for this settings resource.
        web_terminal_interfaces: Ordered collection of web terminal interfaces values represented by
            this settings schema.
        root_ssh_enabled: Whether root ssh enabled is enabled for this settings resource.
        external_dns_servers: Ordered collection of external dns servers values represented by this
            settings schema.
    """

    appliance_fqdn: Annotated[str, Field(description='Requested appliance fqdn value for this settings resource.')] = Field(default="core.atlaso.internal", min_length=1, max_length=180)
    management_https_enabled: Annotated[bool, Field(description='Whether management https enabled is enabled for this settings resource.')] = False
    web_terminal_enabled: Annotated[bool, Field(description='Whether web terminal enabled is enabled for this settings resource.')] = False
    web_terminal_interfaces: Annotated[list[str], Field(description='Ordered collection of web terminal interfaces values represented by this settings schema.')] = Field(default_factory=list)
    root_ssh_enabled: Annotated[bool, Field(description='Whether root ssh enabled is enabled for this settings resource.')] = False
    external_dns_servers: Annotated[list[str], Field(description='Ordered collection of external dns servers values represented by this settings schema.')] = Field(default_factory=lambda: ["1.1.1.1", "9.9.9.9"])


class OidcProviderSettingsUpdate(BaseModel):
    """Fields accepted when updating or operating on a oidc provider settings resource.

    Attributes:
        enabled: Whether the resource is enabled in saved Atlaso state.
        hostname: DNS hostname associated with the resource, normalized according to the endpoint
            contract.
        listen_interfaces: Saved access interfaces or enabled VLANs used as service bind targets.
        port: TCP or UDP port in the valid 1 through 65535 range.
        issuer_url: Validated issuer url used for this oidc provider settings integration.
        access_token_lifetime_seconds: Access token lifetime seconds, measured in seconds, for this
            oidc provider settings resource.
        id_token_lifetime_seconds: Id token lifetime seconds, measured in seconds, for this oidc
            provider settings resource.
        authorization_code_lifetime_seconds: Authorization code lifetime seconds, measured in
            seconds, for this oidc provider settings resource.
        clock_skew_seconds: Clock skew seconds, measured in seconds, for this oidc provider settings
            resource.
        signing_key_overlap_seconds: Signing key overlap seconds, measured in seconds, for this oidc
            provider settings resource.
    """

    enabled: Annotated[bool, Field(description='Whether the resource is enabled in saved Atlaso state.')] = False
    hostname: Annotated[str | None, Field(description='DNS hostname associated with the resource, normalized according to the endpoint contract. Omit it to preserve the current factory-derived or operator-customized hostname.')] = Field(default=None, min_length=1, max_length=180)
    listen_interfaces: Annotated[list[str], Field(description='Saved access interfaces or enabled VLANs used as service bind targets.')] = Field(default_factory=list)
    port: Annotated[int, Field(description='TCP or UDP port in the valid 1 through 65535 range.')] = Field(default=443, ge=1, le=65535)
    issuer_url: Annotated[str | None, Field(description='Validated issuer URL for this OIDC provider. Atlaso derives it from the effective hostname and port when omitted.')] = Field(default=None, min_length=1, max_length=500)
    access_token_lifetime_seconds: Annotated[int, Field(description='Access token lifetime seconds, measured in seconds, for this oidc provider settings resource.')] = Field(default=300, ge=60, le=3600)
    id_token_lifetime_seconds: Annotated[int, Field(description='Id token lifetime seconds, measured in seconds, for this oidc provider settings resource.')] = Field(default=300, ge=60, le=3600)
    authorization_code_lifetime_seconds: Annotated[int, Field(description='Authorization code lifetime seconds, measured in seconds, for this oidc provider settings resource.')] = Field(default=60, ge=30, le=300)
    clock_skew_seconds: Annotated[int, Field(description='Clock skew seconds, measured in seconds, for this oidc provider settings resource.')] = Field(default=120, ge=0, le=300)
    signing_key_overlap_seconds: Annotated[int, Field(description='Signing key overlap seconds, measured in seconds, for this oidc provider settings resource.')] = Field(default=3600, ge=300, le=604800)


class OidcProviderSettingsResponse(OidcProviderSettingsUpdate):
    """Fields returned by the Atlaso oidc provider settings API.

    Attributes:
        listen_addresses: Derived IPv4 and IPv6 listener addresses for the selected interfaces.
        authorization_flow_available: Whether authorization flow available is enabled for this oidc
            provider settings resource.
        valid: Whether the represented desired state passed Atlaso validation.
        validation_errors: Actionable validation failures that must be corrected before the state
            can be applied.
        discovery_url: Validated discovery url used for this oidc provider settings integration.
        authorization_endpoint: Returned authorization endpoint value for this oidc provider
            settings resource.
        token_endpoint: Returned token endpoint value for this oidc provider settings resource.
        userinfo_endpoint: Returned userinfo endpoint value for this oidc provider settings
            resource.
        jwks_uri: Returned jwks uri value for this oidc provider settings resource.
        end_session_endpoint: Returned end session endpoint value for this oidc provider settings
            resource.
    """

    hostname: Annotated[str, Field(description='Persisted DNS hostname used by the OIDC provider response.')] = Field(min_length=1, max_length=180)
    issuer_url: Annotated[str, Field(description='Persisted issuer URL used by the OIDC provider response.')] = Field(min_length=1, max_length=500)
    listen_addresses: Annotated[list[str], Field(description='Derived IPv4 and IPv6 listener addresses for the selected interfaces.')] = Field(default_factory=list)
    authorization_flow_available: Annotated[bool, Field(description='Whether authorization flow available is enabled for this oidc provider settings resource.')]
    valid: Annotated[bool, Field(description='Whether the represented desired state passed Atlaso validation.')]
    validation_errors: Annotated[list[str], Field(description='Actionable validation failures that must be corrected before the state can be applied.')] = Field(default_factory=list)
    discovery_url: Annotated[str, Field(description='Validated discovery url used for this oidc provider settings integration.')]
    authorization_endpoint: Annotated[str, Field(description='Returned authorization endpoint value for this oidc provider settings resource.')]
    token_endpoint: Annotated[str, Field(description='Returned token endpoint value for this oidc provider settings resource.')]
    userinfo_endpoint: Annotated[str, Field(description='Returned userinfo endpoint value for this oidc provider settings resource.')]
    jwks_uri: Annotated[str, Field(description='Returned jwks uri value for this oidc provider settings resource.')]
    end_session_endpoint: Annotated[str, Field(description='Returned end session endpoint value for this oidc provider settings resource.')]


class OidcClientCreate(BaseModel):
    """Fields accepted when creating a oidc client resource.

    Attributes:
        name: Stable operator-facing name of this resource.
        description: Operator-facing purpose or context for this resource.
        organization_id: Stable identifier of the related organization resource.
        redirect_uris: Ordered collection of redirect uris values represented by this oidc client
            schema.
        post_logout_redirect_uris: Ordered collection of post logout redirect uris values
            represented by this oidc client schema.
        allowed_scopes: OIDC scopes this client is permitted to request; `openid` is always
            required.
        allow_loopback_redirects: Whether allow loopback redirects is enabled for this oidc client
            resource.
        access_token_lifetime_seconds: Access token lifetime seconds, measured in seconds, for this
            oidc client resource.
        id_token_lifetime_seconds: Id token lifetime seconds, measured in seconds, for this oidc
            client resource.
        authorization_code_lifetime_seconds: Authorization code lifetime seconds, measured in
            seconds, for this oidc client resource.
        enabled: Whether the resource is enabled in saved Atlaso state.
    """

    name: Annotated[str, Field(description='Stable operator-facing name of this resource.')] = Field(min_length=1, max_length=160)
    description: Annotated[str, Field(description='Operator-facing purpose or context for this resource.')] = Field(default="", max_length=1000)
    organization_id: Annotated[int | None, Field(description='Stable identifier of the related organization resource.')] = None
    redirect_uris: Annotated[list[str], Field(description='Ordered collection of redirect uris values represented by this oidc client schema.')] = Field(min_length=1)
    post_logout_redirect_uris: Annotated[list[str], Field(description='Ordered collection of post logout redirect uris values represented by this oidc client schema.')] = Field(default_factory=list)
    allowed_scopes: Annotated[list[str], Field(description='OIDC scopes this client is permitted to request; `openid` is always required.')] = Field(
        default_factory=lambda: ["openid", "profile", "email", "groups"]
    )
    allow_loopback_redirects: Annotated[bool, Field(description='Whether allow loopback redirects is enabled for this oidc client resource.')] = False
    access_token_lifetime_seconds: Annotated[int, Field(description='Access token lifetime seconds, measured in seconds, for this oidc client resource.')] = Field(default=300, ge=60, le=3600)
    id_token_lifetime_seconds: Annotated[int, Field(description='Id token lifetime seconds, measured in seconds, for this oidc client resource.')] = Field(default=300, ge=60, le=3600)
    authorization_code_lifetime_seconds: Annotated[int, Field(description='Authorization code lifetime seconds, measured in seconds, for this oidc client resource.')] = Field(default=60, ge=30, le=300)
    enabled: Annotated[bool, Field(description='Whether the resource is enabled in saved Atlaso state.')] = True


class OidcClientUpdate(OidcClientCreate):
    """Mutable confidential-client settings.

    The generated client identifier and secret are intentionally absent.
    """


class OidcClientResponse(BaseModel):
    """Fields returned by the Atlaso oidc client API.

    Attributes:
        id: Unique database identifier assigned to this resource.
        name: Stable operator-facing name of this resource.
        description: Operator-facing purpose or context for this resource.
        client_id: Stable identifier of the related client resource.
        organization_id: Stable identifier of the related organization resource.
        organization_slug: Returned organization slug value for this oidc client resource.
        redirect_uris: Ordered collection of redirect uris values represented by this oidc client
            schema.
        post_logout_redirect_uris: Ordered collection of post logout redirect uris values
            represented by this oidc client schema.
        allowed_scopes: OIDC scopes this client is permitted to request; `openid` is always
            required.
        token_endpoint_auth_method: Returned token endpoint auth method value for this oidc client
            resource.
        access_token_lifetime_seconds: Access token lifetime seconds, measured in seconds, for this
            oidc client resource.
        id_token_lifetime_seconds: Id token lifetime seconds, measured in seconds, for this oidc
            client resource.
        authorization_code_lifetime_seconds: Authorization code lifetime seconds, measured in
            seconds, for this oidc client resource.
        allow_loopback_redirects: Whether allow loopback redirects is enabled for this oidc client
            resource.
        enabled: Whether the resource is enabled in saved Atlaso state.
        created_at: UTC timestamp when the resource was created.
        updated_at: UTC timestamp when the resource was last updated.
    """

    id: Annotated[int, Field(description='Unique database identifier assigned to this resource.')]
    name: Annotated[str, Field(description='Stable operator-facing name of this resource.')]
    description: Annotated[str, Field(description='Operator-facing purpose or context for this resource.')]
    client_id: Annotated[str, Field(description='Stable identifier of the related client resource.')]
    organization_id: Annotated[int | None, Field(description='Stable identifier of the related organization resource.')]
    organization_slug: Annotated[str | None, Field(description='Returned organization slug value for this oidc client resource.')]
    redirect_uris: Annotated[list[str], Field(description='Ordered collection of redirect uris values represented by this oidc client schema.')]
    post_logout_redirect_uris: Annotated[list[str], Field(description='Ordered collection of post logout redirect uris values represented by this oidc client schema.')]
    allowed_scopes: Annotated[list[str], Field(description='OIDC scopes this client is permitted to request; `openid` is always required.')]
    token_endpoint_auth_method: Annotated[str, Field(description='Returned token endpoint auth method value for this oidc client resource.')]
    access_token_lifetime_seconds: Annotated[int, Field(description='Access token lifetime seconds, measured in seconds, for this oidc client resource.')]
    id_token_lifetime_seconds: Annotated[int, Field(description='Id token lifetime seconds, measured in seconds, for this oidc client resource.')]
    authorization_code_lifetime_seconds: Annotated[int, Field(description='Authorization code lifetime seconds, measured in seconds, for this oidc client resource.')]
    allow_loopback_redirects: Annotated[bool, Field(description='Whether allow loopback redirects is enabled for this oidc client resource.')]
    enabled: Annotated[bool, Field(description='Whether the resource is enabled in saved Atlaso state.')]
    created_at: Annotated[datetime, Field(description='UTC timestamp when the resource was created.')]
    updated_at: Annotated[datetime, Field(description='UTC timestamp when the resource was last updated.')]


class OidcClientCreated(BaseModel):
    """Fields returned by the Atlaso oidc client API.

    Attributes:
        client: Returned client value for this oidc client resource.
        client_secret: One-time OIDC client secret returned only at creation or rotation; only its
            verifier is retained.
    """

    client: Annotated[OidcClientResponse, Field(description='Returned client value for this oidc client resource.')]
    client_secret: Annotated[str, Field(description='One-time OIDC client secret returned only at creation or rotation; only its verifier is retained.')]


class OidcClientSecretRotated(BaseModel):
    """Validated fields used by the Atlaso oidc client secret rotated API contract.

    Attributes:
        client_id: Stable identifier of the related client resource.
        client_secret: One-time OIDC client secret returned only at creation or rotation; only its
            verifier is retained.
    """

    client_id: Annotated[str, Field(description='Stable identifier of the related client resource.')]
    client_secret: Annotated[str, Field(description='One-time OIDC client secret returned only at creation or rotation; only its verifier is retained.')]


class OidcIntegrationExport(BaseModel):
    """Validated fields used by the Atlaso oidc integration API contract.

    Attributes:
        issuer: Validated issuer used for this oidc integration integration.
        discovery_url: Validated discovery url used for this oidc integration integration.
        authorization_endpoint: Returned authorization endpoint value for this oidc integration
            resource.
        token_endpoint: Returned token endpoint value for this oidc integration resource.
        userinfo_endpoint: Returned userinfo endpoint value for this oidc integration resource.
        jwks_uri: Returned jwks uri value for this oidc integration resource.
        end_session_endpoint: Returned end session endpoint value for this oidc integration
            resource.
        client_id: Stable identifier of the related client resource.
        token_endpoint_auth_method: Returned token endpoint auth method value for this oidc
            integration resource.
        allowed_scopes: OIDC scopes this client is permitted to request; `openid` is always
            required.
        redirect_uris: Ordered collection of redirect uris values represented by this oidc
            integration schema.
        post_logout_redirect_uris: Ordered collection of post logout redirect uris values
            represented by this oidc integration schema.
        organization: Returned organization value for this oidc integration resource.
        enabled: Whether the resource is enabled in saved Atlaso state.
    """

    issuer: Annotated[str, Field(description='Validated issuer used for this oidc integration integration.')]
    discovery_url: Annotated[str, Field(description='Validated discovery url used for this oidc integration integration.')]
    authorization_endpoint: Annotated[str, Field(description='Returned authorization endpoint value for this oidc integration resource.')]
    token_endpoint: Annotated[str, Field(description='Returned token endpoint value for this oidc integration resource.')]
    userinfo_endpoint: Annotated[str, Field(description='Returned userinfo endpoint value for this oidc integration resource.')]
    jwks_uri: Annotated[str, Field(description='Returned jwks uri value for this oidc integration resource.')]
    end_session_endpoint: Annotated[str, Field(description='Returned end session endpoint value for this oidc integration resource.')]
    client_id: Annotated[str, Field(description='Stable identifier of the related client resource.')]
    token_endpoint_auth_method: Annotated[str, Field(description='Returned token endpoint auth method value for this oidc integration resource.')]
    allowed_scopes: Annotated[list[str], Field(description='OIDC scopes this client is permitted to request; `openid` is always required.')]
    redirect_uris: Annotated[list[str], Field(description='Ordered collection of redirect uris values represented by this oidc integration schema.')]
    post_logout_redirect_uris: Annotated[list[str], Field(description='Ordered collection of post logout redirect uris values represented by this oidc integration schema.')]
    organization: Annotated[str, Field(description='Returned organization value for this oidc integration resource.')]
    enabled: Annotated[bool, Field(description='Whether the resource is enabled in saved Atlaso state.')]


class OidcClientEnabledUpdate(BaseModel):
    """Fields accepted when updating or operating on a oidc client enabled resource.

    Attributes:
        enabled: Whether the resource is enabled in saved Atlaso state.
    """

    enabled: Annotated[bool, Field(description='Whether the resource is enabled in saved Atlaso state.')]


class OidcGroupMappingCreate(BaseModel):
    """Fields accepted when creating a oidc group mapping resource.

    Attributes:
        source_type: Requested source type value for this oidc group mapping resource.
        local_role: Requested local role value for this oidc group mapping resource.
        ldap_group_id: Stable identifier of the related LDAP group resource.
        oidc_client_id: Stable identifier of the related OIDC client resource.
        external_group_name: Requested external group name value for this oidc group mapping
            resource.
    """

    source_type: Annotated[Literal["local_role", "ldap_group"], Field(description='Requested source type value for this oidc group mapping resource.')]
    local_role: Annotated[str, Field(description='Requested local role value for this oidc group mapping resource.')] = Field(default="", max_length=50)
    ldap_group_id: Annotated[int | None, Field(description='Stable identifier of the related LDAP group resource.')] = None
    oidc_client_id: Annotated[int | None, Field(description='Stable identifier of the related OIDC client resource.')] = None
    external_group_name: Annotated[str, Field(description='Requested external group name value for this oidc group mapping resource.')] = Field(min_length=1, max_length=160)


class OidcGroupMappingUpdate(BaseModel):
    """Fields accepted when updating or operating on a oidc group mapping resource.

    Attributes:
        oidc_client_id: Stable identifier of the related OIDC client resource.
        external_group_name: Requested external group name value for this oidc group mapping
            resource.
    """

    oidc_client_id: Annotated[int | None, Field(description='Stable identifier of the related OIDC client resource.')] = None
    external_group_name: Annotated[str, Field(description='Requested external group name value for this oidc group mapping resource.')] = Field(min_length=1, max_length=160)


class OidcGroupMappingResponse(BaseModel):
    """Fields returned by the Atlaso oidc group mapping API.

    Attributes:
        id: Unique database identifier assigned to this resource.
        source_type: Returned source type value for this oidc group mapping resource.
        source_name: Returned source name value for this oidc group mapping resource.
        local_role: Returned local role value for this oidc group mapping resource.
        ldap_group_id: Stable identifier of the related LDAP group resource.
        organization_id: Stable identifier of the related organization resource.
        organization_name: Returned organization name value for this oidc group mapping resource.
        oidc_client_id: Stable identifier of the related OIDC client resource.
        oidc_client_name: Returned OIDC client name value for this oidc group mapping resource.
        external_group_name: Returned external group name value for this oidc group mapping
            resource.
        created_at: UTC timestamp when the resource was created.
        updated_at: UTC timestamp when the resource was last updated.
    """

    id: Annotated[int, Field(description='Unique database identifier assigned to this resource.')]
    source_type: Annotated[Literal["local_role", "ldap_group"], Field(description='Returned source type value for this oidc group mapping resource.')]
    source_name: Annotated[str, Field(description='Returned source name value for this oidc group mapping resource.')]
    local_role: Annotated[str, Field(description='Returned local role value for this oidc group mapping resource.')]
    ldap_group_id: Annotated[int | None, Field(description='Stable identifier of the related LDAP group resource.')]
    organization_id: Annotated[int | None, Field(description='Stable identifier of the related organization resource.')]
    organization_name: Annotated[str, Field(description='Returned organization name value for this oidc group mapping resource.')]
    oidc_client_id: Annotated[int | None, Field(description='Stable identifier of the related OIDC client resource.')]
    oidc_client_name: Annotated[str, Field(description='Returned OIDC client name value for this oidc group mapping resource.')]
    external_group_name: Annotated[str, Field(description='Returned external group name value for this oidc group mapping resource.')]
    created_at: Annotated[datetime, Field(description='UTC timestamp when the resource was created.')]
    updated_at: Annotated[datetime, Field(description='UTC timestamp when the resource was last updated.')]


class OidcSigningKeyResponse(BaseModel):
    """Fields returned by the Atlaso oidc signing key API.

    Attributes:
        id: Unique database identifier assigned to this resource.
        kid: Returned kid value for this oidc signing key resource.
        algorithm: Returned algorithm value for this oidc signing key resource.
        status: Returned status value for this oidc signing key resource.
        key_type: Returned key type value for this oidc signing key resource.
        created_at: UTC timestamp when the resource was created.
        activated_at: UTC timestamp for activated at on this oidc signing key resource.
        retired_at: UTC timestamp for retired at on this oidc signing key resource.
        publish_until: Returned publish until value for this oidc signing key resource.
    """

    id: Annotated[int, Field(description='Unique database identifier assigned to this resource.')]
    kid: Annotated[str, Field(description='Returned kid value for this oidc signing key resource.')]
    algorithm: Annotated[str, Field(description='Returned algorithm value for this oidc signing key resource.')]
    status: Annotated[str, Field(description='Returned status value for this oidc signing key resource.')]
    key_type: Annotated[str | None, Field(description='Returned key type value for this oidc signing key resource.')]
    created_at: Annotated[datetime, Field(description='UTC timestamp when the resource was created.')]
    activated_at: Annotated[datetime, Field(description='UTC timestamp for activated at on this oidc signing key resource.')]
    retired_at: Annotated[datetime | None, Field(description='UTC timestamp for retired at on this oidc signing key resource.')]
    publish_until: Annotated[datetime | None, Field(description='Returned publish until value for this oidc signing key resource.')]


class OidcSubjectResponse(BaseModel):
    """Fields returned by the Atlaso oidc subject API.

    Attributes:
        subject: Returned subject value for this oidc subject resource.
        source: Validated network or address value for source in this oidc subject resource.
        username: Returned username value for this oidc subject resource.
        organization_id: Stable identifier of the related organization resource.
        organization_name: Returned organization name value for this oidc subject resource.
        created_at: UTC timestamp when the resource was created.
    """

    subject: Annotated[str, Field(description='Returned subject value for this oidc subject resource.')]
    source: Annotated[str, Field(description='Validated network or address value for source in this oidc subject resource.')]
    username: Annotated[str, Field(description='Returned username value for this oidc subject resource.')]
    organization_id: Annotated[int | None, Field(description='Stable identifier of the related organization resource.')]
    organization_name: Annotated[str, Field(description='Returned organization name value for this oidc subject resource.')]
    created_at: Annotated[datetime, Field(description='UTC timestamp when the resource was created.')]


class VsphereKeyProviderSettingsUpdate(BaseModel):
    """Fields accepted for appliance-wide vSphere Key Provider listener desired state."""

    enabled: Annotated[bool, Field(description="Whether the shared KMIP listener is enabled in desired state.")]
    listen_interfaces: Annotated[list[str], Field(description="Access interfaces selected for the shared KMIP listener.")]
    listen_addresses: Annotated[
        list[str],
        Field(
            description=(
                "IP addresses derived from selected KMIP listener interfaces. Callers may echo this field for shape "
                "compatibility, but Atlaso ignores supplied entries and derives the saved addresses server-side."
            )
        ),
    ]
    port: Annotated[int, Field(description="TCP port for the KMIP 1.4 listener.", ge=1, le=65535)] = 5696
    hostname: Annotated[str, Field(description="DNS hostname advertised for the shared vSphere Key Provider endpoint.", min_length=1, max_length=253)]


class VsphereKeyProviderSettingsResponse(VsphereKeyProviderSettingsUpdate):
    """Fields returned for appliance-wide vSphere Key Provider listener desired state."""

    updated_at: Annotated[datetime, Field(description="UTC timestamp of the most recent saved listener change.")]
    valid: Annotated[bool, Field(description="Whether current desired state is ready for global Appliance Apply validation.")]
    validation_errors: Annotated[list[str], Field(description="Secret-free reasons current desired state needs attention.")]
    config_path: Annotated[str, Field(description="Fixed runtime path for the applied bounded KMIP configuration.")]


class VsphereKeyProviderCreate(BaseModel):
    """Fields accepted when creating a logical vSphere Key Provider namespace."""

    name: Annotated[str, Field(description="Unique operator-facing provider name.", min_length=1, max_length=120)]
    description: Annotated[str, Field(description="Operator-facing purpose of the provider namespace.", max_length=1000)] = ""
    enabled: Annotated[bool, Field(description="Whether the provider enters rendered desired state after validation.")] = True


class VsphereKeyProviderUpdate(BaseModel):
    """Fields accepted when updating a logical vSphere Key Provider namespace."""

    name: Annotated[str | None, Field(description="Replacement unique operator-facing provider name.", min_length=1, max_length=120)] = None
    description: Annotated[str | None, Field(description="Replacement operator-facing provider purpose.", max_length=1000)] = None
    enabled: Annotated[bool | None, Field(description="Replacement provider desired-state enablement.")] = None


class VsphereKeyProviderResponse(BaseModel):
    """Fields returned for one logical vSphere Key Provider namespace."""

    id: Annotated[str, Field(description="Immutable UUID qualifying every operational key lookup in this namespace.")]
    name: Annotated[str, Field(description="Unique operator-facing provider name.")]
    description: Annotated[str, Field(description="Operator-facing purpose of the provider namespace.")]
    enabled: Annotated[bool, Field(description="Whether the provider is enabled in saved desired state.")]
    trusted_vcenter_count: Annotated[int, Field(description="Number of trusted vCenter records assigned to the provider.")]
    certificate_count: Annotated[int, Field(description="Number of public client certificate records assigned to the provider.")]
    usable_certificate_count: Annotated[int, Field(description="Number of current exact certificate fingerprints usable after apply.")]
    created_at: Annotated[datetime, Field(description="UTC timestamp when the provider was created.")]
    updated_at: Annotated[datetime, Field(description="UTC timestamp when the provider was last updated.")]


class VsphereTrustedVcenterCreate(BaseModel):
    """Fields accepted when creating a provider-scoped trusted vCenter."""

    name: Annotated[str, Field(description="Unique vCenter label within the provider.", min_length=1, max_length=120)]
    hostname: Annotated[str, Field(description="Operational vCenter hostname or IP label; no credentials or URL are stored.", max_length=253)] = ""
    description: Annotated[str, Field(description="Operator-facing purpose of this trusted vCenter.", max_length=1000)] = ""
    enabled: Annotated[bool, Field(description="Whether current certificate fingerprints enter rendered trust desired state.")] = True


class VsphereTrustedVcenterUpdate(BaseModel):
    """Fields accepted when updating a provider-scoped trusted vCenter."""

    name: Annotated[str | None, Field(description="Replacement unique vCenter label within the provider.", min_length=1, max_length=120)] = None
    hostname: Annotated[str | None, Field(description="Replacement operational vCenter hostname or IP label.", max_length=253)] = None
    description: Annotated[str | None, Field(description="Replacement operator-facing purpose.", max_length=1000)] = None
    enabled: Annotated[bool | None, Field(description="Replacement trust desired-state enablement.")] = None


class VsphereTrustedVcenterResponse(BaseModel):
    """Fields returned for one provider-scoped trusted vCenter."""

    id: Annotated[str, Field(description="Immutable UUID assigned to this trusted-vCenter record.")]
    provider_id: Annotated[str, Field(description="Immutable UUID of the owning provider namespace.")]
    provider_name: Annotated[str, Field(description="Operator-facing name of the owning provider.")]
    name: Annotated[str, Field(description="Unique vCenter label within the provider.")]
    hostname: Annotated[str, Field(description="Operational vCenter hostname or IP label.")]
    description: Annotated[str, Field(description="Operator-facing purpose of this trusted vCenter.")]
    enabled: Annotated[bool, Field(description="Whether its current fingerprints enter rendered trust desired state.")]
    certificate_count: Annotated[int, Field(description="Number of assigned public certificate records.")]
    usable_certificate_count: Annotated[int, Field(description="Number of current exact fingerprints usable after apply.")]
    earliest_expiry: Annotated[datetime | None, Field(description="Earliest assigned certificate expiry, or null when no certificate is assigned.")]
    created_at: Annotated[datetime, Field(description="UTC timestamp when the trusted-vCenter record was created.")]
    updated_at: Annotated[datetime, Field(description="UTC timestamp when the trusted-vCenter record was last updated.")]


class VsphereTrustedCertificateCreate(BaseModel):
    """Fields accepted when assigning one public vCenter client certificate."""

    certificate_pem: Annotated[str, Field(description="One PEM-encoded public X.509 vCenter client certificate; private keys are forbidden.", min_length=1, max_length=65536)]


class VsphereTrustedCertificateResponse(BaseModel):
    """Fields returned for one exact public vCenter client certificate identity."""

    id: Annotated[str, Field(description="Immutable UUID assigned to the certificate record.")]
    provider_id: Annotated[str, Field(description="Immutable UUID of the owning provider namespace.")]
    provider_name: Annotated[str, Field(description="Operator-facing name of the owning provider.")]
    trusted_vcenter_id: Annotated[str, Field(description="Immutable UUID of the owning trusted-vCenter record.")]
    trusted_vcenter_name: Annotated[str, Field(description="Operator-facing name of the owning trusted vCenter.")]
    fingerprint_sha256: Annotated[str, Field(description="Normalized lowercase SHA-256 fingerprint used for exact provider authorization.")]
    certificate_pem: Annotated[str, Field(description="Canonical public PEM certificate; no private material is returned.")]
    subject: Annotated[str, Field(description="RFC 4514 subject name parsed from the public certificate.")]
    issuer: Annotated[str, Field(description="RFC 4514 issuer name parsed from the public certificate.")]
    serial_number: Annotated[str, Field(description="Lowercase hexadecimal public certificate serial number.")]
    not_valid_before: Annotated[datetime, Field(description="UTC certificate validity start.")]
    not_valid_after: Annotated[datetime, Field(description="UTC certificate expiry.")]
    source: Annotated[str, Field(description="Origin of the public trust record; currently uploaded_public.")]
    status: Annotated[str, Field(description="Current certificate status: valid, expired, or not-yet-valid.")]
    created_at: Annotated[datetime, Field(description="UTC timestamp when the certificate trust record was created.")]


class VsphereProviderReadinessResponse(BaseModel):
    """Fields returned by a provider desired-state readiness evaluation."""

    provider_id: Annotated[str, Field(description="Immutable UUID of the evaluated provider namespace.")]
    ready: Annotated[bool, Field(description="Whether provider desired state satisfies the bounded pre-apply contract.")]
    reasons: Annotated[list[str], Field(description="Secret-free readiness failures; empty when ready is true.")]
    requires_appliance_apply: Annotated[bool, Field(description="Whether saved desired state still requires global Appliance Apply enforcement.")]


class VsphereProviderHealthResponse(BaseModel):
    """Fields returned by a redacted provider runtime health evaluation."""

    provider_id: Annotated[str, Field(description="Immutable UUID of the evaluated provider namespace.")]
    desired_state: Annotated[str, Field(description="Saved provider state: enabled or disabled.")]
    runtime_state: Annotated[str, Field(description="Observed shared daemon state or not-reported when unavailable.")]
    store_status: Annotated[str, Field(description="Authenticated operational-store status or not-reported when unavailable.")]
    observed_at: Annotated[datetime, Field(description="UTC timestamp when health evidence was collected.")]


class VsphereProviderLifecycleCountsResponse(BaseModel):
    """Fields returned for redacted operational key lifecycle counts."""

    provider_id: Annotated[str, Field(description="Immutable UUID qualifying the counted operational namespace.")]
    status: Annotated[str, Field(description="Evidence state: available or not-reported.")]
    pre_active: Annotated[int | None, Field(description="Authenticated count of Pre-Active keys, or null when unavailable.")]
    active: Annotated[int | None, Field(description="Authenticated count of Active keys, or null when unavailable.")]
    total: Annotated[int | None, Field(description="Authenticated total operational-key count, or null when unavailable.")]
    observed_at: Annotated[datetime, Field(description="UTC timestamp when count evidence was collected.")]


class VsphereServerCertificateResponse(BaseModel):
    """Fields returned for the appliance-wide public KMIP server identity."""

    available: Annotated[bool, Field(description="Whether an issued public server certificate is currently available.")]
    hostname: Annotated[str, Field(description="Configured DNS hostname of the shared KMIP endpoint.")]
    fingerprint_sha256: Annotated[str, Field(description="Public server-certificate SHA-256 fingerprint, or empty when unavailable.")]
    certificate_pem: Annotated[str, Field(description="Public server certificate PEM, or empty when unavailable.")]
    chain_pem: Annotated[str, Field(description="Public issuer chain PEM, or empty when unavailable.")]
    expires_at: Annotated[datetime | None, Field(description="UTC server-certificate expiry, or null when unavailable.")]
