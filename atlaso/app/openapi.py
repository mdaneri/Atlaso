"""OpenAPI metadata and enforcement helpers for Atlaso's versioned API."""

from inspect import getdoc
from typing import Any

from fastapi.routing import APIRoute

from atlaso.app.schemas import ProblemDetails


class DocumentedAPIRoute(APIRoute):
    """Use an endpoint's explicit documentation as its success-response summary."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize the documented apiroute."""
        endpoint = kwargs.get("endpoint")
        endpoint_doc = getdoc(endpoint) if endpoint is not None else None
        if kwargs.get("response_description", "Successful Response") == "Successful Response" and endpoint_doc:
            first_paragraph = endpoint_doc.split("\n\n", maxsplit=1)[0].replace("\n", " ").strip()
            if kwargs.get("status_code") == 204:
                kwargs["response_description"] = (
                    f"{first_paragraph} The operation completed successfully and returns no response body."
                )
            else:
                kwargs["response_description"] = (
                    f"{first_paragraph} The response body matches the documented success schema."
                )
        super().__init__(*args, **kwargs)


API_VALIDATION_RESPONSES = {
    422: {
        "model": ProblemDetails,
        "description": (
            "The request parameters or body failed Atlaso validation. The response includes a request ID "
            "that can be correlated with operational logs."
        ),
    }
}


OPENAPI_TAGS = [
    {"name": "Appliance", "description": "Read public Atlaso appliance release and build provenance metadata."},
    {"name": "Auth", "description": "Issue API bearer tokens and inspect the authenticated Atlaso identity."},
    {"name": "API Tokens", "description": "Create, inspect, revoke, and retire scoped Atlaso API tokens."},
    {"name": "Dashboard", "description": "Read the appliance operations summary exposed to API consumers."},
    {"name": "Monitor", "description": "Read bounded appliance CPU, memory, network, and disk activity history."},
    {"name": "Interfaces", "description": "Inspect and manage saved physical-interface desired state."},
    {"name": "VLANs", "description": "Inspect and manage VLAN-interface desired state."},
    {"name": "Routes", "description": "Inspect and manage static-route desired state."},
    {"name": "NAT", "description": "Inspect and manage explicit IPv4 masquerade desired state."},
    {"name": "WAN", "description": "Inspect and manage interface-level WAN simulation policies."},
    {"name": "DNS", "description": "Inspect, validate, and manage DNS desired state."},
    {"name": "DHCP", "description": "Inspect, validate, and manage DHCP scopes, options, leases, and reservations."},
    {"name": "Firewall", "description": "Inspect, validate, and manage appliance firewall desired state."},
    {"name": "Services", "description": "Inspect and operate registered appliance services."},
    {"name": "Logs", "description": "Read bounded, redacted operational log output."},
    {"name": "Audit", "description": "Read attributable Atlaso audit events."},
    {"name": "Jobs", "description": "Create, inspect, and cancel durable Atlaso tasks."},
    {"name": "Settings", "description": "Inspect and update appliance settings desired state."},
    {"name": "CA", "description": "Inspect and manage the integrated certificate authority."},
    {"name": "LDAP", "description": "Inspect and manage Atlaso-managed LDAP organizations, users, and groups."},
    {"name": "OIDC Provider", "description": "Administer the constrained Atlaso OpenID Connect provider."},
    {"name": "ESXi PXE", "description": "Manage ESXi Kickstarts, host references, and installer media."},
    {"name": "network-boot", "description": "Manage Network Boot environments, discovered hosts, and reports."},
    {"name": "ESX Storage", "description": "Inspect disks and manage NFS datastore desired state."},
    {"name": "VCF Backups", "description": "Inspect VCF Backup service state and binding details."},
    {"name": "VCF Offline Depot", "description": "Inspect VCF Offline Depot service and repository state."},
    {"name": "VCF Private Registry", "description": "Inspect VCF Private Registry desired state."},
    {"name": "Backup Restore", "description": "Export or restore bounded Atlaso settings archives."},
]
