---
title: Use the Atlaso API
description: Authenticate safely, explore the versioned API, and interpret Atlaso responses and mutation boundaries.
audience:
  - operator
  - maintainer
status: current
---

# Use the Atlaso API

Atlaso publishes its supported REST contract under `/api/v1`. Use the interactive Swagger UI at `/api/docs`, the
alternative ReDoc view at `/api/redoc`, or the machine-readable OpenAPI 3.1 document at `/openapi.json`. The schema
contains only versioned `/api/v1` operations; browser pages and service-specific protocol routes remain supported but
are documented in their service guides instead of Swagger.

The authenticated browser application is rooted at `/ui/management`, and app-owned public pages are rooted at
`/ui/public`. Those presentation namespaces do not change API URLs or make management APIs available on Public Services
listeners. See [Public Services](../services/public-services.md) for the listener and compatibility contract.

## Create and protect an API token

1. Sign in to the management UI and open **Authentication > API Tokens**.
2. Create a token with a clear purpose, the shortest practical lifetime, and only the scopes required by the client.
3. Copy the token when it is shown. Atlaso displays the secret once and cannot recover it later.
4. In `/api/docs`, select **Authorize**, paste the token value, and authorize the bearer scheme.
5. Revoke the token when its client is retired or its value may have been exposed. Create a replacement instead of
   trying to recover or reuse the old secret.

Treat bearer tokens like passwords. Do not put them in command history, source files, screenshots, issue reports,
authenticated URLs, or shared logs. Prefer a secret manager for automation and an environment variable for short-lived
interactive work.

## Call the API safely

The examples below use the RFC 1918 lab address `192.168.50.10` and read the token from the environment. Replace the
address with the appliance management address; do not replace the token variable with a literal secret.

=== "curl"

    ```bash
    export ATLASO_TOKEN="<read securely from your secret manager>"
    curl --fail-with-body --silent --show-error \
      --header "Authorization: Bearer ${ATLASO_TOKEN}" \
      --header "Accept: application/json" \
      https://192.168.50.10/api/v1/dashboard
    ```

=== "PowerShell"

    ```powershell
    $headers = @{
        Authorization = "Bearer $env:ATLASO_TOKEN"
        Accept = "application/json"
    }
    Invoke-RestMethod -Uri "https://192.168.50.10/api/v1/dashboard" -Headers $headers
    ```

Use a certificate trusted by the client. Do not disable TLS verification in saved automation. Examples that create or
change resources should use RFC 1918 lab addresses such as `192.168.50.0/24` and be reviewed against the operation's
documented authorization and apply behavior before execution.

### Configure management UI exposure on access interfaces

`PhysicalInterfaceResponse` and `VlanCreate`/`VlanResponse` include
`access_management_ui_enabled`. Set it only on an access-role, access-mode physical interface or an access-role VLAN.
The switch exposes the authenticated `/ui/management` browser plane without changing that interface's access routing or
public-service eligibility. A management-role physical interface ignores the switch because it exposes management
inherently. Network apply rejects a configuration that would leave no effective management UI listener.

Physical-interface and VLAN role fields accept exactly `management`, `access`, `route`, or `unused`. The retired
`services` and `storage` values are rejected on new requests. Appliance startup and settings-archive restore map those
values to `access` only when reading compatible persisted state from an older Atlaso release.

### Update physical-interface desired state

`PATCH /api/v1/interfaces/physical/{name}` accepts the typed `PhysicalInterfaceUpdate` schema. Omit a property to keep
its saved value; use an empty string or `null` only for the documented CIDR and gateway fields that can be cleared.
Recognized role, mode, and IPv4-method spellings are case-insensitive. New requests reject the retired `services` and
`storage` roles; the legacy `routed` mode spelling remains supported. Atlaso rejects unsupported properties instead of
silently ignoring them.

Changing a physical interface's IPv4 or IPv6 CIDR automatically refreshes dependent desired-state addresses for DNS,
NTP/NTS, Certificate Authority, KMS, LDAP, OIDC, VCF services, ESX Storage, Web Terminal, matching DHCP scopes, and
Network Boot/PXE. Atlaso commits the interface and dependent rows as one transaction. If any dependent update fails,
none of those changes are saved. Removing an address family or converting an interface to trunk mode is rejected while
an enabled service, ESX Storage datastore, DHCP scope, or Network Boot/PXE listener still depends on the address;
administratively disabling an interface follows the same rule. Disabling a physical parent also evaluates bindings to
its enabled child VLANs. If other selected interfaces remain eligible, Atlaso removes only the ineligible service,
Web Terminal, or PXE selection. Disable or move a final binding first. The audit event names the dependent units that
were refreshed. This remains a desired-state edit: review the resulting network and service previews, then use global
Appliance Apply for host enforcement.

The internal Certificate Authority is the exception: if its last selected portal interface becomes ineligible, Atlaso
clears the public CA portal binding and app-owned alias while leaving internal CA custody enabled.

DHCP scope gateway, DNS, and NTP values remain operator-owned when they are valid and do not match a replaced interface
address. Interface edits update only blank or stale derived values. Enabled reservations that would otherwise leave
every enabled scope retain their host offset in the uniquely matching rebased scope; Atlaso updates app-owned
reservation DNS records in the same transaction and rejects ambiguous moves. When real scope rows exist, inactive
legacy global DHCP binding fields are retained for compatibility but do not constrain interface edits.

## Scopes and authorization

Each Swagger operation describes its required Atlaso scope or authentication posture. A token can call only operations
covered by its scopes; prefer a read-only token when the client does not mutate desired state. A valid token with
insufficient scope receives `403 Forbidden`. Missing, invalid, expired, or revoked credentials receive
`401 Unauthorized`.

## Understand responses

Successful responses use the operation's documented response model. Common failure statuses include:

| Status | Meaning |
| --- | --- |
| `400 Bad Request` | The request is unsafe, inconsistent, or cannot be processed in its current form. |
| `401 Unauthorized` | Bearer authentication is missing or invalid. |
| `403 Forbidden` | The authenticated identity lacks the required scope or permission. |
| `404 Not Found` | The requested resource does not exist or is not visible to the caller. |
| `409 Conflict` | Current resource state conflicts with the requested transition. |
| `422 Unprocessable Content` | A parameter or request body failed Atlaso validation. |
| `423 Locked` | Another guarded operation owns the resource or global mutation boundary; wait for it to finish and retry. |
| `500 Internal Server Error` | An unexpected server failure occurred; correlate the request ID with appliance logs. |

Atlaso errors use the `ProblemDetails` contract:

    {
      "type": "https://atlaso.example/problems/validation",
      "title": "Request validation failed",
      "status": 422,
      "detail": "One or more request values are invalid.",
      "instance": "/api/v1/example",
      "error_code": "request_validation_failed",
      "request_id": "req_example123"
    }

The `X-Request-ID` response header and the `request_id` problem field identify the same request for troubleshooting.
Record them without recording credentials or sensitive payload values.

## Immediate and applied effects

Read each mutation's description before calling it. Some operations change application state immediately, some queue a
durable job, and some save desired state only. Desired-state edits do not mutate the host by themselves:
`/ui/management/appliance-apply` remains the reviewed global host-mutation workflow. A successful save means Atlaso
accepted the
desired state, not that the corresponding service is already applied. Follow returned job identifiers through the Jobs
or Tasks interfaces and verify terminal results.

Legacy `/api/v1/dns/apply`, `/api/v1/dhcp/apply`, and `/api/v1/firewall/apply` routes remain available for compatibility
but are intentionally absent from Swagger because they predate the reviewed global workflow. New clients must save
desired state and use `/ui/management/appliance-apply`; do not build new automation around the legacy direct-apply routes.

## Authorize one ESXi boot

`POST /api/v1/network-boot/esxi-hosts/{host_id}/authorize-boot-once` requires
`write:pxe` and accepts JSON containing the `boot_code` displayed by the exact
pending host-console attempt, for example `{"boot_code":"ABCD-EFGH"}`. Start
Network Boot and choose the assigned ESXi entry before calling this operation.
It does not modify desired state and does not replace global Appliance Apply.
The response contains only the host ID, issue and
expiry timestamps, and secret-free operator guidance; it never contains the
capability or a credential-bearing URL.

The authorization lasts ten minutes, is consumed by the first matching
Kickstart retrieval, and is bound to the exact applied host, full applied
Kickstart revision, applied HTTP listener, and generated boot attempt. A `409`
means the code is invalid or expired, the desired Host Reference has drifted,
or exact applied state is unavailable; start a new host attempt or review and
apply Network Boot state before retrying. Continue the intended host promptly
after a `202` response, and never collect PXE URLs from packet traces or
boot consoles in tickets, logs, screenshots, or automation output.

## Troubleshoot clients

- Confirm `/openapi.json` is reachable and every client URL begins with `/api/v1`.
- Check token expiry, revocation, and required scopes before replacing credentials.
- For `422`, compare parameter formats and allowed values with Swagger and inspect the returned `ProblemDetails`.
- For `423`, identify the active task and retry only after its terminal result.
- For unexpected failures, preserve the status, `error_code`, and request ID, then inspect Atlaso operational logs.

Atlaso preserves existing operation IDs, request and response shapes, authentication behavior, and versioned paths
within the published compatibility contract. Additive fields may appear. Clients should ignore unknown response fields
and must not depend on browser pages or non-`/api/v1` protocol routes as generated REST-client contracts.
