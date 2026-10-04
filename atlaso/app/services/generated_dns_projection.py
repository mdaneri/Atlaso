"""Project app-owned generated DNS directives into a prior configuration."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from ipaddress import ip_address, ip_network

_AUTHORITATIVE_PREFIX = "# atlaso-authoritative-config: "
_GENERATED_PTR_TRUE = "true"
_OWNED_DESCRIPTIONS = frozenset(
    {
        "Atlaso app-owned appliance FQDN record.",
        "Created from Certificate Authority portal endpoint.",
        "Created from ESX Storage endpoint.",
        "Created from ESXi PXE boot endpoint.",
        "Atlaso app-owned KMS/KMIP endpoint record.",
        "Managed by Atlaso LDAP service",
        "Created from NTP/NTS endpoint.",
        "Created from OpenID Connect provider endpoint.",
        "Created from VCF Offline Depot endpoint.",
        "Created from VCF private registry endpoint.",
    }
)


def dns_comparison_preview(config: str) -> str:
    """Compare DNS directives without generated ordering or SOA serial churn.

    Args:
        config: Rendered dnsmasq configuration.
    """
    settings: list[str] = []
    records: list[str] = []
    for line in config.splitlines():
        if line.startswith("# Atlaso authoritative serial"):
            continue
        directive = line.removeprefix(_AUTHORITATIVE_PREFIX)
        if directive.startswith("auth-soa="):
            fields = directive.split(",")
            if len(fields) >= 2:
                fields[0] = "auth-soa=<generated-serial>"
                line = (_AUTHORITATIVE_PREFIX if line.startswith(_AUTHORITATIVE_PREFIX) else "") + ",".join(fields)
        (records if _is_record_line(line) else settings).append(line)
    return "\n".join([*settings, *sorted(records)])


def project_generated_dns(
    previous_config: str,
    desired_config: str,
    previous_records: list[dict[str, str]],
    desired_records: list[dict[str, str]],
) -> str:
    """Apply generated DNS record changes while retaining unrelated prior config.

    Only records with an exact Atlaso ownership description participate. Their
    directives are removed from the previous config only when the exact rendered
    directive matches. Desired directives are copied from the desired config, so
    this function never renders caller-provided record data into configuration.

    ``generated_ptr`` metadata is honored only when it is the exact string
    ``"true"``. For A and AAAA rows it identifies the reverse record derived
    from that address; for PTR rows it identifies the explicit rendered PTR row.
    Callers must leave it false when a PTR may be operator-owned.

    Args:
        previous_config: Last-applied dnsmasq config text.
        desired_config: Current desired dnsmasq config text.
        previous_records: Previously generated DNS rows with exact provenance.
        desired_records: Currently generated DNS rows with exact provenance.
    """
    previous_owned = _record_directive_counts(previous_records)
    desired_owned = _record_directive_counts(desired_records)
    if previous_owned == desired_owned:
        return previous_config

    retained_lines: list[str] = []
    for line in previous_config.splitlines(keepends=True):
        directive = _unwrap_authoritative_line(line)
        if directive is not None and previous_owned[directive] > 0:
            previous_owned[directive] -= 1
            continue
        retained_lines.append(line)

    retained_directives = Counter(
        directive
        for line in retained_lines
        if (directive := _unwrap_authoritative_line(line)) is not None
    )
    for directive, count in retained_directives.items():
        desired_owned[directive] = max(0, desired_owned[directive] - count)

    additions = _desired_lines(desired_config, desired_owned)
    if not additions:
        return _refresh_authority("".join(retained_lines), previous_config, desired_records)

    output = "".join(retained_lines)
    if output and not output.endswith(("\n", "\r")):
        output += _newline_for(output)
    return _refresh_authority(output + "".join(additions), previous_config, desired_records)


def project_listener_addresses(
    config: str, replacements: dict[str, str], *, protected_ptr_owners: set[str] | None = None,
) -> str:
    """Move applied DNS listeners without activating pending DNS settings.

    Args:
        config: Applied configuration with proven generated records reconciled.
        replacements: Old to new addresses derived from selected Network intent.
        protected_ptr_owners: Explicit reverse-record owners that must remain unchanged.
    """
    output = []
    authority_servers = {
        line.removeprefix(_AUTHORITATIVE_PREFIX).partition("=")[2].split(",")[0]
        for line in config.splitlines()
        if line.removeprefix(_AUTHORITATIVE_PREFIX).startswith("auth-server=")
    }
    listeners = {line.partition("=")[2] for line in config.splitlines() if line.startswith("listen-address=")}
    for line in config.splitlines(keepends=True):
        value = line.rstrip("\r\n")
        prefix = _AUTHORITATIVE_PREFIX if value.startswith(_AUTHORITATIVE_PREFIX) else ""
        directive = value.removeprefix(prefix) if prefix else value
        ending = line[len(value):]
        if value.startswith("listen-address="):
            address = value.partition("=")[2]
            if address in replacements:
                line = f"listen-address={replacements[address]}{ending}"
        elif prefix and directive.startswith("host-record="):
            name, separator, address = directive.partition("=")[2].partition(",")
            if separator and name in authority_servers and address in listeners and address in replacements:
                line = f"{prefix}host-record={name},{replacements[address]}{ending}"
        elif directive.startswith("ptr-record="):
            reverse, separator, name = directive.partition("=")[2].partition(",")
            for old, new in replacements.items():
                if (separator and reverse not in (protected_ptr_owners or set())
                        and name in authority_servers and old in listeners and reverse == ip_address(old).reverse_pointer):
                    line = f"{prefix}ptr-record={ip_address(new).reverse_pointer},{name}{ending}"
                    break
        output.append(line)
    return "".join(output)


def _refresh_authority(config: str, previous: str, records: list[dict[str, str]]) -> str:
    """Advance applied SOA and include generated targets in their existing zones.

    Args:
        config: Reconciled configuration.
        previous: Previous applied configuration.
        records: Proven generated target records.
    """
    if config == previous:
        return config
    output = []
    for line in config.splitlines(keepends=True):
        value = line.rstrip("\r\n")
        prefix = _AUTHORITATIVE_PREFIX if value.startswith(_AUTHORITATIVE_PREFIX) else ""
        directive = value.removeprefix(prefix) if prefix else value
        ending = line[len(value):]
        if directive.startswith("auth-soa="):
            serial, separator, remainder = directive.partition("=")[2].partition(",")
            if serial.isdecimal() and separator:
                directive = f"auth-soa={(int(serial) + 1) % (2**32)},{remainder}"
        elif directive.startswith("auth-zone="):
            parts = directive.partition("=")[2].split(",")
            zone = parts[0]
            networks = [ip_network(value, strict=False) for value in parts[1:]]
            for record in records:
                if record.get("record_type") not in {"A", "AAAA"}:
                    continue
                name = record.get("hostname", "")
                if name != zone and not name.endswith(f".{zone}"):
                    continue
                address = ip_address(record["address"])
                if not any(address in network for network in networks if network.version == address.version):
                    network = ip_network(f"{address}/{address.max_prefixlen}")
                    networks.append(network)
                    parts.append(str(network))
            directive = "auth-zone=" + ",".join(parts)
        output.append(prefix + directive + ending)
    return "".join(output)


def defer_dns_record_publication(previous_config: str, desired_config: str) -> str:
    """Use desired settings while retaining the prior DNS records verbatim.

    This supports protected network handoff: candidate listeners and other
    dnsmasq settings can be validated with the new Network state while service
    records continue to describe the previously applied listeners until
    readiness succeeds.

    Args:
        previous_config: Last-applied dnsmasq config text.
        desired_config: Candidate dnsmasq config text.
    """
    previous_records = [
        line
        for line in previous_config.splitlines(keepends=True)
        if _is_record_line(line)
    ]
    desired_lines = desired_config.splitlines(keepends=True)
    first_record_index = next(
        (index for index, line in enumerate(desired_lines) if _is_record_line(line)),
        None,
    )
    candidate_lines = [line for line in desired_lines if not _is_record_line(line)]
    insertion_index = (
        sum(
            not _is_record_line(line)
            for line in desired_lines[:first_record_index]
        )
        if first_record_index is not None
        else len(candidate_lines)
    )
    projected_lines = [*candidate_lines[:insertion_index], *previous_records, *candidate_lines[insertion_index:]]
    output = "".join(projected_lines)
    if previous_records and output and not output.endswith(("\n", "\r")):
        output += _newline_for(output)
    return output


def _record_directive_counts(records: Iterable[dict[str, str]]) -> Counter[str]:
    """Build counts of exact rendered directives proven app-owned.

    Args:
        records: DNS rows supplied by the caller.
    """
    directives: Counter[str] = Counter()
    for record in records:
        if record.get("description") not in _OWNED_DESCRIPTIONS:
            continue
        hostname = record.get("hostname", "")
        record_type = record.get("record_type", "").upper()
        address = record.get("address", "")
        if not hostname or not address:
            continue
        if record_type in {"A", "AAAA", "CNAME"}:
            directive = (
                f"cname={hostname},{address}"
                if record_type == "CNAME"
                else f"host-record={hostname},{address}"
            )
            directives[directive] += 1
            if record_type in {"A", "AAAA"} and record.get("generated_ptr") == _GENERATED_PTR_TRUE:
                try:
                    reverse_name = ip_address(address).reverse_pointer
                except ValueError:
                    continue
                directives[f"ptr-record={reverse_name},{hostname}"] += 1
        elif record_type == "PTR" and record.get("generated_ptr") == _GENERATED_PTR_TRUE:
            directives[f"ptr-record={hostname},{address.strip().strip('.').lower()}"] += 1
    return directives


def _desired_lines(config: str, needed: Counter[str]) -> list[str]:
    """Select desired config lines matching exact owned directives.

    Args:
        config: Rendered desired dnsmasq configuration.
        needed: Directive multiplicities still missing from the projected config.
    """
    selected: list[str] = []
    for line in config.splitlines(keepends=True):
        directive = _unwrap_authoritative_line(line)
        if directive is None or needed[directive] <= 0:
            continue
        selected.append(line)
        needed[directive] -= 1
    return selected


def _unwrap_authoritative_line(line: str) -> str | None:
    """Return a dnsmasq directive, unwrapping the authority renderer comment.

    Args:
        line: One rendered config line, including its line ending if present.
    """
    value = line.rstrip("\r\n")
    if value.startswith(_AUTHORITATIVE_PREFIX):
        value = value[len(_AUTHORITATIVE_PREFIX) :]
    if value.startswith(_RECORD_DIRECTIVE_PREFIXES):
        return value
    return None


_RECORD_DIRECTIVE_PREFIXES = (
    "host-record=",
    "cname=",
    "ptr-record=",
    "txt-record=",
    "srv-host=",
    "mx-host=",
    "caa-record=",
)


def _is_record_line(line: str) -> bool:
    """Return whether a line renders a DNS record directive.

    Args:
        line: One rendered config line.
    """
    return _unwrap_authoritative_line(line) is not None


def _newline_for(config: str) -> str:
    """Return the line ending used by the existing config, defaulting to LF.

    Args:
        config: Existing rendered config.
    """
    return "\r\n" if "\r\n" in config else "\n"
