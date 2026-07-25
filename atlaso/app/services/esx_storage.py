"""Desired-state validation and rendering for the dual-stack ESX NFS service."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from ipaddress import ip_address, ip_interface, ip_network
import json
from pathlib import PurePosixPath
import re
from typing import Any, Iterable

from atlaso.app.models import EsxNfsShare, EsxStorageSettings, EsxStorageVolume


ESX_STORAGE_STAGED_CONFIG_PATH = "/var/lib/atlaso/apply/esx-storage/atlaso-esx-storage.json"
ESX_STORAGE_MOUNT_ROOT = "/mnt/atlaso-esx-storage"
ESX_STORAGE_EXPORT_ROOT = "/srv/atlaso/esx-storage"
ESX_STORAGE_DNS_DESCRIPTION = "Created from ESX Storage endpoint."
ESX_STORAGE_FORMAT_CONFIRMATION_PREFIX = "FORMAT"
ESX_STORAGE_RESERVED_MOUNT_PATHS = {
    "/mnt/atlaso-vcf-backups": "VCF Backups",
    "/mnt/atlaso-vcf-offline-depot": "VCF Offline Depot / VCFDT",
}
ADDRESS_FAMILIES = ("ipv4", "ipv6")
ANY_CLIENT_NETWORK = {"ipv4": "0.0.0.0/0", "ipv6": "::/0"}
NFS_VERSIONS = ("3", "4.1")


@dataclass(frozen=True)
class StorageInterface:
    name: str
    ipv4: tuple[str, ...] = ()
    ipv6: tuple[str, ...] = ()


def rpcbind_required(shares: Iterable[EsxNfsShare]) -> bool:
    """Return whether an enabled NFS 3 share requires rpcbind at runtime."""

    return any(share.enabled is not False and share.preferred_nfs_version == "3" for share in shares)


def split_lines(value: str | Iterable[str] | None) -> list[str]:
    if value is None:
        return []
    values = value if not isinstance(value, str) else value.replace(",", "\n").splitlines()
    return list(dict.fromkeys(str(item).strip() for item in values if str(item).strip()))


def storage_slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")
    if not slug:
        raise ValueError("A name must contain at least one letter or number.")
    return slug[:63]


def normalize_relative_path(value: str) -> str:
    raw = value.strip().replace("\\", "/").strip("/")
    if not raw:
        raise ValueError("Share path is required and cannot be the volume root.")
    path = PurePosixPath(raw)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("Share path must be a contained relative path without traversal.")
    return path.as_posix()


def share_paths_overlap(left: str, right: str) -> bool:
    left_parts = PurePosixPath(normalize_relative_path(left)).parts
    right_parts = PurePosixPath(normalize_relative_path(right)).parts
    common = min(len(left_parts), len(right_parts))
    return left_parts[:common] == right_parts[:common]


def reserved_mount_owner(value: str) -> str:
    """Return the appliance service that exclusively owns a mounted path."""

    raw = value.strip()
    if not raw.startswith("/"):
        return ""
    path = PurePosixPath(raw)
    for reserved_path, owner in ESX_STORAGE_RESERVED_MOUNT_PATHS.items():
        reserved = PurePosixPath(reserved_path)
        if path == reserved or reserved in path.parents:
            return owner
    return ""


def validate_mounted_volume_path(value: str) -> str:
    """Validate an existing ext4 mount before it can be claimed by ESX Storage."""

    mount_path = value.strip()
    if not PurePosixPath(mount_path or ".").is_absolute():
        raise ValueError("An existing ext4 volume requires its absolute mount path.")
    owner = reserved_mount_owner(mount_path)
    if owner:
        raise ValueError(f"Mount path {mount_path} is reserved for {owner} and cannot be used by ESX Storage.")
    return mount_path


def normalize_families(value: str | Iterable[str]) -> list[str]:
    families = split_lines(value)
    invalid = [family for family in families if family not in ADDRESS_FAMILIES]
    if invalid:
        raise ValueError(f"Unsupported address families: {', '.join(invalid)}")
    return [family for family in ADDRESS_FAMILIES if family in families]


def validate_clients(values: str | Iterable[str], family: str) -> list[str]:
    expected_version = 4 if family == "ipv4" else 6
    clients: list[str] = []
    for value in split_lines(values):
        try:
            network = ip_network(value, strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid {family.upper()} VMkernel client IP/CIDR: {value}") from exc
        if network.version != expected_version:
            raise ValueError(f"{value} does not match the enabled {family.upper()} family.")
        clients.append(str(network))
    return clients


def valid_clients_or_empty(values: str | Iterable[str], family: str) -> list[str]:
    try:
        return validate_clients(values, family)
    except ValueError:
        return []


def effective_clients(values: str | Iterable[str], family: str) -> list[str]:
    """Return the configured allowlist, or the explicit any-client network."""
    return valid_clients_or_empty(values, family) or [ANY_CLIENT_NETWORK[family]]


def interface_addresses(interface: StorageInterface, family: str) -> list[str]:
    values = interface.ipv4 if family == "ipv4" else interface.ipv6
    result: list[str] = []
    for value in values:
        try:
            result.append(str(ip_interface(value).ip) if "/" in value else str(ip_address(value)))
        except ValueError:
            continue
    return list(dict.fromkeys(result))


def target_token(address: str, naming_mode: str, interface_name: str) -> str:
    if naming_mode == "interface":
        return storage_slug(interface_name)
    parsed = ip_address(address)
    if parsed.version == 4:
        return str(parsed).replace(".", "-")
    return "-".join(format(int(group, 16), "x") for group in parsed.exploded.split(":"))


def target_hostname(service_hostname: str, token: str) -> str:
    hostname = service_hostname.strip().lower().rstrip(".")
    if "." not in hostname:
        raise ValueError("ESX Storage hostname must be a fully qualified DNS name.")
    label, domain = hostname.split(".", 1)
    suffix = f"-{storage_slug(token)}"
    if len(label) + len(suffix) > 63:
        digest = sha256(f"{label}{suffix}".encode()).hexdigest()[:8]
        label = f"{label[: max(1, 63 - len(suffix) - 9)].rstrip('-')}{suffix}-{digest}"
    else:
        label = f"{label}{suffix}"
    return f"{label}.{domain}"


def share_remote_path(share: EsxNfsShare | dict[str, Any]) -> str:
    version = share.preferred_nfs_version if isinstance(share, EsxNfsShare) else str(share["preferred_nfs_version"])
    slug = storage_slug(share.datastore_name if isinstance(share, EsxNfsShare) else str(share["datastore_name"]))
    return f"/{slug}" if version == "4.1" else f"{ESX_STORAGE_EXPORT_ROOT}/{slug}"


def connection_command(*, version: str, hostname: str, remote_path: str, datastore_name: str) -> str:
    if version == "4.1":
        return f"esxcli storage nfs41 add --hosts={hostname} --share={remote_path} --volume-name={datastore_name}"
    return f"esxcli storage nfs add --host={hostname} --share={remote_path} --volume-name={datastore_name}"


def powercli_connection_command(*, version: str, hostname: str, remote_path: str, datastore_name: str) -> str:
    def quote(value: str) -> str:
        return "'" + value.replace("'", "''") + "'"

    file_system_version = {"3": "NFS", "4.1": "NFS41"}.get(version)
    if file_system_version is None:
        raise ValueError("PowerCLI connection commands require NFS 3 or NFS 4.1.")
    return (
        "New-Datastore -Nfs -VMHost $vmHost "
        f"-Name {quote(datastore_name)} -NfsHost {quote(hostname)} "
        f"-Path {quote(remote_path)} -FileSystemVersion {quote(file_system_version)}"
    )


def validate_storage_state(
    settings: EsxStorageSettings,
    volumes: list[EsxStorageVolume],
    shares: list[EsxNfsShare],
    interfaces: dict[str, StorageInterface],
    *,
    dns_enabled: bool,
) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    if settings.enabled and not dns_enabled:
        errors.append("DNS desired state must be enabled before ESX Storage can be applied.")
    if settings.enabled and "." not in settings.hostname.strip().rstrip("."):
        errors.append("ESX Storage service hostname must be a fully qualified DNS name.")
    if settings.enabled and not any(share.enabled for share in shares):
        errors.append("Enable at least one NFS datastore share.")

    volume_by_id = {volume.id: volume for volume in volumes}
    enabled_shares = [share for share in shares if share.enabled]
    seen_names: set[str] = set()
    for share in enabled_shares:
        name_key = share.datastore_name.strip().casefold()
        if name_key in seen_names:
            errors.append(f"Datastore name {share.datastore_name!r} is duplicated.")
        seen_names.add(name_key)
        volume = volume_by_id.get(share.volume_id)
        if volume is None:
            errors.append(f"Datastore {share.datastore_name} does not reference an existing volume.")
            continue
        try:
            normalize_relative_path(share.relative_path)
        except ValueError as exc:
            errors.append(f"Datastore {share.datastore_name}: {exc}")
        if share.preferred_nfs_version not in NFS_VERSIONS:
            errors.append(f"Datastore {share.datastore_name} must use NFS 3 or NFS 4.1.")
        interface = interfaces.get(share.interface_name)
        if interface is None:
            errors.append(f"Datastore {share.datastore_name} selects unavailable interface/VLAN {share.interface_name!r}.")
            continue
        try:
            families = normalize_families(share.address_families)
        except ValueError as exc:
            errors.append(f"Datastore {share.datastore_name}: {exc}")
            continue
        if not families:
            errors.append(f"Datastore {share.datastore_name} must enable IPv4, IPv6, or both.")
        for family in families:
            if not interface_addresses(interface, family):
                errors.append(f"Datastore {share.datastore_name} enables {family.upper()} but {share.interface_name} has no {family.upper()} address.")
            raw_clients = share.ipv4_clients if family == "ipv4" else share.ipv6_clients
            try:
                validate_clients(raw_clients, family)
            except ValueError as exc:
                errors.append(f"Datastore {share.datastore_name}: {exc}")

    for index, left in enumerate(enabled_shares):
        for right in enabled_shares[index + 1 :]:
            if left.volume_id != right.volume_id:
                continue
            try:
                overlaps = share_paths_overlap(left.relative_path, right.relative_path)
            except ValueError:
                continue
            if overlaps:
                errors.append(f"Datastores {left.datastore_name} and {right.datastore_name} have overlapping export paths on the same volume.")

    for volume in volumes:
        if volume.source_type == "blank_disk" and not volume.stable_device_id.startswith("/dev/disk/by-id/"):
            errors.append(f"Volume {volume.name} must use a stable /dev/disk/by-id identity.")
        if volume.source_type == "mounted_ext4":
            try:
                validate_mounted_volume_path(volume.mount_path)
            except ValueError as exc:
                errors.append(f"Existing volume {volume.name}: {exc}")
        if not any(share.volume_id == volume.id for share in enabled_shares):
            warnings.append(f"Volume {volume.name} has no enabled datastore share.")
    return list(dict.fromkeys(errors)), list(dict.fromkeys(warnings))


def render_manifest(
    settings: EsxStorageSettings,
    volumes: list[EsxStorageVolume],
    shares: list[EsxNfsShare],
    interfaces: dict[str, StorageInterface],
    *,
    dns_enabled: bool,
    dns_naming_mode: str = "ip",
) -> dict[str, Any]:
    errors, warnings = validate_storage_state(settings, volumes, shares, interfaces, dns_enabled=dns_enabled)
    volume_by_id = {volume.id: volume for volume in volumes}
    rendered_shares: list[dict[str, Any]] = []
    for share in shares:
        volume = volume_by_id.get(share.volume_id)
        interface = interfaces.get(share.interface_name, StorageInterface(share.interface_name))
        try:
            families = normalize_families(share.address_families)
        except ValueError:
            families = []
        listeners = {family: interface_addresses(interface, family) if family in families else [] for family in ADDRESS_FAMILIES}
        hostnames = {
            family: [target_hostname(settings.hostname, target_token(address, dns_naming_mode, share.interface_name)) for address in listeners[family]]
            for family in ADDRESS_FAMILIES
        }
        remote_path = share_remote_path(share)
        commands = {
            family: [
                connection_command(
                    version=share.preferred_nfs_version,
                    hostname=hostname,
                    remote_path=remote_path,
                    datastore_name=share.datastore_name,
                )
                for hostname in hostnames[family]
            ]
            for family in ADDRESS_FAMILIES
        }
        powercli_commands = {
            family: [
                powercli_connection_command(
                    version=share.preferred_nfs_version,
                    hostname=hostname,
                    remote_path=remote_path,
                    datastore_name=share.datastore_name,
                )
                for hostname in hostnames[family]
            ]
            for family in ADDRESS_FAMILIES
        }
        rendered_shares.append(
            {
                "id": share.id,
                "datastore_name": share.datastore_name,
                "slug": storage_slug(share.datastore_name),
                "volume_id": share.volume_id,
                "volume_name": volume.name if volume else "",
                "relative_path": share.relative_path,
                "source_path": str(PurePosixPath(volume.mount_path if volume else "") / share.relative_path),
                "bind_path": f"{ESX_STORAGE_EXPORT_ROOT}/{storage_slug(share.datastore_name)}",
                "remote_path": remote_path,
                "preferred_nfs_version": share.preferred_nfs_version,
                "interface_name": share.interface_name,
                "address_families": families,
                "listeners": listeners,
                "target_hostnames": hostnames,
                "clients": {
                    "ipv4": effective_clients(share.ipv4_clients, "ipv4") if "ipv4" in families else [],
                    "ipv6": effective_clients(share.ipv6_clients, "ipv6") if "ipv6" in families else [],
                },
                "connection_commands": commands,
                "powercli_commands": powercli_commands,
                "enabled": share.enabled,
            }
        )
    rendered_volumes = [
        {
            "id": volume.id,
            "name": volume.name,
            "slug": storage_slug(volume.name),
            "source_type": volume.source_type,
            "stable_device_id": volume.stable_device_id,
            "fingerprint": {
                "model": volume.device_model,
                "serial": volume.device_serial,
                "wwn": volume.device_wwn,
                "size_bytes": volume.capacity_bytes,
            },
            "filesystem_uuid": volume.filesystem_uuid,
            "filesystem_label": volume.filesystem_label,
            "mount_path": volume.mount_path or f"{ESX_STORAGE_MOUNT_ROOT}/{storage_slug(volume.name)}",
            "state": volume.state,
            "applied": volume.applied,
            "requires_format": volume.source_type == "blank_disk" and not volume.filesystem_uuid,
        }
        for volume in volumes
    ]
    return {
        "schema_version": 1,
        "enabled": settings.enabled,
        "hostname": settings.hostname.strip().lower().rstrip("."),
        "dns_naming_mode": dns_naming_mode,
        "nfs": {"versions": ["3", "4.1"], "transport": "tcp", "mountd_port": 20048, "auth": "AUTH_SYS", "ipv4": True, "ipv6": True},
        "volumes": rendered_volumes,
        "shares": rendered_shares,
        "validation": {"errors": errors, "warnings": warnings},
    }


def manifest_json(manifest: dict[str, Any]) -> str:
    return json.dumps(manifest, indent=2, sort_keys=True) + "\n"


def manifest_hash(manifest: dict[str, Any]) -> str:
    return sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def format_authorization(*, job_id: str, manifest: dict[str, Any], volume: dict[str, Any], confirmation: str) -> dict[str, str]:
    expected = f"{ESX_STORAGE_FORMAT_CONFIRMATION_PREFIX} {volume['name']}"
    if confirmation != expected:
        raise ValueError(f"Formatting {volume['name']} requires the exact confirmation {expected!r}.")
    if not volume.get("requires_format"):
        raise ValueError(f"Volume {volume['name']} does not require formatting.")
    return {
        "job_id": job_id,
        "manifest_sha256": manifest_hash(manifest),
        "stable_device_id": str(volume["stable_device_id"]),
        "confirmation": confirmation,
    }


def desired_dns_records(manifest: dict[str, Any]) -> list[dict[str, str]]:
    target_records: list[dict[str, str]] = []
    canonical_records: list[dict[str, str]] = []
    for share in manifest.get("shares", []):
        if not share.get("enabled"):
            continue
        for family in ADDRESS_FAMILIES:
            record_type = "A" if family == "ipv4" else "AAAA"
            for hostname, address in zip(share["target_hostnames"][family], share["listeners"][family], strict=True):
                item = {"hostname": hostname, "record_type": record_type, "address": address}
                if item not in target_records:
                    target_records.append(item)
                canonical = {"hostname": manifest["hostname"], "record_type": record_type, "address": address}
                if canonical not in canonical_records:
                    canonical_records.append(canonical)
    return [*canonical_records, *target_records]


def firewall_rule_specs(manifest: dict[str, Any]) -> list[dict[str, str]]:
    rules: list[dict[str, str]] = []
    for share in manifest.get("shares", []):
        if not share.get("enabled"):
            continue
        ports = "2049" if share["preferred_nfs_version"] == "4.1" else "111,20048,2049"
        for family in ADDRESS_FAMILIES:
            for client in share["clients"][family]:
                rules.append(
                    {
                        "name": f"esx-nfs-{share['slug']}-{family}-{len(rules) + 1}",
                        "interface_name": share["interface_name"],
                        "source": client,
                        "source_expression": f"{'ip' if family == 'ipv4' else 'ip6'} saddr {client}",
                        "protocol": "tcp",
                        "ports": ports,
                        "family": family,
                    }
                )
    return rules


def normalize_disk_inventory_entry(entry: dict[str, Any], *, claimed_ids: set[str] | None = None) -> dict[str, Any]:
    filesystem_uuid = str(entry.get("filesystem_uuid") or "")
    stable_id = str(entry.get("stable_device_id") or entry.get("by_id") or (f"UUID={filesystem_uuid}" if filesystem_uuid else ""))
    reasons: list[str] = []
    candidate_type = str(entry.get("candidate_type") or "blank_disk")
    if candidate_type == "mounted_ext4":
        if entry.get("filesystem_type") != "ext4" or not entry.get("mount_path"):
            reasons.append("not a mounted ext4 filesystem")
        if entry.get("os_related"):
            reasons.append("is related to the operating-system disk")
        owner = reserved_mount_owner(str(entry.get("mount_path") or ""))
        if owner:
            reasons.append(f"is reserved for {owner}")
    else:
        if not stable_id.startswith("/dev/disk/by-id/"):
            reasons.append("no stable /dev/disk/by-id identity")
        if str(entry.get("type") or "disk") != "disk":
            reasons.append("not a whole disk")
        for key, label in [
            ("partitions", "has partitions"),
            ("filesystem_type", "has a filesystem"),
            ("mount_path", "is mounted"),
            ("swap", "is swap"),
            ("lvm", "belongs to LVM"),
            ("raid", "belongs to RAID"),
            ("holders", "has device holders"),
            ("os_related", "is related to the operating-system disk"),
        ]:
            if entry.get(key):
                reasons.append(label)
    if stable_id in (claimed_ids or set()):
        reasons.append("is already claimed by ESX Storage")
    return {
        "stable_device_id": stable_id,
        "device_path": str(entry.get("device_path") or entry.get("path") or ""),
        "model": str(entry.get("model") or ""),
        "serial": str(entry.get("serial") or ""),
        "wwn": str(entry.get("wwn") or ""),
        "size_bytes": int(entry.get("size_bytes") or entry.get("size") or 0),
        "filesystem_type": str(entry.get("filesystem_type") or ""),
        "filesystem_uuid": filesystem_uuid,
        "filesystem_label": str(entry.get("filesystem_label") or ""),
        "mount_path": str(entry.get("mount_path") or ""),
        "candidate_type": candidate_type,
        "eligible": not reasons,
        "eligibility_reason": "; ".join(reasons),
    }


def parse_disk_inventory_output(stdout: str, *, claimed_ids: set[str] | None = None) -> list[dict[str, Any]]:
    """Parse the helper envelope and return normalized, safety-qualified candidates."""
    lines = [line for line in (stdout or "").splitlines() if line.strip()]
    if not lines:
        return []
    payload = json.loads(lines[-1])
    if not isinstance(payload, list):
        raise ValueError("ESX Storage disk inventory must be a JSON list.")
    return [normalize_disk_inventory_entry(item, claimed_ids=claimed_ids) for item in payload if isinstance(item, dict)]


def select_inventory_candidate(
    inventory: list[dict[str, Any]],
    *,
    source_type: str,
    stable_device_id: str,
    mount_path: str,
) -> dict[str, Any]:
    """Resolve a submitted volume to the exact eligible helper inventory row."""
    stable_id = stable_device_id.strip()
    mounted_path = mount_path.strip()
    matches = [
        item
        for item in inventory
        if item.get("candidate_type") == source_type
        and (
            (source_type == "blank_disk" and item.get("stable_device_id") == stable_id)
            or (source_type == "mounted_ext4" and item.get("mount_path") == mounted_path)
        )
    ]
    if len(matches) != 1:
        identity = stable_id if source_type == "blank_disk" else mounted_path
        raise ValueError(f"{identity or 'The selected source'} is not present as one eligible {source_type} inventory candidate.")
    candidate = matches[0]
    if not candidate.get("eligible"):
        raise ValueError(str(candidate.get("eligibility_reason") or "The selected storage source is not eligible."))
    return candidate
