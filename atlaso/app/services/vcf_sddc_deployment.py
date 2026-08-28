"""Implement vcf sddc deployment service behavior."""

from __future__ import annotations

import hashlib
import http.client
import re
import socket
import ssl
import tarfile
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit, urlunsplit

SDDC_MANAGER_OVA_ROOT = Path("/mnt/atlaso-vcf-offline-depot/PROD/COMP/SDDC_MANAGER_VCF")
OVF_NS = "http://schemas.dmtf.org/ovf/envelope/1"
OVF = f"{{{OVF_NS}}}"
MANIFEST_LINE = re.compile(r"^(SHA1|SHA256|SHA512)\(([^)]+)\)=\s*([0-9a-fA-F]+)\s*$")
Progress = Callable[[int, str], None]
CancelCheck = Callable[[], bool]
DATASTORE_FREE_SPACE_BUFFER_BYTES = 512 * 1024 * 1024
NFC_UPLOAD_SOCKET_TIMEOUT_SECONDS = 30
DISK_PROVISIONING_MODES = {"thin", "thick"}


class VcfSddcDeploymentError(RuntimeError):
    """Report a vcf sddc deployment error."""
    pass


class VcfSddcDeploymentCancelled(VcfSddcDeploymentError):
    """Represent vcf sddc deployment cancelled."""
    pass


class VcfSddcPostImportError(VcfSddcDeploymentError):
    """Report a vcf sddc post import error.

    Attributes:
        vm_result: Vm result maintained by this vcfsddcpostimporterror.
    """
    def __init__(self, message: str, vm_result: dict[str, Any]) -> None:
        """Initialize the vcf sddc post import error.

        Args:
            message: Human-readable message associated with the operation.
            vm_result: Vm result consumed by init.
        """
        super().__init__(message)
        self.vm_result = vm_result


def _check_cancelled(cancelled: CancelCheck | None) -> None:
    """Check cancelled.

    Args:
        cancelled: Cancelled consumed by check cancelled.


    Raises:
        VcfSddcDeploymentCancelled: If the operation encounters an invalid state.
    """
    if cancelled and cancelled():
        raise VcfSddcDeploymentCancelled("SDDC Manager deployment was cancelled.")


class _LeaseProgress:
    """Represent lease progress.

    Attributes:
        lease: Lease maintained by this leaseprogress.
        value: Value maintained by this leaseprogress.
        lock: Lock maintained by this leaseprogress.
    """
    def __init__(self, lease: Any) -> None:
        """Initialize the lease progress.

        Args:
            lease: Lease consumed by init.
        """
        self.lease = lease
        self.value = 0
        self.lock = threading.Lock()

    def update(self, percent: int) -> None:
        """Update operation.

        Args:
            percent: Percent consumed by update.
        """
        with self.lock:
            self.value = max(self.value, max(0, min(99, int(percent))))
            self.lease.HttpNfcLeaseProgress(self.value)

    def heartbeat(self, stop_event: threading.Event) -> None:
        """Handle heartbeat.

        Args:
            stop_event: Stop event consumed by heartbeat.
        """
        while not stop_event.wait(5):
            try:
                self.update(self.value)
            except Exception:  # noqa: BLE001 - progress callbacks must not interrupt the vSphere transfer.
                return


@dataclass(frozen=True)
class OvfProperty:
    """Represent ovf property.

    Attributes:
        key: Key maintained by this ovfproperty.
        value_type: Value type maintained by this ovfproperty.
        label: Label maintained by this ovfproperty.
        description: Operator-facing purpose or context for the resource.
        default: Default maintained by this ovfproperty.
        qualifiers: Qualifiers maintained by this ovfproperty.
        password: Password maintained by this ovfproperty.
        user_configurable: User configurable maintained by this ovfproperty.
    """
    key: str
    value_type: str
    label: str
    description: str
    default: str
    qualifiers: str
    password: bool
    user_configurable: bool


@dataclass(frozen=True)
class OvfDeploymentOption:
    """Describe one target-supported OVF deployment option."""

    key: str
    label: str
    description: str


@dataclass(frozen=True)
class OvaDescriptor:
    """Represent ova descriptor.

    Attributes:
        path: Path maintained by this ovadescriptor.
        relative_path: Filesystem path used for relative.
        filename: Filename maintained by this ovadescriptor.
        size_bytes: Size size in bytes.
        vm_name: Vm name maintained by this ovadescriptor.
        ovf_member: Ovf member maintained by this ovadescriptor.
        manifest_member: Manifest member maintained by this ovadescriptor.
        networks: Networks maintained by this ovadescriptor.
        properties: Properties maintained by this ovadescriptor.
        files: Files maintained by this ovadescriptor.
    """
    path: str
    relative_path: str
    filename: str
    size_bytes: int
    vm_name: str
    ovf_member: str
    manifest_member: str
    networks: list[str]
    properties: list[OvfProperty]
    files: list[dict[str, Any]]
    deployment_options: list[OvfDeploymentOption] = field(default_factory=list)
    default_deployment_option: str = ""
    selected_deployment_option: str = ""
    ovf_environment_transports: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    product: str = ""
    product_version: str = ""

    def public_dict(self) -> dict[str, Any]:
        """Return public dict."""
        payload = asdict(self)
        payload["properties"] = [asdict(item) for item in self.properties]
        payload["deployment_options"] = [asdict(item) for item in self.deployment_options]
        return payload


def _attribute(element: ET.Element, name: str) -> str:
    """Return attribute.

    Args:
        element: Element consumed by attribute.
        name: Stable name identifying the resource or operation.
    """
    return str(element.attrib.get(f"{OVF}{name}") or element.attrib.get(name) or "")


def normalize_ova_path(value: str | Path, *, root: Path = SDDC_MANAGER_OVA_ROOT) -> Path:
    """Normalize ova path.

    Args:
        value: Candidate value consumed by normalize ova path.
        root: Repository or filesystem root searched by the operation.


    Returns:
        The normalize ova path result.

    Raises:
        VcfSddcDeploymentError: If the operation encounters an invalid state.
    """
    root_resolved = root.resolve()
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = root_resolved / candidate
    resolved = candidate.resolve(strict=True)
    if root_resolved != resolved and root_resolved not in resolved.parents:
        raise VcfSddcDeploymentError("Selected OVA must remain inside the SDDC Manager depot folder.")
    if not resolved.is_file() or resolved.suffix.lower() != ".ova":
        raise VcfSddcDeploymentError("Selected SDDC Manager artifact must be a regular .ova file.")
    return resolved


def inspect_ova(value: str | Path, *, root: Path = SDDC_MANAGER_OVA_ROOT) -> OvaDescriptor:
    """Return inspect ova.

    Args:
        value: Candidate value consumed by inspect ova.
        root: Repository or filesystem root searched by the operation.


    Raises:
        VcfSddcDeploymentError: If the operation encounters an invalid state.
    """
    path = normalize_ova_path(value, root=root)
    try:
        with tarfile.open(path, "r") as archive:
            members = {member.name: member for member in archive.getmembers() if member.isfile()}
            ovf_names = [name for name in members if name.lower().endswith(".ovf")]
            manifest_names = [name for name in members if name.lower().endswith(".mf")]
            if len(ovf_names) != 1:
                raise VcfSddcDeploymentError("The OVA must contain exactly one OVF descriptor.")
            if len(manifest_names) != 1:
                raise VcfSddcDeploymentError("The OVA must contain exactly one manifest.")
            ovf_file = archive.extractfile(members[ovf_names[0]])
            if ovf_file is None:
                raise VcfSddcDeploymentError("The OVA OVF descriptor could not be read.")
            root_element = ET.parse(ovf_file).getroot()
            properties: list[OvfProperty] = []
            for element in root_element.findall(f".//{OVF}Property"):
                if _attribute(element, "userConfigurable").lower() != "true":
                    continue
                properties.append(
                    OvfProperty(
                        key=_attribute(element, "key"),
                        value_type=_attribute(element, "type") or "string",
                        label=(element.findtext(f"{OVF}Label") or _attribute(element, "key")).strip(),
                        description=(element.findtext(f"{OVF}Description") or "").strip(),
                        default=_attribute(element, "value"),
                        qualifiers=_attribute(element, "qualifiers"),
                        password=_attribute(element, "password").lower() == "true",
                        user_configurable=True,
                    )
                )
            referenced: list[dict[str, Any]] = []
            for element in root_element.findall(f".//{OVF}References/{OVF}File"):
                href = _attribute(element, "href")
                if not href or href not in members:
                    raise VcfSddcDeploymentError(f"The OVA is missing referenced file {href or '(empty reference)' }.")
                referenced.append(
                    {
                        "id": _attribute(element, "id"),
                        "href": href,
                        "size_bytes": int(_attribute(element, "size") or members[href].size),
                    }
                )
            networks = [_attribute(item, "name") for item in root_element.findall(f".//{OVF}NetworkSection/{OVF}Network")]
            vm_name = (root_element.findtext(f".//{OVF}VirtualSystem/{OVF}Name") or path.stem).strip()
            product = (root_element.findtext(f".//{OVF}ProductSection/{OVF}Product") or "").strip()
            product_version = (root_element.findtext(f".//{OVF}ProductSection/{OVF}Version") or "").strip()
            transports: list[str] = []
            for section in root_element.findall(f".//{OVF}VirtualHardwareSection"):
                for transport in re.split(r"[\s,]+", _attribute(section, "transport")):
                    if transport and transport not in transports:
                        transports.append(transport)
    except (OSError, tarfile.TarError, ET.ParseError, ValueError) as exc:
        if isinstance(exc, VcfSddcDeploymentError):
            raise
        raise VcfSddcDeploymentError(f"Could not inspect the selected OVA: {exc}") from exc
    return OvaDescriptor(
        path=str(path),
        relative_path=path.relative_to(root.resolve()).as_posix(),
        filename=path.name,
        size_bytes=path.stat().st_size,
        vm_name=vm_name,
        ovf_member=ovf_names[0],
        manifest_member=manifest_names[0],
        networks=[name for name in networks if name],
        properties=properties,
        files=referenced,
        ovf_environment_transports=transports,
        product=product,
        product_version=product_version,
    )


def ova_inventory(*, root: Path = SDDC_MANAGER_OVA_ROOT) -> list[dict[str, Any]]:
    """Return ova inventory.

    Args:
        root: Repository or filesystem root searched by the operation.
    """
    if not root.exists():
        return []
    rows: list[dict[str, Any]] = []
    for path in sorted((item for item in root.rglob("*") if item.is_file() and item.suffix.lower() == ".ova"), key=lambda item: str(item).lower()):
        try:
            rows.append(inspect_ova(path, root=root).public_dict())
        except VcfSddcDeploymentError as exc:
            rows.append({"path": str(path), "relative_path": path.relative_to(root).as_posix(), "filename": path.name, "error": str(exc)})
    return rows


def validate_ova_manifest(descriptor: OvaDescriptor, *, progress: Progress | None = None, cancelled: CancelCheck | None = None) -> None:
    """Validate ova manifest.

    Args:
        descriptor: Candidate descriptor to validate.
        progress: Candidate progress to validate.
        cancelled: Candidate cancelled to validate.


    Raises:
        VcfSddcDeploymentError: If the operation encounters an invalid state.
    """
    algorithms = {"SHA1": "sha1", "SHA256": "sha256", "SHA512": "sha512"}
    path = Path(descriptor.path)
    with tarfile.open(path, "r") as archive:
        manifest_file = archive.extractfile(descriptor.manifest_member)
        if manifest_file is None:
            raise VcfSddcDeploymentError("The OVA manifest could not be read.")
        entries: list[tuple[str, str, str]] = []
        for raw_line in manifest_file.read().decode("utf-8", errors="strict").splitlines():
            if not raw_line.strip():
                continue
            match = MANIFEST_LINE.fullmatch(raw_line.strip())
            if not match:
                raise VcfSddcDeploymentError("The OVA manifest contains an unsupported entry.")
            entries.append((algorithms[match.group(1)], match.group(2), match.group(3).lower()))
        total = sum(archive.getmember(name).size for _, name, _ in entries)
        completed = 0
        for algorithm, name, expected in entries:
            try:
                member = archive.getmember(name)
            except KeyError as exc:
                raise VcfSddcDeploymentError(f"The OVA manifest references missing file {name}.") from exc
            source = archive.extractfile(member)
            if source is None:
                raise VcfSddcDeploymentError(f"The OVA manifest file {name} could not be read.")
            digest = hashlib.new(algorithm)
            while True:
                _check_cancelled(cancelled)
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                completed += len(chunk)
                if progress and total:
                    progress(min(10, int(completed / total * 10)), "validating-manifest")
            if digest.hexdigest().lower() != expected:
                raise VcfSddcDeploymentError(f"OVA manifest validation failed for {name}.")


def _fingerprint_tls_context() -> ssl.SSLContext:
    """Return fingerprint tls context."""
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def tls_sha256_fingerprint(address: str, port: int = 443, *, timeout: float = 10.0) -> str:
    """Return tls sha256 fingerprint.

    Args:
        address: Network address of the target service or interface.
        port: TCP or UDP port of the target service.
        timeout: Maximum time to wait for completion.
    """
    context = _fingerprint_tls_context()
    with socket.create_connection((address, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=address) as wrapped:
            certificate = wrapped.getpeercert(binary_form=True)
    digest = hashlib.sha256(certificate).hexdigest().upper()
    return ":".join(digest[index : index + 2] for index in range(0, len(digest), 2))


def _wait_task(task: Any, *, timeout: float = 900.0, cancelled: CancelCheck | None = None) -> Any:
    """Return wait task.

    Args:
        task: Task supplied by the caller.
        timeout: Maximum time to wait for completion.
        cancelled: Callback that reports whether cancellation was requested.

    Raises:
        VcfSddcDeploymentError: If the operation encounters an invalid state.
    """
    started = time.monotonic()
    while str(task.info.state) not in {"success", "error"}:
        _check_cancelled(cancelled)
        if time.monotonic() - started > timeout:
            raise VcfSddcDeploymentError("Timed out waiting for the vSphere task.")
        time.sleep(1)
    if str(task.info.state) == "error":
        error = task.info.error
        detail = _safe_vsphere_message(error) if error else "vSphere task failed."
        raise VcfSddcDeploymentError(detail)
    return task.info.result


def _safe_vsphere_message(exc: Exception) -> str:
    """Return safe vsphere message.

    Args:
        exc: Exception that caused the current failure path.
    """
    message = str(getattr(exc, "msg", "") or getattr(exc, "localizedMessage", "") or "")
    if not message:
        fault_message = getattr(exc, "faultMessage", None)
        if fault_message:
            parts = [str(getattr(item, "message", "") or "") for item in fault_message]
            message = "; ".join(part for part in parts if part)
    if not message:
        message = str(exc)
    message = re.sub(r"\s+", " ", message).strip()
    return message or exc.__class__.__name__


def _ovf_descriptor_text(descriptor: OvaDescriptor) -> str:
    """Read the manifest-selected OVF descriptor without extracting the OVA."""
    try:
        with tarfile.open(descriptor.path, "r") as archive:
            source = archive.extractfile(descriptor.ovf_member)
            if source is None:
                raise VcfSddcDeploymentError("The OVA descriptor could not be read.")
            return source.read().decode("utf-8", errors="strict")
    except (OSError, tarfile.TarError, UnicodeDecodeError) as exc:
        raise VcfSddcDeploymentError("The OVA descriptor could not be read for vSphere validation.") from exc


def _redact_ovf_property_values(message: str, values: list[str] | tuple[str, ...]) -> str:
    """Remove every submitted OVF property value from a diagnostic string."""
    redacted = str(message or "")
    unique_values = sorted({str(value) for value in values if str(value)}, key=len, reverse=True)
    for value in unique_values:
        redacted = re.sub(re.escape(value), "[redacted]", redacted, flags=re.IGNORECASE)
    return re.sub(r"\s+", " ", redacted).strip()


def _ovf_diagnostic_messages(items: Any, *, property_values: dict[str, str] | None = None) -> list[str]:
    """Return bounded, value-redacted VMware OVF diagnostics."""
    values = list((property_values or {}).values())
    messages: list[str] = []
    for item in list(items or []):
        safe = _redact_ovf_property_values(_safe_vsphere_message(item), values)
        fault = getattr(item, "fault", None)
        fault_name = (fault or item).__class__.__name__
        rendered = f"{fault_name}: {safe}" if safe and safe != fault_name else fault_name
        if rendered not in messages:
            messages.append(rendered[:1000])
    return messages


def _parse_vsphere_ovf_descriptor(
    content: Any,
    descriptor: OvaDescriptor,
    *,
    deployment_option: str = "",
    property_values: dict[str, str] | None = None,
) -> OvaDescriptor:
    """Merge VMware's authoritative descriptor result into local OVA metadata."""
    from pyVmomi import vim

    params = vim.OvfManager.ParseDescriptorParams(
        locale="",
        deploymentOption=str(deployment_option or ""),
    )
    try:
        parsed = content.ovfManager.ParseDescriptor(_ovf_descriptor_text(descriptor), params)
    except Exception as exc:  # pyVmomi exposes version-specific fault types.
        message = _redact_ovf_property_values(_safe_vsphere_message(exc), list((property_values or {}).values()))
        raise VcfSddcDeploymentError(f"vSphere could not parse the OVA descriptor: {message}") from exc
    errors = _ovf_diagnostic_messages(getattr(parsed, "error", None), property_values=property_values)
    if errors:
        raise VcfSddcDeploymentError(f"vSphere rejected the OVA descriptor: {'; '.join(errors)}")

    local_properties = {item.key: item for item in descriptor.properties}
    properties: list[OvfProperty] = []
    for item in list(getattr(parsed, "property", None) or []):
        if getattr(item, "userConfigurable", None) is False:
            continue
        key = str(getattr(item, "id", "") or "").strip()
        if not key:
            raise VcfSddcDeploymentError("vSphere returned an OVF property without an identifier.")
        local = local_properties.get(key)
        value_type = str(getattr(item, "type", "") or (local.value_type if local else "string"))
        password = value_type.lower() == "password" or bool(local and local.password)
        default = "" if password else str(getattr(item, "defaultValue", "") or "")
        properties.append(
            OvfProperty(
                key=key,
                value_type=value_type,
                label=str(getattr(item, "label", "") or (local.label if local else key)),
                description=str(getattr(item, "description", "") or (local.description if local else "")),
                default=default,
                qualifiers=local.qualifiers if local else "",
                password=password,
                user_configurable=True,
            )
        )
    if descriptor.properties and not properties:
        raise VcfSddcDeploymentError("vSphere did not return any deployable OVF properties for this appliance.")

    options = [
        OvfDeploymentOption(
            key=str(getattr(item, "key", "") or ""),
            label=str(getattr(item, "label", "") or getattr(item, "key", "") or ""),
            description=str(getattr(item, "description", "") or ""),
        )
        for item in list(getattr(parsed, "deploymentOption", None) or [])
        if str(getattr(item, "key", "") or "")
    ]
    default_option = str(getattr(parsed, "defaultDeploymentOption", "") or "")
    option_keys = {item.key for item in options}
    selected_option = str(deployment_option or default_option)
    if selected_option and selected_option not in option_keys:
        raise VcfSddcDeploymentError("The selected OVF deployment option is no longer accepted by vSphere.")
    warnings = _ovf_diagnostic_messages(getattr(parsed, "warning", None), property_values=property_values)
    return replace(
        descriptor,
        vm_name=str(getattr(parsed, "defaultEntityName", "") or descriptor.vm_name),
        properties=properties,
        deployment_options=options,
        default_deployment_option=default_option,
        selected_deployment_option=selected_option,
        warnings=warnings,
    )


def complete_property_mapping(descriptor: OvaDescriptor, submitted: dict[str, str]) -> dict[str, str]:
    """Build an exact mapping for every reviewed target-deployable OVF property."""
    properties = {item.key: item for item in descriptor.properties}
    unknown = sorted(set(submitted) - set(properties))
    if unknown:
        raise VcfSddcDeploymentError(f"The submitted OVF property keys are not accepted by vSphere: {', '.join(unknown)}.")
    return {
        key: str(submitted[key]) if key in submitted else str(property_info.default or "")
        for key, property_info in properties.items()
    }


def connect_vsphere(address: str, username: str, password: str, *, port: int = 443, expected_fingerprint: str = "") -> Any:
    """Return connect vsphere.

    Args:
        address: Network address of the target service or interface.
        username: Account name used for authentication or lookup.
        password: Password supplied for the immediate authenticated operation.
        port: TCP or UDP port of the target service.
        expected_fingerprint: Certificate fingerprint explicitly confirmed by the operator.

    Raises:
        VcfSddcDeploymentError: If the operation encounters an invalid state.
    """
    from pyVim.connect import SmartConnect

    if expected_fingerprint and tls_sha256_fingerprint(address, port).upper() != expected_fingerprint.upper():
        raise VcfSddcDeploymentError("The vSphere TLS certificate changed after confirmation.")
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        return SmartConnect(host=address, user=username, pwd=password, port=port, sslContext=context)
    except Exception as exc:  # pyVmomi exposes version-specific fault types.
        raise VcfSddcDeploymentError(f"vSphere authentication failed: {exc}") from exc


def _walk_inventory(content: Any, vim_types: list[Any]) -> list[Any]:
    """Return walk inventory.

    Args:
        content: Content processed or persisted by the operation.
        vim_types: Vim types consumed by walk inventory.
    """
    view = content.viewManager.CreateContainerView(content.rootFolder, vim_types, True)
    try:
        return list(view.view)
    finally:
        view.Destroy()


def _format_bytes(value: int) -> str:
    """Render bytes.

    Args:
        value: Candidate value consumed by format bytes.


    Returns:
        The format bytes result.
    """
    units = ("bytes", "KiB", "MiB", "GiB", "TiB")
    amount = float(max(0, value))
    for unit in units:
        if amount < 1024 or unit == units[-1]:
            return f"{amount:.1f} {unit}" if unit != "bytes" else f"{int(amount)} bytes"
        amount /= 1024
    return f"{int(value)} bytes"


def _datastore_free_space_bytes(datastore: Any) -> int | None:
    """Return datastore free space bytes.

    Args:
        datastore: Datastore consumed by datastore free space bytes.
    """
    summary = getattr(datastore, "summary", None)
    value = getattr(summary, "freeSpace", None)
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _ensure_datastore_free_space(datastore: Any, required_bytes: int) -> None:
    """Ensure datastore free space.

    Args:
        datastore: Datastore consumed by ensure datastore free space.
        required_bytes: Required size in bytes.


    Raises:
        VcfSddcDeploymentError: If the operation encounters an invalid state.
    """
    free_space = _datastore_free_space_bytes(datastore)
    if free_space is None:
        return
    required_with_buffer = max(required_bytes + DATASTORE_FREE_SPACE_BUFFER_BYTES, int(required_bytes * 1.10))
    if free_space < required_with_buffer:
        datastore_name = str(getattr(datastore, "name", "selected datastore"))
        raise VcfSddcDeploymentError(
            f"Selected datastore {datastore_name} has only {_format_bytes(free_space)} free, "
            f"but the SDDC Manager OVA import needs about {_format_bytes(required_with_buffer)} "
            "including a safety buffer. Free space on the target datastore or choose another datastore before retrying."
        )


def normalize_disk_provisioning(value: str) -> str:
    """Normalize disk provisioning.

    Args:
        value: Candidate value consumed by normalize disk provisioning.


    Returns:
        The normalize disk provisioning result.

    Raises:
        VcfSddcDeploymentError: If the operation encounters an invalid state.
    """
    normalized = str(value or "thin").strip()
    if normalized not in DISK_PROVISIONING_MODES:
        raise VcfSddcDeploymentError("Disk provisioning must be thin or thick.")
    return normalized


def _ova_file_item_sizes(file_items: list[Any], archive: tarfile.TarFile) -> tuple[dict[str, int], int]:
    """Return ova file item sizes.

    Args:
        file_items: File items consumed by ova file item sizes.
        archive: Archive consumed by ova file item sizes.
    """
    member_sizes: dict[str, int] = {}
    required_bytes = 0
    for item in file_items:
        path = str(item.path)
        member_size = archive.getmember(path).size
        member_sizes[path] = member_size
        try:
            import_size = max(0, int(getattr(item, "size", 0) or 0))
        except (TypeError, ValueError):
            import_size = 0
        required_bytes += max(member_size, import_size)
    return member_sizes, required_bytes


def _lease_imported_entity(lease: Any) -> Any:
    """Return lease imported entity.

    Args:
        lease: Lease consumed by lease imported entity.


    Raises:
        VcfSddcDeploymentError: If the operation encounters an invalid state.
    """
    entity = getattr(getattr(lease, "info", None), "entity", None)
    if entity is None:
        raise VcfSddcDeploymentError("vSphere completed the OVA import but did not return the imported VM reference.")
    return entity


def _verify_imported_ovf_environment(
    vm: Any,
    descriptor: OvaDescriptor,
    property_values: dict[str, str],
) -> dict[str, Any]:
    """Prove imported vApp metadata and guest OVF transport before power-on."""
    config = getattr(vm, "config", None)
    vapp_config = getattr(config, "vAppConfig", None)
    if vapp_config is None:
        raise VcfSddcDeploymentError("The imported VM has no vApp/OVF configuration metadata.")
    expected_keys = set(property_values)
    actual_values = {
        str(getattr(item, "id", "") or ""): str(getattr(item, "value", "") or "")
        for item in list(getattr(vapp_config, "property", None) or [])
        if str(getattr(item, "id", "") or "")
    }
    actual_keys = set(actual_values)
    missing_keys = sorted(expected_keys - actual_keys)
    if missing_keys:
        raise VcfSddcDeploymentError(
            f"The imported VM is missing reviewed OVF property metadata for keys: {', '.join(missing_keys)}."
        )
    mismatched_keys = sorted(key for key, expected in property_values.items() if actual_values[key] != expected)
    if mismatched_keys:
        raise VcfSddcDeploymentError(
            f"The imported VM did not retain reviewed OVF property values for keys: {', '.join(mismatched_keys)}."
        )
    expected_transports = set(descriptor.ovf_environment_transports)
    actual_transports = {
        str(item)
        for item in list(getattr(vapp_config, "ovfEnvironmentTransport", None) or [])
        if str(item)
    }
    if expected_keys and not expected_transports:
        raise VcfSddcDeploymentError("The OVA does not declare an OVF environment transport for its deployment properties.")
    supported_transports = {"com.vmware.guestInfo", "iso"}
    if expected_keys and not actual_transports.intersection(expected_transports, supported_transports):
        raise VcfSddcDeploymentError("The imported VM retained no supported OVF environment transport declared by the OVA.")
    return {
        "property_keys": sorted(actual_keys),
        "transports": sorted(actual_transports),
    }


def _destroy_imported_vm(vm: Any) -> None:
    """Remove only the exact VM reference returned by the current NFC lease."""
    try:
        _wait_task(vm.Destroy_Task(), timeout=900.0)
    except Exception as exc:
        if isinstance(exc, VcfSddcDeploymentError):
            raise
        raise VcfSddcDeploymentError(f"vSphere could not remove the incomplete imported VM: {_safe_vsphere_message(exc)}") from exc


def _datastore_row(item: Any) -> dict[str, Any]:
    """Return datastore row.

    Args:
        item: Item consumed by datastore row.
    """
    free_space = _datastore_free_space_bytes(item)
    summary = getattr(item, "summary", None)
    try:
        capacity = int(getattr(summary, "capacity", 0) or 0)
    except (TypeError, ValueError):
        capacity = 0
    row: dict[str, Any] = {"id": str(item._moId), "name": str(getattr(item, "name", item._moId))}
    if free_space is not None:
        row["free_space_bytes"] = free_space
        row["free_space_label"] = _format_bytes(free_space)
    if capacity:
        row["capacity_bytes"] = capacity
        row["capacity_label"] = _format_bytes(capacity)
    return row


def vsphere_inventory(
    address: str,
    username: str,
    password: str,
    *,
    port: int = 443,
    expected_fingerprint: str = "",
    descriptor: OvaDescriptor | None = None,
    deployment_option: str = "",
) -> dict[str, Any]:
    """Return vsphere inventory.

    Args:
        address: Network address of the target service or interface.
        username: Account name used for authentication or lookup.
        password: Password supplied for the immediate authenticated operation.
        port: TCP or UDP port of the target service.
        expected_fingerprint: Certificate fingerprint explicitly confirmed by the operator.
        descriptor: Optional OVA descriptor to parse through the target OVF manager.
        deployment_option: Target-supported OVF deployment option key.
    """
    from pyVim.connect import Disconnect
    from pyVmomi import vim

    service_instance = connect_vsphere(address, username, password, port=port, expected_fingerprint=expected_fingerprint)
    try:
        content = service_instance.RetrieveContent()
        type_map = {
            "datacenters": vim.Datacenter,
            "clusters": vim.ClusterComputeResource,
            "hosts": vim.HostSystem,
            "resource_pools": vim.ResourcePool,
            "folders": vim.Folder,
            "datastores": vim.Datastore,
            "networks": vim.Network,
        }
        result: dict[str, Any] = {"api_type": str(content.about.apiType or "")}
        for key, vim_type in type_map.items():
            rows = _walk_inventory(content, [vim_type])
            result[key] = [_datastore_row(item) if key == "datastores" else {"id": str(item._moId), "name": str(getattr(item, "name", item._moId))} for item in rows]
        if descriptor is not None:
            result["ova"] = _parse_vsphere_ovf_descriptor(
                content,
                descriptor,
                deployment_option=deployment_option,
            ).public_dict()
        return result
    finally:
        Disconnect(service_instance)


def vsphere_ovf_descriptor(
    address: str,
    username: str,
    password: str,
    descriptor: OvaDescriptor,
    *,
    port: int = 443,
    expected_fingerprint: str = "",
    deployment_option: str = "",
    property_values: dict[str, str] | None = None,
) -> OvaDescriptor:
    """Parse one OVA with the exact target vSphere OVF manager."""
    from pyVim.connect import Disconnect

    service_instance = connect_vsphere(
        address,
        username,
        password,
        port=port,
        expected_fingerprint=expected_fingerprint,
    )
    try:
        return _parse_vsphere_ovf_descriptor(
            service_instance.RetrieveContent(),
            descriptor,
            deployment_option=deployment_option,
            property_values=property_values,
        )
    finally:
        Disconnect(service_instance)


def _find_object(content: Any, vim_type: Any, object_id: str, label: str) -> Any:
    """Return object.

    Args:
        content: Content processed or persisted by the operation.
        vim_type: Vim type consumed by find object.
        object_id: Stable identifier of the associated object resource.
        label: Human-readable label used to identify the result.


    Raises:
        VcfSddcDeploymentError: If the operation encounters an invalid state.
    """
    for item in _walk_inventory(content, [vim_type]):
        if str(item._moId) == object_id:
            return item
    raise VcfSddcDeploymentError(f"Selected {label} is no longer present in vSphere inventory.")


def _upload_member(
    url: str,
    source: Any,
    size: int,
    *,
    endpoint: str,
    name: str,
    transferred: list[int],
    total: int,
    lease: Any,
    progress: Progress | None,
    cancelled: CancelCheck | None = None,
) -> None:
    """Handle upload member.

    Args:
        url: URL of the target resource or service.
        source: Source path, address, or record to process.
        size: Size supplied by the caller.
        endpoint: Endpoint supplied by the caller.
        name: Name of the target object.
        transferred: Transferred supplied by the caller.
        total: Total supplied by the caller.
        lease: Lease supplied by the caller.
        progress: Progress supplied by the caller.
        cancelled: Callback that reports whether cancellation was requested.

    Raises:
        VcfSddcDeploymentError: If the operation encounters an invalid state.
    """
    parsed = urlsplit(url)
    hostname = endpoint if parsed.hostname in {"*", ""} else str(parsed.hostname)
    netloc = hostname if not parsed.port else f"{hostname}:{parsed.port}"
    parsed = urlsplit(urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, "")))
    connection_class = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    kwargs: dict[str, Any] = {"timeout": NFC_UPLOAD_SOCKET_TIMEOUT_SECONDS}
    if parsed.scheme == "https":
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        kwargs["context"] = context
    connection = connection_class(parsed.hostname, parsed.port, **kwargs)
    stop_heartbeat = threading.Event()
    lease_progress = _LeaseProgress(lease)
    heartbeat = threading.Thread(target=lease_progress.heartbeat, args=(stop_heartbeat,), name="vcf-sddc-nfc-lease-heartbeat", daemon=True)
    heartbeat.start()
    try:
        target = parsed.path + (f"?{parsed.query}" if parsed.query else "")
        connection.putrequest("POST", target)
        connection.putheader("Content-Length", str(size))
        content_type = "application/x-vnd.vmware-streamVmdk" if name.lower().endswith(".vmdk") else "application/octet-stream"
        connection.putheader("Content-Type", content_type)
        connection.endheaders()
        try:
            while True:
                _check_cancelled(cancelled)
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                connection.send(chunk)
                transferred[0] += len(chunk)
                percent = 10 + int(transferred[0] / max(total, 1) * 60)
                lease_progress.update(int(transferred[0] / max(total, 1) * 100))
                if progress:
                    progress(min(70, percent), f"uploading-{name}")
            response = connection.getresponse()
            response_body = response.read(4096)
        except (OSError, http.client.HTTPException) as exc:
            raise VcfSddcDeploymentError(f"vSphere NFC upload failed while streaming {name}: {exc}") from exc
        if response.status < 200 or response.status >= 300:
            detail = response_body.decode("utf-8", errors="replace").strip()
            suffix = f": {detail}" if detail else "."
            raise VcfSddcDeploymentError(f"vSphere NFC upload failed for {name} with HTTP {response.status}{suffix}")
    finally:
        stop_heartbeat.set()
        heartbeat.join(timeout=2)
        connection.close()


def deploy_ova(
    descriptor: OvaDescriptor,
    *,
    endpoint: str,
    username: str,
    password: str,
    resource_pool_id: str,
    datastore_id: str,
    network_ids: dict[str, str],
    vm_name: str,
    property_values: dict[str, str],
    folder_id: str = "",
    host_id: str = "",
    port: int = 443,
    progress: Progress | None = None,
    expected_fingerprint: str = "",
    disk_provisioning: str = "thin",
    deployment_option: str = "",
    power_on: bool = True,
    cancelled: CancelCheck | None = None,
) -> dict[str, Any]:
    """Return deploy ova.

    Args:
        descriptor: Descriptor supplied by the caller.
        endpoint: Endpoint supplied by the caller.
        username: Account name used for authentication or lookup.
        password: Password supplied for the immediate authenticated operation.
        resource_pool_id: Identifier of the resource pool.
        datastore_id: Identifier of the datastore.
        network_ids: Network ids supplied by the caller.
        vm_name: Vm name supplied by the caller.
        property_values: Property values supplied by the caller.
        folder_id: Identifier of the folder.
        host_id: Identifier of the host.
        port: TCP or UDP port of the target service.
        progress: Progress supplied by the caller.
        expected_fingerprint: Certificate fingerprint explicitly confirmed by the operator.
        disk_provisioning: Disk provisioning supplied by the caller.
        deployment_option: Target-supported OVF deployment option key.
        power_on: Power on supplied by the caller.
        cancelled: Callback that reports whether cancellation was requested.

    Raises:
        VcfSddcDeploymentError: If the operation encounters an invalid state.
        VcfSddcPostImportError: If the operation encounters an invalid state.
    """
    from pyVim.connect import Disconnect
    from pyVmomi import vim

    validate_ova_manifest(descriptor, progress=progress, cancelled=cancelled)
    disk_provisioning = normalize_disk_provisioning(disk_provisioning)
    service_instance = connect_vsphere(endpoint, username, password, port=port, expected_fingerprint=expected_fingerprint)
    lease = None
    imported_vm_result: dict[str, Any] | None = None
    try:
        content = service_instance.RetrieveContent()
        _check_cancelled(cancelled)
        descriptor = _parse_vsphere_ovf_descriptor(
            content,
            descriptor,
            deployment_option=deployment_option,
            property_values=property_values,
        )
        property_values = complete_property_mapping(descriptor, property_values)
        if any(str(item.name).lower() == vm_name.strip().lower() for item in _walk_inventory(content, [vim.VirtualMachine])):
            raise VcfSddcDeploymentError(f"A virtual machine named {vm_name} already exists.")
        resource_pool = _find_object(content, vim.ResourcePool, resource_pool_id, "resource pool")
        datastore = _find_object(content, vim.Datastore, datastore_id, "datastore")
        folder = _find_object(content, vim.Folder, folder_id, "VM folder") if folder_id else None
        host = _find_object(content, vim.HostSystem, host_id, "host") if host_id else None
        api_type = str(getattr(getattr(content, "about", None), "apiType", "") or "")
        if api_type == "HostAgent":
            hosts = _walk_inventory(content, [vim.HostSystem])
            if len(hosts) != 1:
                raise VcfSddcDeploymentError("Standalone ESXi inventory did not contain exactly one target host.")
            direct_host = hosts[0]
            if host is not None and str(host._moId) != str(direct_host._moId):
                raise VcfSddcDeploymentError("The selected host does not belong to the standalone ESXi endpoint.")
            host = direct_host
        network_mappings = []
        for source_name in descriptor.networks:
            network_id = network_ids.get(source_name, "")
            if not network_id:
                raise VcfSddcDeploymentError(f"Map OVA network {source_name} before deployment.")
            network = _find_object(content, vim.Network, network_id, "network")
            network_mappings.append(vim.OvfManager.NetworkMapping(name=source_name, network=network))
        parameter_values: dict[str, Any] = {
            "entityName": vm_name,
            "diskProvisioning": disk_provisioning,
            "deploymentOption": descriptor.selected_deployment_option,
            "networkMapping": network_mappings,
            "propertyMapping": [vim.KeyValue(key=key, value=value) for key, value in property_values.items()],
        }
        if host is not None:
            parameter_values["hostSystem"] = host
        params = vim.OvfManager.CreateImportSpecParams(**parameter_values)
        import_warnings = list(descriptor.warnings)
        with tarfile.open(descriptor.path, "r") as archive:
            ovf_source = archive.extractfile(descriptor.ovf_member)
            if ovf_source is None:
                raise VcfSddcDeploymentError("The OVA descriptor could not be read for deployment.")
            spec = content.ovfManager.CreateImportSpec(ovf_source.read().decode("utf-8"), resource_pool, datastore, params)
            if spec.error:
                messages = "; ".join(_ovf_diagnostic_messages(spec.error, property_values=property_values))
                raise VcfSddcDeploymentError(f"vSphere rejected the OVA import specification: {messages}")
            for warning in _ovf_diagnostic_messages(getattr(spec, "warning", None), property_values=property_values):
                if warning not in import_warnings:
                    import_warnings.append(warning)
            if import_warnings and progress:
                progress(10, "reviewed-import-warnings")
            member_sizes, required_bytes = _ova_file_item_sizes(list(spec.fileItem), archive)
            _ensure_datastore_free_space(datastore, required_bytes)
            lease = resource_pool.ImportVApp(spec.importSpec, folder, host)
            started = time.monotonic()
            while str(lease.state) not in {"ready", "error"}:
                _check_cancelled(cancelled)
                if time.monotonic() - started > 300:
                    raise VcfSddcDeploymentError("Timed out waiting for the vSphere NFC lease.")
                time.sleep(1)
            if str(lease.state) == "error":
                raise VcfSddcDeploymentError(str(lease.error or "vSphere NFC lease failed."))
            device_urls = {str(item.importKey): str(item.url) for item in lease.info.deviceUrl}
            total = sum(member_sizes.values())
            transferred = [0]
            for file_item in spec.fileItem:
                member = archive.getmember(str(file_item.path))
                source = archive.extractfile(member)
                if source is None:
                    raise VcfSddcDeploymentError(f"Could not read {file_item.path} from the OVA.")
                upload_url = device_urls.get(str(file_item.deviceId))
                if not upload_url:
                    raise VcfSddcDeploymentError(f"vSphere did not provide an upload URL for {file_item.path}.")
                _upload_member(
                    upload_url,
                    source,
                    member.size,
                    endpoint=endpoint,
                    name=str(file_item.path),
                    transferred=transferred,
                    total=total,
                    lease=lease,
                    progress=progress,
                    cancelled=cancelled,
                )
            vm = _lease_imported_entity(lease)
            lease.HttpNfcLeaseComplete()
        imported_vm_result = {
            "vm_id": str(vm._moId),
            "vm_name": str(vm.name),
            "guest_ip": "",
            "warnings": import_warnings,
            "api_type": api_type,
            "deployment_option": descriptor.selected_deployment_option,
        }
        try:
            imported_vm_result["ovf_verification"] = _verify_imported_ovf_environment(vm, descriptor, property_values)
        except Exception as verification_exc:
            message = (
                str(verification_exc)
                if isinstance(verification_exc, VcfSddcDeploymentError)
                else f"Could not verify the imported OVF environment: {_safe_vsphere_message(verification_exc)}"
            )
            try:
                _destroy_imported_vm(vm)
            except VcfSddcDeploymentError as cleanup_exc:
                raise VcfSddcPostImportError(
                    f"{message} Automatic rollback of the exact incomplete VM also failed: {cleanup_exc}",
                    imported_vm_result,
                ) from verification_exc
            imported_vm_result = None
            raise VcfSddcDeploymentError(f"{message} The exact incomplete VM was removed before power-on.") from verification_exc
        if not power_on:
            if progress:
                progress(100, "deployed-powered-off")
            return imported_vm_result
        if progress:
            progress(75, "powering-on")
        _wait_task(vm.PowerOnVM_Task(), cancelled=cancelled)
        if progress:
            progress(80, "waiting-for-guest-address")
        started = time.monotonic()
        guest_ip = ""
        while time.monotonic() - started < 900:
            _check_cancelled(cancelled)
            guest_ip = str(getattr(vm.guest, "ipAddress", "") or "")
            if guest_ip:
                break
            time.sleep(5)
        imported_vm_result["guest_ip"] = guest_ip
        return imported_vm_result
    except Exception as exc:
        if lease is not None and str(getattr(lease, "state", "")) not in {"done", "error"}:
            try:
                lease.HttpNfcLeaseAbort()
            except Exception:  # noqa: BLE001 - cleanup must continue after a best-effort lease abort.
                pass
        if imported_vm_result is not None:
            message = str(exc) if isinstance(exc, VcfSddcDeploymentError) else f"vSphere deployment failed after VM import: {_safe_vsphere_message(exc)}"
            raise VcfSddcPostImportError(message, imported_vm_result) from exc
        if isinstance(exc, VcfSddcDeploymentError):
            raise
        raise VcfSddcDeploymentError(f"vSphere deployment failed: {_safe_vsphere_message(exc)}") from exc
    finally:
        Disconnect(service_instance)
