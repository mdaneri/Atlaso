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
from dataclasses import asdict, dataclass
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
    def __init__(self, message: str, vm_result: dict[str, str]) -> None:
        """Initialize the vcf sddc post import error."""
        super().__init__(message)
        self.vm_result = vm_result


def _check_cancelled(cancelled: CancelCheck | None) -> None:
    """Check cancelled.

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
        """Initialize the lease progress."""
        self.lease = lease
        self.value = 0
        self.lock = threading.Lock()

    def update(self, percent: int) -> None:
        """Update operation."""
        with self.lock:
            self.value = max(self.value, max(0, min(99, int(percent))))
            self.lease.HttpNfcLeaseProgress(self.value)

    def heartbeat(self, stop_event: threading.Event) -> None:
        """Handle heartbeat."""
        while not stop_event.wait(5):
            try:
                self.update(self.value)
            except Exception:
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

    def public_dict(self) -> dict[str, Any]:
        """Return public dict."""
        payload = asdict(self)
        payload["properties"] = [asdict(item) for item in self.properties]
        return payload


def _attribute(element: ET.Element, name: str) -> str:
    """Return attribute."""
    return str(element.attrib.get(f"{OVF}{name}") or element.attrib.get(name) or "")


def normalize_ova_path(value: str | Path, *, root: Path = SDDC_MANAGER_OVA_ROOT) -> Path:
    """Normalize ova path.

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
    )


def ova_inventory(*, root: Path = SDDC_MANAGER_OVA_ROOT) -> list[dict[str, Any]]:
    """Return ova inventory."""
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
    """Return safe vsphere message."""
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
    """Return walk inventory."""
    view = content.viewManager.CreateContainerView(content.rootFolder, vim_types, True)
    try:
        return list(view.view)
    finally:
        view.Destroy()


def _format_bytes(value: int) -> str:
    """Render bytes.

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
    """Return datastore free space bytes."""
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
    """Return ova file item sizes."""
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

    Raises:
        VcfSddcDeploymentError: If the operation encounters an invalid state.
    """
    entity = getattr(getattr(lease, "info", None), "entity", None)
    if entity is None:
        raise VcfSddcDeploymentError("vSphere completed the OVA import but did not return the imported VM reference.")
    return entity


def _datastore_row(item: Any) -> dict[str, Any]:
    """Return datastore row."""
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


def vsphere_inventory(address: str, username: str, password: str, *, port: int = 443, expected_fingerprint: str = "") -> dict[str, Any]:
    """Return vsphere inventory.

    Args:
        address: Network address of the target service or interface.
        username: Account name used for authentication or lookup.
        password: Password supplied for the immediate authenticated operation.
        port: TCP or UDP port of the target service.
        expected_fingerprint: Certificate fingerprint explicitly confirmed by the operator.
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
        return result
    finally:
        Disconnect(service_instance)


def _find_object(content: Any, vim_type: Any, object_id: str, label: str) -> Any:
    """Return object.

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
    power_on: bool = True,
    cancelled: CancelCheck | None = None,
) -> dict[str, str]:
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
    imported_vm_result: dict[str, str] | None = None
    try:
        content = service_instance.RetrieveContent()
        _check_cancelled(cancelled)
        if any(str(item.name).lower() == vm_name.strip().lower() for item in _walk_inventory(content, [vim.VirtualMachine])):
            raise VcfSddcDeploymentError(f"A virtual machine named {vm_name} already exists.")
        resource_pool = _find_object(content, vim.ResourcePool, resource_pool_id, "resource pool")
        datastore = _find_object(content, vim.Datastore, datastore_id, "datastore")
        folder = _find_object(content, vim.Folder, folder_id, "VM folder") if folder_id else None
        host = _find_object(content, vim.HostSystem, host_id, "host") if host_id else None
        network_mappings = []
        for source_name in descriptor.networks:
            network_id = network_ids.get(source_name, "")
            if not network_id:
                raise VcfSddcDeploymentError(f"Map OVA network {source_name} before deployment.")
            network = _find_object(content, vim.Network, network_id, "network")
            network_mappings.append(vim.OvfManager.NetworkMapping(name=source_name, network=network))
        params = vim.OvfManager.CreateImportSpecParams(
            entityName=vm_name,
            diskProvisioning=disk_provisioning,
            networkMapping=network_mappings,
            propertyMapping=[vim.KeyValue(key=key, value=value) for key, value in property_values.items()],
        )
        with tarfile.open(descriptor.path, "r") as archive:
            ovf_source = archive.extractfile(descriptor.ovf_member)
            if ovf_source is None:
                raise VcfSddcDeploymentError("The OVA descriptor could not be read for deployment.")
            spec = content.ovfManager.CreateImportSpec(ovf_source.read().decode("utf-8"), resource_pool, datastore, params)
            if spec.error:
                messages = "; ".join(str(getattr(item, "localizedMessage", item)) for item in spec.error)
                raise VcfSddcDeploymentError(f"vSphere rejected the OVA import specification: {messages}")
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
        imported_vm_result = {"vm_id": str(vm._moId), "vm_name": str(vm.name), "guest_ip": ""}
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
            except Exception:
                pass
        if imported_vm_result is not None:
            message = str(exc) if isinstance(exc, VcfSddcDeploymentError) else f"vSphere deployment failed after VM import: {_safe_vsphere_message(exc)}"
            raise VcfSddcPostImportError(message, imported_vm_result) from exc
        if isinstance(exc, VcfSddcDeploymentError):
            raise
        raise VcfSddcDeploymentError(f"vSphere deployment failed: {_safe_vsphere_message(exc)}") from exc
    finally:
        Disconnect(service_instance)
