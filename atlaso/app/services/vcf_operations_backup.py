"""Compose lifecycle and per-manager backups behind one Operations connection."""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Callable
from urllib.parse import quote

from atlaso.app.services.vcf_backup_native import (
    NativeBackup,
    _extract_task_id,
    _openssh_sha256_fingerprint,
    _state,
    _TransientPollUnavailable,
    _validate_encryption_passphrase,
    _validation_result,
)
from atlaso.app.services.vcf_certificate_remote import Credentials, RemoteError, Target
from atlaso.app.services.vcf_operations_proxy import OperationsProxy


class _ManagerTransport:
    """Translate native SDDC API calls to one Operations-selected manager."""

    def __init__(self, proxy: OperationsProxy, resource_id: str) -> None:
        """Bind the resource context without accepting manager credentials.

        Args:
            proxy: Owned Operations session shared by this composite connection.
            resource_id: Operations resource UUID selected from its inventory.
        """
        self.proxy = proxy
        self.resource_id = resource_id

    def request(
        self, method: str, path: str, *, body: Any = None,
        credentials: Credentials | None = None, session_header: tuple[str, str] | None = None,
    ) -> tuple[int, Any]:
        """Forward one explicit native request; never send direct credentials.

        Args:
            method: Native HTTP method.
            path: Native SDDC API path.
            body: Optional transient native payload.
            credentials: Unsupported direct-appliance credential override.
            session_header: Legacy adapter marker, replaced by the Operations token.
        """
        if credentials is not None:
            raise RemoteError("Direct manager credentials are not used through Operations")
        return self.proxy.request(self.resource_id, method, path, body)


class ManagedSddcBackup(NativeBackup):
    """Reuse the native manager contract through the authenticated Operations proxy."""

    def __init__(
        self, source: dict[str, Any], credentials: Credentials,
        proxy: OperationsProxy, manager: dict[str, Any],
    ) -> None:
        """Pin every manager request to Operations and its discovered resource.

        Args:
            source: Confirmed Operations endpoint.
            credentials: Operations account, retained only in request memory.
            proxy: Owned proxy session that supplies per-resource tokens.
            manager: Allowlisted Operations inventory record and native manager UUID.
        """
        self.manager = manager
        transport = _ManagerTransport(proxy, manager["resource_id"])
        super().__init__({**source, "kind": "sddc"}, credentials, transport_factory=lambda _target: transport)

    def login(self) -> None:
        """Use the existing Operations context instead of a manager token login."""
        self._session = "operations-proxy"
        self._load_version()

    def discover(self) -> dict[str, Any]:
        """Refuse a proxy whose native manager identity differs from Operations."""
        result = super().discover()
        manager = self._sddc_manager
        if not isinstance(manager, dict) or manager.get("id") != self.manager["manager_uuid"]:
            raise RemoteError("Operations proxy manager identity does not match its inventory")
        return result

    def _select_sddc_manager(self, rows: list[dict[str, Any]], management_ips: set[str], system_id: Any) -> dict[str, Any]:
        """Require Operations' manager UUID and the native management address together.

        Args:
            rows: Native manager inventory, which may omit domain metadata in VCF 9.1.
            management_ips: Addresses of the proxied authenticated appliance.
            system_id: Separate native system UUID, never a manager UUID substitute.
        """
        matches = [row for row in rows if row.get("id") == self.manager["manager_uuid"]
                   and row.get("ipAddress") in management_ips]
        if len(matches) != 1:
            raise RemoteError("Operations proxy manager identity does not match its inventory")
        return matches[0]

    def _receiver_key(self, proposed: dict[str, Any]) -> str:
        """Require the native RSA thumbprint to match the locally verified key.

        Args:
            proposed: Reviewed destination and public RSA host key.
        """
        key = proposed.get("host_key")
        if not isinstance(key, str):
            raise ValueError("The verified backup receiver RSA key is required")
        fingerprint = _openssh_sha256_fingerprint(key, "ssh-rsa")
        if proposed.get("ecdsa_fingerprint") != fingerprint:
            raise ValueError("The reviewed receiver RSA fingerprint is inconsistent")
        host, port = proposed.get("host"), proposed.get("port")
        if not isinstance(host, str) or not host or type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("The reviewed backup receiver is invalid")
        result = self._call("GET", "/v1/system/backup-configuration/backup-locations"
                            f"?serverIp={quote(host, safe='')}&port={port}")
        if (
            not isinstance(result, dict) or result.get("server") != host
            or result.get("port") != port or result.get("sshFingerprint") != fingerprint
        ):
            raise RemoteError("Operations manager SSH fingerprint does not match the verified receiver RSA key")
        return fingerprint

    def proposed(self, group: str, policy: dict[str, Any], receiver: dict[str, Any]) -> dict[str, Any]:
        """Review the manager's native RSA key requirement before configuration.

        Args:
            group: Discovered native manager group.
            policy: Reviewed schedule and retention choices.
            receiver: Applied receiver endpoint and locally verified public keys.
        """
        proposed = super().proposed(group, policy, receiver)
        key = receiver.get("rsa_host_key")
        if not isinstance(key, str):
            raise ValueError("The applied receiver RSA public key is unavailable")
        proposed["host_key"] = key
        proposed["ecdsa_fingerprint"] = _openssh_sha256_fingerprint(key, "ssh-rsa")
        self._receiver_key(proposed)
        return proposed

    def validate(self, group: str, proposed: dict[str, Any], sftp_password: str, encryption_passphrase: str) -> dict[str, Any]:
        """Recheck the receiver key before native destination validation.

        Args:
            group: Reviewed manager scheduler.
            proposed: Reviewed native public settings.
            sftp_password: Request-local receiver password.
            encryption_passphrase: Request-local recovery passphrase.
        """
        self._group(group)
        self._load_version()
        if not sftp_password or not encryption_passphrase:
            raise ValueError("Backup SFTP and encryption secrets are required")
        _validate_encryption_passphrase("sddc", encryption_passphrase)
        self._receiver_key(proposed)
        validation = self._sddc_config_body(proposed, sftp_password, encryption_passphrase)
        # Operations validates Site Settings separately from the manager's
        # schedule editor. Match that observed destination-only contract.
        validation.pop("backupSchedules")
        result = self._call("POST", "/v1/system/backup-configuration/validations?useAsyncValidation=true",
                            validation)
        validation_id = result.get("id") if isinstance(result, dict) else None
        # Some 9.1 managers finish synchronously even with async requested.
        # Accept an explicit terminal result only; an empty acceptance response
        # still requires an identity that can be polled.
        if validation_id is None and isinstance(result, dict) and result.get("resultStatus") in {"SUCCEEDED", "FAILED"}:
            return _validation_result(result)
        if not isinstance(validation_id, str) or not validation_id or len(validation_id) > 256:
            raise RemoteError("Operations did not return a backup validation identity")
        deadline = time.monotonic() + 120
        for _ in range(60):
            if time.monotonic() >= deadline:
                break
            result = self._call("GET", "/v1/system/backup-configuration/validations/"
                                + quote(validation_id, safe="") + "?useAsyncValidation=true")
            if not isinstance(result, dict):
                raise RemoteError("Operations returned invalid backup validation status")
            if result.get("id") != validation_id:
                raise RemoteError("Operations returned a different backup validation identity")
            if str(result.get("executionStatus", "")).upper() not in {"IN_PROGRESS", "PENDING", "RUNNING", "QUEUED", "STARTING"}:
                return _validation_result(result)
            time.sleep(min(2, max(0, deadline - time.monotonic())))
        raise RemoteError("Operations backup validation is still running; settings were not configured")

    def configure(self, group: str, proposed: dict[str, Any], sftp_password: str, encryption_passphrase: str) -> dict[str, Any]:
        """Recheck the receiver key before the single reviewed configuration write.

        Args:
            group: Reviewed manager scheduler.
            proposed: Reviewed native public settings.
            sftp_password: Request-local receiver password.
            encryption_passphrase: Request-local recovery passphrase.
        """
        self._group(group)
        self._load_version()
        if not sftp_password or not encryption_passphrase:
            raise ValueError("Backup SFTP and encryption secrets are required")
        _validate_encryption_passphrase("sddc", encryption_passphrase)
        self._receiver_key(proposed)
        result = self._call("PUT", "/v1/system/backup-configuration",
                            self._sddc_config_body(proposed, sftp_password, encryption_passphrase))
        task_id = _extract_task_id(result)
        if task_id is None:
            raise RemoteError("Operations backup configuration returned no task reference")
        return {"native_task_id": task_id, "kind": "sddc", "group_id": group}

    def configuration_status(self, group: str, reference: dict[str, Any]) -> dict[str, Any]:
        """Poll the exact asynchronous manager configuration before initial backup.

        Args:
            group: Reviewed manager scheduler.
            reference: Recorded native configuration task and scheduler binding.
        """
        self._group(group)
        task_id = _extract_task_id({"id": reference.get("native_task_id")}) if isinstance(reference, dict) else None
        if task_id is None or reference.get("kind") != "sddc" or reference.get("group_id") != group:
            raise ValueError("Native manager configuration reference does not match this group")
        try:
            result = self._poll_call("/v1/tasks/" + quote(task_id, safe=""))
        except _TransientPollUnavailable:
            return {"state": "running", "warning": "Operations manager configuration status is temporarily unavailable; polling the recorded task will continue."}
        if not isinstance(result, dict) or result.get("id") != task_id:
            raise RemoteError("Operations returned a different manager configuration task")
        return {"state": _state(result.get("status"))}


class OperationsBackup(NativeBackup):
    """Present one Operations source while retaining distinct native schedulers."""

    def __init__(
        self, source: dict[str, Any], credentials: Credentials, *,
        native_factory: Callable[..., Any] = NativeBackup,
        proxy_factory: Callable[..., Any] = OperationsProxy,
        manager_factory: Callable[..., Any] = ManagedSddcBackup,
    ) -> None:
        """Bind a composite connection to explicit Operations backup scopes.

        Args:
            source: Confirmed Operations identity and selected backup scopes.
            credentials: One Operations credential for both backup areas.
            native_factory: Lifecycle adapter factory, injectable for contract tests.
            proxy_factory: Owned Operations session factory.
            manager_factory: Native manager adapter factory.
        """
        self.source = dict(source)
        self.credentials = credentials
        self.kind = "fleet"
        self._validate_target(source)
        scopes = source.get("operations_scopes")
        if (
            not isinstance(scopes, list) or not scopes
            or any(not isinstance(scope, str) or scope not in {"lifecycle", "sddc"} for scope in scopes)
            or len(scopes) != len(set(scopes))
        ):
            raise ValueError("Select valid Operations backup scopes")
        self.scopes = sorted(scopes)
        self.root = native_factory(source, credentials)
        self.proxy: Any = None
        self._proxy_factory = proxy_factory
        self._manager_factory = manager_factory
        self._managers: dict[str, Any] = {}
        self._routes: dict[str, tuple[Any, str, dict[str, Any]]] = {}
        self._component_ids: dict[str, dict[str, str]] = {}
        self._inventory = None
        self._started = False

    def login(self) -> None:
        """Authenticate only to the backup areas chosen in the first step."""
        if "lifecycle" in self.scopes:
            self.root.login()
        if "sddc" in self.scopes:
            self.proxy = self._proxy_factory(Target(self.source["address"], self.source["port"], self.source["fingerprint"]), self.credentials)
            try:
                self.proxy.login()
            except BaseException:
                self.proxy.close()
                self.proxy = None
                raise
        self._started = True

    def __exit__(self, *_args: Any) -> None:
        """Close owned sessions without affecting native backup execution.

        Args:
            *_args: Context manager exception state.
        """
        for child in self._managers.values():
            child.__exit__(None, None, None)
        self.root.__exit__(None, None, None)
        if self.proxy is not None:
            self.proxy.close()
        self._managers.clear()
        self._routes.clear()
        self._component_ids.clear()
        self._started = False

    def discover(self) -> dict[str, Any]:
        """Compose lifecycle groups and inventory-verified manager schedulers."""
        if not self._started:
            self.login()
        inventory = self.root.operations_inventory()
        managers = inventory.get("managers")
        if not isinstance(managers, list) or len(managers) > 12:
            raise RemoteError("Operations backup discovery supports at most twelve connected managers")
        components: list[dict[str, Any]] = []
        groups: list[dict[str, Any]] = []
        gaps: list[dict[str, Any]] = []
        identities: list[Any] = []
        versions: list[str] = []
        service: Any = None
        routes: dict[str, tuple[Any, str, dict[str, Any]]] = {}
        mapping: dict[str, dict[str, str]] = {}

        def include(child: Any, value: dict[str, Any], scope: str, manager: dict[str, Any] | None = None) -> None:
            """Bind each returned native group and component to its real scheduler.

            Args:
                child: Already authenticated native adapter.
                value: Child's allowlisted backup inventory.
                scope: Lifecycle or manager backup area.
                manager: Operations manager identity for managed backup groups.
            """
            prefix = f"sddc:{manager['manager_uuid']}:" if manager else ""
            component_map = {prefix + row["id"]: row["id"] for row in value["components"]}
            for group in value["groups"]:
                public_id = prefix + group["id"]
                binding = {"scope": scope, "group_id": group["id"],
                           **({"resource_id": manager["resource_id"], "manager_uuid": manager["manager_uuid"]} if manager else {})}
                routes[public_id] = (child, group["id"], binding)
                mapping[public_id] = component_map
                public = {**group, "id": public_id, "component_ids": [prefix + item for item in group["component_ids"]],
                          "backup_kind": "sddc" if manager else "fleet",
                          "native_identity": {**group.get("native_identity", {}), "operations_binding": binding}}
                if manager is None:
                    # Lifecycle-service backups and the manager/NSX backup policy
                    # are separate schedulers. The global operation lease still
                    # serializes their dispatch, including legacy connections.
                    public["reservation_keys"] = ["fleet-lifecycle:" + key for key in group.get("reservation_keys", [])]
                groups.append(public)
            for row in value["components"]:
                public = {**row, "id": prefix + row["id"], "group_id": prefix + row["group_id"], "backup_scope": scope}
                if manager and row.get("supported") is True:
                    public["name"] = ("SDDC Manager — " + manager["name"])[:160]
                    public["warnings"] = [*row.get("warnings", []), "Operations configures this manager and its co-managed NSX using the Operations account and the receiver's verified RSA host key."]
                components.append(public)
            gaps.extend(value.get("coverage_gaps", []))
            identities.append({"binding": manager["manager_uuid"] if manager else "lifecycle", "identity": value["identity"]})
            versions.append(value["version"])

        if "lifecycle" in self.scopes:
            lifecycle = self.root.discover()
            include(self.root, lifecycle, "lifecycle")
            service = lifecycle.get("service")
        if "sddc" in self.scopes:
            if self.proxy is None:
                raise RemoteError("Operations manager proxy is unavailable")
            for manager in managers:
                resource_id = manager["resource_id"]
                child = self._managers.get(resource_id)
                if child is None:
                    child = self._manager_factory(self.source, self.credentials, self.proxy, manager)
                    child.login()
                    self._managers[resource_id] = child
                include(child, child.discover(), "sddc", manager)
            if not managers:
                gaps.append({"product": "sddc", "reason": "Operations has no connected SDDC Managers."})
        if not versions:
            raise RemoteError("Operations did not return a supported backup scope")
        identity = hashlib.sha256(json.dumps({
            "address": self.source["address"], "port": self.source["port"], "fingerprint": self.source["fingerprint"],
            "scopes": self.scopes, "native_identities": identities,
            "manager_plugin": self.proxy.plugin_key if self.proxy is not None else None,
        }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self._routes, self._component_ids = routes, mapping
        self._inventory = {"identity": "operations:" + identity, "version": versions[0],
                           "components": components, "groups": groups, "coverage_gaps": gaps,
                           "service": service, "managed_inventory": inventory}
        return self._inventory

    def _route(self, group: str) -> tuple[Any, str, dict[str, Any]]:
        """Resolve a public group only through its current discovered binding.

        Args:
            group: Composite group identifier from reviewed inventory.
        """
        if not self._routes:
            self.discover()
        if group not in self._routes:
            raise ValueError("Unknown Operations backup group")
        return self._routes[group]

    def proposed(self, group: str, policy: dict[str, Any], receiver: dict[str, Any]) -> dict[str, Any]:
        """Build the selected scheduler's exact public proposal.

        Args:
            group: Reviewed composite scheduler group.
            policy: Operator schedule and retention intent.
            receiver: Applied receiver and verified public host keys.
        """
        child, native_group, _ = self._route(group)
        return dict(child.proposed(native_group, policy, receiver))

    def current(self, group: str) -> dict[str, Any]:
        """Read only the selected native scheduler's current settings.

        Args:
            group: Reviewed composite group.
        """
        child, native_group, _ = self._route(group)
        return dict(child.current(native_group))

    def validate(self, group: str, proposed: dict[str, Any], sftp_password: str, encryption_passphrase: str) -> dict[str, Any]:
        """Run the child product's explicit destination preflight.

        Args:
            group: Reviewed composite group.
            proposed: Reviewed public settings.
            sftp_password: Request-local receiver password.
            encryption_passphrase: Request-local recovery passphrase.
        """
        child, native_group, _ = self._route(group)
        return dict(child.validate(native_group, proposed, sftp_password, encryption_passphrase))

    def configure(self, group: str, proposed: dict[str, Any], sftp_password: str, encryption_passphrase: str) -> dict[str, Any]:
        """Dispatch one reviewed configuration and bind its result to the manager.

        Args:
            group: Reviewed composite group.
            proposed: Reviewed public settings.
            sftp_password: Request-local receiver password.
            encryption_passphrase: Request-local recovery passphrase.
        """
        child, native_group, binding = self._route(group)
        result = child.configure(native_group, proposed, sftp_password, encryption_passphrase)
        return {"operations_binding": binding, "native_reference": result}

    def _reference(self, group: str, reference: dict[str, Any]) -> tuple[Any, str, dict[str, Any]]:
        """Reject a recorded reference belonging to any other Operations resource.

        Args:
            group: Rediscovered composite group.
            reference: Durable native reference and original manager binding.
        """
        child, native_group, binding = self._route(group)
        if (
            not isinstance(reference, dict) or reference.get("operations_binding") != binding
            or not isinstance(reference.get("native_reference"), dict)
        ):
            raise ValueError("Recorded task does not match the Operations manager binding")
        return child, native_group, reference["native_reference"]

    def configuration_status(self, group: str, reference: dict[str, Any]) -> dict[str, Any]:
        """Poll the recorded configuration without replaying it.

        Args:
            group: Rediscovered composite group.
            reference: Recorded and context-bound configuration reference.
        """
        child, native_group, native_reference = self._reference(group, reference)
        return dict(child.configuration_status(native_group, native_reference))

    def start_backup(self, group: str, component_ids: list[str]) -> dict[str, Any]:
        """Start only the selected native scheduler's initial backup once.

        Args:
            group: Reviewed composite group.
            component_ids: Exact public native component membership.
        """
        child, native_group, binding = self._route(group)
        known = self._component_ids[group]
        if not component_ids or len(component_ids) != len(set(component_ids)) or any(item not in known for item in component_ids):
            raise ValueError("Select inspected Operations backup components")
        result = child.start_backup(native_group, [known[item] for item in component_ids])
        return {"reference": {"operations_binding": binding, "native_reference": result.get("reference", result)}}

    def backup_status(self, group: str, reference: dict[str, Any]) -> dict[str, Any]:
        """Read the exact backup reference and map artifact ownership back to public IDs.

        Args:
            group: Rediscovered composite group.
            reference: Recorded and context-bound initial backup reference.
        """
        child, native_group, native_reference = self._reference(group, reference)
        result = dict(child.backup_status(native_group, native_reference))
        reverse = {native_id: public_id for public_id, native_id in self._component_ids[group].items()}
        result["artifacts"] = [{**item, "component_id": reverse.get(str(item.get("component_id", "")), "")}
                               for item in result.get("artifacts", []) if isinstance(item, dict)]
        return result

    def backup_task_status(self, group: str, reference: dict[str, Any]) -> dict[str, Any]:
        """Read task termination without adopting new artifact locations.

        Args:
            group: Rediscovered composite group.
            reference: Original context-bound backup reference.
        """
        child, native_group, native_reference = self._reference(group, reference)
        return dict(child.backup_task_status(native_group, native_reference))
