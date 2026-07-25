from dataclasses import dataclass
import json
from pathlib import Path
import subprocess

from labfoundry.app.config import get_settings


@dataclass(frozen=True)
class AdapterResult:
    command: list[str]
    dry_run: bool
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0


class SystemAdapter:
    """Safe MVP adapter that records approved command intent without executing it."""

    HELPER_PATH = "/opt/labfoundry/bin/labfoundry-helper"

    def __init__(self, dry_run: bool | None = None) -> None:
        settings = get_settings()
        self.dry_run = settings.dry_run_system_adapters if dry_run is None else dry_run

    def apply_wan_policy(self, interface_name: str, policy_name: str) -> AdapterResult:
        return self._record_only_result(["tc", "qdisc", "replace", "dev", interface_name, "root", "netem", "policy", policy_name], "dry-run: WAN policy command recorded")

    def clear_wan_policy(self, interface_name: str) -> AdapterResult:
        return self._record_only_result(["tc", "qdisc", "del", "dev", interface_name, "root"], "dry-run: WAN policy clear command recorded")

    def validate_wan_config(self, config_path: str) -> AdapterResult:
        return self._helper_result("wan", "validate", config_path, dry_run_message="dry-run: WAN config validation command recorded")

    def apply_wan_config(self, config_path: str) -> AdapterResult:
        return self._helper_result("wan", "apply", config_path, dry_run_message="dry-run: WAN config apply command recorded")

    def prepare_apply_staging_path(self, path: str) -> AdapterResult:
        return self._helper_result("staging", "prepare", path, dry_run_message="dry-run: apply staging ownership repair command recorded")

    def service_action(self, service: str, action: str) -> AdapterResult:
        return self._record_only_result(["systemctl", action, service], f"dry-run: service {action} recorded for {service}")

    def service_status(self, unit: str) -> AdapterResult:
        command = ["systemctl", "is-active", unit, "&&", "systemctl", "is-enabled", unit]
        if self.dry_run:
            return AdapterResult(command=command, dry_run=True, stdout=json.dumps({"active": "unknown", "enabled": "unknown"}))
        try:
            active = subprocess.run(["systemctl", "is-active", unit], check=False, capture_output=True, text=True)
            enabled = subprocess.run(["systemctl", "is-enabled", unit], check=False, capture_output=True, text=True)
        except OSError as exc:
            return AdapterResult(command=command, dry_run=False, stderr=f"Unable to query {unit}: {exc}", returncode=127)
        return AdapterResult(
            command=command,
            dry_run=False,
            stdout=json.dumps(
                {
                    "active": active.stdout.strip() or active.stderr.strip(),
                    "active_returncode": active.returncode,
                    "enabled": enabled.stdout.strip() or enabled.stderr.strip(),
                    "enabled_returncode": enabled.returncode,
                },
                sort_keys=True,
            ),
        )

    def validate_dnsmasq_config(self, config_path: str) -> AdapterResult:
        return self._helper_result("dnsmasq", "validate", config_path, dry_run_message="dry-run: dnsmasq validation command recorded")

    def validate_local_users_config(self, config_path: str) -> AdapterResult:
        return self._helper_result("local-users", "validate", config_path, dry_run_message="dry-run: local users validation command recorded")

    def apply_local_users_config(self, config_path: str) -> AdapterResult:
        return self._helper_result("local-users", "apply", config_path, dry_run_message="dry-run: local users apply command recorded")

    def authenticate_local_user(self, username: str, password: str) -> AdapterResult:
        return self._helper_result(
            "local-users",
            "authenticate",
            username,
            dry_run_message="dry-run: local user authentication is unavailable",
            input_text=f"{password}\n",
            dry_run_returncode=1,
        )

    def local_users_status(self, config_path: str) -> AdapterResult:
        if self.dry_run:
            return AdapterResult(command=["labfoundry-helper", "local-users", "status", config_path], dry_run=True, stdout='{"users":[],"status":"dry-run"}')
        return self._helper_result("local-users", "status", config_path, dry_run_message="dry-run: local users status command recorded")

    def apply_dnsmasq_config(self, config_path: str) -> AdapterResult:
        return self._helper_result("dnsmasq", "apply", config_path, dry_run_message="dry-run: dnsmasq apply command recorded")

    def reload_dnsmasq(self) -> AdapterResult:
        return self._helper_result("dnsmasq", "reload", dry_run_message="dry-run: dnsmasq reload command recorded")

    def validate_esxi_pxe_config(self, config_path: str) -> AdapterResult:
        return self._helper_result("esxi-pxe", "validate", config_path, dry_run_message="dry-run: ESXi PXE validation command recorded")

    def apply_esxi_pxe_config(self, config_path: str) -> AdapterResult:
        return self._helper_result("esxi-pxe", "apply", config_path, dry_run_message="dry-run: ESXi PXE apply command recorded")

    def esx_storage_inventory(self) -> AdapterResult:
        return self._helper_result(
            "esx-storage",
            "inventory",
            dry_run_message="dry-run: ESX Storage disk inventory command recorded",
            execute_in_dry_run=True,
        )

    def validate_esx_storage_config(self, config_path: str) -> AdapterResult:
        return self._helper_result("esx-storage", "validate", config_path, dry_run_message="dry-run: ESX Storage validation command recorded")

    def apply_esx_storage_config(self, config_path: str) -> AdapterResult:
        return self._helper_result("esx-storage", "apply", config_path, dry_run_message="dry-run: ESX Storage apply command recorded", timeout_seconds=180)

    def esx_storage_status(self) -> AdapterResult:
        return self._helper_result("esx-storage", "status", dry_run_message="dry-run: ESX Storage status command recorded", use_sudo=False, timeout_seconds=5)

    def esx_storage_logs(self) -> AdapterResult:
        return self._helper_result("esx-storage", "logs", dry_run_message="dry-run: ESX Storage log read command recorded", timeout_seconds=5)

    def read_dhcp_leases(self) -> AdapterResult:
        if self.dry_run:
            return self._record_only_result(
                ["labfoundry-helper", "dnsmasq", "leases"],
                (
                    "1893456000 02:15:5d:00:20:30 192.168.50.130 api-client.labfoundry.internal 01:02:15:5d:00:20:30\n"
                    "1893459600 02:15:5d:00:20:31 192.168.50.131 vcsa.labfoundry.internal 01:02:15:5d:00:20:31"
                ),
            )
        helper_result = self._helper_result("dnsmasq", "leases", dry_run_message="dry-run: dnsmasq lease read command recorded", use_sudo=False)
        if helper_result.returncode == 0:
            return helper_result
        helper_result = self._helper_result("dnsmasq", "leases", dry_run_message="dry-run: dnsmasq lease read command recorded")
        if "sudo:" in helper_result.stderr and "password is required" in helper_result.stderr:
            return AdapterResult(
                command=helper_result.command,
                dry_run=False,
                stdout=helper_result.stdout,
                stderr=(
                    "DHCP lease readback needs the updated LabFoundry sudoers helper rule. "
                    "Reinstall the appliance helper/sudoers configuration, then restart labfoundry.service."
                ),
                returncode=helper_result.returncode,
            )
        return helper_result

    def apply_ca_config(self, config_path: str) -> AdapterResult:
        return self._helper_result("ca", "apply", config_path, dry_run_message="dry-run: CA apply command recorded")

    def validate_ca_config(self, config_path: str) -> AdapterResult:
        return self._helper_result("ca", "validate", config_path, dry_run_message="dry-run: CA validation command recorded")

    def apply_kms_config(self, config_path: str) -> AdapterResult:
        return self._helper_result("kms", "apply", config_path, dry_run_message="dry-run: KMS apply command recorded")

    def validate_kms_config(self, config_path: str) -> AdapterResult:
        return self._helper_result("kms", "validate", config_path, dry_run_message="dry-run: KMS validation command recorded")

    def apply_ldap_config(self, config_path: str) -> AdapterResult:
        return self._helper_result("ldap", "apply", config_path, dry_run_message="dry-run: LDAP apply command recorded")

    def validate_ldap_config(self, config_path: str) -> AdapterResult:
        return self._helper_result("ldap", "validate", config_path, dry_run_message="dry-run: LDAP validation command recorded")

    def ldap_status(self) -> AdapterResult:
        return self._helper_result(
            "ldap",
            "status",
            dry_run_message=json.dumps({"active": "unknown", "listeners": [], "dry_run": True}),
            use_sudo=False,
            timeout_seconds=5,
        )

    def authenticate_ldap_user(self, user_dn: str, password: str) -> AdapterResult:
        return self._helper_result(
            "ldap",
            "authenticate",
            user_dn,
            dry_run_message="dry-run: managed LDAP authentication is unavailable",
            input_text=f"{password}\n",
            dry_run_returncode=1,
        )

    def export_ldap_recovery(self, archive_path: str) -> AdapterResult:
        return self._helper_result("ldap", "export", archive_path, dry_run_message="dry-run: LDAP recovery export command recorded")

    def apply_ntpd_config(self, config_path: str) -> AdapterResult:
        return self._helper_result("ntpd", "apply", config_path, dry_run_message="dry-run: NTPsec apply command recorded")

    def validate_ntpd_config(self, config_path: str) -> AdapterResult:
        return self._helper_result("ntpd", "validate", config_path, dry_run_message="dry-run: NTPsec validation command recorded")

    def read_ntpd_status(self) -> AdapterResult:
        if self.dry_run:
            return self._record_only_result(
                ["labfoundry-helper", "ntpd", "status"],
                json.dumps(
                    {
                        "peers": {"returncode": 0, "stdout": "remote refid st t when poll reach delay offset jitter\n", "stderr": ""},
                        "variables": {"returncode": 0, "stdout": "status=0615 leap_none, sync_ntp\n", "stderr": ""},
                        "nts": {"returncode": 0, "stdout": "NTS client status unavailable in dry-run\n", "stderr": ""},
                    },
                    sort_keys=True,
                ),
            )
        return self._helper_result("ntpd", "status", dry_run_message="dry-run: NTPsec status command recorded", use_sudo=False, timeout_seconds=5)

    def read_ntpd_logs(self) -> AdapterResult:
        if self.dry_run:
            return self._record_only_result(
                ["labfoundry-helper", "ntpd", "logs"],
                "No host NTPsec journal is read in development mode.",
            )
        return self._helper_result("ntpd", "logs", dry_run_message="dry-run: NTPsec log read command recorded", timeout_seconds=5)

    def read_ldap_logs(self) -> AdapterResult:
        if self.dry_run:
            return self._record_only_result(
                ["labfoundry-helper", "ldap", "logs"],
                "No host LDAP journal is read in development mode.",
            )
        return self._helper_result("ldap", "logs", dry_run_message="dry-run: LDAP log read command recorded", timeout_seconds=5)

    def read_dnsmasq_logs(self) -> AdapterResult:
        if self.dry_run:
            return self._record_only_result(
                ["labfoundry-helper", "dnsmasq", "logs"],
                "No host dnsmasq journal is read in development mode.",
            )
        return self._helper_result("dnsmasq", "logs", dry_run_message="dry-run: dnsmasq log read command recorded", timeout_seconds=5)

    def read_nginx_logs(self) -> AdapterResult:
        if self.dry_run:
            return self._record_only_result(
                ["labfoundry-helper", "nginx", "logs"],
                "No host Nginx journal is read in development mode.",
            )
        return self._helper_result("nginx", "logs", dry_run_message="dry-run: Nginx log read command recorded", timeout_seconds=5)

    def read_nginx_access_logs(self) -> AdapterResult:
        if self.dry_run:
            return self._record_only_result(
                ["labfoundry-helper", "nginx", "access-logs"],
                "No host Nginx access log is read in development mode.",
            )
        return self._helper_result("nginx", "access-logs", dry_run_message="dry-run: Nginx access log read command recorded", timeout_seconds=5)

    def read_nginx_error_logs(self) -> AdapterResult:
        if self.dry_run:
            return self._record_only_result(
                ["labfoundry-helper", "nginx", "error-logs"],
                "No host Nginx error log is read in development mode.",
            )
        return self._helper_result("nginx", "error-logs", dry_run_message="dry-run: Nginx error log read command recorded", timeout_seconds=5)

    def read_ntpd_capabilities(self) -> AdapterResult:
        if self.dry_run:
            return self._record_only_result(["labfoundry-helper", "ntpd", "capabilities"], json.dumps({"nts": True, "version": "ntpd ntpsec dry-run"}))
        return self._helper_result(
            "ntpd",
            "capabilities",
            dry_run_message="dry-run: NTPsec capability check recorded",
            use_sudo=False,
            timeout_seconds=5,
        )

    def apply_network_config(self, config_path: str) -> AdapterResult:
        return self._helper_result("network", "apply", config_path, dry_run_message="dry-run: network apply command recorded")

    def validate_network_config(self, config_path: str) -> AdapterResult:
        return self._helper_result("network", "validate", config_path, dry_run_message="dry-run: network validation command recorded")

    def apply_appliance_settings_config(self, config_path: str) -> AdapterResult:
        return self._helper_result("appliance-settings", "apply", config_path, dry_run_message="dry-run: appliance settings apply command recorded")

    def validate_appliance_settings_config(self, config_path: str) -> AdapterResult:
        return self._helper_result("appliance-settings", "validate", config_path, dry_run_message="dry-run: appliance settings validation command recorded")

    def web_terminal_status(self) -> AdapterResult:
        return self._helper_result(
            "web-terminal",
            "status",
            dry_run_message=json.dumps({"enabled": False, "dry_run": True}),
            timeout_seconds=5,
        )

    def sign_web_terminal_key(self, request_path: str) -> AdapterResult:
        return self._helper_result(
            "web-terminal",
            "sign",
            request_path,
            dry_run_message="dry-run: web terminal certificate signing is unavailable",
            timeout_seconds=10,
            dry_run_returncode=2,
        )

    def apply_firewall_config(self, config_path: str) -> AdapterResult:
        return self._helper_result("firewall", "apply", config_path, dry_run_message="dry-run: firewall apply command recorded")

    def validate_firewall_config(self, config_path: str) -> AdapterResult:
        return self._helper_result("firewall", "validate", config_path, dry_run_message="dry-run: firewall validation command recorded")

    def apply_vcf_backup_config(self, config_path: str) -> AdapterResult:
        return self._helper_result("vcf-backups", "apply", config_path, dry_run_message="dry-run: VCF backup SFTP apply command recorded")

    def validate_vcf_backup_config(self, config_path: str) -> AdapterResult:
        return self._helper_result("vcf-backups", "validate", config_path, dry_run_message="dry-run: VCF backup SFTP validation command recorded")

    def validate_vcf_private_registry_config(self, config_path: str) -> AdapterResult:
        return self._record_only_result(["labfoundry-helper", "vcf-private-registry", "validate", config_path], "dry-run: VCF private registry validation command recorded")

    def apply_vcf_private_registry_config(self, config_path: str) -> AdapterResult:
        return self._record_only_result(["labfoundry-helper", "vcf-private-registry", "apply", config_path], "dry-run: VCF private registry apply command recorded")

    def relocate_vcf_private_registry_bundles(self, config_path: str) -> AdapterResult:
        return self._record_only_result(["labfoundry-helper", "vcf-private-registry", "relocate-bundles", config_path], "dry-run: VCF private registry bundle relocation command recorded")

    def validate_vcf_offline_depot_config(self, config_path: str) -> AdapterResult:
        return self._helper_result("vcf-offline-depot", "validate", config_path, dry_run_message="dry-run: VCF Offline Depot validation command recorded")

    def stage_vcf_offline_depot_tool(self, archive_path: str) -> AdapterResult:
        helper_archive_path = str(Path(archive_path).resolve()) if not archive_path.startswith("/") else archive_path
        return self._helper_result("vcf-offline-depot", "stage-tool", helper_archive_path, dry_run_message="dry-run: VCF Download Tool extraction command recorded")

    def reset_vcf_offline_depot_tool(self) -> AdapterResult:
        return self._helper_result("vcf-offline-depot", "reset-tool", dry_run_message="dry-run: VCF Download Tool runtime reset command recorded")

    def generate_vcf_offline_depot_software_depot_id(self) -> AdapterResult:
        return self._helper_result(
            "vcf-offline-depot",
            "generate-software-depot-id",
            dry_run_message="dry-run: VCF Download Tool software depot ID generation command recorded",
        )

    def sync_vcf_offline_depot(self, config_path: str) -> AdapterResult:
        return self._helper_result("vcf-offline-depot", "sync", config_path, dry_run_message="dry-run: VCF Offline Depot sync command recorded")

    def apply_vcf_offline_depot_application_properties(self, properties_path: str) -> AdapterResult:
        return self._helper_result(
            "vcf-offline-depot",
            "apply-properties",
            properties_path,
            dry_run_message="dry-run: VCF Download Tool application properties apply command recorded",
        )

    def apply_vcf_offline_depot_ceip(self, enabled: bool) -> AdapterResult:
        choice = "ENABLE" if enabled else "DISABLE"
        return self._helper_result(
            "vcf-offline-depot",
            "apply-ceip",
            choice,
            dry_run_message=f"dry-run: VCF Download Tool CEIP {choice} command recorded",
        )

    def apply_vcf_offline_depot_https_config(self, config_path: str) -> AdapterResult:
        return self._helper_result("vcf-offline-depot", "apply-https", config_path, dry_run_message="dry-run: VCF Offline Depot HTTPS apply command recorded")

    def validate_public_services_config(self, config_path: str) -> AdapterResult:
        return self._helper_result("public-services", "validate", config_path, dry_run_message="dry-run: public services nginx validation command recorded")

    def apply_public_services_config(self, config_path: str) -> AdapterResult:
        return self._helper_result("public-services", "apply", config_path, dry_run_message="dry-run: public services nginx apply command recorded")

    def check_appliance_update_config(self, config_path: str, credentials_path: str = "") -> AdapterResult:
        args = [config_path, credentials_path] if credentials_path else [config_path]
        return self._helper_result("appliance-update", "check", *args, dry_run_message="dry-run: appliance update check command recorded")

    def apply_appliance_update_config(self, config_path: str, credentials_path: str = "") -> AdapterResult:
        args = [config_path, credentials_path] if credentials_path else [config_path]
        return self._helper_result("appliance-update", "apply", *args, dry_run_message="dry-run: appliance update apply command recorded")

    def sync_appliance_update_sources(self, config_path: str, credentials_path: str = "") -> AdapterResult:
        args = [config_path, credentials_path] if credentials_path else [config_path]
        return self._helper_result("appliance-update", "sync-sources", *args, dry_run_message="dry-run: software source synchronization recorded")

    def restart_appliance_after_update(self, config_path: str) -> AdapterResult:
        return self._helper_result("appliance-update", "restart-service", config_path, dry_run_message="dry-run: LabFoundry service restart command recorded")

    def run_automation_script(self, script_path: str, interpreter: str, timeout_seconds: int, arguments: list[str] | None = None) -> AdapterResult:
        return self._helper_result(
            "automation",
            "run",
            script_path,
            interpreter,
            str(timeout_seconds),
            "--",
            *(arguments or []),
            dry_run_message="dry-run: managed automation script execution recorded",
            timeout_seconds=float(timeout_seconds + 30),
        )

    def schedule_appliance_power(self, action: str) -> AdapterResult:
        if action not in {"reboot", "shutdown"}:
            return AdapterResult(
                command=["labfoundry-helper", "appliance-power", action],
                dry_run=self.dry_run,
                stderr=f"Unsupported appliance power action: {action}",
                returncode=2,
            )
        return self._helper_result(
            "appliance-power",
            action,
            dry_run_message=f"dry-run: appliance {action} scheduling command recorded",
            timeout_seconds=5,
        )

    def _record_only_result(self, command: list[str], stdout: str) -> AdapterResult:
        return AdapterResult(command=command, dry_run=True, stdout=stdout)

    def _helper_result(
        self,
        group: str,
        action: str,
        *args: str,
        dry_run_message: str,
        use_sudo: bool = True,
        timeout_seconds: float | None = None,
        input_text: str | None = None,
        dry_run_returncode: int = 0,
        execute_in_dry_run: bool = False,
    ) -> AdapterResult:
        display_command = ["labfoundry-helper", group, action, *args]
        if self.dry_run and not execute_in_dry_run:
            return AdapterResult(command=display_command, dry_run=True, stdout=dry_run_message, returncode=dry_run_returncode)

        command = [self.HELPER_PATH, group, action, "--real", *args]
        if use_sudo:
            command = ["sudo", "-n", *command]
        run_kwargs: dict[str, object] = {
            "check": False,
            "capture_output": True,
            "text": True,
        }
        if timeout_seconds is not None:
            run_kwargs["timeout"] = timeout_seconds
        if input_text is not None:
            run_kwargs["input"] = input_text
        try:
            completed = subprocess.run(command, **run_kwargs)
        except OSError as exc:
            return AdapterResult(
                command=command,
                dry_run=False,
                stderr=f"Unable to execute {' '.join(command)}: {exc}",
                returncode=127,
            )
        except subprocess.TimeoutExpired:
            return AdapterResult(
                command=command,
                dry_run=False,
                stderr=f"{' '.join(command)} timed out after {timeout_seconds} seconds",
                returncode=124,
            )
        return AdapterResult(
            command=command,
            dry_run=False,
            stdout=completed.stdout,
            stderr=completed.stderr,
            returncode=completed.returncode,
        )
