#!/usr/bin/env python3
"""LabFoundry Hyper-V lifecycle interop runner.

The Windows Hyper-V script owns VM topology. This runner owns appliance and
guest assertions so failures produce reusable evidence instead of console fog.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import html
import http.cookiejar
import json
import random
import re
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from ipaddress import ip_address, ip_interface
from pathlib import Path
from typing import Any

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
except ImportError:  # pragma: no cover - Photon image should include cryptography
    x509 = None  # type: ignore[assignment]


ALL_SCOPES = [
    "read:dashboard",
    "read:interfaces",
    "write:interfaces",
    "read:vlans",
    "write:vlans",
    "read:routes",
    "write:routes",
    "read:wan",
    "write:wan",
    "read:firewall",
    "write:firewall",
    "read:dns",
    "write:dns",
    "read:dhcp",
    "write:dhcp",
    "read:ca",
    "write:ca",
    "read:kms",
    "write:kms",
    "read:repository",
    "write:repository",
    "read:esxi-pxe",
    "write:esxi-pxe",
    "read:esx-storage",
    "write:esx-storage",
    "read:vcf-registry",
    "write:vcf-registry",
    "read:vcf-backups",
    "write:vcf-backups",
    "read:services",
    "write:services",
    "read:logs",
    "read:audit",
    "write:backup",
    "admin:all",
]
LIFECYCLE_LDAP_PASSWORD = "LifecycleLdap1!Strong"


@dataclass
class StepResult:
    name: str
    status: str
    evidence: dict[str, Any] = field(default_factory=dict)
    started_at: str = field(default_factory=lambda: utc_now())
    finished_at: str | None = None
    error: str | None = None

    def finish(self, status: str = "passed", error: str | None = None) -> None:
        self.status = status
        self.error = error
        self.finished_at = utc_now()


class LifecycleError(RuntimeError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run LabFoundry appliance lifecycle interop checks.")
    parser.add_argument("--appliance-url", default="https://192.168.49.1")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", required=True)
    parser.add_argument("--result-dir", default="test-results/hyperv-lifecycle/latest")
    parser.add_argument("--site-interface", default="eth1")
    parser.add_argument("--trunk-interface", default="eth2")
    parser.add_argument("--wan-interface", default="eth3")
    parser.add_argument("--vlan-id", type=int, default=50)
    parser.add_argument("--site-cidr", default="192.168.50.1/24")
    parser.add_argument("--site-ipv6-cidr", default="fd00:50::1/64")
    parser.add_argument("--vlan-cidr", default="192.168.60.1/24")
    parser.add_argument("--wan-cidr", default="172.31.50.1/24")
    parser.add_argument("--domain", default="labfoundry.internal")
    parser.add_argument("--client-a-host", default="")
    parser.add_argument("--client-b-host", default="")
    parser.add_argument("--client-ca-request-interface", default="eth3")
    parser.add_argument("--client-ca-request-cidr", default="192.168.49.20/24")
    parser.add_argument("--client-ca-request-url", default="")
    parser.add_argument("--pxe-test-mode", choices=["linux", "esxi"], default="linux")
    parser.add_argument("--pxe-client-mac", default="")
    parser.add_argument("--pxe-client-ip", default="")
    parser.add_argument("--pxe-installer-iso-path", default="")
    parser.add_argument("--esx-storage-test", action="store_true", help="Configure and apply one dual-stack ESX NFS datastore.")
    parser.add_argument("--esx-storage-device-id", default="", help="Exact eligible /dev/disk/by-id identity; required when inventory has multiple blank disks.")
    parser.add_argument("--esx-storage-ipv4-client", default="192.168.50.210/32")
    parser.add_argument("--esx-storage-ipv6-client", default="fd00:50::210/128")
    parser.add_argument("--confirm-esx-storage-format", action="store_true", help="Authorize the selected lifecycle blank disk to be formatted as ext4.")
    parser.add_argument("--ssh-user", default="", help="Compatibility override for both appliance and client SSH users.")
    parser.add_argument("--appliance-ssh-user", default="admin")
    parser.add_argument("--client-ssh-user", default="alpine")
    parser.add_argument("--ssh-key", default="")
    parser.add_argument("--ssh-password", default="")
    parser.add_argument("--appliance-ssh-host", default="192.168.49.1")
    parser.add_argument("--appliance-ssh-hostkey", default="")
    parser.add_argument("--client-a-hostkey", default="")
    parser.add_argument("--client-b-hostkey", default="")
    parser.add_argument("--vcf-backup-password", default="VMware01!Test")
    parser.add_argument("--vcf-depot-password", default="VMware01!Depot")
    parser.add_argument("--vcf-depot-new-password", default="VMware02!Depot")
    parser.add_argument("--allow-dry-run", action="store_true", help="Allow apply units to report dry-run instead of failing.")
    parser.add_argument(
        "--signed-release-repository-url",
        default="",
        help="Run signed release success/rollback coverage against an HTTPS fixture whose preview channel succeeds and development channel fails after database startup.",
    )
    parser.add_argument("--skip-client-checks", action="store_true")
    parser.add_argument("--export-settings-backup", default="", help="Write a settings backup archive after the full lifecycle run passes.")
    parser.add_argument("--restore-settings-backup", default="", help="Restore a settings backup archive before running restored-state checks.")
    parser.add_argument("--certificate-baseline-result", default="", help="Compare restored CA certificate evidence with a previous lifecycle result.json.")
    parser.add_argument("--restored-state-run", action="store_true", help="Run restored-state checks instead of configuring desired state from scratch.")
    parser.add_argument("--routing-wan-only", action="store_true", help="Run only network, routing, NAT, WAN, and client forwarding checks.")
    parser.add_argument("--plan-only", action="store_true", help="Write the intended lifecycle plan without changing the appliance.")
    return parser.parse_args(argv)


class HttpClient:
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.cookie_jar = http.cookiejar.CookieJar()
        self.https_context = ssl.create_default_context()
        self.https_context.check_hostname = False
        self.https_context.verify_mode = ssl.CERT_NONE
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookie_jar),
            urllib.request.HTTPSHandler(context=self.https_context),
        )
        self.bearer_token = ""

    def remember_base_url(self, url: str) -> None:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme and parsed.netloc:
            self.base_url = f"{parsed.scheme}://{parsed.netloc}"

    def request_bytes(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
        form: dict[str, Any] | list[tuple[str, Any]] | None = None,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
        follow_redirects: bool = True,
        timeout: int = 30,
    ) -> tuple[int, bytes, dict[str, str]]:
        url = f"{self.base_url}{path}"
        request_headers = dict(headers or {})
        if self.bearer_token:
            request_headers.setdefault("Authorization", f"Bearer {self.bearer_token}")
        if json_body is not None:
            body = json.dumps(json_body).encode("utf-8")
            request_headers["Content-Type"] = "application/json"
        elif form is not None:
            body = urllib.parse.urlencode(form, doseq=True).encode("utf-8")
            request_headers["Content-Type"] = "application/x-www-form-urlencoded"
        current_method = method
        current_body = body
        current_headers = dict(request_headers)
        opener = no_redirect_opener(self.cookie_jar, self.https_context)
        for _attempt in range(6):
            request = urllib.request.Request(url, data=current_body, headers=current_headers, method=current_method)
            try:
                with opener.open(request, timeout=timeout) as response:
                    status = response.status
                    response_body = response.read()
                    response_headers = dict(response.headers.items())
                    final_url = response.geturl()
            except urllib.error.HTTPError as exc:
                status = exc.code
                response_body = exc.read()
                response_headers = dict(exc.headers.items())
                final_url = exc.geturl()
            self.remember_base_url(final_url)
            location = next((value for key, value in response_headers.items() if key.lower() == "location"), "")
            if follow_redirects and status in {301, 302, 303, 307, 308} and location:
                url = urllib.parse.urljoin(final_url, location)
                self.remember_base_url(url)
                if status in {301, 302, 303} and current_method.upper() not in {"GET", "HEAD"}:
                    current_method = "GET"
                    current_body = None
                    current_headers = {
                        key: value
                        for key, value in current_headers.items()
                        if key.lower() not in {"content-type", "content-length"}
                    }
                continue
            return status, response_body, response_headers
        raise LifecycleError(f"{method} {path} exceeded redirect limit")

    def request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
        form: dict[str, Any] | list[tuple[str, Any]] | None = None,
        headers: dict[str, str] | None = None,
        follow_redirects: bool = True,
        timeout: int = 30,
    ) -> tuple[int, str, dict[str, str]]:
        status, body, response_headers = self.request_bytes(
            method,
            path,
            json_body=json_body,
            form=form,
            headers=headers,
            follow_redirects=follow_redirects,
            timeout=timeout,
        )
        return status, body.decode("utf-8", errors="replace"), response_headers

    def multipart_request(
        self,
        method: str,
        path: str,
        *,
        fields: dict[str, str],
        files: dict[str, tuple[str, bytes, str]],
    ) -> tuple[int, str, dict[str, str]]:
        boundary = f"----LabFoundryLifecycle{random.randrange(0, 1_000_000_000):09d}"
        chunks: list[bytes] = []
        for name, value in fields.items():
            chunks.extend(
                [
                    f"--{boundary}\r\n".encode("utf-8"),
                    f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode("utf-8"),
                    value.encode("utf-8"),
                    b"\r\n",
                ]
            )
        for name, (filename, content, content_type) in files.items():
            chunks.extend(
                [
                    f"--{boundary}\r\n".encode("utf-8"),
                    f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'.encode("utf-8"),
                    f"Content-Type: {content_type}\r\n\r\n".encode("utf-8"),
                    content,
                    b"\r\n",
                ]
            )
        chunks.append(f"--{boundary}--\r\n".encode("utf-8"))
        status, body, headers = self.request_bytes(
            method,
            path,
            body=b"".join(chunks),
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        )
        return status, body.decode("utf-8", errors="replace"), headers

    def json_request(self, method: str, path: str, *, json_body: dict[str, Any] | None = None) -> Any:
        status, body, _headers = self.request(method, path, json_body=json_body)
        if status >= 400:
            raise LifecycleError(f"{method} {path} failed with HTTP {status}: {body[:500]}")
        return json.loads(body) if body else None


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def no_redirect_opener(cookie_jar: http.cookiejar.CookieJar, https_context: ssl.SSLContext | None = None) -> urllib.request.OpenerDirector:
    handlers: list[Any] = [urllib.request.HTTPCookieProcessor(cookie_jar), NoRedirectHandler]
    if https_context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=https_context))
    return urllib.request.build_opener(*handlers)


def extract_csrf(body: str) -> str:
    patterns = [
        r'name="csrf"\s+value="([^"]+)"',
        r"data-csrf=\"([^\"]+)\"",
    ]
    for pattern in patterns:
        match = re.search(pattern, body)
        if match:
            return html.unescape(match.group(1))
    raise LifecycleError("CSRF token not found in HTML response.")


def summarize_html_response(body: str, *, limit: int = 1200) -> str:
    text = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", body)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    text = html.unescape(text)
    text = re.sub(r"\s+", " ", text).strip()
    anchors = [
        "Resolve validation errors before submitting appliance changes.",
        "Select at least one appliance change to submit.",
        "Appliance apply task failed",
    ]
    for anchor in anchors:
        index = text.find(anchor)
        if index >= 0:
            return text[index : index + limit]
    return text[:limit]


def ssh_username(args: argparse.Namespace, role: str) -> str:
    if args.ssh_user:
        return args.ssh_user
    if role == "appliance":
        return args.appliance_ssh_user
    return args.client_ssh_user


def ssh_hostkey(host: str, args: argparse.Namespace, role: str) -> str:
    if role == "appliance":
        return args.appliance_ssh_hostkey
    if host == args.client_a_host:
        return args.client_a_hostkey
    if host == args.client_b_host:
        return args.client_b_hostkey
    return ""


def appliance_ssh_command(args: argparse.Namespace, command: str) -> str:
    if ssh_username(args, "appliance") == "root":
        return command
    quoted_command = shell_single_quote(command)
    if args.ssh_password:
        quoted_password = shell_single_quote(args.ssh_password)
        return f"printf '%s\\n' {quoted_password} | sudo -S -p '' sh -lc {quoted_command}"
    return f"sudo -n sh -lc {quoted_command}"


def redact_text(value: str, secrets: list[str] | None = None) -> str:
    redacted = value
    for secret in secrets or []:
        if secret:
            redacted = redacted.replace(secret, "[redacted]")
    return redacted


def redact_sequence(values: list[str], secrets: list[str] | None = None) -> list[str]:
    return [redact_text(value, secrets) for value in values]


def ssh_command(
    host: str,
    args: argparse.Namespace,
    command: str,
    *,
    role: str,
    appliance_as_root: bool = True,
    redact_values: list[str] | None = None,
) -> dict[str, Any]:
    if not host:
        raise LifecycleError("SSH host was not provided.")
    user = ssh_username(args, role)
    remote_command = appliance_ssh_command(args, command) if role == "appliance" and appliance_as_root else command
    secrets = [args.ssh_password, *(redact_values or [])]
    if args.ssh_password:
        plink_args = ["plink", "-batch", "-ssh", "-pw", args.ssh_password, f"{user}@{host}", remote_command]
        hostkey = ssh_hostkey(host, args, role)
        if hostkey:
            plink_args[3:3] = ["-hostkey", hostkey]
        redacted = ["plink", "-batch", "-ssh"]
        if hostkey:
            redacted.extend(["-hostkey", hostkey])
        redacted.extend(["-pw", "[redacted]", f"{user}@{host}", redact_text(remote_command, secrets)])
        try:
            completed = subprocess.run(plink_args, text=True, encoding="utf-8", errors="replace", capture_output=True, timeout=120)
        except subprocess.TimeoutExpired as exc:
            return {
                "command": redacted,
                "returncode": 124,
                "stdout": redact_text(exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or ""), secrets),
                "stderr": "SSH command timed out after 120 seconds.",
            }
        return {
            "command": redacted,
            "returncode": completed.returncode,
            "stdout": redact_text(completed.stdout, secrets),
            "stderr": redact_text(completed.stderr, secrets),
        }
    ssh_args = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=15"]
    if args.ssh_key:
        ssh_args.extend(["-i", args.ssh_key])
    target = f"{user}@{host}"
    redacted_command = redact_sequence([*ssh_args, target, remote_command], secrets)
    try:
        completed = subprocess.run([*ssh_args, target, remote_command], text=True, encoding="utf-8", errors="replace", capture_output=True, timeout=120)
    except subprocess.TimeoutExpired as exc:
        return {
            "command": redacted_command,
            "returncode": 124,
            "stdout": redact_text(exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or ""), secrets),
            "stderr": "SSH command timed out after 120 seconds.",
        }
    return {
        "command": redacted_command,
        "returncode": completed.returncode,
        "stdout": redact_text(completed.stdout, secrets),
        "stderr": redact_text(completed.stderr, secrets),
    }


def require_success(result: dict[str, Any], label: str) -> None:
    if result["returncode"] != 0:
        details = []
        if result.get("stderr"):
            details.append(f"stderr: {result['stderr']}")
        if result.get("stdout"):
            details.append(f"stdout: {result['stdout']}")
        raise LifecycleError(f"{label} failed with exit {result['returncode']}: {' '.join(details) or 'no output'}")


def ssh_until_success(
    host: str,
    args: argparse.Namespace,
    command: str,
    *,
    role: str,
    label: str,
    timeout_seconds: int = 60,
    interval_seconds: int = 5,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    attempts = 0
    last_result: dict[str, Any] | None = None
    while True:
        attempts += 1
        last_result = ssh_command(host, args, command, role=role)
        if last_result["returncode"] == 0:
            last_result["attempts"] = attempts
            return last_result
        if time.monotonic() >= deadline:
            last_result["attempts"] = attempts
            require_success(last_result, label)
        time.sleep(interval_seconds)


def lifecycle_plan(args: argparse.Namespace) -> dict[str, Any]:
    vlan_name = f"{args.trunk_interface}.{args.vlan_id}"
    return {
        "appliance_url": args.appliance_url,
        "interfaces": {
            "site": {"name": args.site_interface, "ip_cidr": args.site_cidr, "ipv6_cidr": args.site_ipv6_cidr, "mode": "access"},
            "trunk": {"name": args.trunk_interface, "mode": "trunk"},
            "vlan": {"name": vlan_name, "parent": args.trunk_interface, "vlan_id": args.vlan_id, "ip_cidr": args.vlan_cidr},
            "wan": {"name": args.wan_interface, "ip_cidr": args.wan_cidr, "mode": "access"},
            "client_ca_request": {
                "name": args.client_ca_request_interface,
                "ip_cidr": args.client_ca_request_cidr,
                "url": args.client_ca_request_url or args.appliance_url,
            },
        },
        "apply_units": ["local_users", "network", "firewall", "wan", "dnsmasq", "esxi_pxe", "esx_storage", "ca", "ntpd", "kms", "ldap", "appliance_settings", "vcf_backups", "vcf_offline_depot", "public_services"],
        "esx_storage": {
            "enabled": bool(args.esx_storage_test),
            "device_id": args.esx_storage_device_id,
            "ipv4_client": args.esx_storage_ipv4_client,
            "ipv6_client": args.esx_storage_ipv6_client,
            "format_authorized": bool(args.confirm_esx_storage_format),
        },
        "pxe_boot": {
            "enabled": bool(args.pxe_client_mac),
            "mode": args.pxe_test_mode,
            "client_mac": args.pxe_client_mac,
            "client_ip": pxe_client_ip(args) if args.pxe_client_mac else "",
            "installer_iso_path": args.pxe_installer_iso_path if args.pxe_test_mode == "esxi" else "",
        },
        "checks": [
            "appliance health",
            "interface and VLAN desired state",
            "DNS and DHCP desired state",
            "firewall, routing, NAT, and WAN desired state",
            "CA desired state, root certificate download, atomic generated certificate request with explicit SAN verification, client CSR request, issued certificate download, and client-side verification",
            "NTPsec desired state, NTS upstream and server mode, ntpq health, UDP/123 compatibility, and Alpine chrony-nts authenticated synchronization",
            "KMS desired state, DNS/firewall apply, PyKMIP service, and TLS client-certificate probe",
            "Managed LDAP desired state, two isolated organization suffixes, duplicate uid support, nested groups, configurable LDAP/LDAPS listeners, management-interface exclusion, and CA hostname verification",
            "VCF Backup desired state, local user sync, SFTP listener, and client probe",
            "VCF Offline Depot browser login, curl/wget Basic auth, and Local Users password rotation",
            "ESXi PXE desired state, DHCP boot options, TFTP artifacts, and Hyper-V PXE VM smoke",
            "ESX NFS 3 and 4.1 desired state, blank-disk initialization, equal IPv4/IPv6 DNS targets, exports, sockets, firewall rules, and persistence evidence",
            "passwordless admin web terminal on management and one selected extra interface",
            "client DNS/DHCP/routing probes",
            "optional signed release preview upgrade plus deliberately broken development rollback with database identity verification",
        ],
        "client_checks_enabled": not args.skip_client_checks,
        "routing_wan_only": bool(args.routing_wan_only),
        "settings_backup_export": bool(args.export_settings_backup),
        "settings_backup_restore": bool(args.restore_settings_backup),
        "certificate_baseline_check": bool(args.certificate_baseline_result),
        "signed_release_update_check": bool(args.signed_release_repository_url),
    }


def api_login(client: HttpClient, args: argparse.Namespace) -> str:
    path = f"/api/v1/auth/login?{urllib.parse.urlencode({'username': args.username, 'password': args.password})}"
    payload = {"name": "hyperv lifecycle interop", "scopes": ALL_SCOPES}
    token = client.json_request("POST", path, json_body=payload)["raw_token"]
    client.bearer_token = token
    return token


def ui_login(client: HttpClient, args: argparse.Namespace) -> str:
    status, body, _headers = client.request("GET", "/login")
    if status >= 400:
        raise LifecycleError(f"GET /login failed with HTTP {status}")
    csrf = extract_csrf(body)
    status, body, _headers = client.request(
        "POST",
        "/login",
        form={"username": args.username, "password": args.password, "csrf": csrf},
        follow_redirects=False,
    )
    if status not in {303, 302}:
        raise LifecycleError(f"UI login failed with HTTP {status}: {body[:500]}")
    return csrf


def authenticated_ui_client(client: HttpClient, args: argparse.Namespace) -> HttpClient:
    fresh_client = HttpClient(client.base_url)
    api_login(fresh_client, args)
    ui_login(fresh_client, args)
    return fresh_client


def configure_network(client: HttpClient, args: argparse.Namespace) -> dict[str, Any]:
    evidence: dict[str, Any] = {}
    evidence["refresh"] = client.json_request("POST", "/api/v1/interfaces/refresh")
    if "." in args.site_interface:
        site_parent, site_vlan_raw = args.site_interface.split(".", 1)
        client.json_request(
            "PATCH",
            f"/api/v1/interfaces/physical/{site_parent}",
            json_body={"admin_state": "up", "mode": "trunk", "role": "unused", "ip_cidr": "", "ipv6_enabled": False, "ipv6_cidr": ""},
        )
        ensure_vlan(
            client,
            parent_interface=site_parent,
            vlan_id=int(site_vlan_raw),
            ip_cidr=args.site_cidr,
            ipv6_cidr=args.site_ipv6_cidr,
            role="access",
        )
        evidence["site_vlan"] = args.site_interface
    else:
        client.json_request(
            "PATCH",
            f"/api/v1/interfaces/physical/{args.site_interface}",
            json_body={"admin_state": "up", "mode": "access", "role": "access", "ip_cidr": args.site_cidr, "ipv6_enabled": True, "ipv6_cidr": args.site_ipv6_cidr},
        )
    client.json_request(
        "PATCH",
        f"/api/v1/interfaces/physical/{args.trunk_interface}",
        json_body={"admin_state": "up", "mode": "trunk", "role": "unused", "ip_cidr": ""},
    )
    client.json_request(
        "PATCH",
        f"/api/v1/interfaces/physical/{args.wan_interface}",
        json_body={"admin_state": "up", "mode": "access", "role": "route", "ip_cidr": args.wan_cidr},
    )
    evidence["vlan"] = ensure_vlan(
        client,
        parent_interface=args.trunk_interface,
        vlan_id=args.vlan_id,
        ip_cidr=args.vlan_cidr,
        role="route",
    )
    return evidence


def ensure_vlan(client: HttpClient, *, parent_interface: str, vlan_id: int, ip_cidr: str, role: str, ipv6_cidr: str = "") -> dict[str, Any]:
    existing_vlans = client.json_request("GET", "/api/v1/vlans")
    vlan_name = f"{parent_interface}.{vlan_id}"
    existing = next((row for row in existing_vlans if row.get("name") == vlan_name), None)
    payload = {
        "parent_interface": parent_interface,
        "vlan_id": vlan_id,
        "ip_cidr": ip_cidr,
        "ipv6_cidr": ipv6_cidr,
        "mtu": 1500,
        "role": role,
        "enabled": True,
    }
    if existing:
        return client.json_request("PATCH", f"/api/v1/vlans/{existing['id']}", json_body=payload)
    return client.json_request("POST", "/api/v1/vlans", json_body=payload)


def configure_dns_dhcp(client: HttpClient, args: argparse.Namespace) -> dict[str, Any]:
    site = ip_interface(args.site_cidr)
    site_ip = str(site.ip)
    site_ipv6 = str(ip_interface(args.site_ipv6_cidr).ip)
    site_network = site.network
    hosts = list(site_network.hosts())
    if len(hosts) < 181:
        raise LifecycleError(f"Site network {site_network} is too small for the default lifecycle DHCP pool.")
    range_start = str(hosts[99])
    range_end = str(hosts[179])
    client.json_request(
        "PATCH",
        "/api/v1/dns/settings",
        json_body={
            "enabled": True,
            "listen_interface": args.site_interface,
            "listen_address": f"{site_ip}\n{site_ipv6}",
            "domain": args.domain,
            "upstream_servers": ["1.1.1.1", "9.9.9.9"],
            "conditional_forwarders": [],
            "cache_size": 1000,
            "expand_hosts": True,
            "authoritative": True,
            "authoritative_server": f"ns1.{args.domain}",
            "authoritative_contact": f"hostmaster.{args.domain}",
            "authoritative_ttl": 3600,
            "authoritative_refresh": 1200,
            "authoritative_retry": 180,
            "authoritative_expire": 1209600,
        },
    )
    records = client.json_request("GET", "/api/v1/dns/records")
    record_payload = {
        "hostname": f"interop-appliance.{args.domain}",
        "record_type": "A",
        "address": site_ip,
        "description": "Hyper-V lifecycle interop record",
        "enabled": True,
    }
    existing_record = next((row for row in records if row.get("hostname") == record_payload["hostname"]), None)
    if existing_record:
        record = client.json_request("PATCH", f"/api/v1/dns/records/{existing_record['id']}", json_body=record_payload)
    else:
        record = client.json_request("POST", "/api/v1/dns/records", json_body=record_payload)

    client.json_request(
        "PATCH",
        "/api/v1/dhcp/settings",
        json_body={
            "enabled": True,
            "interface_name": args.site_interface,
            "site_address": site_ip,
            "prefix_length": site.network.prefixlen,
            "range_start": range_start,
            "range_end": range_end,
            "lease_time": "1h",
            "domain_name": args.domain,
            "dns_server": site_ip,
            "authoritative": True,
        },
    )
    scopes = client.json_request("GET", "/api/v1/dhcp/scopes")
    scope_payload = {
        "name": "Lifecycle SiteA",
        "address_family": "ipv4",
        "interface_name": args.site_interface,
        "site_address": site_ip,
        "prefix_length": site.network.prefixlen,
        "range_expression": f"{range_start}-{range_end}",
        "lease_time": "1h",
        "domain_name": args.domain,
        "dns_server": site_ip,
        "ntp_server": "",
        "enabled": True,
        "description": "Hyper-V lifecycle interop scope",
    }
    existing_scope = next((row for row in scopes if row.get("name") == scope_payload["name"]), None)
    if existing_scope:
        scope = client.json_request("PATCH", f"/api/v1/dhcp/scopes/{existing_scope['id']}", json_body=scope_payload)
    else:
        scope = client.json_request("POST", "/api/v1/dhcp/scopes", json_body=scope_payload)
    return {"record": record, "scope": scope}


def configure_esxi_pxe(client: HttpClient, args: argparse.Namespace) -> dict[str, Any]:
    if not args.pxe_client_mac:
        return {"enabled": False, "reason": "No PXE client MAC was supplied."}

    site_ip = str(ip_interface(args.site_cidr).ip)
    hostname = f"esxi-pxe.{args.domain}".strip(".").lower()
    scopes = client.json_request("GET", "/api/v1/dhcp/scopes")
    site_scope = next(
        (
            row
            for row in scopes
            if row.get("name") == "Lifecycle SiteA"
            or (row.get("interface_name") == args.site_interface and row.get("site_address") == site_ip)
        ),
        None,
    )
    if not site_scope or not site_scope.get("id"):
        raise LifecycleError("ESXi PXE setup requires the Lifecycle SiteA DHCP scope to exist before PXE boot settings are saved.")
    status, body, _headers = client.request("GET", "/esxi-pxe")
    if status >= 400:
        raise LifecycleError(f"GET /esxi-pxe failed with HTTP {status}")
    csrf = extract_csrf(body)
    form: list[tuple[str, Any]] = [
        ("enabled", "on"),
        ("hostname", hostname),
        ("dhcp_scope_id", str(site_scope["id"])),
        ("dhcp_scope_ids", str(site_scope["id"])),
        ("listen_interfaces_present", "1"),
        ("listen_interfaces", args.site_interface),
        ("listen_addresses_present", "1"),
        ("listen_addresses", site_ip),
        ("tftp_root", "/var/lib/labfoundry/pxe/tftp"),
        ("http_port", "8080"),
        ("bios_bootfile", "undionly.kpxe"),
        ("uefi_bootfile", "snponly.efi"),
        ("native_uefi_http_enabled", "on"),
        ("native_uefi_http_url", f"http://{site_ip}:8080/pxe/esxi/mboot.efi"),
        ("csrf", csrf),
    ]
    status, response_body, _headers = client.request(
        "POST",
        "/esxi-pxe/boot-settings",
        form=form,
        headers={"X-LabFoundry-Autosave": "1"},
    )
    if status >= 400:
        raise LifecycleError(f"ESXi PXE boot settings update failed with HTTP {status}: {response_body[:500]}")
    settings_payload = json.loads(response_body)
    if settings_payload.get("validation_errors"):
        raise LifecycleError(f"ESXi PXE desired state is invalid: {settings_payload.get('validation_errors')}")

    kickstart_id = None
    if args.pxe_test_mode == "esxi":
        if not args.pxe_installer_iso_path:
            raise LifecycleError("--pxe-installer-iso-path is required when --pxe-test-mode esxi is used.")
        kickstart = ensure_lifecycle_esxi_kickstart(client)
        kickstart_id = kickstart["id"]

    host_payload = {
        "hostname": f"pxe-client.{args.domain}",
        "mac_address": args.pxe_client_mac.strip().lower(),
        "ip_address": pxe_client_ip(args) if args.pxe_test_mode == "esxi" else "",
        "kickstart_id": kickstart_id,
        "installer_iso_path": args.pxe_installer_iso_path if args.pxe_test_mode == "esxi" else "",
        "variables": {},
        "enabled": True,
    }
    existing_hosts = client.json_request("GET", "/api/v1/esxi-pxe/hosts")
    existing_host = next((row for row in existing_hosts if row.get("mac_address", "").lower() == host_payload["mac_address"]), None)
    if existing_host:
        host = client.json_request("PUT", f"/api/v1/esxi-pxe/hosts/{existing_host['id']}", json_body=host_payload)
    else:
        host = client.json_request("POST", "/api/v1/esxi-pxe/hosts", json_body=host_payload)

    reservations = client.json_request("GET", "/api/v1/dhcp/reservations")
    reservation = next(
        (
            row
            for row in reservations
            if str(row.get("mac_address", "")).lower() == host_payload["mac_address"]
            and str(row.get("ip_address", "")) == host_payload["ip_address"]
            and row.get("enabled") is True
        ),
        None,
    )
    if args.pxe_test_mode == "esxi" and not reservation:
        raise LifecycleError(
            f"ESXi PXE host {host_payload['mac_address']} did not create an enabled DHCP reservation for {host_payload['ip_address']}."
        )

    return {
        "enabled": True,
        "mode": args.pxe_test_mode,
        "hostname": hostname,
        "dhcp_scope_id": site_scope["id"],
        "dhcp_scope_name": site_scope.get("name"),
        "listen_interface": args.site_interface,
        "listen_address": site_ip,
        "client_mac": host_payload["mac_address"],
        "client_ip": host_payload["ip_address"],
        "kickstart_id": kickstart_id,
        "installer_iso_path": host_payload["installer_iso_path"],
        "host_id": host.get("id"),
        "dhcp_reservation_id": reservation.get("id") if reservation else None,
        "dns_record_action": settings_payload.get("dns_record_action"),
    }


def lifecycle_esxi_kickstart_content() -> str:
    return """#
# LabFoundry lifecycle ESXi scripted install.
vmaccepteula
rootpw vmware01!
install --firstdisk --overwritevmfs
network --bootproto=dhcp --device=vmnic0 --hostname=pxe-client.labfoundry.internal
reboot

%firstboot --interpreter=busybox
vim-cmd hostsvc/enable_ssh
vim-cmd hostsvc/start_ssh
esxcli network firewall ruleset set -e true -r sshServer
"""


def ensure_lifecycle_esxi_kickstart(client: HttpClient) -> dict[str, Any]:
    name = "Lifecycle ESXi install"
    payload = {
        "name": name,
        "description": "Created by the LabFoundry lifecycle ESXi PXE install check.",
        "content": lifecycle_esxi_kickstart_content(),
        "enabled": True,
    }
    kickstarts = client.json_request("GET", "/api/v1/esxi-pxe/kickstarts")
    existing = next((row for row in kickstarts if row.get("name") == name), None)
    if existing:
        return client.json_request("PUT", f"/api/v1/esxi-pxe/kickstarts/{existing['id']}", json_body=payload)
    return client.json_request("POST", "/api/v1/esxi-pxe/kickstarts", json_body=payload)


def configure_firewall(client: HttpClient, args: argparse.Namespace) -> dict[str, Any]:
    return client.json_request(
        "PATCH",
        "/api/v1/firewall/settings",
        json_body={
            "enabled": True,
            "default_input_policy": "drop",
            "default_forward_policy": "drop",
            "default_output_policy": "accept",
            "allow_established": True,
            "allow_loopback": True,
            "allow_icmp": True,
            "log_dropped": False,
        },
    )


def configure_wan_policy(client: HttpClient, args: argparse.Namespace) -> dict[str, Any]:
    policies = client.json_request("GET", "/api/v1/wan/policies")
    policy_payload = wan_policy_payload(packet_loss_percent=0.0)
    existing_policy = next((row for row in policies if row.get("name") == policy_payload["name"]), None)
    if existing_policy:
        return client.json_request("PATCH", f"/api/v1/wan/policies/{existing_policy['id']}", json_body=policy_payload)
    return client.json_request("POST", "/api/v1/wan/policies", json_body=policy_payload)


def configure_routes_nat(client: HttpClient, args: argparse.Namespace, policy: dict[str, Any] | None = None) -> dict[str, Any]:
    site_source = str(ip_interface(args.site_cidr).network)
    wan_network = str(ip_interface(args.wan_cidr).network)
    policy = policy or configure_wan_policy(client, args)
    route_payload = {
        "destination_cidr": wan_network,
        "gateway": None,
        "interface_name": args.wan_interface,
        "metric": 100,
        "enabled": True,
        "wan_policy_id": policy["id"],
        "wan_mode": "interface",
    }
    routes = client.json_request("GET", "/api/v1/routes")
    existing_route = next(
        (
            row
            for row in routes
            if row.get("destination_cidr") == route_payload["destination_cidr"]
            and row.get("interface_name") == route_payload["interface_name"]
        ),
        None,
    )
    if existing_route:
        route = client.json_request("PATCH", f"/api/v1/routes/{existing_route['id']}", json_body=route_payload)
    else:
        route = client.json_request("POST", "/api/v1/routes", json_body=route_payload)
    nat_payload = {
        "name": "Lifecycle SiteA outbound WAN",
        "enabled": True,
        "source": site_source,
        "outbound_interface": args.wan_interface,
        "masquerade": True,
        "priority": 100,
        "description": "Hyper-V lifecycle interop NAT",
    }
    nat_rules = client.json_request("GET", "/api/v1/nat/rules")
    existing_nat = next((row for row in nat_rules if row.get("name") == nat_payload["name"]), None)
    if existing_nat:
        nat = client.json_request("PATCH", f"/api/v1/nat/rules/{existing_nat['id']}", json_body=nat_payload)
    else:
        nat = client.json_request("POST", "/api/v1/nat/rules", json_body=nat_payload)
    return {"route": route, "nat": nat}


def routing_rule_form_payload(args: argparse.Namespace) -> dict[str, str]:
    return {
        "name": "Lifecycle SiteA to WAN",
        "source_interface": args.site_interface,
        "destination_interface": args.wan_interface,
        "priority": "100",
        "description": "Lifecycle explicit access-network routing permission.",
        "enabled": "on",
    }


def configure_routing_permissions(client: HttpClient, args: argparse.Namespace) -> dict[str, Any]:
    status, body, _headers = client.request("GET", "/routes-wan")
    if status >= 400:
        raise LifecycleError(f"GET /routes-wan failed with HTTP {status}")
    csrf = extract_csrf(body)
    payload = routing_rule_form_payload(args)
    status, response_body, headers = client.request(
        "POST",
        "/routes-wan/routing-rules",
        form={**payload, "csrf": csrf},
        follow_redirects=False,
    )
    if status in {302, 303}:
        return {"created_or_updated": True, "routing_rule": payload, "location": headers.get("Location", "")}
    if status == 409 or "already exists" in response_body.lower():
        return {"created_or_updated": False, "routing_rule": payload, "reason": "already exists"}
    if status >= 400:
        raise LifecycleError(f"Routing permission setup failed with HTTP {status}: {response_body[:500]}")
    return {"created_or_updated": True, "routing_rule": payload}


def configure_firewall_wan(client: HttpClient, args: argparse.Namespace) -> dict[str, Any]:
    firewall = configure_firewall(client, args)
    policy = configure_wan_policy(client, args)
    routes_nat = configure_routes_nat(client, args, policy)
    routing = configure_routing_permissions(client, args)
    return {"firewall": firewall, "wan_policy": policy, **routes_nat, "routing": routing}


def wan_policy_payload(*, packet_loss_percent: float) -> dict[str, Any]:
    return {
        "name": "Lifecycle WAN",
        "description": "Hyper-V lifecycle interop WAN policy",
        "enabled": True,
        "latency_ms": 25,
        "jitter_ms": 5,
        "packet_loss_percent": packet_loss_percent,
        "bandwidth_mbit": 100,
        "corrupt_percent": 0.0,
        "duplicate_percent": 0.0,
        "reorder_percent": 0.0,
    }


def set_lifecycle_wan_policy(client: HttpClient, *, packet_loss_percent: float) -> dict[str, Any]:
    policies = client.json_request("GET", "/api/v1/wan/policies")
    payload = wan_policy_payload(packet_loss_percent=packet_loss_percent)
    matching_policies = [row for row in policies if row.get("name") == payload["name"]]
    if not matching_policies:
        raise LifecycleError("Lifecycle WAN policy was not found; configure-firewall-wan must run before WAN loss checks.")
    updated = [
        client.json_request("PATCH", f"/api/v1/wan/policies/{policy['id']}", json_body=payload)
        for policy in matching_policies
    ]
    return {"packet_loss_percent": packet_loss_percent, "updated_count": len(updated), "policies": updated}


def certificate_summary(pem: str) -> dict[str, Any]:
    summary: dict[str, Any] = {"pem_bytes": len(pem.encode("utf-8"))}
    if x509 is None:
        return summary
    certificate = x509.load_pem_x509_certificate(pem.encode("utf-8"))
    summary.update(
        {
            "subject": certificate.subject.rfc4514_string(),
            "issuer": certificate.issuer.rfc4514_string(),
            "serial_number": format(certificate.serial_number, "x"),
            "sha256_fingerprint": certificate.fingerprint(hashes.SHA256()).hex(),
            "not_before": certificate.not_valid_before_utc.isoformat(),
            "not_after": certificate.not_valid_after_utc.isoformat(),
        }
    )
    return summary


def configure_ca(client: HttpClient, args: argparse.Namespace) -> dict[str, Any]:
    status, body, _headers = client.request("GET", "/certificate-authority")
    if status >= 400:
        raise LifecycleError(f"GET /certificate-authority failed with HTTP {status}")
    csrf = extract_csrf(body)
    form = {
        "enabled": "on",
        "listen_interfaces_present": "1",
        "listen_interfaces": [args.site_interface],
        "root_common_name": "LabFoundry Lifecycle Root CA",
        "organization": "LabFoundry",
        "organizational_unit": "Interop",
        "country": "US",
        "state": "California",
        "locality": "Lifecycle Lab",
        "key_algorithm": "RSA",
        "key_size": "2048",
        "digest_algorithm": "sha256",
        "root_valid_days": "3650",
        "intermediate_valid_days": "1825",
        "csrf": csrf,
    }
    status, response_body, _headers = client.request("POST", "/certificate-authority/settings", form=form, follow_redirects=False)
    if status not in {200, 302, 303}:
        raise LifecycleError(f"CA settings update failed with HTTP {status}: {response_body[:500]}")
    status, root_ca, _headers = client.request("GET", "/certificate-authority/downloads/root-ca.pem")
    if status >= 400 or "BEGIN CERTIFICATE" not in root_ca:
        raise LifecycleError(f"CA root download failed with HTTP {status}")
    return {"root_ca": certificate_summary(root_ca)}


def configure_ntp(client: HttpClient, args: argparse.Namespace) -> dict[str, Any]:
    status, body, _headers = client.request("GET", "/ntp")
    if status >= 400:
        raise LifecycleError(f"GET /ntp failed with HTTP {status}")
    csrf = extract_csrf(body)
    hostname = f"ntp.{args.domain}"
    sources = json.dumps(
        [
            {"id": "cloudflare-nts", "source": "time.cloudflare.com", "enabled": True, "use_nts": True, "description": "Cloudflare public NTS"},
            {"id": "netnod-nts", "source": "nts.netnod.se", "enabled": True, "use_nts": True, "description": "Netnod public NTS"},
        ]
    )
    form = {
        "enabled": "on",
        "hostname": hostname,
        "listen_interfaces_present": "1",
        "listen_interfaces": [args.site_interface],
        "port": "123",
        "upstream_sources_json": sources,
        "allow_clients": str(ip_interface(args.site_cidr).network),
        "nts_server_enabled": "on",
        "minsources": "1",
        "csrf": csrf,
    }
    status, response_body, _headers = client.request(
        "POST",
        "/ntp/settings",
        form=form,
        headers={"X-LabFoundry-Autosave": "1"},
    )
    if status >= 400:
        raise LifecycleError(f"NTP settings update failed with HTTP {status}: {response_body[:500]}")
    payload = json.loads(response_body)
    if not payload.get("valid") or not payload.get("nts_server_enabled"):
        raise LifecycleError(f"NTP/NTS desired state is not ready: {payload.get('validation_errors')}")
    return {
        "hostname": payload.get("hostname"),
        "listen_interfaces": payload.get("listen_interfaces"),
        "listen_addresses": payload.get("listen_addresses"),
        "upstream_sources": payload.get("upstream_sources"),
        "nts_server_enabled": payload.get("nts_server_enabled"),
    }


def configure_management_https(client: HttpClient, args: argparse.Namespace) -> dict[str, Any]:
    status, body, _headers = client.request("GET", "/settings")
    if status >= 400:
        raise LifecycleError(f"GET /settings failed with HTTP {status}")
    csrf = extract_csrf(body)
    settings_payload = client.json_request("GET", "/api/v1/settings")
    management_interface = str(settings_payload.get("management_interface") or "eth0")
    form = {
        "fqdn": "labfoundry.labfoundry.internal",
        "management_https_enabled": "on",
        "web_terminal_enabled": "on",
        "web_terminal_interfaces_present": "1",
        "web_terminal_interfaces": [management_interface, args.site_interface],
        "external_dns_servers": "1.1.1.1\n9.9.9.9",
        "csrf": csrf,
    }
    status, response_body, _headers = client.request(
        "POST",
        "/settings",
        form=form,
        headers={"X-LabFoundry-Autosave": "1"},
    )
    if status >= 400:
        raise LifecycleError(f"Management HTTPS settings update failed with HTTP {status}: {response_body[:500]}")
    payload = json.loads(response_body)
    if not payload.get("valid"):
        raise LifecycleError(f"Management HTTPS desired state is invalid: {payload.get('validation_errors')}")
    if not payload.get("management_https_enabled") or not payload.get("management_https_cert_available"):
        raise LifecycleError("Management HTTPS desired state did not report an available CA-managed certificate.")
    if not payload.get("web_terminal_enabled") or payload.get("web_terminal_interfaces") != [management_interface, args.site_interface]:
        raise LifecycleError(f"Web terminal desired state did not retain the selected interfaces: {payload.get('web_terminal_interfaces')}")
    ceip_status, ceip_body, _headers = client.request(
        "POST",
        "/settings/vmware-ceip",
        form={"csrf": csrf},
        headers={"X-LabFoundry-Autosave": "1"},
    )
    if ceip_status >= 400:
        raise LifecycleError(f"VMware CEIP settings update failed with HTTP {ceip_status}: {ceip_body[:500]}")
    ceip_payload = json.loads(ceip_body)
    if ceip_payload.get("vmware_ceip_enabled") is not False:
        raise LifecycleError("VMware CEIP desired state did not remain disabled.")
    return {
        "fqdn": payload.get("fqdn"),
        "management_https_enabled": payload.get("management_https_enabled"),
        "management_https_cert_available": payload.get("management_https_cert_available"),
        "web_terminal_enabled": payload.get("web_terminal_enabled"),
        "web_terminal_interfaces": payload.get("web_terminal_interfaces"),
        "web_terminal_addresses": payload.get("web_terminal_addresses"),
        "vmware_ceip_enabled": ceip_payload.get("vmware_ceip_enabled"),
        "config_path": payload.get("config_path"),
    }


def https_request_unverified(url: str) -> tuple[int, str, dict[str, str]]:
    request = urllib.request.Request(url, method="GET")
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(request, timeout=30, context=context) as response:
            return response.status, response.read().decode("utf-8", errors="replace"), dict(response.headers.items())
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace"), dict(exc.headers.items())


def management_https_check(client: HttpClient, args: argparse.Namespace) -> dict[str, Any]:
    parsed = urllib.parse.urlparse(args.appliance_url)
    host = parsed.hostname or args.appliance_ssh_host
    http_client = HttpClient(f"http://{host}")
    http_status, _http_body, http_headers = http_client.request("GET", "/openapi.json", follow_redirects=False)
    if http_status not in {301, 302, 307, 308}:
        raise LifecycleError(f"HTTP management endpoint should redirect after HTTPS apply, got HTTP {http_status}")
    location = http_headers.get("Location", "")
    if not location.lower().startswith("https://"):
        raise LifecycleError(f"HTTP management redirect did not point at HTTPS: {location}")
    https_url = f"https://{host}/openapi.json"
    https_status, https_body, _https_headers = https_request_unverified(https_url)
    if https_status >= 400 or '"openapi"' not in https_body:
        raise LifecycleError(f"HTTPS management endpoint failed with HTTP {https_status}")
    client.base_url = f"https://{host}"
    return {"http_status": http_status, "redirect_location": location, "https_status": https_status, "https_url": https_url}


def web_terminal_check(client: HttpClient, args: argparse.Namespace) -> dict[str, Any]:
    management_status, management_body, _headers = client.request("GET", "/terminal")
    if management_status != 200 or 'data-terminal-available="true"' not in management_body:
        raise LifecycleError(f"Management web terminal was not ready after apply: HTTP {management_status}")

    host_evidence = ssh_command(
        args.appliance_ssh_host,
        args,
        "/opt/labfoundry/bin/labfoundry-helper web-terminal status --real && sshd -T | grep -i '^trustedusercakeys '",
        role="appliance",
    )
    require_success(host_evidence, "web terminal OpenSSH CA state")
    if '"enabled": true' not in host_evidence.get("stdout", "") or "web-terminal-ca.pub" not in host_evidence.get("stdout", ""):
        raise LifecycleError(f"OpenSSH did not report the applied web terminal CA state: {host_evidence.get('stdout', '')}")

    site_address = str(ip_interface(args.site_cidr).ip)
    site_client = HttpClient(f"https://{site_address}")
    ui_login(site_client, args)
    site_status, site_body, _site_headers = site_client.request("GET", "/terminal")
    if site_status != 200 or 'data-terminal-available="true"' not in site_body:
        raise LifecycleError(f"Selected extra-interface terminal route was not ready: HTTP {site_status}")
    csrf_match = re.search(r'data-csrf="([^"]+)"', site_body)
    if not csrf_match:
        raise LifecycleError("Selected extra-interface terminal page did not include a session CSRF token.")
    ticket_status, ticket_body, _ticket_headers = site_client.request(
        "POST",
        "/terminal/tickets",
        form={"csrf": html.unescape(csrf_match.group(1))},
    )
    if ticket_status != 200:
        raise LifecycleError(f"Selected extra-interface terminal ticket failed with HTTP {ticket_status}: {ticket_body[:300]}")
    ticket_payload = json.loads(ticket_body)
    if ticket_payload.get("websocket_path") != "/terminal/ws" or not ticket_payload.get("ticket"):
        raise LifecycleError("Web terminal ticket response was incomplete.")
    dashboard_status, _dashboard_body, _dashboard_headers = site_client.request("GET", "/dashboard", follow_redirects=False)
    if dashboard_status != 404:
        raise LifecycleError(f"Extra-interface terminal listener exposed /dashboard with HTTP {dashboard_status}")
    return {
        "management_status": management_status,
        "extra_interface": args.site_interface,
        "extra_address": site_address,
        "extra_terminal_status": site_status,
        "ticket_status": ticket_status,
        "dashboard_status": dashboard_status,
        "host_status": host_evidence.get("stdout", ""),
    }


def extract_ca_profile_id(body: str, profile_name: str) -> str:
    for match in re.finditer(r'<option value="(\d+)">([^<]+)</option>', body):
        if html.unescape(match.group(2)).strip() == profile_name:
            return match.group(1)
    raise LifecycleError(f"Could not find enabled CA profile {profile_name!r}.")


def extract_ca_certificate_id(body: str, common_name: str) -> str:
    row_pattern = re.compile(
        rf"<tr>\s*<td>{re.escape(html.escape(common_name))}</td>.*?/certificate-authority/certificates/(\d+)/downloads/certificate\.pem",
        flags=re.DOTALL,
    )
    match = row_pattern.search(body)
    if match:
        return match.group(1)
    loose = re.search(r"/certificate-authority/certificates/(\d+)/downloads/certificate\.pem", body)
    if loose and common_name in body:
        return loose.group(1)
    raise LifecycleError(f"Could not find issued CA certificate download link for {common_name}.")


def create_client_csr(common_name: str) -> str:
    if x509 is None:
        raise LifecycleError("cryptography is required to generate the lifecycle client CSR.")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "LabFoundry"),
                    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Lifecycle Client"),
                ]
            )
        )
        .sign(private_key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def client_ca_probe_setup(interface_name: str, address_cidr: str, request_host: str) -> str:
    ca_request = ip_interface(address_cidr)
    ca_interface = shell_single_quote(interface_name)
    neigh_flush = ""
    if request_host:
        neigh_flush = f"$ELEV ip neigh flush {shell_single_quote(request_host)} dev \"$CA_IF\" 2>/dev/null || true; "
    return (
        f"CA_IF={ca_interface}; "
        'if ip link show dev "$CA_IF" >/dev/null 2>&1; then '
        '$ELEV ip link set "$CA_IF" up; '
        f'$ELEV ip addr replace {ca_request.ip}/{ca_request.network.prefixlen} dev "$CA_IF"; '
        f"{neigh_flush}"
        'else echo "optional CA probe interface $CA_IF not present; using existing route" >&2; fi; '
    )


def session_cookie_header(client: HttpClient) -> str:
    return "; ".join(f"{cookie.name}={cookie.value}" for cookie in client.cookie_jar)


def ca_client_certificate_request(client: HttpClient, args: argparse.Namespace) -> dict[str, Any]:
    if args.skip_client_checks:
        return {"skipped": "client checks disabled"}
    if not args.client_a_host:
        return {"skipped": "client A host not provided"}
    common_name = f"client-a.{args.domain}"
    csr_text = create_client_csr(common_name)

    status, body, _headers = client.request("GET", "/certificate-authority")
    if status >= 400:
        raise LifecycleError(f"GET /certificate-authority failed with HTTP {status}")
    csrf = extract_csrf(body)
    profile_id = extract_ca_profile_id(body, "VCF KMIP client")
    cookie_header = session_cookie_header(client)
    if not cookie_header:
        raise LifecycleError("No authenticated session cookie is available for the client CA request.")
    ca_request = ip_interface(args.client_ca_request_cidr)
    ca_request_url = (args.client_ca_request_url or client.base_url).rstrip("/")
    ca_probe_setup = client_ca_probe_setup(args.client_ca_request_interface, args.client_ca_request_cidr, urllib.parse.urlparse(ca_request_url).hostname or "")
    elevate = elevation_probe()
    command = (
        f"ELEV=\"$({elevate})\"; "
        "test -n \"$ELEV\"; "
        f"{ca_probe_setup}"
        "http_code=$(curl -k -sS --connect-timeout 10 --max-time 30 -o /dev/null -w '%{http_code}' "
        f"-X POST -H {shell_single_quote('Cookie: ' + cookie_header)} "
        f"--data-urlencode csrf={shell_single_quote(csrf)} "
        f"--data-urlencode common_name={shell_single_quote(common_name)} "
        f"--data-urlencode profile_id={shell_single_quote(profile_id)} "
        "--data-urlencode subject_alt_names= "
        "--data-urlencode ip_addresses= "
        "--data-urlencode status=csr-staged "
        "--data-urlencode serial_number= "
        "--data-urlencode description='Hyper-V lifecycle client CSR request' "
        f"--data-urlencode csr_text={shell_single_quote(csr_text.strip())} "
        "--data-urlencode enabled=on "
        f"{ca_request_url}/certificate-authority/certificates); "
        "echo \"$http_code\"; test \"$http_code\" = \"302\" -o \"$http_code\" = \"303\""
    )
    request_result = ssh_command(args.client_a_host, args, command, role="client", redact_values=[cookie_header])
    require_success(request_result, "client A CA certificate request")
    return {
        "common_name": common_name,
        "profile": "VCF KMIP client",
        "csr_bytes": len(csr_text.encode("utf-8")),
        "request": request_result,
        "requested_via": f"{ca_request_url}/certificate-authority/certificates",
        "client_probe_ip": str(ca_request.ip),
        "client_probe_interface": args.client_ca_request_interface,
    }


def ca_generated_certificate_request_check(client: HttpClient, args: argparse.Namespace) -> dict[str, Any]:
    if x509 is None:
        raise LifecycleError("cryptography is required to verify the generated lifecycle certificate.")
    common_name = f"generated-client-a.{args.domain}"
    alternate_name = f"generated-alias.{args.domain}"
    ip_san = str(ip_interface(args.client_ca_request_cidr).ip)
    status, body, _headers = client.request("GET", "/certificate-authority")
    if status >= 400:
        raise LifecycleError(f"GET /certificate-authority failed with HTTP {status}")
    csrf = extract_csrf(body)
    profile_id = extract_ca_profile_id(body, "VCF service TLS")
    form = {
        "csrf": csrf,
        "common_name": common_name,
        "profile_id": profile_id,
        "subject_alt_names": f"{common_name}\n{alternate_name}",
        "ip_addresses": ip_san,
        "description": "Hyper-V lifecycle generated certificate request",
        "enabled": "on",
    }
    status, response_body, _headers = client.request(
        "POST",
        "/certificate-authority/certificates",
        form=form,
        follow_redirects=False,
    )
    if status not in {302, 303}:
        raise LifecycleError(f"Generated CA certificate request failed with HTTP {status}: {response_body[:500]}")
    status, body, _headers = client.request("GET", "/certificate-authority")
    if status >= 400:
        raise LifecycleError(f"GET /certificate-authority after generated request failed with HTTP {status}")
    certificate_id = extract_ca_certificate_id(body, common_name)
    status, certificate_pem, _headers = client.request(
        "GET",
        f"/certificate-authority/certificates/{certificate_id}/downloads/certificate.pem",
    )
    if status >= 400 or "BEGIN CERTIFICATE" not in certificate_pem:
        raise LifecycleError(f"Generated CA certificate download failed with HTTP {status}")
    certificate = x509.load_pem_x509_certificate(certificate_pem.encode("utf-8"))
    subject_names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    subject_cn = subject_names[0].value if subject_names else ""
    if subject_cn != common_name:
        raise LifecycleError(f"Generated certificate CN {subject_cn!r} does not match {common_name!r}.")
    sans = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    dns_sans = sans.get_values_for_type(x509.DNSName)
    ip_sans = [str(value) for value in sans.get_values_for_type(x509.IPAddress)]
    if dns_sans != [common_name, alternate_name]:
        raise LifecycleError(f"Generated certificate DNS SANs {dns_sans!r} do not match the submitted request.")
    if ip_sans != [ip_san]:
        raise LifecycleError(f"Generated certificate IP SANs {ip_sans!r} do not match the submitted request.")
    eku = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    if ExtendedKeyUsageOID.SERVER_AUTH not in eku:
        raise LifecycleError("Generated certificate is missing the serverAuth extended key usage.")
    return {
        "common_name": common_name,
        "certificate_id": certificate_id,
        "dns_sans": dns_sans,
        "ip_sans": ip_sans,
        "profile": "VCF service TLS",
        "certificate": certificate_summary(certificate_pem),
    }


def extract_vcf_backup_user_id(body: str) -> str:
    for match in re.finditer(r'<option value="(\d+)"[^>]*>(.*?)</option>', body, flags=re.DOTALL):
        label = re.sub(r"\s+", " ", html.unescape(match.group(2))).strip()
        if label in {"vcf-backup", "vcf-backup (disabled)"}:
            return match.group(1)
    raise LifecycleError("Could not find the default vcf-backup local user in /vcf-backups.")


def extract_user_id_from_users_page(body: str, username: str) -> str:
    for match in re.finditer(r"<button[^>]*data-reset-user-button[^>]*>", body):
        tag = match.group(0)
        id_match = re.search(r'data-user-id="(\d+)"', tag)
        username_match = re.search(r'data-username="([^"]+)"', tag)
        if id_match and username_match and html.unescape(username_match.group(1)).strip() == username:
            return id_match.group(1)
    raise LifecycleError(f"Could not find local user {username!r} in /users.")


def ensure_vcf_backup_user_id(client: HttpClient, args: argparse.Namespace) -> tuple[str, str]:
    status, body, _headers = client.request("GET", "/users")
    if status >= 400:
        raise LifecycleError(f"GET /users failed with HTTP {status}")
    csrf = extract_csrf(body)
    try:
        return extract_user_id_from_users_page(body, "vcf-backup"), csrf
    except LifecycleError:
        pass
    status, create_body, _headers = client.request(
        "POST",
        "/users",
        form={"username": "vcf-backup", "role": "viewer", "roles": "viewer", "shell": "/sbin/nologin", "csrf": csrf},
        follow_redirects=False,
    )
    if status not in {200, 302, 303, 409}:
        raise LifecycleError(f"VCF backup user creation failed with HTTP {status}: {create_body[:500]}")
    status, body, _headers = client.request("GET", "/users")
    if status >= 400:
        raise LifecycleError(f"GET /users failed with HTTP {status}")
    return extract_user_id_from_users_page(body, "vcf-backup"), extract_csrf(body)


def stage_vcf_backup_password_via_appliance(args: argparse.Namespace) -> dict[str, Any]:
    password_literal = repr(args.vcf_backup_password)
    python_script = f"""
from sqlalchemy import select

from labfoundry.app.database import SessionLocal
from labfoundry.app.models import User, VcfBackupSettings
from labfoundry.app.services.local_users import stage_user_os_password

password = {password_literal}
with SessionLocal() as db:
    user = db.execute(select(User).where(User.username == "vcf-backup")).scalar_one_or_none()
    if user is None:
        user = User(username="vcf-backup", role="viewer", roles_json='["viewer"]', shell="/sbin/nologin", enabled=True)
        db.add(user)
        db.flush()
    stage_user_os_password(user, password)
    user.enabled = True
    db.add(user)
    settings = db.execute(select(VcfBackupSettings)).scalar_one_or_none()
    if settings is not None:
        settings.sftp_user_id = user.id
        db.add(settings)
    db.commit()
    print(f"staged:user_id={{user.id}}")
"""
    encoded_script = base64.b64encode(python_script.encode("utf-8")).decode("ascii")
    script = (
        "set -a; . /etc/labfoundry/labfoundry.env; set +a; "
        f"printf %s {shell_single_quote(encoded_script)} | base64 -d | /opt/labfoundry/.venv/bin/python -"
    )
    result = ssh_command(args.appliance_ssh_host, args, script, role="appliance", redact_values=[args.vcf_backup_password])
    require_success(result, "appliance VCF backup password staging")
    return {"username": "vcf-backup", "password_staged": True, "method": "appliance-python", "ssh": result}


def stage_vcf_backup_password(client: HttpClient, args: argparse.Namespace) -> dict[str, Any]:
    status, body, _headers = client.request("GET", "/vcf-backups")
    if status >= 400:
        raise LifecycleError(f"GET /vcf-backups failed with HTTP {status}")
    csrf = extract_csrf(body)
    try:
        user_id = extract_vcf_backup_user_id(body)
    except LifecycleError:
        try:
            user_id, csrf = ensure_vcf_backup_user_id(client, args)
        except LifecycleError:
            return stage_vcf_backup_password_via_appliance(args)
    status, reset_body, _headers = client.request(
        "POST",
        f"/users/{user_id}/password",
        form={"password": args.vcf_backup_password, "confirm_password": args.vcf_backup_password, "csrf": csrf},
        follow_redirects=False,
    )
    if status not in {200, 302, 303}:
        raise LifecycleError(f"VCF backup user password staging failed with HTTP {status}: {reset_body[:500]}")
    return {"username": "vcf-backup", "password_staged": True, "method": "ui"}


def stage_vcf_depot_password_via_appliance(args: argparse.Namespace, password: str) -> dict[str, Any]:
    password_literal = repr(password)
    python_script = f"""
from sqlalchemy import select

from labfoundry.app.database import SessionLocal
from labfoundry.app.models import User, VcfOfflineDepotSettings
from labfoundry.app.services.local_users import stage_user_os_password

password = {password_literal}
with SessionLocal() as db:
    user = db.execute(select(User).where(User.username == "vcf-depot")).scalar_one_or_none()
    if user is None:
        user = User(username="vcf-depot", role="viewer", roles_json='["viewer"]', shell="/sbin/nologin", enabled=True)
        db.add(user)
        db.flush()
    stage_user_os_password(user, password)
    user.enabled = True
    db.add(user)
    settings = db.execute(select(VcfOfflineDepotSettings)).scalar_one_or_none()
    if settings is not None:
        settings.http_user_id = user.id
        db.add(settings)
    db.commit()
    print(f"staged:user_id={{user.id}}")
"""
    encoded_script = base64.b64encode(python_script.encode("utf-8")).decode("ascii")
    script = (
        "set -a; . /etc/labfoundry/labfoundry.env; set +a; "
        f"printf %s {shell_single_quote(encoded_script)} | base64 -d | /opt/labfoundry/.venv/bin/python -"
    )
    result = ssh_command(args.appliance_ssh_host, args, script, role="appliance", redact_values=[password])
    require_success(result, "appliance VCF depot password staging")
    return {"username": "vcf-depot", "password_staged": True, "method": "appliance-python", "ssh": result}


def stage_vcf_depot_password(client: HttpClient, args: argparse.Namespace, password: str | None = None) -> dict[str, Any]:
    password = password or args.vcf_depot_password
    status, body, _headers = client.request("GET", "/users")
    if status >= 400:
        raise LifecycleError(f"GET /users failed with HTTP {status}")
    csrf = extract_csrf(body)
    try:
        user_id = extract_user_id_from_users_page(body, "vcf-depot")
    except LifecycleError:
        status, create_body, _headers = client.request(
            "POST",
            "/users",
            form={"username": "vcf-depot", "role": "viewer", "roles": "viewer", "shell": "/sbin/nologin", "csrf": csrf},
            follow_redirects=False,
        )
        if status not in {200, 302, 303, 409}:
            raise LifecycleError(f"VCF depot user creation failed with HTTP {status}: {create_body[:500]}")
        status, body, _headers = client.request("GET", "/users")
        if status >= 400:
            raise LifecycleError(f"GET /users failed with HTTP {status}")
        csrf = extract_csrf(body)
        try:
            user_id = extract_user_id_from_users_page(body, "vcf-depot")
        except LifecycleError:
            return stage_vcf_depot_password_via_appliance(args, password)
    status, reset_body, _headers = client.request(
        "POST",
        f"/users/{user_id}/password",
        form={"password": password, "confirm_password": password, "csrf": csrf},
        follow_redirects=False,
    )
    if status not in {200, 302, 303}:
        raise LifecycleError(f"VCF depot user password staging failed with HTTP {status}: {reset_body[:500]}")
    return {"username": "vcf-depot", "password_staged": True, "method": "ui"}


def configure_vcf_offline_depot(client: HttpClient, args: argparse.Namespace) -> dict[str, Any]:
    stage_vcf_depot_password(client, args)
    status, body, _headers = client.request("GET", "/vcf-offline-depot")
    if status >= 400:
        raise LifecycleError(f"GET /vcf-offline-depot failed with HTTP {status}")
    csrf = extract_csrf(body)
    user_id = extract_user_id_from_users_page(client.request("GET", "/users")[1], "vcf-depot")
    hostname = f"depot.{args.domain}"
    status, response_body, _headers = client.request(
        "POST",
        "/vcf-offline-depot/settings",
        form={
            "enabled": "on",
            "hostname": hostname,
            "listen_interface": args.site_interface,
            "port": "443",
            "http_user_id": user_id,
            "csrf": csrf,
        },
        headers={"X-LabFoundry-Autosave": "1"},
    )
    if status >= 400:
        raise LifecycleError(f"VCF Offline Depot settings update failed with HTTP {status}: {response_body[:500]}")
    payload = json.loads(response_body)
    non_certificate_errors = [
        error for error in payload.get("validation_errors", [])
        if "CA-managed HTTPS certificate" not in str(error)
    ]
    if non_certificate_errors:
        raise LifecycleError(f"VCF Offline Depot desired state is invalid: {non_certificate_errors}")
    return {
        "hostname": payload.get("endpoint") or hostname,
        "listen_address": payload.get("listen_address"),
        "http_username": payload.get("http_username"),
        "config_path": payload.get("config_path"),
    }


def configure_vcf_backups(client: HttpClient, args: argparse.Namespace) -> dict[str, Any]:
    status, body, _headers = client.request("GET", "/vcf-backups")
    if status >= 400:
        raise LifecycleError(f"GET /vcf-backups failed with HTTP {status}")
    csrf = extract_csrf(body)
    user_id = extract_vcf_backup_user_id(body)
    stage_vcf_backup_password(client, args)
    status, response_body, _headers = client.request(
        "POST",
        "/vcf-backups/settings",
        form={
            "enabled": "on",
            "listen_interface": args.site_interface,
            "port": "22",
            "sftp_user_id": user_id,
            "chroot_enabled": "on",
            "allow_password_auth": "on",
            "allow_public_key_auth": "on",
            "max_sessions": "4",
            "csrf": csrf,
        },
        headers={"X-LabFoundry-Autosave": "1"},
    )
    if status >= 400:
        raise LifecycleError(f"VCF Backup settings update failed with HTTP {status}: {response_body[:500]}")
    payload = json.loads(response_body)
    if not payload.get("valid"):
        raise LifecycleError(f"VCF Backup desired state is invalid: {payload.get('validation_errors')}")
    return {
        "listen_interface": payload.get("listen_interface"),
        "listen_address": payload.get("listen_address"),
        "sftp_username": payload.get("sftp_username"),
        "remote_directory": payload.get("remote_directory"),
        "config_path": payload.get("config_path"),
        "valid": payload.get("valid"),
    }


def configure_kms(client: HttpClient, args: argparse.Namespace) -> dict[str, Any]:
    status, body, _headers = client.request("GET", "/kms")
    if status >= 400:
        raise LifecycleError(f"GET /kms failed with HTTP {status}")
    csrf = extract_csrf(body)
    hostname = f"kms.{args.domain}"
    status, response_body, _headers = client.request(
        "POST",
        "/kms/settings",
        form={
            "enabled": "on",
            "backend": "pykmip",
            "listen_interface": args.site_interface,
            "port": "5696",
            "hostname": hostname,
            "server_certificate": hostname,
            "require_client_cert": "on",
            "allow_register": "on",
            "csrf": csrf,
        },
        headers={"X-LabFoundry-Autosave": "1"},
    )
    if status >= 400:
        raise LifecycleError(f"KMS settings update failed with HTTP {status}: {response_body[:500]}")
    payload = json.loads(response_body)
    if not payload.get("valid"):
        raise LifecycleError(f"KMS desired state is invalid: {payload.get('validation_errors')}")
    status, client_body, _headers = client.request(
        "POST",
        "/kms/clients",
        form={
            "name": "vcf-management",
            "certificate_subject": f"CN=vcf-management.{args.domain},O=LabFoundry",
            "role": "service",
            "allowed_operations": "locate,get,register,create,activate",
            "description": "Hyper-V lifecycle KMIP client",
            "enabled": "on",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    if status not in {200, 302, 303, 409}:
        raise LifecycleError(f"KMS client setup failed with HTTP {status}: {client_body[:500]}")
    return {
        "hostname": payload.get("hostname"),
        "listen_interface": payload.get("listen_interface"),
        "listen_address": payload.get("listen_address"),
        "port": payload.get("port"),
        "config_path": payload.get("config_path"),
        "client": "vcf-management",
        "valid": payload.get("valid"),
    }


def configure_ldap(client: HttpClient, args: argparse.Namespace) -> dict[str, Any]:
    organizations = client.json_request("GET", "/api/v1/ldap/organizations")
    organizations_by_slug = {organization["slug"]: organization for organization in organizations}
    desired_organizations = [
        ("lifecycle-org-a", "Lifecycle Org A"),
        ("lifecycle-org-b", "Lifecycle Org B"),
    ]
    created: list[dict[str, Any]] = []
    for slug, name in desired_organizations:
        organization = organizations_by_slug.get(slug)
        if organization is None:
            organization = client.json_request(
                "POST",
                "/api/v1/ldap/organizations",
                json_body={"name": name, "slug": slug, "enabled": True},
            )
        created.append(organization)

    password = LIFECYCLE_LDAP_PASSWORD
    users: list[dict[str, Any]] = []
    for organization in created:
        organization_users = client.json_request("GET", f"/api/v1/ldap/organizations/{organization['id']}/users")
        user = next((row for row in organization_users if row["uid"] == "operator"), None)
        if user is None:
            user = client.json_request(
                "POST",
                f"/api/v1/ldap/organizations/{organization['id']}/users",
                json_body={
                    "uid": "operator",
                    "given_name": "Lifecycle",
                    "surname": "Operator",
                    "display_name": f"{organization['name']} Operator",
                    "email": f"operator@{organization['slug']}.invalid",
                    "enabled": True,
                    "password": password,
                },
            )
        else:
            client.json_request(
                "POST",
                f"/api/v1/ldap/users/{user['id']}/password",
                json_body={"password": password},
            )
        users.append(user)

    org_a = created[0]
    org_a_groups = client.json_request("GET", f"/api/v1/ldap/organizations/{org_a['id']}/groups")
    leaf = next((row for row in org_a_groups if row["name"] == "Lifecycle Operators"), None)
    if leaf is None:
        leaf = client.json_request(
            "POST",
            f"/api/v1/ldap/organizations/{org_a['id']}/groups",
            json_body={
                "name": "Lifecycle Operators",
                "description": "Direct lifecycle LDAP membership",
                "enabled": True,
                "members": [{"type": "user", "id": users[0]["id"]}],
            },
        )
    parent = next((row for row in org_a_groups if row["name"] == "Lifecycle Nested Administrators"), None)
    if parent is None:
        client.json_request(
            "POST",
            f"/api/v1/ldap/organizations/{org_a['id']}/groups",
            json_body={
                "name": "Lifecycle Nested Administrators",
                "description": "Nested lifecycle LDAP membership",
                "enabled": True,
                "members": [{"type": "group", "id": leaf["id"]}],
            },
        )
    org_b = created[1]
    org_b_groups = client.json_request("GET", f"/api/v1/ldap/organizations/{org_b['id']}/groups")
    if not any(row["name"] == "Lifecycle Operators" for row in org_b_groups):
        client.json_request(
            "POST",
            f"/api/v1/ldap/organizations/{org_b['id']}/groups",
            json_body={
                "name": "Lifecycle Operators",
                "description": "Independent organization-local group",
                "enabled": True,
                "members": [{"type": "user", "id": users[1]["id"]}],
            },
        )

    site_ip = str(ip_interface(args.site_cidr).ip)
    settings = client.json_request(
        "PATCH",
        "/api/v1/ldap/settings",
        json_body={
            "enabled": True,
            "hostname": f"ldap.{args.domain}",
            "listen_interfaces": [args.site_interface],
            "listen_addresses": [site_ip],
            "port": 636,
            "password_policy": {
                "min_length": 14,
                "require_uppercase": True,
                "require_lowercase": True,
                "require_number": True,
                "require_special": True,
                "disallow_username": True,
                "max_failures": 5,
                "lockout_minutes": 15,
                "failure_window_minutes": 15,
                "history": 5,
                "max_age_days": 0,
            },
        },
    )
    return {
        "hostname": settings["hostname"],
        "listen_interfaces": settings["listen_interfaces"],
        "listen_addresses": settings["listen_addresses"],
        "organization_suffixes": [organization["suffix_dn"] for organization in created],
        "duplicate_uid": "operator",
        "nested_group": "Lifecycle Nested Administrators",
        "service_account_mapping": "employeeType",
    }


def apply_units(client: HttpClient, units: list[str], args: argparse.Namespace) -> dict[str, Any]:
    task: dict[str, Any] = {}
    status = 0
    job_id = ""
    attempts = 0
    for attempt in range(2):
        attempts = attempt + 1
        status, body, _headers = client.request("GET", "/appliance-apply")
        if status >= 400:
            raise LifecycleError(f"GET /appliance-apply failed with HTTP {status}")
        csrf = extract_csrf(body)
        form: list[tuple[str, Any]] = [("csrf", csrf)]
        form.extend(("selected_units", unit) for unit in units)
        if "esx_storage" in units:
            review = client.json_request("GET", "/appliance-apply/review")
            esx_unit = next((item for item in review.get("units", []) if item.get("id") == "esx_storage"), None)
            format_volumes = list((esx_unit or {}).get("format_volumes") or [])
            if format_volumes and not args.confirm_esx_storage_format:
                raise LifecycleError(
                    "ESX Storage apply requires --confirm-esx-storage-format after reviewing the complete disk fingerprint."
                )
            for volume in format_volumes:
                form.append(
                    (
                        "format_confirmations",
                        json.dumps({"volume_id": volume["id"], "confirmation": volume["confirmation"]}, separators=(",", ":")),
                    )
                )
        status, response_body, _headers = client.request(
            "POST",
            "/appliance-apply",
            form=form,
            headers={"Accept": "application/json"},
            follow_redirects=False,
            timeout=30,
        )
        if status != 202:
            raise LifecycleError(f"Appliance apply submission failed with HTTP {status}: {summarize_html_response(response_body)}")
        try:
            submission = json.loads(response_body)
        except json.JSONDecodeError as exc:
            raise LifecycleError("Appliance apply submission did not return a JSON master task.") from exc
        job_id = str(submission.get("job_id") or "")
        status_url = str(submission.get("status_url") or (f"/tasks/{job_id}/status" if job_id else ""))
        if not job_id or not status_url:
            raise LifecycleError("Appliance apply submission did not identify the master task.")

        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            task_payload = client.json_request("GET", status_url)
            task = dict(task_payload.get("task") or {})
            if str(task.get("status") or "") not in {"pending", "running"}:
                break
            time.sleep(1)
        else:
            raise LifecycleError(f"Appliance apply task {job_id} did not finish within 180 seconds.")

        if task.get("status") == "succeeded":
            break
        task_error = str(task.get("error") or "")
        if attempt == 0 and task_error.startswith("Desired state changed after task submission:"):
            time.sleep(1)
            continue
        failed_steps = [
            f"{step.get('label')}: {step.get('status')} {step.get('error') or ''}".strip()
            for step in task.get("_children", [])
            if step.get("status") in {"failed", "skipped"}
        ]
        detail = task_error or "; ".join(failed_steps) or "unknown failure"
        raise LifecycleError(f"Appliance apply task {job_id} ended {task.get('status')}: {detail}")

    if task.get("status") != "succeeded":
        raise LifecycleError(f"Appliance apply task {job_id} did not succeed after {attempts} attempts.")
    if not args.allow_dry_run and bool((task.get("result") or {}).get("dry_run")):
        raise LifecycleError("Appliance apply reported dry-run; rerun with --allow-dry-run or enable real adapters for lifecycle validation.")
    return {
        "http_status": status,
        "job_id": job_id,
        "attempts": attempts,
        "selected_units": units,
        "status": task.get("status"),
        "components": [
            {"component": step.get("component_key"), "status": step.get("status")}
            for step in task.get("_children", [])
        ],
    }


def _configure_signed_release_source(
    client: HttpClient,
    args: argparse.Namespace,
    *,
    channel: str,
) -> dict[str, Any]:
    status, body, _headers = client.request("GET", "/appliance-update")
    if status >= 400:
        raise LifecycleError(f"GET /appliance-update failed with HTTP {status}")
    section_match = re.search(
        r'<details\b[^>]*data-update-source-group="labfoundry"[^>]*>(.*?)</details>',
        body,
        flags=re.DOTALL,
    )
    if not section_match:
        raise LifecycleError("LabFoundry release source group was not found in Appliance Update.")
    section = section_match.group(1)
    source_match = re.search(
        r'<form\b[^>]*action="/appliance-update/sources/(\d+)"[^>]*>(.*?)</form>',
        section,
        flags=re.DOTALL,
    )
    if not source_match:
        raise LifecycleError("No configured LabFoundry release source was found.")
    source_id, form_body = source_match.groups()

    def field_value(name: str, default: str) -> str:
        match = re.search(rf'<input\b[^>]*name="{re.escape(name)}"[^>]*value="([^"]*)"', form_body)
        return html.unescape(match.group(1)) if match else default

    csrf = extract_csrf(form_body)
    source_name = field_value("name", "Lifecycle signed releases")
    priority = field_value("priority", "1")
    status, response_body, _headers = client.request(
        "POST",
        f"/appliance-update/sources/{source_id}",
        form={
            "csrf": csrf,
            "name": source_name,
            "url": args.signed_release_repository_url.rstrip("/"),
            "priority": priority,
            "enabled_present": "1",
            "enabled": "on",
            "channel": channel,
        },
        headers={"X-LabFoundry-Autosave": "1", "Accept": "application/json"},
        follow_redirects=False,
    )
    if status != 200:
        raise LifecycleError(
            f"Signed release source update failed with HTTP {status}: {summarize_html_response(response_body)}"
        )
    return {
        "source_id": int(source_id),
        "source_name": source_name,
        "base_url": args.signed_release_repository_url.rstrip("/"),
        "channel": channel,
    }


def _submit_signed_release_update(
    client: HttpClient,
    *,
    expected_status: str,
    timeout_seconds: int = 360,
) -> dict[str, Any]:
    before = client.json_request("GET", "/tasks/status?size=100")
    before_ids = {str(row.get("id") or "") for row in before.get("tasks", [])}
    status, body, _headers = client.request("GET", "/appliance-update")
    if status >= 400:
        raise LifecycleError(f"GET /appliance-update failed with HTTP {status}")
    csrf = extract_csrf(body)
    status, response_body, _headers = client.request(
        "POST",
        "/appliance-update/run",
        form=[("csrf", csrf), ("selected_streams", "labfoundry_release")],
        follow_redirects=False,
        timeout=30,
    )
    if status != 200:
        raise LifecycleError(
            f"Signed release submission failed with HTTP {status}: {summarize_html_response(response_body)}"
        )

    deadline = time.monotonic() + timeout_seconds
    task: dict[str, Any] = {}
    job_id = ""
    while time.monotonic() < deadline:
        if not job_id:
            rows = client.json_request("GET", "/tasks/status?size=100").get("tasks", [])
            created = [
                row
                for row in rows
                if str(row.get("id") or "") not in before_ids and row.get("type") == "appliance-update"
            ]
            if created:
                job_id = str(created[0]["id"])
        if job_id:
            task = dict(client.json_request("GET", f"/tasks/{job_id}/status").get("task") or {})
            if str(task.get("status") or "") not in {"pending", "running"}:
                break
        time.sleep(2)
    else:
        raise LifecycleError("Signed release update did not finish within the lifecycle timeout.")
    if task.get("status") != expected_status:
        detail = task.get("error") or "; ".join(str(value) for value in task.get("error_messages", []))
        raise LifecycleError(
            f"Signed release task {job_id} ended {task.get('status')}; expected {expected_status}: {detail}"
        )
    children = list(task.get("_children") or [])
    if len(children) != 1 or children[0].get("component_key") != "labfoundry_release":
        raise LifecycleError(
            f"Signed release task {job_id} did not expose exactly one LabFoundry Release child step."
        )
    if children[0].get("status") != expected_status:
        raise LifecycleError(
            f"Signed release child step for {job_id} ended {children[0].get('status')}; "
            f"expected {expected_status}."
        )
    return task


def _release_database_identity(args: argparse.Namespace) -> dict[str, Any]:
    script = """
import hashlib
import json
import os
import sqlite3

database = "/var/lib/labfoundry/labfoundry.db"
connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
try:
    schema = connection.execute(
        "select type, name, coalesce(sql, '') from sqlite_master "
        "where name not like 'sqlite_%' order by type, name"
    ).fetchall()
    users = connection.execute("select id, username from users order by id").fetchall()
finally:
    connection.close()
canonical_schema = json.dumps(schema, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
print(json.dumps({
    "current_release": os.path.realpath("/opt/labfoundry/current"),
    "compatibility_venv": os.path.realpath("/opt/labfoundry/.venv"),
    "schema_sha256": hashlib.sha256(canonical_schema).hexdigest(),
    "users": users,
}, sort_keys=True))
"""
    encoded = base64.b64encode(script.strip().encode("utf-8")).decode("ascii")
    result = ssh_command(
        args.appliance_ssh_host,
        args,
        appliance_ssh_command(args, f"printf %s {encoded} | base64 -d | python3 -"),
        role="appliance",
    )
    require_success(result, "release database identity probe")
    try:
        payload = json.loads(result["stdout"])
    except json.JSONDecodeError as exc:
        raise LifecycleError("Release database identity probe did not return JSON.") from exc
    payload["ssh_command"] = result["command"]
    return payload


def signed_release_update_check(client: HttpClient, args: argparse.Namespace) -> dict[str, Any]:
    parsed_url = urllib.parse.urlparse(args.signed_release_repository_url)
    if parsed_url.scheme != "https" or not parsed_url.netloc:
        raise LifecycleError("--signed-release-repository-url must be an absolute HTTPS base URL.")

    before = _release_database_identity(args)
    preview_source = _configure_signed_release_source(client, args, channel="preview")
    successful_task = _submit_signed_release_update(client, expected_status="succeeded")
    time.sleep(8)
    after_success = _release_database_identity(args)
    if after_success["current_release"] == before["current_release"]:
        raise LifecycleError("The preview lifecycle release did not switch /opt/labfoundry/current.")

    broken_source = _configure_signed_release_source(client, args, channel="development")
    broken_baseline = _release_database_identity(args)
    failed_task = _submit_signed_release_update(client, expected_status="failed")
    time.sleep(4)
    after_rollback = _release_database_identity(args)
    for key in ("current_release", "compatibility_venv", "schema_sha256", "users"):
        if after_rollback[key] != broken_baseline[key]:
            raise LifecycleError(f"Broken release rollback did not restore database/release identity field {key}.")
    transaction = (failed_task.get("result") or {}).get("release_transaction") or {}
    if transaction.get("rolled_back") is not True or transaction.get("rollback_health") is not True:
        raise LifecycleError("Broken release task did not record a healthy automatic rollback.")
    health = appliance_health(client, args)
    return {
        "preview_source": preview_source,
        "successful_task_id": successful_task.get("id"),
        "installed_release": after_success["current_release"],
        "broken_source": broken_source,
        "failed_task_id": failed_task.get("id"),
        "verified_key_id": transaction.get("verified_key_id"),
        "bundle_sha256": transaction.get("bundle_sha256"),
        "rolled_back": transaction.get("rolled_back"),
        "database_identity_restored": True,
        "service_health": health,
    }


def appliance_health(client: HttpClient, args: argparse.Namespace) -> dict[str, Any]:
    openapi = client.request("GET", "/openapi.json")
    if openapi[0] >= 400:
        raise LifecycleError(f"/openapi.json failed with HTTP {openapi[0]}")
    api_login(client, args)
    dashboard = client.json_request("GET", "/api/v1/dashboard")
    ui_login(client, args)
    ssh = ssh_command(
        args.appliance_ssh_host,
        args,
        "systemctl is-active labfoundry && "
        "systemctl is-active labfoundry-worker && "
        "systemctl is-enabled labfoundry-worker && "
        "curl -fsS http://127.0.0.1:8000/openapi.json >/dev/null",
        role="appliance",
    )
    require_success(ssh, "appliance health SSH probe")
    return {"openapi_status": openapi[0], "dashboard_keys": sorted(dashboard.keys()), "ssh": ssh}


def direct_dns_a_query_command(name: str, server: str, expected_ip: str) -> str:
    script = f"""
import random
import socket
import struct
import sys

name = {name!r}
server = {server!r}
expected_ip = {expected_ip!r}
query_id = random.randrange(0, 65536)
qname = b"".join(bytes([len(part)]) + part.encode("ascii") for part in name.rstrip(".").split(".")) + b"\\0"
packet = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(5)
sock.sendto(packet, (server, 53))
data, _ = sock.recvfrom(512)
if len(data) < 12:
    sys.exit("short DNS response")
response_id, flags, _qdcount, ancount, _nscount, _arcount = struct.unpack("!HHHHHH", data[:12])
if response_id != query_id:
    sys.exit("DNS response ID mismatch")
rcode = flags & 0x000F
if rcode != 0:
    sys.exit(f"DNS query failed with rcode {{rcode}}")
offset = 12
while offset < len(data) and data[offset] != 0:
    offset += data[offset] + 1
offset += 5
answers = []
for _ in range(ancount):
    if offset >= len(data):
        break
    if data[offset] & 0xC0 == 0xC0:
        offset += 2
    else:
        while offset < len(data) and data[offset] != 0:
            offset += data[offset] + 1
        offset += 1
    if offset + 10 > len(data):
        break
    rtype, rclass, _ttl, rdlen = struct.unpack("!HHIH", data[offset:offset + 10])
    offset += 10
    rdata = data[offset:offset + rdlen]
    offset += rdlen
    if rtype == 1 and rclass == 1 and rdlen == 4:
        answers.append(socket.inet_ntoa(rdata))
print("\\n".join(answers))
if expected_ip not in answers:
    sys.exit(f"expected {{expected_ip}} from {{server}} for {{name}}, got {{answers}}")
"""
    encoded = base64.b64encode(script.strip().encode("utf-8")).decode("ascii")
    return f"printf %s {encoded} | base64 -d | python3 -"


def authoritative_dns_probe_command(domain: str, server: str, expected_ip: str) -> str:
    script = f'''
import random
import socket
import struct

server = {server!r}

def skip_name(data, offset):
    while True:
        length = data[offset]
        if length & 0xC0 == 0xC0:
            return offset + 2
        offset += 1
        if length == 0:
            return offset
        offset += length

def query(name, qtype, target=server):
    query_id = random.randrange(0, 65536)
    qname = b"".join(bytes([len(part)]) + part.encode("ascii") for part in name.rstrip(".").split(".")) + b"\\0"
    packet = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", qtype, 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    sock.sendto(packet, (target, 53))
    data, _ = sock.recvfrom(4096)
    response_id, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    assert response_id == query_id
    offset = 12
    for _ in range(qd):
        offset = skip_name(data, offset) + 4
    types = []
    for count in (an, ns, ar):
        section = []
        for _ in range(count):
            offset = skip_name(data, offset)
            rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", data[offset:offset + 10])
            offset += 10 + rdlen
            section.append(rtype)
        types.append(section)
    return flags, types

domain = {domain!r}
expected = [
    (domain, 6, 0, 6, True),
    (domain, 2, 0, 2, True),
    ("ns1." + domain, 1, 0, 1, True),
    ("interop-appliance." + domain, 1, 0, 1, True),
]
for name, qtype, expected_rcode, expected_type, authoritative in expected:
    flags, sections = query(name, qtype)
    assert flags & 0x000F == expected_rcode, (name, flags, sections)
    assert expected_type in sections[0], (name, flags, sections)
    if authoritative:
        assert flags & 0x0400, (name, flags, sections)

flags, sections = query("missing-authoritative." + domain, 1)
assert flags & 0x000F == 3, (flags, sections)
assert flags & 0x0400, (flags, sections)
assert 6 in sections[1], (flags, sections)

print("authoritative DNS lifecycle probes passed")
'''
    encoded = base64.b64encode(script.strip().encode("utf-8")).decode("ascii")
    return f"printf %s {encoded} | base64 -d | python3 -"


def recursive_dns_probe_command(server: str, expected_ip: str) -> str:
    reverse_name = ip_address(expected_ip).reverse_pointer
    script = f'''
import random
import socket
import struct

server = {server!r}

def skip_name(data, offset):
    while True:
        length = data[offset]
        if length & 0xC0 == 0xC0:
            return offset + 2
        offset += 1
        if length == 0:
            return offset
        offset += length

def query(name, qtype):
    query_id = random.randrange(0, 65536)
    qname = b"".join(bytes([len(part)]) + part.encode("ascii") for part in name.rstrip(".").split(".")) + b"\\0"
    packet = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", qtype, 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    sock.sendto(packet, (server, 53))
    data, _ = sock.recvfrom(4096)
    response_id, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    assert response_id == query_id
    offset = 12
    for _ in range(qd):
        offset = skip_name(data, offset) + 4
    types = []
    for count in (an, ns, ar):
        section = []
        for _ in range(count):
            offset = skip_name(data, offset)
            rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", data[offset:offset + 10])
            offset += 10 + rdlen
            section.append(rtype)
        types.append(section)
    return flags, types

flags, sections = query({reverse_name!r}, 12)
assert flags & 0x000F == 0, (flags, sections)
assert 12 in sections[0], (flags, sections)

flags, sections = query("example.com", 1)
assert flags & 0x000F == 0, (flags, sections)
assert sections[0], (flags, sections)
print("recursive DNS and PTR lifecycle probes passed")
'''
    encoded = base64.b64encode(script.strip().encode("utf-8")).decode("ascii")
    return f"printf %s {encoded} | base64 -d | python3 -"


def run_host_checks(
    args: argparse.Namespace,
    checks: dict[str, str],
    *,
    appliance_as_root: bool = True,
) -> dict[str, Any]:
    evidence: dict[str, Any] = {}
    for name, command in checks.items():
        result = ssh_command(
            args.appliance_ssh_host,
            args,
            command,
            role="appliance",
            appliance_as_root=appliance_as_root,
        )
        require_success(result, f"host {name} check")
        evidence[name] = result
    return evidence


def managed_ldap_helper_authentication_check(args: argparse.Namespace) -> dict[str, Any]:
    user_dn = "uid=operator,ou=users,dc=lifecycle-org-a,dc=ldap,dc=labfoundry,dc=internal"
    helper_command = (
        "IFS= read -r ldap_password; "
        "printf '%s\\n' \"$ldap_password\" | "
        f"/opt/labfoundry/bin/labfoundry-helper ldap authenticate --real {shell_single_quote(user_dn)}"
    )
    user = ssh_username(args, "appliance")
    host = args.appliance_ssh_host
    hostkey = ssh_hostkey(host, args, "appliance")
    secrets = [args.ssh_password, LIFECYCLE_LDAP_PASSWORD]
    if user == "root":
        remote_command = f"sh -lc {shell_single_quote(helper_command)}"
        input_text = f"{LIFECYCLE_LDAP_PASSWORD}\n"
    elif args.ssh_password:
        remote_command = f"sudo -S -p '' sh -lc {shell_single_quote(helper_command)}"
        input_text = f"{args.ssh_password}\n{LIFECYCLE_LDAP_PASSWORD}\n"
    else:
        remote_command = f"sudo -n sh -lc {shell_single_quote(helper_command)}"
        input_text = f"{LIFECYCLE_LDAP_PASSWORD}\n"

    if args.ssh_password:
        command = ["plink", "-batch", "-ssh", "-pw", args.ssh_password, f"{user}@{host}", remote_command]
        if hostkey:
            command[3:3] = ["-hostkey", hostkey]
        redacted_command = redact_sequence(command, secrets)
    else:
        command = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=15"]
        if args.ssh_key:
            command.extend(["-i", args.ssh_key])
        command.extend([f"{user}@{host}", remote_command])
        redacted_command = redact_sequence(command, secrets)
    try:
        completed = subprocess.run(
            command,
            input=input_text,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=120,
        )
        result = {
            "command": redacted_command,
            "returncode": completed.returncode,
            "stdout": redact_text(completed.stdout, secrets),
            "stderr": redact_text(completed.stderr, secrets),
            "password_transport": "stdin-only",
            "bind_transport": "ldapi:///",
        }
    except subprocess.TimeoutExpired:
        result = {
            "command": redacted_command,
            "returncode": 124,
            "stdout": "",
            "stderr": "Managed LDAP helper authentication timed out after 120 seconds.",
            "password_transport": "stdin-only",
            "bind_transport": "ldapi:///",
        }
    require_success(result, "managed LDAP helper authentication")
    return result


def configure_esx_storage(client: HttpClient, args: argparse.Namespace) -> dict[str, Any]:
    """Configure one volume and equivalent dual-stack NFS 3 and 4.1 datastores."""
    if not args.esx_storage_test:
        return {"skipped": "--esx-storage-test was not selected"}
    volumes = client.json_request("GET", "/api/v1/esx-storage/volumes")
    volume = next((item for item in volumes if item.get("name") == "lifecycle-esx-data"), None)
    selected_disk: dict[str, Any] = {}
    if volume is None:
        disks = client.json_request("GET", "/api/v1/esx-storage/disks")
        candidates = [item for item in disks if item.get("eligible") and item.get("candidate_type") == "blank_disk"]
        if args.esx_storage_device_id:
            candidates = [item for item in candidates if item.get("stable_device_id") == args.esx_storage_device_id]
        if len(candidates) != 1:
            raise LifecycleError(
                "ESX Storage lifecycle requires exactly one eligible blank disk after --esx-storage-device-id filtering; "
                f"found {len(candidates)}."
            )
        selected_disk = candidates[0]
        volume = client.json_request(
            "POST",
            "/api/v1/esx-storage/volumes",
            json_body={
                "name": "lifecycle-esx-data",
                "source_type": "blank_disk",
                "stable_device_id": selected_disk["stable_device_id"],
                "mount_path": "",
            },
        )
    shares = client.json_request("GET", "/api/v1/esx-storage/shares")
    desired_shares = [
        ("lifecycle-nfs3", "nfs3", "3"),
        ("lifecycle-nfs41", "nfs41", "4.1"),
    ]
    configured_shares: list[dict[str, Any]] = []
    for datastore_name, relative_path, version in desired_shares:
        payload = {
            "datastore_name": datastore_name,
            "volume_id": volume["id"],
            "relative_path": relative_path,
            "preferred_nfs_version": version,
            "interface_name": args.site_interface,
            "address_families": ["ipv4", "ipv6"],
            "ipv4_clients": [args.esx_storage_ipv4_client],
            "ipv6_clients": [args.esx_storage_ipv6_client],
            "enabled": True,
        }
        existing = next((item for item in shares if item.get("datastore_name") == datastore_name), None)
        if existing:
            configured = client.json_request("PATCH", f"/api/v1/esx-storage/shares/{existing['id']}", json_body=payload)
        else:
            configured = client.json_request("POST", "/api/v1/esx-storage/shares", json_body=payload)
        configured_shares.append(configured)
    status = client.json_request(
        "PATCH",
        "/api/v1/esx-storage/status",
        json_body={"enabled": True, "hostname": f"nfs.{args.domain}"},
    )
    return {
        "status": status,
        "volume": volume,
        "selected_disk": selected_disk,
        "shares": configured_shares,
        "ipv4_client": args.esx_storage_ipv4_client,
        "ipv6_client": args.esx_storage_ipv6_client,
    }


def routing_host_check_commands(args: argparse.Namespace) -> dict[str, str]:
    wan_network = str(ip_interface(args.wan_cidr).network)
    return {
        "network": "ip -br addr && ip route",
        "routing_tables": (
            'ip rule show | grep -E "lookup (100|labfoundry_mgmt)" && '
            'ip rule show | grep -E "lookup (200|labfoundry_lab)" && '
            f'ip route show table 200 | grep -F "{wan_network}" && '
            '! ip route show table 200 | grep -q "^default" && '
            'sysctl -n net.ipv4.ip_forward | grep "^1$"'
        ),
        "firewall": (
            "nft list ruleset | tee /tmp/labfoundry-lifecycle-nft.txt | head -n 200 && "
            'grep -F "comment \\"isolate-" /tmp/labfoundry-lifecycle-nft.txt && '
            'grep -F "comment \\"route-" /tmp/labfoundry-lifecycle-nft.txt && '
            'grep -F "masquerade" /tmp/labfoundry-lifecycle-nft.txt'
        ),
        "wan": (
            f"sysctl net.ipv4.ip_forward; "
            f"tc qdisc show dev {args.wan_interface}; "
            f"tc qdisc show dev {args.wan_interface} | grep netem | grep delay | grep 25ms"
        ),
    }


def routing_host_state_checks(args: argparse.Namespace) -> dict[str, Any]:
    return run_host_checks(args, routing_host_check_commands(args))


def host_state_checks(args: argparse.Namespace) -> dict[str, Any]:
    site_ip = str(ip_interface(args.site_cidr).ip)
    httpx_probe = base64.b64encode(b"import httpx; print(httpx.__version__)").decode("ascii")
    vcf_sdk_probe = base64.b64encode(
        b'from importlib.metadata import version; assert version("vcf-sdk") == "9.1.0.0"'
    ).decode("ascii")
    powercli_probe = base64.b64encode(
        (
            '$m = Get-Module VCF.PowerCLI -ListAvailable | Where-Object Version -eq "9.1.0.25380678" | '
            'Select-Object -First 1; if (-not $m) { exit 1 }; Import-Module $m.Path -Force; '
            '$configured = Get-PowerCLIConfiguration -Scope AllUsers; if ([bool]$configured.ParticipateInCEIP) { exit 1 }; '
            'if (-not (Get-Command Connect-VIServer -ErrorAction SilentlyContinue)) { exit 1 }'
        ).encode("utf-16le")
    ).decode("ascii")
    checks = {
        **routing_host_check_commands(args),
        "local_console": (
            "systemctl is-active labfoundry-console.service && "
            "systemctl is-enabled labfoundry-console.service && "
            "test \"$(systemctl is-enabled getty@tty1.service 2>/dev/null)\" = masked && "
            "test \"$(systemctl show getty@tty2.service -p LoadState --value)\" = loaded && "
            "test \"$(systemctl show getty@tty2.service -p UnitFileState --value)\" != masked && "
            "test -x /opt/labfoundry/.venv/bin/labfoundry-console && "
            "/opt/labfoundry/bin/labfoundry-helper console status --real | "
            "grep -F '\"maintenance_isolation\": false'"
        ),
        "vcf_trust_dependencies": (
            f"printf %s {httpx_probe} | base64 -d | /opt/labfoundry/.venv/bin/python -"
        ),
        "vcf_automation_tooling": (
            f"printf %s {vcf_sdk_probe} | base64 -d | /opt/labfoundry/.venv/bin/python -"
        ),
        "ca": "test -f /etc/labfoundry/ca/ca-bundle.pem && openssl x509 -in /etc/labfoundry/ca/root-ca.pem -noout -subject",
        "ntpsec": (
            "rpm -q ntpsec && systemctl is-active ntpd.service && "
            "ntpq -pn && ntpq -c rv && ntpq -c ntsinfo && "
            f"test \"$(stat -c '%U:%G %a' /etc/labfoundry/ntp/certs/ntp.{args.domain}.key)\" = 'root:ntp 640' && "
            "nft list ruleset | grep -F 'ntpd-' && nft list ruleset | grep -F 'ntpd-nts-'"
        ),
        "kms_files": (
            "for path in "
            "/etc/labfoundry/kms/pykmip.conf "
            "/etc/pykmip/server.conf "
            "/etc/labfoundry/kms/certs/kms.labfoundry.internal.crt "
            "/etc/labfoundry/kms/certs/kms.labfoundry.internal.key "
            "/etc/labfoundry/kms/clients/certs/vcf-management.crt "
            "/etc/labfoundry/kms/clients/certs/vcf-management.key; "
            "do test -f \"$path\" || { echo \"missing $path\"; exit 1; }; done"
        ),
        "kms_service": "systemctl is-active labfoundry-kms.service || (systemctl status labfoundry-kms.service --no-pager; journalctl -u labfoundry-kms.service -n 80 --no-pager; exit 1)",
        "kms_tls": (
            f"timeout 10 openssl s_client -connect {site_ip}:5696 "
            "-cert /etc/labfoundry/kms/clients/certs/vcf-management.crt "
            "-key /etc/labfoundry/kms/clients/certs/vcf-management.key "
            "-CAfile /etc/labfoundry/ca/root.crt -verify_return_error </dev/null"
        ),
        "ldap_files": (
            "for path in "
            "/etc/labfoundry/ldap/tls/server.crt "
            "/etc/labfoundry/ldap/tls/server.key "
            "/etc/systemd/system/slapd.service.d/labfoundry.conf; "
            "do test -f \"$path\" || { echo \"missing $path\"; exit 1; }; done"
        ),
        "ldap_service": "systemctl is-active slapd.service || (systemctl status slapd.service --no-pager; journalctl -u slapd.service -n 100 --no-pager; exit 1)",
        "ldap_listeners": (
            "ss -lnt | grep -E '[:.]636[[:space:]]' && "
            "! ss -lnt | grep -E '[:.]389[[:space:]]'"
        ),
        "ldap_tls": (
            f"timeout 10 openssl s_client -connect {site_ip}:636 "
            f"-servername ldap.{args.domain} -verify_hostname ldap.{args.domain} "
            "-CAfile /etc/labfoundry/ca/root.crt -verify_return_error </dev/null"
        ),
        "ldap_suffixes_and_nested_groups": (
            "ldapsearch -LLL -Y EXTERNAL -H ldapi:/// "
            "-b dc=lifecycle-org-a,dc=ldap,dc=labfoundry,dc=internal '(uid=operator)' dn && "
            "ldapsearch -LLL -Y EXTERNAL -H ldapi:/// "
            "-b dc=lifecycle-org-b,dc=ldap,dc=labfoundry,dc=internal '(uid=operator)' dn && "
            "ldapsearch -LLL -Y EXTERNAL -H ldapi:/// "
            "-b ou=groups,dc=lifecycle-org-a,dc=ldap,dc=labfoundry,dc=internal "
            "'(cn=Lifecycle Nested Administrators)' member"
        ),
        "vcf_backups": (
            "test -f /etc/ssh/sshd_config.d/labfoundry-vcf-backups.conf && "
            "grep -F Match\\ User\\ vcf-backup /etc/ssh/sshd_config.d/labfoundry-vcf-backups.conf && "
            "grep -F ForceCommand\\ internal-sftp /etc/ssh/sshd_config.d/labfoundry-vcf-backups.conf && "
            "id vcf-backup && "
            "test -d /mnt/labfoundry-vcf-backups/backups && "
            "systemctl is-active sshd"
        ),
    }
    checks["dnsmasq"] = "test -f /etc/labfoundry/dnsmasq.d/labfoundry.conf && systemctl is-active dnsmasq"
    if args.esx_storage_test:
        site_ipv6 = str(ip_interface(args.site_ipv6_cidr).ip)
        ipv4_target = f"nfs-{site_ip.replace('.', '-')}.{args.domain}"
        ipv6_token = "-".join(format(int(group, 16), "x") for group in ip_interface(args.site_ipv6_cidr).ip.exploded.split(":"))
        ipv6_target = f"nfs-{ipv6_token}.{args.domain}"
        checks["esx_storage"] = (
            "systemctl is-active rpcbind.service && systemctl is-active nfs-server.service && "
            "/opt/labfoundry/bin/labfoundry-helper esx-storage status --real && "
            "exportfs -v && grep -F lifecycle-nfs3 /etc/exports.d/labfoundry-esx-storage.exports && "
            "grep -F lifecycle-nfs41 /etc/exports.d/labfoundry-esx-storage.exports && "
            "ss -lnt | grep -E ':(111|2049|20048)[[:space:]]' && "
            "nft list ruleset | grep -F esx-nfs- && "
            f"dig +short A {ipv4_target} @127.0.0.1 | grep -Fx {site_ip} && "
            f"dig +short AAAA {ipv6_target} @127.0.0.1 | grep -Fx {site_ipv6}"
        )
    evidence = run_host_checks(args, checks)
    evidence.update(
        run_host_checks(
            args,
            {
                "vcf_powercli_user": (
                    f"pwsh -NoLogo -NoProfile -NonInteractive -EncodedCommand {powercli_probe}"
                )
            },
            appliance_as_root=False,
        )
    )
    return evidence


def authoritative_dns_state_check(args: argparse.Namespace) -> dict[str, Any]:
    site_ip = str(ip_interface(args.site_cidr).ip)
    if args.skip_client_checks or not args.client_a_host:
        return {"skipped": "client A host not provided"}
    authoritative = ssh_command(
        args.client_a_host,
        args,
        authoritative_dns_probe_command(args.domain, site_ip, site_ip),
        role="client",
    )
    require_success(authoritative, "client A authoritative DNS probe")
    return {"authoritative": authoritative}


def recursive_dns_state_check(args: argparse.Namespace) -> dict[str, Any]:
    site_ip = str(ip_interface(args.site_cidr).ip)
    recursive = ssh_command(
        args.appliance_ssh_host,
        args,
        recursive_dns_probe_command("127.0.0.1", site_ip),
        role="appliance",
    )
    require_success(recursive, "appliance recursive DNS and PTR probe")
    return {"recursive_and_ptr": recursive}


def vcf_backup_client_check(args: argparse.Namespace) -> dict[str, Any]:
    if args.skip_client_checks:
        return {"skipped": "client checks disabled"}
    if not args.client_a_host:
        return {"skipped": "client A host not provided"}
    site = ip_interface(args.site_cidr)
    site_ip = str(site.ip)
    wan = ip_interface(args.wan_cidr)
    password = args.vcf_backup_password
    command = (
        f"ip route replace {wan.network} via {site_ip} dev eth1 2>/dev/null || true; "
        f"nc -z -w 5 {site_ip} 22; "
        "if command -v sshpass >/dev/null 2>&1; then "
        f"printf 'pwd\\nls\\nquit\\n' | sshpass -p '{password}' "
        f"sftp -oBatchMode=no -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null -P 22 vcf-backup@{site_ip}; "
        "else "
        "PASS_FILE=$(mktemp); ASKPASS=$(mktemp); "
        f"printf '%s\\n' '{password}' > \"$PASS_FILE\"; "
        "printf '#!/bin/sh\\ncat \"$PASS_FILE\"\\n' > \"$ASKPASS\"; chmod 700 \"$ASKPASS\"; "
        "export PASS_FILE ASKPASS SSH_ASKPASS=\"$ASKPASS\" SSH_ASKPASS_REQUIRE=force DISPLAY=none; "
        f"printf 'pwd\\nls\\nquit\\n' | setsid -w sftp -oBatchMode=no -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null -P 22 vcf-backup@{site_ip}; "
        "rc=$?; rm -f \"$PASS_FILE\" \"$ASKPASS\"; exit $rc; "
        "fi"
    )
    result = ssh_command(args.client_a_host, args, command, role="client", redact_values=[password])
    require_success(result, "client A VCF Backup SFTP probe")
    return {"client_a_sftp": result, "target": f"vcf-backup@{site_ip}:22"}


def vcf_depot_auth_check(client: HttpClient, args: argparse.Namespace, password: str | None = None) -> dict[str, Any]:
    password = password or args.vcf_depot_password
    site_ip = str(ip_interface(args.site_cidr).ip)
    depot_url = f"https://{site_ip}"
    artifact_command = (
        "install -d -m 0755 /mnt/labfoundry-vcf-offline-depot/PROD && "
        "printf lifecycle-auth-ok >/mnt/labfoundry-vcf-offline-depot/PROD/lifecycle-auth.txt && "
        "chmod 0755 /mnt/labfoundry-vcf-offline-depot /mnt/labfoundry-vcf-offline-depot/PROD && "
        "chmod 0644 /mnt/labfoundry-vcf-offline-depot/PROD/lifecycle-auth.txt"
    )
    artifact_result = ssh_command(args.appliance_ssh_host, args, artifact_command, role="appliance")
    require_success(artifact_result, "VCF depot lifecycle artifact creation")
    if args.skip_client_checks or not args.client_a_host:
        depot_client = HttpClient(depot_url)
        status, login_body, _headers = depot_client.request("GET", "/PROD/login?next=/PROD/")
        if status != 200:
            raise LifecycleError(f"VCF depot login page failed with HTTP {status}")
        csrf = extract_csrf(login_body)
        status, _body, _headers = depot_client.request(
            "POST",
            "/PROD/login",
            form={"username": "vcf-depot", "password": password, "csrf": csrf, "next": "/PROD/"},
            follow_redirects=False,
        )
        browser_status, browser_body, _headers = depot_client.request("GET", "/PROD/")
        if status != 303 or browser_status != 200 or "VCF Offline Depot" not in browser_body:
            raise LifecycleError(f"VCF depot browser session failed with login={status}, page={browser_status}")
        basic_value = base64.b64encode(f"vcf-depot:{password}".encode("utf-8")).decode("ascii")
        basic_headers = {"Authorization": f"Basic {basic_value}", "Accept": "*/*"}
        invalid_value = base64.b64encode(b"vcf-depot:not-the-password").decode("ascii")
        invalid_status = HttpClient(depot_url).request(
            "GET", "/PROD/", headers={"Authorization": f"Basic {invalid_value}", "Accept": "*/*"}, follow_redirects=False
        )[0]
        basic_status = HttpClient(depot_url).request("GET", "/PROD/", headers=basic_headers, follow_redirects=False)[0]
        if invalid_status != 401 or basic_status != 200:
            raise LifecycleError(f"VCF depot Basic auth returned invalid={invalid_status}, valid={basic_status}")
        return {"browser_status": browser_status, "basic_status": basic_status, "invalid_status": invalid_status, "artifact": artifact_result}
    quoted_password = shell_single_quote(password)
    quoted_password_form = shell_single_quote(f"password={password}")
    valid_basic = base64.b64encode(f"vcf-depot:{password}".encode("utf-8")).decode("ascii")
    invalid_basic = base64.b64encode(b"vcf-depot:not-the-password").decode("ascii")
    command = (
        f"login=$(curl -kisS '{depot_url}/PROD/login?next=/PROD/'); "
        "csrf=$(printf '%s\\n' \"$login\" | grep -o 'name=\"csrf\" value=\"[^\"]*\"' | head -n1 | cut -d'\"' -f4); "
        "cookie=$(printf '%s\\n' \"$login\" | sed -n 's/^[Ss]et-[Cc]ookie: \\([^;]*\\).*/\\1/p' | tail -n1); "
        "test -n \"$csrf\"; test -n \"$cookie\"; "
        f"post=$(curl -kisS -H \"Cookie: $cookie\" "
        f"--data-urlencode username=vcf-depot --data-urlencode {quoted_password_form} --data-urlencode csrf=\"$csrf\" "
        f"--data-urlencode next=/PROD/ {depot_url}/PROD/login); "
        "printf '%s\\n' \"$post\" | head -n1 | grep -E ' 303 '; "
        "session_cookie=$(printf '%s\\n' \"$post\" | sed -n 's/^[Ss]et-[Cc]ookie: \\([^;]*\\).*/\\1/p' | tail -n1); "
        "test -n \"$session_cookie\"; "
        f"curl -kfsS -H \"Cookie: $session_cookie\" {depot_url}/PROD/ | grep -F 'VCF Offline Depot'; "
        f"test \"$(curl -ksS -o /dev/null -w '%{{http_code}}' -H 'Authorization: Basic {invalid_basic}' {depot_url}/PROD/lifecycle-auth.txt)\" = 401; "
        f"curl -kfsS -H 'Authorization: Basic {valid_basic}' {depot_url}/PROD/lifecycle-auth.txt | grep -F lifecycle-auth-ok; "
        f"wget -qO- --no-check-certificate --header 'Authorization: Basic {valid_basic}' {depot_url}/PROD/lifecycle-auth.txt | grep -F lifecycle-auth-ok"
    )
    client_result = ssh_command(args.client_a_host, args, command, role="client", redact_values=[password])
    require_success(client_result, "client A VCF depot curl and wget probes")
    return {
        "browser_status": 200,
        "basic_status": 200,
        "invalid_status": 401,
        "artifact": artifact_result,
        "client_a": client_result,
        "target": f"{depot_url}/PROD/lifecycle-auth.txt",
    }


def rotate_vcf_depot_password_without_depot_apply(client: HttpClient, args: argparse.Namespace) -> dict[str, Any]:
    stage = stage_vcf_depot_password(client, args, args.vcf_depot_new_password)
    apply = apply_units(client, ["local_users"], args)
    site_ip = str(ip_interface(args.site_cidr).ip)
    old_basic = base64.b64encode(f"vcf-depot:{args.vcf_depot_password}".encode("utf-8")).decode("ascii")
    old_probe = ssh_command(
        args.client_a_host,
        args,
        f"test \"$(curl -ksS -o /dev/null -w '%{{http_code}}' -H 'Authorization: Basic {old_basic}' https://{site_ip}/PROD/)\" = 401",
        role="client",
        redact_values=[args.vcf_depot_password],
    )
    require_success(old_probe, "old VCF depot password rejection")
    verification = vcf_depot_auth_check(client, args, args.vcf_depot_new_password)
    return {"stage": stage, "apply": apply, "old_password_status": 401, "old_password_probe": old_probe, "new_password": verification}


def shell_single_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def verify_certificate_signed_by_root(certificate_pem: str, root_ca_pem: str, common_name: str) -> dict[str, Any]:
    if x509 is None:
        raise LifecycleError("cryptography is required to verify the issued lifecycle client certificate.")
    certificate = x509.load_pem_x509_certificate(certificate_pem.encode("utf-8"))
    root = x509.load_pem_x509_certificate(root_ca_pem.encode("utf-8"))
    if certificate.issuer != root.subject:
        raise LifecycleError("Issued client certificate issuer does not match the LabFoundry root CA.")
    root.public_key().verify(
        certificate.signature,
        certificate.tbs_certificate_bytes,
        padding.PKCS1v15(),
        certificate.signature_hash_algorithm,
    )
    subject_names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    subject_cn = subject_names[0].value if subject_names else ""
    if subject_cn != common_name:
        raise LifecycleError(f"Issued client certificate CN {subject_cn!r} does not match {common_name!r}.")
    return {
        "subject": certificate.subject.rfc4514_string(),
        "issuer": certificate.issuer.rfc4514_string(),
        "serial_number": format(certificate.serial_number, "x"),
        "not_after": certificate.not_valid_after_utc.isoformat(),
    }


def ca_client_certificate_check(client: HttpClient, args: argparse.Namespace) -> dict[str, Any]:
    if args.skip_client_checks:
        return {"skipped": "client checks disabled"}
    if not args.client_a_host:
        return {"skipped": "client A host not provided"}
    ca_client = authenticated_ui_client(client, args)
    common_name = f"client-a.{args.domain}"
    status, body, _headers = ca_client.request("GET", "/certificate-authority")
    if status >= 400:
        raise LifecycleError(f"GET /certificate-authority failed with HTTP {status}")
    certificate_id = extract_ca_certificate_id(body, common_name)
    status, certificate_pem, _headers = ca_client.request("GET", f"/certificate-authority/certificates/{certificate_id}/downloads/certificate.pem")
    if status >= 400 or "BEGIN CERTIFICATE" not in certificate_pem:
        raise LifecycleError(f"CA issued certificate download failed with HTTP {status}")
    status, root_ca_pem, _headers = ca_client.request("GET", "/certificate-authority/downloads/root-ca.pem")
    if status >= 400 or "BEGIN CERTIFICATE" not in root_ca_pem:
        raise LifecycleError(f"CA root certificate download failed with HTTP {status}")
    crypto_summary = verify_certificate_signed_by_root(certificate_pem, root_ca_pem, common_name)
    cookie_header = session_cookie_header(ca_client)
    ca_request = ip_interface(args.client_ca_request_cidr)
    ca_request_url = (args.client_ca_request_url or ca_client.base_url).rstrip("/")
    ca_request_host = urllib.parse.urlparse(ca_request_url).hostname or ""
    ca_probe_setup = client_ca_probe_setup(args.client_ca_request_interface, args.client_ca_request_cidr, ca_request_host)
    elevate = elevation_probe()
    command = (
        f"ELEV=\"$({elevate})\"; "
        "test -n \"$ELEV\"; "
        f"{ca_probe_setup}"
        "http_code=$(curl -k -sS --connect-timeout 10 --max-time 30 -o /dev/null -w '%{http_code}' "
        f"-H {shell_single_quote('Cookie: ' + cookie_header)} "
        f"{ca_request_url}/certificate-authority/certificates/{certificate_id}/downloads/certificate.pem); "
        "echo \"$http_code\"; test \"$http_code\" = \"200\""
    )
    download_result = ssh_command(args.client_a_host, args, command, role="client", redact_values=[cookie_header])
    require_success(download_result, "client A CA certificate download")
    return {
        "common_name": common_name,
        "certificate_id": certificate_id,
        "certificate": {**certificate_summary(certificate_pem), "signature_verification": crypto_summary},
        "client_a_download": download_result,
    }


def elevation_probe() -> str:
    return "if command -v sudo >/dev/null 2>&1; then echo 'sudo -n'; elif command -v doas >/dev/null 2>&1; then echo 'doas -n'; else echo ''; fi"


def second_host_address(cidr: str) -> str:
    return host_address(cidr, 2)


def host_address(cidr: str, host_offset: int) -> str:
    network = ip_interface(cidr).network
    if host_offset <= 0 or host_offset >= network.num_addresses - 1:
        raise LifecycleError(f"Network {network} is too small for host offset {host_offset}.")
    return str(ip_address(int(network.network_address) + host_offset))


def pxe_client_ip(args: argparse.Namespace) -> str:
    if args.pxe_client_ip:
        return args.pxe_client_ip
    network = ip_interface(args.site_cidr).network
    offset = 210 if network.num_addresses > 212 else max(2, network.num_addresses - 3)
    return host_address(args.site_cidr, offset)


def client_b_wan_setup_command(args: argparse.Namespace, *, include_site_route: bool = True, include_vlan_route: bool = False) -> str:
    site = ip_interface(args.site_cidr)
    vlan = ip_interface(args.vlan_cidr)
    wan = ip_interface(args.wan_cidr)
    wan_ip = str(wan.ip)
    wan_peer_ip = second_host_address(args.wan_cidr)
    routes: list[str] = []
    if include_site_route:
        routes.append(f"$ELEV ip route replace {site.network} via {wan_ip} dev eth1;")
    if include_vlan_route:
        routes.append(f"$ELEV ip route replace {vlan.network} via {wan_ip} dev eth1;")
    return (
        f"ELEV=\"$({elevation_probe()})\"; test -n \"$ELEV\"; "
        f"$ELEV ip addr replace {wan_peer_ip}/{wan.network.prefixlen} dev eth1; "
        "$ELEV ip link set eth1 up; "
        f"{' '.join(routes)} "
        "ip -br addr; ip route"
    )


def client_a_access_to_wan_command(args: argparse.Namespace, *, expect_success: bool) -> str:
    site = ip_interface(args.site_cidr)
    wan = ip_interface(args.wan_cidr)
    site_ip = str(site.ip)
    wan_peer_ip = second_host_address(args.wan_cidr)
    expectation = "" if expect_success else '; rc=$?; test "$rc" -ne 0'
    return (
        f"ELEV=\"$({elevation_probe()})\"; test -n \"$ELEV\"; "
        "$ELEV /usr/local/sbin/labfoundry-refresh-test-dhcp 2>/dev/null || /usr/local/sbin/labfoundry-refresh-test-dhcp 2>/dev/null || true; "
        f"$ELEV ip route replace {wan.network} via {site_ip} dev eth1; "
        f"ping -c 2 -W 2 {wan_peer_ip}{expectation}"
    )


def client_a_route_role_to_wan_command(args: argparse.Namespace) -> str:
    vlan = ip_interface(args.vlan_cidr)
    wan = ip_interface(args.wan_cidr)
    vlan_peer_ip = second_host_address(args.vlan_cidr)
    vlan_ip = str(vlan.ip)
    wan_peer_ip = second_host_address(args.wan_cidr)
    return (
        f"ELEV=\"$({elevation_probe()})\"; test -n \"$ELEV\"; "
        "$ELEV modprobe 8021q 2>/dev/null || true; "
        f"$ELEV ip link add link eth2 name eth2.{args.vlan_id} type vlan id {args.vlan_id} 2>/dev/null || true; "
        f"$ELEV ip addr replace {vlan_peer_ip}/{vlan.network.prefixlen} dev eth2.{args.vlan_id}; "
        f"$ELEV ip link set eth2 up; $ELEV ip link set eth2.{args.vlan_id} up; "
        f"$ELEV ip route replace {wan.network} via {vlan_ip} dev eth2.{args.vlan_id}; "
        f"ping -c 2 -W 2 {wan_peer_ip}"
    )


def access_routing_blocked_check(args: argparse.Namespace) -> dict[str, Any]:
    if args.skip_client_checks:
        return {"skipped": "client checks disabled"}
    if not args.client_a_host or not args.client_b_host:
        return {"skipped": "client hosts not provided"}
    client_b = ssh_command(args.client_b_host, args, client_b_wan_setup_command(args), role="client")
    require_success(client_b, "client B WAN setup before access routing rule")
    client_a = ssh_command(args.client_a_host, args, client_a_access_to_wan_command(args, expect_success=False), role="client")
    require_success(client_a, "client A access-to-WAN expected block")
    return {"client_b_setup": client_b, "client_a_blocked": client_a}


def route_role_routing_check(args: argparse.Namespace) -> dict[str, Any]:
    if args.skip_client_checks:
        return {"skipped": "client checks disabled"}
    if not args.client_a_host or not args.client_b_host:
        return {"skipped": "client hosts not provided"}
    client_b = ssh_command(args.client_b_host, args, client_b_wan_setup_command(args, include_site_route=False, include_vlan_route=True), role="client")
    require_success(client_b, "client B WAN route-role setup")
    client_a = ssh_command(args.client_a_host, args, client_a_route_role_to_wan_command(args), role="client")
    require_success(client_a, "client A route-role VLAN-to-WAN probe")
    return {"client_b_setup": client_b, "client_a_route_role": client_a}


def client_checks(args: argparse.Namespace) -> dict[str, Any]:
    if args.skip_client_checks:
        return {"skipped": "client checks disabled"}
    evidence: dict[str, Any] = {}
    site = ip_interface(args.site_cidr)
    wan = ip_interface(args.wan_cidr)
    site_ip = str(site.ip)
    wan_ip = str(wan.ip)
    wan_peer_ip = second_host_address(args.wan_cidr)
    elevate = elevation_probe()
    if args.client_b_host:
        command = client_b_wan_setup_command(args) + f"; ping -c 2 {wan_ip}"
        result = ssh_command(args.client_b_host, args, command, role="client")
        require_success(result, "client B WAN probe")
        evidence["client_b"] = result
    else:
        evidence["client_b"] = {"skipped": "client B host not provided"}
    if args.client_a_host:
        command = (
            f"ELEV=\"$({elevate})\"; "
            "$ELEV /usr/local/sbin/labfoundry-refresh-test-dhcp 2>/dev/null || /usr/local/sbin/labfoundry-refresh-test-dhcp 2>/dev/null || true; "
            f"$ELEV ip route replace {wan.network} via {site_ip} dev eth1; "
            "ip -br addr; "
            "getent hosts interop-appliance.labfoundry.internal; "
            f"nslookup interop-appliance.{args.domain} {site_ip}; "
            f"ping -c 2 {site_ip}; "
            f"ping -c 2 {wan_peer_ip}; "
            f"traceroute -n {wan_peer_ip} 2>/dev/null || true; "
            "resolvectl status 2>/dev/null || true"
        )
        result = ssh_command(args.client_a_host, args, command, role="client")
        require_success(result, "client A DNS/DHCP probe")
        evidence["client_a"] = result
    else:
        evidence["client_a"] = {"skipped": "client A host not provided"}
    return evidence


def ntp_client_checks(args: argparse.Namespace) -> dict[str, Any]:
    if args.skip_client_checks:
        return {"skipped": "client checks disabled"}
    if not args.client_a_host:
        return {"skipped": "client A host not provided"}
    site_ip = str(ip_interface(args.site_cidr).ip)
    hostname = f"ntp.{args.domain}"
    elevate = elevation_probe()
    command = (
        f"ELEV=\"$({elevate})\"; test -n \"$ELEV\"; "
        "command -v chronyd; chronyd -v; "
        f"curl -ksS --connect-timeout 10 --max-time 30 https://{site_ip}/ca/downloads/root-ca.pem -o /tmp/labfoundry-root-ca.pem; "
        "grep -F 'BEGIN CERTIFICATE' /tmp/labfoundry-root-ca.pem; "
        f"printf '%s\\n' 'server {hostname} iburst nts' 'ntstrustedcerts /tmp/labfoundry-root-ca.pem' 'driftfile /tmp/labfoundry-chrony-nts.drift' > /tmp/labfoundry-chrony-nts.conf; "
        "$ELEV timeout 90 chronyd -Q -t 75 -f /tmp/labfoundry-chrony-nts.conf; "
        f"printf '%s\\n' 'server {site_ip} iburst' 'driftfile /tmp/labfoundry-chrony-ntp.drift' > /tmp/labfoundry-chrony-ntp.conf; "
        "$ELEV timeout 45 chronyd -Q -t 30 -f /tmp/labfoundry-chrony-ntp.conf"
    )
    result = ssh_command(args.client_a_host, args, command, role="client")
    require_success(result, "client A NTS-authenticated and ordinary NTP probes")
    return {"client_a": result, "hostname": hostname, "ordinary_ntp_target": site_ip}


def wan_packet_loss_check(client: HttpClient, args: argparse.Namespace) -> dict[str, Any]:
    if args.skip_client_checks:
        return {"skipped": "client checks disabled"}
    if not args.client_a_host or not args.client_b_host:
        return {"skipped": "client hosts not provided"}

    evidence: dict[str, Any] = {}
    cleanup_evidence: dict[str, Any] = {}
    original_error: Exception | None = None
    site = ip_interface(args.site_cidr)
    wan = ip_interface(args.wan_cidr)
    site_ip = str(site.ip)
    wan_ip = str(wan.ip)
    wan_peer_ip = second_host_address(args.wan_cidr)
    elevate = elevation_probe()
    client_b_setup = (
        f"ELEV=\"$({elevate})\"; test -n \"$ELEV\"; "
        f"$ELEV ip addr replace {wan_peer_ip}/{wan.network.prefixlen} dev eth1; "
        "$ELEV ip link set eth1 up; "
        f"$ELEV ip route replace {site.network} via {wan_ip} dev eth1; "
        "ip -br addr"
    )
    loss_ping = (
        f"ELEV=\"$({elevate})\"; test -n \"$ELEV\"; "
        "$ELEV /usr/local/sbin/labfoundry-refresh-test-dhcp 2>/dev/null || /usr/local/sbin/labfoundry-refresh-test-dhcp 2>/dev/null || true; "
        f"$ELEV ip route replace {wan.network} via {site_ip} dev eth1; "
        f"ping -c 3 -W 1 {wan_peer_ip}; rc=$?; "
        "test \"$rc\" -ne 0"
    )
    recovery_ping = (
        f"ELEV=\"$({elevate})\"; test -n \"$ELEV\"; "
        "$ELEV /usr/local/sbin/labfoundry-refresh-test-dhcp 2>/dev/null || /usr/local/sbin/labfoundry-refresh-test-dhcp 2>/dev/null || true; "
        f"$ELEV ip route replace {wan.network} via {site_ip} dev eth1; "
        f"ping -c 2 -W 2 {wan_peer_ip}"
    )

    wan_client = authenticated_ui_client(client, args)

    try:
        evidence["loss_policy"] = set_lifecycle_wan_policy(wan_client, packet_loss_percent=100.0)
        evidence["loss_apply"] = apply_units(wan_client, ["wan"], args)
        loss_command = (
            f"tc qdisc show dev {args.wan_interface} > /tmp/labfoundry-wan-loss-check.txt && "
            "grep netem /tmp/labfoundry-wan-loss-check.txt && "
            "grep loss /tmp/labfoundry-wan-loss-check.txt && "
            "grep 100 /tmp/labfoundry-wan-loss-check.txt"
        )
        try:
            loss_host = ssh_until_success(
                args.appliance_ssh_host,
                args,
                loss_command,
                role="appliance",
                label="host WAN 100 percent loss check",
                timeout_seconds=30,
            )
        except LifecycleError:
            evidence["loss_reapply"] = apply_units(wan_client, ["wan"], args)
            try:
                loss_host = ssh_until_success(
                    args.appliance_ssh_host,
                    args,
                    loss_command,
                    role="appliance",
                    label="host WAN 100 percent loss check",
                    timeout_seconds=30,
                )
            except LifecycleError:
                helper_apply = ssh_command(
                    args.appliance_ssh_host,
                    args,
                    "/opt/labfoundry/bin/labfoundry-helper wan apply --real /var/lib/labfoundry/apply/wan/labfoundry-wan.conf",
                    role="appliance",
                )
                require_success(helper_apply, "host WAN helper reapply")
                evidence["loss_helper_apply"] = helper_apply
                loss_host = ssh_until_success(
                    args.appliance_ssh_host,
                    args,
                    loss_command,
                    role="appliance",
                    label="host WAN 100 percent loss check",
                )
        evidence["loss_host"] = loss_host
        client_b = ssh_command(args.client_b_host, args, client_b_setup, role="client")
        require_success(client_b, "client B WAN loss setup")
        evidence["client_b_setup"] = client_b
        client_a_loss = ssh_command(args.client_a_host, args, loss_ping, role="client")
        require_success(client_a_loss, "client A WAN loss expected ping failure")
        evidence["client_a_loss_ping"] = client_a_loss
    except Exception as exc:  # noqa: BLE001 - restore normal WAN policy before reporting the original failure
        original_error = exc
    finally:
        try:
            cleanup_evidence["restored_policy"] = set_lifecycle_wan_policy(wan_client, packet_loss_percent=0.0)
            cleanup_evidence["restore_apply"] = apply_units(wan_client, ["wan"], args)
            restore_host = ssh_until_success(
                args.appliance_ssh_host,
                args,
                f"tc qdisc show dev {args.wan_interface} > /tmp/labfoundry-wan-restore-check.txt && "
                "grep netem /tmp/labfoundry-wan-restore-check.txt && "
                "grep delay /tmp/labfoundry-wan-restore-check.txt && "
                "grep 25ms /tmp/labfoundry-wan-restore-check.txt && "
                "! grep 'loss 100' /tmp/labfoundry-wan-restore-check.txt",
                role="appliance",
                label="host WAN loss restore check",
            )
            cleanup_evidence["restore_host"] = restore_host
            client_b_recovery = ssh_command(args.client_b_host, args, client_b_setup, role="client")
            require_success(client_b_recovery, "client B WAN recovery setup")
            cleanup_evidence["client_b_recovery_setup"] = client_b_recovery
            client_a_recovery = ssh_command(args.client_a_host, args, recovery_ping, role="client")
            require_success(client_a_recovery, "client A WAN recovery ping")
            cleanup_evidence["client_a_recovery_ping"] = client_a_recovery
        except Exception as cleanup_exc:  # noqa: BLE001
            if original_error is not None:
                raise LifecycleError(f"{original_error}; WAN loss cleanup also failed: {cleanup_exc}") from cleanup_exc
            raise
    evidence["restore"] = cleanup_evidence
    if original_error is not None:
        raise original_error
    return evidence


def run_step(results: list[StepResult], name: str, func, *args) -> Any:  # type: ignore[no-untyped-def]
    step = StepResult(name=name, status="running")
    results.append(step)
    try:
        evidence = func(*args)
    except Exception as exc:  # noqa: BLE001 - preserve failing evidence in result JSON
        step.finish("failed", str(exc))
        raise
    step.evidence = evidence or {}
    step.finish("passed")
    return evidence


def export_settings_backup(client: HttpClient, args: argparse.Namespace, archive_path: str) -> dict[str, Any]:
    export_client = authenticated_ui_client(client, args)
    status, body, _headers = export_client.request("GET", "/backup-restore")
    if status >= 400:
        raise LifecycleError(f"GET /backup-restore failed with HTTP {status}")
    csrf = extract_csrf(body)
    status, archive_bytes, response_headers = export_client.request_bytes("POST", "/backup-restore/export", form={"csrf": csrf})
    if status >= 400:
        raise LifecycleError(f"Settings backup export failed with HTTP {status}: {archive_bytes[:500].decode('utf-8', errors='replace')}")
    if not archive_bytes.strip():
        raise LifecycleError("Settings backup export returned an empty response body.")
    archive = json.loads(archive_bytes.decode("utf-8-sig"))
    path = Path(archive_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(archive_bytes)
    data = archive.get("data") or {}
    if "ntp_settings" not in data or "chrony_settings" in data:
        raise LifecycleError("Settings backup must contain ntp_settings and must not contain chrony_settings.")
    return {
        "path": str(path),
        "kind": archive.get("kind"),
        "schema_version": archive.get("schema_version"),
        "content_disposition": response_headers.get("Content-Disposition", ""),
        "total_rows": sum(len(value) for value in data.values() if isinstance(value, list)),
        "tables": sorted(data.keys()),
    }


def restore_settings_backup(client: HttpClient, args: argparse.Namespace) -> dict[str, Any]:
    archive_path = Path(args.restore_settings_backup)
    if not archive_path.exists():
        raise LifecycleError(f"Settings backup archive not found: {archive_path}")
    status, body, _headers = client.request("GET", "/backup-restore")
    if status >= 400:
        raise LifecycleError(f"GET /backup-restore failed with HTTP {status}")
    csrf = extract_csrf(body)
    status, response_body, _headers = client.multipart_request(
        "POST",
        "/backup-restore/restore",
        fields={"csrf": csrf},
        files={"archive_file": (archive_path.name, archive_path.read_bytes(), "application/json")},
    )
    if status >= 400 or "Settings restored" not in response_body:
        raise LifecycleError(f"Settings backup restore failed with HTTP {status}: {summarize_html_response(response_body)}")
    archive = json.loads(archive_path.read_text(encoding="utf-8-sig"))
    data = archive.get("data") or {}
    if "ntp_settings" not in data or "chrony_settings" in data:
        raise LifecycleError("Settings restore archive must contain ntp_settings and must not contain chrony_settings.")
    return {
        "path": str(archive_path),
        "http_status": status,
        "total_rows": sum(len(value) for value in data.values() if isinstance(value, list)),
        "services_forced_stopped": "Services are stopped and unconfigured" in response_body,
    }


def step_evidence(result: dict[str, Any], step_name: str) -> dict[str, Any]:
    for step in result.get("steps", []):
        if step.get("name") == step_name and step.get("status") == "passed":
            evidence = step.get("evidence")
            if isinstance(evidence, dict):
                return evidence
    raise LifecycleError(f"Could not find passed step {step_name!r} in baseline result.")


def restored_certificate_baseline_check(args: argparse.Namespace, restored_evidence: dict[str, Any]) -> dict[str, Any]:
    baseline_path = Path(args.certificate_baseline_result)
    if not baseline_path.exists():
        raise LifecycleError(f"Certificate baseline result not found: {baseline_path}")
    baseline = json.loads(baseline_path.read_text(encoding="utf-8-sig"))
    initial_evidence = step_evidence(baseline, "ca-client-certificate-check")
    initial_certificate = initial_evidence.get("certificate") or {}
    restored_certificate = restored_evidence.get("certificate") or {}
    comparisons = {
        "common_name": (initial_evidence.get("common_name"), restored_evidence.get("common_name")),
        "serial_number": (initial_certificate.get("serial_number"), restored_certificate.get("serial_number")),
        "sha256_fingerprint": (initial_certificate.get("sha256_fingerprint"), restored_certificate.get("sha256_fingerprint")),
        "subject": (initial_certificate.get("subject"), restored_certificate.get("subject")),
        "issuer": (initial_certificate.get("issuer"), restored_certificate.get("issuer")),
    }
    mismatches = {key: {"initial": pair[0], "restored": pair[1]} for key, pair in comparisons.items() if pair[0] != pair[1]}
    if mismatches:
        raise LifecycleError(f"Restored certificate does not match pre-restore certificate: {mismatches}")
    return {
        "baseline_result": str(baseline_path),
        "common_name": restored_evidence.get("common_name"),
        "serial_number": restored_certificate.get("serial_number"),
        "sha256_fingerprint": restored_certificate.get("sha256_fingerprint"),
    }


def ca_archive_certificate_identity(archive: dict[str, Any]) -> dict[str, Any]:
    data = archive.get("data") or {}
    identity: dict[str, Any] = {"root_ca": None, "certificates": {}}
    settings_rows = data.get("ca_settings") or []
    for row in settings_rows:
        root_pem = row.get("root_certificate_pem")
        if root_pem:
            identity["root_ca"] = certificate_summary(root_pem)
            break
    for row in data.get("ca_certificates") or []:
        certificate_pem = row.get("certificate_pem")
        common_name = str(row.get("common_name") or "")
        if not certificate_pem or not common_name:
            continue
        summary = certificate_summary(certificate_pem)
        identity["certificates"][common_name] = {
            "status": row.get("status"),
            "managed_owner": row.get("managed_owner") or "",
            "serial_number": summary.get("serial_number"),
            "sha256_fingerprint": summary.get("sha256_fingerprint"),
            "subject": summary.get("subject"),
            "issuer": summary.get("issuer"),
        }
    return identity


def restored_ca_archive_baseline_check(args: argparse.Namespace, restored_archive_path: str) -> dict[str, Any]:
    baseline_path = Path(args.restore_settings_backup)
    restored_path = Path(restored_archive_path)
    baseline = json.loads(baseline_path.read_text(encoding="utf-8-sig"))
    restored = json.loads(restored_path.read_text(encoding="utf-8-sig"))
    baseline_identity = ca_archive_certificate_identity(baseline)
    restored_identity = ca_archive_certificate_identity(restored)
    if baseline_identity != restored_identity:
        raise LifecycleError("Restored CA archive certificates do not match the pre-restore settings backup.")
    certificates = restored_identity.get("certificates") or {}
    root_ca = restored_identity.get("root_ca") or {}
    return {
        "baseline_archive": str(baseline_path),
        "restored_archive": str(restored_path),
        "root_ca_sha256_fingerprint": root_ca.get("sha256_fingerprint"),
        "certificate_count": len(certificates),
        "certificates": {
            common_name: {
                "serial_number": values.get("serial_number"),
                "sha256_fingerprint": values.get("sha256_fingerprint"),
                "managed_owner": values.get("managed_owner"),
            }
            for common_name, values in sorted(certificates.items())
        },
    }


def run_full_lifecycle(results: list[StepResult], client: HttpClient, args: argparse.Namespace) -> None:
    run_step(results, "appliance-health", appliance_health, client, args)
    run_step(results, "configure-network", configure_network, client, args)
    run_step(results, "configure-dns-dhcp", configure_dns_dhcp, client, args)
    run_step(results, "configure-esx-storage", configure_esx_storage, client, args)
    run_step(results, "configure-esxi-pxe", configure_esxi_pxe, client, args)
    run_step(results, "configure-firewall-wan", configure_firewall_wan, client, args)
    run_step(results, "configure-ca", configure_ca, client, args)
    run_step(results, "configure-ntp", configure_ntp, client, args)
    run_step(results, "configure-vcf-backups", configure_vcf_backups, client, args)
    run_step(results, "configure-vcf-offline-depot", configure_vcf_offline_depot, client, args)
    run_step(results, "configure-kms", configure_kms, client, args)
    run_step(results, "configure-ldap", configure_ldap, client, args)
    run_step(
        results,
        "apply-connectivity-units",
        apply_units,
        client,
        ["local_users", "network", "firewall", "wan", "dnsmasq", "esxi_pxe", "vcf_backups", "ldap"],
        args,
    )
    if args.esx_storage_test:
        run_step(results, "apply-esx-storage-units", apply_units, client, ["esx_storage", "dnsmasq", "firewall"], args)
    run_step(results, "ca-client-certificate-request", ca_client_certificate_request, client, args)
    run_step(results, "ca-generated-certificate-request-check", ca_generated_certificate_request_check, client, args)
    run_step(results, "apply-ca-unit", apply_units, client, ["ca"], args)
    run_step(results, "apply-ntp-unit", apply_units, client, ["ntpd", "firewall"], args)
    run_step(results, "apply-vcf-offline-depot-unit", apply_units, client, ["dnsmasq", "firewall", "vcf_offline_depot", "public_services"], args)
    run_step(results, "apply-kms-unit", apply_units, client, ["dnsmasq", "firewall", "wan", "kms"], args)
    run_step(results, "authoritative-dns-state-check", authoritative_dns_state_check, args)
    run_step(results, "recursive-dns-state-check", recursive_dns_state_check, args)
    run_step(results, "host-state-checks", host_state_checks, args)
    run_step(results, "managed-ldap-helper-authentication", managed_ldap_helper_authentication_check, args)
    run_step(results, "client-checks", client_checks, args)
    run_step(results, "ntp-client-checks", ntp_client_checks, args)
    run_step(results, "wan-packet-loss-check", wan_packet_loss_check, client, args)
    run_step(results, "ca-client-certificate-check", ca_client_certificate_check, client, args)
    run_step(results, "vcf-backup-client-check", vcf_backup_client_check, args)
    run_step(results, "vcf-depot-auth-check", vcf_depot_auth_check, client, args)
    run_step(results, "vcf-depot-password-rotation", rotate_vcf_depot_password_without_depot_apply, client, args)
    run_step(results, "configure-management-https", configure_management_https, client, args)
    run_step(results, "apply-appliance-settings-unit", apply_units, client, ["appliance_settings", "firewall", "public_services"], args)
    run_step(results, "management-https-check", management_https_check, client, args)
    run_step(results, "web-terminal-check", web_terminal_check, client, args)
    if args.signed_release_repository_url:
        run_step(results, "signed-release-update-check", signed_release_update_check, client, args)
    if args.export_settings_backup:
        run_step(results, "export-settings-backup", export_settings_backup, client, args, args.export_settings_backup)


def run_routing_wan_lifecycle(results: list[StepResult], client: HttpClient, args: argparse.Namespace) -> None:
    run_step(results, "appliance-health", appliance_health, client, args)
    run_step(results, "configure-network", configure_network, client, args)
    run_step(results, "configure-firewall", configure_firewall, client, args)
    policy = run_step(results, "configure-wan-policy", configure_wan_policy, client, args)
    run_step(results, "configure-routes-nat", configure_routes_nat, client, args, policy)
    run_step(results, "apply-routing-wan-before-access-rule", apply_units, client, ["network", "firewall", "wan"], args)
    run_step(results, "host-state-checks-before-access-rule", routing_host_state_checks, args)
    run_step(results, "route-role-routing-check", route_role_routing_check, args)
    run_step(results, "access-routing-blocked-check", access_routing_blocked_check, args)
    run_step(results, "configure-routing-permissions", configure_routing_permissions, client, args)
    run_step(results, "apply-routing-wan-after-access-rule", apply_units, client, ["firewall", "wan"], args)
    run_step(results, "host-state-checks", routing_host_state_checks, args)
    run_step(results, "client-checks", client_checks, args)
    run_step(results, "wan-packet-loss-check", wan_packet_loss_check, client, args)


def run_restored_lifecycle(results: list[StepResult], client: HttpClient, args: argparse.Namespace) -> None:
    if not args.restore_settings_backup:
        raise LifecycleError("--restored-state-run requires --restore-settings-backup.")
    run_step(results, "appliance-health", appliance_health, client, args)
    run_step(results, "restore-settings-backup", restore_settings_backup, client, args)
    run_step(results, "configure-ldap", configure_ldap, client, args)
    run_step(results, "configure-esx-storage", configure_esx_storage, client, args)
    run_step(results, "stage-vcf-backup-password", stage_vcf_backup_password, client, args)
    run_step(results, "stage-vcf-depot-password", stage_vcf_depot_password, client, args)
    run_step(
        results,
        "apply-connectivity-units",
        apply_units,
        client,
        ["local_users", "network", "firewall", "wan", "dnsmasq", "esxi_pxe", "vcf_backups", "ldap"],
        args,
    )
    if args.esx_storage_test:
        run_step(results, "apply-esx-storage-units", apply_units, client, ["esx_storage", "dnsmasq", "firewall"], args)
    run_step(results, "apply-ca-unit", apply_units, client, ["ca"], args)
    run_step(results, "apply-ntp-unit", apply_units, client, ["ntpd", "firewall"], args)
    run_step(results, "apply-vcf-offline-depot-unit", apply_units, client, ["dnsmasq", "firewall", "vcf_offline_depot", "public_services"], args)
    run_step(results, "apply-kms-unit", apply_units, client, ["dnsmasq", "firewall", "wan", "kms"], args)
    run_step(results, "authoritative-dns-state-check", authoritative_dns_state_check, args)
    run_step(results, "recursive-dns-state-check", recursive_dns_state_check, args)
    run_step(results, "host-state-checks", host_state_checks, args)
    run_step(results, "managed-ldap-helper-authentication", managed_ldap_helper_authentication_check, args)
    run_step(results, "client-checks", client_checks, args)
    run_step(results, "ntp-client-checks", ntp_client_checks, args)
    run_step(results, "wan-packet-loss-check", wan_packet_loss_check, client, args)
    cert_evidence = run_step(results, "ca-client-certificate-check", ca_client_certificate_check, client, args)
    if args.certificate_baseline_result:
        run_step(results, "restored-certificate-baseline-check", restored_certificate_baseline_check, args, cert_evidence)
    restored_archive_path = str(Path(args.result_dir) / "restored-settings-backup.json")
    run_step(results, "export-restored-settings-backup", export_settings_backup, client, args, restored_archive_path)
    run_step(results, "restored-ca-archive-baseline-check", restored_ca_archive_baseline_check, args, restored_archive_path)
    run_step(results, "vcf-backup-client-check", vcf_backup_client_check, args)
    run_step(results, "vcf-depot-auth-check", vcf_depot_auth_check, client, args)
    run_step(results, "apply-appliance-settings-unit", apply_units, client, ["appliance_settings", "firewall", "public_services"], args)
    run_step(results, "management-https-check", management_https_check, client, args)
    run_step(results, "web-terminal-check", web_terminal_check, client, args)


def format_step_summary(step: dict[str, Any]) -> str:
    status = str(step.get("status", "unknown")).upper()
    name = str(step.get("name", "unknown"))
    status_token = f"[{status}]"
    if getattr(sys.stdout, "isatty", lambda: False)():
        if status == "PASSED":
            status_token = f"\x1b[32m{status_token}\x1b[0m"
        elif status == "FAILED":
            status_token = f"\x1b[31m{status_token}\x1b[0m"
    if step.get("error"):
        return f"{status_token} {name}: {step['error']}"
    evidence = step.get("evidence") or {}
    detail = ""
    if name == "configure-ca":
        root_ca = evidence.get("root_ca") or {}
        detail = str(root_ca.get("subject") or f"{root_ca.get('pem_bytes', 0)} bytes")
    elif name == "ca-client-certificate-request":
        detail = f"{evidence.get('common_name', '')} via {evidence.get('profile', '')}"
    elif name == "ca-client-certificate-check":
        detail = f"{evidence.get('common_name', '')} certificate id {evidence.get('certificate_id', '')}"
    elif name == "restored-certificate-baseline-check":
        detail = f"{evidence.get('common_name', '')} fingerprint {str(evidence.get('sha256_fingerprint', ''))[:16]}"
    elif name == "restored-ca-archive-baseline-check":
        detail = f"{evidence.get('certificate_count', 0)} CA certificates"
    elif name == "configure-vcf-backups":
        detail = f"{evidence.get('sftp_username', 'vcf-backup')} on {evidence.get('listen_address', '')}:{22}"
    elif name == "configure-kms":
        detail = f"{evidence.get('hostname', 'kms')} on {evidence.get('listen_address', '')}:{evidence.get('port', 5696)}"
    elif name == "configure-firewall-wan":
        policy = evidence.get("wan_policy") or {}
        route = evidence.get("route") or {}
        detail = f"{policy.get('latency_ms', 0)}ms delay, {policy.get('jitter_ms', 0)}ms jitter on {route.get('interface_name', '')}"
    elif name in {
        "apply-connectivity-units",
        "apply-ca-unit",
        "apply-kms-unit",
        "apply-lifecycle-units",
        "apply-routing-wan-before-access-rule",
        "apply-routing-wan-after-access-rule",
    }:
        detail = ", ".join(evidence.get("selected_units", []))
    elif name in {"host-state-checks", "host-state-checks-before-access-rule"}:
        detail = ", ".join(sorted(evidence.keys()))
    elif name == "access-routing-blocked-check":
        detail = "SiteA access to WAN blocked before explicit permission"
    elif name == "route-role-routing-check":
        detail = "route-role VLAN to WAN forwarding passed"
    elif name == "configure-routing-permissions":
        rule = evidence.get("routing_rule") or {}
        detail = f"{rule.get('source_interface', '')} to {rule.get('destination_interface', '')}"
    elif name in {"export-settings-backup", "restore-settings-backup", "export-restored-settings-backup"}:
        detail = f"{evidence.get('total_rows', 0)} rows"
    elif name == "stage-vcf-backup-password":
        detail = str(evidence.get("username", "vcf-backup"))
    elif name == "vcf-backup-client-check":
        detail = str(evidence.get("target", ""))
    elif name == "client-checks":
        detail = ", ".join(sorted(evidence.keys()))
    elif name == "wan-packet-loss-check":
        loss_policy = evidence.get("loss_policy") or {}
        restored_policy = (evidence.get("restore") or {}).get("restored_policy") or {}
        detail = f"{loss_policy.get('packet_loss_percent', 100)}% loss blocked ping; restored to {restored_policy.get('packet_loss_percent', 0)}%"
    return f"{status_token} {name}{': ' + detail if detail else ''}"


def print_human_summary(result: dict[str, Any], result_path: Path) -> None:
    print("")
    print("Lifecycle summary")
    print("=================")
    print(f"Status: {str(result.get('status', 'unknown')).upper()}")
    if result.get("error"):
        print(f"Error: {result['error']}")
    plan = result.get("plan") or {}
    print(f"Appliance: {plan.get('appliance_url', '')}")
    interfaces = plan.get("interfaces") or {}
    if interfaces:
        print(
            "Networks: "
            f"site {interfaces.get('site', {}).get('name', '')} {interfaces.get('site', {}).get('ip_cidr', '')}; "
            f"vlan {interfaces.get('vlan', {}).get('name', '')} {interfaces.get('vlan', {}).get('ip_cidr', '')}; "
            f"wan {interfaces.get('wan', {}).get('name', '')} {interfaces.get('wan', {}).get('ip_cidr', '')}"
        )
    if plan.get("apply_units"):
        print(f"Apply units: {', '.join(plan['apply_units'])}")
    print("Steps:")
    for step in result.get("steps", []):
        print(f"  {format_step_summary(step)}")
    print(f"Result JSON: {result_path}")


def main() -> int:
    args = parse_args()
    result_dir = Path(args.result_dir)
    result_dir.mkdir(parents=True, exist_ok=True)
    results: list[StepResult] = []
    result: dict[str, Any] = {
        "started_at": utc_now(),
        "plan": lifecycle_plan(args),
        "steps": [],
        "status": "running",
    }
    if args.plan_only:
        result["status"] = "planned"
        result["finished_at"] = utc_now()
        (result_dir / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(json.dumps(result["plan"], indent=2))
        return 0

    client = HttpClient(args.appliance_url)
    try:
        if args.routing_wan_only:
            run_routing_wan_lifecycle(results, client, args)
        elif args.restored_state_run:
            run_restored_lifecycle(results, client, args)
        else:
            run_full_lifecycle(results, client, args)
        result["status"] = "passed"
        return_code = 0
    except Exception as exc:  # noqa: BLE001
        result["status"] = "failed"
        result["error"] = str(exc)
        return_code = 1
    finally:
        result["finished_at"] = utc_now()
        result["steps"] = [step.__dict__ for step in results]
        result_path = result_dir / "result.json"
        result_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print_human_summary(result, result_path)
    return return_code


if __name__ == "__main__":
    sys.exit(main())
