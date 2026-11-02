"""Reuse existing offline validators for bounded installed-content measurements."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import textwrap
import zlib
from pathlib import Path
from typing import Any

from scripts import verify_virtualization_guest_wheel as wheel_verifier
from scripts.installation.layout import PROFILE

KINDS = ("assets", "python", "powercli", "rpm", "notices")
PHOTON_FILESYSTEM_SHA256 = "7f5bba3e84f6eb50f6e5e311325089bc642549469d83793e0ba5f40d74ec6024"
PHOTON_SYSTEMD_SHA256 = "2ef0275f25c9b782e7f3cbbaaa5bf0d9037149b5253630c6db27e155c461618f"
PHOTON_LAYOUT_HELPER_SHA256 = "1feb571697f3a1e592e3839bc303cd4c20cd8d40f7acd4e3d7df93449de99608"
PHOTON_GRUB_EFI_SHA256 = "516e63a3c609abecf4a4bf3ef2661d4f1bed26729a612f73e0bfcb530727e91f"
PHOTON_SHIM_SHA256 = "e41e6109d7be89ae83da63ef8021ef9a0e053ecd4fe1f47ae73dd79270d688c7"
PHOTON_RPCBIND_SHA256 = "2c3d001aca71e6c6c81377a7bfc7ec9c3d26ee7a9891b4a706a8205657bc31ba"
PHOTON_OPENLDAP_SHA256 = "11b4af044b7418ba9af5cf6762e2cbe5add5b3463774d20f6be89b8ff98c47dc"
# Reviewed openssh-server-10.6p1-2.ph5 retains the native root:sys 0711 directory policy.
PHOTON_OPENSSH_SHA256 = "8701947e3a0ca692ad4dc19b51432e2030e04b54d1a3f124276c43ccbd016dc3"
PHOTON_AUDIT_SHA256 = "e55fac7b24b2f7546485f0b8b37fb7b105be764436dd4b139ccaa88e6c3e374f"
# The original native pip RPM requires setuptools. Shared provisioning removes
# setuptools after creating the protected application venv, so tdnf also erases
# system pip. Admit that bootstrap-only transition only for these reviewed bytes.
PHOTON_BOOTSTRAP_PIP_RPMS = {
    "python3-pip": "758f649ebad0db9c591278ee7d4a0f69ca8e0c368388c314f1f9adde447df039",
    "python3-setuptools": "b0adce2fba217f99ee6c97ac74d20f6f2e52029c323037e901c2aba5e3c0dab0",
}
PHOTON_MODULE_RPMS = {
    "linux": "e9fce63202ba573679b5c450a320d7cb6ad1d38ccb5d64ceceb917616a9a7191",
    "kmod": "b7614a76f7a17b832e2158fe90413cf2af719b1d1e9d85bfae7195e4905a7850",
    "kmod-binary": "ee872a0ddff939b69e87beec32090dc98d1882e9028f4bd5729b9a2b858aaaeb",
}
# Public-name diagnostics only, never RPM acceptance exceptions. These names
# come from filesystem-1.1-11.ph5.x86_64.rpm, SHA-256
# 7f5bba3e84f6eb50f6e5e311325089bc642549469d83793e0ba5f40d74ec6024.
# The journal directories are from systemd-257.13-5.ph5,
# SHA-256 2ef0275f25c9b782e7f3cbbaaa5bf0d9037149b5253630c6db27e155c461618f.
# The audit log directory is from audit-4.1.3-3.ph5, SHA-256
# e55fac7b24b2f7546485f0b8b37fb7b105be764436dd4b139ccaa88e6c3e374f.
# The rpcbind state directory is from rpcbind-1.2.6-6.ph5, SHA-256
# 2c3d001aca71e6c6c81377a7bfc7ec9c3d26ee7a9891b4a706a8205657bc31ba.
# The EFI files are from shim-signed-16.1-1.ph5, SHA-256
# e41e6109d7be89ae83da63ef8021ef9a0e053ecd4fe1f47ae73dd79270d688c7.
# The LDAP directories and unit are from openldap-servers-2.6.4-6.ph5,
# SHA-256 11b4af044b7418ba9af5cf6762e2cbe5add5b3463774d20f6be89b8ff98c47dc.
# The kernel boot configuration and module alias index are from linux-6.12.114-1.ph5, SHA-256
# e9fce63202ba573679b5c450a320d7cb6ad1d38ccb5d64ceceb917616a9a7191.
RPM_DIAGNOSTIC_PATHS = (
    "/bin",
    "/boot",
    "/dev",
    "/etc",
    "/etc/fstab",
    "/etc/group",
    "/etc/hosts",
    "/etc/inputrc",
    "/etc/modprobe.d",
    "/etc/modprobe.d/usb.conf",
    "/etc/mtab",
    "/etc/opt",
    "/etc/passwd",
    "/etc/profile",
    "/etc/profile.d",
    "/etc/profile.d/proxy.sh",
    "/etc/sysconfig",
    "/etc/sysconfig/clock",
    "/etc/sysconfig/console",
    "/etc/sysconfig/proxy",
    "/home",
    "/lib",
    "/lib64",
    "/media",
    "/mnt",
    "/mnt/hgfs",
    "/proc",
    "/root",
    "/run",
    "/run/lock",
    "/run/media/cdrom",
    "/run/media/floppy",
    "/sbin",
    "/srv",
    "/tmp",
    "/usr",
    "/usr/bin",
    "/usr/include",
    "/usr/lib",
    "/usr/lib/debug",
    "/usr/lib/debug/bin",
    "/usr/lib/debug/lib",
    "/usr/lib/debug/lib64",
    "/usr/lib/debug/sbin",
    "/usr/lib/debug/usr/bin",
    "/usr/lib/debug/usr/lib",
    "/usr/lib/debug/usr/lib64",
    "/usr/lib/debug/usr/sbin",
    "/usr/lib/sysusers.d/group.conf",
    "/usr/lib/sysusers.d/users.conf",
    "/usr/lib64",
    "/usr/libexec",
    "/usr/local",
    "/usr/local/bin",
    "/usr/local/include",
    "/usr/local/lib",
    "/usr/local/lib64",
    "/usr/local/share",
    "/usr/local/share/color",
    "/usr/local/share/dict",
    "/usr/local/share/doc",
    "/usr/local/share/info",
    "/usr/local/share/locale",
    "/usr/local/share/man",
    "/usr/local/share/man/man1",
    "/usr/local/share/man/man2",
    "/usr/local/share/man/man3",
    "/usr/local/share/man/man4",
    "/usr/local/share/man/man5",
    "/usr/local/share/man/man6",
    "/usr/local/share/man/man7",
    "/usr/local/share/man/man8",
    "/usr/local/share/misc",
    "/usr/local/share/terminfo",
    "/usr/local/share/zoneinfo",
    "/usr/local/src",
    "/usr/sbin",
    "/usr/share",
    "/usr/share/color",
    "/usr/share/dict",
    "/usr/share/doc",
    "/usr/share/info",
    "/usr/share/locale",
    "/usr/share/man",
    "/usr/share/man/man1",
    "/usr/share/man/man2",
    "/usr/share/man/man3",
    "/usr/share/man/man4",
    "/usr/share/man/man5",
    "/usr/share/man/man6",
    "/usr/share/man/man7",
    "/usr/share/man/man8",
    "/usr/share/misc",
    "/usr/share/terminfo",
    "/usr/share/zoneinfo",
    "/usr/src",
    "/var",
    "/var/cache",
    "/var/lib",
    "/var/lib/color",
    "/var/lib/locate",
    "/var/lib/misc",
    "/var/local",
    "/var/lock",
    "/var/log",
    "/var/log/btmp",
    "/var/log/wtmp",
    "/var/mail",
    "/var/mnt",
    "/var/opt",
    "/var/run",
    "/var/spool",
    "/var/srv",
    "/var/tmp",
    "/var/log/journal",
    "/var/log/journal/remote",
    "/var/log/audit",
    "/var/lib/rpcbind",
    "/boot/efi/EFI/BOOT/bootx64.efi",
    "/boot/efi/EFI/BOOT/revocations.efi",
    "/usr/lib/systemd/system/slapd.service",
    "/var/lib/openldap",
    "/var/run/openldap",
    "/boot/linux-6.12.114-1.ph5.cfg",
    "/lib/modules/6.12.114-1.ph5/modules.alias",
)
SOURCE_MEMBERS = (
    "source/image/common/scripts/provision-atlaso.sh",
    "source/scripts/verify_virtualization_guest_wheel.py",
    "source/image/common/powershell/powercli-lock.json",
    "source/image/common/scripts/verify-photon-package-state.py",
)
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_PACKAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9+._:-]{0,127}\Z")
_RUNTIME_ROOTS = {"bin", "releases", "current", ".venv", "build-info.json"}
_RSYNC_EXCLUDES = {".git", ".venv", ".pytest_cache", "data", "test-results"}
_VMWARE_SOURCES = {
    "scripts/appliance/atlaso-vmware-ovf-customize.py",
    "image/vmware-workstation/systemd/atlaso-vmware-ovf-customize.service",
    "image/vmware-workstation/systemd/atlaso-vmware-ovf-prepare.service",
}
_COMMON_KEYS = {"schema", "kind", "iso_sha256"}
_EXPECTED_EXTRA = {
    "assets": {"environment_verifier_sha256", "source_digest", "source_file_count", "trust_names", "trust_digest", "omitted_sources", "deployed_file_count"},
    "python": {"software_verifier_sha256", "environment_verifier_sha256", "release_manifest_sha256", "version", "source_commit", "wheel_sha256"},
    "powercli": {"powercli_script_sha256", "powercli_lock_sha256", "module_count"},
    "rpm": {"package_state_sha256", "allowed_inventory", "required_packages", "filesystem_sha256", "systemd_sha256", "audit_sha256", "rpcbind_sha256", "openssh_sha256", "openldap_sha256", "shim_sha256", "grub_efi_sha256"},
    "notices": {"notice_generator_sha256", "notice_config_sha256", "notice_lock_sha256", "version"},
}


class MissingRequiredRpms(ValueError):
    """Retain only public positions in the admitted required-package list."""

    def __init__(self, indices: list[int]) -> None:
        """Record the missing admitted package positions.

        Args:
            indices: Sorted positions derived solely from the admitted expectation.
        """
        super().__init__("installed RPM required package set is incomplete")
        self.indices = indices


def _canonical_digest(records: dict[str, str]) -> str:
    """Hash a public path/content inventory using the existing module convention.

    Args:
        records: Relative public paths and their SHA-256 content digests.
    """
    return hashlib.sha256("".join(f"{name}\0{records[name]}\n" for name in sorted(records)).encode()).hexdigest()


def _compressed(value: Any) -> str:
    """Encode a bounded public inventory without expanding console commands.

    Args:
        value: Public package records or package names.
    """
    return base64.b64encode(zlib.compress(json.dumps(value, sort_keys=True, separators=(",", ":")).encode(), 9)).decode()


def _decode_inventory(value: str) -> Any:
    """Decode one capped public package inventory.

    Args:
        value: Base64-encoded compressed JSON inventory.
    """
    if not isinstance(value, str) or len(value) > 8192:
        raise ValueError("content inventory exceeds its encoded bound")
    decoder = zlib.decompressobj()
    raw = decoder.decompress(base64.b64decode(value, validate=True), 131073)
    if len(raw) > 131072 or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
        raise ValueError("content inventory exceeds its decoded bound")
    return json.loads(raw)


def _package_inventory(value: Any) -> dict[str, list[str]]:
    """Require a bounded public name/version/architecture inventory.

    Args:
        value: Decoded installed or media RPM identity mapping.
    """
    if not isinstance(value, dict) or not 1 <= len(value) <= 1024:
        raise ValueError("content package inventory is invalid")
    for name, identity in value.items():
        if (not isinstance(name, str) or not _PACKAGE.fullmatch(name)
                or not isinstance(identity, list) or len(identity) != 2
                or not isinstance(identity[0], str) or not re.fullmatch(r"[A-Za-z0-9+._:~^-]{1,192}", identity[0])
                or not isinstance(identity[1], str) or identity[1] not in {"x86_64", "noarch"}):
            raise ValueError("content package inventory is invalid")
    return value


def prepare_content_inputs(base: dict[str, Any], manifest: dict, sources: dict[str, bytes]) -> list[dict[str, Any]]:
    """Derive public checks solely from the checksum-admitted ISO inventory.

    Args:
        base: Existing ISO/software expectations returned by the inspector.
        manifest: Original ISO payload manifest whose bytes were admitted.
        sources: Fixed source members independently checked against that manifest.
    """
    files = {item["path"]: item["sha256"] for item in manifest["files"]}
    for name in SOURCE_MEMBERS:
        if name not in sources or hashlib.sha256(sources[name]).hexdigest() != files.get(name):
            raise ValueError("content source differs from admitted ISO")
    reference_digest = hashlib.sha256(Path(wheel_verifier.__file__).read_bytes()).hexdigest()
    if reference_digest != files[SOURCE_MEMBERS[1]]:
        raise ValueError("content adapter requires the original shared verifier contract")
    state_digest = hashlib.sha256((Path(__file__).resolve().parents[2] /
                                   "image/common/scripts/verify-photon-package-state.py").read_bytes()).hexdigest()
    if state_digest != files[SOURCE_MEMBERS[3]]:
        raise ValueError("content adapter requires the original shared Photon runtime contract")
    notice_lock_sha256 = files.get("software/requirements-appliance.lock")
    if not isinstance(notice_lock_sha256, str) or not _DIGEST.fullmatch(notice_lock_sha256):
        raise ValueError("content notices require the admitted signed software lock")
    removals = re.findall(r'run_tdnf "Build-only package removal" --noautoremove remove ([^\r\n]+)', sources[SOURCE_MEMBERS[0]].decode())
    if len(removals) != 1 or not all(_PACKAGE.fullmatch(name) for name in removals[0].split()):
        raise ValueError("shared build-only package removal is ambiguous")
    removed = set(removals[0].split())
    rpms = manifest.get("rpm_inventory")
    packages = manifest.get("packages")
    if not isinstance(rpms, list) or not 1 <= len(rpms) <= 1024 or not isinstance(packages, list):
        raise ValueError("content RPM inventory is missing or excessive")
    allowed = {}
    filesystem_sha256 = ""
    systemd_sha256 = ""
    audit_sha256 = ""
    rpcbind_sha256 = ""
    openssh_sha256 = ""
    openldap_sha256 = ""
    shim_sha256 = ""
    grub_efi_sha256 = ""
    for item in rpms:
        if (not isinstance(item, dict) or set(item) != {"file", "name", "version", "architecture", "sha256"}
                or not _PACKAGE.fullmatch(str(item["name"])) or item["name"] in allowed
                or not re.fullmatch(r"[A-Za-z0-9+._:~^-]{1,192}", str(item["version"]))
                or item["architecture"] not in {"x86_64", "noarch"}
                or files.get("rpms/" + str(item["file"])) != item["sha256"]):
            raise ValueError("content RPM identity differs from admitted files")
        allowed[item["name"]] = [item["version"], item["architecture"]]
        if item["name"] == "filesystem":
            filesystem_sha256 = item["sha256"]
        if item["name"] == "systemd":
            systemd_sha256 = item["sha256"]
        if item["name"] == "audit":
            audit_sha256 = item["sha256"]
        if item["name"] == "rpcbind":
            rpcbind_sha256 = item["sha256"]
        if item["name"] == "openssh-server":
            openssh_sha256 = item["sha256"]
        if item["name"] == "openldap-servers":
            openldap_sha256 = item["sha256"]
        if item["name"] == "shim-signed":
            shim_sha256 = item["sha256"]
        if item["name"] == "grub2-efi-image":
            grub_efi_sha256 = item["sha256"]
    if filesystem_sha256 != PHOTON_FILESYSTEM_SHA256:
        raise ValueError("admitted Photon filesystem requires a reviewed runtime metadata profile")
    if systemd_sha256 != PHOTON_SYSTEMD_SHA256:
        raise ValueError("admitted Photon systemd requires a reviewed runtime metadata profile")
    if audit_sha256 != PHOTON_AUDIT_SHA256:
        raise ValueError("admitted Photon audit requires a reviewed runtime metadata profile")
    if rpcbind_sha256 != PHOTON_RPCBIND_SHA256:
        raise ValueError("admitted Photon rpcbind requires a reviewed runtime metadata profile")
    if openssh_sha256 != PHOTON_OPENSSH_SHA256:
        raise ValueError("admitted Photon OpenSSH requires a reviewed runtime metadata profile")
    if openldap_sha256 != PHOTON_OPENLDAP_SHA256:
        raise ValueError("admitted Photon OpenLDAP requires a reviewed runtime metadata profile")
    if shim_sha256 != PHOTON_SHIM_SHA256:
        raise ValueError("admitted Photon shim requires a reviewed runtime metadata profile")
    if grub_efi_sha256 != PHOTON_GRUB_EFI_SHA256:
        raise ValueError("admitted Photon GRUB EFI requires a reviewed runtime metadata profile")
    module_rpms = {item["name"]: item["sha256"] for item in rpms if item["name"] in PHOTON_MODULE_RPMS}
    if module_rpms != PHOTON_MODULE_RPMS:
        raise ValueError("admitted Photon module inputs require the original Linux and kmod RPMs")
    if files.get("source/scripts/installation/layout.py") != PHOTON_LAYOUT_HELPER_SHA256:
        raise ValueError("admitted installation layout requires the original shared verifier contract")
    bootstrap_removed = set()
    if "python3-pip" in packages and "python3-setuptools" in removed:
        bootstrap_pins = {item["name"]: item["sha256"] for item in rpms if item["name"] in PHOTON_BOOTSTRAP_PIP_RPMS}
        if bootstrap_pins != PHOTON_BOOTSTRAP_PIP_RPMS:
            raise ValueError("admitted Photon bootstrap pip cleanup requires reviewed RPMs")
        bootstrap_removed.add("python3-pip")
    required = sorted(set(packages) - removed - bootstrap_removed)
    if not required or not set(required) <= allowed.keys():
        raise ValueError("required runtime package set is incomplete")
    lock = json.loads(sources[SOURCE_MEMBERS[2]])
    if lock.get("schema_version") != 2 or not isinstance(lock.get("modules"), dict) or not lock["modules"]:
        raise ValueError("content PowerCLI lock is invalid")
    copied = {}
    for name, checksum in files.items():
        if not name.startswith("source/"):
            continue
        relative = name.removeprefix("source/")
        parts = relative.split("/")
        if (parts[0] in _RUNTIME_ROOTS or any(part in _RSYNC_EXCLUDES or part == "__pycache__" for part in parts)
                or relative.endswith(".pyc")):
            continue
        copied[relative] = checksum
    trust = {name.removeprefix("source/"): checksum for name, checksum in files.items()
             if name.startswith("source/image/common/update-trust/") and name.endswith(".pem")}
    if not copied or not trust or any(not re.fullmatch(r"atlaso-release-[A-Za-z0-9._-]+\.pem", Path(name).name) for name in trust):
        raise ValueError("content source or public trust inventory is incomplete")
    specifications = {
        "assets": {"environment_verifier_sha256": reference_digest, "source_digest": _canonical_digest(copied),
                   "source_file_count": len(copied), "trust_names": sorted(Path(name).name for name in trust),
                   "trust_digest": _canonical_digest(trust), "omitted_sources": sorted(_VMWARE_SOURCES),
                   "deployed_file_count": len((wheel_verifier.DEPLOYED_TEXT_FILES | wheel_verifier.DEPLOYED_BINARY_FILES).keys() - _VMWARE_SOURCES)},
        "python": {**{key: base[key] for key in _EXPECTED_EXTRA["python"] - {"environment_verifier_sha256"}},
                   "environment_verifier_sha256": reference_digest},
        "powercli": {"powercli_script_sha256": files["source/image/common/powershell/provision-powercli.ps1"],
                     "powercli_lock_sha256": files[SOURCE_MEMBERS[2]], "module_count": len(lock["modules"])},
        "rpm": {"package_state_sha256": files["source/image/common/scripts/verify-photon-package-state.py"],
                "allowed_inventory": _compressed(allowed), "required_packages": _compressed(required),
                "filesystem_sha256": filesystem_sha256, "systemd_sha256": systemd_sha256, "audit_sha256": audit_sha256, "rpcbind_sha256": rpcbind_sha256, "openssh_sha256": openssh_sha256, "openldap_sha256": openldap_sha256, "shim_sha256": shim_sha256, "grub_efi_sha256": grub_efi_sha256},
        "notices": {"notice_generator_sha256": files["source/scripts/generate_third_party_notices.py"],
                    "notice_config_sha256": files["source/scripts/third_party_notices.json"],
                    "notice_lock_sha256": notice_lock_sha256, "version": base["version"]},
    }
    return [{"schema": 1, "kind": kind, "iso_sha256": base["iso_sha256"], **specifications[kind]} for kind in KINDS]


def _validate_expected(expected: dict[str, Any]) -> str:
    """Validate the exact internal expectation shape before command generation.

    Args:
        expected: One content check derived from admitted media.
    """
    if not isinstance(expected, dict):
        raise ValueError("content expectation schema is invalid")
    kind = expected.get("kind")
    if (not isinstance(kind, str) or kind not in KINDS or type(expected.get("schema")) is not int or expected["schema"] != 1 or
            set(expected) != _COMMON_KEYS | _EXPECTED_EXTRA[kind]):
        raise ValueError("content expectation schema is invalid")
    for key, value in expected.items():
        if (key.endswith("_sha256") or key in {"source_digest", "trust_digest"}) and (
                not isinstance(value, str) or not _DIGEST.fullmatch(value)):
            raise ValueError("content expectation digest is invalid")
    if "version" in expected and (not isinstance(expected["version"], str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", expected["version"])):
        raise ValueError("content expectation version is invalid")
    if "source_commit" in expected and (not isinstance(expected["source_commit"], str) or not re.fullmatch(r"[0-9a-f]{40}", expected["source_commit"])):
        raise ValueError("content expectation commit is invalid")
    if kind == "assets":
        names = expected["trust_names"]
        if (not isinstance(names, list) or not 1 <= len(names) <= 16
                or any(not isinstance(name, str) or not re.fullmatch(r"atlaso-release-[A-Za-z0-9._-]+\.pem", name) for name in names)
                or names != sorted(set(names)) or expected["omitted_sources"] != sorted(_VMWARE_SOURCES)
                or type(expected["source_file_count"]) is not int or not 1 <= expected["source_file_count"] <= 10000
                or type(expected["deployed_file_count"]) is not int or not 1 <= expected["deployed_file_count"] <= 100):
            raise ValueError("content source or public trust expectation is invalid")
    if kind == "powercli" and (type(expected["module_count"]) is not int or not 1 <= expected["module_count"] <= 1000):
        raise ValueError("content module count is invalid")
    if kind == "rpm":
        if expected["filesystem_sha256"] != PHOTON_FILESYSTEM_SHA256:
            raise ValueError("Photon filesystem runtime metadata profile is not admitted")
        if expected["systemd_sha256"] != PHOTON_SYSTEMD_SHA256:
            raise ValueError("Photon systemd runtime metadata profile is not admitted")
        if expected["audit_sha256"] != PHOTON_AUDIT_SHA256:
            raise ValueError("Photon audit runtime metadata profile is not admitted")
        if expected["rpcbind_sha256"] != PHOTON_RPCBIND_SHA256:
            raise ValueError("Photon rpcbind runtime metadata profile is not admitted")
        if expected["openssh_sha256"] != PHOTON_OPENSSH_SHA256:
            raise ValueError("Photon OpenSSH runtime metadata profile is not admitted")
        if expected["openldap_sha256"] != PHOTON_OPENLDAP_SHA256:
            raise ValueError("Photon OpenLDAP runtime metadata profile is not admitted")
        if expected["shim_sha256"] != PHOTON_SHIM_SHA256:
            raise ValueError("Photon shim runtime metadata profile is not admitted")
        if expected["grub_efi_sha256"] != PHOTON_GRUB_EFI_SHA256:
            raise ValueError("Photon GRUB EFI runtime metadata profile is not admitted")
        allowed = _package_inventory(_decode_inventory(expected["allowed_inventory"]))
        required = _decode_inventory(expected["required_packages"])
        if (not isinstance(required, list) or not required or any(not isinstance(name, str) for name in required)
                or required != sorted(set(required)) or not set(required) <= allowed.keys()):
            raise ValueError("required content package set is invalid")
    return kind


def rpm_diagnostic_packages(expected: dict[str, Any]) -> list[str]:
    """Bind public diagnostic package names to the admitted media inventory.

    Args:
        expected: Original ISO-derived content expectation.
    """
    if _validate_expected(expected) != "rpm":
        return []
    return sorted(_package_inventory(_decode_inventory(expected["allowed_inventory"])))


def guest_content_program(
    expected: dict[str, Any], *, atlaso_root: str | Path = "/opt/atlaso",
    software_root: str | Path = "/var/lib/atlaso/installation-inspection/software",
    temporary_root: str | Path = "/run", site_root: str | Path | None = None,
) -> str:
    """Adapt existing validators to the receipt-bound guest's private console.

    Args:
        expected: Strict public ISO-bound content expectation.
        atlaso_root: Installed source root; injectable only by isolated fixtures.
        software_root: Retained authenticated software; injectable only by fixtures.
        temporary_root: Ephemeral RAM parent; injectable only by fixtures.
        site_root: Explicit fixture site-packages path; live checks use package metadata.
    """
    kind = _validate_expected(expected)
    # The host has checked these exact package pins above, and prepare binds
    # the installed helper to the supported bytes. Reuse its authenticated
    # constants instead of transmitting duplicate random digests.
    omitted = {"allowed_inventory", "required_packages"}
    if kind == "rpm":
        omitted |= {"filesystem_sha256", "systemd_sha256", "audit_sha256", "rpcbind_sha256", "openssh_sha256", "openldap_sha256", "shim_sha256", "grub_efi_sha256"}
    command_expected = {key: value for key, value in expected.items() if key not in omitted}
    if kind == "rpm":
        # Only the internal console envelope is abbreviated. The host still
        # admits the complete expectation, and checked() authenticates the helper.
        command_expected = {"i": expected["iso_sha256"], "p": expected["package_state_sha256"]}
    imports = ("import base64,hashlib,json,os,re,stat,subprocess,types,zlib\nfrom pathlib import Path\n" if kind == "rpm" else
               "import base64,hashlib,importlib.metadata,json,os,re,shutil,stat,subprocess,tarfile,tempfile,types,zlib\nfrom pathlib import Path,PurePosixPath\n")
    prelude = imports + '''
def read(p,n=16777216):
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 with os.fdopen(fd,"rb") as f:
  z=os.fstat(f.fileno());b=f.read(n+1)
 if not stat.S_ISREG(z.st_mode) or z.st_nlink!=1 or len(b)>n: raise ValueError()
 return b
def checked(rel,key):
 p=a/rel;b=read(p,1048576)
 if hashlib.sha256(b).hexdigest()!=e[key]: raise ValueError()
 return p,b
class CommandError(Exception):
 def __init__(self,result):
  super().__init__();self.result=result

def run(args,timeout=60):
 c=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
 if len(c.stdout)+len(c.stderr)>1048576: raise ValueError()
 if c.returncode: raise CommandError(c)
 return c.stdout
'''
    if kind in {"assets", "python", "rpm"}:
        prelude += '''def load(rel,key,n):
 p,b=checked(rel,key);m=types.ModuleType(n);m.__file__=str(p);exec(compile(b,str(p),"exec"),m.__dict__);return m
'''
    if kind == "assets":
        prelude += '''def digest(d):return hashlib.sha256("".join(k+"\\0"+d[k]+"\\n" for k in sorted(d)).encode()).hexdigest()
'''
    declarations = "e=" + repr(command_expected) + "\na=Path(" + repr(str(atlaso_root)) + ")\n"
    if kind != "rpm":
        declarations += ("s=Path(" + repr(str(software_root)) + ")\nt=Path(" + repr(str(temporary_root)) + ")\nsite_override=" +
                         repr(str(site_root) if site_root is not None else None) + "\nprofile_data=" + repr(PROFILE.encode()) + "\n")
    if kind == "rpm":
        declarations += "paths=" + repr(" ".join(RPM_DIAGNOSTIC_PATHS)) + ".split()\n"
    body = 'stage="system-' + kind + '"\n' + prelude + declarations + _PROGRAMS[kind]
    binding = 'kind="rpm",iso_sha256=e["i"]' if kind == "rpm" else 'kind=e["kind"],iso_sha256=e["iso_sha256"]'
    body += '\nr.update(schema=1,' + binding + ')\nx=json.dumps(r,sort_keys=True,separators=(",",":")).encode()\nif len(x)>4096: raise ValueError()\nprint("ATLASO-INSPECTION:"+base64.b64encode(x).decode()+":END")'
    program = 'try:\n' + textwrap.indent(body, " ") + '\nexcept BaseException:\n print("ATLASO-INSPECTION-FAILED:"+stage)'
    codec = "b85" if kind == "rpm" else "b64"
    compressed = getattr(base64, codec + "encode")(zlib.compress(program.encode(), 9)).decode()
    # Both standard alphabets exclude quotes and backslashes, preserving the
    # existing single POSIX -c argument without increasing its console limit.
    if any(char in compressed for char in "'\"\\\r\n"):
        raise ValueError("content inspection transport is not quote-safe")
    command = "/opt/atlaso/.venv/bin/python -B -I -c 'exec(__import__(\"zlib\").decompress(__import__(\"base64\")." + codec + "decode(\"" + compressed + "\")))'"
    if len(command) > 3500 or not command.isascii():
        raise ValueError("content inspection command exceeds the console bound")
    return command


def validate_content_report(raw: bytes, expected: dict[str, Any]) -> dict[str, Any]:
    """Require all requested checks and reduce output to public measurements.

    Args:
        raw: Bounded JSON recovered from the private guest console.
        expected: Original media-bound expectation for this content kind.
    """
    kind = _validate_expected(expected)
    if not raw or len(raw) > 4096:
        raise ValueError("content report exceeds its bound")
    value = json.loads(raw)
    keys = {
        "assets": {"source_digest", "source_file_count", "deployed_files", "trust_digest", "trust_keys"},
        "python": {"python_payload_sha256", "python_files", "python_distributions", "python_external_files"},
        "powercli": {"powercli_lock_sha256", "module_count"},
        "rpm": {"installed_inventory", "firmware_verified", "rpm_files_verified", "package_state_verified", "runtime_proc_verified", "runtime_run_verified", "runtime_media_directories_absent", "runtime_login_metadata_verified", "runtime_mail_spool_verified", "runtime_journal_metadata_verified", "runtime_audit_metadata_verified", "runtime_rpcbind_metadata_verified", "runtime_openssh_metadata_verified", "runtime_openldap_metadata_verified", "runtime_efi_metadata_verified", "runtime_module_indexes_verified", "runtime_network_databases_verified"},
        "notices": {"notices_sha256", "notice_inputs_verified"},
    }[kind]
    if (not isinstance(value, dict) or set(value) != _COMMON_KEYS | keys or type(value.get("schema")) is not int or value["schema"] != 1
            or value.get("kind") != kind or value.get("iso_sha256") != expected["iso_sha256"]):
        raise ValueError("content report schema or media identity differs")
    for key, field in value.items():
        if (key.endswith("_sha256") or key.endswith("_digest")) and (not isinstance(field, str) or not _DIGEST.fullmatch(field)):
            raise ValueError("content report digest is invalid")
    for key in {"source_file_count", "deployed_files", "trust_keys", "python_files", "python_distributions", "module_count"} & value.keys():
        if type(value[key]) is not int or not 1 <= value[key] <= 100000:
            raise ValueError("content report count is invalid")
    if kind == "python" and (type(value["python_external_files"]) is not int or not 0 <= value["python_external_files"] <= 100000):
        raise ValueError("content external-file count is invalid")
    if kind == "assets" and any(value[key] != expected[key] for key in ("source_digest", "source_file_count", "trust_digest")):
        raise ValueError("installed source or trust differs from media")
    if kind == "assets" and value["trust_keys"] != len(expected["trust_names"]):
        raise ValueError("installed public trust key set differs")
    if kind == "assets" and value["deployed_files"] != expected["deployed_file_count"]:
        raise ValueError("installed shared asset set is incomplete")
    if kind == "powercli" and any(value[key] != expected[key] for key in ("powercli_lock_sha256", "module_count")):
        raise ValueError("installed PowerCLI differs from the original lock")
    if kind == "rpm":
        actual = _package_inventory(_decode_inventory(value["installed_inventory"]))
        allowed = _decode_inventory(expected["allowed_inventory"])
        required = _decode_inventory(expected["required_packages"])
        if not isinstance(allowed, dict) or not isinstance(required, list):
            raise ValueError("content RPM expectation inventory is invalid")
        if not set(required) <= actual.keys():
            raise MissingRequiredRpms([i for i, name in enumerate(required) if name not in actual])
        if any(name not in allowed or identity != allowed[name] for name, identity in actual.items()):
            raise ValueError("installed RPM identity differs from media")
        if any(value[key] is not True for key in ("firmware_verified", "rpm_files_verified", "package_state_verified", "runtime_proc_verified", "runtime_run_verified", "runtime_login_metadata_verified", "runtime_mail_spool_verified", "runtime_journal_metadata_verified", "runtime_audit_metadata_verified", "runtime_rpcbind_metadata_verified", "runtime_openssh_metadata_verified", "runtime_openldap_metadata_verified", "runtime_efi_metadata_verified", "runtime_module_indexes_verified", "runtime_network_databases_verified")):
            raise ValueError("installed RPM native verification is incomplete")
        if type(value["runtime_media_directories_absent"]) is not int or not 0 <= value["runtime_media_directories_absent"] <= 2:
            raise ValueError("installed RPM absent directory count is invalid")
        value = {key: field for key, field in value.items() if key != "installed_inventory"}
        value.update(installed_rpms=len(actual), rpm_inventory_sha256=hashlib.sha256(json.dumps(actual,sort_keys=True,separators=(",", ":")).encode()).hexdigest())
    if kind == "notices" and value["notice_inputs_verified"] is not True:
        raise ValueError("installed notices were not reproduced")
    return value


_PROGRAMS = {
    "python": r'''
stage="system-python-helpers"
v=load("image/common/scripts/verify-template-software.py","software_verifier_sha256","_software")
h=load("scripts/verify_virtualization_guest_wheel.py","environment_verifier_sha256","_wheels")
stage="system-python-software"
software=v.verify(s,e["release_manifest_sha256"],e["version"],e["source_commit"])
stage="system-python-expected"
records,distributions,external=h._expected_installation(s/software["application_wheel"],s/"wheelhouse/cp314",e["wheel_sha256"])
stage="system-python-site"
site=Path(site_override) if site_override is not None else Path(importlib.metadata.distribution("atlaso").locate_file(""))
if site_override is None and site.resolve()!=(a/".venv/lib/python3.14/site-packages").resolve(): raise ValueError()
stage="system-python-scratch"
size=sum(v[1] for v in records.values())
if size>1073741824 or size+67108864>shutil.disk_usage(t).free: raise ValueError()
stage="system-python-archive"
with tempfile.TemporaryDirectory(prefix="atlaso-inspection-",dir=t) as d:
 archive=Path(d)/"site.tar";count=0;total=0
 with tarfile.open(archive,"w") as out:
  for p in sorted(site.rglob("*")):
   z=p.lstat()
   if p.is_symlink() or not(stat.S_ISDIR(z.st_mode) or(stat.S_ISREG(z.st_mode) and z.st_nlink==1)): raise ValueError()
   if p.is_dir(): continue
   count+=1;total+=z.st_size
   if count>100000 or total>1073741824: raise ValueError()
   out.add(p,arcname=p.relative_to(site).as_posix(),recursive=False)
 stage="system-python-files"
 try:
  h._verify_site_packages_archive(archive,records,distributions)
 except SystemExit as failure:
  message=str(failure)
  if message.startswith("guest site-packages contains an unexpected file: "):
   name=message.partition(": ")[2]
   stage="system-python-bytecode" if name.endswith(".pyc") and "__pycache__" in PurePosixPath(name).parts else "system-python-extra"
  elif message.startswith("installed wheel member does not match: "):
   stage="system-python-changed";name=message.partition(": ")[2]
   if name in records: stage+="-"+hashlib.sha256(name.encode("utf-8")).hexdigest()
  elif message.startswith("installed wheel member is missing: "): stage="system-python-missing"
  raise
stage="system-python-external"
venv=site.resolve().parents[2]
interpreters=(str(a/".venv/bin/python"),str(venv/"bin/python"))
for name,record in external.items():
 p=venv/name
 for parent in (p,*p.parents):
  if parent==venv: break
  if parent.is_symlink(): raise ValueError()
 z=p.lstat()
 if z.st_uid or z.st_gid or(name.startswith("bin/") and not z.st_mode&0o111): raise ValueError()
 h._verify_external_payload(read(p),record,interpreters)
r=dict(python_files=len(records),python_distributions=len(distributions),python_external_files=len(external),python_payload_sha256=hashlib.sha256(json.dumps(dict(site=records,external=external),sort_keys=True,separators=(",", ":")).encode()).hexdigest())
''',
    "powercli": r'''
p,b=checked("image/common/powershell/provision-powercli.ps1","powercli_script_sha256")
lp,lb=checked("image/common/powershell/powercli-lock.json","powercli_lock_sha256")
lock=json.loads(lb)
run(["pwsh","-NoLogo","-NoProfile","-NonInteractive","-File",str(p),"-Mode","Validate","-ModuleRoot","/usr/local/share/powershell/Modules","-LockPath",str(lp),"-SuiteVersion",lock["suite_version"]],90)
r=dict(powercli_lock_sha256=hashlib.sha256(lb).hexdigest(),module_count=len(lock["modules"]))
''',
    "rpm": r'''
stage="system-rpm-helper"
h=load("image/common/scripts/verify-photon-package-state.py","p","_rpm_state")
stage="system-rpm-package-state"
run(["/usr/bin/python3","-B",h.__file__,"--guest-platform","none"])
stage="system-rpm-inventory"
rows=run(["rpm","--noplugins","-qa","--qf","%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{ARCH}\\n"]).decode().splitlines()
installed={}
for row in rows:
 fields=row.split("\t")
 if len(fields)!=3: raise ValueError()
 name,version,arch=fields
 if name=="gpg-pubkey": continue
 if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+._:-]{0,127}",name) or name in installed or arch not in {"x86_64","noarch"}: raise ValueError()
 installed[name]=[version,arch]
 if len(installed)>1024: raise ValueError()
stage="system-rpm-runtime"
runtime=h.verify_installation_metadata()
stage="system-rpm-files"
absent=set()
try:
 run(["rpm","--noplugins","-Va","--noscripts","--nodeps","--noconfig","--noghost"],90)
except CommandError as failure:
 lines=failure.result.stdout.decode("utf-8").splitlines()
 bad=[]
 for line in lines:
  if re.fullmatch(r"\.M\.{7}\s+/(?:proc|var/mail|var/log/audit)",line): continue
  if re.fullmatch(r"\.{6}G\.{2}\s+/(?:var/lib/rpcbind|usr/share/empty\.sshd)",line): continue
  if re.fullmatch(r"missing\s+/var/run/openldap",line): continue
  if re.fullmatch(r"\.M\.{5}[T.]\.\s+/boot/efi/EFI/BOOT/(?:bootx64|revocations|grubx64)\.efi",line): continue
  if re.fullmatch(r"\.[M.]\.{4}[G.]\.{2}\s+/var/log/journal",line): continue
  if re.fullmatch(r"[S.][M.][5.]\.{3}[G.][T.]\.\s+(/var/log/(?:btmp|wtmp))",line): continue
  m=re.fullmatch(r"missing\s+(/run/media/(?:cdrom|floppy))",line)
  if m:
   try: Path(m[1]).lstat()
   except FileNotFoundError: absent.add(m[1]);continue
  derived=re.fullmatch(r"[S.]\.[5.]\.{4}[T.]\.\s+(/[^\x00\r\n]+)",line)
  if derived and derived[1] in h.INSTALLATION_MODULE_GENERATED_PATHS: continue
  bad.append(line)
 if failure.result.returncode!=1 or failure.result.stderr or not lines: bad=lines or [""]
 entries=[]
 for line in bad:
  match=re.fullmatch(r"(?:[SM5DLUGTP?.]{9}|missing)\s+(?:[a-z?]\s+)?(/[^\x00\r\n]+)",line)
  if match: entries.append((match[1],line.split()[0]))
  if len(entries)==16: break
 for path,flags in entries:
  owners=run(["rpm","--noplugins","-qf","--qf","%{NAME}\\n",path],3).decode("utf-8").splitlines()
  owners=sorted(owner for owner in set(owners) if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+._:-]{0,127}",owner))
  if owners:
   stage+="-package-"+hashlib.sha256(owners[0].encode("utf-8")).hexdigest()
   if path in paths:
    entry="-entry"+str(paths.index(path))
    try: z=Path(path).lstat()
    except FileNotFoundError: stage+=entry+"-missing"
    else:
     kind="d" if stat.S_ISDIR(z.st_mode) else "l" if stat.S_ISLNK(z.st_mode) else "f" if stat.S_ISREG(z.st_mode) else "o"
     stage+=entry+"-"+kind+format(stat.S_IMODE(z.st_mode),"04o")
    if re.fullmatch(r"[SM5DLUGTP?.]{9}",flags): stage+="-v"+flags
   break
 if bad: raise
stage="system-rpm-runtime"
runtime.update(h.verify_installation_module_indexes())
stage="system-rpm-firmware"
run(["rpm","--noplugins","-V","--noscripts","--nodeps","linux-firmware"],60)
stage="system-rpm-runtime"
runtime=h.verify_installation_metadata()
runtime.update(h.verify_installation_module_indexes())
stage="system-rpm-network-databases"
runtime.update(h.verify_installation_network_databases())
r=dict(installed_inventory=base64.b64encode(zlib.compress(json.dumps(installed,sort_keys=True,separators=(",", ":")).encode(),9)).decode(),firmware_verified=True,rpm_files_verified=True,package_state_verified=True,runtime_media_directories_absent=len(absent),**runtime)
''',
    "assets": r'''
stage="system-assets-profile"
if read(Path("/etc/atlaso/installation-profile"),128)!=profile_data: raise ValueError()
stage="system-assets-helper"
h=load("scripts/verify_virtualization_guest_wheel.py","environment_verifier_sha256","_assets")
stage="system-assets-source"
records={};pending=[a];total=0
skip={"bin","releases","current",".venv","build-info.json"};excluded={".git",".venv",".pytest_cache","data","test-results","__pycache__"}
while pending:
 for p in sorted(pending.pop().iterdir()):
  rel=p.relative_to(a).as_posix();parts=rel.split("/")
  if parts[0] in skip or any(v in excluded for v in parts) or rel.endswith(".pyc"): continue
  if p.is_symlink(): raise ValueError()
  if p.is_dir(): pending.append(p);continue
  b=read(p);total+=len(b);records[rel]=hashlib.sha256(b).hexdigest()
  if len(records)>10000 or total>536870912: raise ValueError()
if len(records)!=e["source_file_count"] or digest(records)!=e["source_digest"]: raise ValueError()
stage="system-assets-powershell-profile"
omit=set(e["omitted_sources"])
profiles=[p for p in h.POWERSHELL_PROFILE_TARGETS if Path(p).exists()]
if len(profiles)!=1 or Path("/usr/bin/pwsh").resolve().parent/"profile.ps1"!=Path(profiles[0]): raise ValueError()
stage="system-assets-deployed"
verified=0
for source,target in {**h.DEPLOYED_TEXT_FILES,**h.DEPLOYED_BINARY_FILES}.items():
 if source in omit:
  if Path(target.replace("/opt-atlaso/",str(a)+"/",1)).exists(): raise ValueError()
  continue
 actual=profiles[0] if source==h.POWERSHELL_PROFILE_SOURCE else target.replace("/opt-atlaso/",str(a)+"/",1)
 b=read(a/source);b=b.replace(b"\r\n",b"\n") if source in h.DEPLOYED_TEXT_FILES else b
 z=Path(actual).lstat()
 if z.st_uid or z.st_gid or stat.S_IMODE(z.st_mode)!=h.DEPLOYED_FILE_MODES[target] or read(Path(actual))!=b: raise ValueError()
 verified+=1
stage="system-assets-trust"
trust=Path("/etc/atlaso/update-trust.d")
if sorted(p.name for p in trust.iterdir())!=e["trust_names"]: raise ValueError()
trusted={}
for name in e["trust_names"]:
 source="image/common/update-trust/"+name;b=read(a/source);p=trust/name;z=p.lstat()
 if z.st_uid or z.st_gid or stat.S_IMODE(z.st_mode)!=420 or read(p)!=b: raise ValueError()
 trusted[source]=hashlib.sha256(b).hexdigest()
r=dict(source_digest=digest(records),source_file_count=len(records),deployed_files=verified,trust_digest=digest(trusted),trust_keys=len(trusted))
''',
    "notices": r'''
stage="system-notices-inputs"
p,b=checked("scripts/generate_third_party_notices.py","notice_generator_sha256")
checked("scripts/third_party_notices.json","notice_config_sha256")
lock=s/"requirements-appliance.lock";lb=read(lock,1048576)
if hashlib.sha256(lb).hexdigest()!=e["notice_lock_sha256"]: raise ValueError()
stage="system-notices-inventory"
inventory=run(["rpm","--noplugins","-qa","--qf","%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{LICENSE}\\t%{URL}\\n"])
with tempfile.TemporaryDirectory(prefix="atlaso-inspection-",dir=t) as d:
 inv=Path(d)/"rpms.tsv";out=Path(d)/"notices.md";inv.write_bytes(b"\n".join(sorted(set(inventory.splitlines())))+b"\n")
 stage="system-notices-generate"
 run(["/opt/atlaso/.venv/bin/python","-B","-I",str(p),"--version",e["version"],"--output",str(out),"--lock",str(lock),"--python-environment",str(a/".venv"),"--rpm-inventory",str(inv)],90)
 stage="system-notices-compare"
 wanted=read(out);actual=read(Path("/usr/share/doc/atlaso/THIRD_PARTY_NOTICES.md"))
 if wanted!=actual: raise ValueError()
r=dict(notices_sha256=hashlib.sha256(actual).hexdigest(),notice_inputs_verified=True)
''',
}
