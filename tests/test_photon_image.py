"""Test photon image behavior."""

import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest


def load_lifecycle_runner():
    """Return lifecycle runner."""
    path = Path("scripts/interop/lifecycle_test.py")
    spec = importlib.util.spec_from_file_location("lifecycle_test", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["lifecycle_test"] = module
    spec.loader.exec_module(module)
    return module


def load_nocloud_seed_helper():
    """Return the NoCloud seed helper module."""
    path = Path("scripts/interop/create_nocloud_seed_iso.py")
    spec = importlib.util.spec_from_file_location("create_nocloud_seed_iso", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha256(path: str) -> str:
    """Return sha256.

    Args:
        path: Filesystem or URL path to read, validate, or update.
    """
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def test_data_disk_policies_remain_lf_in_windows_checkouts(tmp_path: Path) -> None:
    """Materialize shell-sourced image policies with Windows conversion enabled.

    Args:
        tmp_path: Pytest-provided isolated checkout destination.
    """
    policies = (Path("image/common/data-disks.conf"),)
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    completed = subprocess.run(
        [
            "git",
            "-c",
            "core.autocrlf=true",
            "checkout-index",
            "--force",
            f"--prefix={checkout.as_posix()}/",
            "--",
            *(path.as_posix() for path in policies),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    for policy in policies:
        materialized = (checkout / policy).read_bytes()
        assert materialized.endswith(b"\n")
        assert b"\r" not in materialized


def test_photon_image_installs_fixed_size_atlaso_grub_branding():
    """Verify that photon image installs fixed size atlaso grub branding."""
    background = Path("image/common/boot/grub/atlaso.png").read_bytes()
    photon_logo = Path("image/common/boot/grub/photon-os-logo.png").read_bytes()
    theme = Path("image/common/boot/grub/theme.txt").read_text(encoding="utf-8")
    installer = Path("scripts/appliance/atlaso-install-boot-branding").read_text(encoding="utf-8")
    provision = Path("image/common/scripts/provision-atlaso.sh").read_text(encoding="utf-8")
    deploy = Path("scripts/windows/vmware/deploy-wheel.ps1").read_text(encoding="utf-8")

    assert background[:8] == b"\x89PNG\r\n\x1a\n"
    assert struct.unpack(">II", background[16:24]) == (640, 480)
    assert photon_logo[:8] == b"\x89PNG\r\n\x1a\n"
    assert 'desktop-image: "atlaso.png"' in theme
    assert "Powered by Photon OS" not in theme  # Copy is rendered into the fixed background.
    assert "set theme=/grub2/themes/atlaso/theme.txt" in installer
    assert 'menuentry " "' in installer
    assert "atlaso-backup" in installer
    assert '"$ATLASO_HOME/bin/atlaso-install-boot-branding"' in provision
    assert "SkipBootBrandingSync" in deploy
    assert "/opt/atlaso/bin/atlaso-install-boot-branding" in deploy
    assert '"${SshUser}@${IpAddress}:$remoteBootThemePath"' in deploy
    assert '"${SshUser}@${IpAddress}:$remoteBootBackgroundPath"' in deploy


def test_offline_guest_agent_staging_remains_root_owned_after_provisioning() -> None:
    """The final state ownership pass must prune the persistent RPM trust boundary."""

    provision = Path("image/common/scripts/provision-atlaso.sh").read_text(encoding="utf-8")
    staging = provision.index('GUEST_AGENT_STAGING="$ATLASO_STATE/first-boot-packages"')
    root_ownership = provision.index(
        'find "$GUEST_AGENT_STAGING" -type d -exec chown root:root {} + -exec chmod 0700 {} +'
    )
    pruned_state_ownership = provision.index(
        'find "$ATLASO_STATE" -path "$GUEST_AGENT_STAGING" -prune -o -exec chown atlaso:atlaso {} +'
    )
    assert staging < root_ownership < pruned_state_ownership
    assert 'chown -R atlaso:atlaso "$ATLASO_STATE"' not in provision
    notice_inventory = provision.index(
        'find "$GUEST_AGENT_STAGING" -type f -name \'*.rpm\' | LC_ALL=C sort'
    )
    notice_generation = provision.index('"$ATLASO_HOME/scripts/generate_third_party_notices.py"')
    assert root_ownership < notice_inventory < notice_generation
    assert "rpm -qp --qf" in provision


def test_vmware_template_scrubs_credentials_and_host_identity() -> None:
    """The exported template cannot retain deployment credentials or SSH identity."""

    provision = Path("image/common/scripts/provision-atlaso.sh").read_text(encoding="utf-8")
    assert '"ATLASO_SECRET_KEY": "INITIALIZATION_REQUIRED"' in provision
    assert 'usermod --password \'!\' "$BOOTSTRAP_USERNAME"' in provision
    identity_scrub = "rm -f /etc/ssh/ssh_host_* /etc/machine-id"
    assert provision.count(identity_scrub) == 2
    final_update = provision.index('run_tdnf "Final Photon OS update verification" update')
    final_scrub = provision.rindex(identity_scrub)
    zero_fill = provision.index('zero_fill_free_space / "Photon OS filesystem"')
    assert final_update < final_scrub < zero_fill
    assert "find /etc/ssh -maxdepth 1 -type f -name 'ssh_host_*'" in provision
    assert '|| [ -e /etc/machine-id ] || [ -e /var/lib/dbus/machine-id ]' in provision
    assert "Final Photon update left reusable host identity material" in provision
    assert "guestinfo.atlaso.template_ssh_host_ed25519_public_key" not in provision


def test_every_virtualenv_systemd_unit_disables_generated_bytecode() -> None:
    """Root and service-account units cannot recreate active package bytecode."""

    unit_roots = (
        Path("image/common/systemd"),
        Path("image/vmware-workstation/systemd"),
    )
    virtualenv_units = []
    for root in unit_roots:
        for path in root.glob("*.service"):
            source = path.read_text(encoding="utf-8")
            if "/opt/atlaso/.venv/" in source:
                virtualenv_units.append((path, source))
    assert virtualenv_units
    for path, source in virtualenv_units:
        assert "Environment=PYTHONDONTWRITEBYTECODE=1" in source, path


def test_guest_agent_success_marker_makes_cleanup_retryable() -> None:
    """Commit provider success before erasure and retry an interrupted cleanup."""

    selector = Path("scripts/appliance/atlaso-select-guest-agent").read_text(encoding="utf-8")
    provision = Path("image/common/scripts/provision-atlaso.sh").read_text(encoding="utf-8")
    existing_marker = selector.index('if [ -f "$SUCCESS_MARKER" ]; then')
    retry_cleanup = selector.index("cleanup_staging", existing_marker)
    already_completed = selector.index('log "Guest-agent selection already completed."', existing_marker)
    publish_marker = selector.rindex('mv -f -- "$marker_tmp" "$SUCCESS_MARKER"')
    assert 'stat -c \'%U:%G:%a\' "$marker_parent"' in selector
    assert "success marker parent ownership or mode is unsafe" in selector
    assert (
        "install -d -o root -g root -m 0700 "
        "/var/lib/atlaso-privileged/guest-agent"
    ) in provision
    final_cleanup = selector.rindex("cleanup_staging")

    assert retry_cleanup < already_completed
    assert publish_marker < final_cleanup
    assert 'PACKAGE_CACHE_DIRECTORY="${ATLASO_GUEST_AGENT_PACKAGE_CACHE:-/var/cache/tdnf}"' in selector
    assert 'if [ "$cleanup_required" -eq 1 ]; then' in selector


def test_inventory_linux_release_package_is_reproducible_and_deployable(tmp_path):
    """Verify that inventory linux release package is reproducible and deployable.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    path = Path("scripts/build_inventory_linux_package.py")
    spec = importlib.util.spec_from_file_location("build_inventory_linux_package", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    source = tmp_path / "source"
    (source / "legal-info").mkdir(parents=True)
    kernel = b"kernel"
    initrd = b"initrd"
    (source / "bzImage").write_bytes(kernel)
    (source / "rootfs.cpio.gz").write_bytes(initrd)
    (source / "legal-info/LICENSE").write_text("license\n", encoding="utf-8")
    (source / "manifest.json").write_text(
        json.dumps(
            {
                "kind": "atlaso-inventory-linux",
                "schema_version": 1,
                "version": "2026.05.1+8",
                "artifacts": {
                    "bzImage": hashlib.sha256(kernel).hexdigest(),
                    "rootfs.cpio.gz": hashlib.sha256(initrd).hexdigest(),
                },
            }
        ),
        encoding="utf-8",
    )
    first = module.package_inventory_linux(source, tmp_path / "first")
    second = module.package_inventory_linux(source, tmp_path / "second")
    assert hashlib.sha256(first.read_bytes()).digest() == hashlib.sha256(second.read_bytes()).digest()
    with zipfile.ZipFile(first) as package:
        assert {"manifest.json", "bzImage", "rootfs.cpio.gz", "legal-info/LICENSE"} <= set(package.namelist())

    deploy = Path("scripts/windows/vmware/deploy-wheel.ps1").read_text(encoding="utf-8")
    release = Path(".github/workflows/release.yml").read_text(encoding="utf-8")
    assert "SkipInventoryLinuxSync" in deploy
    assert "[AllowEmptyString()][string[]]$Arguments" in deploy
    assert "Installed Atlaso Inventory Linux" in deploy
    assert (
        "install -d -o atlaso -g atlaso -m 0755 "
        "/var/lib/atlaso/pxe/media /var/lib/atlaso/pxe/uploads"
    ) in deploy
    restore_trap = deploy.index("trap restore_services_on_exit EXIT")
    stop_writers = deploy.index("systemctl stop atlaso-worker.service atlaso.service")
    media_preflight = deploy.index("Atlaso media path must not be a symlink")
    media_install = deploy.index(
        "install -d -o atlaso -g atlaso -m 0755 "
        "/var/lib/atlaso/pxe/media /var/lib/atlaso/pxe/uploads"
    )
    inventory_install = deploy.index(
        'if [ -n "$inventory_linux_package" ]; then'
    )
    disarm_trap = deploy.rindex("trap - EXIT")
    worker_active = deploy.index("systemctl is-active atlaso-worker.service")
    readiness_complete = deploy.index(
        'echo "Atlaso service restarted and loopback OpenAPI is reachable."'
    )
    assert restore_trap < stop_writers < media_preflight < media_install < inventory_install
    assert worker_active < disarm_trap < readiness_complete
    assert 'if [ "$atlaso_was_active" = "true" ]; then' in deploy
    assert 'if [ "$worker_was_active" = "true" ]; then' in deploy
    assert "systemctl stop atlaso.service" in deploy
    assert "systemctl stop atlaso-worker.service" in deploy
    assert 'install -o root -g root -m 0644 "$atlaso_service_path" /etc/systemd/system/atlaso.service' in deploy
    assert "target.parent.is_symlink()" in deploy
    assert "target.is_symlink()" in deploy
    assert "installed_artifact.is_symlink()" in deploy
    assert "installed_manifest_path.is_symlink()" in deploy
    assert 'target / name for name in ("bzImage", "rootfs.cpio.gz", "manifest.json")' in deploy
    assert "owned_path.is_symlink()" in deploy
    assert "follow_symlinks=False" in deploy
    assert 'target.rglob("*")' not in deploy
    provision = Path("image/common/scripts/provision-atlaso.sh").read_text(
        encoding="utf-8"
    )
    assert "INVENTORY_SOURCE_DIR" not in provision
    assert "staging bundled Atlaso Inventory Linux" not in provision
    assert "command -v gpg" in deploy
    assert "tdnf -y install gnupg" in deploy
    inventory_release = Path(
        ".github/workflows/inventory-linux-release.yml"
    ).read_text(encoding="utf-8")
    assert "Build Inventory Linux package" not in release
    assert "--inventory-package" not in release
    assert "Build reproducible Inventory Linux package" in inventory_release
    assert "build_inventory_linux_release.py" in inventory_release
    build = Path("image/inventory-linux/build.sh").read_text(encoding="utf-8")
    assert 'buildroot_version="2026.05.1"' in build
    assert 'package_version="2026.05.1+8"' in build
    assert "vga=791" in build
    assert "video=efifb:1024x768" in build
    assert "fbcon=font:VGA8x16" in build
    assert 'git --git-dir="${git_dir}" --work-tree="${repo_root}"' in build
    assert 'git_dir="/mnt/${git_drive}/${git_tail}"' in build
    assert '"version": "${package_version}"' in build
    assert (
        '"arguments": "rdinit=/sbin/init console=tty0 quiet loglevel=3 logo.nologo '
        'vt.global_cursor_default=0 vga=791 video=efifb:1024x768 fbcon=font:VGA8x16 '
        'atlaso.inventory=1"' in build
    )
    assert '"${source_root}/output/target/usr/bin/lscpu"' in build
    assert '"${source_root}/output/target/bin/lsblk"' in build
    assert '"${source_root}/output/target/usr/bin/lspci"' in build
    assert '"${source_root}/output/target/usr/share/pci.ids.gz"' in build
    assert "Required pci.ids metadata is missing" in build
    assert "Required util-linux tool is missing" in build
    assert "Required util-linux tool resolves to BusyBox" in build
    assert 'metadata_probe="${output_dir}/.atlaso-metadata-probe.$$"' in build
    assert 'chmod 0600 "${metadata_probe}" 2>/dev/null' in build
    assert 'touch -r "${source_root}/output/images/bzImage"' in build
    assert 'if [[ "${output_supports_posix_metadata}" == "1" ]]' in build
    assert 'cp "${source_root}/output/images/bzImage"' in build
    assert 'cp "${source_root}/output/images/rootfs.cpio.gz"' in build
    assert 'rsync -r --delete "${source_root}/output/legal-info/"' in build
    inventory_defconfig = Path(
        "image/inventory-linux/external/configs/atlaso_inventory_x86_64_defconfig"
    ).read_text(encoding="utf-8")
    assert "BR2_PACKAGE_UTIL_LINUX_BINARIES=y" in inventory_defconfig
    assert "BR2_PACKAGE_PCIUTILS=y" in inventory_defconfig
    assert (
        'BR2_PACKAGE_BUSYBOX_CONFIG_FRAGMENT_FILES="$(BR2_EXTERNAL_ATLASO_INVENTORY_PATH)'
        '/board/atlaso-inventory/busybox.fragment"' in inventory_defconfig
    )
    assert "BR2_PACKAGE_UTIL_LINUX_LSCPU" not in inventory_defconfig
    assert "BR2_PACKAGE_UTIL_LINUX_LSBLK" not in inventory_defconfig
    busybox_fragment = Path(
        "image/inventory-linux/external/board/atlaso-inventory/busybox.fragment"
    ).read_text(encoding="utf-8")
    assert "# CONFIG_LSBLK is not set" in busybox_fragment
    assert "CONFIG_OD=y" in busybox_fragment
    inventory_client = Path(
        "image/inventory-linux/external/overlay/usr/bin/atlaso-inventory"
    ).read_text(encoding="utf-8")
    inventory_library = Path(
        "image/inventory-linux/external/overlay/usr/lib/atlaso-inventory-lib.sh"
    ).read_text(encoding="utf-8")
    assert "optional_ethernet_mac()" in inventory_library
    assert "grep -Eq '^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$'" in inventory_library
    assert 'current_mac="$(optional_ethernet_mac ' in inventory_library
    assert 'permanent_mac="$(optional_ethernet_mac ' in inventory_library
    assert "schema_version: 2" in inventory_client
    assert "collect_pci_devices" in inventory_client
    assert "collect_usb_devices" in inventory_client
    assert '"${SYSFS_ROOT}"/firmware/dmi/entries/17-*' in inventory_library
    assert 'tolower($1) == tolower(expected)' in inventory_library
    assert "remaining=300" in inventory_client
    assert "read -r -s -n 1 -t 1 key" in inventory_client
    assert "render_inventory_console" in inventory_client
    assert "refresh_inventory_console_footer" in inventory_client
    assert "FRAMEBUFFER_ROOT" in inventory_library
    assert "| gsub(" not in inventory_library
    assert "\\033]P6dbeafe" in inventory_library
    assert "\\033]P7eef2f7" in inventory_library
    assert "\\033[46m" in inventory_library
    assert "\\033[47m" in inventory_library
    assert "\\033[44m" in inventory_library
    kernel_fragment = Path(
        "image/inventory-linux/external/board/atlaso-inventory/linux.fragment"
    ).read_text(encoding="utf-8")
    for driver in (
        "CONFIG_VMXNET3=y",
        "CONFIG_VMWARE_PVSCSI=y",
        "CONFIG_FUSION_SPI=y",
        "CONFIG_HYPERV_NET=y",
        "CONFIG_HYPERV_STORAGE=y",
        "CONFIG_VIRTIO_NET=y",
        "CONFIG_VIRTIO_BLK=y",
        "CONFIG_SCSI_VIRTIO=y",
        "CONFIG_HYPERVISOR_GUEST=y",
        "CONFIG_HYPERV=y",
        "CONFIG_XEN_NETDEV_FRONTEND=y",
        "CONFIG_XEN_BLKDEV_FRONTEND=y",
        "CONFIG_BNXT=y",
        "CONFIG_QEDE=y",
        "CONFIG_BE2NET=y",
        "CONFIG_ENIC=y",
        "CONFIG_CHELSIO_T4=y",
        "CONFIG_USB_RTL8152=y",
        "CONFIG_MEGARAID_SAS=y",
        "CONFIG_SCSI_HPSA=y",
        "CONFIG_SCSI_LPFC=y",
        "CONFIG_SCSI_QLA_FC=y",
    ):
        assert driver in kernel_fragment
    assert "CONFIG_DRM_SIMPLEDRM=y" in kernel_fragment
    assert "CONFIG_DMI_SYSFS=y" in kernel_fragment
    assert "CONFIG_SYSFB_SIMPLEFB=y" in kernel_fragment
    assert "CONFIG_FRAMEBUFFER_CONSOLE=y" in kernel_fragment
    assert "# CONFIG_LOGO is not set" in kernel_fragment
    inventory_defconfig = Path(
        "image/inventory-linux/external/configs/atlaso_inventory_x86_64_defconfig"
    ).read_text(encoding="utf-8")
    for firmware in (
        "BR2_PACKAGE_LINUX_FIRMWARE_BNX2=y",
        "BR2_PACKAGE_LINUX_FIRMWARE_BNX2X=y",
        "BR2_PACKAGE_LINUX_FIRMWARE_INTEL_ICE=y",
        "BR2_PACKAGE_LINUX_FIRMWARE_QLOGIC_4X=y",
        "BR2_PACKAGE_LINUX_FIRMWARE_QLOGIC_2XXX=y",
        "BR2_PACKAGE_LINUX_FIRMWARE_RTL_8169=y",
    ):
        assert firmware in inventory_defconfig
    init = Path(
        "image/inventory-linux/external/overlay/etc/init.d/S99atlaso-inventory"
    ).read_text(encoding="utf-8")
    assert "atlaso.boot_mac=*" in init
    assert 'candidate_mac="$(cat "${candidate_path}/address"' in init
    assert 'udhcpc -i "${candidate}"' in init
    assert 'grep -q " dev ${candidate}' in init
    assert "for candidate_path in /sys/class/net/*" in init
    assert init.index("udhcpc -i") < init.index("/usr/bin/atlaso-inventory")
    assert "fbsplash -c -d /dev/fb0 -s /usr/share/atlaso/inventory-splash.ppm" in init
    splash = Path(
        "image/inventory-linux/external/overlay/usr/share/atlaso/inventory-splash.ppm"
    )
    assert splash.read_bytes().startswith(b"P6\n640 480\n255\n")
    assert "CONFIG_FBSPLASH=y" in busybox_fragment
    assert "CONFIG_FBSET=y" in busybox_fragment
    assert "CONFIG_DRM_HYPERV=y" in kernel_fragment
    assert 'installed_manifest.get("kind") != "atlaso-network-boot-media"' in deploy
    assert 'installed_manifest.get("environment") != "inventory"' in deploy


def test_windows_inventory_linux_build_selects_one_distribution_and_native_cache():
    """Verify that windows inventory linux build selects one distribution and native cache."""
    wrapper = Path("scripts/windows/common/Build-AtlasoInventoryLinux.ps1").read_text(
        encoding="utf-8"
    )
    module = Path("scripts/windows/common/Atlaso.WslBuild.psm1").read_text(
        encoding="utf-8"
    )

    linux_path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    assert "[string]$WslDistribution = 'Atlaso-Build'" in wrapper
    assert "Assert-AtlasoWslBuildEnvironment" in wrapper
    assert "@('--distribution', $WslDistribution)" in wrapper
    assert "-Distribution $WslDistribution" in wrapper
    assert f"$linuxPath = '{linux_path}'" in wrapper
    assert '${XDG_CACHE_HOME:-$HOME/.cache}/atlaso/inventory-linux' in module
    assert "[System.Security.Cryptography.SHA256]::HashData" in wrapper
    assert '"ATLASO_INVENTORY_BUILD_ROOT=$linuxBuildRoot"' in wrapper
    assert 'exec flock --exclusive "$2" bash "$3"' in wrapper
    assert '"$linuxBuildRoot.lock"' in wrapper
    assert '"Global\\Atlaso.InventoryLinux.$repositoryKey"' in wrapper
    assert "$checkoutMutex.WaitOne()" in wrapper
    assert wrapper.index("$checkoutMutex.WaitOne()") < wrapper.index("& $wsl @wslArguments")
    assert wrapper.index("Buildroot legal-info") < wrapper.index("$checkoutMutex.ReleaseMutex()")
    assert 'Buildroot must run as a non-root WSL user.' in module
    assert 'cache storage is not case-sensitive' in module
    assert "wsl.exe --exec bash $linuxScript" not in wrapper


def test_wsl_build_state_errors_are_non_mutating_and_actionable():
    """Verify that wsl build state errors are non mutating and actionable."""
    module = Path("scripts/windows/common/Atlaso.WslBuild.psm1").read_text(
        encoding="utf-8"
    )

    assert "WSL is required for Atlaso image builds" in module
    assert "WSL is installed but unavailable or incomplete" in module
    assert "no Linux distributions are installed" in module
    assert "is not installed. Provision it explicitly with" in module
    assert "wsl --list --verbose" in module
    assert "wsl --terminate $Distribution" in module
    assert "Enable-WindowsOptionalFeature" not in module
    assert "--import" not in module
    assert "--unregister" not in module


def test_wsl_build_module_behavior():
    """Verify that wsl build module behavior."""
    pwsh = shutil.which("pwsh")
    if pwsh is None:
        pytest.skip("PowerShell 7 is not available")

    result = subprocess.run(
        [
            pwsh,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            "tests/powershell/Test-AtlasoWslBuild.ps1",
            "-RepositoryRoot",
            str(Path.cwd()),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Atlaso WSL build module behavior tests passed." in result.stdout


def test_photon_kickstart_generator_is_canonical_and_provider_specific(tmp_path):
    """Verify the canonical portable Photon kickstart contract.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    pwsh = shutil.which("pwsh")
    if pwsh is None:
        pytest.skip("PowerShell 7 is required")

    result = subprocess.run(
        [
            pwsh,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            "tests/powershell/Test-AtlasoPhotonImage.ps1",
            "-RepositoryRoot",
            str(Path.cwd()),
            "-OutputDirectory",
            str(tmp_path / "photon-kickstart"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Atlaso Photon kickstart generator contract tests passed." in result.stdout

    output_dir = tmp_path / "photon-kickstart"
    generated = {
        "vmware-workstation": json.loads(
            (output_dir / "vmware-workstation-kickstart.json").read_text(encoding="utf-8")
        )
    }
    for kickstart in generated.values():
        assert kickstart["bootmode"] == "efi"
        assert kickstart["packagelist_file"] == "packages_minimal.json"
        assert kickstart["partitions"] == [
            {"mountpoint": "/", "size": 0, "filesystem": "ext4"},
            {"mountpoint": "/boot", "size": 256, "filesystem": "ext4"},
            {"size": 1024, "filesystem": "swap"},
        ]
        packages = set(kickstart["additional_packages"])
        assert {"openssh-server", "shadow", "sudo", "systemd"} <= packages
        postinstall = kickstart["postinstall"]
        assert postinstall[0] == "#!/bin/sh"
        assert "useradd -m -G sudo -s /bin/bash atlaso-build || true" in postinstall
        assert "systemctl disable sshd.socket" in postinstall
        assert "systemctl enable sshd.service" in postinstall
        assert "systemctl enable sshd" not in postinstall
        assert postinstall.index("systemctl disable sshd.socket") < postinstall.index(
            "systemctl enable sshd.service"
        )
        assert (
            "echo 'atlaso-build ALL=(ALL) NOPASSWD:ALL' "
            ">/etc/sudoers.d/90-atlaso-build"
        ) in postinstall
        assert "chmod 0440 /etc/sudoers.d/90-atlaso-build" in postinstall

    vmware = generated["vmware-workstation"]
    assert vmware["disk"] == "$ATLASO_PHOTON_INSTALL_DISK"
    vmware_preinstall = "\n".join(vmware["preinstall"])
    assert "scsi-0:0:0:0" in vmware_preinstall
    assert '"$disk_count" -ne 1' in vmware_preinstall
    assert "/dev/sda" not in vmware_preinstall
    assert "open-vm-tools" in vmware["additional_packages"]
    assert "hyper-v" in vmware["additional_packages"]
    assert "systemctl enable vmtoolsd || true" in vmware["postinstall"]
    assert "systemctl enable hv_kvp_daemon || true" in vmware["postinstall"]

    module = Path("scripts/windows/common/Atlaso.PhotonImage.psm1").read_text(
        encoding="utf-8"
    )
    assert "New-AtlasoPhotonKickstart" in module
    assert "-AdditionalPackages $GuestPackages" in module
    assert "-PostInstallCommands $GuestPostInstallCommands" in module
    assert "ConvertTo-AtlasoUtf8Base64" in module
    assert "| base64 -d | chpasswd" in module
    assert '"printf \'%s:%s\\n\' \'$BuildUsername\' \'$BuildPassword\' | chpasswd"' not in module

    wrappers = {
        "vmware-workstation": Path("scripts/windows/vmware/build-photon-image.ps1").read_text(encoding="utf-8")
    }
    for wrapper in wrappers.values():
        assert "Invoke-AtlasoPhotonImageBuild" in wrapper
        assert "-SshPassword $SshPassword" in wrapper
    assert "-GuestPackages @('open-vm-tools', 'hyper-v')" in wrappers["vmware-workstation"]
    assert "systemctl enable hv_kvp_daemon || true" in wrappers["vmware-workstation"]

    for template_path in (Path("image/vmware-workstation/atlaso-photon.pkr.hcl"),):
        template = template_path.read_text(encoding="utf-8")
        assert "templatefile(" not in template
        assert 'ssh_password_stdin_base64    = base64encode("${var.ssh_password}\\n")' in template
        assert template.count("${local.ssh_password_stdin_base64}") == 2
        assert "echo '${var.ssh_password}'" not in template
        assert "systemd-run --quiet --unit=atlaso-image-build-finalize" in template
        assert "/opt/atlaso/bin/atlaso-finalize-image-build ${var.ssh_username}" in template
        assert "/usr/local/sbin/atlaso-finalize-image-build" not in template
        assert "userdel -r ${var.ssh_username}" not in template
        assert "| base64 -d | sudo -S -E sh -c" in template

    finalizer = Path("image/common/scripts/finalize-image-build.sh").read_text(encoding="utf-8")
    uid_capture = finalizer.index('build_uid=$(printf')
    root_identity_guard = finalizer.index('[ "$build_uid" -ne 0 ]', uid_capture)
    process_wait = finalizer.index('while pgrep -u "$build_uid"', root_identity_guard)
    graceful_termination = finalizer.index('pkill -TERM -u "$build_uid"', process_wait)
    forced_termination = finalizer.index('pkill -KILL -u "$build_uid"', graceful_termination)
    user_deletion = finalizer.index('userdel -r "$build_user"')
    account_verification = finalizer.index('if getent passwd "$build_user"', user_deletion)
    home_verification = finalizer.index('[ ! -e "$build_home" ]', account_verification)
    sudoers_verification = finalizer.index("[ ! -e /etc/sudoers.d/90-atlaso-build ]", home_verification)
    helper_removal = finalizer.index(
        "rm -f -- /opt/atlaso/image/common/scripts/finalize-image-build.sh "
        "/opt/atlaso/bin/atlaso-finalize-image-build"
    )
    poweroff = finalizer.index("systemctl poweroff")
    assert uid_capture < root_identity_guard < process_wait < graceful_termination < forced_termination
    assert forced_termination < user_deletion < account_verification < home_verification < sudoers_verification
    assert sudoers_verification < helper_removal < poweroff
    assert "[ \"$attempt\" -le 40 ]" in finalizer
    assert 'if [ "$attempt" -le 30 ]' in finalizer
    assert "[ ! -e /opt/atlaso/bin/atlaso-finalize-image-build ] || exit 2" in finalizer
    assert "/usr/local/sbin/atlaso-finalize-image-build" not in finalizer

    provision = Path("image/common/scripts/provision-atlaso.sh").read_text(encoding="utf-8")
    assert 'install -o root -g root -m 0700 "$IMAGE_BUILD_FINALIZER_SOURCE"' in provision
    assert '"$ATLASO_HOME/bin/atlaso-finalize-image-build"' in provision
    assert "/usr/local/sbin/atlaso-finalize-image-build" not in provision


def test_vmware_workstation_build_monitor_behavior(tmp_path):
    """Verify bounded sanitized monitoring across VMware builder startup phases.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated process evidence.
    """
    pwsh = shutil.which("pwsh")
    if pwsh is None:
        pytest.skip("PowerShell 7 is not available")

    result = subprocess.run(
        [
            pwsh,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            "tests/powershell/Test-AtlasoWorkstationBuildMonitor.ps1",
            "-RepositoryRoot",
            str(Path.cwd()),
            "-OutputDirectory",
            str(tmp_path / "vmware-build-monitor"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "Atlaso VMware Workstation build monitor tests passed." in result.stdout
    assert "generated-vnc-test-secret" not in result.stdout
    assert "generated-vnc-test-secret" not in result.stderr


def test_vmware_workstation_address_readiness_behavior(tmp_path):
    """Verify duplicate static addresses and wrong host neighbors fail closed.

    Args:
        tmp_path: Temporary directory provided by pytest for synthetic VMX evidence.
    """
    pwsh = shutil.which("pwsh")
    if pwsh is None:
        pytest.skip("PowerShell 7 is not available")

    result = subprocess.run(
        [
            pwsh,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            "tests/powershell/Test-AtlasoWorkstationReadiness.ps1",
            "-RepositoryRoot",
            str(Path.cwd()),
            "-OutputDirectory",
            str(tmp_path / "vmware-readiness"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "Atlaso VMware Workstation readiness tests passed." in result.stdout


def test_wsl_build_contract_and_setup_are_pinned_idempotent_and_non_destructive():
    """Verify that wsl build contract and setup are pinned idempotent and non destructive."""
    contract = json.loads(
        Path("image/inventory-linux/wsl-build-contract.json").read_text(
            encoding="utf-8"
        )
    )
    setup = Path(
        "scripts/windows/common/Initialize-AtlasoBuildWslDistribution.ps1"
    ).read_text(encoding="utf-8")
    provision = Path(
        "image/inventory-linux/provision-wsl-build-host.sh"
    ).read_text(encoding="utf-8")

    assert contract["distribution_name"] == "Atlaso-Build"
    assert contract["build_user"] == "atlaso-build"
    assert contract["base"] == {
        "name": "Ubuntu Base 24.04.4",
        "architecture": "amd64",
        "filename": "ubuntu-base-24.04.4-base-amd64.tar.gz",
        "import_filename": "ubuntu-base-24.04.4-base-amd64.tar",
        "url": "https://cdimages.ubuntu.com/ubuntu-base/releases/24.04/release/ubuntu-base-24.04.4-base-amd64.tar.gz",
        "sha256": "c1e67ef7b17a6300e136118bd1dc04725009cb376c1aad10abcf8cd453628d58",
    }
    for command in ("bash", "flock", "make", "rsync", "sha256sum", "tar"):
        assert command in contract["required_commands"]

    assert "[System.IO.Compression.GZipStream]" in setup
    assert "--import $distribution $InstallLocation $importArchivePath --version 2" in setup
    assert "Remove-Item -LiteralPath $importArchivePath -Force" in setup
    assert "Get-FileHash" in setup
    assert "Get-AtlasoWslDefaultDistribution" in setup
    assert "--set-default $defaultBefore" in setup
    assert "$importSucceeded" in setup
    assert "} finally {\n        if ($importSucceeded" in setup
    assert setup.index("$importSucceeded = $true") < setup.index("$ownershipScript")
    assert setup.index("$ownershipScript") < setup.index("if ($importSucceeded")
    assert "Default-distribution restoration also failed" in setup
    assert "no default could be identified" in setup
    assert "/var/lib/atlaso-build/ownership.json" in setup
    assert setup.index("/var/lib/atlaso-build/ownership.json") < setup.index(
        "--set-default $defaultBefore"
    )
    assert "already exists without an Atlaso ownership marker" in setup
    assert "--unregister" not in setup
    assert "Enable-WindowsOptionalFeature" not in setup
    assert "Start-Process" not in setup
    assert "apt-get install -y --no-install-recommends" in provision
    assert "if ! id -u" in provision
    assert "/var/lib/atlaso-build/contract.json" in provision


def test_photon_wrappers_do_not_build_inventory_linux():
    """Verify that photon wrappers do not build inventory linux."""
    for path in ("scripts/windows/vmware/build-photon-image.ps1",):
        wrapper = Path(path).read_text(encoding="utf-8")
        assert "WslDistribution" not in wrapper
        assert "Build-AtlasoInventoryLinux.ps1" not in wrapper


def test_inventory_linux_retries_uncertain_reboot_acknowledgments():
    """Verify that inventory linux retries uncertain reboot acknowledgments."""
    client = Path(
        "image/inventory-linux/external/overlay/usr/bin/atlaso-inventory"
    ).read_text(encoding="utf-8")

    assert 'pending_reboot_id=""' in client
    assert 'pending_reboot_id="${command_id}"' in client
    assert "acknowledge_remote_reboot" in client
    assert client.index("acknowledge_remote_reboot") < client.index("reboot -f", client.index("acknowledge_remote_reboot"))


def test_inventory_linux_shell_hardware_console_and_reboot_fixtures():
    """Verify that inventory linux shell hardware console and reboot fixtures."""
    if os.name == "nt":
        return
    completed = subprocess.run(
        [
            "sh",
            "tests/shell/test_inventory_linux.sh",
            "image/inventory-linux/external/overlay/usr/lib/atlaso-inventory-lib.sh",
            "image/inventory-linux/external/overlay/usr/bin/atlaso-inventory",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_inventory_linux_retries_capacity_responses_with_bounded_backoff():
    """Verify that inventory linux retries capacity responses with bounded backoff."""
    client = Path(
        "image/inventory-linux/external/overlay/usr/bin/atlaso-inventory"
    ).read_text(encoding="utf-8")

    assert "--write-out '%{http_code}'" in client
    assert '[ "${report_status}" != "503" ]' in client
    assert '[ "${report_attempt}" -ge 6 ]' in client
    assert "sleep $((report_attempt * 2))" in client
    assert "response body" not in client


def test_photon_provisioning_management_network_matches_eth0_only():
    """Verify that photon provisioning management network matches eth0 only."""
    script = Path("image/common/scripts/provision-atlaso.sh").read_text(encoding="utf-8")
    main = Path("atlaso/app/main.py").read_text(encoding="utf-8")
    seed = Path("atlaso/app/seed.py").read_text(encoding="utf-8")

    assert 'ATLASO_MGMT_INTERFACE="${ATLASO_MGMT_INTERFACE:-eth0}"' in script
    assert 'printf \'Name=%s\\n\\n\' "$ATLASO_MGMT_INTERFACE"' in script
    assert "Name=eth* en*" not in script
    assert "rm -f /etc/systemd/network/50-static-en.network /etc/systemd/network/99-dhcp-en.network" in script
    assert "seed_initial_data(db, include_examples=not appliance_mode, appliance_mode=appliance_mode)" in main
    assert "ensure_ca_state(db)" in main
    assert main.index("refresh_startup_host_inventory(db, environment=settings.environment)") < main.index("ensure_ca_state(db)")
    assert "if include_examples:" in seed
    assert "management_https_enabled=False if factory_defaults else appliance_mode" in seed
    assert 'install -d -o atlaso -g atlaso -m 0700 "$ATLASO_STATE/vcfDownloadTool/active-tool/secrets"' in script


def test_photon_provisioning_installs_default_nginx_management_proxy():
    """Verify that photon provisioning installs default nginx management proxy."""
    script = Path("image/common/scripts/provision-atlaso.sh").read_text(encoding="utf-8")
    bootstrap = Path("scripts/appliance/atlaso-bootstrap-https").read_text(encoding="utf-8")
    systemd_unit = Path("image/common/systemd/atlaso.service").read_text(encoding="utf-8")
    worker_unit = Path("image/common/systemd/atlaso-worker.service").read_text(encoding="utf-8")
    bootstrap_unit = Path("image/common/systemd/atlaso-bootstrap-https.service").read_text(encoding="utf-8")
    disk_identity_rule = Path("image/common/udev/99-atlaso-disk-identity.rules").read_text(encoding="utf-8")
    sudoers = Path("image/common/sudoers.d/atlaso-helper").read_text(encoding="utf-8")
    docs = Path("image/vmware-workstation/README.md").read_text(encoding="utf-8")
    root_docs = Path("docs/reference/full-technical-reference.md").read_text(encoding="utf-8")

    assert 'run_tdnf "Photon appliance package installation"' in script
    assert "nginx" in script
    assert "gnupg" in script
    assert "ntpsec" in script
    assert "python3-ntp" in script
    assert "systemctl disable --now ntpd.service" in script
    assert "systemctl disable --now systemd-timesyncd.service" in script
    assert "systemctl disable --now chronyd.service" in script
    assert '"$ATLASO_STATE/apply/ntpd"' in script
    assert "openldap-servers" in script
    assert "nfs-utils" in script and "rpcbind" in script
    assert "99-atlaso-disk-identity.rules" in script
    assert 'SUBSYSTEM=="block", ENV{DEVTYPE}=="disk", IMPORT{builtin}="path_id"' in disk_identity_rule
    assert 'SYMLINK+="disk/by-id/atlaso-path-$env{ID_PATH_TAG}"' in disk_identity_rule
    assert 'ENV{ID_SERIAL}==""' not in script
    assert "powershell" in script
    assert "VCF.PowerCLI" in script
    assert "9.1.0.25380678" in script
    assert "Connect-VIServer" in script
    assert "Set-PowerCLIConfiguration -ParticipateInCeip $false -Scope AllUsers -Confirm:$false" in script
    assert "Get-PowerCLIConfiguration -Scope AllUsers" in script
    assert "ATLASO_POWERCLI_MODULE_SOURCE" in script
    assert 'awk \'$2 == "/tmp" { print $3; exit }\' /proc/mounts' in script
    assert "mount -o remount,size=4G /tmp" in script
    assert script.index("mount -o remount,size=4G /tmp") < script.index("Install-Module -Name VCF.PowerCLI")
    assert "chmod 0755 /usr/local/share/powershell /usr/local/share/powershell/Modules" in script
    assert "chmod -R a+rX,go-w /usr/local/share/powershell/Modules" in script
    assert "ipxe" in script
    assert "syslinux" in script
    assert "IPXE_BOOTLOADER_SOURCE_DIR=\"$ATLASO_HOME/third_party/ipxe/bootloaders\"" in script
    assert "IPXE_BOOTLOADER_TARGET_DIR=\"$ATLASO_STATE/pxe/bootloaders\"" in script
    assert "staging bundled iPXE bootloaders" in script
    assert '"$IPXE_BOOTLOADER_TARGET_DIR/undionly.kpxe"' in script
    assert '"$IPXE_BOOTLOADER_TARGET_DIR/snponly.efi"' in script
    assert 'BOOTSTRAP_SHELL="${ATLASO_BOOTSTRAP_ADMIN_SHELL:-/usr/bin/pwsh}"' in script
    assert 'ln -sfn "$ATLASO_HOME/.venv/bin/atlaso-vault" /usr/local/bin/atlaso-vault' in script
    assert 'ln -sfn "$ATLASO_HOME/.venv/bin/atlaso-vault" /usr/bin/atlaso-vault' in script
    assert '"$ATLASO_HOME/image/common/powershell/atlaso-vault-profile.ps1"' in script
    assert '"$ATLASO_HOME/image/common/powershell/profile.ps1"' in script
    assert '"$POWERSHELL_HOME/profile.ps1"' in script
    assert "/opt/microsoft/powershell/7 | /usr/share/powershell" in script
    assert 'touch "$POWERSHELL_HOME/profile.ps1"' not in script
    assert '>>"$POWERSHELL_HOME/profile.ps1"' not in script
    profile = Path("image/common/powershell/atlaso-vault-profile.ps1").read_text(encoding="utf-8")
    assert "function global:Get-AtlasoVault" in profile
    assert "/opt/atlaso/.venv/bin/atlaso-vault" in profile
    global_profile = Path("image/common/powershell/profile.ps1").read_text(encoding="utf-8")
    assert global_profile == (
        "<#\n.SYNOPSIS\nLoads the Atlaso vault helpers into PowerShell sessions.\n#>\n"
        ". '/opt/atlaso/bin/atlaso-vault-profile.ps1'\n"
    )
    assert '--shell "$BOOTSTRAP_SHELL"' in script
    assert "touch /etc/shells" in script
    assert 'grep -qxF "$BOOTSTRAP_SHELL" /etc/shells' in script
    assert "atlaso-bootstrap-admin" in script
    assert "$BOOTSTRAP_USERNAME ALL=(ALL) ALL" in script
    assert "visudo -cf /etc/sudoers.d/atlaso-bootstrap-admin" in script
    assert (
        'sudo -H -u "$BOOTSTRAP_USERNAME" env -u PSModulePath '
        'ATLASO_POWERCLI_VERSION="$ATLASO_POWERCLI_VERSION"'
    ) in script
    assert "is not available to the bootstrap administrator" in script
    assert 'chmod 0711 "$ATLASO_STATE"' in script
    assert 'chown "$BOOTSTRAP_USERNAME:$(id -gn "$BOOTSTRAP_USERNAME")" "$ATLASO_STATE/users/$BOOTSTRAP_USERNAME"' in script
    assert 'chmod 0750 "$ATLASO_STATE/users/$BOOTSTRAP_USERNAME"' in script
    assert "UMask=0027" in systemd_unit
    assert "--host 127.0.0.1 --port 8000" in systemd_unit
    assert "--host 0.0.0.0" not in systemd_unit
    assert "configuring first-boot Atlaso management nginx bootstrap" in script
    assert "install -d -o root -g root -m 0755 /etc/nginx/conf.d" in script
    assert "/etc/nginx/conf.d/atlaso.conf" in script
    assert "/etc/atlaso/nginx/sites.d/management.conf" in bootstrap
    assert "rm -f /etc/nginx/conf.d/default.conf /etc/nginx/conf.d/default_server.conf" in script
    assert "atlaso-bootstrap-https" in script
    assert "atlaso-bootstrap-https.service" in script
    assert "ExecStart=/opt/atlaso/.venv/bin/python /opt/atlaso/bin/atlaso-bootstrap-https" in bootstrap_unit
    assert "EnvironmentFile=/etc/atlaso/atlaso.env" in bootstrap_unit
    assert "After=network-online.target atlaso-data-disks.service atlaso-vmware-ovf-customize.service" in bootstrap_unit
    assert "Wants=network-online.target" in bootstrap_unit
    assert "Requires=atlaso-data-disks.service" in bootstrap_unit
    assert "ConditionPathExists" not in bootstrap_unit
    assert '"$ATLASO_HOME/.venv/bin/python" "$ATLASO_HOME/bin/atlaso-bootstrap-https"' not in script
    assert "sync_host_physical_interfaces(db)" in bootstrap
    assert bootstrap.index("sync_host_physical_interfaces(db)") < bootstrap.index("ensure_ca_state(db)")
    assert "first-boot-development-root-ca.json" in bootstrap
    assert "first-boot-development-root-ca-imported" in bootstrap
    assert "guestinfo.atlaso.test_vm_development_root_ca_imported" in bootstrap
    assert "import_root_ca_material(" in bootstrap
    assert 'expected_common_name="Atlaso Development Root CA"' in bootstrap
    assert "certificates=certificates" in bootstrap
    import_failure = bootstrap.index("except Exception as exc:")
    failure_scrub = bootstrap.index(
        "scrub_staged_development_root_ca_after_failure()", import_failure
    )
    assert failure_scrub < bootstrap.index("return 2", failure_scrub)
    committed_import = bootstrap.index("db.commit()")
    staged_removal = bootstrap.index("remove_staged_development_root_ca()", committed_import)
    assert committed_import < staged_removal < bootstrap.index("ensure_ca_state(db)")
    proof_write = bootstrap.index("write_development_root_ca_import_proof(development_root_fingerprint)")
    proof_publish = bootstrap.index("publish_development_root_ca_import_proof()", proof_write)
    marker_write = bootstrap.index("write_text_atomic(MARKER_PATH, COMPLETION_MARKER_TEXT")
    assert bootstrap.index("fix_state_permissions()") < proof_write < proof_publish < marker_write
    assert 'str(HELPER_PATH), "ca", action, str(CA_STAGED_CONFIG_PATH), "--real"' in bootstrap
    assert 'for db_file in state_path.glob("atlaso.db*")' in bootstrap
    assert 'shutil.chown(db_file, user="atlaso", group="atlaso")' in bootstrap
    assert 'for path in [ca_apply_path, *ca_apply_path.rglob("*")]' in bootstrap
    assert 'listen 80 default_server;' in bootstrap
    assert "location = /ca/downloads/root-ca.pem {" in bootstrap
    assert "location = /ca/downloads/ca-bundle.pem {" in bootstrap
    assert 'return 308 https://$host$request_uri;' in bootstrap
    assert "location / {{\n    return 308 https://$host$request_uri;" in bootstrap
    assert 'listen 443 ssl default_server;' in bootstrap
    assert 'ssl_certificate {cert_path};' in bootstrap
    assert 'ssl_certificate_key {key_path};' in bootstrap

    assert "client_max_body_size 1g;" in bootstrap
    assert "client_max_body_size 512m;" not in bootstrap
    assert "proxy_pass http://127.0.0.1:8000;" in bootstrap
    assert "proxy_set_header Host $host;" in bootstrap
    assert "proxy_set_header X-Real-IP $remote_addr;" in bootstrap
    assert "proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;" in bootstrap
    assert "proxy_set_header X-Forwarded-Proto https;" in bootstrap
    assert "proxy_set_header X-Forwarded-Proto http;" in bootstrap
    assert "proxy_set_header Upgrade $http_upgrade;" in bootstrap
    assert "if not certificate.is_file() or not key.is_file():" in bootstrap
    assert 'if nginx is None:' in bootstrap
    assert bootstrap.index("if not certificate.is_file() or not key.is_file():") < marker_write
    assert bootstrap.index("validation = run([nginx, \"-t\"])") < marker_write
    assert "nginx -t" in script
    assert "systemctl enable --now nginx" in script
    assert 'ATLASO_DRY_RUN_SYSTEM_ADAPTERS="${ATLASO_DRY_RUN_SYSTEM_ADAPTERS:-true}"' in script
    assert 'ATLASO_MGMT_SOURCE_CIDR="${ATLASO_MGMT_SOURCE_CIDR:-}"' in script
    assert 'ATLASO_MGMT_USES_DHCP=false' in script
    assert 'ATLASO_APPLIANCE_EXTERNAL_DNS_SERVERS=$(if [ "$ATLASO_MGMT_USES_DHCP" = "true" ]; then printf \'\'; else printf \'%s\' "$ATLASO_MGMT_DNS" | tr \' \' \',\'; fi)' in script
    assert 'if [ "$ATLASO_MGMT_USES_DHCP" != "true" ] && [ -n "$ATLASO_MGMT_DNS" ]; then' in script
    assert 'ip -4 -o addr show dev "$ATLASO_MGMT_INTERFACE" scope global' in script
    assert 'DETECTED_MGMT_ADDRESS' in script
    assert "ipaddress.ip_interface(sys.argv[1]).network" in script
    assert "printf '\\nATLASO_MANAGEMENT_SOURCE_CIDR=%s\\n' \"$ATLASO_MGMT_SOURCE_CIDR\" >>/etc/atlaso/atlaso.env" in script
    assert 'log_step "system adapter dry-run mode: $ATLASO_DRY_RUN_SYSTEM_ADAPTERS"' in script
    assert "ATLASO_DRY_RUN_SYSTEM_ADAPTERS=$ATLASO_DRY_RUN_SYSTEM_ADAPTERS" in script
    assert 'ATLASO_MGMT_ACCESS_RULE="    ip saddr $ATLASO_MGMT_SOURCE_CIDR tcp dport { 22, 80, 443 } accept comment \\"Atlaso management access\\""' in script
    assert 'ATLASO_MGMT_ACCESS_RULE="    iifname \\"$ATLASO_MGMT_INTERFACE\\" tcp dport { 22, 80, 443 } accept comment \\"Atlaso management access\\""' in script
    assert "$ATLASO_MGMT_ACCESS_RULE" in script
    assert 'install -o root -g root -m 0440 "$ATLASO_HOME/image/common/sudoers.d/atlaso-helper" /etc/sudoers.d/atlaso-helper' in script
    assert 'sed -i \'s/\\r$//\'' in script
    assert '"$ATLASO_HOME/bin/atlaso-install-boot-branding"' in script
    assert "/etc/systemd/system/atlaso-worker.service" in script
    assert 'useradd --system --gid atlaso-automation' in script
    assert 'systemctl enable atlaso-worker.service' in script
    assert "RuntimeDirectory=atlaso-automation-vaults" in worker_unit
    assert "RuntimeDirectoryMode=0700" in worker_unit
    assert "atlaso ALL=(root) NOPASSWD: /opt/atlaso/bin/atlaso-helper *" in sudoers
    assert "atlaso-root-login.conf" in script
    assert "PermitRootLogin no" in script
    assert "HTTPS/443" in docs
    assert "management HTTP/80 redirect-only" in docs
    assert "proxying HTTPS/443 to" in root_docs
    assert (
        "ExecStartPre=+/opt/atlaso/bin/atlaso-helper appliance-update recover-release --real"
        in worker_unit
    )
    assert "-PipGlobalIndex" in root_docs
    assert "-PipGlobalIndexUrl" in root_docs
    assert "Leave both options empty to keep" in root_docs
    assert "standard pip behavior" in root_docs


def test_photon_https_bootstrap_publishes_exact_development_root_import_proof(
    tmp_path, monkeypatch
):
    """Publish only the durable exact fingerprint after signer import and scrub.

    Args:
        tmp_path: Isolated proof-marker directory.
        monkeypatch: Pytest fixture used to replace VMware guest-info commands.
    """
    import importlib.machinery
    import importlib.util
    from types import SimpleNamespace

    script_path = Path("scripts/appliance/atlaso-bootstrap-https")
    loader = importlib.machinery.SourceFileLoader("atlaso_bootstrap_https_test", str(script_path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    bootstrap = importlib.util.module_from_spec(spec)
    loader.exec_module(bootstrap)
    bootstrap.DEVELOPMENT_ROOT_CA_IMPORTED_MARKER_PATH = tmp_path / "imported"
    fingerprint = "A1" * 32
    commands = []

    def fake_run(command):
        """Capture VMware guest-info commands and return deterministic results.

        Args:
            command: Command and arguments issued by the bootstrap helper.
        """
        commands.append(command)
        stdout = f"{fingerprint}\n" if "info-get" in command[-1] else ""
        return SimpleNamespace(returncode=0, stdout=stdout, stderr="")

    monkeypatch.setattr(
        bootstrap.shutil,
        "which",
        lambda name: "/usr/bin/vmware-rpctool" if name == "vmware-rpctool" else None,
    )
    monkeypatch.setattr(bootstrap, "run", fake_run)

    bootstrap.write_development_root_ca_import_proof(fingerprint)

    assert bootstrap.publish_development_root_ca_import_proof() is True
    assert bootstrap.DEVELOPMENT_ROOT_CA_IMPORTED_MARKER_PATH.read_text(
        encoding="ascii"
    ) == fingerprint
    assert commands == [
        [
            "/usr/bin/vmware-rpctool",
            f"info-set {bootstrap.DEVELOPMENT_ROOT_CA_IMPORTED_GUESTINFO} {fingerprint}",
        ],
        [
            "/usr/bin/vmware-rpctool",
            f"info-get {bootstrap.DEVELOPMENT_ROOT_CA_IMPORTED_GUESTINFO}",
        ],
    ]


def test_photon_https_bootstrap_sets_secret_payload_mode_before_write(tmp_path, monkeypatch):
    """Protect decrypted CA keys before opening their apply payload for writing.

    Args:
        tmp_path: Isolated destination directory.
        monkeypatch: Pytest fixture used to record descriptor operations.
    """
    import importlib.machinery
    import importlib.util

    script_path = Path("scripts/appliance/atlaso-bootstrap-https")
    loader = importlib.machinery.SourceFileLoader(
        "atlaso_bootstrap_https_secret_write_test", str(script_path)
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    bootstrap = importlib.util.module_from_spec(spec)
    loader.exec_module(bootstrap)
    destination = tmp_path / "apply" / "ca" / "atlaso-ca.json"
    events = []
    original_fchmod = bootstrap.os.fchmod
    original_fdopen = bootstrap.os.fdopen

    def record_fchmod(descriptor, mode):
        """Record and apply the descriptor mode.

        Args:
            descriptor: Open temporary-file descriptor.
            mode: Requested filesystem mode.
        """
        events.append(("fchmod", mode))
        return original_fchmod(descriptor, mode)

    def record_fdopen(descriptor, *args, **kwargs):
        """Record conversion of the protected descriptor to a text handle.

        Args:
            descriptor: Protected temporary-file descriptor.
            *args: Positional arguments forwarded to ``os.fdopen``.
            **kwargs: Keyword arguments forwarded to ``os.fdopen``.
        """
        events.append(("fdopen", None))
        return original_fdopen(descriptor, *args, **kwargs)

    monkeypatch.setattr(bootstrap.os, "fchmod", record_fchmod)
    monkeypatch.setattr(bootstrap.os, "fdopen", record_fdopen)

    bootstrap.write_secret_text_atomic(destination, "private-key-payload")

    assert events[:2] == [("fchmod", 0o600), ("fdopen", None)]
    assert destination.read_text(encoding="utf-8") == "private-key-payload"
    if os.name == "posix":
        assert destination.stat().st_mode & 0o777 == 0o600


def test_photon_https_bootstrap_rejects_incomplete_durable_contract(tmp_path, monkeypatch):
    """Reject empty or mismatched marker and nginx state after interruption.

    Args:
        tmp_path: Isolated destination directory.
        monkeypatch: Pytest fixture used to replace bootstrap paths and commands.
    """
    import importlib.machinery
    import importlib.util
    from types import SimpleNamespace

    script_path = Path("scripts/appliance/atlaso-bootstrap-https")
    loader = importlib.machinery.SourceFileLoader(
        "atlaso_bootstrap_https_contract_test", str(script_path)
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    bootstrap = importlib.util.module_from_spec(spec)
    loader.exec_module(bootstrap)
    marker = tmp_path / "first-boot-https.applied"
    main_config = tmp_path / "nginx.conf"
    include = tmp_path / "atlaso.conf"
    management = tmp_path / "management.conf"
    certificate = tmp_path / "certificate.pem"
    key = tmp_path / "private-key.pem"
    monkeypatch.setattr(bootstrap, "MARKER_PATH", marker)
    monkeypatch.setattr(bootstrap, "NGINX_MAIN_CONFIG_PATH", main_config)
    monkeypatch.setattr(bootstrap, "NGINX_CONF_INCLUDE_PATH", include)
    monkeypatch.setattr(bootstrap, "NGINX_MANAGEMENT_PATH", management)
    monkeypatch.setattr(bootstrap.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(
        bootstrap,
        "run",
        lambda command: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )

    marker.write_text("", encoding="utf-8")
    management.write_text("", encoding="utf-8")
    assert bootstrap.first_boot_https_contract_is_complete() is False

    certificate.write_text("certificate", encoding="utf-8")
    key.write_text("key", encoding="utf-8")
    main_config.write_text(
        "http {\n  include /etc/nginx/conf.d/atlaso.conf;\n}\n",
        encoding="utf-8",
    )
    bootstrap.write_text_atomic(include, bootstrap.NGINX_INCLUDE_TEXT, mode=0o644)
    bootstrap.write_text_atomic(
        management,
        "\n".join(
            [
                "server {",
                "  listen 443 ssl default_server;",
                f"  ssl_certificate {certificate};",
                f"  ssl_certificate_key {key};",
                "  location / {",
                "    proxy_pass http://127.0.0.1:8000;",
                "  }",
                "}",
                "",
            ]
        ),
        mode=0o644,
    )
    bootstrap.write_text_atomic(
        marker,
        bootstrap.COMPLETION_MARKER_TEXT,
        mode=0o640,
    )

    assert bootstrap.first_boot_https_contract_is_complete() is True

    include.write_text(
        "# include /etc/atlaso/nginx/sites.d/*.conf;\n",
        encoding="utf-8",
    )
    assert bootstrap.first_boot_https_contract_is_complete() is False

    include.write_text(bootstrap.NGINX_INCLUDE_TEXT, encoding="utf-8")
    main_config.write_text(
        "http {\n  # include /etc/nginx/conf.d/atlaso.conf;\n}\n",
        encoding="utf-8",
    )
    assert bootstrap.first_boot_https_artifacts_are_complete() is True
    assert bootstrap.first_boot_https_contract_is_complete() is False

    annotated_main_config = (
        "http {\n"
        "  include /etc/nginx/conf.d/*.conf; # load managed sites\n"
        "}\n"
    )
    main_config.write_text(annotated_main_config, encoding="utf-8")
    assert bootstrap.first_boot_https_contract_is_complete() is True
    bootstrap.ensure_nginx_main_config_includes_atlaso()
    assert main_config.read_text(encoding="utf-8") == annotated_main_config


def test_photon_https_bootstrap_syncs_file_and_parent_before_success(tmp_path, monkeypatch):
    """Publish an atomic replacement only after syncing its bytes and directory.

    Args:
        tmp_path: Isolated destination directory.
        monkeypatch: Pytest fixture used to record durability operations.
    """
    import importlib.machinery
    import importlib.util

    script_path = Path("scripts/appliance/atlaso-bootstrap-https")
    loader = importlib.machinery.SourceFileLoader(
        "atlaso_bootstrap_https_durability_test", str(script_path)
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    bootstrap = importlib.util.module_from_spec(spec)
    loader.exec_module(bootstrap)
    destination = tmp_path / "management.conf"
    events: list[str] = []
    parent_descriptor = 919
    original_fsync = bootstrap.os.fsync
    original_open = bootstrap.os.open
    original_close = bootstrap.os.close
    original_replace = bootstrap.os.replace

    def record_fsync(descriptor):
        """Record file and parent sync calls.

        Args:
            descriptor: File descriptor selected for durable sync.
        """
        if descriptor == parent_descriptor:
            events.append("fsync-parent")
            return None
        events.append("fsync-file")
        return original_fsync(descriptor)

    def record_replace(source, target):
        """Record and perform the atomic replacement.

        Args:
            source: Temporary file path.
            target: Final destination path.
        """
        events.append("replace")
        return original_replace(source, target)

    def record_open(path, flags, *args):
        """Return a synthetic descriptor only for the parent directory.

        Args:
            path: Filesystem path being opened.
            flags: Operating-system open flags.
            *args: Optional file creation mode.
        """
        if bootstrap.os.fspath(path) == bootstrap.os.fspath(destination.parent) and not args:
            return parent_descriptor
        return original_open(path, flags, *args)

    def record_close(descriptor):
        """Record the synthetic parent close and preserve ordinary closes.

        Args:
            descriptor: File descriptor being closed.
        """
        if descriptor == parent_descriptor:
            events.append("close-parent")
            return None
        return original_close(descriptor)

    monkeypatch.setattr(bootstrap.os, "name", "posix")
    monkeypatch.setattr(bootstrap.os, "fsync", record_fsync)
    monkeypatch.setattr(bootstrap.os, "replace", record_replace)
    monkeypatch.setattr(bootstrap.os, "open", record_open)
    monkeypatch.setattr(bootstrap.os, "close", record_close)

    bootstrap.write_text_atomic(destination, "complete\n", mode=0o640)

    assert destination.read_text(encoding="utf-8") == "complete\n"
    assert events == ["fsync-file", "replace", "fsync-parent", "close-parent"]


def test_photon_https_bootstrap_does_not_regenerate_completed_state_on_global_nginx_failure(
    tmp_path,
    monkeypatch,
):
    """Fail validation without re-entering destructive first-boot initialization.

    Args:
        tmp_path: Isolated destination directory.
        monkeypatch: Pytest fixture used to replace bootstrap paths and commands.
    """
    import importlib.machinery
    import importlib.util
    from types import SimpleNamespace

    script_path = Path("scripts/appliance/atlaso-bootstrap-https")
    loader = importlib.machinery.SourceFileLoader(
        "atlaso_bootstrap_https_global_nginx_failure_test",
        str(script_path),
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    bootstrap = importlib.util.module_from_spec(spec)
    loader.exec_module(bootstrap)
    marker = tmp_path / "first-boot-https.applied"
    main_config = tmp_path / "nginx.conf"
    include = tmp_path / "atlaso.conf"
    management = tmp_path / "management.conf"
    marker.write_text(bootstrap.COMPLETION_MARKER_TEXT, encoding="utf-8")
    main_config.write_text(
        "http {\n  include /etc/nginx/conf.d/atlaso.conf;\n}\n",
        encoding="utf-8",
    )
    include.write_text(bootstrap.NGINX_INCLUDE_TEXT, encoding="utf-8")
    management.write_text(
        "listen 80 default_server;\nproxy_pass http://127.0.0.1:8000;\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(bootstrap, "MARKER_PATH", marker)
    monkeypatch.setattr(bootstrap, "NGINX_MAIN_CONFIG_PATH", main_config)
    monkeypatch.setattr(bootstrap, "NGINX_CONF_INCLUDE_PATH", include)
    monkeypatch.setattr(bootstrap, "NGINX_MANAGEMENT_PATH", management)
    monkeypatch.setattr(bootstrap.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(
        bootstrap,
        "run",
        lambda command: SimpleNamespace(
            returncode=1,
            stdout="",
            stderr="unrelated site invalid\n",
        ),
    )

    def reject_destructive_initialization():
        """Prove completed state never returns to database initialization."""
        raise AssertionError("completed state entered destructive first-boot initialization")

    monkeypatch.setattr(bootstrap, "init_db", reject_destructive_initialization)

    assert bootstrap.main() == 1


def test_photon_provisioning_prepares_attached_data_disks():
    """Verify that photon provisioning prepares attached data disks."""
    provision = Path("image/common/scripts/provision-atlaso.sh").read_text(encoding="utf-8")
    mount_script = Path("scripts/appliance/atlaso-mount-data-disks").read_text(encoding="utf-8")
    atlaso_unit = Path("image/common/systemd/atlaso.service").read_text(encoding="utf-8")
    worker_unit = Path("image/common/systemd/atlaso-worker.service").read_text(encoding="utf-8")
    data_disks_unit = Path("image/common/systemd/atlaso-data-disks.service").read_text(encoding="utf-8")
    bootstrap_unit = Path("image/common/systemd/atlaso-bootstrap-https.service").read_text(encoding="utf-8")
    nginx_dropin = Path("image/common/systemd/nginx-atlaso-data-disks.conf").read_text(encoding="utf-8")
    atlaso_dropin = Path("image/common/systemd/atlaso-require-data-disks.conf").read_text(encoding="utf-8")
    disk_identity_rule = Path("image/common/udev/99-atlaso-disk-identity.rules").read_text(encoding="utf-8")
    virtualization_policy = Path("image/common/data-disks.conf").read_text(encoding="utf-8")
    vmware_docs = Path("image/vmware-workstation/README.md").read_text(encoding="utf-8")
    root_docs = Path("docs/reference/full-technical-reference.md").read_text(encoding="utf-8")
    vmware_packer = Path("image/vmware-workstation/atlaso-photon.pkr.hcl").read_text(encoding="utf-8")

    assert 'run_tdnf "Photon appliance package installation"' in provision
    assert "install -d -o root -g root -m 0700 /var/lib/atlaso-privileged/management-front-door" in provision
    assert "install -d -o root -g root -m 0700 /var/lib/atlaso-privileged/appliance-update-status" in provision
    assert "e2fsprogs" in provision
    assert "atlaso-mount-data-disks" in provision
    assert "atlaso-data-disks.service" in provision
    assert "systemctl enable atlaso-data-disks.service" in provision
    assert "Before=atlaso-bootstrap-https.service atlaso.service" in data_disks_unit

    assert "ATLASO_DEPOT" in mount_script
    assert "ATLASO_BKUP" in mount_script
    assert "/mnt/atlaso-vcf-offline-depot" in mount_script
    assert "/mnt/atlaso-vcf-backups" in mount_script
    assert 'format_disk="$(revalidate_blank_format_target' in mount_script
    assert 'mkfs.ext4 -F -L "$label" "$format_disk"' in mount_script
    assert "UUID=%s %s ext4 defaults,nofail,x-systemd.device-timeout=30s 0 2" in mount_script
    assert "findmnt -n -o SOURCE /" in mount_script
    assert 'DISK_IDENTITY_RULE_SOURCE="$ATLASO_SRC/image/common/udev/99-atlaso-disk-identity.rules"' in provision
    assert 'DATA_DISK_POLICY_SOURCE="$ATLASO_SRC/image/common/data-disks.conf"' in provision
    assert '"$DISK_IDENTITY_RULE_SOURCE" /etc/udev/rules.d/99-atlaso-disk-identity.rules' in provision
    assert '"$DATA_DISK_POLICY_SOURCE" /etc/atlaso/data-disks.conf' in provision
    assert provision.index('if [ ! -r "$DISK_IDENTITY_RULE_SOURCE" ]') < provision.index(
        'run_tdnf "Photon appliance package installation"'
    )
    assert provision.index('if [ ! -r "$DATA_DISK_POLICY_SOURCE" ]') < provision.index(
        'run_tdnf "Photon appliance package installation"'
    )
    assert provision.index('"$DISK_IDENTITY_RULE_SOURCE" /etc/udev/rules.d/99-atlaso-disk-identity.rules') < provision.index(
        'log_step "syncing Atlaso application files"'
    )
    assert provision.index('"$DATA_DISK_POLICY_SOURCE" /etc/atlaso/data-disks.conf') < provision.index(
        'log_step "syncing Atlaso application files"'
    )
    assert 'SYMLINK+="disk/by-id/atlaso-path-$env{ID_PATH_TAG}"' in disk_identity_rule
    assert 'source      = "../common/udev"' in vmware_packer
    assert 'destination = "/tmp/atlaso-src/image/common/udev"' in vmware_packer
    assert 'source      = "../common/data-disks.conf"' in vmware_packer
    assert 'destination = "/tmp/atlaso-src/image/common/data-disks.conf"' in vmware_packer
    assert "ATLASO_DATA_DISK_SIZE_BYTES=536870912000" in virtualization_policy
    assert "ATLASO_VMWARE_DEPOT_SCSI_TUPLE=0:2:0" in virtualization_policy
    assert "ATLASO_HYPERV_DEPOT_SCSI_TUPLE=0:0:2" in virtualization_policy
    assert "ATLASO_KVM_DEPOT_SCSI_TUPLE=0:0:2" in virtualization_policy
    assert "ATLASO_BAREMETAL_DEPOT_SCSI_TUPLE=0:2:0" in virtualization_policy
    assert "validate_exact_disk_set" in mount_script
    assert "is_managed_esx_storage_disk" in mount_script
    assert "# BEGIN ATLASO ESX STORAGE" in mount_script
    assert "ESX_STORAGE_ALLOWLIST_PATH" in mount_script
    assert "stable_path_for_disk" in mount_script
    assert "unexpected whole disk" in mount_script
    assert "No blank data disk available" not in mount_script

    assert 'ATLASO_SYSTEM_CONTENT_DISK="${ATLASO_SYSTEM_CONTENT_DISK:-false}"' in provision
    assert 'lsblk -s -n -o PATH,TYPE "$root_source"' in provision
    assert 'Photon OS root source resolves to $root_disk_count physical disks' in provision
    assert 'root_tuple="$(scsi_tuple_for_disk "$root_disk" || true)"' in provision
    assert '"$root_tuple" != "$ATLASO_ROOT_SCSI_TUPLE"' in provision
    assert '"$system_tuple" != "$ATLASO_SYSTEM_SCSI_TUPLE"' in provision
    assert 'VMware image provisioning requires exactly two payload disks' in provision
    assert 'mkfs.ext4 -F -L ATLASO_SYSTEM "$system_disk"' in provision
    assert provision.index('"$system_tuple" != "$ATLASO_SYSTEM_SCSI_TUPLE"') < provision.index(
        'mkfs.ext4 -F -L ATLASO_SYSTEM "$system_disk"'
    )
    assert "Expected exactly one additional blank disk for Atlaso system content" in provision
    assert 'UUID=%s %s ext4 defaults 0 2' in provision
    assert "x-systemd.requires-mounts-for=%s" in provision
    assert 'mount --bind "$ATLASO_SYSTEM_CONTENT_MOUNT/opt-atlaso" "$ATLASO_HOME"' in provision
    assert "powershell-modules" in provision
    assert (
        'run_tdnf "Build-only package removal" --noautoremove remove python3-devel'
        in provision
    )
    assert provision.count(
        'run_tdnf "Final Photon package cache cleanup" clean all'
    ) == 2
    assert 'run_tdnf "Final Photon repository refresh" makecache' in provision
    assert 'run_tdnf "Final Photon OS update verification" update' in provision
    final_update_index = provision.index(
        'run_tdnf "Final Photon OS update verification" update'
    )
    final_guest_agent_closure_index = provision.rindex("stage_guest_agent_packages")
    final_python_closure_index = provision.rindex("stage_python_runtime_packages")
    final_notice_index = provision.rindex("write_third_party_notices")
    final_compatibility_index = provision.index(
        'log_step "revalidating Photon compatibility and runtime capabilities '
        'after final update"'
    )
    assert provision.count("stage_python_runtime_packages") == 3
    assert provision.count("stage_guest_agent_packages") == 3
    assert provision.count("write_third_party_notices") == 3
    assert final_update_index < final_guest_agent_closure_index < final_compatibility_index
    assert final_update_index < final_python_closure_index < final_compatibility_index
    assert final_update_index < final_notice_index < final_compatibility_index
    assert final_update_index < provision.rindex("nginx -t")
    assert final_update_index < provision.rindex(
        '"$ATLASO_HOME/.venv/bin/python" '
        '"$ATLASO_HOME/scripts/check_photon_compatibility.py"'
    )
    assert final_compatibility_index < provision.rindex(
        'python3 "$PHOTON_PACKAGE_STATE_VERIFIER" --guest-platform '
        '"$ATLASO_GUEST_PLATFORM"'
    )
    assert provision.count(
        'python3 "$PHOTON_PACKAGE_STATE_VERIFIER" --guest-platform '
        '"$ATLASO_GUEST_PLATFORM"'
    ) == 2
    assert provision.count("write_build_info") == 3
    assert final_update_index < provision.rindex("write_build_info")
    assert provision.rindex("write_build_info") < provision.rindex(
        'run_tdnf "Final Photon package cache cleanup" clean all'
    )
    assert "zero_fill_free_space / \"Photon OS filesystem\"" in provision
    assert 'zero_fill_free_space "$ATLASO_SYSTEM_CONTENT_MOUNT" "Atlaso system-content filesystem"' in provision
    assert "reserve_kib=524288" in provision
    assert 'of="$zero_file" bs=1048576 count="$zero_count_mib" conv=fsync status=progress' in provision
    assert "fstrim -av" in provision

    assert "After=network-online.target atlaso-data-disks.service atlaso-bootstrap-https.service" in atlaso_unit
    assert "Requires=atlaso-bootstrap-https.service" in atlaso_unit
    assert "Requires=atlaso-data-disks.service" in atlaso_dropin
    assert "bootstrap-data-disk-safety --real /opt/atlaso/current" in atlaso_unit
    assert "management-front-door recover --real" in atlaso_unit
    assert "factory-reset resume --real" in atlaso_unit
    assert "Wants=network-online.target atlaso.service" in worker_unit
    assert "Requires=atlaso-data-disks.service\n" in worker_unit
    assert "Requires=atlaso-data-disks.service atlaso.service" not in worker_unit
    assert "ExecStart=/opt/atlaso/bin/atlaso-mount-data-disks" in data_disks_unit
    assert "Requires=atlaso-data-disks.service" in bootstrap_unit
    assert "Requires=atlaso-data-disks.service" in nginx_dropin
    startup_guard = (
        "ExecStartPre=+/opt/atlaso/bin/atlaso-helper "
        "appliance-update guard-release --real"
    )
    assert startup_guard in atlaso_dropin
    assert startup_guard in nginx_dropin
    assert "/etc/systemd/system/nginx.service.d/atlaso-data-disks.conf" in provision
    assert "/etc/systemd/system/atlaso.service.d/atlaso-data-disks.conf" in provision
    assert provision.index("systemctl enable --now nginx") < provision.index(
        '"$ATLASO_HOME/image/common/systemd/nginx-atlaso-data-disks.conf"'
    )

    assert "atlaso-data-disks.service" in root_docs
    assert "atlaso-data-disks.service" in vmware_docs


def test_bundled_ipxe_bootloaders_have_provenance_and_expected_hashes():
    """Verify that bundled ipxe bootloaders have provenance and expected hashes."""
    readme = Path("third_party/ipxe/README.md").read_text(encoding="utf-8")
    copying = Path("third_party/ipxe/COPYING").read_text(encoding="utf-8")
    gpl = Path("third_party/ipxe/COPYING.GPLv2").read_text(encoding="utf-8")
    undionly_licence = Path("third_party/ipxe/bootloaders/undionly.kpxe.licence").read_text(encoding="utf-8")
    snponly_licence = Path("third_party/ipxe/bootloaders/snponly.efi.licence").read_text(encoding="utf-8")

    assert Path("third_party/ipxe/bootloaders/source-commit.txt").read_text(encoding="utf-8").strip() == "bbd7821bd42da5456ee068a471ef73d525ea26a1"
    assert sha256("third_party/ipxe/bootloaders/undionly.kpxe") == "b2ff1718908401bd71d5f84d433ec5c2e73fe563866ad904d0c3fa3d9ce67c0b"
    assert sha256("third_party/ipxe/bootloaders/snponly.efi") == "a3fec333e4ae52c33b3ef8b140422a16019c4d7aa63a13f8ac3c95079fad0715"
    assert sha256("third_party/ipxe/bootloaders/undionly.kpxe.licence") == "4c06a9f1384900fa50c68042795e11d1939bbee3b76f4b692f7655c99d3026d8"
    assert sha256("third_party/ipxe/bootloaders/snponly.efi.licence") == "04369e5a91dc2cfb5c86ca6a1db031897ceb349c46f8f5c06c4a8e7bdc6ab5f8"
    assert "make -j2 bin/undionly.kpxe bin-x86_64-efi/snponly.efi" in readme
    assert "GPL version 2 (or, at your option, any later version)" in undionly_licence
    assert "GPL version 2 (or, at your option, any later version)" in snponly_licence
    assert "make bin/xxxxxxx.yyy.licence" in copying
    assert "GNU GENERAL PUBLIC LICENSE" in gpl


def test_packer_templates_stage_shared_appliance_assets():
    """Verify that packer templates stage shared appliance assets."""
    for template_path in (Path("image/vmware-workstation/atlaso-photon.pkr.hcl"),):
        template = template_path.read_text(encoding="utf-8")

        assert 'source      = "../common/boot"' in template
        assert 'destination = "/tmp/atlaso-src/image/common/boot"' in template
        assert 'source      = "../common/powershell"' in template
        assert 'destination = "/tmp/atlaso-src/image/common/powershell"' in template


def test_vmware_packer_leaves_directory_upload_destinations_uncreated() -> None:
    """Packer directory uploads must create their own exact destination paths."""

    template = Path("image/vmware-workstation/atlaso-photon.pkr.hcl").read_text(
        encoding="utf-8"
    )
    staging_command = next(
        line.strip()
        for line in template.splitlines()
        if line.strip().startswith('"mkdir -p /tmp/atlaso-src/scripts ')
    )

    assert "/tmp/atlaso-src/image/common " in staging_command
    assert "/tmp/atlaso-src/image/common/scripts" not in staging_command
    assert "/tmp/atlaso-src/image/common/guest-agents" not in staging_command
    assert 'source      = "../common/scripts"' in template
    assert 'destination = "/tmp/atlaso-src/image/common/scripts"' in template
    assert 'source      = "../common/guest-agents"' in template
    assert 'destination = "/tmp/atlaso-src/image/common/guest-agents"' in template


def test_vmware_packer_build_uses_two_compacted_payload_disks():
    """Verify that vmware packer build uses two compacted payload disks."""
    template = Path("image/vmware-workstation/atlaso-photon.pkr.hcl").read_text(encoding="utf-8")
    wrapper = Path("scripts/windows/vmware/build-photon-image.ps1").read_text(encoding="utf-8")

    assert 'disk_size            = 40960' in template
    assert 'disk_additional_size = [20480]' in template
    assert 'disk_type_id         = 0' in template
    assert 'skip_compaction      = false' in template
    assert '"ATLASO_SYSTEM_CONTENT_DISK=true"' in template
    assert '"ATLASO_ROOT_SCSI_TUPLE=0:0:0"' in template
    assert '"ATLASO_SYSTEM_SCSI_TUPLE=0:1:0"' in template
    assert "-InstallDiskLayout 'vmware-workstation'" in wrapper
    assert "Atlaso.VmwarePayload.psm1" in wrapper
    assert "Write-AtlasoVmwareBuildProvenance" in wrapper
    assert "tracked_source_dirty" in wrapper
    assert "schema_version       = 2" in wrapper
    assert "payload_disks" in wrapper
    assert "Get-AtlasoVmwarePayloadLayout" in wrapper
    payload_module = Path("scripts/windows/vmware/Atlaso.VmwarePayload.psm1").read_text(
        encoding="utf-8"
    )
    assert "Get-FileHash -LiteralPath $vmx.FullName -Algorithm SHA256" in payload_module


def test_vmware_payload_layout_and_provenance_fail_closed(tmp_path: Path) -> None:
    """Verify canonical payload roles pass while reversed layouts and roles fail.

    Args:
        tmp_path: Pytest-provided isolated output directory.
    """
    pwsh = shutil.which("pwsh")
    if pwsh is None:
        pytest.skip("PowerShell 7 is required")

    result = subprocess.run(
        [
            pwsh,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            "tests/powershell/Test-AtlasoVmwarePayload.ps1",
            "-RepositoryRoot",
            str(Path.cwd()),
            "-OutputDirectory",
            str(tmp_path / "vmware-payload"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Atlaso VMware payload layout and provenance tests passed." in result.stdout


def test_photon_kickstart_uses_deterministic_build_time_sshd_service():
    """Verify that photon kickstart uses deterministic build time sshd service."""
    build_module = Path("scripts/windows/common/Atlaso.PhotonImage.psm1").read_text(encoding="utf-8")

    disable_socket = "'systemctl disable sshd.socket'"
    enable_service = "'systemctl enable sshd.service'"
    assert disable_socket in build_module
    assert enable_service in build_module
    assert "'systemctl enable sshd'" not in build_module
    assert build_module.index(disable_socket) < build_module.index(enable_service)


def test_photon_image_optional_pip_global_index_configuration():
    """Verify that photon image optional pip global index configuration."""
    wrapper = Path("scripts/windows/vmware/build-photon-image.ps1").read_text(encoding="utf-8")
    build_module = Path("scripts/windows/common/Atlaso.PhotonImage.psm1").read_text(encoding="utf-8")
    template = Path("image/vmware-workstation/atlaso-photon.pkr.hcl").read_text(encoding="utf-8")
    script = Path("image/common/scripts/provision-atlaso.sh").read_text(encoding="utf-8")

    assert "[string[]]$BuilderStaticDns = @()" in wrapper
    assert "[string]$PipGlobalIndex = ''" in wrapper
    assert "[string]$PipGlobalIndexUrl = ''" in wrapper
    assert "Join-Path $PSScriptRoot '..\\common\\Atlaso.PhotonImage.psm1'" in wrapper
    assert "pip_global_index         = $PipGlobalIndex" in build_module
    assert "pip_global_index_url     = $PipGlobalIndexUrl" in build_module

    assert 'variable "pip_global_index" {\n  type        = string\n  default     = ""' in template
    assert 'variable "pip_global_index_url" {\n  type        = string\n  default     = ""' in template
    assert '"ATLASO_PIP_GLOBAL_INDEX=${var.pip_global_index}"' in template
    assert '"ATLASO_PIP_GLOBAL_INDEX_URL=${var.pip_global_index_url}"' in template

    assert 'ATLASO_PIP_GLOBAL_INDEX="${ATLASO_PIP_GLOBAL_INDEX:-}"' in script
    assert 'ATLASO_PIP_GLOBAL_INDEX_URL="${ATLASO_PIP_GLOBAL_INDEX_URL:-}"' in script
    assert 'PIP_CACHE_DIR="${PIP_CACHE_DIR:-/var/cache/atlaso-pip}"' in script
    assert "write_pip_config() {" in script
    assert 'printf \'index = %s\\n\' "$ATLASO_PIP_GLOBAL_INDEX"' in script
    assert 'printf \'index-url = %s\\n\' "$ATLASO_PIP_GLOBAL_INDEX_URL"' in script
    assert 'printf \'cache-dir = %s\\n\' "$PIP_CACHE_DIR"' in script
    assert 'write_pip_config /etc/pip.conf' in script
    assert 'python3 -m venv "$ATLASO_RELEASE_DIR/.venv"' in script
    assert (
        'python3 "$ATLASO_HOME/scripts/version.py" project-get --root "$ATLASO_HOME"'
        in script
    )
    assert "sed -n 's/^version" not in script
    assert 'ATLASO_RELEASE_DIR="$ATLASO_HOME/releases/bootstrap-$ATLASO_RELEASE_VERSION"' in script
    assert '"$ATLASO_RELEASE_DIR/bundle-metadata.json"' in script
    assert 'ln -sfn "releases/bootstrap-$ATLASO_RELEASE_VERSION" "$ATLASO_HOME/current"' in script
    assert 'ln -sfn "current/.venv" "$ATLASO_HOME/.venv"' in script
    assert 'write_pip_config "$ATLASO_HOME/.venv/pip.conf"' in script
    assert '--requirement "$ATLASO_HOME/requirements-appliance.lock"' in script
    assert 'pip install --no-compile --no-deps "$ATLASO_HOME"' in script
    assert 'ATLASO_SITE_PACKAGES_REAL="$(readlink -f "$ATLASO_SITE_PACKAGES")"' in script
    assert (
        'ATLASO_EXPECTED_SITE_PACKAGES="$ATLASO_RELEASE_DIR/.venv/lib/python3.14/site-packages"'
        in script
    )
    assert 'if [ "$ATLASO_SITE_PACKAGES_REAL" != "$ATLASO_EXPECTED_SITE_PACKAGES" ]; then' in script
    assert "Atlaso site-packages resolved outside the expected release environment." in script
    assert 'find "$ATLASO_SITE_PACKAGES_REAL" -type f -name \'*.pyc\' -delete' in script
    assert "/etc/atlaso/update-trust.d" in script
    assert 'trust_source_dir="$ATLASO_HOME/image/common/update-trust"' in script
    assert 'for trust_key in "$trust_source_dir"/*.pem' in script
    for packer_template in (template,):
        assert 'source      = "../../requirements-appliance.lock"' in packer_template
        assert 'destination = "/tmp/atlaso-src/requirements-appliance.lock"' in packer_template
        assert 'source      = "../../scripts/generate_third_party_notices.py"' in packer_template
        assert 'destination = "/tmp/atlaso-src/scripts/generate_third_party_notices.py"' in packer_template
        assert 'source      = "../../scripts/third_party_notices.json"' in packer_template
        assert 'destination = "/tmp/atlaso-src/scripts/third_party_notices.json"' in packer_template
        assert 'source      = "../../scripts/version.py"' in packer_template
        assert 'destination = "/tmp/atlaso-src/scripts/version.py"' in packer_template
        assert 'source      = "../../scripts/run_tdnf_with_progress.py"' in packer_template
        assert 'destination = "/tmp/atlaso-src/scripts/run_tdnf_with_progress.py"' in packer_template
        assert 'source      = "../inventory-linux/README.md"' in packer_template
        assert 'destination = "/tmp/atlaso-src/image/inventory-linux/README.md"' in packer_template
        assert 'source      = "../common/update-trust"' in packer_template
        assert 'destination = "/tmp/atlaso-src/image/common/update-trust"' in packer_template
    assert "Atlaso release trust source directory is missing" in script
    assert "No Atlaso release trust keys were staged" in script
    assert 'openssl pkey -pubin -in "$trust_key" -text -noout' in script
    assert "*ED25519*" in script
    assert 'export PIP_DISABLE_PIP_VERSION_CHECK=1' in script
    assert 'export PIP_INDEX_URL="$ATLASO_PIP_GLOBAL_INDEX_URL"' in script
    assert "pip install --upgrade pip setuptools wheel" not in script
    assert "packages.vcfd.broadcom.net/artifactory" not in wrapper
    assert "packages.vcfd.broadcom.net/artifactory" not in template
    assert "packages.vcfd.broadcom.net/artifactory" not in script
    assert 'TDNF_PROGRESS_RUNNER="$ATLASO_SRC/scripts/run_tdnf_with_progress.py"' in script
    assert 'run_tdnf "Photon package metadata refresh" makecache' in script
    assert 'run_tdnf "Photon OS update" update' in script
    assert 'run_tdnf "Photon appliance package installation"' in script
    assert 'run_tdnf "Photon OS update verification" update' in script
    assert "\ntdnf -y update" not in script


def test_photon_build_installs_the_complete_qemu_build_toolchain() -> None:
    """Photon supplies the compiler and Linux userspace headers separately."""

    provision = Path("image/common/scripts/provision-atlaso.sh").read_text(
        encoding="utf-8"
    )
    qemu_builder = Path(
        "image/common/scripts/build-qemu-guest-agent-rpm.sh"
    ).read_text(encoding="utf-8")
    package_install = next(
        line.strip()
        for line in provision.splitlines()
        if line.strip().startswith("install python3 ")
    )
    package_removal = next(
        line.strip()
        for line in provision.splitlines()
        if line.strip().startswith(
            'run_tdnf "Build-only package removal" --noautoremove remove '
        )
    )

    assert " gcc " in f" {package_install} "
    assert " gcc " in f" {package_removal} "
    assert " binutils " in f" {package_install} "
    assert " binutils " in f" {package_removal} "
    assert " linux-api-headers " in f" {package_install} "
    assert " linux-api-headers " in f" {package_removal} "
    assert "gcc-c++" not in package_install
    assert "gcc-c++" not in package_removal
    assert (
        'install --downloadonly --downloaddir "$GUEST_AGENT_STAGING/qemu" '
        "--alldeps glib systemd"
        in provision
    )
    assert (
        '"$QEMU_GUEST_AGENT_RPM" '
        '"$GUEST_AGENT_STAGING/qemu/$(basename "$QEMU_GUEST_AGENT_RPM")"'
        in provision
    )
    assert "--nogpgcheck" not in provision
    assert (
        "find hyperv qemu -type f -name '*.rpm' -print | LC_ALL=C sort | "
        "xargs sha256sum >SHA256SUMS"
        in provision
    )
    assert "QEMU configure diagnostic (last 80 Meson log lines):" in qemu_builder
    assert "tail -n 80 build/meson-logs/meson-log.txt" in qemu_builder
    assert (
        'install -o root -g root -m 0755 build/qga/qemu-ga "$RPM_ROOT/SOURCES/qemu-ga"'
        in qemu_builder
    )


def test_vmware_builder_uses_nat_gateway_dns_by_default():
    """Verify that vmware builder uses nat gateway dns by default."""
    wrapper = Path("scripts/windows/vmware/build-photon-image.ps1").read_text(encoding="utf-8")
    docs = Path("image/vmware-workstation/README.md").read_text(encoding="utf-8")

    assert "[SecureString]$SshPassword" in wrapper
    assert "[SecureString]$BootstrapAdminPassword" in wrapper
    assert "$needsOnePasswordDefaults = $null -eq $SshPassword -or $null -eq $BootstrapAdminPassword" in wrapper
    assert "PrepareIsoOnly is not supported because a retained remastered ISO" in wrapper
    assert "Read-Host" not in wrapper
    assert "Get-AtlasoOnePasswordCredentialPair" in wrapper
    assert "$builderDnsWasPassed = $PSBoundParameters.ContainsKey('BuilderStaticDns')" in wrapper
    assert "-not $builderDnsWasPassed -and $BuilderStaticDns.Count -eq 0 -and $management.Type -eq 'nat'" in wrapper
    assert "$BuilderStaticDns = @($managementGateway)" in wrapper
    assert "Using VMware NAT gateway DNS for Photon builder" in wrapper
    assert "Photon builder temporary SSH address" in wrapper
    assert "gateway DNS proxy" in docs
    assert "copying unrelated host" in docs
    assert "servers into the Photon kickstart" in docs


def test_windows_script_names_use_provider_tokens():
    """Verify that windows script names use provider tokens."""
    script_paths = {
        path.relative_to("scripts/windows").as_posix()
        for path in Path("scripts/windows").rglob("*.ps1")
    }
    root_scripts = {path.name for path in Path("scripts/windows").glob("*.ps1")}

    old_vmware_token = "vmware-" + "workstation"
    old_names = {
        f"build-photon-{old_vmware_token}-image.ps1",
        f"create-atlaso-{old_vmware_token}-test-vm.ps1",
        f"invoke-{old_vmware_token}-lifecycle-test.ps1",
        f"prepare-{old_vmware_token}-networks.ps1",
        "prepare-" + "tiny-linux-client.ps1",
        "get-atlaso-" + "vm-ip.ps1",
        "start-atlaso-" + "vm.ps1",
        "stop-atlaso-" + "vm.ps1",
    }
    assert root_scripts == set()
    assert script_paths.isdisjoint(old_names)

    assert "common/Atlaso.PhotonImage.psm1" not in script_paths
    assert not any(path.startswith("hyperv/") for path in script_paths)
    assert "virtualization/export-artifacts.ps1" in script_paths
    assert "virtualization/templates/Import-Atlaso.ps1" in script_paths
    assert "vmware/build-photon-image.ps1" in script_paths
    assert "vmware/create-atlaso-test-vm.ps1" in script_paths
    assert "vmware/create-atlaso-vm.ps1" in script_paths
    assert "vmware/invoke-lifecycle-test.ps1" in script_paths
    assert "vmware/prepare-networks.ps1" in script_paths
    assert "vmware/prepare-tiny-linux-client.ps1" in script_paths
    assert "vmware/get-atlaso-vm-ip.ps1" in script_paths
    assert "vmware/start-atlaso-vm.ps1" in script_paths
    assert "vmware/stop-atlaso-vm.ps1" in script_paths
    assert "vmware/remove-atlaso-vm.ps1" in script_paths
    assert "vmware/remove-lifecycle-vms.ps1" in script_paths
    assert "vmware/reset-atlaso-vm.ps1" in script_paths
    assert "vmware/set-test-nics.ps1" in script_paths


def test_windows_documentation_requires_powershell_74_or_newer():
    """Verify that Windows documentation requires PowerShell 7.4 or newer."""
    documentation_paths = [
        Path("README.md"),
        *Path("clients").rglob("*.md"),
        *Path("docs").rglob("*.md"),
        *Path("image").rglob("*.md"),
    ]
    for path in documentation_paths:
        text = path.read_text(encoding="utf-8")
        powershell_blocks = re.findall(r"```powershell\n(.*?)```", text, re.DOTALL)
        assert all("powershell.exe" not in block.lower() for block in powershell_blocks), path

    support_note = "PowerShell 7.4 or newer (`pwsh`)"
    for path in (
        Path("image/vmware-workstation/README.md"),
        Path("docs/reference/virtualization-artifacts.md"),
        Path("docs/reference/full-technical-reference.md"),
    ):
        assert support_note in path.read_text(encoding="utf-8")


def test_create_atlaso_vmware_test_vm_wrapper_uses_common_helpers():
    """Verify that create atlaso vmware test vm wrapper uses common helpers."""
    script = Path("scripts/windows/vmware/create-atlaso-test-vm.ps1").read_text(encoding="utf-8")
    vm_script = Path("scripts/windows/vmware/create-atlaso-vm.ps1").read_text(encoding="utf-8")
    nics_script = Path("scripts/windows/vmware/set-test-nics.ps1").read_text(encoding="utf-8")
    build_script = Path("scripts/windows/vmware/build-photon-image.ps1").read_text(encoding="utf-8")
    build_monitor = Path(
        "scripts/windows/vmware/Atlaso.WorkstationBuildMonitor.psm1"
    ).read_text(encoding="utf-8")
    packer_template = Path("image/vmware-workstation/atlaso-photon.pkr.hcl").read_text(encoding="utf-8")
    docs = Path("image/vmware-workstation/README.md").read_text(encoding="utf-8")

    assert "[string]$Name = 'Atlaso-VMware'" in script
    assert "[switch]$Redeploy" in script
    assert "[switch]$SkipLabNetworkAdapters" in script
    assert "[switch]$IncludeLabNetworkAdapters" in script
    assert "[switch]$ResetDataDisks" in script
    assert "[switch]$WaitForIp" in script
    assert "$PSBoundParameters.ContainsKey('WaitForIp')" in script
    assert "$waitForIpEnabled = if" in script
    assert "[switch]$TrustRootCa" in script
    assert "[string]$OnePasswordEnvironmentId = ''" in script
    assert "[string]$EnvironmentIdFile = ''" in script
    assert "[Alias('OnePasswordEnvironmentIdFile')]" in script
    assert "ExpectedEnvironmentIdSha256" in script
    assert "Assert-AtlasoOnePasswordEnvironmentId" in script
    assert "Atlaso.OnePasswordCredentials.psm1" in script
    assert ".atlaso-local\\onepassword-environment-id" in script
    assert "/.atlaso-local/" in Path(".gitignore").read_text(encoding="utf-8")
    assert script.index("Invoke-PendingAtlasoDevelopmentCaCleanup `") < script.index(
        "$OnePasswordEnvironmentId = Resolve-OnePasswordDevelopmentCaEnvironmentId `"
    )
    assert "Install the Environments-enabled beta CLI and retry." in script
    assert script.index("'1Password CLI\\op.exe'") < script.index("'Microsoft\\WinGet\\Links\\op.exe'")
    assert "[switch]$RootSshEnabled" in script
    assert "[string]$SshPublicKeyPath = ''" in script
    assert "[switch]$SkipSshKeyProvisioning" in script
    assert "Resolve-AtlasoWorkstationAdminSshPublicKey -Path $SshPublicKeyPath" in script
    assert "Pass either -SshPublicKeyPath or -SkipSshKeyProvisioning" in script
    assert "[int]$TimeoutSeconds = 300" in script
    assert "Install-ApplianceRootCa" in script
    assert "Waiting up to $TimeoutSeconds seconds for the Atlaso root CA" in script
    assert "Atlaso root CA is not ready; retrying in $PollSeconds seconds." in script
    assert "-TimeoutSec $requestTimeoutSeconds" in script
    assert "-ExpectedCertificatePath $developmentRootCaCertificatePath" in script
    assert "-TrustRootCa:$TrustRootCa" in script
    assert "Write-ConnectionSummary" in script
    assert "Get-AtlasoWorkstationSshHostKey" in script
    assert "ssh-keyscan" not in script
    assert "Write-SummaryRow" in script
    assert "-ForegroundColor Cyan" in script
    assert "-ForegroundColor DarkGray" in script
    assert "http://$IpAddress/ca/downloads/root-ca.pem" in script
    assert "-SkipCertificateCheck" not in script
    assert "Cert:\\CurrentUser\\Root" in script
    assert "certutil.exe -user -delstore Root" not in script
    assert "certutil.exe -f -user -addstore Root $rootCerPath" in script
    assert "-NoStart is not supported for normal test VMs" in script
    assert "if (($waitForIpEnabled -or $TrustRootCa) -and $readinessIdentity)" in script
    assert "-ExpectedHostname $FirstBootFqdn" in script
    assert "-PassThruIdentity" in script
    assert "Atlaso Workstation test VM ready" in script
    assert 'Write-SummaryRow -Label "Console URL:" -Value "https://$IpAddress/"' in script
    assert 'Write-SummaryRow -Label "API URL:" -Value "https://$IpAddress/openapi.json"' in script
    assert 'Write-SummaryRow -Label "Swagger URL:" -Value "https://$IpAddress/api/docs"' in script
    assert 'Write-SummaryRow -Label "Root CA URL:" -Value "http://$IpAddress/ca/downloads/root-ca.pem"' in script
    assert 'Write-SummaryRow -Label "SSH:" -Value "ssh admin@$IpAddress"' in script
    assert 'Write-Host "SSH host public key: $($sshHostKey.PublicKey)"' in script
    assert 'Write-Host "SSH host key fingerprint: $($sshHostKey.Fingerprint)"' in script
    assert "test-only passwordless sudo" in script
    assert 'Write-SummaryRow -Label "Lab DNS:"' in script
    assert "Windows DNS for lab FQDNs" in script
    assert "pass -TrustRootCa to trust this appliance root CA" in script
    assert "explicitly disabled with -WaitForIp:$false" in script
    assert "-ValueColor Yellow" in script
    assert "[string]$ManagementNetwork = 'VMnet8'" in script
    assert "[string]$ManagementNetwork = 'VMnet8'" in vm_script
    assert "[string]$ManagementNetwork = 'VMnet8'" in nics_script
    assert "prepare-networks.ps1" in script
    assert "create-atlaso-vm.ps1" in script
    assert "start-atlaso-vm.ps1" in script
    assert "get-atlaso-vm-ip.ps1" in script
    assert "remove-atlaso-vm.ps1" in script
    assert "Find-LatestApplianceVmx" in script
    assert "image\\vmware-workstation\\output" in script
    assert "image\\vmware-workstation\\test-vms\\$Name" in script
    assert "$effectiveSkipLabNetworkAdapters = -not $IncludeLabNetworkAdapters" in script
    assert "Atlaso-Depot.vmdk" in script
    assert "Atlaso-Backups.vmdk" in script
    assert "Atlaso.WorkstationCleanup.psm1" in script
    assert "expected Atlaso VMX is missing" in script
    assert "-ExpectedName $Name" in script
    assert "Assert-AtlasoStrictDescendantPath" in script
    assert "Assert-AtlasoVmwarePayloadProvenance -VmxPath $resolvedSourceVmx" in vm_script
    assert "Get-AtlasoVmwarePayloadLayout -VmxPath $targetVmx -RequireExactlyTwoVmdks" in vm_script
    assert vm_script.index(
        "Assert-AtlasoVmwarePayloadProvenance -VmxPath $resolvedSourceVmx"
    ) < vm_script.index("Invoke-Vmrun -Arguments @('-T', 'ws', 'clone'")
    assert "Set-VmxScsiDisk -Path $targetVmx -Unit 2 -DiskPath $resolvedDepotVmdkPath" in vm_script
    assert "Set-VmxScsiDisk -Path $targetVmx -Unit 3 -DiskPath $resolvedBackupVmdkPath" in vm_script
    assert "Set-VmxScsiDisk -Path $targetVmx -Unit 1 -DiskPath $resolvedDepotVmdkPath" not in vm_script
    assert '"disk.EnableUUID"          = "TRUE"' in packer_template
    assert "Refusing to reset VMware data disk outside the VM output directory" in script
    assert "vmrun.exe was not found" in vm_script
    assert "vmware-vdiskmanager.exe was not found" in vm_script
    assert "vmrun $($Arguments -join ' ') failed" in vm_script
    assert "New-DataVmdk" in vm_script
    assert vm_script.count("[ValidateScript({ $_ -eq '500GB' })]") == 2
    assert "[regex]::Matches($descriptor" in vm_script
    assert "$capacityBytes -ne 500GB" in vm_script
    assert "does not expose a readable VMDK capacity descriptor" in vm_script
    assert vm_script.index("foreach ($reusedDataDisk") < vm_script.index(
        "Invoke-Vmrun -Arguments @('-T', 'ws', 'clone'"
    )
    assert vm_script.index("Assert-ExistingDataVmdk -Path $reusedDataDisk.Path") < vm_script.index(
        "Invoke-Vmrun -Arguments @('-T', 'ws', 'clone'"
    )
    assert "Set-VmxScsiDisk" in vm_script
    assert "disk.EnableUUID" in vm_script
    assert "scsi0:$Unit" in vm_script
    assert "set-test-nics.ps1" in vm_script

    explicit_ssh_probe = "if (-not [string]::IsNullOrWhiteSpace($SshHost))"
    static_builder_probe = "elseif ($BuilderStaticIp)"
    assert "[int]$PackerStartupTimeoutSeconds = 2700" in build_script
    assert explicit_ssh_probe in build_script
    assert static_builder_probe in build_script
    assert build_script.index(explicit_ssh_probe) < build_script.index(static_builder_probe)
    assert build_script.count("Initialize-AtlasoWorkstationGui `") == 1
    assert "-ProcessLauncher $requireExistingUi" in build_script
    assert "Start-AtlasoWorkstationUiBreakawayProcess -FilePath $FilePath" not in build_script
    assert "Initialize-AtlasoWorkstationGui -VmrunPath $parentVmrunPath" in build_script
    assert "[scriptblock]$ProcessLauncher" in build_monitor
    assert "The VMware Workstation UI launcher returned an unexpected executable identity." in build_monitor
    child_gui_check = build_script.index("Initialize-AtlasoWorkstationGui `")
    assert build_script.index("$packerBuildInvoker = {") < child_gui_check < build_script.index(
        "Invoke-AtlasoMonitoredPackerBuild"
    )

    lifecycle_script = Path(
        "scripts/windows/vmware/run-lifecycle-test.ps1"
    ).read_text(encoding="utf-8")
    assert "Assert-AtlasoVmwarePayloadProvenance -VmxPath $resolvedSourceVmx" in lifecycle_script
    assert "Get-AtlasoVmwarePayloadLayout -VmxPath $targetVmx -RequireExactlyTwoVmdks" in lifecycle_script
    assert lifecycle_script.index(
        "Assert-AtlasoVmwarePayloadProvenance -VmxPath $resolvedSourceVmx"
    ) < lifecycle_script.index("Copy-Item -LiteralPath $sourceDirectory")
    assert '"$prefix.vnet"' in nics_script
    assert "if ($Vmnet -match '^(?i)vmnet(\\d+)$')" in nics_script
    assert '$Vmnet = "VMnet$($Matches[1])"' in nics_script
    assert "$prefix.virtualDev" in nics_script
    assert "vmxnet3" in nics_script
    assert "Join-Path $PSScriptRoot '..\\common\\Atlaso.PhotonImage.psm1'" in build_script
    assert "Join-Path $PSScriptRoot '..\\..\\..\\image\\vmware-workstation'" in build_script
    assert "[string]$ServiceVmnetName = 'VMnet1'" in build_script
    assert "service_vmnet_name = $ServiceVmnetName" in build_script
    assert "Using VMware services network $ServiceVmnetName" in build_script
    assert "prepare-networks.ps1" in build_script
    assert "Resolve-WorkstationVmrunPath -Path $VmrunPath" in build_script
    assert "Resolve-WorkstationOutputDirectory -PackerDirectory $PackerDirectory -OutputDirectory $OutputDirectory" in build_script
    assert "Atlaso.WorkstationCleanup.psm1" in build_script
    assert "Remove-AtlasoWorkstationArtifactRoot" in build_script
    assert "-ExpectedRemovalRoot $workstationOutputDirectory" in build_script
    assert build_script.index("Remove-AtlasoWorkstationArtifactRoot") < build_script.index(
        "Invoke-AtlasoPhotonImageBuild"
    )
    assert "Invoke-WorkstationVmrunBestEffort" not in build_script
    assert 'variable "service_vmnet_name"' in packer_template
    assert '"ethernet1.present"        = "TRUE"' in packer_template
    assert '"ethernet1.vnet"           = var.service_vmnet_name' in packer_template
    assert '"ethernet1.virtualDev"     = "vmxnet3"' in packer_template
    assert 'guest_os_type        = "vmware-photon-64"' in packer_template
    assert 'disk_adapter_type    = "pvscsi"' in packer_template
    assert '"sata0:0.present" = "FALSE"' in packer_template
    assert "-TrustRootCa" in docs
    assert "already trusted" in docs
    assert "connection summary" in docs
    assert "Windows DNS for lab FQDNs" in docs
    assert "Add-DnsClientNrptRule" in docs
    assert "Swagger URL" in docs
    assert "root certificate URL" in docs
    assert "ssh admin@<appliance-ip>" in docs
    assert "`vmxnet3` adapter" in docs
    assert "`-ServiceVmnetName`" in docs


def test_vmware_raw_vmx_workflows_inject_complete_first_boot_ovf_environment_before_start():
    """Verify raw Workstation clones receive the same complete first-boot contract as OVA deployments."""
    helper = Path("scripts/windows/vmware/Atlaso.WorkstationFirstBoot.ps1").read_text(encoding="utf-8")
    test_vm = Path("scripts/windows/vmware/create-atlaso-test-vm.ps1").read_text(encoding="utf-8")
    test_vm_credentials = Path(
        "scripts/windows/vmware/Invoke-AtlasoTestVmCredentials.ps1"
    ).read_text(encoding="utf-8")
    lifecycle = Path("scripts/windows/vmware/run-lifecycle-test.ps1").read_text(encoding="utf-8")
    lifecycle_wrapper = Path("scripts/windows/vmware/invoke-lifecycle-test.ps1").read_text(encoding="utf-8")
    customizer = Path("scripts/appliance/atlaso-vmware-ovf-customize.py").read_text(
        encoding="utf-8"
    )
    docs = Path("docs/reference/vmware-workstation-lifecycle-testing.md").read_text(encoding="utf-8")

    for key in (
        "atlaso.deployment_id",
        "atlaso.management_mode",
        "atlaso.cidr",
        "atlaso.gateway",
        "atlaso.ipv6_enabled",
        "atlaso.ipv6_cidr",
        "atlaso.ipv6_gateway",
        "atlaso.dns_servers",
        "atlaso.fqdn",
        "atlaso.admin_password",
        "atlaso.root_password",
        "atlaso.root_ssh_enabled",
    ):
        assert f"'{key}'" in helper
    assert "'atlaso.development_admin_ssh_public_key'" in helper
    assert "'atlaso.development_test_vm'" in helper
    assert "'atlaso.development_root_ca_certificate'" in helper
    assert "guestinfo.atlaso.test_vm_development_root_ca_private_key" in helper
    assert "[guid]::NewGuid().ToString('D')" in helper
    assert "[System.Security.SecurityElement]::Escape($Value)" in helper
    assert "[System.Xml.XmlConvert]::VerifyXmlChars($passwordInput.Value)" in helper
    assert "$passwordInput.Value -ne $passwordInput.Value.Trim()" in helper
    assert "$passwordInput.Value -match '[\\r\\n\\t]'" in helper
    assert "must contain at least 12 characters" in helper
    assert ".EndsWith('.local')" in helper
    assert "First-boot FQDN must not use .local." in helper
    assert "guestinfo.ovfEnv = " in helper
    assert "Write-Host" not in helper
    assert "Assert-AtlasoWorkstationEd25519PublicKey" in helper
    assert "Resolve-AtlasoWorkstationAdminSshPublicKey" in helper
    assert "[System.Xml.XmlConvert]::VerifyXmlChars($normalized)" in helper
    assert "guestinfo.atlaso.test_vm_ssh_host_ed25519_public_key" in helper
    assert "@('-T', 'ws', 'readVariable', $resolvedVmxPath, 'runtimeConfig', $guestInfoName)" in helper
    assert "ssh-keyscan" not in helper

    assert 'TEST_VM_SSH_HOST_KEY_GUESTINFO = "guestinfo.atlaso.test_vm_ssh_host_ed25519_public_key"' in customizer
    assert 'PROPERTY_DEVELOPMENT_TEST_VM = f"{PROPERTY_PREFIX}development_test_vm"' in customizer
    assert 'PROPERTY_DEVELOPMENT_ROOT_CA_CERTIFICATE = f"{PROPERTY_PREFIX}development_root_ca_certificate"' in customizer
    assert '"guestinfo.atlaso.test_vm_development_root_ca_private_key"' in customizer
    assert "def stage_development_root_ca(" in customizer
    assert "def publish_test_vm_ssh_host_key()" in customizer
    assert 'run_initialization_layer("SSH host key", publish_test_vm_ssh_host_key)' in customizer
    assert 'if config["normal_test_vm"]:' in customizer
    assert 'run_initialization_layer("test VM hostname", publish_test_vm_hostname)' in customizer

    assert "Atlaso.WorkstationFirstBoot.ps1" in test_vm
    assert "New-AtlasoWorkstationOvfEnvironment" in test_vm_credentials
    assert "-NormalTestVm" in test_vm_credentials
    assert "Set-AtlasoWorkstationOvfEnvironment -VmxPath $VmxPath" in test_vm_credentials
    assert "Invoke-OnePasswordDevelopmentCaChild" in test_vm
    assert "Invoke-AtlasoTestVmCredentialStage" in test_vm
    assert "Wait-AtlasoWorkstationDevelopmentRootCaPrivateKeyScrub" in test_vm
    assert test_vm.index("Invoke-AtlasoTestVmCredentialStage") < test_vm.index(
        "start-atlaso-vm.ps1"
    )

    assert "Atlaso.WorkstationFirstBoot.ps1" in lifecycle
    assert "New-AtlasoWorkstationOvfEnvironment" in lifecycle
    assert "-RootSshEnabled:($ApplianceSshUser -eq 'root')" in lifecycle
    assert "Set-AtlasoWorkstationOvfEnvironment -VmxPath $applianceVmx" in lifecycle
    assert "DevelopmentAdminSshPublicKey" not in lifecycle
    assert "DevelopmentRootCaCertificatePem" not in lifecycle
    assert "test_vm_development_root_ca_private_key" not in lifecycle
    assert "-NormalTestVm" not in lifecycle
    assert lifecycle.index("Set-AtlasoWorkstationOvfEnvironment -VmxPath $applianceVmx") < lifecycle.index(
        "Start-WorkstationVm -Path $vmx"
    )
    assert "[string]$SecretBundlePath" in lifecycle
    assert "Import-Clixml -LiteralPath $SecretBundlePath" in lifecycle
    assert "$ApplianceGuestPassword = $AdminPassword" in lifecycle
    assert "'--secret-stdin'" in lifecycle
    assert "'--password', $AdminPassword" not in lifecycle
    assert "'--appliance-ssh-password', $ApplianceGuestPassword" not in lifecycle
    assert "'--ssh-password', $SshPassword" not in lifecycle
    assert "'--vcf-backup-password', $VcfBackupPassword" not in lifecycle
    assert "-gp $SshPassword" not in lifecycle
    assert "[SecureString]$AdminPassword" in lifecycle_wrapper
    assert "[SecureString]$SshPassword" in lifecycle_wrapper
    assert "Export-Clixml -LiteralPath $secretBundlePath -Force" in lifecycle_wrapper
    assert "'-SecretBundlePath', $secretBundlePath" in lifecycle_wrapper
    assert "Remove-Item -LiteralPath $secretBundlePath -Force" in lifecycle_wrapper
    assert "[SecureString]$AdminPassword" in test_vm
    assert "[SecureString]$RootPassword" in test_vm
    assert "Read-Host -Prompt 'Atlaso bootstrap administrator password' -AsSecureString" not in test_vm
    assert "Read-Host -Prompt 'Photon root console password' -AsSecureString" not in test_vm
    ovf_block = test_vm.split("$credentialBridgeState = $null", 1)[1].split(
        "if ($SkipLabNetworkAdapters", 1
    )[0]
    assert "if (-not $WhatIfPreference)" in ovf_block
    assert "New-AtlasoTestVmCredentialBridgeState" in ovf_block
    assert "DEFAULT_ADMIN_PASSWORD" in test_vm_credentials
    assert "DEFAULT_ROOT_PASSWORD" in test_vm_credentials
    assert "complete Atlaso first-boot OVF environment" in docs
    assert "plan and result artifacts" in docs
    normal_test_vm_docs = docs.split("## Normal Test VM", 1)[1].split("## Fidelity Boundary", 1)[0]
    assert ".atlaso-local/onepassword-environment-id" in normal_test_vm_docs
    assert "-OnePasswordEnvironmentId` override" in normal_test_vm_docs
    assert "Environments-enabled beta 1Password CLI" in normal_test_vm_docs


def test_create_atlaso_vmware_test_vm_root_ca_retry_cleanup_is_idempotent():
    """Verify root CA retry cleanup handles missing files and dotted short temp paths."""
    script = Path("scripts/windows/vmware/create-atlaso-test-vm.ps1").read_text(encoding="utf-8")
    install_root_ca = script.split("function Install-ApplianceRootCa", 1)[1].split(
        "function Write-ConnectionSummary", 1
    )[0]

    assert "[System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())" in install_root_ca
    assert "[guid]::NewGuid().ToString('N')" in install_root_ca
    assert '[System.IO.Path]::Combine($tempRoot, "atlaso-$temporaryToken-root-ca.pem")' in install_root_ca
    assert "[System.IO.File]::Delete($rootPemPath)" in install_root_ca
    assert "File.Delete is idempotent for a missing file" in install_root_ca
    assert "valid dotted/short Windows paths" in install_root_ca
    assert "Best-effort cleanup must never mask" in install_root_ca
    assert "Test-Path -LiteralPath $rootPemPath" not in install_root_ca
    assert "Remove-Item -LiteralPath $rootPemPath" not in install_root_ca


def test_vmware_deploy_wheel_supports_secure_onepassword_password_deploy():
    """Verify that VMware deploy wheel uses a concealed 1Password Environment handoff."""
    script = Path("scripts/windows/vmware/deploy-wheel.ps1").read_text(encoding="utf-8")
    readme = Path("docs/reference/full-technical-reference.md").read_text(encoding="utf-8")
    image_readme = Path("image/vmware-workstation/README.md").read_text(encoding="utf-8")
    image_password_docs = image_readme.split("## Local Wheel Deploy", 1)[1].split("## OVF / OVA Export", 1)[0]
    image_password_docs = " ".join(image_password_docs.split())

    assert "[string]$OnePasswordEnvironmentId = ''" in script
    assert "[string]$OnePasswordAccount = ''" in script
    assert "[string]$OnePasswordPython = ''" in script
    assert "$script:PasswordDeployLockName = 'requirements-onepassword-deploy.lock'" in script
    assert "from onepassword import Client, DesktopAuth" in script
    assert "onepassword.environments.get_variables(args.onepassword_environment_id)" in script
    assert "DEFAULT_ADMIN_PASSWORD" in script
    assert "must contain one concealed DEFAULT_ADMIN_PASSWORD variable" in script
    assert "ATLASO_DEPLOY_SSH_PASSWORD" not in script
    assert "ATLASO_DEPLOY_RUNTIME_PASSWORD" not in script
    assert "function Initialize-PasswordDeployPythonPath" in script
    assert "Preparing the isolated 1Password SDK and Paramiko deployment runtime" in script
    assert "Stage-PasswordDeployPythonWheels" in script
    assert "'--require-hashes'" in script
    assert "'--no-index'" in script
    assert "'--find-links', $wheelDirectory" in script
    assert "'--target', $dependencyDirectory" in script
    assert "'-I', '-S', $pythonDeploy" in script
    assert "'--dependency-path', $pythonDependencyPath" in script
    assert "$env:PYTHONPATH" not in script
    assert "function Invoke-PasswordBackedDeploy" in script
    assert "import paramiko" in script
    assert 'sys.stdout.reconfigure(errors="replace")' in script
    assert "--local-worker-service" in script
    assert "--local-atlaso-service-drop-in" in script
    assert "--local-nginx-service-drop-in" in script
    assert '--local-trust-key", action="append"' in script
    assert '--remote-trust-key", action="append"' in script
    assert "At least one matched local and remote Atlaso release trust key is required." in script
    assert "image\\common\\update-trust" in script
    assert "No Atlaso release trust keys found under" in script
    assert "install -d -o root -g root -m 0755 /etc/atlaso/update-trust.d" in script
    assert 'install -o root -g root -m 0644 "$trust_key_path" "/etc/atlaso/update-trust.d/$trust_key_name"' in script
    assert "openssl pkey -pubin" in script
    assert "Atlaso release trust key is not Ed25519" in script
    assert "--local-runtime-dependency" in script
    assert "'authlib-*.whl'" in script
    assert "'joserfc-*.whl'" in script
    assert "'pycdlib-*.whl'" in script
    assert '"atlaso-runtime-wheels-$([guid]::NewGuid().ToString(\'N\'))"' in script
    assert "'-m', 'pip', 'wheel', '.', '-w', $generatedRuntimeDependencyRoot" in script
    assert "Remove-Item -LiteralPath $generatedRuntimeDependencyRoot -Recurse -Force" in script
    assert "Matched local and remote runtime dependency wheels are required." in script
    assert (
        '"$python" -m pip install --force-reinstall --no-compile --no-deps '
        '"$runtime_dependency_path"'
    ) in script
    assert '"$python" -m pip install --force-reinstall --no-compile --no-deps "$wheel"' in script
    assert "Atlaso site-packages resolved outside the active environment." in script
    assert 'find "$site_packages" -type f -name \'*.pyc\' -delete' in script
    assert "/etc/systemd/system/atlaso.service.d/atlaso-data-disks.conf" in script
    assert "/etc/systemd/system/nginx.service.d/atlaso-data-disks.conf" in script
    assert "systemctl enable atlaso-worker.service" in script
    assert "systemctl restart atlaso-worker.service" in script
    assert "systemctl is-active atlaso-worker.service" in script
    assert 'parser.add_argument("--dependency-path", required=True)' in script
    assert "sys.path.insert(0, args.dependency_path)" in script
    assert "supported 1Password SDK" in readme
    assert "beta-only Environment" in readme
    assert "read_paramiko_command_output" in script
    assert "recv_stderr_ready" in script
    assert "time.monotonic" in script
    assert "args.readiness_timeout" in script
    assert "DeploymentTimeoutSeconds" in script
    assert "$invokingProcess.CommandLine" not in script
    assert "client.set_missing_host_key_policy(paramiko.RejectPolicy())" in script
    assert "client.load_system_host_keys()" in script
    assert "transport.get_security_options()" in script
    assert "security_options.key_types" in script
    assert "auth_interactive" in script
    assert "connect_password_or_keyboard_interactive" in script
    assert "one[- ]?time" in script
    assert "multi[- ]?factor" in script
    assert "verification" in script
    assert "get_pty=False" in script
    assert "shutdown_write()" in script
    assert "ConvertTo-WindowsSshRemoteCommand" in script
    assert "base64 -d | sh" in script
    assert "sudo -S -p '' sh" in script
    assert "sanitized(stdout_text, password)" in script
    assert "if (-not $UsePasswordDeploy) {" in script
    assert "Test-RequiredCommand -Name 'scp'" in script
    assert "Invoke-PasswordBackedDeploy `" in script
    assert "-OnePasswordEnvironmentId '<atlaso-environment-id>'" in readme
    assert "-OnePasswordAccount '<account-name-or-id>'" in readme
    assert "-OnePasswordPython '<path-to-python-3.13.exe>'" in readme
    assert "temporary deployment directory" in readme
    assert "global Python" in readme
    assert "pinned 1Password SDK" in readme
    assert "Without `-OnePasswordEnvironmentId`, the helper preserves" in readme
    assert "`scp`/`ssh` key or agent workflow" in readme
    assert "-OnePasswordEnvironmentId '<atlaso-environment-id>'" in image_password_docs
    assert "-OnePasswordAccount '<account-name-or-id>'" in image_password_docs
    assert "-OnePasswordPython '<path-to-python-3.13.exe>'" in image_password_docs
    assert "../../docs/reference/full-technical-reference.md#vmware-workstation-workflow" in image_password_docs


def test_vmware_deploy_wheel_remote_path_contract():
    """Verify both SSH modes reject unsafe remote staging paths before deployment."""
    pwsh = shutil.which("pwsh")
    if pwsh is None:
        pytest.skip("PowerShell 7 is not available")

    result = subprocess.run(
        [
            pwsh,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            "tests/powershell/Test-DeployWheelRemotePaths.ps1",
            "-RepositoryRoot",
            str(Path.cwd()),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    docs = Path("docs/reference/full-technical-reference.md").read_text(encoding="utf-8")
    assert "`-RemoteDirectory` defaults to `/tmp`" in docs
    assert "password-backed and key/agent-backed SSH" in docs
    assert "apostrophes, dollar signs, backticks, semicolons" in docs


def test_vmware_deploy_wheel_onepassword_bridge_contract():
    """Verify the Windows 1Password bridge fails closed at its runtime boundaries."""
    pwsh = shutil.which("pwsh")
    if pwsh is None:
        pytest.skip("PowerShell 7 is not available")

    result = subprocess.run(
        [
            pwsh,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            "tests/powershell/Test-DeployWheelOnePassword.ps1",
            "-RepositoryRoot",
            str(Path.cwd()),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr


def test_vmware_normal_test_vm_development_ca_bridge_contract():
    """Verify normal test VM shared-CA defaults and fail-closed boundaries."""
    pwsh = shutil.which("pwsh")
    if pwsh is None:
        pytest.skip("PowerShell 7 is not available")

    result = subprocess.run(
        [
            pwsh,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            "tests/powershell/Test-CreateAtlasoTestVmDevelopmentCa.ps1",
            "-RepositoryRoot",
            str(Path.cwd()),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr


def test_vmware_password_deploy_omits_absent_optional_native_arguments():
    """Verify skipped deployment assets do not rely on native empty-argument preservation."""
    script = Path("scripts/windows/vmware/deploy-wheel.ps1").read_text(encoding="utf-8")
    password_deploy = script.split("function Invoke-PasswordBackedDeploy", 1)[1].split(
        "$resolvedRepoRoot = Resolve-RepoRoot", 1
    )[0]
    argument_construction = password_deploy.split("$deployArguments = @(", 1)[1]
    mandatory_arguments = argument_construction.split("foreach ($optionalPathPair", 1)[0]
    optional_arguments = argument_construction.split("foreach ($optionalPathPair", 1)[1]

    for option in (
        "--local-helper",
        "--local-console-manager",
        "--local-boot-installer",
        "--local-boot-theme",
        "--local-boot-background",
        "--local-inventory-linux-package",
        "--remote-helper",
        "--remote-console-manager",
        "--remote-boot-installer",
        "--remote-boot-theme",
        "--remote-boot-background",
        "--remote-inventory-linux-package",
    ):
        assert option not in mandatory_arguments
        assert option in optional_arguments

    assert "if (-not $localPath -and -not $remotePath)" in optional_arguments
    assert "continue" in optional_arguments
    assert "if (-not $localPath -or -not $remotePath)" in optional_arguments
    assert "Optional deployment paths must provide both" in optional_arguments
    assert "$deployArguments += $optionalPathPair" in optional_arguments


def test_vmware_deploy_wheel_uses_canonical_common_service_unit():
    """Verify live wheel deployment sources the guest-neutral Atlaso unit."""
    script = Path("scripts/windows/vmware/deploy-wheel.ps1").read_text(encoding="utf-8")

    assert "image\\common\\systemd\\atlaso.service" in script
    assert "image\\vmware-workstation\\systemd\\atlaso.service" not in script
    assert Path("image/common/systemd/atlaso.service").is_file()


def test_vmware_lifecycle_cleanup_only_removes_existing_lifecycle_vms():
    """Verify that vmware lifecycle cleanup only removes existing lifecycle vms."""
    wrapper = Path("scripts/windows/vmware/invoke-lifecycle-test.ps1").read_text(encoding="utf-8")
    cleanup_script = Path("scripts/windows/vmware/remove-lifecycle-vms.ps1").read_text(encoding="utf-8")
    cleanup_module = Path("scripts/windows/vmware/Atlaso.WorkstationCleanup.psm1").read_text(encoding="utf-8")
    runner = Path("scripts/windows/vmware/run-lifecycle-test.ps1").read_text(encoding="utf-8")
    docs = Path("docs/reference/vmware-workstation-lifecycle-testing.md").read_text(encoding="utf-8")

    assert "ParameterSetName = 'CleanupVms'" in wrapper
    assert "remove-lifecycle-vms.ps1" in wrapper
    assert "run-lifecycle-test.ps1" in wrapper
    cleanup_block = wrapper.split("if ($PSCmdlet.ParameterSetName -eq 'CleanupVms') {\n    &", 1)[1].split("return", 1)[0]
    assert "remove-lifecycle-vms.ps1" in cleanup_block
    assert "run-lifecycle-test.ps1" not in cleanup_block
    assert "ApplianceVmxPath" not in cleanup_block
    assert "ClientVmdkPath" not in cleanup_block
    assert "CleanupCreatedLab" not in cleanup_block
    assert "#requires -Version 7.0" in wrapper
    assert "Get-Command -Name 'pwsh' -CommandType Application" in wrapper
    assert "PowerShell 7 (pwsh) is required to run the VMware Workstation lifecycle test." in wrapper
    assert "& $powerShell7Path @arguments" in wrapper
    assert "powershell.exe" not in wrapper.lower()
    assert "Refusing VM cleanup for prefix '$LabName'" in cleanup_script
    assert "AtlasoWorkstationLifecycle" in cleanup_script
    assert "test-results\\vmware-workstation-lifecycle" in cleanup_script
    assert "vmrun.exe was not found" in cleanup_script
    assert "Get-AtlasoVmxDisplayName" in cleanup_script
    assert "'Get-AtlasoVmxDisplayName'" in cleanup_module
    assert "Refusing to remove VM outside Workstation lifecycle results" in cleanup_script
    assert "Atlaso.WorkstationCleanup.psm1" in cleanup_script
    assert "Remove-AtlasoWorkstationVmArtifacts" in cleanup_script
    assert "Remove-Item -LiteralPath $candidate.Directory -Recurse -Force" not in cleanup_script
    assert "VMware\\inventory.vmls" in cleanup_module
    assert "[Parameter(Mandatory = $false)]\n        [ValidateSet('running')]\n        [string]$State = 'running'" in cleanup_module
    inventory_resolver = cleanup_module.split("function Resolve-AtlasoWorkstationInventoryPath", 1)[1].split(
        "function Get-AtlasoScopedInventoryEntries", 1
    )[0]
    assert "Assert-AtlasoPathHasNoReparsePoint" not in inventory_resolver
    assert "Assert-AtlasoPathHasNoReparsePoint -Path $resolvedRemovalRoot" in cleanup_module
    assert "failed with exit code $exitCode" in cleanup_module
    assert "VMware Workstation VM remains running after stop succeeded" in cleanup_module
    assert "VMware Workstation VMX remains after deleteVM succeeded" in cleanup_module
    assert "VixHost_UnregisterVM" not in cleanup_module
    assert "'-T', 'ws', 'unregister'" not in cleanup_module
    assert "'-T', 'ws', 'deleteVM', $resolvedVmxPath" in cleanup_module
    assert cleanup_module.index("Confirm-AtlasoWorkstationVmInactive") < cleanup_module.index(
        "Remove-Item -LiteralPath $resolvedRemovalRoot -Recurse -Force"
    )
    snapshot = cleanup_module.rindex("$snapshot = Get-AtlasoRootSnapshot")
    inactive = cleanup_module.rindex("Confirm-AtlasoWorkstationVmInactive")
    provider_delete = cleanup_module.rindex("'-T', 'ws', 'deleteVM', $resolvedVmxPath")
    post_provider_guard = cleanup_module.index(
        "Assert-AtlasoRootSnapshotUnreplaced", provider_delete
    )
    final_running_check = cleanup_module.rindex("Assert-AtlasoWorkstationNoRunningTarget -VmrunPath")
    assert cleanup_module.count("Assert-AtlasoWorkstationNoRunningTarget -VmrunPath") == 2
    stale_repair = cleanup_module.rindex("Remove-AtlasoWorkstationStaleRegistrations")
    final_registration_check = cleanup_module.rindex("Test-AtlasoWorkstationVmxRegistered")
    final_replacement_guard = cleanup_module.index(
        "Assert-AtlasoRootSnapshotUnreplaced", final_registration_check
    )
    recursive_delete = cleanup_module.rindex(
        "Remove-Item -LiteralPath $resolvedRemovalRoot -Recurse -Force -ErrorAction Stop"
    )
    assert (
        snapshot
        < inactive
        < provider_delete
        < post_provider_guard
        < stale_repair
        < final_running_check
        < final_registration_check
        < final_replacement_guard
        < recursive_delete
    )
    assert "Start-Sleep" not in cleanup_module
    assert "InventorySnapshotsEqual" not in cleanup_module
    assert "VMware artifact directory remains after recursive cleanup; refusing to report success" in cleanup_module
    assert "Atlaso.WorkstationCleanup.psm1" in runner
    assert "Remove-AtlasoWorkstationVmArtifacts" in runner
    assert "Cleanup also failed; VM artifacts were preserved" in runner
    assert "Remove-Item -LiteralPath $vmRoot -Recurse -Force" not in runner
    assert "-CleanupVmsOnly" in docs


def test_lifecycle_vmware_script_supports_routing_wan_only_and_esxi_pxe_install():
    """Verify that lifecycle vmware script supports routing wan only and esxi pxe install."""
    wrapper = Path("scripts/windows/vmware/invoke-lifecycle-test.ps1").read_text(encoding="utf-8")
    runner = Path("scripts/windows/vmware/run-lifecycle-test.ps1").read_text(encoding="utf-8")
    cleanup_module = Path("scripts/windows/vmware/Atlaso.WorkstationCleanup.psm1").read_text(encoding="utf-8")

    assert "[switch]$RoutingWanOnly" in wrapper
    assert "[switch]$OidcOnly" in wrapper
    assert "[switch]$FullEsxiPxeInstall" in wrapper
    assert "[string]$PxeInstallerIsoPath = ''" in wrapper
    assert "$effectiveSkipBackupRestoreTest = [bool]($SkipBackupRestoreTest -or $RoutingWanOnly -or $OidcOnly)" in wrapper
    assert "if ($OidcOnly) { $arguments += '-OidcOnly' }" in wrapper
    assert "if ($RoutingWanOnly) { $arguments += '-RoutingWanOnly' }" in wrapper
    assert "if ($FullEsxiPxeInstall) { $arguments += '-FullEsxiPxeInstall' }" in wrapper
    assert "if ($PxeInstallerIsoPath) { $arguments += @('-PxeInstallerIsoPath', $PxeInstallerIsoPath) }" in wrapper
    assert "-OidcOnly, -RoutingWanOnly, and -FullEsxiPxeInstall are mutually exclusive." in wrapper
    assert "[SecureString]$EsxiPassword" in wrapper
    assert "Read-Host -Prompt 'ESXi root password for lifecycle probing' -AsSecureString" in wrapper
    assert "if (-not ($OidcOnly -or $RoutingWanOnly) -and $null -eq $VcfBackupPassword)" in wrapper
    assert wrapper.index("$secretBundlePath = ''\ntry {") < wrapper.index("Export-Clixml")
    assert wrapper.index("Export-Clixml") < wrapper.index("Remove-Item -LiteralPath $secretBundlePath -Force")
    assert "Remove-Item -LiteralPath $secretBundlePath -Force -ErrorAction Stop" in wrapper
    assert "-GuestPassword $esxiPasswordSecure" in runner
    assert "'--secret-stdin'" in runner
    assert "$secretPayload | & python @Arguments | Out-Host" in runner
    assert "'--esxi-password'," not in runner

    assert "function Get-GuestIPv4ViaGuestOps" in runner
    assert "function Invoke-VmrunBounded" in runner
    assert "vmrun timed out after $TimeoutSeconds seconds" in runner
    assert "function Get-GuestIPv4FromHostNeighbor" in runner
    assert "function Get-VmxEthernetMacAddress" in runner
    assert "Get-NetNeighbor -AddressFamily IPv4" in runner
    assert "ip -4 -br addr" in runner
    assert "'copyFileFromGuestToHost', $Path, $guestOutput, $hostOutput" in runner
    assert "'getGuestIPAddress', $Path" in runner
    assert "-TimeoutSeconds 15" in runner
    assert "function Get-PlinkHostKey" in runner
    assert "function Test-ApplianceOpenApi" in runner
    assert "& $curl.Source -k -f -sS $Url" in runner
    assert "ServerCertificateValidationCallback = { $true }" in runner
    assert "$applianceHostKey = Get-PlinkHostKey -HostName $ApplianceIPAddress" in runner
    assert "'--appliance-ssh-hostkey', $applianceHostKey" in runner
    assert "'--client-a-hostkey', $clientAHostKey" in runner
    assert "function Sync-ApplianceHelperScript" in runner
    assert "scripts\\appliance\\atlaso-helper" in runner
    assert "copyFileFromHostToGuest $ApplianceVmx $localHelper $guestTemp" in runner
    assert "install -o root -g root -m 0755 $quotedTemp /opt/atlaso/bin/atlaso-helper" in runner
    assert "function Sync-ApplianceApplicationWheel" in runner
    assert "python -m pip wheel $repoRoot --no-deps -w $wheelRoot" in runner
    assert "pip install --force-reinstall --no-deps $quotedWheel" in runner
    assert "systemctl restart atlaso.service" in runner
    assert "$applianceWheelPath = Sync-ApplianceApplicationWheel -ApplianceVmx $applianceVmx" in runner
    assert "function Register-WorkstationVm" in runner
    assert "$resolvedVmrun @Arguments" in runner
    assert "ws register $Path" in runner
    assert "'-T', 'ws', 'deleteVM', $resolvedVmxPath" in cleanup_module
    assert "Invoke-AtlasoWorkstationVixUnregister" not in cleanup_module
    assert "Register-WorkstationVm -Path $Path" in runner
    assert "function New-EsxiPxeVm" in runner
    assert "[string]$PxeClientIPAddress = ''" in runner
    assert "[int]$EsxiInstallProbeDelaySeconds = 300" in runner
    assert "Waiting $EsxiInstallProbeDelaySeconds seconds before probing ESXi guest operations." in runner
    assert "esxi_probe_delay_seconds = $EsxiInstallProbeDelaySeconds" in runner
    assert "if ($PxeClientIPAddress)" in runner
    assert "@('--pxe-client-ip', $PxeClientIPAddress)" in runner
    assert "$Vmnet.StartsWith('lan:')" in runner
    assert "if ($Vmnet -match '^(?i)vmnet(\\d+)$')" in runner
    assert '$Vmnet = "VMnet$($Matches[1])"' in runner
    assert "function Resolve-LanSegmentId" in runner
    assert "pref.namedPVNs$nextIndex.name" in runner
    assert "connectionType\" -Value 'pvn'" in runner
    assert "$prefix.pvnID" in runner
    assert "Remove-VmxValue -Path $Path -Key \"$prefix.vnet\"" in runner
    assert "sata0:0.deviceType = \"disk\"" in runner
    assert "sata0:1.deviceType = \"cdrom-image\"" in runner
    assert "Set-VmxNetworkAdapter -Path $vmxPath -Index $index -Vmnet $Networks[$index] -VirtualDev 'e1000'" in runner
    assert "firmware = \"efi\"" in runner
    assert "uefi.secureBoot.enabled = \"FALSE\"" in runner
    assert "vhv.enable = \"FALSE\"" in runner
    assert "& $vdiskManager -c -s 32GB -a pvscsi -t 0 $diskTarget" in runner
    assert 'virtualHW.version = "22"' in runner
    assert 'pciBridge0.present = "TRUE"' in runner
    assert 'pciBridge4.virtualDev = "pcieRootPort"' in runner
    assert 'pciBridge7.functions = "8"' in runner
    assert 'vmci0.present = "TRUE"' in runner
    assert 'virtualHW.productCompatibility = "hosted"' in runner
    assert 'tools.syncTime = "FALSE"' in runner
    assert 'floppy0.present = "FALSE"' in runner
    assert 'guestOS = "vmkernel9"' in runner
    assert 'scsi0.virtualDev = "pvscsi"' in runner
    assert "Set-VmxNetworkAdapter -Path $vmxPath -Index 0 -Vmnet $Network -StaticMac $MacAddress -VirtualDev 'vmxnet3'" in runner
    assert "function Resolve-ApplianceEsxiIsoPath" in runner
    assert "copyFileFromHostToGuest $ApplianceVmx $localIso.Path $guestTemp" in runner
    assert "'--routing-wan-only'" in runner
    assert "'--pxe-test-mode', $(if ($FullEsxiPxeInstall) { 'esxi' } else { 'linux' })" in runner
    assert "Add-LifecycleResultStep -ResultDirectory $initialResultRoot -Name 'esxi-pxe-install-check' -Status 'passed'" in runner
    assert "--password-stdin" in runner
    assert "--password $SshPassword" not in runner
    assert "function Remove-ClientSeedArtifacts" in runner
    assert "Remove-Item -LiteralPath $seedPath -Force -ErrorAction Stop" in runner
    assert "Credential-bearing client seed ISO remains after cleanup" in runner
    assert runner.index("Remove-ClientSeedArtifacts `") > runner.index(
        "Invoke-LifecyclePython -Arguments $initialPythonArgs"
    )
    assert runner.count("Remove-ClientSeedArtifacts `") == 2
    assert "$seedCleanupFailure" in runner


def test_nocloud_seed_helper_writes_client_cloud_init_contract():
    """Verify that nocloud seed helper writes client cloud init contract."""
    script = Path("scripts/interop/create_nocloud_seed_iso.py").read_text(encoding="utf-8")

    assert 'vol_ident="cidata"' in script
    assert "ssh_authorized_keys:" in script
    assert 'parser.add_argument("--public-key", default="")' in script
    assert '"--password-stdin"' in script
    assert "load_password_from_stdin(args, sys.stdin)" in script
    assert "Either --public-key or --password is required" in script
    assert "openssl" in script
    assert "sshpass" in script
    assert "chrony-nts" in script
    assert "atlaso-refresh-test-dhcp" in script
    assert "joliet_path=f\"/{name}\"" in script


def test_nocloud_seed_helper_reads_client_password_from_stdin():
    """Verify the seed helper loads a client password without argv exposure."""
    helper = load_nocloud_seed_helper()
    args = helper.argparse.Namespace(password="", password_stdin=True)

    helper.load_password_from_stdin(args, io.StringIO("ClientSecret!\n"))

    assert args.password == "ClientSecret!"


@pytest.mark.parametrize("stdin_value", ["", "\n", "first\nsecond\n", "x" * 4097])
def test_nocloud_seed_helper_rejects_invalid_stdin_password(stdin_value):
    """Verify malformed stdin password payloads fail closed.

    Args:
        stdin_value: Empty, multiline, or oversized password payload under test.
    """
    helper = load_nocloud_seed_helper()
    args = helper.argparse.Namespace(password="", password_stdin=True)

    with pytest.raises(ValueError):
        helper.load_password_from_stdin(args, io.StringIO(stdin_value))


def test_prepare_tiny_linux_client_downloads_verifies_and_converts_alpine():
    """Verify that prepare tiny linux client downloads verifies and converts alpine."""
    script = Path("scripts/windows/vmware/prepare-tiny-linux-client.ps1").read_text(encoding="utf-8")

    assert "dl-cdn.alpinelinux.org/alpine/v3.24/releases/cloud" in script
    assert "generic_alpine-3.24.1-x86_64-uefi-cloudinit-r0.qcow2" in script
    assert "-ExpectedDigest $ExpectedSha512" in script
    assert "Get-FileHash -Algorithm SHA512" in script
    assert "qemu-img convert -p -f qcow2 -O vmdk -o subformat=monolithicSparse" in script
    assert "atlaso-tiny-linux-client.vmdk" in script


def test_lifecycle_runner_plan_includes_ca_and_global_apply_units():
    """Verify that lifecycle runner plan includes ca and global apply units."""
    module = load_lifecycle_runner()
    args = module.parse_args(
        [
            "--password",
            "test",
            "--plan-only",
        ]
    )

    plan = module.lifecycle_plan(args)

    assert plan["apply_units"] == [
        "local_users",
        "network",
        "firewall",
        "wan",
            "dnsmasq",
            "esxi_pxe",
            "esx_storage",
            "ca",
        "ntpd",
        "kms",
        "ldap",
        "appliance_settings",
        "vcf_backups",
        "vcf_offline_depot",
        "public_services",
    ]
    assert plan["interfaces"]["vlan"]["name"] == "eth2.50"
    assert plan["interfaces"]["client_ca_request"]["name"] == "eth3"
    assert plan["interfaces"]["client_ca_request"]["ip_cidr"] == "192.168.49.20/24"
    assert any("CA desired state" in check and "client-side verification" in check for check in plan["checks"])
    assert any("Alpine chrony-nts authenticated synchronization" in check for check in plan["checks"])
    assert "VCF Backup desired state, local user sync, SFTP listener, and client probe" in plan["checks"]
    assert "VCF Offline Depot browser login, curl/wget Basic auth, and Local Users password rotation" in plan["checks"]
    assert any("Managed LDAP desired state" in check for check in plan["checks"])
    assert plan["pxe_boot"]["enabled"] is False
    assert plan["pxe_boot"]["mode"] == "linux"


def test_lifecycle_runner_uses_supported_network_roles():
    """Verify that lifecycle runner uses supported network roles."""
    script = Path("scripts/interop/lifecycle_test.py").read_text(encoding="utf-8")

    assert '"mode": "access", "role": "access"' in script
    assert '"mode": "trunk", "role": "unused"' in script
    assert 'role="access"' in script
    assert '"role": "lab"' not in script
    assert '"role": "trunk"' not in script


def test_lifecycle_runner_supports_alpine_doas_and_plink_hostkeys():
    """Verify that lifecycle runner supports alpine doas and plink hostkeys."""
    script = Path("scripts/interop/lifecycle_test.py").read_text(encoding="utf-8")

    assert "--client-a-hostkey" in script
    assert "--client-b-hostkey" in script
    assert '"-hostkey", hostkey' in script
    assert "command -v doas" in script
    assert "ip route replace {wan.network} via {site_ip} dev eth1" in script
    assert "traceroute -n {wan_peer_ip}" in script


def test_lifecycle_runner_covers_ca_vcf_backups_wan_noise_and_console_summary():
    """Verify that lifecycle runner covers ca vcf backups wan noise and console summary."""
    script = Path("scripts/interop/lifecycle_test.py").read_text(encoding="utf-8")

    assert "direct_dns_a_query_command" in script
    assert "base64 -d | python3 -" in script
    assert '"dnsmasq": "test -f /etc/atlaso/dnsmasq.d/atlaso.conf && getent hosts interop-appliance.atlaso.internal"' not in script
    assert "--vcf-backup-password" in script
    assert "--client-ca-request-interface" in script
    assert "configure_management_https" in script
    assert "management_https_check" in script
    assert "apply-appliance-settings-unit" in script
    assert "HTTP management endpoint should redirect after HTTPS apply" in script
    assert "https_request_unverified" in script
    assert "configure-vcf-backups" in script
    assert "configure-kms" in script
    assert '"/vsphere-key-providers"' in script
    assert "not-configured-without-external-public-certificate" in script
    assert "kms_external_trust_required" in script
    assert '"local_console"' in script
    assert "systemctl is-active atlaso-console.service" in script
    assert "systemctl is-enabled getty@tty1.service" in script
    assert "systemctl show getty@tty2.service" in script
    assert '\\"maintenance_isolation\\": false' in script
    assert "apply-kms-unit" in script
    assert "Appliance apply task failed" in script
    assert "stderr:" in script
    assert "stdout:" in script
    assert "vcf-backup-client-check" in script
    assert "sshpass -p" in script
    assert "redact_text" in script
    assert '"local_users", "network", "firewall", "wan", "dnsmasq", "esxi_pxe", "vcf_backups"' in script
    assert "certificate_summary" in script
    assert "root_ca" in script
    assert "ca-client-certificate-request" in script
    assert "ca-client-certificate-check" in script
    assert "create_client_csr" in script
    assert '"listen_interfaces_present": "1"' in script
    assert '"listen_interfaces": [args.site_interface]' in script
    assert "ca_request_url" in script
    assert "Cookie: " in script
    assert "--connect-timeout 10 --max-time 30" in script
    assert "except subprocess.TimeoutExpired" in script
    assert "SSH command timed out after 120 seconds." in script
    assert "VCF KMIP client" in script
    assert "verify_certificate_signed_by_root" in script
    assert "client_a_download" in script
    assert "-o /dev/null -w '%{http_code}'" in script
    assert "apply-connectivity-units" in script
    assert "apply-ca-unit" in script
    assert "configure-ntp" in script
    assert "apply-ntp-unit" in script
    assert "ntp-client-checks" in script
    assert '"ntp_settings" not in data or "chrony_settings" in data' in script
    assert "tc qdisc show dev {args.wan_interface} | grep netem | grep delay | grep 25ms" in script
    assert "Lifecycle summary" in script
    assert "Result JSON:" in script


def test_lifecycle_runner_summarizes_apply_validation_html():
    """Verify that lifecycle runner summarizes apply validation html."""
    module = load_lifecycle_runner()
    summary = module.summarize_html_response(
        """
        <!doctype html>
        <html>
          <body>
            <aside>Atlaso navigation noise</aside>
            <div class="alert error">Resolve validation errors before submitting appliance changes.</div>
            <article>
              <strong>Certificate Authority</strong>
              <div class="alert error"><div>CA listen interfaces must use configured access targets.</div></div>
            </article>
          </body>
        </html>
        """
    )

    assert summary.startswith("Resolve validation errors before submitting appliance changes.")
    assert "CA listen interfaces must use configured access targets." in summary
    assert "doctype" not in summary.lower()
