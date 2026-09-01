packer {
  required_version = ">= 1.10.0"

  required_plugins {
    vmware = {
      version = "= 2.1.5"
      source  = "github.com/vmware/vmware"
    }
  }
}

variable "vm_name" {
  type        = string
  description = "Canonical task- or release-owned Photon builder identity supplied by the supported wrapper."

  validation {
    condition = can(regex(
      "^Atlaso-(PR-[1-9][0-9]*-Photon-Builder-VMware(-[a-z0-9]+(-[a-z0-9]+)*)?|Release-v[0-9]+-[0-9]+-[0-9]+-[0-9a-f]{12}-Photon-Builder-VMware(-run-[1-9][0-9]*)?)$",
      var.vm_name
    ))
    error_message = "Vm_name must be one canonical PR-owned or release-owned Atlaso Photon builder identity."
  }
}

variable "output_directory" {
  type        = string
  description = "Canonical output directory whose final component exactly matches vm_name."

  validation {
    condition = can(regex(
      "/Atlaso-(PR-[1-9][0-9]*-Photon-Builder-VMware(-[a-z0-9]+(-[a-z0-9]+)*)?|Release-v[0-9]+-[0-9]+-[0-9]+-[0-9a-f]{12}-Photon-Builder-VMware(-run-[1-9][0-9]*)?)/?$",
      replace(var.output_directory, "\\", "/")
    ))
    error_message = "Output_directory must end with one canonical PR-owned or release-owned Atlaso Photon builder identity."
  }
}

variable "vmnet_name" {
  type        = string
  default     = "VMnet8"
  description = "VMware Workstation network used by the Packer builder NIC."
}

variable "service_vmnet_name" {
  type        = string
  default     = "VMnet1"
  description = "VMware Workstation network attached as the appliance service NIC after the management NIC."
}

variable "headless" {
  type        = bool
  default     = false
  description = "Run the VMware Workstation builder without a visible console window."
}

variable "iso_url" {
  type        = string
  description = "Photon OS 5.0 ISO URL. Use the current Photon 5.0 full ISO from VMware package downloads."
}

variable "iso_checksum" {
  type        = string
  description = "Photon OS ISO checksum in Packer format, for example sha256:<checksum>."
}

variable "ssh_username" {
  type    = string
  default = "atlaso-build"

  validation {
    condition     = can(regex("^[a-z_][a-z0-9_-]*$", var.ssh_username))
    error_message = "SSH username must be one safe Linux account name."
  }
}

variable "ssh_password" {
  type      = string
  default   = "Atlaso-ChangeMe-Photon!"
  sensitive = true
}

variable "bootstrap_admin_password" {
  type        = string
  default     = "Atlaso-ChangeMe-Admin!"
  sensitive   = true
  description = "Initial Atlaso admin password, separate from the build-time SSH password."
}

variable "ssh_host" {
  type        = string
  default     = null
  description = "Optional Photon guest SSH host override."
}

variable "iso_contains_kickstart" {
  type        = bool
  default     = false
  description = "Set true only for a Photon ISO remastered by scripts/windows/vmware/build-photon-image.ps1 with photon-ks.json and the Atlaso GRUB auto-install entry embedded."

  validation {
    condition     = var.iso_contains_kickstart
    error_message = "Iso_contains_kickstart must be true. Run scripts/windows/vmware/build-photon-image.ps1 so it creates and passes the remastered Photon ISO."
  }
}

variable "builder_static_ip" {
  type        = string
  default     = "192.168.167.30/24"
  description = "Static IP or CIDR for the installed Photon builder VM. Packer uses this address for SSH when ssh_host is unset."
}

variable "builder_static_netmask" {
  type        = string
  default     = "255.255.255.0"
  description = "Netmask for builder_static_ip when using Photon legacy static kickstart networking."
}

variable "builder_static_gateway" {
  type        = string
  default     = "192.168.167.2"
  description = "Gateway for builder_static_ip. For the default Workstation NAT vmnet this is the VMware NAT gateway."
}

variable "builder_static_dns" {
  type        = list(string)
  default     = ["1.1.1.1", "9.9.9.9"]
  description = "DNS servers for builder_static_ip."
}

variable "final_mgmt_address" {
  type        = string
  default     = "dhcp"
  description = "Final Atlaso appliance management address after provisioning, or dhcp for VMware NAT-assigned management."
}

variable "final_mgmt_gateway" {
  type        = string
  default     = ""
  description = "Final Atlaso appliance management gateway after provisioning. Leave blank when final_mgmt_address is dhcp."
}

variable "final_mgmt_interface" {
  type        = string
  default     = "eth0"
  description = "Final Atlaso appliance management interface after provisioning."
}

variable "pip_global_index" {
  type        = string
  default     = ""
  description = "Optional pip global.index value. Empty keeps default pip behavior."
}

variable "pip_global_index_url" {
  type        = string
  default     = ""
  description = "Optional pip global.index-url value. Empty keeps default pip behavior."
}

variable "dry_run_system_adapters" {
  type        = bool
  default     = true
  description = "Keep Atlaso system adapters in dry-run mode. Set false only for disposable lifecycle/demo images that should mutate Photon services."
}

locals {
  builder_static_address       = var.builder_static_ip != "" ? split("/", var.builder_static_ip)[0] : ""
  builder_static_dns_text      = join(" ", var.builder_static_dns)
  bootstrap_admin_password     = var.bootstrap_admin_password
  dry_run_system_adapters_text = var.dry_run_system_adapters ? "true" : "false"
  ssh_password_stdin_base64    = base64encode("${var.ssh_password}\n")
  # Packer variable validation cannot compare two variables. Force template
  # evaluation to fail when the canonical output leaf and VM name diverge.
  verified_output_directory = basename(replace(var.output_directory, "\\", "/")) == var.vm_name ? var.output_directory : regex("^$", var.output_directory)
}

source "vmware-iso" "photon" {
  vm_name              = var.vm_name
  output_directory     = local.verified_output_directory
  guest_os_type        = "vmware-photon-64"
  version              = 21
  headless             = var.headless
  cpus                 = 4
  memory               = 4096
  disk_size            = 40960
  disk_additional_size = [20480]
  disk_adapter_type    = "pvscsi"
  disk_type_id         = 0
  skip_compaction      = false
  cdrom_adapter_type   = "sata"
  network              = var.vmnet_name
  network_adapter_type = "vmxnet3"
  iso_url              = var.iso_url
  iso_checksum         = var.iso_checksum
  communicator         = "ssh"
  ssh_host             = var.ssh_host != null ? var.ssh_host : (local.builder_static_address != "" ? local.builder_static_address : null)
  ssh_port             = 22
  ssh_username         = var.ssh_username
  ssh_password         = var.ssh_password
  ssh_timeout          = "45m"
  shutdown_command     = "printf '%s' '${local.ssh_password_stdin_base64}' | base64 -d | sudo -S systemd-run --quiet --unit=atlaso-image-build-finalize --on-active=1s --property=Type=oneshot /opt/atlaso/bin/atlaso-finalize-image-build ${var.ssh_username}"

  vmx_data = {
    "firmware"                 = "efi"
    "disk.EnableUUID"          = "TRUE"
    "uefi.secureBoot.enabled"  = "FALSE"
    "ethernet1.present"        = "TRUE"
    "ethernet1.connectionType" = "custom"
    "ethernet1.vnet"           = var.service_vmnet_name
    "ethernet1.virtualDev"     = "vmxnet3"
    "ethernet1.addressType"    = "generated"
    "ethernet1.startConnected" = "TRUE"
  }

  vmx_data_post = {
    "sata0:0.present" = "FALSE"
  }
}

build {
  name    = "atlaso-photon-vmware-workstation"
  sources = ["source.vmware-iso.photon"]

  provisioner "shell" {
    inline = [
      "mkdir -p /tmp/atlaso-src/scripts /tmp/atlaso-src/image/common /tmp/atlaso-src/image/vmware-workstation /tmp/atlaso-src/image/inventory-linux /tmp/atlaso-src/third_party"
    ]
  }

  provisioner "file" {
    source      = "../../atlaso"
    destination = "/tmp/atlaso-src/atlaso"
  }

  provisioner "file" {
    source      = "../../pyproject.toml"
    destination = "/tmp/atlaso-src/pyproject.toml"
  }

  provisioner "file" {
    source      = "../../requirements-appliance.lock"
    destination = "/tmp/atlaso-src/requirements-appliance.lock"
  }

  provisioner "file" {
    source      = "../../README.md"
    destination = "/tmp/atlaso-src/README.md"
  }

  provisioner "file" {
    source      = "../../scripts/appliance"
    destination = "/tmp/atlaso-src/scripts/appliance"
  }

  provisioner "file" {
    source      = "../../scripts/check_photon_compatibility.py"
    destination = "/tmp/atlaso-src/scripts/check_photon_compatibility.py"
  }

  provisioner "file" {
    source      = "../../scripts/generate_third_party_notices.py"
    destination = "/tmp/atlaso-src/scripts/generate_third_party_notices.py"
  }

  provisioner "file" {
    source      = "../../scripts/third_party_notices.json"
    destination = "/tmp/atlaso-src/scripts/third_party_notices.json"
  }

  provisioner "file" {
    source      = "../../scripts/version.py"
    destination = "/tmp/atlaso-src/scripts/version.py"
  }

  provisioner "file" {
    source      = "../../scripts/run_tdnf_with_progress.py"
    destination = "/tmp/atlaso-src/scripts/run_tdnf_with_progress.py"
  }

  provisioner "file" {
    source      = "../../third_party/ipxe"
    destination = "/tmp/atlaso-src/third_party/ipxe"
  }

  provisioner "file" {
    source      = "../inventory-linux/README.md"
    destination = "/tmp/atlaso-src/image/inventory-linux/README.md"
  }

  provisioner "file" {
    source      = "systemd"
    destination = "/tmp/atlaso-src/image/vmware-workstation/systemd"
  }

  provisioner "file" {
    source      = "../common/systemd"
    destination = "/tmp/atlaso-src/image/common/systemd"
  }

  provisioner "file" {
    source      = "../common/scripts"
    destination = "/tmp/atlaso-src/image/common/scripts"
  }

  provisioner "file" {
    source      = "../common/guest-agents"
    destination = "/tmp/atlaso-src/image/common/guest-agents"
  }

  provisioner "file" {
    source      = "../common/udev"
    destination = "/tmp/atlaso-src/image/common/udev"
  }

  provisioner "file" {
    source      = "../common/data-disks.conf"
    destination = "/tmp/atlaso-src/image/common/data-disks.conf"
  }

  provisioner "file" {
    source      = "../common/sudoers.d"
    destination = "/tmp/atlaso-src/image/common/sudoers.d"
  }

  provisioner "file" {
    source      = "../common/boot"
    destination = "/tmp/atlaso-src/image/common/boot"
  }

  provisioner "file" {
    source      = "../common/update-trust"
    destination = "/tmp/atlaso-src/image/common/update-trust"
  }

  provisioner "file" {
    source      = "../common/powershell"
    destination = "/tmp/atlaso-src/image/common/powershell"
  }

  provisioner "shell" {
    environment_vars = [
      "ATLASO_GUEST_PLATFORM=vmware",
      "ATLASO_SYSTEM_CONTENT_DISK=true",
      "ATLASO_ROOT_SCSI_TUPLE=0:0:0",
      "ATLASO_SYSTEM_SCSI_TUPLE=0:1:0",
      "ATLASO_ROOT_DISK_SIZE_BYTES=42949672960",
      "ATLASO_SYSTEM_DISK_SIZE_BYTES=21474836480",
      "ATLASO_IMAGE_ASSET_DIR=image/vmware-workstation",
      "ATLASO_BOOTSTRAP_ADMIN_PASSWORD=${local.bootstrap_admin_password}",
      "ATLASO_DRY_RUN_SYSTEM_ADAPTERS=${local.dry_run_system_adapters_text}",
      "ATLASO_MGMT_ADDRESS=${var.final_mgmt_address}",
      "ATLASO_MGMT_GATEWAY=${var.final_mgmt_gateway}",
      "ATLASO_MGMT_IPV4_METHOD=${var.final_mgmt_address == "dhcp" ? "dhcp" : "static"}",
      "ATLASO_MGMT_INTERFACE=${var.final_mgmt_interface}",
      "ATLASO_MGMT_DNS=${local.builder_static_dns_text}",
      "ATLASO_PIP_GLOBAL_INDEX=${var.pip_global_index}",
      "ATLASO_PIP_GLOBAL_INDEX_URL=${var.pip_global_index_url}"
    ]
    execute_command = "printf '%s' '${local.ssh_password_stdin_base64}' | base64 -d | sudo -S -E sh -c '{{ .Vars }} {{ .Path }}'"
    script          = "${path.root}/../common/scripts/provision-atlaso.sh"
  }
}
