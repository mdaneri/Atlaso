packer {
  required_version = ">= 1.10.0"

  required_plugins {
    vmware = {
      version = ">= 2.1.3"
      source  = "github.com/vmware/vmware"
    }
  }
}

variable "vm_name" {
  type    = string
  default = "LabFoundry-Photon-Builder-VMware"
}

variable "output_directory" {
  type    = string
  default = "output/labfoundry-photon-vmware-workstation"
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
  default = "labfoundry-build"
}

variable "ssh_password" {
  type      = string
  default   = "LabFoundry-ChangeMe-Photon!"
  sensitive = true
}

variable "bootstrap_admin_password" {
  type        = string
  default     = ""
  sensitive   = true
  description = "Initial LabFoundry admin password. If empty, the build falls back to ssh_password for compatibility."
}

variable "ssh_host" {
  type        = string
  default     = null
  description = "Optional Photon guest SSH host override."
}

variable "iso_contains_kickstart" {
  type        = bool
  default     = false
  description = "Set true only for a Photon ISO remastered by scripts/windows/vmware/build-photon-image.ps1 with photon-ks.json and the LabFoundry GRUB auto-install entry embedded."

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
  description = "Final LabFoundry appliance management address after provisioning, or dhcp for VMware NAT-assigned management."
}

variable "final_mgmt_gateway" {
  type        = string
  default     = ""
  description = "Final LabFoundry appliance management gateway after provisioning. Leave blank when final_mgmt_address is dhcp."
}

variable "final_mgmt_interface" {
  type        = string
  default     = "eth0"
  description = "Final LabFoundry appliance management interface after provisioning."
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
  description = "Keep LabFoundry system adapters in dry-run mode. Set false only for disposable lifecycle/demo images that should mutate Photon services."
}

locals {
  builder_static_address       = var.builder_static_ip != "" ? split("/", var.builder_static_ip)[0] : ""
  builder_static_dns_text      = join(" ", var.builder_static_dns)
  bootstrap_admin_password     = var.bootstrap_admin_password != "" ? var.bootstrap_admin_password : var.ssh_password
  dry_run_system_adapters_text = var.dry_run_system_adapters ? "true" : "false"
}

source "vmware-iso" "photon" {
  vm_name              = var.vm_name
  output_directory     = var.output_directory
  guest_os_type        = "vmware-photon-64"
  version              = 21
  headless             = var.headless
  cpus                 = 4
  memory               = 4096
  disk_size            = 40960
  disk_adapter_type    = "pvscsi"
  disk_type_id         = 0
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
  shutdown_command     = "echo '${var.ssh_password}' | sudo -S systemctl poweroff"

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
  name    = "labfoundry-photon-vmware-workstation"
  sources = ["source.vmware-iso.photon"]

  provisioner "shell" {
    inline = [
      "mkdir -p /tmp/labfoundry-src/scripts /tmp/labfoundry-src/image/common /tmp/labfoundry-src/image/vmware-workstation /tmp/labfoundry-src/third_party"
    ]
  }

  provisioner "file" {
    source      = "../../labfoundry"
    destination = "/tmp/labfoundry-src/labfoundry"
  }

  provisioner "file" {
    source      = "../../pyproject.toml"
    destination = "/tmp/labfoundry-src/pyproject.toml"
  }

  provisioner "file" {
    source      = "../../requirements-appliance.lock"
    destination = "/tmp/labfoundry-src/requirements-appliance.lock"
  }

  provisioner "file" {
    source      = "../../README.md"
    destination = "/tmp/labfoundry-src/README.md"
  }

  provisioner "file" {
    source      = "../../scripts/appliance"
    destination = "/tmp/labfoundry-src/scripts/appliance"
  }

  provisioner "file" {
    source      = "../../scripts/check_photon_compatibility.py"
    destination = "/tmp/labfoundry-src/scripts/check_photon_compatibility.py"
  }

  provisioner "file" {
    source      = "../../scripts/generate_third_party_notices.py"
    destination = "/tmp/labfoundry-src/scripts/generate_third_party_notices.py"
  }

  provisioner "file" {
    source      = "../../scripts/third_party_notices.json"
    destination = "/tmp/labfoundry-src/scripts/third_party_notices.json"
  }

  provisioner "file" {
    source      = "../../scripts/version.py"
    destination = "/tmp/labfoundry-src/scripts/version.py"
  }

  provisioner "file" {
    source      = "../../scripts/run_tdnf_with_progress.py"
    destination = "/tmp/labfoundry-src/scripts/run_tdnf_with_progress.py"
  }

  provisioner "file" {
    source      = "../../third_party/ipxe"
    destination = "/tmp/labfoundry-src/third_party/ipxe"
  }

  provisioner "file" {
    source      = "systemd"
    destination = "/tmp/labfoundry-src/image/vmware-workstation/systemd"
  }

  provisioner "file" {
    source      = "../common/systemd"
    destination = "/tmp/labfoundry-src/image/common/systemd"
  }

  provisioner "file" {
    source      = "../common/boot"
    destination = "/tmp/labfoundry-src/image/common/boot"
  }

  provisioner "file" {
    source      = "../common/update-trust"
    destination = "/tmp/labfoundry-src/image/common/update-trust"
  }

  provisioner "file" {
    source      = "sudoers.d"
    destination = "/tmp/labfoundry-src/image/vmware-workstation/sudoers.d"
  }

  provisioner "shell" {
    environment_vars = [
      "LABFOUNDRY_GUEST_PLATFORM=vmware",
      "LABFOUNDRY_IMAGE_ASSET_DIR=image/vmware-workstation",
      "LABFOUNDRY_BOOTSTRAP_ADMIN_PASSWORD=${local.bootstrap_admin_password}",
      "LABFOUNDRY_DRY_RUN_SYSTEM_ADAPTERS=${local.dry_run_system_adapters_text}",
      "LABFOUNDRY_MGMT_ADDRESS=${var.final_mgmt_address}",
      "LABFOUNDRY_MGMT_GATEWAY=${var.final_mgmt_gateway}",
      "LABFOUNDRY_MGMT_IPV4_METHOD=${var.final_mgmt_address == "dhcp" ? "dhcp" : "static"}",
      "LABFOUNDRY_MGMT_INTERFACE=${var.final_mgmt_interface}",
      "LABFOUNDRY_MGMT_DNS=${local.builder_static_dns_text}",
      "LABFOUNDRY_PIP_GLOBAL_INDEX=${var.pip_global_index}",
      "LABFOUNDRY_PIP_GLOBAL_INDEX_URL=${var.pip_global_index_url}"
    ]
    execute_command = "echo '${var.ssh_password}' | sudo -S -E sh -c '{{ .Vars }} {{ .Path }}'"
    script          = "${path.root}/../common/scripts/provision-labfoundry.sh"
  }
}
