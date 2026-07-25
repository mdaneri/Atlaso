packer {
  required_version = ">= 1.10.0"

  required_plugins {
    hyperv = {
      version = ">= 1.1.3"
      source  = "github.com/hashicorp/hyperv"
    }
  }
}

variable "vm_name" {
  type    = string
  default = "LabFoundry-Photon-Builder"
}

variable "output_directory" {
  type    = string
  default = "output/labfoundry-photon-hyperv"
}

variable "switch_name" {
  type    = string
  default = "LabFoundry-Mgmt"
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
  description = "Optional Photon guest SSH host override. Leave null to let the Hyper-V builder discover the guest IP through KVP."
}

variable "iso_contains_kickstart" {
  type        = bool
  default     = false
  description = "Set true only for a Photon ISO remastered by scripts/windows/hyperv/build-photon-image.ps1 with photon-ks.json and the LabFoundry GRUB auto-install entry embedded."

  validation {
    condition     = var.iso_contains_kickstart
    error_message = "Iso_contains_kickstart must be true. Run scripts/windows/hyperv/build-photon-image.ps1 so it creates and passes the remastered Photon ISO."
  }
}

variable "builder_static_ip" {
  type        = string
  default     = "192.168.49.30/24"
  description = "Static IP or CIDR for the installed Photon builder VM. Packer uses this address for SSH."
}

variable "builder_static_netmask" {
  type        = string
  default     = "255.255.255.0"
  description = "Netmask for builder_static_ip when using Photon legacy static kickstart networking."
}

variable "builder_static_gateway" {
  type        = string
  default     = "192.168.49.254"
  description = "Gateway for builder_static_ip. For LabFoundry-Mgmt this is the Windows host-side vEthernet address."
}

variable "builder_static_dns" {
  type        = list(string)
  default     = ["1.1.1.1", "9.9.9.9"]
  description = "DNS servers for builder_static_ip."
}

variable "final_mgmt_address" {
  type        = string
  default     = "192.168.49.1/24"
  description = "Final LabFoundry appliance management address after provisioning."
}

variable "final_mgmt_gateway" {
  type        = string
  default     = "192.168.49.254"
  description = "Final LabFoundry appliance management gateway after provisioning."
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

source "hyperv-iso" "photon" {
  vm_name            = var.vm_name
  output_directory   = var.output_directory
  switch_name        = var.switch_name
  generation         = 2
  enable_secure_boot = false
  cpus               = 4
  memory             = 4096
  disk_size          = 40960
  differencing_disk  = false
  headless           = true
  iso_url            = var.iso_url
  iso_checksum       = var.iso_checksum
  communicator       = "ssh"
  # Hyper-V auto-detects this through the guest KVP daemon. Use ssh_host only
  # as a fallback when Photon is reachable but Packer cannot infer the guest IP.
  ssh_host               = var.ssh_host != null ? var.ssh_host : (local.builder_static_address != "" ? local.builder_static_address : null)
  ssh_port               = 22
  ssh_username           = var.ssh_username
  ssh_password           = var.ssh_password
  ssh_timeout            = "45m"
  ssh_handshake_attempts = 200
  shutdown_command       = "echo '${var.ssh_password}' | sudo -S systemctl poweroff"
  # The remastered ISO owns the GRUB auto-install entry; Packer should not race
  # the VM console by typing boot commands.
}

build {
  name    = "labfoundry-photon-hyperv"
  sources = ["source.hyperv-iso.photon"]

  provisioner "shell" {
    inline = [
      "mkdir -p /tmp/labfoundry-src/scripts /tmp/labfoundry-src/image/common /tmp/labfoundry-src/image/hyperv /tmp/labfoundry-src/third_party"
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
    destination = "/tmp/labfoundry-src/image/hyperv/systemd"
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
    destination = "/tmp/labfoundry-src/image/hyperv/sudoers.d"
  }

  provisioner "shell" {
    environment_vars = [
      "LABFOUNDRY_GUEST_PLATFORM=hyperv",
      "LABFOUNDRY_IMAGE_ASSET_DIR=image/hyperv",
      "LABFOUNDRY_BOOTSTRAP_ADMIN_PASSWORD=${local.bootstrap_admin_password}",
      "LABFOUNDRY_DRY_RUN_SYSTEM_ADAPTERS=${local.dry_run_system_adapters_text}",
      "LABFOUNDRY_MGMT_ADDRESS=${var.final_mgmt_address}",
      "LABFOUNDRY_MGMT_GATEWAY=${var.final_mgmt_gateway}",
      "LABFOUNDRY_MGMT_INTERFACE=${var.final_mgmt_interface}",
      "LABFOUNDRY_MGMT_DNS=${local.builder_static_dns_text}",
      "LABFOUNDRY_PIP_GLOBAL_INDEX=${var.pip_global_index}",
      "LABFOUNDRY_PIP_GLOBAL_INDEX_URL=${var.pip_global_index_url}"
    ]
    execute_command = "echo '${var.ssh_password}' | sudo -S -E sh -c '{{ .Vars }} {{ .Path }}'"
    script          = "${path.root}/../common/scripts/provision-labfoundry.sh"
  }
}
