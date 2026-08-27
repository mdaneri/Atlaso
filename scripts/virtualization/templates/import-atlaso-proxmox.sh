#!/bin/sh
set -eu

ova_argument="${1:?usage: import-atlaso-proxmox.sh OVA VMID STORAGE [MANAGEMENT_BRIDGE] [SERVICE_BRIDGE]}"
vmid="${2:?usage: import-atlaso-proxmox.sh OVA VMID STORAGE [MANAGEMENT_BRIDGE] [SERVICE_BRIDGE]}"
storage="${3:?usage: import-atlaso-proxmox.sh OVA VMID STORAGE [MANAGEMENT_BRIDGE] [SERVICE_BRIDGE]}"
management_bridge="${4:-vmbr0}"
service_bridge="${5:-$management_bridge}"
helper_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
validator="$helper_dir/validate_ova.py"
if [ ! -f "$validator" ]; then
  validator="$helper_dir/../validate_ova.py"
fi

case "$vmid" in ''|*[!0-9]*) echo "VMID must be numeric." >&2; exit 2 ;; esac
for value in "$storage" "$management_bridge" "$service_bridge"; do
  case "$value" in ''|*[!A-Za-z0-9_.-]*) echo "Storage and bridge names contain an unsafe character." >&2; exit 2 ;; esac
done
for command in python3 qm pvesm qemu-img jq mktemp realpath flock; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "$command is required on the Proxmox VE node." >&2
    exit 2
  }
done
[ -f "$validator" ] && [ ! -L "$validator" ] || {
  echo "The OVA validator must be an ordinary file beside this helper." >&2
  exit 2
}
ova_path=$(realpath -- "$ova_argument")
[ -f "$ova_path" ] && [ ! -L "$ova_argument" ] || {
  echo "The OVA must be an existing ordinary file, not a symlink." >&2
  exit 2
}

# Serialize the complete absent-VMID ownership transaction. Every importer
# using this helper observes the same lock before preflight, mutation, or rollback.
lock_path="/run/lock/atlaso-proxmox-vmid-$vmid.lock"
exec 9>"$lock_path"
flock -n 9 || {
  echo "Another Atlaso import owns Proxmox VMID $vmid." >&2
  exit 2
}
vmids=$(qm list 2>/dev/null | awk 'NR > 1 { print $1 }') || {
  echo "Proxmox inventory could not prove VMID $vmid absent." >&2
  exit 2
}
if printf '%s\n' "$vmids" | grep -Fxq -- "$vmid"; then
  echo "A Proxmox VM with ID $vmid already exists." >&2
  exit 2
fi

validation_root=$(mktemp -d -t atlaso-ova-validation.XXXXXX)
created=0
cleanup() {
  exit_status=$?
  trap - EXIT HUP INT TERM
  cleanup_failed=0
  rm -rf -- "$validation_root" || cleanup_failed=1
  if [ "$created" -eq 1 ]; then
    if vmids=$(qm list 2>/dev/null | awk 'NR > 1 { print $1 }'); then
      if printf '%s\n' "$vmids" | grep -Fxq -- "$vmid"; then
        qm destroy "$vmid" --purge 1 --destroy-unreferenced-disks 1 >/dev/null 2>&1 || cleanup_failed=1
      fi
    else
      cleanup_failed=1
    fi
    if vmids=$(qm list 2>/dev/null | awk 'NR > 1 { print $1 }'); then
      if printf '%s\n' "$vmids" | grep -Fxq -- "$vmid"; then
        echo "Proxmox rollback retained VMID $vmid." >&2
        cleanup_failed=1
      fi
    else
      echo "Proxmox rollback could not inventory VMID $vmid." >&2
      cleanup_failed=1
    fi
  fi
  if [ "$cleanup_failed" -ne 0 ]; then
    echo "Proxmox import rollback did not reach its cleanup postcondition." >&2
    [ "$exit_status" -ne 0 ] || exit_status=1
  fi
  exit "$exit_status"
}
trap cleanup EXIT
trap 'exit 2' HUP INT TERM
python3 "$validator" "$ova_path" --extract-directory "$validation_root/extracted" >"$validation_root/contract.json"
ovf_name=$(jq -er '.ovf | select(type == "string" and test("^[^/\\\\]+[.]ovf$"; "i"))' "$validation_root/contract.json")
ovf_path="$validation_root/extracted/$ovf_name"
[ -f "$ovf_path" ] && [ ! -L "$ovf_path" ] || {
  echo "The validated OVA did not produce one ordinary OVF descriptor." >&2
  exit 2
}

# Ownership begins only after every source and destination preflight passes.
created=1
qm importovf "$vmid" "$ovf_path" "$storage" --format qcow2
qm set "$vmid" \
  --name atlaso \
  --memory 4096 \
  --cores 4 \
  --machine q35 \
  --bios ovmf \
  --efidisk0 "$storage:1,efitype=4m,pre-enrolled-keys=0" \
  --scsihw virtio-scsi-pci \
  --agent enabled=1 \
  --net0 "virtio,bridge=$management_bridge" \
  --net1 "virtio,bridge=$service_bridge"

disk_records=$(qm config "$vmid" | awk -F': ' '$1 ~ /^(scsi|sata|ide|virtio)[0-9]+$/ { print $1 "|" $2 }' | sort -V)
disk_count=$(printf '%s\n' "$disk_records" | awk 'NF { count++ } END { print count + 0 }')
if [ "$disk_count" -lt 2 ] || [ "$disk_count" -gt 4 ]; then
  echo "Proxmox OVA import created $disk_count disks; expected two payload disks and zero to two fileless data disks." >&2
  exit 2
fi

index=0
printf '%s\n' "$disk_records" | while IFS='|' read -r key value; do
  [ -n "$key" ] || continue
  volume=${value%%,*}
  volume_path=$(pvesm path "$volume")
  actual_size=$(qemu-img info --output=json "$volume_path" | jq -er '."virtual-size"')
  case "$index" in
    0) expected_size=42949672960 ;;
    1) expected_size=21474836480 ;;
    2|3) expected_size=536870912000 ;;
    *) echo "Internal disk index overflow." >&2; exit 2 ;;
  esac
  if [ "$actual_size" -ne "$expected_size" ]; then
    echo "Imported disk $key is reordered or has conflicting capacity $actual_size; expected $expected_size." >&2
    exit 2
  fi
  index=$((index + 1))
done

# Detach imported disks before assigning the fixed SCSI slots. Their volumes
# remain owned by this newly created VM and are purged by bounded rollback.
printf '%s\n' "$disk_records" | while IFS='|' read -r key _value; do
  [ -n "$key" ] || continue
  qm set "$vmid" --delete "$key"
done

index=0
printf '%s\n' "$disk_records" | while IFS='|' read -r _key value; do
  [ -n "$value" ] || continue
  volume=${value%%,*}
  qm set "$vmid" "--scsi$index" "$volume,discard=on,ssd=1"
  index=$((index + 1))
done

if [ "$disk_count" -lt 3 ]; then
  qm set "$vmid" --scsi2 "$storage:500,discard=on,ssd=1"
fi
if [ "$disk_count" -lt 4 ]; then
  qm set "$vmid" --scsi3 "$storage:500,discard=on,ssd=1"
fi
qm set "$vmid" --boot order=scsi0

config=$(qm config "$vmid")
for required in '^bios: ovmf$' '^cores: 4$' '^memory: 4096$' '^machine: q35' '^agent: enabled=1' \
  '^scsihw: virtio-scsi-pci$' '^scsi0:' '^scsi1:' '^scsi2:' '^scsi3:' '^net0:' '^net1:' '^boot: order=scsi0'; do
  printf '%s\n' "$config" | grep -Eq "$required" || {
    echo "Normalized Proxmox configuration is missing required contract: $required" >&2
    exit 2
  }
done
for slot in 0 1 2 3; do
  value=$(printf '%s\n' "$config" | sed -n "s/^scsi$slot: //p")
  volume=${value%%,*}
  actual_size=$(qemu-img info --output=json "$(pvesm path "$volume")" | jq -er '."virtual-size"')
  case "$slot" in 0) expected_size=42949672960 ;; 1) expected_size=21474836480 ;; *) expected_size=536870912000 ;; esac
  [ "$actual_size" -eq "$expected_size" ] || {
    echo "Normalized Proxmox SCSI slot $slot has capacity $actual_size; expected $expected_size." >&2
    exit 2
  }
done

created=0
trap - EXIT HUP INT TERM
rm -rf -- "$validation_root"
qm config "$vmid"
