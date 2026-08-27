#!/bin/sh
set -eu

ova_argument="${1:?usage: import-atlaso-kvm.sh OVA NAME POOL [MANAGEMENT_NETWORK] [SERVICE_NETWORK]}"
name="${2:?usage: import-atlaso-kvm.sh OVA NAME POOL [MANAGEMENT_NETWORK] [SERVICE_NETWORK]}"
pool="${3:?usage: import-atlaso-kvm.sh OVA NAME POOL [MANAGEMENT_NETWORK] [SERVICE_NETWORK]}"
management_network="${4:-default}"
service_network="${5:-$management_network}"
helper_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
validator="$helper_dir/validate_ova.py"
normalizer="$helper_dir/normalize_libvirt.py"
if [ ! -f "$validator" ]; then
  validator="$helper_dir/../validate_ova.py"
fi
if [ ! -f "$normalizer" ]; then
  normalizer="$helper_dir/../normalize_libvirt.py"
fi

for value in "$name" "$pool" "$management_network" "$service_network"; do
  case "$value" in
    ''|.|..|*[!A-Za-z0-9_.-]*)
      echo "Domain, pool, and network names contain an unsafe character." >&2
      exit 2
      ;;
  esac
done
for command in python3 virt-v2v virsh qemu-img jq mktemp realpath awk grep flock; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "$command is required on the KVM host." >&2
    exit 2
  }
done
domain_lock_path="/run/lock/atlaso-kvm-domain-${name}.lock"
pool_lock_path="/run/lock/atlaso-kvm-pool-${pool}-${name}.lock"
exec 8>"$domain_lock_path"
flock -n 8 || {
  echo "Another Atlaso KVM import owns domain name $name." >&2
  exit 2
}
exec 9>"$pool_lock_path"
flock -n 9 || {
  echo "Another Atlaso KVM import owns the $pool/$name namespace." >&2
  exit 2
}
for helper in "$validator" "$normalizer"; do
  [ -f "$helper" ] && [ ! -L "$helper" ] || {
    echo "The OVA validator and libvirt normalizer must be ordinary files beside this helper." >&2
    exit 2
  }
done
[ -f "$ova_argument" ] && [ ! -L "$ova_argument" ] || {
  echo "The OVA must be an existing ordinary file, not a symlink." >&2
  exit 2
}
ova_path=$(realpath -- "$ova_argument")
if domain_names=$(virsh list --all --name 2>/dev/null); then
  if printf '%s\n' "$domain_names" | grep -Fxq -- "$name"; then
    echo "A libvirt domain named $name already exists." >&2
    exit 2
  fi
else
  echo "Libvirt inventory could not prove domain name $name is available." >&2
  exit 2
fi
virsh pool-info "$pool" | grep -Eq '^State:[[:space:]]+running$' || {
  echo "The libvirt storage pool $pool is not active." >&2
  exit 2
}
if ! volumes=$(virsh vol-list "$pool" --name 2>/dev/null); then
  echo "Libvirt inventory could not prove the $pool/$name storage namespace is available." >&2
  exit 2
fi
if printf '%s\n' "$volumes" | grep -Eq "^${name}-"; then
  echo "The storage pool already contains a volume reserved for $name." >&2
  exit 2
fi
for network in "$management_network" "$service_network"; do
  virsh net-info "$network" >/dev/null 2>&1 || {
    echo "The libvirt network $network does not exist." >&2
    exit 2
  }
done

validation_root=$(mktemp -d -t atlaso-ova-validation.XXXXXX)
created=0
depot_volume_created=0
backup_volume_created=0
owned_volume_names="$validation_root/owned-volumes"
cleanup() {
  exit_status=$?
  trap - EXIT HUP INT TERM
  cleanup_failed=0
  domain_absent=0
  if [ "$created" -eq 1 ] && virsh dominfo "$name" >/dev/null 2>&1; then
    cleanup_safe=1
    : >"$owned_volume_names"
    virsh domblklist "$name" --details | awk '$2 == "disk" { print $4 }' >"$validation_root/owned-disk-paths"
    while IFS= read -r disk_path; do
      [ -n "$disk_path" ] || continue
      volume_pool=$(virsh vol-pool "$disk_path" 2>/dev/null || true)
      volume_name=$(virsh vol-name "$disk_path" 2>/dev/null || true)
      case "$volume_name" in
        "$name"-*) ;;
        *) cleanup_safe=0 ;;
      esac
      if [ "$volume_pool" != "$pool" ]; then
        cleanup_safe=0
      fi
      printf '%s\n' "$volume_name" >>"$owned_volume_names"
    done <"$validation_root/owned-disk-paths"
    if [ "$cleanup_safe" -eq 1 ]; then
      if state=$(virsh domstate "$name" 2>/dev/null); then
        case "$state" in
          'shut off') ;;
          *) virsh destroy "$name" >/dev/null 2>&1 || cleanup_failed=1 ;;
        esac
        virsh undefine "$name" --nvram >/dev/null 2>&1 ||
          virsh undefine "$name" >/dev/null 2>&1 || cleanup_failed=1
      else
        cleanup_failed=1
      fi
    else
      echo "Rollback preserved $name because an attached disk is outside the invocation-owned storage namespace." >&2
    fi
  fi
  if [ "$created" -eq 1 ]; then
    # A failed dominfo call is not absence proof: libvirt itself may be
    # unavailable. Only a successful inventory that omits the exact name lets
    # rollback remove volumes from the invocation-owned locked namespace.
    if domain_names=$(virsh list --all --name 2>/dev/null); then
      if ! printf '%s\n' "$domain_names" | grep -Fxq -- "$name"; then
        domain_absent=1
      fi
    fi
  fi
  if [ "$created" -eq 1 ] && [ "$domain_absent" -eq 1 ]; then
    # The locked name/pool namespace was empty before ownership began. Any
    # matching partial volume is therefore owned by this failed virt-v2v run.
    if volumes=$(virsh vol-list "$pool" --name 2>/dev/null); then
      printf '%s\n' "$volumes" >"$validation_root/rollback-volumes"
      while IFS= read -r volume_name; do
        case "$volume_name" in
          "$name"-*) virsh vol-delete --pool "$pool" "$volume_name" >/dev/null 2>&1 || cleanup_failed=1 ;;
        esac
      done <"$validation_root/rollback-volumes"
    else
      cleanup_failed=1
    fi
  fi
  if [ "$created" -eq 1 ] && [ "$domain_absent" -ne 1 ]; then
    echo "Rollback preserved $name volumes because exact domain absence could not be proved." >&2
  fi
  if [ "$created" -eq 1 ] && [ "$domain_absent" -eq 1 ]; then
    if volumes=$(virsh vol-list "$pool" --name 2>/dev/null); then
      if printf '%s\n' "$volumes" | grep -Eq "^${name}-"; then
        echo "Rollback retained a volume in the locked $pool/$name namespace." >&2
        cleanup_failed=1
      fi
    else
      echo "Rollback could not inventory the locked $pool/$name namespace." >&2
      cleanup_failed=1
    fi
  fi
  rm -rf -- "$validation_root" || cleanup_failed=1
  if [ "$cleanup_failed" -ne 0 ]; then
    echo "KVM import rollback did not reach its cleanup postcondition." >&2
    [ "$exit_status" -ne 0 ] || exit_status=1
  fi
  exit "$exit_status"
}
trap cleanup EXIT
trap 'exit 2' HUP INT TERM
python3 "$validator" "$ova_path" --extract-directory "$validation_root/extracted" >"$validation_root/contract.json"

# The name, pool, networks, and matching storage namespace are all absent or
# valid before ownership begins. Rollback can therefore touch only this domain
# and the volumes created by this invocation.
created=1
virt-v2v \
  -i ova "$ova_path" \
  -o libvirt \
  -os "$pool" \
  -on "$name" \
  --network "Atlaso Management Network:$management_network" \
  --network "Atlaso Services Network:$service_network"

disk_records=$(virsh domblklist "$name" --details | awk '$2 == "disk" { print $3 "|" $4 }')
disk_count=$(printf '%s\n' "$disk_records" | awk 'NF { count++ } END { print count + 0 }')
if [ "$disk_count" -lt 2 ] || [ "$disk_count" -gt 4 ]; then
  echo "virt-v2v created $disk_count disks; expected two payload disks and zero to two fileless data disks." >&2
  exit 2
fi

index=0
printf '%s\n' "$disk_records" | while IFS='|' read -r _target path; do
  [ -n "$path" ] || continue
  actual_size=$(qemu-img info --output=json "$path" | jq -er '."virtual-size"')
  case "$index" in
    0) expected_size=42949672960 ;;
    1) expected_size=21474836480 ;;
    2|3) expected_size=536870912000 ;;
    *) echo "Internal disk index overflow." >&2; exit 2 ;;
  esac
  if [ "$actual_size" -ne "$expected_size" ]; then
    echo "Imported disk $path is reordered or has conflicting capacity $actual_size; expected $expected_size." >&2
    exit 2
  fi
  index=$((index + 1))
done

if [ "$disk_count" -lt 3 ]; then
  virsh vol-create-as "$pool" "$name-vcf-offline-depot.qcow2" 536870912000 --allocation 0 --format qcow2
  depot_volume_created=1
  depot_path=$(virsh vol-path --pool "$pool" "$name-vcf-offline-depot.qcow2")
  virsh attach-disk "$name" "$depot_path" sdc --config --targetbus scsi --subdriver qcow2
fi
if [ "$disk_count" -lt 4 ]; then
  virsh vol-create-as "$pool" "$name-vcf-backups.qcow2" 536870912000 --allocation 0 --format qcow2
  backup_volume_created=1
  backup_path=$(virsh vol-path --pool "$pool" "$name-vcf-backups.qcow2")
  virsh attach-disk "$name" "$backup_path" sdd --config --targetbus scsi --subdriver qcow2
fi

virsh dumpxml "$name" --inactive >"$validation_root/imported.xml"
python3 "$normalizer" "$validation_root/imported.xml" \
  --management-network "$management_network" \
  --service-network "$service_network" \
  --output "$validation_root/normalized.xml"
virsh define "$validation_root/normalized.xml" >/dev/null
virsh dumpxml "$name" --inactive >"$validation_root/defined.xml"
python3 "$normalizer" "$validation_root/defined.xml" \
  --management-network "$management_network" \
  --service-network "$service_network" \
  --check

index=0
python3 "$normalizer" "$validation_root/defined.xml" --print-disk-sources | while IFS= read -r path; do
  actual_size=$(qemu-img info --output=json "$path" | jq -er '."virtual-size"')
  case "$index" in
    0) expected_size=42949672960 ;;
    1) expected_size=21474836480 ;;
    2|3) expected_size=536870912000 ;;
    *) echo "Internal disk index overflow." >&2; exit 2 ;;
  esac
  [ "$actual_size" -eq "$expected_size" ] || {
    echo "Normalized libvirt disk $index has capacity $actual_size; expected $expected_size." >&2
    exit 2
  }
  index=$((index + 1))
done

state=$(virsh domstate "$name")
[ "$state" = "shut off" ] || {
  echo "The imported domain must remain shut off after normalization; found $state." >&2
  exit 2
}
created=0
depot_volume_created=0
backup_volume_created=0
trap - EXIT HUP INT TERM
rm -rf -- "$validation_root"
virsh dumpxml "$name" --inactive
