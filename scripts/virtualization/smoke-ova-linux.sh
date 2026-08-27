#!/bin/sh
set -eu

provider="${1:?usage: smoke-ova-linux.sh PROVIDER OVA IDENTIFIER STORAGE MANAGEMENT_NETWORK SERVICE_NETWORK}"
ova_argument="${2:?usage: smoke-ova-linux.sh PROVIDER OVA IDENTIFIER STORAGE MANAGEMENT_NETWORK SERVICE_NETWORK}"
identifier="${3:?usage: smoke-ova-linux.sh PROVIDER OVA IDENTIFIER STORAGE MANAGEMENT_NETWORK SERVICE_NETWORK}"
storage="${4:?usage: smoke-ova-linux.sh PROVIDER OVA IDENTIFIER STORAGE MANAGEMENT_NETWORK SERVICE_NETWORK}"
management_network="${5:?usage: smoke-ova-linux.sh PROVIDER OVA IDENTIFIER STORAGE MANAGEMENT_NETWORK SERVICE_NETWORK}"
service_network="${6:?usage: smoke-ova-linux.sh PROVIDER OVA IDENTIFIER STORAGE MANAGEMENT_NETWORK SERVICE_NETWORK}"
script_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
template_root="$script_root/templates"

case "$provider" in
  proxmox|kvm) ;;
  *) echo "Provider must be proxmox or kvm." >&2; exit 2 ;;
esac
for value in "$identifier" "$storage" "$management_network" "$service_network"; do
  case "$value" in
    ''|.|..|*[!A-Za-z0-9_.-]*)
      echo "Provider identifiers contain an unsafe character." >&2
      exit 2
      ;;
  esac
done
for command in jq curl flock mktemp realpath; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "$command is required for the Linux OVA smoke test." >&2
    exit 2
  }
done
ova_path=$(realpath -- "$ova_argument")
[ -f "$ova_path" ] && [ ! -L "$ova_argument" ] || {
  echo "The smoke-test OVA must be an ordinary file, not a symlink." >&2
  exit 2
}

work_root=$(mktemp -d -t atlaso-ova-smoke.XXXXXX)
owned=0
disk_volume_list="$work_root/kvm-volumes"

proxmox_vmids() {
  qm_inventory=$(qm list 2>/dev/null) || return 1
  printf '%s\n' "$qm_inventory" | awk 'NR > 1 { print $1 }'
}

cleanup() {
  exit_status=$?
  trap - EXIT HUP INT TERM
  cleanup_failed=0
  if [ "$owned" -eq 1 ]; then
    case "$provider" in
      proxmox)
        if vmids=$(proxmox_vmids); then
          if printf '%s\n' "$vmids" | grep -Fxq -- "$identifier"; then
            if status=$(qm status "$identifier" 2>/dev/null); then
              case "$status" in
                *'status: running'*) qm stop "$identifier" --skiplock 0 >/dev/null 2>&1 || cleanup_failed=1 ;;
              esac
              qm destroy "$identifier" --purge 1 --destroy-unreferenced-disks 1 >/dev/null 2>&1 || cleanup_failed=1
            else
              cleanup_failed=1
            fi
          fi
        else
          cleanup_failed=1
        fi
        if vmids=$(proxmox_vmids); then
          if printf '%s\n' "$vmids" | grep -Fxq -- "$identifier"; then
            echo "The Proxmox smoke VM remains after cleanup: $identifier" >&2
            cleanup_failed=1
          fi
        else
          echo "Proxmox inventory could not prove cleanup for VMID $identifier." >&2
          cleanup_failed=1
        fi
        ;;
      kvm)
        domain_absent=0
        if domains=$(virsh list --all --name 2>/dev/null); then
          if printf '%s\n' "$domains" | grep -Fxq -- "$identifier"; then
            if state=$(virsh domstate "$identifier" 2>/dev/null); then
              case "$state" in
                'shut off') ;;
                *) virsh destroy "$identifier" >/dev/null 2>&1 || cleanup_failed=1 ;;
              esac
              virsh undefine "$identifier" --nvram >/dev/null 2>&1 || \
                virsh undefine "$identifier" >/dev/null 2>&1 || cleanup_failed=1
            else
              cleanup_failed=1
            fi
          fi
        else
          cleanup_failed=1
        fi
        if domains=$(virsh list --all --name 2>/dev/null); then
          if printf '%s\n' "$domains" | grep -Fxq -- "$identifier"; then
            echo "The KVM smoke domain remains after cleanup: $identifier" >&2
            cleanup_failed=1
          else
            domain_absent=1
          fi
        else
          echo "KVM inventory could not prove cleanup for domain $identifier." >&2
          cleanup_failed=1
        fi
        # A surviving domain may still reference every imported volume. Preserve
        # those volumes unless inventory proves the exact domain is absent.
        if [ "$domain_absent" -eq 1 ] && [ -f "$disk_volume_list" ]; then
          while IFS= read -r volume; do
            [ -n "$volume" ] || continue
            if volumes=$(virsh vol-list --pool "$storage" --name 2>/dev/null); then
              if printf '%s\n' "$volumes" | grep -Fxq -- "$volume"; then
                virsh vol-delete --pool "$storage" "$volume" >/dev/null 2>&1 || cleanup_failed=1
              fi
            else
              cleanup_failed=1
            fi
            if volumes=$(virsh vol-list --pool "$storage" --name 2>/dev/null); then
              if printf '%s\n' "$volumes" | grep -Fxq -- "$volume"; then
                echo "The KVM smoke volume remains after cleanup: $volume" >&2
                cleanup_failed=1
              fi
            else
              cleanup_failed=1
            fi
          done <"$disk_volume_list"
        fi
        ;;
    esac
  fi
  rm -rf -- "$work_root" || cleanup_failed=1
  if [ "$cleanup_failed" -ne 0 ] && [ "$exit_status" -eq 0 ]; then
    exit_status=1
  fi
  exit "$exit_status"
}
trap cleanup EXIT
trap 'exit 2' HUP INT TERM

qga_ping() {
  case "$provider" in
    proxmox) qm guest cmd "$identifier" ping >/dev/null 2>&1 ;;
    kvm) virsh qemu-agent-command "$identifier" '{"execute":"guest-ping"}' >/dev/null 2>&1 ;;
  esac
}

wait_for_qga() {
  waited=0
  until qga_ping; do
    if [ "$waited" -ge 900 ]; then
      echo "The QEMU guest agent did not become ready within 15 minutes." >&2
      exit 2
    fi
    sleep 5
    waited=$((waited + 5))
  done
}

wait_for_qga_outage() {
  waited=0
  while qga_ping; do
    if [ "$waited" -ge 300 ]; then
      echo "The appliance reboot never produced a QEMU guest-agent outage." >&2
      exit 2
    fi
    sleep 2
    waited=$((waited + 2))
  done
}

qga_exec_kvm() {
  command_text="$1"
  request=$(jq -nc --arg command "$command_text" \
    '{execute:"guest-exec",arguments:{path:"/bin/sh",arg:["-c",$command],"capture-output":true}}')
  pid=$(virsh qemu-agent-command "$identifier" "$request" | jq -er '.return.pid')
  waited=0
  while :; do
    status_request=$(jq -nc --argjson pid "$pid" \
      '{execute:"guest-exec-status",arguments:{pid:$pid}}')
    status=$(virsh qemu-agent-command "$identifier" "$status_request")
    if [ "$(printf '%s' "$status" | jq -er '.return.exited')" = "true" ]; then
      printf '%s' "$status" | jq -r '.return["out-data"] // "" | @base64d'
      printf '%s' "$status" | jq -r '.return["err-data"] // "" | @base64d' >&2
      [ "$(printf '%s' "$status" | jq -er '.return.exitcode')" -eq 0 ]
      return
    fi
    if [ "$waited" -ge 300 ]; then
      echo "A KVM guest command did not complete within five minutes." >&2
      return 2
    fi
    sleep 2
    waited=$((waited + 2))
  done
}

qga_exec() {
  command_text="$1"
  case "$provider" in
    proxmox)
      result=$(qm guest exec "$identifier" -- /bin/sh -c "$command_text")
      printf '%s' "$result" | jq -r '."out-data" // ""'
      printf '%s' "$result" | jq -r '."err-data" // ""' >&2
      [ "$(printf '%s' "$result" | jq -er '.exitcode')" -eq 0 ]
      ;;
    kvm) qga_exec_kvm "$command_text" ;;
  esac
}

guest_ipv4() {
  case "$provider" in
    proxmox) interfaces=$(qm guest cmd "$identifier" network-get-interfaces) ;;
    kvm)
      interfaces=$(virsh qemu-agent-command "$identifier" \
        '{"execute":"guest-network-get-interfaces"}' | jq -c '.return')
      ;;
  esac
  printf '%s' "$interfaces" | jq -er '
    [ .[] | .["ip-addresses"][]?
      | select(.["ip-address-type"] == "ipv4")
      | .["ip-address"]
      | select(. != "127.0.0.1") ][0]
  '
}

validate_guest() {
  qga_exec '
    set -eu
    test "$(find /sys/class/net -mindepth 1 -maxdepth 1 ! -name lo | wc -l)" -eq 2
    test "$(lsblk -dn -o TYPE | awk '\''$1 == "disk" { count++ } END { print count + 0 }'\'')" -eq 4
    grep -qx "platform=qemu" /var/lib/atlaso-privileged/guest-agent/guest-agent.applied
    test ! -e /var/lib/atlaso/first-boot-packages
    rpm -q atlaso-qemu-guest-agent >/dev/null
    ! rpm -q open-vm-tools >/dev/null 2>&1
    ! rpm -q hyper-v >/dev/null 2>&1
    systemctl is-active --quiet qemu-guest-agent.service
    ! systemctl is-active --quiet vmtoolsd.service
    ! systemctl is-enabled --quiet vmtoolsd.service
    for service in hv_kvp_daemon.service hv_fcopy_daemon.service hv_vss_daemon.service; do
      ! systemctl is-active --quiet "$service"
      ! systemctl is-enabled --quiet "$service"
    done
    findmnt -rn --target /var/lib/atlaso-system >/dev/null
    findmnt -rn --target /mnt/atlaso-vcf-offline-depot >/dev/null
    findmnt -rn --target /mnt/atlaso-vcf-backups >/dev/null
    systemctl is-active --quiet atlaso-data-disks.service
    systemctl is-active --quiet atlaso.service
    systemctl is-active --quiet atlaso-worker.service
    systemctl is-active --quiet nginx.service
    curl -fsS http://127.0.0.1:8000/openapi.json >/dev/null
    printf "atlaso-guest-smoke-ok\\n"
  ' | grep -qx 'atlaso-guest-smoke-ok'
  address=$(guest_ipv4)
  curl --fail --silent --show-error --insecure --max-time 30 \
    "https://$address/openapi.json" >/dev/null
}

case "$provider" in
  proxmox)
    for command in qm pvesm qemu-img; do
      command -v "$command" >/dev/null 2>&1 || {
        echo "$command is required on the Proxmox VE smoke runner." >&2
        exit 2
      }
    done
    proxmox_lock_path="/run/lock/atlaso-proxmox-vmid-$identifier.lock"
    exec 9>"$proxmox_lock_path"
    flock -n 9 || {
      echo "Another Atlaso smoke run owns Proxmox VMID $identifier." >&2
      exit 2
    }
    export ATLASO_PROXMOX_LOCK_FD=9
    if vmids=$(proxmox_vmids); then
      if printf '%s\n' "$vmids" | grep -Fxq -- "$identifier"; then
        echo "The Proxmox smoke-test VMID already exists: $identifier" >&2
        exit 2
      fi
    else
      echo "Proxmox inventory could not prove VMID $identifier absent." >&2
      exit 2
    fi
    "$template_root/import-atlaso-proxmox.sh" \
      "$ova_path" "$identifier" "$storage" "$management_network" "$service_network" >/dev/null
    owned=1
    qm start "$identifier"
    ;;
  kvm)
    for command in virsh virt-v2v qemu-img; do
      command -v "$command" >/dev/null 2>&1 || {
        echo "$command is required on the KVM smoke runner." >&2
        exit 2
      }
    done
    kvm_domain_lock_path="/run/lock/atlaso-kvm-domain-${identifier}.lock"
    kvm_pool_lock_path="/run/lock/atlaso-kvm-pool-${storage}-${identifier}.lock"
    exec 8>"$kvm_domain_lock_path"
    flock -n 8 || {
      echo "Another Atlaso smoke run owns KVM domain $identifier." >&2
      exit 2
    }
    exec 9>"$kvm_pool_lock_path"
    flock -n 9 || {
      echo "Another Atlaso smoke run owns the $storage/$identifier KVM namespace." >&2
      exit 2
    }
    export ATLASO_KVM_DOMAIN_LOCK_FD=8
    export ATLASO_KVM_POOL_LOCK_FD=9
    virsh dominfo "$identifier" >/dev/null 2>&1 && {
      echo "The KVM smoke-test domain already exists: $identifier" >&2
      exit 2
    }
    "$template_root/import-atlaso-kvm.sh" \
      "$ova_path" "$identifier" "$storage" "$management_network" "$service_network" >/dev/null
    : >"$disk_volume_list"
    if disk_inventory=$(virsh domblklist "$identifier" --details 2>/dev/null); then
      printf '%s\n' "$disk_inventory" | awk '$2 == "disk" { print $4 }' >"$work_root/kvm-disk-paths"
    else
      echo "KVM disk inventory failed before cleanup ownership was established." >&2
      exit 2
    fi
    [ "$(wc -l <"$work_root/kvm-disk-paths")" -eq 4 ] || {
      echo "The normalized KVM domain does not own exactly four disks." >&2
      exit 2
    }
    while IFS= read -r disk_path; do
      [ "$(virsh vol-pool "$disk_path")" = "$storage" ] || {
        echo "A KVM disk is outside the selected smoke-test storage pool: $disk_path" >&2
        exit 2
      }
      virsh vol-name "$disk_path" >>"$disk_volume_list"
    done <"$work_root/kvm-disk-paths"
    [ "$(sort -u "$disk_volume_list" | wc -l)" -eq 4 ] || {
      echo "The normalized KVM domain does not own four distinct volumes." >&2
      exit 2
    }
    # Cleanup ownership begins only after all four attached volume identities
    # are captured from successful provider queries.
    owned=1
    virsh start "$identifier" >/dev/null
    ;;
esac

wait_for_qga
validate_guest
qga_exec 'systemctl reboot' >/dev/null 2>&1 || true
wait_for_qga_outage
wait_for_qga
validate_guest
printf 'Atlaso %s OVA smoke test passed for %s.\n' "$provider" "$identifier"
