#!/bin/sh

SYSFS_ROOT="${ATLASO_SYSFS_ROOT:-/sys}"
PROC_ROOT="${ATLASO_PROC_ROOT:-/proc}"
DMI_ROOT="${SYSFS_ROOT}/class/dmi/id"
RUNTIME_ROOT="${ATLASO_RUNTIME_ROOT:-/run}"

bounded_text() {
  maximum="$1"
  value="${2:-}"
  printf '%s' "${value}" | cut -c "1-${maximum}"
}

read_value() {
  value="$(cat "$1" 2>/dev/null || true)"
  value="$(printf '%s' "${value}" | tr '\t\r\n' '   ' | sed 's/^ *//;s/ *$//')"
  bounded_text 240 "${value}"
}

unsigned_value() {
  case "${1:-}" in
    ''|*[!0-9]*) printf '0' ;;
    *) printf '%s' "$1" ;;
  esac
}

hex_id() {
  value="$(read_value "$1")"
  printf '%s' "${value#0x}" | tr 'A-F' 'a-f'
}

human_size() {
  bytes="$(unsigned_value "${1:-0}")"
  awk -v bytes="${bytes}" 'BEGIN {
    split("B KiB MiB GiB TiB PiB", units, " ")
    value = bytes + 0
    unit = 1
    while (value >= 1024 && unit < 6) { value /= 1024; unit++ }
    if (unit == 1 || value >= 100) printf "%.0f %s", value, units[unit]
    else if (value >= 10) printf "%.1f %s", value, units[unit]
    else printf "%.2f %s", value, units[unit]
  }'
}

optional_ethernet_mac() {
  if printf '%s\n' "$1" | grep -Eq '^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$'; then
    printf '%s' "$1" | tr 'A-F' 'a-f'
  fi
}

pci_readable() {
  address="$1"
  field="$2"
  command -v lspci >/dev/null 2>&1 || return 0
  lspci -D -vmmnn -s "${address}" 2>/dev/null |
    awk -F '\t' -v wanted="${field}:" '$1 == wanted {sub(/ \[[^][]*\]$/, "", $2); print $2; exit}' |
    tr '\t\r\n' '   ' | sed 's/^ *//;s/ *$//' | cut -c 1-240
}

pci_class_name() {
  case "${1:-}" in
    0100*) printf 'SCSI storage controller' ;;
    0101*) printf 'IDE controller' ;;
    0104*) printf 'RAID controller' ;;
    0106*) printf 'SATA controller' ;;
    0107*) printf 'SAS controller' ;;
    0108*) printf 'NVM Express controller' ;;
    01*) printf 'Mass storage controller' ;;
    02*) printf 'Network controller' ;;
    03*) printf 'Display controller' ;;
    04*) printf 'Multimedia controller' ;;
    06*) printf 'Bridge' ;;
    0c03*) printf 'USB controller' ;;
    0c*) printf 'Serial bus controller' ;;
    *) printf 'PCI device' ;;
  esac
}

storage_controller_type() {
  case "${1:-}" in
    0100*) printf 'SCSI' ;;
    0101*) printf 'IDE' ;;
    0104*) printf 'RAID' ;;
    0106*) printf 'SATA' ;;
    0107*) printf 'SAS' ;;
    0108*) printf 'NVMe' ;;
    01*) printf 'Other storage' ;;
    *) printf '' ;;
  esac
}

collect_pci_devices() {
  output="$(mktemp "${RUNTIME_ROOT}/atlaso-pci.XXXXXX")"
  : >"${output}"
  count=0
  for path in "${SYSFS_ROOT}"/bus/pci/devices/*; do
    [ -d "${path}" ] || continue
    [ "${count}" -lt 512 ] || break
    address="${path##*/}"
    class_id="$(hex_id "${path}/class")"
    vendor_id="$(hex_id "${path}/vendor")"
    device_id="$(hex_id "${path}/device")"
    subsystem_vendor_id="$(hex_id "${path}/subsystem_vendor")"
    subsystem_device_id="$(hex_id "${path}/subsystem_device")"
    driver="$(bounded_text 120 "$(basename "$(readlink "${path}/driver" 2>/dev/null || true)")")"
    class_name="$(pci_readable "${address}" Class)"
    [ -n "${class_name}" ] || class_name="$(pci_class_name "${class_id}")"
    vendor="$(pci_readable "${address}" Vendor)"
    device="$(pci_readable "${address}" Device)"
    jq -cn \
      --arg pci_address "${address}" --arg class_id "${class_id}" \
      --arg class "${class_name}" --arg vendor_id "${vendor_id}" \
      --arg device_id "${device_id}" --arg vendor "${vendor}" \
      --arg device "${device}" --arg subsystem_vendor_id "${subsystem_vendor_id}" \
      --arg subsystem_device_id "${subsystem_device_id}" --arg driver "${driver}" \
      '{pci_address:$pci_address,class_id:$class_id,class:$class,vendor_id:$vendor_id,
        device_id:$device_id,vendor:$vendor,device:$device,
        subsystem_vendor_id:$subsystem_vendor_id,
        subsystem_device_id:$subsystem_device_id,driver:$driver}' >>"${output}"
    count=$((count + 1))
  done
  jq -s '.' "${output}"
  rm -f "${output}"
}

collect_storage_controllers() {
  pci_json="$1"
  printf '%s' "${pci_json}" | jq '[.[] | select(.class_id | startswith("01")) | {
    pci_address, type: (if .class_id | startswith("0100") then "SCSI"
      elif .class_id | startswith("0101") then "IDE"
      elif .class_id | startswith("0104") then "RAID"
      elif .class_id | startswith("0106") then "SATA"
      elif .class_id | startswith("0107") then "SAS"
      elif .class_id | startswith("0108") then "NVMe" else "Other storage" end),
    vendor_id, device_id, vendor, device, driver
  }][0:64]'
}

collect_interfaces() {
  boot_interface="$1"
  output="$(mktemp "${RUNTIME_ROOT}/atlaso-net.XXXXXX")"
  : >"${output}"
  count=0
  for path in "${SYSFS_ROOT}"/class/net/*; do
    [ -d "${path}" ] || continue
    name="${path##*/}"
    [ "${name}" = "lo" ] && continue
    [ "${count}" -lt 64 ] || break
    current_mac="$(optional_ethernet_mac "$(read_value "${path}/address")")"
    permanent_mac="$(optional_ethernet_mac "$(ethtool -P "${name}" 2>/dev/null | awk '{print $3}')")"
    device_path="$(readlink -f "${path}/device" 2>/dev/null || true)"
    pci_address="$(printf '%s\n' "${device_path}" | grep -Eo '[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]' | tail -n1 | tr 'A-F' 'a-f')"
    driver="$(bounded_text 120 "$(basename "$(readlink "${path}/device/driver" 2>/dev/null || true)")")"
    vendor_id=""
    device_id=""
    vendor=""
    device=""
    if [ -n "${pci_address}" ]; then
      vendor_id="$(hex_id "${SYSFS_ROOT}/bus/pci/devices/${pci_address}/vendor")"
      device_id="$(hex_id "${SYSFS_ROOT}/bus/pci/devices/${pci_address}/device")"
      vendor="$(pci_readable "${pci_address}" Vendor)"
      device="$(pci_readable "${pci_address}" Device)"
    fi
    link_state="$(read_value "${path}/operstate")"
    speed="$(unsigned_value "$(read_value "${path}/speed")")"
    addresses="$(ip -j address show dev "${name}" 2>/dev/null |
      jq '[.[0].addr_info[]? | "\(.local)/\(.prefixlen)"][0:64]' 2>/dev/null || printf '[]')"
    boot=false
    [ "${name}" = "${boot_interface}" ] && boot=true
    jq -cn \
      --arg name "$(bounded_text 64 "${name}")" --arg permanent_mac "${permanent_mac}" \
      --arg current_mac "${current_mac}" --arg driver "${driver}" \
      --arg pci_address "${pci_address}" --arg vendor_id "${vendor_id}" \
      --arg device_id "${device_id}" --arg vendor "${vendor}" --arg device "${device}" \
      --arg link_state "${link_state}" --argjson speed_mbps "${speed}" \
      --argjson addresses "${addresses}" --argjson boot_interface "${boot}" \
      '{name:$name,permanent_mac:$permanent_mac,current_mac:$current_mac,driver:$driver,
        pci_address:$pci_address,vendor_id:$vendor_id,device_id:$device_id,vendor:$vendor,
        device:$device,link_state:$link_state,speed_mbps:$speed_mbps,
        addresses:$addresses,boot_interface:$boot_interface}' >>"${output}"
    count=$((count + 1))
  done
  jq -s '.' "${output}"
  rm -f "${output}"
}

disk_type() {
  name="$1"
  transport="$2"
  rotational="$3"
  case "${name}:${transport}:${rotational}" in
    nvme*:*|*:nvme:*) printf 'NVMe' ;;
    mmcblk*:*) printf 'Flash' ;;
    *:usb:*) printf 'USB' ;;
    *:*:true) printf 'HDD' ;;
    *) printf 'SSD' ;;
  esac
}

collect_disks() {
  lsblk_json="$(lsblk --json --bytes --nodeps --output NAME,WWN,TRAN 2>/dev/null || printf '{"blockdevices":[]}')"
  output="$(mktemp "${RUNTIME_ROOT}/atlaso-disk.XXXXXX")"
  : >"${output}"
  count=0
  for path in "${SYSFS_ROOT}"/class/block/*; do
    [ -d "${path}" ] || continue
    [ ! -e "${path}/partition" ] || continue
    [ -e "${path}/device" ] || continue
    [ "${count}" -lt 128 ] || break
    name="${path##*/}"
    sectors="$(unsigned_value "$(read_value "${path}/size")")"
    size_bytes=$((sectors * 512))
    model="$(read_value "${path}/device/model")"
    serial="$(read_value "${path}/device/serial")"
    wwn="$(read_value "${path}/device/wwid")"
    [ -n "${wwn}" ] || wwn="$(printf '%s' "${lsblk_json}" | jq -r --arg name "${name}" '.blockdevices[]? | select(.name == $name) | .wwn // ""' | head -n1)"
    wwn="$(bounded_text 240 "${wwn}")"
    transport="$(printf '%s' "${lsblk_json}" | jq -r --arg name "${name}" '.blockdevices[]? | select(.name == $name) | .tran // ""' | head -n1)"
    transport="$(bounded_text 64 "${transport}")"
    rotational=false
    [ "$(read_value "${path}/queue/rotational")" = "1" ] && rotational=true
    removable=false
    [ "$(read_value "${path}/removable")" = "1" ] && removable=true
    read_only=false
    [ "$(read_value "${path}/ro")" = "1" ] && read_only=true
    device_path="$(readlink -f "${path}/device" 2>/dev/null || true)"
    controller="$(printf '%s\n' "${device_path}" | grep -Eo '[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]' | tail -n1 | tr 'A-F' 'a-f')"
    type="$(disk_type "${name}" "${transport}" "${rotational}")"
    flags="$(jq -cn --argjson rotational "${rotational}" --argjson removable "${removable}" \
      --argjson read_only "${read_only}" '[if $rotational then "rotational" else empty end,
        if $removable then "removable" else empty end,
        if $read_only then "read-only" else empty end]')"
    jq -cn --arg device "$(bounded_text 120 "/dev/${name}")" --arg model "${model}" --arg serial "${serial}" \
      --arg wwn "${wwn}" --arg transport "${transport}" --argjson size_bytes "${size_bytes}" \
      --arg size_human "$(human_size "${size_bytes}")" --arg type "${type}" \
      --argjson flags "${flags}" --arg controller_pci_address "${controller}" \
      --argjson rotational "${rotational}" --argjson removable "${removable}" \
      --argjson read_only "${read_only}" \
      '{device:$device,model:$model,serial:$serial,wwn:$wwn,transport:$transport,
        size_bytes:$size_bytes,size_human:$size_human,type:$type,flags:$flags,
        controller_pci_address:$controller_pci_address,rotational:$rotational,
        removable:$removable,read_only:$read_only}' >>"${output}"
    count=$((count + 1))
  done
  jq -s '.' "${output}"
  rm -f "${output}"
}

dimm_size_bytes() {
  # BusyBox ash can be configured with 32-bit arithmetic even on x86_64. Use
  # awk's numeric representation so populated DIMMs of 4 GiB or more do not
  # wrap to zero before they reach the structured report.
  printf '%s\n' "$1" | awk '
    {
      amount = $1 + 0
      unit = toupper($2)
      factor = unit == "KB" ? 1024 :
        unit == "MB" ? 1024 * 1024 :
        unit == "GB" ? 1024 * 1024 * 1024 :
        unit == "TB" ? 1024 * 1024 * 1024 * 1024 : 0
      if (amount < 0 || factor == 0) print "0"
      else printf "%.0f\n", amount * factor
    }
  '
}

collect_dimms() {
  records="$(mktemp "${RUNTIME_ROOT}/atlaso-dimm-records.XXXXXX")"
  output="$(mktemp "${RUNTIME_ROOT}/atlaso-dimm-json.XXXXXX")"
  : >"${records}"
  : >"${output}"
  dmidecode --type 17 2>/dev/null | awk '
    function clean(v) { gsub(/[|\t\r\n]/, " ", v); sub(/^ +/, "", v); sub(/ +$/, "", v); return v }
    function emit() {
      if (size != "" && size !~ /No Module Installed|Not Installed/) {
        print clean(locator) "|" clean(bank) "|" clean(size) "|" clean(type) "|" clean(speed) "|" clean(manufacturer) "|" clean(part) "|" clean(serial)
      }
    }
    /^[[:space:]]*Memory Device[[:space:]]*$/ { emit(); active=1; locator=bank=size=type=speed=manufacturer=part=serial=""; next }
    active && /^[[:space:]]*Locator:/ { sub(/^[^:]*:[[:space:]]*/, ""); locator=$0; next }
    active && /^[[:space:]]*Bank Locator:/ { sub(/^[^:]*:[[:space:]]*/, ""); bank=$0; next }
    active && /^[[:space:]]*Size:/ { sub(/^[^:]*:[[:space:]]*/, ""); size=$0; next }
    active && /^[[:space:]]*Type:/ { sub(/^[^:]*:[[:space:]]*/, ""); type=$0; next }
    active && /^[[:space:]]*Configured Memory Speed:/ { sub(/^[^:]*:[[:space:]]*/, ""); speed=$0; next }
    active && speed == "" && /^[[:space:]]*Speed:/ { sub(/^[^:]*:[[:space:]]*/, ""); speed=$0; next }
    active && /^[[:space:]]*Manufacturer:/ { sub(/^[^:]*:[[:space:]]*/, ""); manufacturer=$0; next }
    active && /^[[:space:]]*Part Number:/ { sub(/^[^:]*:[[:space:]]*/, ""); part=$0; next }
    active && /^[[:space:]]*Serial Number:/ { sub(/^[^:]*:[[:space:]]*/, ""); serial=$0; next }
    END { emit() }
  ' >"${records}"
  count=0
  while IFS='|' read -r locator bank size type speed manufacturer part serial; do
    [ "${count}" -lt 256 ] || break
    size_bytes="$(dimm_size_bytes "${size}")"
    speed_mts="$(unsigned_value "$(printf '%s' "${speed}" | awk '{print $1}')")"
    jq -cn --arg locator "$(bounded_text 240 "${locator}")" \
      --arg bank "$(bounded_text 240 "${bank}")" \
      --argjson size_bytes "${size_bytes}" --arg size_human "$(human_size "${size_bytes}")" \
      --arg type "$(bounded_text 240 "${type}")" --argjson speed_mts "${speed_mts}" \
      --arg manufacturer "$(bounded_text 240 "${manufacturer}")" \
      --arg part_number "$(bounded_text 240 "${part}")" \
      --arg serial "$(bounded_text 240 "${serial}")" \
      '{locator:$locator,bank:$bank,size_bytes:$size_bytes,size_human:$size_human,
        type:$type,speed_mts:$speed_mts,manufacturer:$manufacturer,
        part_number:$part_number,serial:$serial}' >>"${output}"
    count=$((count + 1))
  done <"${records}"
  jq -s '.' "${output}"
  rm -f "${records}" "${output}"
}

usb_class_name() {
  case "${1:-}" in
    00) printf 'Per-interface' ;;
    02) printf 'Communications' ;;
    03) printf 'Human interface' ;;
    08) printf 'Mass storage' ;;
    09) printf 'Hub' ;;
    0e) printf 'Video' ;;
    e0) printf 'Wireless' ;;
    *) printf 'USB device' ;;
  esac
}

collect_usb_devices() {
  output="$(mktemp "${RUNTIME_ROOT}/atlaso-usb.XXXXXX")"
  : >"${output}"
  count=0
  for path in "${SYSFS_ROOT}"/bus/usb/devices/*; do
    [ -d "${path}" ] || continue
    [ -f "${path}/idVendor" ] || continue
    [ -f "${path}/idProduct" ] || continue
    [ "${count}" -lt 256 ] || break
    class_id="$(hex_id "${path}/bDeviceClass")"
    bus="$(unsigned_value "$(read_value "${path}/busnum")")"
    device_number="$(unsigned_value "$(read_value "${path}/devnum")")"
    driver="$(bounded_text 120 "$(basename "$(readlink "${path}/driver" 2>/dev/null || true)")")"
    jq -cn --argjson bus "${bus}" --argjson device_number "${device_number}" \
      --arg port "$(bounded_text 64 "${path##*/}")" --arg vendor_id "$(hex_id "${path}/idVendor")" \
      --arg product_id "$(hex_id "${path}/idProduct")" \
      --arg manufacturer "$(read_value "${path}/manufacturer")" \
      --arg product "$(read_value "${path}/product")" --arg serial "$(read_value "${path}/serial")" \
      --arg class "$(usb_class_name "${class_id}")" --arg driver "${driver}" \
      '{bus:$bus,device_number:$device_number,port:$port,vendor_id:$vendor_id,
        product_id:$product_id,manufacturer:$manufacturer,product:$product,
        serial:$serial,class:$class,driver:$driver}' >>"${output}"
    count=$((count + 1))
  done
  jq -s '.' "${output}"
  rm -f "${output}"
}

collect_cpu() {
  cpu_json="$(lscpu -J)"
  cpu_field() {
    printf '%s' "${cpu_json}" | jq -r --arg field "$1" \
      '.lscpu[] | select(.field == ($field + ":")) | .data' | head -n1
  }
  architecture="$(bounded_text 64 "$(cpu_field Architecture)")"
  vendor="$(bounded_text 120 "$(cpu_field "Vendor ID")")"
  model="$(bounded_text 240 "$(cpu_field "Model name")")"
  sockets="$(unsigned_value "$(cpu_field "Socket(s)")")"
  cores_per_socket="$(unsigned_value "$(cpu_field "Core(s) per socket")")"
  threads_per_core="$(unsigned_value "$(cpu_field "Thread(s) per core")")"
  cores=$((sockets * cores_per_socket))
  threads=$((cores * threads_per_core))
  [ "${cores}" -gt 0 ] || cores="$(unsigned_value "$(cpu_field "CPU(s)")")"
  [ "${threads}" -gt 0 ] || threads="$(unsigned_value "$(cpu_field "CPU(s)")")"
  jq -cn --arg architecture "${architecture}" --arg vendor "${vendor}" --arg model "${model}" \
    --argjson sockets "${sockets}" --argjson cores "${cores}" --argjson threads "${threads}" \
    --argjson cores_per_socket "${cores_per_socket}" --argjson threads_per_core "${threads_per_core}" \
    '{architecture:$architecture,vendor:$vendor,model:$model,sockets:$sockets,
      cores:$cores,threads:$threads,cores_per_socket:$cores_per_socket,
      threads_per_core:$threads_per_core}'
}

cycle_console_page() {
  page="$(unsigned_value "${1:-1}")"
  direction="$2"
  case "${direction}" in
    next) page=$((page % 3 + 1)) ;;
    previous) page=$(((page + 1) % 3 + 1)) ;;
  esac
  printf '%s' "${page}"
}

countdown_after_elapsed() {
  remaining="$(unsigned_value "${1:-0}")"
  paused="$2"
  elapsed="$(unsigned_value "${3:-0}")"
  if [ "${paused}" = "true" ]; then
    printf '%s' "${remaining}"
  elif [ "${elapsed}" -ge "${remaining}" ]; then
    printf '0'
  else
    printf '%s' $((remaining - elapsed))
  fi
}

console_key_action() {
  key="$1"
  page="$2"
  paused="$3"
  action="none"
  case "${key}" in
    1|2|3) page="${key}" ;;
    n|N|']') page="$(cycle_console_page "${page}" next)" ;;
    p|P|'[') page="$(cycle_console_page "${page}" previous)" ;;
    s|S)
      if [ "${paused}" = "true" ]; then paused=false; else paused=true; fi
      ;;
    r|R) action="reboot" ;;
  esac
  printf '%s|%s|%s' "${page}" "${paused}" "${action}"
}

acknowledge_remote_reboot() {
  api_base="$1"
  auth_config="$2"
  command_id="$3"
  curl --config "${auth_config}" --fail --silent --max-time 10 --request POST \
    "${api_base}/pxe/inventory/commands/${command_id}/acknowledge" >/dev/null
}

console_line() {
  printf '  %-22s %s\n' "$1" "$2"
}

render_inventory_console() {
  report="$1"
  page="$2"
  remaining="$3"
  paused="$4"
  host_id="$5"
  printf '\033[2J\033[H\033[48;5;153m\033[38;5;17m\033[1m  Atlaso Inventory Linux  \033[0m\033[K\n'
  printf '\033[48;5;255m\033[38;5;235m\033[K'
  case "${page}" in
    1)
      printf '\033[1m  System / CPU / DIMMs\033[0m\033[K\n\n'
      console_line 'Manufacturer' "$(printf '%s' "${report}" | jq -r '.system.manufacturer')"
      console_line 'Product' "$(printf '%s' "${report}" | jq -r '[.system.product_name,.system.product_version] | map(select(length>0)) | join(" ")')"
      console_line 'Serial / UUID' "$(printf '%s' "${report}" | jq -r '(.system.serial_number + " / " + .system.dmi_uuid)')"
      console_line 'BIOS' "$(printf '%s' "${report}" | jq -r '[.system.bios_vendor,.system.bios_version,.system.bios_date] | map(select(length>0)) | join(" ")')"
      console_line 'Baseboard' "$(printf '%s' "${report}" | jq -r '[.system.baseboard.manufacturer,.system.baseboard.product,.system.baseboard.serial] | map(select(length>0)) | join(" / ")')"
      console_line 'Chassis' "$(printf '%s' "${report}" | jq -r '[.system.chassis.manufacturer,.system.chassis.type,.system.chassis.serial] | map(select(length>0)) | join(" / ")')"
      printf '\n\033[1m  CPU\033[0m\n'
      console_line 'Model' "$(printf '%s' "${report}" | jq -r '.cpu.model')"
      console_line 'Topology' "$(printf '%s' "${report}" | jq -r '"\(.cpu.sockets) sockets / \(.cpu.cores) cores / \(.cpu.threads) threads (\(.cpu.cores_per_socket) cores/socket, \(.cpu.threads_per_core) threads/core)"')"
      printf '\n\033[1m  Memory: %s\033[0m\n' "$(printf '%s' "${report}" | jq -r '.memory.total_human')"
      printf '%s' "${report}" | jq -r '.memory.dimms[] | "  \(.locator) | \(.bank) | \(.size_human) | \(.type) | \(.speed_mts) MT/s | \(.manufacturer) \(.part_number) | S/N \(.serial)"'
      ;;
    2)
      printf '\033[1m  Network\033[0m\033[K\n\n'
      printf '%s' "${report}" | jq -r '.interfaces[] | "  " + (if .boot_interface then "* " else "  " end) + .name + "  " + ([.vendor,.device] | map(select(length > 0)) | join(" ")) + "\n      permanent " + .permanent_mac + "  current " + .current_mac + "  " + .link_state + " " + (.speed_mbps|tostring) + " Mb/s\n      " + (.addresses|join(", ")) + "  driver " + .driver + "  PCI " + .pci_address'
      ;;
    *)
      printf '\033[1m  Storage\033[0m\033[K\n\n'
      printf '%s' "${report}" | jq -r '.disks[] | "  " + .device + "  " + .size_human + "  " + .type + "  " + .model + "\n      serial " + .serial + "  WWN " + .wwn + "  transport " + .transport + "  controller " + .controller_pci_address + "  flags " + (.flags|join(", "))'
      printf '\n\033[1m  Storage controllers\033[0m\n'
      printf '%s' "${report}" | jq -r '.storage_controllers[] | "  " + .pci_address + "  " + .type + "  " + ([.vendor,.device] | map(select(length > 0)) | join(" ")) + "  driver " + .driver'
      ;;
  esac
  printf '\033[0m\033[48;5;25m\033[38;5;255m\033[K\n'
  printf '\033[s'
  render_inventory_console_footer_lines "${page}" "${remaining}" "${paused}" "${host_id}"
}

render_inventory_console_footer_lines() {
  page="$1"
  remaining="$2"
  paused="$3"
  host_id="$4"
  if [ "${paused}" = "true" ]; then countdown="Paused at ${remaining}s"; else countdown="Reboot in ${remaining}s"; fi
  printf '  Host %s  |  Page %s/3  |  %s\033[K\n' "${host_id}" "${page}" "${countdown}"
  printf '  [N] Next  [P] Previous  [1-3] Page  [S] Pause/resume  [R] Reboot now\033[K\033[0m\n\033[J'
}

refresh_inventory_console_footer() {
  printf '\033[u\033[48;5;25m\033[38;5;255m'
  render_inventory_console_footer_lines "$1" "$2" "$3" "$4"
}
