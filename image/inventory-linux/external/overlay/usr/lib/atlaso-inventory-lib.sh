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

device_path_is_usb_backed() {
  case "${1:-}" in
    */usb[0-9]*/*) return 0 ;;
    *) return 1 ;;
  esac
}

collect_storage_controllers() {
  pci_file="$1"
  output="$(mktemp "${RUNTIME_ROOT}/atlaso-controller.XXXXXX")"
  jq -c '.[] | select(.class_id | startswith("01")) | {
    pci_address, type: (if .class_id | startswith("0100") then "SCSI"
      elif .class_id | startswith("0101") then "IDE"
      elif .class_id | startswith("0104") then "RAID"
      elif .class_id | startswith("0106") then "SATA"
      elif .class_id | startswith("0107") then "SAS"
      elif .class_id | startswith("0108") then "NVMe" else "Other storage" end),
    vendor_id, device_id, vendor, device, driver
  }' "${pci_file}" >"${output}"
  count="$(wc -l <"${output}" | tr -d ' ')"
  for path in "${SYSFS_ROOT}"/class/scsi_host/host*; do
    [ -d "${path}" ] || continue
    [ "${count}" -lt 64 ] || break
    device_path="$(readlink -f "${path}/device" 2>/dev/null || true)"
    pci_address=''
    if ! device_path_is_usb_backed "${device_path}"; then
      pci_address="$(printf '%s\n' "${device_path}" | grep -Eo '[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]' | tail -n1 | tr 'A-F' 'a-f')"
    fi
    if [ -n "${pci_address}" ] && jq -e --arg address "${pci_address}" 'select(.pci_address == $address)' "${output}" >/dev/null 2>&1; then
      continue
    fi
    driver="$(bounded_text 120 "$(read_value "${path}/proc_name")")"
    [ -n "${driver}" ] || driver="$(bounded_text 120 "$(basename "$(readlink "${path}/device/driver" 2>/dev/null || true)")")"
    case "${driver}" in
      storvsc*) type='Hyper-V SCSI' ;;
      virtio_scsi*) type='Virtio SCSI' ;;
      xen*) type='Xen SCSI' ;;
      *) type='SCSI' ;;
    esac
    vendor="$(bounded_text 240 "$(read_value "${path}/device/vendor")")"
    device="$(bounded_text 240 "$(read_value "${path}/device/model")")"
    [ -n "${device}" ] || device="${path##*/}"
    jq -cn --arg pci_address "${pci_address}" --arg type "${type}" \
      --arg vendor "${vendor}" --arg device "${device}" --arg driver "${driver}" \
      '{pci_address:$pci_address,type:$type,vendor_id:"",device_id:"",
        vendor:$vendor,device:$device,driver:$driver}' >>"${output}"
    count=$((count + 1))
  done
  jq -s '.[0:64]' "${output}"
  rm -f "${output}"
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
    interface_type="$(read_value "${path}/type")"
    [ -z "${interface_type}" ] || [ "${interface_type}" = "1" ] || continue
    [ "${count}" -lt 64 ] || break
    current_mac="$(optional_ethernet_mac "$(read_value "${path}/address")")"
    permanent_mac="$(optional_ethernet_mac "$(ethtool -P "${name}" 2>/dev/null | awk '{print $3}')")"
    device_path="$(readlink -f "${path}/device" 2>/dev/null || true)"
    device_name="${device_path##*/}"
    pci_address=""
    case "${device_name}" in
      [0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F].[0-7])
        pci_address="$(printf '%s' "${device_name}" | tr 'A-F' 'a-f')"
        [ -d "${SYSFS_ROOT}/bus/pci/devices/${pci_address}" ] || pci_address=""
        ;;
    esac
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
  peripheral_type="$4"
  case "${name}:${transport}:${rotational}:${peripheral_type}" in
    *:*:*:5) printf 'Optical' ;;
    nvme*:*|*:nvme:*) printf 'NVMe' ;;
    mmcblk*:*) printf 'Flash' ;;
    *:usb:*) printf 'USB' ;;
    *:*:true:*) printf 'HDD' ;;
    *) printf 'SSD' ;;
  esac
}

collect_disks() {
  lsblk_json="$(lsblk --json --bytes --nodeps --output NAME,WWN,TRAN,SERIAL 2>/dev/null || printf '{"blockdevices":[]}')"
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
    [ -n "${serial}" ] || serial="$(printf '%s' "${lsblk_json}" | jq -r --arg name "${name}" '.blockdevices[]? | select(.name == $name) | .serial // ""' | head -n1)"
    serial="$(bounded_text 240 "${serial}")"
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
    peripheral_type="$(unsigned_value "$(read_value "${path}/device/type")")"
    controller=''
    if ! device_path_is_usb_backed "${device_path}"; then
      controller="$(printf '%s\n' "${device_path}" | grep -Eo '[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]' | tail -n1 | tr 'A-F' 'a-f')"
    fi
    type="$(disk_type "${name}" "${transport}" "${rotational}" "${peripheral_type}")"
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
      factor = unit == "KB" || unit == "KIB" ? 1024 :
        unit == "MB" || unit == "MIB" ? 1024 * 1024 :
        unit == "GB" || unit == "GIB" ? 1024 * 1024 * 1024 :
        unit == "TB" || unit == "TIB" ? 1024 * 1024 * 1024 * 1024 : 0
      if (amount < 0 || factor == 0) print "0"
      else printf "%.0f\n", amount * factor
    }
  '
}

dimm_sysfs_size_bytes() {
  raw="$1"
  base="$(od -An -tu1 -j 12 -N 2 "${raw}" 2>/dev/null || true)"
  extended="$(od -An -tu1 -j 28 -N 4 "${raw}" 2>/dev/null || true)"
  awk -v base="${base}" -v extended="${extended}" 'BEGIN {
    count = split(base, bytes)
    if (count < 2) exit 1
    encoded = bytes[1] + bytes[2] * 256
    if (encoded == 0) exit 1
    if (encoded == 65535) { print "0"; exit }
    if (encoded == 32767) {
      count = split(extended, ext)
      if (count < 4) { print "0"; exit }
      amount = ext[1] + ext[2] * 256 + ext[3] * 65536 + ext[4] * 16777216
      factor = 1024 * 1024
      if (amount >= 2147483648) {
        amount -= 2147483648
        factor = 1024
      }
      printf "%.0f\n", amount * factor
      exit
    }
    if (encoded >= 32768) {
      amount = encoded - 32768
      factor = 1024
    } else {
      amount = encoded
      factor = 1024 * 1024
    }
    printf "%.0f\n", amount * factor
  }'
}

dmi_sysfs_handle() {
  bytes="$(od -An -tu1 -j 2 -N 2 "$1" 2>/dev/null || true)"
  awk -v bytes="${bytes}" 'BEGIN {
    count = split(bytes, value)
    if (count < 2) exit 1
    printf "0x%04X\n", value[1] + value[2] * 256
  }'
}

collect_dimms() {
  records="$(mktemp "${RUNTIME_ROOT}/atlaso-dimm-records.XXXXXX")"
  output="$(mktemp "${RUNTIME_ROOT}/atlaso-dimm-json.XXXXXX")"
  : >"${records}"
  : >"${output}"
  dmidecode --type 17 2>/dev/null | awk '
    function clean(v) { gsub(/[|\t\r\n]/, " ", v); sub(/^ +/, "", v); sub(/ +$/, "", v); return v }
    function emit() {
      if (handle != "") {
        print clean(handle) "|" clean(locator) "|" clean(bank) "|" clean(type) "|" clean(speed) "|" clean(manufacturer) "|" clean(part) "|" clean(serial)
      }
    }
    /^Handle 0x[[:xdigit:]]+,[[:space:]]+DMI type 17,/ { emit(); handle=$2; sub(/,$/, "", handle); active=0; locator=bank=type=speed=manufacturer=part=serial=""; next }
    /^[[:space:]]*Memory Device[[:space:]]*$/ { active=1; next }
    active && /^[[:space:]]*Locator:/ { sub(/^[^:]*:[[:space:]]*/, ""); locator=$0; next }
    active && /^[[:space:]]*Bank Locator:/ { sub(/^[^:]*:[[:space:]]*/, ""); bank=$0; next }
    active && /^[[:space:]]*Type:/ { sub(/^[^:]*:[[:space:]]*/, ""); type=$0; next }
    active && /^[[:space:]]*Configured Memory Speed:/ { sub(/^[^:]*:[[:space:]]*/, ""); speed=$0; next }
    active && speed == "" && /^[[:space:]]*Speed:/ { sub(/^[^:]*:[[:space:]]*/, ""); speed=$0; next }
    active && /^[[:space:]]*Manufacturer:/ { sub(/^[^:]*:[[:space:]]*/, ""); manufacturer=$0; next }
    active && /^[[:space:]]*Part Number:/ { sub(/^[^:]*:[[:space:]]*/, ""); part=$0; next }
    active && /^[[:space:]]*Serial Number:/ { sub(/^[^:]*:[[:space:]]*/, ""); serial=$0; next }
    END { emit() }
  ' >"${records}"
  count=0
  for path in "${SYSFS_ROOT}"/firmware/dmi/entries/17-*; do
    [ -d "${path}" ] || continue
    [ -f "${path}/raw" ] || continue
    [ "${count}" -lt 256 ] || break
    size_bytes="$(dimm_sysfs_size_bytes "${path}/raw" || true)"
    [ -n "${size_bytes}" ] || continue
    handle="$(dmi_sysfs_handle "${path}/raw" || true)"
    enrichment="$(awk -F '|' -v expected="${handle}" 'tolower($1) == tolower(expected) { sub(/^[^|]*\|/, ""); print; exit }' "${records}")"
    enrichment="${enrichment:-||||||}"
    locator="$(printf '%s' "${enrichment}" | cut -d'|' -f1)"
    bank="$(printf '%s' "${enrichment}" | cut -d'|' -f2)"
    type="$(printf '%s' "${enrichment}" | cut -d'|' -f3)"
    speed="$(printf '%s' "${enrichment}" | cut -d'|' -f4)"
    manufacturer="$(printf '%s' "${enrichment}" | cut -d'|' -f5)"
    part="$(printf '%s' "${enrichment}" | cut -d'|' -f6)"
    serial="$(printf '%s' "${enrichment}" | cut -d'|' -f7)"
    [ "${count}" -lt 256 ] || break
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
  done
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
  topology="$(mktemp "${RUNTIME_ROOT}/atlaso-cpu-topology.XXXXXX")"
  : >"${topology}"
  for cpu_path in "${SYSFS_ROOT}"/devices/system/cpu/cpu[0-9]*; do
    [ -d "${cpu_path}" ] || continue
    cpu_index="${cpu_path##*cpu}"
    printf '%s' "${cpu_index}" | grep -Eq '^[0-9]+$' || continue
    if [ -r "${cpu_path}/online" ] && [ "$(read_value "${cpu_path}/online")" = "0" ]; then
      continue
    fi
    package_id="$(read_value "${cpu_path}/topology/physical_package_id")"
    core_id="$(read_value "${cpu_path}/topology/core_id")"
    printf '%s' "${package_id}" | grep -Eq '^[0-9]+$' || package_id=0
    printf '%s' "${core_id}" | grep -Eq '^[0-9]+$' || core_id="${cpu_index}"
    printf '%s %s\n' "${package_id}" "${core_id}" >>"${topology}"
  done
  threads="$(wc -l <"${topology}" | tr -d ' ')"
  sockets="$(awk '{print $1}' "${topology}" | sort -u | wc -l | tr -d ' ')"
  cores="$(sort -u "${topology}" | wc -l | tr -d ' ')"
  cores_per_socket="$(sort -u "${topology}" | awk '
    { count[$1] += 1 }
    END { maximum = 0; for (package in count) if (count[package] > maximum) maximum = count[package]; print maximum }
  ')"
  threads_per_core="$(awk '
    { count[$1 " " $2] += 1 }
    END { maximum = 0; for (core in count) if (count[core] > maximum) maximum = count[core]; print maximum }
  ' "${topology}")"
  rm -f "${topology}"
  sockets="$(unsigned_value "${sockets}")"
  cores="$(unsigned_value "${cores}")"
  threads="$(unsigned_value "${threads}")"
  cores_per_socket="$(unsigned_value "${cores_per_socket}")"
  threads_per_core="$(unsigned_value "${threads_per_core}")"
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

console_window_offset() {
  offset="$(unsigned_value "${1:-0}")"
  total="$(unsigned_value "${2:-0}")"
  page_size="$(unsigned_value "${3:-1}")"
  direction="$4"
  [ "${page_size}" -gt 0 ] || page_size=1
  if [ "${total}" -le "${page_size}" ]; then
    printf '0'
    return
  fi
  case "${direction}" in
    next)
      offset=$((offset + page_size))
      [ "${offset}" -lt "${total}" ] || offset=0
      ;;
    previous)
      if [ "${offset}" -ge "${page_size}" ]; then
        offset=$((offset - page_size))
      else
        offset=$((((total - 1) / page_size) * page_size))
      fi
      ;;
  esac
  printf '%s' "${offset}"
}

console_framebuffer_size() {
  configured_size="${FRAMEBUFFER_SIZE:-}"
  if [ "${configured_size}" != "0,0" ] && printf '%s' "${configured_size}" | grep -Eq '^[0-9]+,[0-9]+$'; then
    printf '%s' "${configured_size}"
    return
  fi
  framebuffer_root="${FRAMEBUFFER_ROOT:-/sys/class/graphics}"
  for virtual_size in "${framebuffer_root}"/fb*/virtual_size; do
    [ -r "${virtual_size}" ] || continue
    configured_size="$(awk -F, 'NR == 1 {print $1 "," $2}' "${virtual_size}" 2>/dev/null || true)"
    if printf '%s' "${configured_size}" | grep -Eq '^[0-9]+,[0-9]+$'; then
      printf '%s' "${configured_size}"
      return
    fi
  done
  if command -v fbset >/dev/null 2>&1; then
    configured_size="$(fbset -s 2>/dev/null | awk '$1 == "geometry" {print $2 "," $3; exit}' || true)"
    if printf '%s' "${configured_size}" | grep -Eq '^[0-9]+,[0-9]+$'; then
      printf '%s' "${configured_size}"
      return
    fi
  fi
  printf '0,0'
}

console_viewport_dimension() {
  detected_dimension="$(unsigned_value "${1:-0}")"
  tty_dimension="$(unsigned_value "${2:-0}")"
  if [ "${tty_dimension}" -gt 0 ] && {
    [ "${detected_dimension}" -eq 0 ] ||
      [ "${tty_dimension}" -lt "${detected_dimension}" ]
  }; then
    printf '%s' "${tty_dimension}"
  else
    printf '%s' "${detected_dimension}"
  fi
}

console_terminal_rows() {
  rows=0
  framebuffer_size="$(console_framebuffer_size)"
  height="$(unsigned_value "${framebuffer_size#*,}")"
  candidate=$((height / 16))
  if [ "${candidate}" -ge 22 ] && [ "${candidate}" -le 120 ]; then rows="${candidate}"; fi
  if [ -c /dev/tty ]; then
    tty_rows="$(stty size 2>/dev/null </dev/tty | awk 'NR == 1 {print $1}' || true)"
    tty_rows="$(unsigned_value "${tty_rows:-0}")"
    rows="$(console_viewport_dimension "${rows}" "${tty_rows}")"
  fi
  [ "${rows}" -ge 22 ] || rows=30
  printf '%s' "${rows}"
}

console_terminal_columns() {
  columns=0
  framebuffer_size="$(console_framebuffer_size)"
  width="$(unsigned_value "${framebuffer_size%%,*}")"
  candidate=$((width / 8))
  if [ "${candidate}" -ge 80 ] && [ "${candidate}" -le 240 ]; then columns="${candidate}"; fi
  if [ -c /dev/tty ]; then
    tty_columns="$(stty size 2>/dev/null </dev/tty | awk 'NR == 1 {print $2}' || true)"
    tty_columns="$(unsigned_value "${tty_columns:-0}")"
    columns="$(console_viewport_dimension "${columns}" "${tty_columns}")"
  fi
  [ "${columns}" -ge 80 ] || columns=80
  printf '%s' "${columns}"
}

console_page_size() {
  kind="$1"
  rows="$(unsigned_value "${2:-30}")"
  [ "${rows}" -ge 22 ] || rows=30
  case "${kind}" in
    dimm) size=$((rows - 18)) ;;
    network) size=$(((rows - 6) / 3)) ;;
    storage) size=$(((rows - 6) / 2)) ;;
    *) size=1 ;;
  esac
  [ "${size}" -gt 0 ] || size=1
  printf '%s' "${size}"
}

console_apply_palette() {
  # Match the appliance console's slate, light body, brand blue, and pale-blue
  # header. Linux virtual terminals accept these palette definitions even when
  # only the base eight ANSI color slots are advertised.
  printf '\033]P00f172a\033]P42563eb'
  printf '\033]P6dbeafe\033]P7eef2f7'
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
  printf '  %-22s %s\n' "$1" "$2" | console_clip_lines "${CONSOLE_CONTENT_WIDTH:-78}"
}

console_clip_lines() {
  width="$(unsigned_value "${1:-78}")"
  [ "${width}" -gt 0 ] || width=78
  awk -v width="${width}" '{ print substr($0, 1, width) }'
}

render_inventory_console() {
  report="$1"
  page="$2"
  remaining="$3"
  paused="$4"
  host_id="$5"
  network_start="$(unsigned_value "${6:-0}")"
  storage_start="$(unsigned_value "${7:-0}")"
  dimm_start="$(unsigned_value "${8:-0}")"
  console_rows="$(unsigned_value "${9:-0}")"
  [ "${console_rows}" -ge 22 ] || console_rows="$(console_terminal_rows)"
  network_page_size="$(console_page_size network "${console_rows}")"
  storage_page_size="$(console_page_size storage "${console_rows}")"
  dimm_page_size="$(console_page_size dimm "${console_rows}")"
  console_columns="$(console_terminal_columns)"
  CONSOLE_CONTENT_WIDTH=$((console_columns - 2))
  [ "${CONSOLE_CONTENT_WIDTH}" -gt 0 ] || CONSOLE_CONTENT_WIDTH=78
  console_apply_palette
  printf '\033[?25l\033[47m\033[30m\033[2J\033[H'
  printf '\033[46m\033[30m\033[1m  Atlaso Inventory Linux  \033[22m\033[K\n'
  printf '\033[47m\033[30m\033[K\n'
  case "${page}" in
    1)
      printf '\033[1m  System / CPU / DIMMs\033[22m\033[K\n'
      console_line 'Manufacturer' "$(printf '%s' "${report}" | jq -r '.system.manufacturer')"
      console_line 'Product' "$(printf '%s' "${report}" | jq -r '[.system.product_name,.system.product_version] | map(select(length>0)) | join(" ")')"
      console_line 'Serial / UUID' "$(printf '%s' "${report}" | jq -r '(.system.serial_number + " / " + .system.dmi_uuid)')"
      console_line 'BIOS' "$(printf '%s' "${report}" | jq -r '[.system.bios_vendor,.system.bios_version,.system.bios_date] | map(select(length>0)) | join(" ")')"
      console_line 'Baseboard' "$(printf '%s' "${report}" | jq -r '[.system.baseboard.manufacturer,.system.baseboard.product,.system.baseboard.serial] | map(select(length>0)) | join(" / ")')"
      console_line 'Chassis' "$(printf '%s' "${report}" | jq -r '[.system.chassis.manufacturer,.system.chassis.type,.system.chassis.serial] | map(select(length>0)) | join(" / ")')"
      printf '\n\033[1m  CPU\033[22m\n'
      console_line 'Model' "$(printf '%s' "${report}" | jq -r '.cpu.model')"
      console_line 'Topology' "$(printf '%s' "${report}" | jq -r '"\(.cpu.sockets) sockets / \(.cpu.cores) cores / \(.cpu.threads) threads (\(.cpu.cores_per_socket) cores/socket, \(.cpu.threads_per_core) threads/core)"')"
      printf '\n\033[1m  Memory: %s\033[22m\n' "$(printf '%s' "${report}" | jq -r '.memory.total_human')"
      dimm_total="$(printf '%s' "${report}" | jq -r '.memory.dimms | length')"
      if [ "${dimm_start}" -ge "${dimm_total}" ]; then dimm_start=0; fi
      dimm_end=$((dimm_start + dimm_page_size))
      [ "${dimm_end}" -le "${dimm_total}" ] || dimm_end="${dimm_total}"
      if [ "${dimm_total}" -gt 0 ]; then dimm_first=$((dimm_start + 1)); else dimm_first=0; fi
      printf '  DIMMs %s-%s of %s  [J] More  [K] Back\n' "${dimm_first}" "${dimm_end}" "${dimm_total}"
      printf '%s' "${report}" | jq -r --argjson start "${dimm_start}" --argjson limit "${dimm_page_size}" '.memory.dimms[$start:($start + $limit)][] | "  \(.locator) | \(.bank) | \(.size_human) | \(.type) | \(.speed_mts) MT/s | \(.manufacturer) \(.part_number) | S/N \(.serial)"' | console_clip_lines "${CONSOLE_CONTENT_WIDTH}"
      footer_row=$((18 + dimm_end - dimm_start))
      [ "${footer_row}" -ge 20 ] || footer_row=20
      ;;
    2)
      printf '\033[1m  Network\033[22m\033[K\n'
      network_total="$(printf '%s' "${report}" | jq -r '.interfaces | length')"
      if [ "${network_start}" -ge "${network_total}" ]; then network_start=0; fi
      network_end=$((network_start + network_page_size))
      [ "${network_end}" -le "${network_total}" ] || network_end="${network_total}"
      if [ "${network_total}" -gt 0 ]; then network_first=$((network_start + 1)); else network_first=0; fi
      printf '  Interfaces %s-%s of %s  [J] More  [K] Back\n' "${network_first}" "${network_end}" "${network_total}"
      printf '%s' "${report}" | jq -r --argjson start "${network_start}" --argjson limit "${network_page_size}" '.interfaces[$start:($start + $limit)][] | "  " + (if .boot_interface then "* " else "  " end) + .name + "  " + ([.vendor,.device] | map(select(length > 0)) | join(" ")) + "\n      permanent " + .permanent_mac + "  current " + .current_mac + "  " + .link_state + " " + (.speed_mbps|tostring) + " Mb/s\n      " + (.addresses|join(", ")) + "  driver " + .driver + "  PCI " + .pci_address' | console_clip_lines "${CONSOLE_CONTENT_WIDTH}"
      footer_row=$((5 + (network_end - network_start) * 3))
      [ "${footer_row}" -ge 12 ] || footer_row=12
      ;;
    *)
      printf '\033[1m  Storage\033[22m\033[K\n'
      storage_total="$(printf '%s' "${report}" | jq -r '(.disks | length) + (.storage_controllers | length)')"
      if [ "${storage_start}" -ge "${storage_total}" ]; then storage_start=0; fi
      storage_end=$((storage_start + storage_page_size))
      [ "${storage_end}" -le "${storage_total}" ] || storage_end="${storage_total}"
      if [ "${storage_total}" -gt 0 ]; then storage_first=$((storage_start + 1)); else storage_first=0; fi
      printf '  Devices %s-%s of %s  [J] More  [K] Back\n' "${storage_first}" "${storage_end}" "${storage_total}"
      printf '%s' "${report}" | jq -r --argjson start "${storage_start}" --argjson limit "${storage_page_size}" '
        ([.disks[] | {kind:"Disk", value:.}] + [.storage_controllers[] | {kind:"Controller", value:.}])[$start:($start + $limit)][] |
        if .kind == "Disk" then
          "  [Disk] " + .value.device + "  " + .value.size_human + "  " + .value.type + "  " + .value.model +
          "\n      serial " + .value.serial + "  WWN " + .value.wwn + "  transport " + .value.transport +
          "  controller " + .value.controller_pci_address + "  flags " + (.value.flags|join(", "))
        else
          "  [Controller] " + .value.pci_address + "  " + .value.type + "  " +
          ([.value.vendor,.value.device] | map(select(length > 0)) | join(" ")) + "  driver " + .value.driver
        end' | console_clip_lines "${CONSOLE_CONTENT_WIDTH}"
      storage_lines="$(printf '%s' "${report}" | jq -r --argjson start "${storage_start}" --argjson limit "${storage_page_size}" '([.disks[] | 2] + [.storage_controllers[] | 1])[$start:($start + $limit)] | add // 0')"
      footer_row=$((5 + storage_lines))
      [ "${footer_row}" -ge 12 ] || footer_row=12
      ;;
  esac
  [ "${footer_row}" -lt "${console_rows}" ] || footer_row=$((console_rows - 1))
  CONSOLE_FOOTER_ROW="${footer_row}"
  printf '\033[%s;1H\033[44m\033[37m' "${CONSOLE_FOOTER_ROW}"
  render_inventory_console_footer_lines "${page}" "${remaining}" "${paused}" "${host_id}"
}

render_inventory_console_footer_lines() {
  page="$1"
  remaining="$2"
  paused="$3"
  host_id="$4"
  console_columns="$(console_terminal_columns)"
  if [ "${paused}" = "true" ]; then countdown="Paused at ${remaining}s"; else countdown="Reboot in ${remaining}s"; fi
  printf '%*s\r  Host %s  |  Page %s/3  |  %s\n' "${console_columns}" '' "${host_id}" "${page}" "${countdown}"
  printf '%*s\r  [N/P] Page  [1-3] Select  [J/K] List  [S] Pause/resume  [R] Reboot now\n' "${console_columns}" ''
  printf '\033[47m\033[30m\033[?25l'
}

refresh_inventory_console_footer() {
  console_rows="$(unsigned_value "${5:-0}")"
  [ "${console_rows}" -ge 22 ] || console_rows="$(console_terminal_rows)"
  footer_row="$(unsigned_value "${CONSOLE_FOOTER_ROW:-0}")"
  [ "${footer_row}" -ge 2 ] || footer_row=$((console_rows - 1))
  [ "${footer_row}" -lt "${console_rows}" ] || footer_row=$((console_rows - 1))
  printf '\033[%s;1H\033[44m\033[37m' "${footer_row}"
  render_inventory_console_footer_lines "$1" "$2" "$3" "$4"
}
