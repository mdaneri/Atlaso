#!/bin/sh
set -eu

library="$1"
client="$2"
fixture_root="$(mktemp -d)"
trap 'rm -rf "${fixture_root}"' EXIT
export ATLASO_SYSFS_ROOT="${fixture_root}/sys"
export ATLASO_PROC_ROOT="${fixture_root}/proc"
export ATLASO_RUNTIME_ROOT="${fixture_root}/run"
mkdir -p "${ATLASO_SYSFS_ROOT}" "${ATLASO_PROC_ROOT}" "${ATLASO_RUNTIME_ROOT}" "${fixture_root}/bin"
PATH="${fixture_root}/bin:${PATH}"
export PATH

fail() {
  printf 'inventory shell fixture failed: %s\n' "$1" >&2
  exit 1
}

assert_jq() {
  value="$1"
  expression="$2"
  printf '%s' "${value}" | jq -e "${expression}" >/dev/null || fail "jq assertion ${expression}"
}

. "${library}"

make_pci() {
  address="$1"
  class="$2"
  vendor="$3"
  device="$4"
  driver="$5"
  path="${ATLASO_SYSFS_ROOT}/bus/pci/devices/${address}"
  mkdir -p "${path}" "${ATLASO_SYSFS_ROOT}/drivers/${driver}"
  printf '0x%s\n' "${class}" >"${path}/class"
  printf '0x%s\n' "${vendor}" >"${path}/vendor"
  printf '0x%s\n' "${device}" >"${path}/device"
  printf '0x%s\n' "${vendor}" >"${path}/subsystem_vendor"
  printf '0x0001\n' >"${path}/subsystem_device"
  ln -s "${ATLASO_SYSFS_ROOT}/drivers/${driver}" "${path}/driver"
}

make_pci 0000:02:00.0 020000 8086 10fb ixgbe
make_pci 0000:03:00.0 010601 8086 2922 ahci

for name in eth0 eth1; do
  path="${ATLASO_SYSFS_ROOT}/class/net/${name}"
  mkdir -p "${path}"
  [ "${name}" = "eth0" ] && pci=0000:02:00.0 || pci=0000:03:00.0
  ln -s "${ATLASO_SYSFS_ROOT}/bus/pci/devices/${pci}" "${path}/device"
  printf 'up\n' >"${path}/operstate"
  printf '10000\n' >"${path}/speed"
done
printf '52:54:00:11:22:33\n' >"${ATLASO_SYSFS_ROOT}/class/net/eth0/address"
printf '52:54:00:44:55:66\n' >"${ATLASO_SYSFS_ROOT}/class/net/eth1/address"

make_disk() {
  name="$1"
  controller="$2"
  sectors="$3"
  rotational="$4"
  removable="$5"
  model="$6"
  serial="$7"
  device_path="${ATLASO_SYSFS_ROOT}/bus/pci/devices/${controller}/disk-${name}"
  class_path="${ATLASO_SYSFS_ROOT}/class/block/${name}"
  mkdir -p "${device_path}" "${class_path}/queue"
  ln -s "${device_path}" "${class_path}/device"
  printf '%s\n' "${sectors}" >"${class_path}/size"
  printf '%s\n' "${rotational}" >"${class_path}/queue/rotational"
  printf '%s\n' "${removable}" >"${class_path}/removable"
  printf '0\n' >"${class_path}/ro"
  printf '%s\n' "${model}" >"${device_path}/model"
  printf '%s\n' "${serial}" >"${device_path}/serial"
}
make_disk sda 0000:03:00.0 209715200 1 0 'Fixture HDD' HDD-1
make_disk nvme0n1 0000:03:00.0 104857600 0 0 'Fixture NVMe' NVME-1

for usb in 1-1 1-2; do
  path="${ATLASO_SYSFS_ROOT}/bus/usb/devices/${usb}"
  mkdir -p "${path}"
  printf '0781\n' >"${path}/idVendor"
  printf '5581\n' >"${path}/idProduct"
  printf '1\n' >"${path}/busnum"
  printf '%s\n' "${usb#1-}" >"${path}/devnum"
  printf '08\n' >"${path}/bDeviceClass"
  printf 'USB Vendor\n' >"${path}/manufacturer"
  printf 'Fixture USB\n' >"${path}/product"
  printf '%s\n' "USB-${usb}" >"${path}/serial"
done

cat >"${fixture_root}/bin/lspci" <<'EOF'
#!/bin/sh
for value in "$@"; do address="${value}"; done
case "${address}" in
  0000:02:00.0)
    printf 'Slot:\t%s\nClass:\tEthernet controller [0200]\nVendor:\tIntel Corporation [8086]\nDevice:\t10-Gigabit Network Connection [10fb]\n' "${address}"
    ;;
  *)
    printf 'Slot:\t%s\nClass:\tSATA controller [0106]\nVendor:\tIntel Corporation [8086]\nDevice:\tSATA Controller [2922]\n' "${address}"
    ;;
esac
EOF
cat >"${fixture_root}/bin/ethtool" <<'EOF'
#!/bin/sh
[ "$2" = "eth0" ] && mac=52:54:00:11:22:33 || mac=52:54:00:44:55:66
printf 'Permanent address: %s\n' "${mac}"
EOF
cat >"${fixture_root}/bin/ip" <<'EOF'
#!/bin/sh
for value in "$@"; do name="${value}"; done
case "${name}" in
  eth0) address=192.0.2.10 ;;
  *) address=198.51.100.10 ;;
esac
printf '[{"addr_info":[{"local":"%s","prefixlen":24}]}]\n' "${address}"
EOF
cat >"${fixture_root}/bin/lsblk" <<'EOF'
#!/bin/sh
printf '%s\n' '{"blockdevices":[{"name":"sda","wwn":"0x5000","tran":"sata"},{"name":"nvme0n1","wwn":"eui.0001","tran":"nvme"}]}'
EOF
cat >"${fixture_root}/bin/dmidecode" <<'EOF'
#!/bin/sh
cat <<'DMI'
Memory Device
        Size: 16 GB
        Locator: DIMM_A1
        Bank Locator: BANK 0
        Type: DDR5
        Configured Memory Speed: 4800 MT/s
        Manufacturer: Memory Vendor
        Serial Number: DIMM-1
        Part Number: MEM-16G

Memory Device
        Size: 16 GB
        Locator: DIMM_B1
        Bank Locator: BANK 1
        Type: DDR5
        Speed: 4800 MT/s
        Manufacturer: Memory Vendor
        Serial Number: DIMM-2
        Part Number: MEM-16G
DMI
EOF
cat >"${fixture_root}/bin/lscpu" <<'EOF'
#!/bin/sh
printf '%s\n' '{"lscpu":[{"field":"Architecture:","data":"x86_64"},{"field":"Vendor ID:","data":"GenuineIntel"},{"field":"Model name:","data":"Fixture CPU"},{"field":"CPU(s):","data":"32"},{"field":"Socket(s):","data":"2"},{"field":"Core(s) per socket:","data":"8"},{"field":"Thread(s) per core:","data":"2"}]}'
EOF
chmod +x "${fixture_root}/bin/"*

pci="$(collect_pci_devices)"
controllers="$(collect_storage_controllers "${pci}")"
interfaces="$(collect_interfaces eth0)"
disks="$(collect_disks)"
dimms="$(collect_dimms)"
usb="$(collect_usb_devices)"
cpu="$(collect_cpu)"

assert_jq "${pci}" 'length == 2 and .[0].vendor_id == "8086" and .[1].class_id == "010601"'
assert_jq "${controllers}" 'length == 1 and .[0].type == "SATA" and .[0].driver == "ahci"'
assert_jq "${interfaces}" 'length == 2 and .[0].boot_interface and .[1].current_mac == "52:54:00:44:55:66"'
assert_jq "${disks}" 'length == 2 and (map(select(.device == "/dev/sda"))[0].type == "HDD") and (map(select(.device == "/dev/nvme0n1"))[0].type == "NVMe") and (map(select(.device == "/dev/nvme0n1"))[0].size_human == "50.0 GiB") and (map(select(.device == "/dev/sda"))[0].controller_pci_address == "0000:03:00.0")'
assert_jq "${dimms}" 'length == 2 and .[0].locator == "DIMM_A1" and .[1].speed_mts == 4800 and .[0].size_bytes == 17179869184'
assert_jq "${usb}" 'length == 2 and .[0].class == "Mass storage" and .[1].serial == "USB-1-2"'
assert_jq "${cpu}" '.sockets == 2 and .cores == 16 and .threads == 32 and .cores_per_socket == 8 and .threads_per_core == 2'
[ "$(human_size 1073741824)" = "1.00 GiB" ] || fail 'human size'
[ "$(dimm_size_bytes '4096 MB')" = "4294967296" ] || fail 'DIMM size exceeds 32-bit arithmetic'
[ "$(printf '%s' "$(bounded_text 240 "$(printf '%0241d' 0)")" | wc -c)" -eq 240 ] || fail 'string limit'
[ "$(cycle_console_page 3 next)" = "1" ] || fail 'next page wraps'
[ "$(cycle_console_page 1 previous)" = "3" ] || fail 'previous page wraps'
[ "$(countdown_after_elapsed 120 false 30)" = "90" ] || fail 'countdown advances'
[ "$(countdown_after_elapsed 90 true 30)" = "90" ] || fail 'countdown pauses'
[ "$(countdown_after_elapsed 90 false 90)" = "0" ] || fail 'countdown reaches automatic reboot boundary'
[ "$(console_key_action S 2 false)" = "2|true|none" ] || fail 'pause key'
[ "$(console_key_action S 2 true)" = "2|false|none" ] || fail 'resume key'
[ "$(console_key_action R 2 false)" = "2|false|reboot" ] || fail 'local reboot key'
grep -F '[ "${remaining}" -gt 0 ] || reboot -f' "${client}" >/dev/null || fail 'automatic reboot integration'
grep -F '[ "${key_action}" != "reboot" ] || reboot -f' "${client}" >/dev/null || fail 'local reboot integration'

cat >"${fixture_root}/bin/curl" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >>"${CURL_LOG}"
exit 0
EOF
chmod +x "${fixture_root}/bin/curl"
export CURL_LOG="${fixture_root}/curl.log"
auth_config="${fixture_root}/auth.conf"
: >"${auth_config}"
acknowledge_remote_reboot 'https://192.0.2.1' "${auth_config}" command-42 || fail 'remote reboot acknowledgment'
grep -F '/pxe/inventory/commands/command-42/acknowledge' "${CURL_LOG}" >/dev/null || fail 'remote reboot URL'
grep -F 'acknowledge_remote_reboot' "${client}" >/dev/null || fail 'remote reboot integration'

report="$(jq -cn --argjson interfaces "${interfaces}" --argjson disks "${disks}" \
  --argjson dimms "${dimms}" --argjson controllers "${controllers}" --argjson cpu "${cpu}" \
  '{system:{manufacturer:"Atlaso",product_name:"Fixture",product_version:"1",serial_number:"S",dmi_uuid:"U",bios_vendor:"B",bios_version:"1",bios_date:"D",baseboard:{manufacturer:"BM",product:"BP",serial:"BS"},chassis:{manufacturer:"CM",type:"Rack",serial:"CS"}},cpu:$cpu,memory:{total_human:"32.0 GiB",dimms:$dimms},interfaces:$interfaces,disks:$disks,storage_controllers:$controllers}')"
console="$(render_inventory_console "${report}" 2 90 false 7)"
printf '%s' "${console}" | grep -F 'Atlaso Inventory Linux' >/dev/null || fail 'console header'
printf '%s' "${console}" | grep -F 'Network' >/dev/null || fail 'network page'
printf '%s' "${console}" | grep -F 'Page 2/3' >/dev/null || fail 'console paging footer'
printf '%s' "${console}" | grep -F '[S] Pause/resume' >/dev/null || fail 'console actions'
footer="$(refresh_inventory_console_footer 2 89 true 7)"
printf '%s' "${footer}" | grep -F 'Paused at 89s' >/dev/null || fail 'in-place countdown footer refresh'
if grep -F '| gsub(' "${library}" >/dev/null; then fail 'Buildroot jq regex dependency'; fi

printf 'Inventory Linux shell fixtures passed.\n'
