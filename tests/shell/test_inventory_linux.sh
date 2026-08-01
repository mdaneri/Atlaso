#!/bin/sh
set -eu

library="$1"
client="$2"
fixture_root="$(mktemp -d)"
trap 'rm -rf "${fixture_root}"' EXIT
export ATLASO_SYSFS_ROOT="${fixture_root}/sys"
export ATLASO_PROC_ROOT="${fixture_root}/proc"
export ATLASO_RUNTIME_ROOT="${fixture_root}/run"
# Keep console geometry deterministic on CI hosts that expose a framebuffer.
export FRAMEBUFFER_SIZE="0,0"
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
make_pci 0000:04:00.0 0c0330 8086 1e31 xhci_hcd

for name in eth0 eth1; do
  path="${ATLASO_SYSFS_ROOT}/class/net/${name}"
  mkdir -p "${path}"
  [ "${name}" = "eth0" ] && pci=0000:02:00.0 || pci=0000:03:00.0
  ln -s "${ATLASO_SYSFS_ROOT}/bus/pci/devices/${pci}" "${path}/device"
  printf '1\n' >"${path}/type"
  printf 'up\n' >"${path}/operstate"
  printf '10000\n' >"${path}/speed"
done
printf '52:54:00:11:22:33\n' >"${ATLASO_SYSFS_ROOT}/class/net/eth0/address"
printf '52:54:00:44:55:66\n' >"${ATLASO_SYSFS_ROOT}/class/net/eth1/address"
usb_net_device="${ATLASO_SYSFS_ROOT}/bus/pci/devices/0000:04:00.0/usb1/1-1/1-1:1.0"
mkdir -p "${usb_net_device}" "${ATLASO_SYSFS_ROOT}/class/net/usb0"
ln -s "${usb_net_device}" "${ATLASO_SYSFS_ROOT}/class/net/usb0/device"
printf '1\n' >"${ATLASO_SYSFS_ROOT}/class/net/usb0/type"
printf 'up\n' >"${ATLASO_SYSFS_ROOT}/class/net/usb0/operstate"
printf '1000\n' >"${ATLASO_SYSFS_ROOT}/class/net/usb0/speed"
printf '52:54:00:77:88:99\n' >"${ATLASO_SYSFS_ROOT}/class/net/usb0/address"
mkdir -p "${ATLASO_SYSFS_ROOT}/class/net/sit0"
printf '776\n' >"${ATLASO_SYSFS_ROOT}/class/net/sit0/type"

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
make_disk sda 0000:03:00.0 209715200 1 0 'Fixture HDD' ''
make_disk nvme0n1 0000:03:00.0 104857600 0 0 'Fixture NVMe' NVME-1
make_disk sr0 0000:03:00.0 1048576 0 1 'Fixture DVD' DVD-1
printf '5\n' >"${ATLASO_SYSFS_ROOT}/bus/pci/devices/0000:03:00.0/disk-sr0/type"

mkdir -p "${ATLASO_SYSFS_ROOT}/class/scsi_host/host9/device"
printf 'storvsc_host\n' >"${ATLASO_SYSFS_ROOT}/class/scsi_host/host9/proc_name"
printf 'Microsoft\n' >"${ATLASO_SYSFS_ROOT}/class/scsi_host/host9/device/vendor"
printf 'Virtual SCSI\n' >"${ATLASO_SYSFS_ROOT}/class/scsi_host/host9/device/model"

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

make_dmi_dimm() {
  instance="$1"
  handle="$2"
  size_low_octal="$3"
  size_high_octal="$4"
  path="${ATLASO_SYSFS_ROOT}/firmware/dmi/entries/17-${instance}"
  mkdir -p "${path}"
  awk 'BEGIN { for (i = 0; i < 32; i++) printf "%c", 0 }' >"${path}/raw"
  handle_value=$((handle))
  handle_low_octal="$(printf '%03o' $((handle_value % 256)))"
  handle_high_octal="$(printf '%03o' $((handle_value / 256)))"
  printf "\\${handle_low_octal}\\${handle_high_octal}" | dd of="${path}/raw" bs=1 seek=2 conv=notrunc 2>/dev/null
  printf "\\${size_low_octal}\\${size_high_octal}" | dd of="${path}/raw" bs=1 seek=12 conv=notrunc 2>/dev/null
}
make_dmi_dimm 0 0x0011 000 100
make_dmi_dimm 1 0x0012 000 100
make_dmi_dimm 2 0x0013 000 040

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
case "$2" in
  eth0) mac=52:54:00:11:22:33 ;;
  eth1) mac=52:54:00:44:55:66 ;;
  *) mac=52:54:00:77:88:99 ;;
esac
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
printf '%s\n' '{"blockdevices":[{"name":"sda","wwn":"0x5000","tran":"sata","serial":"HDD-LSBLK-1"},{"name":"nvme0n1","wwn":"eui.0001","tran":"nvme","serial":"NVME-UDEV"},{"name":"sr0","wwn":"","tran":"sata","serial":"DVD-UDEV"}]}'
EOF
cat >"${fixture_root}/bin/dmidecode" <<'EOF'
#!/bin/sh
cat <<'DMI'
Handle 0x0011, DMI type 17, 92 bytes
Memory Device
        Size: 16 GB
        Locator: DIMM_A1
        Bank Locator: BANK 0
        Type: DDR5
        Configured Memory Speed: 4800 MT/s
        Manufacturer: Memory Vendor
        Serial Number: DIMM-1
        Part Number: MEM-16G

Handle 0x0012, DMI type 17, 92 bytes
Memory Device
        Size: 16 GB
        Locator: DIMM_B1
        Bank Locator: BANK 1
        Type: DDR5
        Speed: 4800 MT/s
        Manufacturer: Memory Vendor
        Serial Number: DIMM-2
        Part Number: MEM-16G

Handle 0x0099, DMI type 17, 92 bytes
Memory Device
        Size: 64 GB
        Locator: PHANTOM
        Bank Locator: BANK 9
        Type: DDR5
        Speed: 4800 MT/s
        Manufacturer: Stale Firmware Record
        Serial Number: PHANTOM
        Part Number: PHANTOM
DMI
EOF
cat >"${fixture_root}/bin/lscpu" <<'EOF'
#!/bin/sh
printf '%s\n' '{"lscpu":[{"field":"Architecture:","data":"x86_64"},{"field":"Vendor ID:","data":"GenuineIntel"},{"field":"Model name:","data":"Fixture CPU"}]}'
EOF
chmod +x "${fixture_root}/bin/"*

cpu_index=0
while [ "${cpu_index}" -lt 32 ]; do
  package_id=$((cpu_index / 16))
  core_id=$(((cpu_index % 16) / 2))
  cpu_path="${ATLASO_SYSFS_ROOT}/devices/system/cpu/cpu${cpu_index}"
  mkdir -p "${cpu_path}/topology"
  printf '%s\n' "${package_id}" >"${cpu_path}/topology/physical_package_id"
  printf '%s\n' "${core_id}" >"${cpu_path}/topology/core_id"
  cpu_index=$((cpu_index + 1))
done

pci="$(collect_pci_devices)"
pci_file="${fixture_root}/pci.json"
printf '%s' "${pci}" >"${pci_file}"
controllers="$(collect_storage_controllers "${pci_file}")"
interfaces="$(collect_interfaces eth0)"
disks="$(collect_disks)"
dimms="$(collect_dimms)"
usb="$(collect_usb_devices)"
cpu="$(collect_cpu)"

assert_jq "${pci}" 'length == 3 and .[0].vendor_id == "8086" and .[1].class_id == "010601"'
assert_jq "${controllers}" 'length == 2 and .[0].type == "SATA" and .[0].driver == "ahci" and .[1].type == "Hyper-V SCSI" and .[1].driver == "storvsc_host" and .[1].pci_address == ""'
assert_jq "${interfaces}" 'length == 3 and .[0].boot_interface and .[1].current_mac == "52:54:00:44:55:66" and (map(select(.name == "usb0"))[0].pci_address == "")'
assert_jq "${disks}" 'length == 3 and (map(select(.device == "/dev/sda"))[0].type == "HDD") and (map(select(.device == "/dev/sda"))[0].serial == "HDD-LSBLK-1") and (map(select(.device == "/dev/nvme0n1"))[0].type == "NVMe") and (map(select(.device == "/dev/nvme0n1"))[0].serial == "NVME-1") and (map(select(.device == "/dev/sr0"))[0].type == "Optical") and (map(select(.device == "/dev/nvme0n1"))[0].size_human == "50.0 GiB") and (map(select(.device == "/dev/sda"))[0].controller_pci_address == "0000:03:00.0")'
assert_jq "${dimms}" 'length == 3 and .[0].locator == "DIMM_A1" and .[1].speed_mts == 4800 and .[0].size_bytes == 17179869184 and .[2].size_bytes == 8589934592 and .[2].locator == "" and (map(.locator) | index("PHANTOM") == null)'
assert_jq "${usb}" 'length == 2 and .[0].class == "Mass storage" and .[1].serial == "USB-1-2"'
assert_jq "${cpu}" '.sockets == 2 and .cores == 16 and .threads == 32 and .cores_per_socket == 8 and .threads_per_core == 2'
[ "$(human_size 1073741824)" = "1.00 GiB" ] || fail 'human size'
[ "$(dmi_sysfs_handle "${ATLASO_SYSFS_ROOT}/firmware/dmi/entries/17-0/raw")" = "0x0011" ] || fail 'sysfs DIMM handle'
[ "$(dimm_size_bytes '4096 MiB')" = "4294967296" ] || fail 'dmidecode 3.7 binary DIMM size'
[ "$(dimm_size_bytes '4 GB')" = "4294967296" ] || fail 'legacy decimal DIMM size'
[ "$(printf '%s' "$(bounded_text 240 "$(printf '%0241d' 0)")" | wc -c)" -eq 240 ] || fail 'string limit'
[ "$(cycle_console_page 3 next)" = "1" ] || fail 'next page wraps'
[ "$(cycle_console_page 1 previous)" = "3" ] || fail 'previous page wraps'
[ "$(console_window_offset 0 12 5 next)" = "5" ] || fail 'list paging advances'
[ "$(console_window_offset 10 12 5 next)" = "0" ] || fail 'list paging wraps'
[ "$(console_window_offset 0 12 5 previous)" = "10" ] || fail 'list paging wraps backward'
[ "$(console_page_size dimm 30)" = "12" ] || fail '30-row DIMM capacity'
[ "$(console_page_size network 30)" = "8" ] || fail '30-row network capacity'
[ "$(console_page_size storage 30)" = "12" ] || fail '30-row storage capacity'
[ "$(console_page_size network 22)" = "5" ] || fail 'compact network capacity'
framebuffer_root="${fixture_root}/graphics"
mkdir -p "${framebuffer_root}/fb0"
printf '1024,768\n' >"${framebuffer_root}/fb0/virtual_size"
[ "$(FRAMEBUFFER_ROOT="${framebuffer_root}" console_terminal_rows)" = "48" ] || fail 'framebuffer row capacity'
[ "$(FRAMEBUFFER_ROOT="${framebuffer_root}" console_terminal_columns)" = "128" ] || fail 'framebuffer column capacity'
[ "$(FRAMEBUFFER_SIZE='1024,768' console_terminal_rows)" = "48" ] || fail 'fbset row capacity'
[ "$(FRAMEBUFFER_SIZE='1024,768' console_terminal_columns)" = "128" ] || fail 'fbset column capacity'
[ "$(countdown_after_elapsed 300 false 30)" = "270" ] || fail 'countdown advances from five minutes'
[ "$(countdown_after_elapsed 90 true 30)" = "90" ] || fail 'countdown pauses'
[ "$(countdown_after_elapsed 90 false 90)" = "0" ] || fail 'countdown reaches automatic reboot boundary'
[ "$(console_key_action S 2 false)" = "2|true|none" ] || fail 'pause key'
[ "$(console_key_action S 2 true)" = "2|false|none" ] || fail 'resume key'
[ "$(console_key_action R 2 false)" = "2|false|reboot" ] || fail 'local reboot key'
grep -F '[ "${remaining}" -gt 0 ] || reboot -f' "${client}" >/dev/null || fail 'automatic reboot integration'
grep -F 'countdown_after_elapsed "${remaining}" "${paused}" "${key_elapsed}"' "${client}" >/dev/null || fail 'key-read elapsed countdown integration'
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
printf '%s' "${console}" | grep -F "$(printf 'Atlaso Inventory Linux  \033[22m\033[K\n\033[47m\033[30m\033[K\n')" >/dev/null || fail 'blank line below console header'
printf '%s' "${console}" | grep -F 'Network' >/dev/null || fail 'network page'
printf '%s' "${console}" | grep -F 'Interfaces 1-3 of 3' >/dev/null || fail 'network list window'
printf '%s' "${console}" | grep -F 'Page 2/3' >/dev/null || fail 'console paging footer'
printf '%s' "${console}" | grep -F '[S] Pause/resume' >/dev/null || fail 'console actions'
printf '%s' "${console}" | grep -F "$(printf '\033]P6dbeafe')" >/dev/null || fail 'appliance pale-blue palette'
printf '%s' "${console}" | grep -F "$(printf '\033]P7eef2f7')" >/dev/null || fail 'appliance light palette'
printf '%s' "${console}" | grep -F "$(printf '\033[46m')" >/dev/null || fail 'console-native pale-blue header'
printf '%s' "${console}" | grep -F "$(printf '\033[47m')" >/dev/null || fail 'console-native light content'
printf '%s' "${console}" | grep -F "$(printf '\033[44m')" >/dev/null || fail 'console-native blue footer'
printf '%s' "${console}" | grep -F "$(printf '\033[14;1H')" >/dev/null || fail 'network footer follows populated rows'
if printf '%s' "${console}" | grep -F "$(printf '\033[0m')" >/dev/null; then fail 'content resets to black terminal background'; fi
footer="$(refresh_inventory_console_footer 2 89 true 7)"
printf '%s' "${footer}" | grep -F 'Paused at 89s' >/dev/null || fail 'in-place countdown footer refresh'
wide_footer="$(FRAMEBUFFER_SIZE='1024,768' refresh_inventory_console_footer 2 89 true 7 48)"
printf '%s' "${wide_footer}" | grep -F "$(printf '\033[47;1H')" >/dev/null || fail 'framebuffer footer uses physical bottom row'
many_report="$(printf '%s' "${report}" | jq '.interfaces = [range(0;8) as $index | (.interfaces[0] | .name = ("nic" + ($index|tostring)))]')"
network_full="$(render_inventory_console "${many_report}" 2 90 false 7)"
printf '%s' "${network_full}" | grep -F 'Interfaces 1-8 of 8' >/dev/null || fail '30-row network capacity reduces paging'
network_window="$(render_inventory_console "${many_report}" 2 90 false 7 5)"
printf '%s' "${network_window}" | grep -F 'Interfaces 6-8 of 8' >/dev/null || fail 'network list subpage status'
printf '%s' "${network_window}" | grep -F 'nic5' >/dev/null || fail 'network list subpage first row'
if printf '%s' "${network_window}" | grep -F 'nic0' >/dev/null; then fail 'network list subpage bounds'; fi
many_storage_report="$(printf '%s' "${report}" | jq '.disks = [range(0;8) as $index | (.disks[0] | .device = ("/dev/disk" + ($index|tostring)))]')"
storage_window="$(render_inventory_console "${many_storage_report}" 3 90 false 7 0 5)"
printf '%s' "${storage_window}" | grep -F 'Devices 6-10 of 10' >/dev/null || fail 'storage list subpage status'
printf '%s' "${storage_window}" | grep -F '/dev/disk5' >/dev/null || fail 'storage list subpage first row'
printf '%s' "${storage_window}" | grep -F '[Controller]' >/dev/null || fail 'storage controller retained in list window'
if printf '%s' "${storage_window}" | grep -F '/dev/disk0' >/dev/null; then fail 'storage list subpage bounds'; fi
many_dimm_report="$(printf '%s' "${report}" | jq '.memory.dimms = [range(0;8) as $index | (.memory.dimms[0] | .locator = ("DIMM_" + ($index|tostring)))]')"
dimm_window="$(render_inventory_console "${many_dimm_report}" 1 90 false 7 0 0 5)"
printf '%s' "${dimm_window}" | grep -F 'DIMMs 6-8 of 8' >/dev/null || fail 'DIMM list subpage status'
printf '%s' "${dimm_window}" | grep -F 'DIMM_5' >/dev/null || fail 'DIMM list subpage first row'
if printf '%s' "${dimm_window}" | grep -F 'DIMM_0' >/dev/null; then fail 'DIMM list subpage bounds'; fi
[ "$(printf '%0100d\n' 0 | console_clip_lines 78 | awk '{ print length }')" = "78" ] || fail 'console line clipping'
[ "$(CONSOLE_CONTENT_WIDTH=78 console_line Product "$(printf '%0200d' 0)" | awk '{ print length }')" = "78" ] || fail 'fixed system field clipping'
if grep -F '| gsub(' "${library}" >/dev/null; then fail 'Buildroot jq regex dependency'; fi
grep -F -- '--slurpfile pci_devices' "${client}" >/dev/null || fail 'large inventory file input'
grep -F 'report="$(jq -cn' "${client}" >/dev/null || fail 'compact report serialization'

printf 'Inventory Linux shell fixtures passed.\n'
