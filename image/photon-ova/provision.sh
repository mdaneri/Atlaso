#!/bin/sh
set -eu

build=/var/tmp/atlaso-ova-build
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export ATLASO_SRC="$build/source"
case "$(uname -r)" in
    *-esx) echo "The generic Photon kernel did not boot."; exit 2 ;;
esac
# The shared provisioner verifies PowerCLI as the unprivileged appliance admin.
# That account needs to traverse the seed directory and read the public sources.
chmod 0711 "$build"
install -d -m 0755 "$ATLASO_SRC"
tar -xf "$build/source.tar" -C "$ATLASO_SRC"
tdnf -y --noautoremove remove linux-esx
useradd --create-home --home-dir /home/atlaso-build --shell /usr/sbin/nologin atlaso-build
root_disk=$(lsblk -s -n -o PATH,TYPE "$(findmnt -n -o SOURCE /)" | awk '$2 == "disk" { print $1 }')
root_tuple=$(basename "$(readlink -f "/sys/class/block/${root_disk##*/}/device")" | cut -d: -f2-4)
[ "$root_tuple" = 0:0:0 ]
# QEMU's PVSCSI target numbers match the VMware provisioner's SCSI tuple.
export ATLASO_ROOT_SCSI_TUPLE=0:0:0 ATLASO_SYSTEM_SCSI_TUPLE=0:1:0
export ATLASO_ROOT_DISK_SIZE_BYTES=42949672960 ATLASO_SYSTEM_DISK_SIZE_BYTES=21474836480
export ATLASO_GUEST_PLATFORM=vmware ATLASO_SYSTEM_CONTENT_DISK=true ATLASO_TEMPLATE_LOCKED_ADMIN=true
export ATLASO_MGMT_ADDRESS=dhcp ATLASO_MGMT_INTERFACE=eth0 ATLASO_DRY_RUN_SYSTEM_ADAPTERS=false
sh "$ATLASO_SRC/image/common/scripts/provision-atlaso.sh"

# During the build Photon's upstream e* DHCP match keeps downloads connected.
rm -f /etc/systemd/network/99-dhcp-en.network
# Restore the graphical menu for VMware. The inherited EFI GRUB has no BIOS VBE module.
sed '/^insmod vbe$/d; /^[[:space:]]*linux \/\(boot\/\)\?\$photon_linux\([[:space:]]\|$\)/ s/$/ net.ifnames=0 biosdevname=0/' \
    "$build/grub.cfg" > /boot/grub2/grub.cfg
grep -q 'net.ifnames=0 biosdevname=0' /boot/grub2/grub.cfg
install -d -m 0700 /var/lib/atlaso-ova-build
cat /etc/atlaso/build-info > /var/lib/atlaso-ova-build/complete
systemctl disable atlaso-ova-build.service
rm -f /etc/systemd/system/atlaso-ova-build.service
rm -rf "$build"
exec /bin/sh /opt/atlaso/bin/atlaso-finalize-image-build atlaso-build
