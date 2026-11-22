#!/bin/sh
set -eu

build=/var/tmp/atlaso-ova-build
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
# The sources must survive the kernel-switch reboot even when /tmp is tmpfs.
export ATLASO_SRC="$build/source"
if [ ! -e "$build/generic-kernel-ready" ]; then
    # The official image boots linux-esx. The canonical appliance uses the
    # generic Photon kernel to support VMware and the portable import targets.
    tdnf -y install python3 tar shadow
    install -d -m 0700 "$ATLASO_SRC"
    tar -xf "$build/source.tar" -C "$ATLASO_SRC"
    python3 "$ATLASO_SRC/image/common/scripts/configure_photon_repositories.py"
    install -d -m 0755 /etc/dracut.conf.d
    printf '%s\n' 'add_drivers+=" vmw_pvscsi virtio_scsi virtio_blk hv_storvsc "' \
        > /etc/dracut.conf.d/90-atlaso-virtual-storage.conf
    tdnf -y install linux initramfs
    config=$(find /boot -maxdepth 1 -type f -name 'linux-*.cfg' ! -name '*-esx.cfg')
    [ -n "$config" ] && [ "$(printf '%s\n' "$config" | wc -l)" -eq 1 ]
    ln -sfn "${config##*/}" /boot/photon.cfg
    touch "$build/generic-kernel-ready"
    sync
    systemctl reboot --no-block
    exit
fi

case "$(uname -r)" in
    *-esx) echo "The generic Photon kernel did not boot."; exit 2 ;;
esac
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

# Atlaso's deployed management definition uses eth0. During the build the
# upstream en* DHCP policy keeps package downloads connected.
rm -f /etc/systemd/network/99-dhcp-en.network
sed -i '/^[[:space:]]*linux \/\(boot\/\)\?\$photon_linux\([[:space:]]\|$\)/ s/$/ net.ifnames=0 biosdevname=0/' /boot/grub2/grub.cfg
grep -q 'net.ifnames=0 biosdevname=0' /boot/grub2/grub.cfg
install -d -m 0700 /var/lib/atlaso-ova-build
cat /etc/atlaso/build-info > /var/lib/atlaso-ova-build/complete
systemctl disable atlaso-ova-build.service
rm -f /etc/systemd/system/atlaso-ova-build.service
rm -rf "$build"
exec /bin/sh /opt/atlaso/bin/atlaso-finalize-image-build atlaso-build
