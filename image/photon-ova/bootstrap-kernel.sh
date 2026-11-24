#!/bin/sh
set -eu
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

# The upstream ESXi kernel cannot boot on the Linux/KVM builder.
python3 /var/tmp/atlaso-ova-build/configure_photon_repositories.py
tdnf -y update kmod dracut zstd
install -d -m 0755 /etc/dracut.conf.d
printf '%s\n' 'add_drivers+=" vmw_pvscsi virtio_scsi virtio_blk hv_storvsc "' \
    > /etc/dracut.conf.d/90-atlaso-virtual-storage.conf
tdnf -y install linux initramfs tar shadow

config=$(readlink -f /boot/photon.cfg)
case "$config" in
    *-esx.cfg) echo "Photon still selects the ESXi kernel." >&2; exit 2 ;;
    /boot/linux-*.cfg) ;;
    *) echo "Photon did not select an installed generic kernel." >&2; exit 2 ;;
esac
kernel=${config#/boot/linux-}
kernel=${kernel%.cfg}
# RPM scriptlet warnings do not always fail the transaction. Explicitly
# generate and check the initramfs before attempting the first live boot.
depmod -a "$kernel"
dracut --force --no-hostonly "/boot/initrd.img-$kernel" "$kernel"
test -s "/boot/initrd.img-$kernel"
