#!/bin/sh
set -eu

OUTPUT_DIRECTORY="${1:-}"
if [ -z "$OUTPUT_DIRECTORY" ]; then
  echo "Usage: build-qemu-guest-agent-rpm.sh OUTPUT_DIRECTORY" >&2
  exit 2
fi

QEMU_VERSION=10.2.2
QEMU_ARCHIVE="qemu-${QEMU_VERSION}.tar.xz"
QEMU_URL="https://download.qemu.org/${QEMU_ARCHIVE}"
QEMU_SHA256=784b296ff29c1417aa72323abcb2d2ea9ab9771724f577dcd785c3b04f21e176
SOURCE_ROOT="${ATLASO_SRC:-/tmp/atlaso-src}"
BUILD_ROOT="/tmp/atlaso-qemu-guest-agent-build"
RPM_ROOT="$BUILD_ROOT/rpmbuild"

rm -rf "$BUILD_ROOT"
install -d -o root -g root -m 0700 "$BUILD_ROOT" "$RPM_ROOT/BUILD" "$RPM_ROOT/BUILDROOT" \
  "$RPM_ROOT/RPMS" "$RPM_ROOT/SOURCES" "$RPM_ROOT/SPECS" "$RPM_ROOT/SRPMS"

curl --fail --location --proto '=https' --tlsv1.2 --output "$BUILD_ROOT/$QEMU_ARCHIVE" "$QEMU_URL"
printf '%s  %s\n' "$QEMU_SHA256" "$BUILD_ROOT/$QEMU_ARCHIVE" | sha256sum -c -
tar -xJf "$BUILD_ROOT/$QEMU_ARCHIVE" -C "$BUILD_ROOT"

cd "$BUILD_ROOT/qemu-$QEMU_VERSION"
# QEMU models the guest agent separately from its ordinary support tools, so
# disabling tools and system/user emulators still leaves the explicitly enabled
# qemu-ga target and its libudev-backed Linux commands available.
./configure \
  --prefix=/usr \
  --libdir=/usr/lib64 \
  --sysconfdir=/etc \
  --localstatedir=/var \
  --libexecdir=/usr/libexec \
  --disable-docs \
  --disable-guest-agent-msi \
  --disable-system \
  --disable-tools \
  --disable-user \
  --enable-guest-agent
ninja -C build qemu-ga

install -o root -g root -m 0755 build/qemu-ga "$RPM_ROOT/SOURCES/qemu-ga"
install -o root -g root -m 0644 \
  "$SOURCE_ROOT/image/common/guest-agents/qemu-guest-agent.service" \
  "$RPM_ROOT/SOURCES/qemu-guest-agent.service"
install -o root -g root -m 0644 \
  "$SOURCE_ROOT/image/common/guest-agents/atlaso-qemu-guest-agent.spec" \
  "$RPM_ROOT/SPECS/atlaso-qemu-guest-agent.spec"

rpmbuild --define "_topdir $RPM_ROOT" -bb "$RPM_ROOT/SPECS/atlaso-qemu-guest-agent.spec"
install -d -o root -g root -m 0700 "$OUTPUT_DIRECTORY"
rpm_count=0
for rpm_path in "$RPM_ROOT"/RPMS/*/atlaso-qemu-guest-agent-*.rpm; do
  [ -f "$rpm_path" ] || continue
  install -o root -g root -m 0600 "$rpm_path" "$OUTPUT_DIRECTORY/$(basename "$rpm_path")"
  rpm_count=$((rpm_count + 1))
done
if [ "$rpm_count" -ne 1 ]; then
  echo "Expected exactly one Atlaso QEMU guest-agent RPM; found $rpm_count." >&2
  exit 2
fi

rm -rf "$BUILD_ROOT"
