#!/bin/sh
set -eu

build_user="${1:-}"
case "$build_user" in
  atlaso-build) ;;
  *)
    printf 'atlaso-finalize-image-build: refusing unexpected build user: %s\n' "$build_user" >&2
    exit 2
    ;;
esac

passwd_record=$(getent passwd "$build_user") || {
  printf 'atlaso-finalize-image-build: build user is missing before cleanup.\n' >&2
  exit 2
}
build_home=$(printf '%s\n' "$passwd_record" | cut -d: -f6)
[ "$build_home" = "/home/$build_user" ] || {
  printf 'atlaso-finalize-image-build: build home is outside the expected boundary.\n' >&2
  exit 2
}

# Packer schedules this root-owned helper from the communicator but runs it in
# a detached transient unit. Wait for that SSH session to leave before userdel;
# a timeout deliberately leaves the VM powered on so the image build fails.
attempt=0
while pgrep -u "$build_user" >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  [ "$attempt" -le 120 ] || {
    printf 'atlaso-finalize-image-build: build-user processes did not exit.\n' >&2
    exit 2
  }
  sleep 1
done

userdel -r "$build_user"
if getent passwd "$build_user" >/dev/null 2>&1; then
  printf 'atlaso-finalize-image-build: build user remains after deletion.\n' >&2
  exit 2
fi
[ ! -e "$build_home" ] && [ ! -L "$build_home" ] || {
  printf 'atlaso-finalize-image-build: build home remains after deletion.\n' >&2
  exit 2
}
[ ! -e /etc/sudoers.d/90-atlaso-build ] && [ ! -L /etc/sudoers.d/90-atlaso-build ] || {
  printf 'atlaso-finalize-image-build: build sudo authorization remains.\n' >&2
  exit 2
}

rm -f -- /opt/atlaso/image/common/scripts/finalize-image-build.sh /usr/local/sbin/atlaso-finalize-image-build
[ ! -e /opt/atlaso/image/common/scripts/finalize-image-build.sh ] || exit 2
[ ! -e /usr/local/sbin/atlaso-finalize-image-build ] || exit 2
sync
systemctl poweroff
