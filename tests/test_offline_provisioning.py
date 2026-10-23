"""Source contracts for provisioning from installation media."""

from pathlib import Path

PROVISIONER = Path("image/common/scripts/provision-atlaso.sh")


def _provisioner() -> str:
    """Read the shared appliance provisioning script."""
    return PROVISIONER.read_text(encoding="utf-8")


def test_installation_media_is_validated_before_package_transactions() -> None:
    """Reject incomplete offline inputs before changing the installed system."""
    source = _provisioner()

    validation = source.rindex("\nvalidate_installation_media\n")
    first_package_transaction = source.index('run_tdnf "Photon local package metadata refresh" makecache')

    assert validation < first_package_transaction
    assert 'ATLASO_GUEST_PLATFORM=none' in source
    assert '[ "$ATLASO_SYSTEM_CONTENT_DISK" = "false" ]' in source
    assert 'ATLASO_SOFTWARE_MANIFEST_SHA256' in source
    assert 'ATLASO_SOFTWARE_SOURCE_COMMIT' in source
    assert 'ATLASO_INSTALLATION_MEDIA/tdnf.conf' in source
    assert 'ATLASO_INSTALLATION_MEDIA/rpm-repos' in source
    assert 'ATLASO_INSTALLATION_MEDIA/powercli' in source
    assert 'verify-template-software.py' in source
    assert 'Path(configured_directory).resolve(strict=True)' in source
    assert 'section.get("gpgcheck", "").strip() != "1"' in source
    assert 'section.get("mirrorlist", "").strip()' in source
    assert 'section.get("metalink", "").strip()' in source
    assert 'parsed.scheme != "file"' in source
    assert 'os.path.commonpath((str(media), str(local_path)))' in source


def test_offline_tdnf_uses_only_explicit_media_configuration() -> None:
    """Keep remote repository setup and update transactions out of offline mode."""
    source = _provisioner()

    assert 'tdnf -c "$ATLASO_INSTALLATION_MEDIA/tdnf.conf" -y "$@"' in source
    repository_setup = source.index('python3 "$PHOTON_REPOSITORY_CONFIGURATOR"')
    first_local_refresh = source.index('run_tdnf "Photon local package metadata refresh"')
    assert repository_setup < first_local_refresh
    assert 'if [ -z "$ATLASO_INSTALLATION_MEDIA" ]; then\n  python3 "$PHOTON_REPOSITORY_CONFIGURATOR"' in source
    assert 'if [ -z "$ATLASO_INSTALLATION_MEDIA" ]; then\n  run_tdnf "Photon OS update verification" update' in source
    assert 'if [ -z "$ATLASO_INSTALLATION_MEDIA" ]; then\n  run_tdnf "Final Photon OS update verification" update' in source


def test_physical_installation_skips_virtual_agent_build_and_staging() -> None:
    """Do not fetch/build virtual guest agents for bare-metal installation."""
    source = _provisioner()

    assert 'if [ "$ATLASO_GUEST_PLATFORM" = "none" ]; then\n  log_step "skipping virtual guest-agent build' in source
    assert 'if [ "$ATLASO_GUEST_PLATFORM" = "none" ]; then\n    log_step "staging empty guest-agent inventory' in source
    assert 'install -d -o root -g root -m 0700 "$GUEST_AGENT_STAGING"' in source
    assert ': >"$GUEST_AGENT_STAGING/SHA256SUMS"' in source
    assert 'ATLASO_POWERCLI_MODULE_SOURCE="$ATLASO_INSTALLATION_MEDIA/powercli"' in source
    assert ' -Mode Validate -ModuleRoot "$ATLASO_POWERCLI_MODULE_SOURCE"' in source
    assert ' -Mode Install' in source


def test_offline_install_requires_signed_software_without_pip_fallback() -> None:
    """Require the prepared signed wheelhouse and retain it through installation."""
    source = _provisioner()

    validation = source.index("validate_installation_media\n")
    install_branch = source.index('if [ -n "${ATLASO_SOFTWARE_MANIFEST_SHA256:-}" ]; then')
    signed_install = source.index('--no-index --no-compile --require-hashes', install_branch)
    fallback = source.index('else\n"$ATLASO_HOME/.venv/bin/python" -m pip install', signed_install)
    staged_bundle_removal = source.index('rm -rf /tmp/atlaso-software')

    assert validation < install_branch < signed_install < fallback < staged_bundle_removal
    assert 'if [ -z "$ATLASO_INSTALLATION_MEDIA" ]; then\n  rm -rf /tmp/atlaso-software' in source


def test_offline_chroot_skips_live_host_setup_and_image_compaction() -> None:
    """Defer runtime operations to installed-host boot and skip image zero-fill."""
    source = _provisioner()

    assert 'systemctl() {' in source
    assert 'daemon-reload|daemon-reexec)' in source
    assert 'start|stop|restart|reload|try-restart|reload-or-restart)' in source
    assert 'Refusing live systemd action during installation-media provisioning' in source
    assert 'command systemctl "$action" "$@"' in source
    assert 'if [ -z "$ATLASO_INSTALLATION_MEDIA" ]; then\n  udevadm control --reload-rules' in source
    assert 'if [ -z "$ATLASO_INSTALLATION_MEDIA" ]; then\n  "$ATLASO_HOME/bin/atlaso-helper" network prepare-observation --real\nfi' in source
    assert 'if [ -z "$ATLASO_INSTALLATION_MEDIA" ]; then\n  systemctl stop atlaso-worker.service atlaso.service' in source
    assert 'if [ -z "$ATLASO_INSTALLATION_MEDIA" ]; then\n  log_step "preserving and activating external service log history"' in source
    assert 'if [ -z "$ATLASO_INSTALLATION_MEDIA" ] && command -v iptables' in source
    assert 'if [ -z "$ATLASO_INSTALLATION_MEDIA" ]; then\n  zero_fill_free_space /' in source
