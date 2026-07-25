from ipaddress import ip_address

from atlaso.app.models import User, VcfBackupSettings
from atlaso.app.services.dnsmasq import split_addresses, split_interfaces


VCF_BACKUP_DEFAULT_VOLUME_MOUNT = "/mnt/atlaso-vcf-backups"
VCF_BACKUP_REMOTE_DIRECTORY = "/backups"
VCF_BACKUP_STAGED_CONFIG_PATH = "/var/lib/atlaso/apply/vcf-backups/atlaso-vcf-backups-sshd.conf"
VCF_BACKUP_EFFECTIVE_CONFIG_PATH = "/etc/ssh/sshd_config.d/atlaso-vcf-backups.conf"
VCF_BACKUP_DEFAULT_USERNAME = "vcf-backup"


def vcf_backup_remote_directory(settings: VcfBackupSettings) -> str:
    if settings.chroot_enabled:
        return VCF_BACKUP_REMOTE_DIRECTORY
    return settings.storage_path.rstrip("/") or VCF_BACKUP_DEFAULT_VOLUME_MOUNT


def vcf_backup_settings_to_dict(settings: VcfBackupSettings) -> dict:
    return {
        "id": settings.id,
        "enabled": settings.enabled,
        "listen_interface": settings.listen_interface,
        "listen_address": settings.listen_address,
        "port": settings.port,
        "sftp_user_id": settings.sftp_user_id,
        "sftp_username": settings.sftp_user.username if settings.sftp_user else "",
        "storage_path": settings.storage_path,
        "remote_directory": vcf_backup_remote_directory(settings),
        "chroot_enabled": settings.chroot_enabled,
        "allow_password_auth": settings.allow_password_auth,
        "allow_public_key_auth": settings.allow_public_key_auth,
        "max_sessions": settings.max_sessions,
        "config_path": settings.config_path,
        "updated_at": settings.updated_at.isoformat() if settings.updated_at else "",
    }


def vcf_backup_service_state(settings: VcfBackupSettings, *, sshd_active: bool | None = None) -> dict[str, object]:
    desired_enabled = bool(settings.enabled)
    running = bool(sshd_active) if sshd_active is not None else desired_enabled
    if running and desired_enabled:
        health = "healthy"
        label = "live"
        pill = "good"
    elif running:
        health = "degraded"
        label = "running"
        pill = "warn"
    elif desired_enabled:
        health = "degraded"
        label = "enabled"
        pill = "warn"
    else:
        health = "disabled"
        label = "disabled"
        pill = "muted"
    return {
        "running": running,
        "enabled": desired_enabled,
        "health": health,
        "label": label,
        "pill": pill,
    }


def validate_vcf_backup_state(settings: VcfBackupSettings, users: list[User], interface_names: set[str] | None = None) -> list[str]:
    errors: list[str] = []
    user_by_id = {user.id: user for user in users}
    selected_user = user_by_id.get(settings.sftp_user_id or -1)
    if settings.enabled and selected_user is None:
        errors.append("Select a local Atlaso user for SFTP authentication before enabling VCF backups.")
    if settings.enabled and selected_user is not None and not selected_user.enabled:
        errors.append(f"SFTP user {selected_user.username} is disabled.")
    if settings.enabled:
        listen_interfaces = split_interfaces(settings.listen_interface)
        listen_addresses = split_addresses(settings.listen_address)
        if not listen_interfaces:
            errors.append("Listen interface is required.")
        elif interface_names is not None:
            for interface in listen_interfaces:
                if interface not in interface_names:
                    errors.append(f"Listen interface {interface} is not configured as a physical or VLAN interface.")
        if not listen_addresses:
            errors.append("Listen address is required.")
        for address in listen_addresses:
            try:
                ip_address(address)
            except ValueError:
                errors.append(f"Listen address {address} is not a valid IP address.")
    if settings.port < 1 or settings.port > 65535:
        errors.append("SFTP port must be between 1 and 65535.")
    if not settings.storage_path.startswith("/"):
        errors.append("Backup volume mount must be an absolute Linux path.")
    if not settings.config_path.startswith("/"):
        errors.append("Config path must be an absolute Linux path.")
    if settings.max_sessions < 1 or settings.max_sessions > 64:
        errors.append("Max sessions must be between 1 and 64.")
    if not settings.allow_password_auth and not settings.allow_public_key_auth:
        errors.append("Enable password authentication, public key authentication, or both.")
    return errors


def render_vcf_backup_config(settings: VcfBackupSettings) -> str:
    username = settings.sftp_user.username if settings.sftp_user else "select-a-atlaso-user"
    remote_directory = vcf_backup_remote_directory(settings)
    common_header = [
        "# Managed by Atlaso. Local changes may be overwritten.",
        f"# Atlaso VCF Backups enabled: {'true' if settings.enabled else 'false'}",
        f"# Atlaso VCF Backups user: {username}",
        f"# Backup volume mount: {settings.storage_path}",
        f"# VCF remote directory: {remote_directory}",
        f"# Listen interfaces: {', '.join(split_interfaces(settings.listen_interface)) or 'none'}",
        f"# Listen addresses: {', '.join(split_addresses(settings.listen_address)) or 'none'}",
        "# The selected listen target is enforced by the Atlaso firewall apply unit.",
        "",
    ]
    if not settings.enabled:
        return "\n".join([*common_header, "# VCF Backup SFTP desired state is disabled.", ""]).strip() + "\n"

    lines = [
        *common_header,
        f"# Service listener targets: {', '.join(f'{address}:{settings.port}' for address in split_addresses(settings.listen_address)) or 'none'}",
        f"Match User {username}",
        "  AuthorizedKeysFile /etc/atlaso/ssh/authorized_keys/%u",
        f"  ChrootDirectory {settings.storage_path}",
        f"  ForceCommand internal-sftp -d {remote_directory}",
        f"  PasswordAuthentication {'yes' if settings.allow_password_auth else 'no'}",
        f"  PubkeyAuthentication {'yes' if settings.allow_public_key_auth else 'no'}",
        f"  MaxSessions {settings.max_sessions}",
        "  PermitTTY no",
        "  PermitTunnel no",
        "  AllowAgentForwarding no",
        "  AllowTcpForwarding no",
        "  X11Forwarding no",
    ]
    if not settings.chroot_enabled:
        lines = [
            *common_header,
            f"# Service listener targets: {', '.join(f'{address}:{settings.port}' for address in split_addresses(settings.listen_address)) or 'none'}",
            f"Match User {username}",
            "  AuthorizedKeysFile /etc/atlaso/ssh/authorized_keys/%u",
            f"  ForceCommand internal-sftp -d {remote_directory}",
            f"  PasswordAuthentication {'yes' if settings.allow_password_auth else 'no'}",
            f"  PubkeyAuthentication {'yes' if settings.allow_public_key_auth else 'no'}",
            f"  MaxSessions {settings.max_sessions}",
            "  PermitTTY no",
            "  PermitTunnel no",
            "  AllowAgentForwarding no",
            "  AllowTcpForwarding no",
            "  X11Forwarding no",
        ]
    return "\n".join(lines).strip() + "\n"
