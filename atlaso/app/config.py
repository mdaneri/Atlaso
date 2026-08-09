"""Implement config behavior."""

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Define environment-backed Atlaso application settings.

    Attributes:
        app_name: Display name of the Atlaso application.
        appliance_hostname: Configured appliance hostname used by the Atlaso application.
        environment: Deployment environment name used by the application.
        database_url: SQLAlchemy connection URL for the Atlaso database.
        secret_key: Signing secret used for application authentication state.
        secrets_key: Key material used to protect stored application secrets.
        session_cookie_name: Configured session cookie name used by the Atlaso application.
        csrf_cookie_name: Configured csrf cookie name used by the Atlaso application.
        jwt_issuer: Configured jwt issuer used by the Atlaso application.
        jwt_audience: Configured jwt audience used by the Atlaso application.
        api_token_ttl_days: Api token ttl duration in days.
        bootstrap_admin_username: Configured bootstrap admin username used by the Atlaso
            application.
        bootstrap_admin_password: Configured bootstrap admin password used by the Atlaso
            application.
        appliance_fqdn: Configured appliance fqdn used by the Atlaso application.
        appliance_management_cidr: Configured appliance management cidr used by the Atlaso
            application.
        appliance_management_gateway: Configured appliance management gateway used by the Atlaso
            application.
        appliance_management_ipv6_enabled: Whether appliance management ipv6 is enabled.
        appliance_management_ipv6_cidr: Configured appliance management ipv6 cidr used by the Atlaso
            application.
        appliance_management_ipv6_gateway: Configured appliance management ipv6 gateway used by the
            Atlaso application.
        appliance_root_ssh_enabled: Whether appliance root ssh is enabled.
        appliance_external_dns_servers: Configured appliance external dns servers used by the Atlaso
            application.
        dry_run_system_adapters: Configured dry run system adapters used by the Atlaso application.
        management_source_cidr: Configured management source cidr used by the Atlaso application.
        repository_path: Filesystem path used for repository.
        vcf_backup_path: Filesystem path used for vcf backup.
        app_log_path: Filesystem path used for app log.
        esxi_kickstart_max_bytes: Esxi kickstart max size in bytes.
        esxi_installer_iso_max_bytes: Esxi installer iso max size in bytes.
        monitor_enabled: Whether monitor is enabled.
        monitor_sample_interval_seconds: Monitor sample interval duration in seconds.
        monitor_retention_hours: Monitor retention duration in hours.
    """
    app_name: str = "Atlaso"
    appliance_hostname: str = "atlaso"
    environment: str = "development"
    database_url: str = "sqlite:///./data/atlaso.db"
    secret_key: str = Field(default="change-me-in-production", min_length=16)
    secrets_key: str = ""
    session_cookie_name: str = "atlaso_session"
    csrf_cookie_name: str = "atlaso_csrf"
    jwt_issuer: str = "atlaso"
    jwt_audience: str = "atlaso-api"
    api_token_ttl_days: int = 90
    bootstrap_admin_username: str = "admin"
    bootstrap_admin_password: str = "atlaso-admin"
    appliance_fqdn: str = "core.atlaso.internal"
    appliance_management_cidr: str = "192.168.49.1/24"
    appliance_management_gateway: str = ""
    appliance_management_ipv6_enabled: bool = False
    appliance_management_ipv6_cidr: str = ""
    appliance_management_ipv6_gateway: str = ""
    appliance_root_ssh_enabled: bool = False
    appliance_external_dns_servers: str = "1.1.1.1\n9.9.9.9"
    dry_run_system_adapters: bool = True
    management_source_cidr: str = "192.168.49.0/24"
    repository_path: Path = Path("/mnt/atlaso-vcf-offline-depot")
    vcf_backup_path: Path = Path("/mnt/atlaso-vcf-backups")
    app_log_path: Path = Path("/var/log/atlaso/atlaso.log")
    esxi_kickstart_max_bytes: int = 262_144
    esxi_installer_iso_max_bytes: int = 1024 * 1024 * 1024
    monitor_enabled: bool = True
    monitor_sample_interval_seconds: int = 30
    monitor_retention_hours: int = 24

    model_config = SettingsConfigDict(
        env_prefix="ATLASO_",
        env_file=".env",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    """Return settings."""
    return Settings()
