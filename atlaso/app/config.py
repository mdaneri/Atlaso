"""Implement config behavior."""

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Define environment-backed Atlaso application settings."""
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
