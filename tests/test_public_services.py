from atlaso.app.models import CaSettings, OidcProviderSettings, PhysicalInterface, VcfOfflineDepotSettings, VcfPrivateRegistrySettings
from atlaso.app.services.public_services import public_service_entries, render_public_services_nginx_config


def test_public_service_entries_scope_services_to_matching_address():
    interfaces = [
        PhysicalInterface(name="eth0", role="management", mode="access", ip_cidr="192.168.167.10/24"),
        PhysicalInterface(name="eth2", role="access", mode="access", ip_cidr="192.168.87.32/24"),
        PhysicalInterface(name="eth3", role="access", mode="access", ip_cidr="192.168.88.32/24"),
    ]
    ca_settings = CaSettings(enabled=True, listen_interface="eth2", listen_address="192.168.87.32", root_certificate_pem="root")
    depot_settings = VcfOfflineDepotSettings(enabled=True, listen_interface="eth2", listen_address="192.168.87.32", port=8443)
    registry_settings = VcfPrivateRegistrySettings(
        enabled=True,
        hostname="registry.atlaso.internal",
        listen_interface="eth3",
        listen_address="192.168.88.32",
        port=9443,
    )

    entries = public_service_entries(
        interfaces=interfaces,
        vlans=[],
        ca_settings=ca_settings,
        esxi_pxe_boot={"enabled": True, "listen_interface": "eth2", "listen_address": "192.168.87.32", "http_port": 8081},
        vcf_depot_settings=depot_settings,
        vcf_registry_settings=registry_settings,
    )

    by_address = {entry["address"]: {service["id"] for service in entry["services"]} for entry in entries}
    assert "192.168.167.10" not in by_address
    assert by_address["192.168.87.32"] == {"ca", "esxi_pxe", "vcf_offline_depot"}
    assert by_address["192.168.88.32"] == {"vcf_private_registry"}
    services_by_id = {service["id"]: service for entry in entries for service in entry["services"]}
    assert services_by_id["ca"]["dns_names"] == ["ca.atlaso.internal"]
    assert services_by_id["ca"]["port"] == 443
    assert services_by_id["esxi_pxe"]["dns_names"] == ["esxi-pxe.atlaso.internal"]
    assert services_by_id["esxi_pxe"]["scheme"] == "http"
    assert services_by_id["esxi_pxe"]["port"] == 8081
    assert services_by_id["vcf_offline_depot"]["dns_names"] == ["depot.atlaso.internal"]
    assert services_by_id["vcf_offline_depot"]["scheme"] == "https"
    assert services_by_id["vcf_offline_depot"]["port"] == 8443
    assert services_by_id["vcf_offline_depot"]["allow_unauthenticated_access"] is False
    assert "allow_unauthenticated_access" not in services_by_id["esxi_pxe"]
    assert services_by_id["vcf_private_registry"]["dns_names"] == ["registry.atlaso.internal"]
    assert services_by_id["vcf_private_registry"]["port"] == 9443

    depot_settings.allow_unauthenticated_access = True
    open_entries = public_service_entries(
        interfaces=interfaces,
        vlans=[],
        ca_settings=ca_settings,
        esxi_pxe_boot={"enabled": True, "listen_interface": "eth2", "listen_address": "192.168.87.32", "http_port": 8081},
        vcf_depot_settings=depot_settings,
        vcf_registry_settings=registry_settings,
    )
    open_services_by_id = {service["id"]: service for entry in open_entries for service in entry["services"]}
    assert open_services_by_id["vcf_offline_depot"]["allow_unauthenticated_access"] is True
    assert "allow_unauthenticated_access" not in open_services_by_id["esxi_pxe"]


def test_public_services_nginx_config_contains_per_ip_scoped_locations():
    config = render_public_services_nginx_config(
        [
            {
                "interface": "eth2",
                "role": "access",
                "address": "192.168.87.32",
                "services": [
                    {"id": "ca"},
                    {"id": "esxi_pxe"},
                    {"id": "vcf_offline_depot"},
                ],
            },
            {
                "interface": "eth3",
                "role": "access",
                "address": "192.168.88.32",
                "services": [{"id": "vcf_private_registry"}],
            },
        ],
        depot_store_path="/mnt/atlaso-vcf-offline-depot",
        ca_certificate_path="/etc/atlaso/ca-portal/certs/ca.atlaso.internal.crt",
        ca_key_path="/etc/atlaso/ca-portal/certs/ca.atlaso.internal.key",
    )

    assert "listen 192.168.87.32:443 ssl;" in config
    assert "server_name ca.atlaso.internal;" in config
    assert "ssl_certificate /etc/atlaso/ca-portal/certs/ca.atlaso.internal.crt;" in config
    assert "ssl_certificate_key /etc/atlaso/ca-portal/certs/ca.atlaso.internal.key;" in config


    assert "IP-scoped HTTPS public services front door." in config
    assert "server_name _ 192.168.87.32;" in config
    assert "location = /ca {" in config
    assert "location ^~ /ca/ {" in config
    assert "location = /requests {" in config
    assert "location ^~ /requests/ {" in config
    assert "location ^~ /static/ {" in config
    assert "location = /favicon.ico {" in config
    assert "location = /manifest.webmanifest {" in config
    assert "location = /service-worker.js {" in config
    assert "proxy_set_header X-Forwarded-Proto https;" in config
    assert "listen 192.168.87.32:80;" in config
    assert "server_name _ 192.168.87.32;" in config
    assert "listen 192.168.88.32:80;" not in config
    assert "server_name _ 192.168.88.32;" not in config
    assert "location = /requests/login {" not in config
    assert "location = /requests/logout {" not in config
    assert "\n  location = /login {" not in config
    assert "\n  location = /logout {" not in config
    assert "location /pxe/esxi/ks/" in config
    assert "location = /pxe/esxi/boot.ipxe" in config
    assert "location = /pxe/esxi {" in config
    assert "return 301 /pxe/esxi/;" in config
    assert "location = /pxe/esxi/ {" in config
    assert "Atlaso ESXi PXE HTTP root" in config
    assert "alias /var/lib/atlaso/pxe/http/esxi/;" in config
    assert "location = /PROD" in config
    assert "return 301 /PROD/;" in config
    assert "location = /PROD/login {" in config
    assert "location = /PROD/logout {" in config
    assert "location = /_atlaso_depot_auth {" in config
    assert "proxy_pass http://127.0.0.1:8000/PROD/auth-check;" in config
    assert "location = /_atlaso_depot_login {" in config
    assert "proxy_pass http://127.0.0.1:8000/PROD/auth-failure;" in config
    assert "location = /PROD/ {" in config
    assert "location ~ ^/PROD/.*/$ {" in config
    assert "location ~ ^/PROD/(?!login$|logout$|auth-check$)(.+[^/])$ {" in config
    assert "auth_request /_atlaso_depot_auth;" in config
    assert "error_page 401 = /_atlaso_depot_login;" in config
    assert "satisfy any;" in config
    assert 'auth_basic "VCF Offline Depot";' in config
    assert "auth_basic_user_file /etc/atlaso/nginx/htpasswd/vcf-offline-depot.htpasswd;" in config
    assert "proxy_set_header X-Atlaso-Depot-Basic-User $remote_user;" in config
    assert "alias /mnt/atlaso-vcf-offline-depot/PROD/$1;" in config
    assert "autoindex off;" in config
    assert "/registry" not in config


def test_oidc_public_service_uses_dedicated_hostname_port_and_closed_routes():
    entries = public_service_entries(
        interfaces=[
            PhysicalInterface(
                name="eth0",
                role="management",
                mode="access",
                ip_cidr="192.168.49.10/24",
            ),
            PhysicalInterface(
                name="eth2",
                role="routed",
                mode="access",
                ip_cidr="192.168.87.32/24",
            ),
        ],
        vlans=[],
        ca_settings=CaSettings(enabled=False),
        esxi_pxe_boot=None,
        vcf_depot_settings=VcfOfflineDepotSettings(enabled=False),
        vcf_registry_settings=VcfPrivateRegistrySettings(enabled=False),
        oidc_settings=OidcProviderSettings(
            enabled=True,
            hostname="oidc.atlaso.internal",
            listen_interface="eth2",
            listen_address="192.168.87.32",
            port=8443,
        ),
    )
    assert [entry["address"] for entry in entries] == ["192.168.87.32"]
    oidc_service = entries[0]["services"][0]
    assert oidc_service["id"] == "oidc"
    assert oidc_service["dns_names"] == ["oidc.atlaso.internal"]
    assert oidc_service["port"] == 8443

    config = render_public_services_nginx_config(
        entries,
        oidc_certificate_path="/etc/atlaso/oidc/certs/oidc.atlaso.internal.crt",
        oidc_key_path="/etc/atlaso/oidc/certs/oidc.atlaso.internal.key",
    )
    assert "OIDC HTTPS front door." in config
    assert "listen 192.168.87.32:8443 ssl;" in config
    assert "server_name oidc.atlaso.internal;" in config
    assert "location ^~ /identity/ {" in config
    assert "proxy_set_header X-Atlaso-Listener-Address $server_addr;" in config
    assert "location / {\n    return 404;" in config
    assert "location = /settings" not in config


def test_public_services_nginx_config_brackets_ipv6_https_and_http_listeners():
    config = render_public_services_nginx_config(
        [
            {
                "interface": "eth2",
                "role": "access",
                "address": "fd87::254",
                "services": [
                    {"id": "ca"},
                    {"id": "esxi_pxe"},
                    {"id": "vcf_offline_depot"},
                ],
                "web_terminal": True,
            }
        ],
        depot_store_path="/mnt/atlaso-vcf-offline-depot",
        ca_certificate_path="/etc/atlaso/ca-portal/certs/ca.atlaso.internal.crt",
        ca_key_path="/etc/atlaso/ca-portal/certs/ca.atlaso.internal.key",
        terminal_certificate_path="/etc/atlaso/https/certs/appliance.crt",
        terminal_key_path="/etc/atlaso/https/private/appliance.key",
    )

    assert "listen [fd87::254]:443 ssl;" in config
    assert "listen [fd87::254]:80;" in config
    assert "listen fd87::254:443 ssl;" not in config
    assert "listen fd87::254:80;" not in config


def test_public_services_nginx_config_skips_non_pxe_http_services():
    config = render_public_services_nginx_config(
        [
            {
                "interface": "eth2",
                "role": "access",
                "address": "192.168.87.32",
                "services": [{"id": "vcf_offline_depot", "allow_unauthenticated_access": True}],
            },
        ],
        depot_store_path="/mnt/atlaso-vcf-offline-depot",
    )

    assert "server {" not in config
    assert "/PROD/" not in config
    assert "auth_basic" not in config


def test_public_services_nginx_config_omits_ip_depot_routes_when_depot_uses_different_port():
    config = render_public_services_nginx_config(
        [
            {
                "interface": "eth2",
                "role": "access",
                "address": "192.168.87.32",
                "services": [
                    {"id": "ca"},
                    {"id": "vcf_offline_depot", "port": 8443},
                ],
            },
        ],
        depot_store_path="/mnt/atlaso-vcf-offline-depot",
        ca_certificate_path="/etc/atlaso/ca-portal/certs/ca.atlaso.internal.crt",
        ca_key_path="/etc/atlaso/ca-portal/certs/ca.atlaso.internal.key",
    )

    assert "CA portal HTTPS front door." in config
    assert "listen 192.168.87.32:443 ssl;" in config
    assert "IP-scoped HTTPS public services front door." not in config
    assert "/PROD/" not in config


def test_public_services_nginx_config_can_expose_terminal_only_on_selected_address():
    config = render_public_services_nginx_config(
        [
            {
                "interface": "eth2",
                "role": "access",
                "address": "192.168.87.32",
                "services": [],
                "web_terminal": True,
            }
        ],
        terminal_certificate_path="/etc/atlaso/ca/certs/appliance.crt",
        terminal_key_path="/etc/atlaso/ca/private/appliance.key",
    )

    assert "# Terminal-only HTTPS front door." in config
    assert "listen 192.168.87.32:443 ssl;" in config
    assert "ssl_certificate /etc/atlaso/ca/certs/appliance.crt;" in config
    assert "ssl_certificate_key /etc/atlaso/ca/private/appliance.key;" in config
    assert "location = /login {" in config
    assert "location = /terminal {" in config
    assert "location = /terminal/tickets {" in config
    assert "location = /terminal/ws {" in config
    assert "proxy_set_header Upgrade $http_upgrade;" in config
    assert "proxy_set_header X-Atlaso-Listener-Address $server_addr;" in config
    assert "location ^~ /static/ {" in config
    assert "location = /dashboard {" not in config
    assert "location = /api/" not in config


def test_public_services_nginx_config_merges_terminal_without_duplicate_static_location():
    config = render_public_services_nginx_config(
        [
            {
                "interface": "eth1",
                "role": "access",
                "address": "192.168.87.22",
                "services": [
                    {"id": "ca"},
                    {"id": "vcf_offline_depot"},
                ],
                "web_terminal": True,
            }
        ],
        ca_certificate_path="/etc/atlaso/ca-portal/certs/ca.atlaso.internal.crt",
        ca_key_path="/etc/atlaso/ca-portal/certs/ca.atlaso.internal.key",
        terminal_certificate_path="/etc/atlaso/https/certs/appliance.crt",
        terminal_key_path="/etc/atlaso/https/private/appliance.key",
    )

    assert "# Terminal-only HTTPS front door." not in config
    assert "location = /terminal {" in config
    assert "location = /terminal/ws {" in config
    assert config.count("location ^~ /static/ {") == 2
