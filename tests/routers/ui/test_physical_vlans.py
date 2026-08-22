"""Test physical-interface and VLAN management UI transport behavior."""

import json

import pytest

from tests.routers.ui.helpers import assert_apply_redirect, login


def test_forget_missing_physical_interface_deletes_only_stale_rows(client):
    """Verify that forget missing physical interface deletes only stale rows.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DhcpScope, PhysicalInterface, VlanInterface

    login(client)
    with SessionLocal() as db:
        missing = PhysicalInterface(
            name="missing_eth7",
            mac_address="00:50:56:00:00:07",
            role="unused",
            mode="unused",
            admin_state="down",
            oper_state="missing",
        )
        db.add(missing)
        db.add(VlanInterface(name="missing_eth7.20", parent_interface="missing_eth7", vlan_id=20, enabled=False))
        db.add(
            DhcpScope(
                name="disabled-child-scope",
                interface_name="missing_eth7.20",
                site_address="10.20.0.1",
                prefix_length=24,
                enabled=False,
            )
        )
        active = PhysicalInterface(
            name="eth8",
            mac_address="00:50:56:00:00:08",
            role="access",
            mode="access",
            admin_state="up",
            oper_state="up",
        )
        db.add(active)
        db.commit()
        missing_id = missing.id
        active_id = active.id

    page = client.get("/physical-interfaces")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    active_response = client.post(f"/physical-interfaces/{active_id}/forget", data={"csrf": csrf})
    assert active_response.status_code == 409
    response = client.post(f"/physical-interfaces/{missing_id}/forget", data={"csrf": csrf}, follow_redirects=False)

    assert response.status_code == 303
    with SessionLocal() as db:
        assert db.get(PhysicalInterface, missing_id) is None
        assert db.query(VlanInterface).filter(VlanInterface.parent_interface == "missing_eth7").count() == 0
        child_scope = db.query(DhcpScope).filter(DhcpScope.name == "disabled-child-scope").one()
        assert child_scope.interface_name == ""
        assert db.get(PhysicalInterface, active_id) is not None


def test_forget_missing_physical_interface_reports_enabled_dependency(client):
    """Verify Forget rolls back and reports an enabled DHCP dependency.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DhcpScope, DhcpSettings, PhysicalInterface

    login(client)
    scope_name = "missing-interface-dependency"
    with SessionLocal() as db:
        db.execute(select(DhcpSettings)).scalar_one().enabled = True
        missing = PhysicalInterface(
            name="missing_eth9",
            mac_address="00:50:56:00:00:09",
            role="access",
            mode="access",
            ip_cidr="10.9.0.1/24",
            admin_state="down",
            oper_state="missing",
        )
        db.add(missing)
        db.flush()
        db.add(
            DhcpScope(
                name=scope_name,
                address_family="ipv4",
                interface_name=missing.name,
                site_address="10.9.0.1",
                prefix_length=24,
                range_expression="10.9.0.100-10.9.0.120",
                dns_server="10.9.0.1",
                ntp_server="10.9.0.1",
                enabled=True,
            )
        )
        db.commit()
        missing_id = missing.id

    page = client.get("/physical-interfaces")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        f"/physical-interfaces/{missing_id}/forget",
        data={"csrf": csrf},
        follow_redirects=False,
    )

    assert response.status_code == 422, response.text
    assert "DHCP scope" in response.text
    with SessionLocal() as db:
        assert db.get(PhysicalInterface, missing_id) is not None
        assert db.execute(
            select(DhcpScope).where(DhcpScope.name == scope_name)
        ).scalar_one().enabled is True


def test_forget_missing_first_service_interface_moves_dns_alias_to_next_target(client):
    """Verify that forget missing first service interface moves dns alias to next target.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsRecord, PhysicalInterface
    from atlaso.app.ui import (
        ensure_dns_for_vcf_registry,
        get_vcf_private_registry_settings_row,
    )

    login(client)
    with SessionLocal() as db:
        db.add_all(
            [
                PhysicalInterface(
                    name="eth7",
                    mac_address="00:50:56:00:00:17",
                    role="access",
                    mode="access",
                    ip_cidr="10.7.0.1/24",
                    admin_state="up",
                    oper_state="up",
                ),
                PhysicalInterface(
                    name="eth8",
                    mac_address="00:50:56:00:00:18",
                    role="access",
                    mode="access",
                    ip_cidr="10.8.0.1/24",
                    admin_state="up",
                    oper_state="up",
                ),
            ]
        )
        settings = get_vcf_private_registry_settings_row(db)
        settings.enabled = True
        settings.hostname = "registry.atlaso.internal"
        settings.listen_interface = "eth7\neth8"
        settings.listen_address = "10.7.0.1\n10.8.0.1"
        ensure_dns_for_vcf_registry(db, settings, "admin")
        db.commit()
        eth7_id = db.execute(select(PhysicalInterface.id).where(PhysicalInterface.name == "eth7")).scalar_one()
        eth7 = db.get(PhysicalInterface, eth7_id)
        eth7.oper_state = "missing"
        db.commit()

    page = client.get("/physical-interfaces")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(f"/physical-interfaces/{eth7_id}/forget", data={"csrf": csrf}, follow_redirects=False)

    assert response.status_code == 303
    with SessionLocal() as db:
        settings = get_vcf_private_registry_settings_row(db)
        assert settings.listen_interface == "eth8"
        assert settings.listen_address == "10.8.0.1"
        canonical = db.execute(
            select(DnsRecord).where(DnsRecord.hostname == "registry.atlaso.internal", DnsRecord.record_type == "CNAME")
        ).scalar_one()
        assert canonical.address == "registry-10-8-0-1.atlaso.internal"
        assert db.execute(select(DnsRecord).where(DnsRecord.hostname == "registry-10-7-0-1.atlaso.internal")).scalar_one_or_none() is None
        target = db.execute(
            select(DnsRecord).where(DnsRecord.hostname == "registry-10-8-0-1.atlaso.internal", DnsRecord.record_type == "A")
        ).scalar_one()
        assert target.address == "10.8.0.1"


def test_physical_and_vlan_pages_render(client):
    """Verify that physical and vlan pages render.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    login(client)
    physical = client.get("/physical-interfaces")
    assert physical.status_code == 200
    assert "Physical Interfaces" in physical.text
    assert "optional access management UI exposure, management gateways" in physical.text
    assert "physical-interfaces-table" in physical.text
    assert "Refresh host inventory" in physical.text
    assert "Observed IPv4" in physical.text
    assert "Observed IPv6" in physical.text
    assert "IPv4 CIDR" in physical.text
    assert "IPv4 Gateway" in physical.text
    assert "Management gateway" in physical.text
    assert "IPv6 CIDR" in physical.text
    assert "IPv6 Gateway" in physical.text
    assert "Management UI" in physical.text
    assert "network-state-icon up" in physical.text
    assert "eth0" in physical.text
    assert "192.168.49.1/24" in physical.text
    assert "192.168.50.1/24" in physical.text
    assert "Link Type" in physical.text
    assert "Review appliance changes" in physical.text
    assert "/var/lib/atlaso/apply/network/atlaso-network.conf" in physical.text

    vlans = client.get("/vlan-interfaces")
    assert vlans.status_code == 200
    assert "VLAN Interfaces" in vlans.text
    assert "For standard access-mode NICs, assign IPv4/IPv6 CIDR on Physical Interfaces instead." in vlans.text
    assert "vlan-interfaces-table" in vlans.text
    assert "An enabled access VLAN can expose the authenticated management UI" in vlans.text
    assert "data-vlan-interface-count" in vlans.text
    assert 'data-can-write="true"' in vlans.text
    assert "data-vlan-interface-form" in vlans.text
    assert 'data-atlaso-wizard-step="vlan"' in vlans.text
    assert 'data-atlaso-wizard-step="addressing"' in vlans.text
    assert 'data-atlaso-wizard-step="role"' in vlans.text
    assert '<option value="access" selected>access</option>' in vlans.text
    assert 'data-atlaso-wizard-step="admin_state"' in vlans.text
    assert 'data-atlaso-wizard-step="review"' in vlans.text
    assert 'name="access_management_ui_enabled"' in vlans.text
    assert 'name="enabled" checked' in vlans.text
    app_js = client.get("/static/app.js").text
    network_action_js = app_js.split("async function postNetworkAction", 1)[1].split(
        "function newVlanWizardRow", 1
    )[0]
    assert 'key === "enabled" || key === "access_management_ui_enabled"' in network_action_js
    physical_table_js = app_js.split("function initializePhysicalInterfacesTable()", 1)[1].split(
        "function initializeVlanInterfacesTable()", 1
    )[0]
    physical_management_ui_column = physical_table_js.split('title: "Management UI"', 1)[1].split(
        'title: "Link Type"', 1
    )[0]
    physical_ipv6_column = physical_table_js.split('title: "IPv6"', 1)[1].split(
        'title: "IPv6 CIDR"', 1
    )[0]
    assert "formatter: atlasoBooleanFormatter" in physical_ipv6_column
    assert 'editor: "tickCross"' in physical_ipv6_column
    assert 'formatter: "tickCross"' not in app_js
    assert "atlasoBooleanFormatter(cell)" in physical_management_ui_column
    assert '<span class="status-pill good">inherent</span>' in physical_management_ui_column
    assert "+ Add VLAN interface here" in app_js
    vlan_table_js = app_js.split("function initializeVlanInterfacesTable()", 1)[1].split("function initializeDnsRecordsTable()", 1)[0]
    assert 'role: context?.role || "access"' in vlan_table_js
    vlan_management_ui_column = vlan_table_js.split('title: "Management UI"', 1)[1].split(
        'title: "Admin Up"', 1
    )[0]
    assert "atlasoBooleanFormatter(cell)" in vlan_management_ui_column
    assert "editor:" not in vlan_management_ui_column
    assert "cellEdited:" not in vlan_management_ui_column
    assert vlan_table_js.index('field: "name"') < vlan_table_js.index('field: "parent_interface"') < vlan_table_js.index('field: "vlan_id"')
    assert 'pattern: "wizard-backed"' in vlan_table_js
    assert "window.AtlasoUiPatterns.createWizard({" in vlan_table_js
    assert 'label: "Edit VLAN"' in vlan_table_js
    assert "onOpenRow: canWrite" in vlan_table_js
    assert 'markNewRecordRow(row, "name")' in vlan_table_js
    assert "atlasoGridWizardRequest(form.action, new FormData(form))" in vlan_table_js
    assert "const updateVlanCount = () =>" in vlan_table_js
    assert "table.getData().filter((row) => !row.is_new).length" in vlan_table_js
    assert "updateVlanCount();" in vlan_table_js
    assert "context ? Boolean(context.enabled) : true" in vlan_table_js
    assert "editor:" not in vlan_table_js
    assert "cellEdited:" not in vlan_table_js
    assert "autoSaveVlanInterface" not in app_js
    assert "activateNewVlanRow" not in app_js
    assert "const parentMtus = Object.fromEntries" in vlan_table_js
    assert "newVlanWizardRow()" in vlan_table_js
    assert "form.elements.mtu.value = parentMtus[parentSelect.value] || 1500" in vlan_table_js
    assert "derivedName.value = parent && vlanId ? `${parent}.${vlanId}` : \"\"" in vlan_table_js
    assert 'data-parent-options=\'[{"label": "eth1 - trunk' in vlans.text
    assert "data-parent-options" in vlans.text
    assert "deleteVlanInterfaceFromMenu" in app_js
    assert "refreshNetworkSideStack" in app_js
    refreshed_side_stack_js = app_js.split("function initializeRefreshedSideStack(sideStack)", 1)[1].split(
        "async function refreshNetworkSideStack()", 1
    )[0]
    assert "initializeAutosaveForms(sideStack)" in refreshed_side_stack_js
    assert "initializeSwitchFields(sideStack)" in refreshed_side_stack_js
    assert "initializeServiceBindEditors(sideStack)" in refreshed_side_stack_js
    assert "initializeDnsSettings(sideStack)" in refreshed_side_stack_js
    refresh_network_side_stack_js = app_js.split("async function refreshNetworkSideStack()", 1)[1].split(
        "async function autoSavePhysicalInterface", 1
    )[0]
    assert "initializeRefreshedSideStack(nextSideStack)" in refresh_network_side_stack_js
    assert "highlightConfigPreviews(nextSideStack)" in app_js
    assert "networkStateIcon" in app_js
    assert "operStateFormatter" in app_js
    assert "physicalRoleFormatter" in app_js
    assert 'editable: (cell) => cell.getRow().getData().mode !== "trunk"' in app_js
    assert app_js.count('editable: (cell) => cell.getRow().getData().mode !== "trunk"') >= 3
    assert 'role: "unused", access_management_ui_enabled: false, ipv4_method: "static", ip_cidr: "", gateway: "", ipv6_enabled: false, ipv6_cidr: "", ipv6_gateway: ""' in app_js
    assert "data.requires_activation && !data.is_activated" in app_js
    assert "cidrInputEditor" in app_js
    assert "isValidCidr" in app_js
    assert "ipv4GatewayIsOnLink" in app_js
    assert 'title: "IPv4 Gateway"' in app_js
    assert 'editorParams: { family: "ipv4", placeholder: "192.168.50.1/24" }' in app_js
    assert 'editorParams: { family: "ipv6", placeholder: "fd00:50::1/64" }' in app_js
    app_css = client.get("/static/app.css").text
    assert ".network-state-icon.up" in app_css
    assert ".network-state-icon.down" in app_css
    assert ".network-state-icon.missing" in app_css
    assert ".invalid-cidr-input" in app_css
    assert ".tabulator .tabulator-row.grid-row-recently-saved" in app_css
    assert "Review appliance changes" in vlans.text
    assert "/var/lib/atlaso/apply/network/atlaso-network.conf" in vlans.text


def test_management_interface_dual_stack_gateways_are_saved_and_drive_main_and_table_100(client):
    """Verify that management interface dual stack gateways are saved and drive main and table 100.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    import html

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface

    login(client)
    page = client.get("/physical-interfaces")
    rows = json.loads(html.unescape(page.text.split("data-interfaces='", 1)[1].split("'", 1)[0]))
    management = next(row for row in rows if row["role"] == "management")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    saved = client.post(
        f"/physical-interfaces/{management['id']}/edit",
        data={
            "role": "management",
            "mode": "access",
            "ipv4_method": "static",
            "ip_cidr": "192.168.49.1/24",
            "gateway": "192.168.49.254",
            "ipv6_enabled": "on",
            "ipv6_cidr": "2001:db8:49::10/64",
            "ipv6_gateway": "fe80::1",
            "mtu": "1500",
            "admin_state": "up",
            "csrf": csrf,
        },
        follow_redirects=False,
    )

    assert saved.status_code == 303
    refreshed = client.get("/physical-interfaces")
    assert '"gateway": "192.168.49.254"' in refreshed.text
    assert '"ipv6_gateway": "fe80::1"' in refreshed.text
    assert "gateway=192.168.49.254" in refreshed.text
    assert "ipv6_gateway=fe80::1" in refreshed.text
    assert "Static management gateways install in the main table and management policy table 100." in refreshed.text
    routes_wan = client.get("/routes-wan")
    assert "gateway=192.168.49.254" in routes_wan.text
    assert "ip route replace default via 192.168.49.254 dev eth0\n" in routes_wan.text
    assert "ip route replace default via 192.168.49.254 dev eth0 table 100" in routes_wan.text
    assert "ip -6 route replace default via fe80::1 dev eth0\n" in routes_wan.text
    assert "ip -6 route replace default via fe80::1 dev eth0 table 100" in routes_wan.text
    with SessionLocal() as db:
        row = db.scalar(select(PhysicalInterface).where(PhysicalInterface.id == management["id"]))
        assert row is not None
        assert row.gateway == "192.168.49.254"
        assert row.ipv6_gateway == "fe80::1"

    invalid = client.post(
        f"/physical-interfaces/{management['id']}/edit",
        data={
            "role": "management",
            "mode": "access",
            "ipv4_method": "static",
            "ip_cidr": "192.168.49.1/24",
            "gateway": "192.168.50.254",
            "mtu": "1500",
            "admin_state": "up",
            "csrf": csrf,
        },
    )
    assert invalid.status_code == 422
    assert "must be on-link" in invalid.text


def test_physical_interface_refresh_imports_host_inventory_without_apply_job(client, monkeypatch):
    """Verify that physical interface refresh imports host inventory without apply job.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, PhysicalInterface, Route, VlanInterface
    from atlaso.app.services.networking import HostPhysicalInterface

    login(client)

    def fake_discover():
        """Return fake discover."""
        return [
            HostPhysicalInterface(
                name="ens192",
                mac_address="00:15:5d:aa:bb:cc",
                driver="hv_netvsc",
                speed="10000 Mbps",
                host_ip_cidr="192.168.49.22/24",
                host_mtu=1500,
                host_admin_state="up",
                oper_state="up",
            )
        ]

    monkeypatch.setattr("atlaso.app.services.networking.discover_host_physical_interfaces", fake_discover)
    page = client.get("/physical-interfaces")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post("/physical-interfaces/refresh", data={"csrf": csrf}, follow_redirects=False)

    assert response.status_code == 303
    refreshed = client.get("/physical-interfaces")
    assert "ens192" in refreshed.text
    assert "192.168.49.22/24" in refreshed.text
    assert "host" in refreshed.text
    assert "02:15:5d:00:10:02" not in refreshed.text
    assert "02:15:5d:00:10:03" not in refreshed.text

    with SessionLocal() as db:
        interface = db.execute(select(PhysicalInterface).where(PhysicalInterface.name == "ens192")).scalar_one()
        assert interface.inventory_source == "host"
        assert interface.desired_state_source == "seed"
        assert interface.ip_cidr is None
        assert interface.admin_state == "down"
        assert db.execute(select(PhysicalInterface).where(PhysicalInterface.name.in_(["eth0", "eth1", "eth2"]))).scalars().all() == []
        assert db.execute(select(VlanInterface).where(VlanInterface.parent_interface == "eth1")).scalars().all() == []
        assert db.execute(select(Route).where(Route.interface_name == "eth1.20")).scalars().all() == []
        assert db.execute(select(Job).where(Job.type == "appliance-apply")).scalar_one_or_none() is None


def test_physical_interface_edit_updates_desired_state(client):
    """Verify that physical interface edit updates desired state.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    import html

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        AuditEvent,
        CaSettings,
        DhcpScope,
        DnsRecord,
        DnsSettings,
        KmsSettings,
        NtpSettings,
        OidcProviderSettings,
        VcfBackupSettings,
        VcfOfflineDepotSettings,
        VcfPrivateRegistrySettings,
    )
    from atlaso.app.services.esxi_pxe import (
        ESXI_PXE_DEFAULT_HOSTNAME,
        ESXI_PXE_DNS_RECORD_DESCRIPTION,
        ESXI_PXE_HTTP_PORT,
        ESXI_TFTP_ROOT,
        esxi_pxe_boot_settings,
        save_esxi_pxe_boot_settings,
    )

    login(client)
    with SessionLocal() as db:
        for model in (
            DnsSettings,
            NtpSettings,
            CaSettings,
            KmsSettings,
            OidcProviderSettings,
            VcfBackupSettings,
            VcfOfflineDepotSettings,
            VcfPrivateRegistrySettings,
        ):
            settings = db.execute(select(model)).scalar_one_or_none()
            if settings is None:
                settings = model()
            settings.enabled = True
            settings.listen_interface = "eth2"
            settings.listen_address = "192.168.50.1"
            db.add(settings)
        scope = db.execute(select(DhcpScope).where(DhcpScope.name == "SiteA")).scalar_one()
        scope.interface_name = "eth2"
        scope.site_address = "192.168.50.1"
        scope.prefix_length = 24
        scope.range_expression = "192.168.50.100-200"
        scope.dns_server = "192.168.50.1"
        scope.ntp_server = "192.168.50.1"
        db.add(scope)
        save_esxi_pxe_boot_settings(
            db,
            enabled=True,
            hostname=ESXI_PXE_DEFAULT_HOSTNAME,
            listen_interface="eth2",
            listen_address="192.168.50.1",
            dhcp_scope_ids=[scope.id],
            tftp_root=ESXI_TFTP_ROOT.as_posix(),
            http_port=ESXI_PXE_HTTP_PORT,
            bios_bootfile="undionly.kpxe",
            uefi_bootfile="snponly.efi",
            native_uefi_http_enabled=True,
            native_uefi_http_url="http://192.168.50.1:8080/pxe/esxi/mboot.efi",
        )
        db.add(
            DnsRecord(
                hostname=ESXI_PXE_DEFAULT_HOSTNAME,
                record_type="A",
                address="192.168.50.1",
                description=ESXI_PXE_DNS_RECORD_DESCRIPTION,
                enabled=True,
            )
        )
        db.commit()

    page = client.get("/physical-interfaces")
    payload = page.text.split("data-interfaces='", 1)[1].split("'", 1)[0]
    rows = json.loads(html.unescape(payload))
    interface_id = next(row["id"] for row in rows if row["name"] == "eth2")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        f"/physical-interfaces/{interface_id}/edit",
        data={
            "role": "route",
            "mode": "access",
            "ip_cidr": "192.168.70.1/24",
            "mtu": "1400",
            "admin_state": "up",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert response.status_code == 303

    refreshed = client.get("/physical-interfaces")
    assert '"role": "route"' in refreshed.text
    assert '"mode": "access"' in refreshed.text
    assert '"ip_cidr": "192.168.70.1/24"' in refreshed.text
    assert '"mtu": 1400' in refreshed.text
    assert '"admin_state": "up"' in refreshed.text
    assert '"desired_state_source": "user"' in refreshed.text

    with SessionLocal() as db:
        for model in (
            DnsSettings,
            NtpSettings,
            CaSettings,
            KmsSettings,
            OidcProviderSettings,
            VcfBackupSettings,
            VcfOfflineDepotSettings,
            VcfPrivateRegistrySettings,
        ):
            settings = db.execute(select(model)).scalar_one()
            assert settings.listen_interface == "eth2"
            assert settings.listen_address == "192.168.70.1"
        scope = db.execute(select(DhcpScope).where(DhcpScope.name == "SiteA")).scalar_one()
        assert scope.interface_name == "eth2"
        assert scope.site_address == "192.168.70.1"
        assert scope.prefix_length == 24
        assert scope.range_expression == "192.168.70.100-192.168.70.200"
        assert scope.dns_server == "192.168.70.1"
        assert scope.ntp_server == "192.168.70.1"
        kms_record = db.execute(select(DnsRecord).where(DnsRecord.hostname == "kms.atlaso.internal", DnsRecord.record_type == "CNAME")).scalar_one()
        assert kms_record.address == "kms-192-168-70-1.atlaso.internal"
        kms_interface_record = db.execute(select(DnsRecord).where(DnsRecord.hostname == "kms-192-168-70-1.atlaso.internal", DnsRecord.record_type == "A")).scalar_one()
        assert kms_interface_record.address == "192.168.70.1"
        boot = esxi_pxe_boot_settings(db)
        assert boot["listen_interface"] == "eth2"
        assert boot["listen_address"] == "192.168.70.1"
        assert boot["effective_native_uefi_http_url"] == "http://192.168.70.1:8080/pxe/esxi/snponly.efi"
        pxe_record = db.execute(select(DnsRecord).where(DnsRecord.hostname == ESXI_PXE_DEFAULT_HOSTNAME, DnsRecord.record_type == "CNAME")).scalar_one()
        assert pxe_record.address == "esxi-pxe-192-168-70-1.atlaso.internal"
        pxe_interface_record = db.execute(select(DnsRecord).where(DnsRecord.hostname == "esxi-pxe-192-168-70-1.atlaso.internal", DnsRecord.record_type == "A")).scalar_one()
        assert pxe_interface_record.address == "192.168.70.1"
        audit = db.execute(
            select(AuditEvent)
            .where(AuditEvent.action == "update_physical_interface")
            .order_by(AuditEvent.id.desc())
        ).scalars().first()
        assert audit is not None
        assert audit.resource_id == "eth2"
        assert "DNS" in (audit.detail or "")
        assert "DHCP" in (audit.detail or "")


def test_interface_dns_alias_refresh_reports_real_changes_and_includes_esx_storage(
    client,
    monkeypatch,
):
    """Verify interface reconciliation ignores unchanged aliases and refreshes ESX Storage.

    Args:
        client: HTTP test client used to initialize the application database.
        monkeypatch: Pytest fixture used to replace DNS alias reconcilers.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal

    unchanged_helpers = [
        "ensure_dns_for_kms",
        "ensure_dns_for_ldap",
        "ensure_dns_for_oidc",
        "ensure_dns_for_vcf_offline_depot",
        "ensure_dns_for_vcf_registry",
        "ensure_dns_for_ca_portal",
        "ensure_dns_for_esxi_pxe",
    ]
    for helper_name in unchanged_helpers:
        monkeypatch.setattr(ui, helper_name, lambda *_args, **_kwargs: "unchanged")
    monkeypatch.setattr(
        ui,
        "ensure_dns_for_kms",
        lambda *_args, **_kwargs: ui.summarize_dns_actions(["conflict", "removed-stale"]),
    )
    monkeypatch.setattr(
        ui,
        "ensure_dns_for_esx_storage",
        lambda *_args, **_kwargs: "updated",
    )

    with SessionLocal() as db:
        assert ui.refresh_interface_service_dns_aliases(db) == ["KMS", "ESX Storage"]

    assert ui.summarize_dns_actions(["conflict", "unchanged"]) == "conflict"


def test_physical_interface_edit_repairs_stale_scope_after_host_inventory_refresh(client):
    """Verify that physical interface edit repairs stale scope after host inventory refresh.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    import html

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        DhcpScope,
        DnsRecord,
        DnsSettings,
        NtpSettings,
        Setting,
    )
    from atlaso.app.services.esxi_pxe import (
        ESXI_PXE_DEFAULT_HOSTNAME,
        ESXI_PXE_DNS_RECORD_DESCRIPTION,
        ESXI_PXE_HTTP_PORT,
        ESXI_PXE_LISTEN_ADDRESS_KEY,
        ESXI_TFTP_ROOT,
        save_esxi_pxe_boot_settings,
    )

    login(client)
    with SessionLocal() as db:
        dns_settings = db.execute(select(DnsSettings)).scalar_one()
        dns_settings.enabled = True
        dns_settings.listen_interface = "eth2"
        dns_settings.listen_address = "192.168.1.1"
        ntp_settings = db.execute(select(NtpSettings)).scalar_one()
        ntp_settings.enabled = True
        ntp_settings.listen_interface = "eth2"
        ntp_settings.listen_address = "192.168.1.1"
        scope = db.execute(select(DhcpScope).where(DhcpScope.name == "SiteA")).scalar_one()
        scope.interface_name = "eth2"
        scope.site_address = "192.168.1.1"
        scope.prefix_length = 24
        scope.range_expression = "192.168.1.100-120"
        scope.dns_server = "192.168.1.1"
        scope.ntp_server = "192.168.1.1"
        save_esxi_pxe_boot_settings(
            db,
            enabled=True,
            hostname=ESXI_PXE_DEFAULT_HOSTNAME,
            listen_interface="eth2",
            listen_address="192.168.1.1",
            dhcp_scope_ids=[scope.id],
            tftp_root=ESXI_TFTP_ROOT.as_posix(),
            http_port=ESXI_PXE_HTTP_PORT,
            bios_bootfile="undionly.kpxe",
            uefi_bootfile="snponly.efi",
            native_uefi_http_enabled=True,
            native_uefi_http_url="",
        )
        db.add(
            DnsRecord(
                hostname=ESXI_PXE_DEFAULT_HOSTNAME,
                record_type="A",
                address="192.168.1.1",
                description=ESXI_PXE_DNS_RECORD_DESCRIPTION,
                enabled=True,
            )
        )
        db.commit()

    page = client.get("/physical-interfaces")
    payload = page.text.split("data-interfaces='", 1)[1].split("'", 1)[0]
    rows = json.loads(html.unescape(payload))
    interface_id = next(row["id"] for row in rows if row["name"] == "eth2")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        f"/physical-interfaces/{interface_id}/edit",
        data={
            "role": "access",
            "mode": "access",
            "ip_cidr": "192.168.50.1/24",
            "mtu": "1500",
            "admin_state": "up",
            "csrf": csrf,
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    with SessionLocal() as db:
        scope = db.execute(select(DhcpScope).where(DhcpScope.name == "SiteA")).scalar_one()
        assert scope.site_address == "192.168.50.1"
        assert scope.range_expression == "192.168.50.100-192.168.50.120"
        assert scope.dns_server == "192.168.50.1"
        assert scope.ntp_server == "192.168.50.1"
        pxe_record = db.execute(select(DnsRecord).where(DnsRecord.hostname == ESXI_PXE_DEFAULT_HOSTNAME, DnsRecord.record_type == "CNAME")).scalar_one()
        assert pxe_record.address == "esxi-pxe-192-168-50-1.atlaso.internal"
        pxe_interface_record = db.execute(select(DnsRecord).where(DnsRecord.hostname == "esxi-pxe-192-168-50-1.atlaso.internal", DnsRecord.record_type == "A")).scalar_one()
        assert pxe_interface_record.address == "192.168.50.1"
        pxe_listen = db.execute(select(Setting).where(Setting.key == ESXI_PXE_LISTEN_ADDRESS_KEY)).scalar_one()
        assert pxe_listen.value == "192.168.50.1"
        pxe_listen.value = "192.168.1.1"
        db.add(pxe_listen)
        db.commit()

    second_response = client.post(
        f"/physical-interfaces/{interface_id}/edit",
        data={
            "role": "access",
            "mode": "access",
            "ip_cidr": "192.168.50.1/24",
            "mtu": "1500",
            "admin_state": "up",
            "csrf": csrf,
        },
        follow_redirects=False,
    )

    assert second_response.status_code == 303
    with SessionLocal() as db:
        pxe_listen = db.execute(select(Setting).where(Setting.key == ESXI_PXE_LISTEN_ADDRESS_KEY)).scalar_one()
        assert pxe_listen.value == "192.168.50.1"


def test_physical_interface_trunk_mode_clears_non_applicable_role(client):
    """Verify that physical interface trunk mode clears non applicable role.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    import html

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DhcpScope, PhysicalInterface

    login(client)
    page = client.get("/physical-interfaces")
    rows = json.loads(html.unescape(page.text.split("data-interfaces='", 1)[1].split("'", 1)[0]))
    interface_id = next(row["id"] for row in rows if row["name"] == "eth2")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    with SessionLocal() as db:
        for scope in db.execute(
            select(DhcpScope).where(DhcpScope.interface_name == "eth2")
        ).scalars().all():
            scope.enabled = False
        db.commit()

    response = client.post(
        f"/physical-interfaces/{interface_id}/edit",
        data={"role": "access", "mode": "trunk", "ipv4_method": "dhcp", "ip_cidr": "192.168.50.1/24", "ipv6_cidr": "fd00:50::1/64", "mtu": "1500", "admin_state": "up", "csrf": csrf},
        follow_redirects=False,
    )

    assert response.status_code == 303
    with SessionLocal() as db:
        interface = db.execute(select(PhysicalInterface).where(PhysicalInterface.id == interface_id)).scalar_one()
        assert interface.mode == "trunk"
        assert interface.role == "unused"
        assert interface.ipv4_method == "static"
        assert interface.ip_cidr is None
        assert interface.ipv6_cidr is None


@pytest.mark.parametrize("invalid_role", ["services", "storage", "unsupported"])
def test_physical_interface_trunk_mode_rejects_noncanonical_role(client, invalid_role):
    """Verify trunk conversion validates the submitted role before canonicalizing saved state.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        invalid_role: Retired or unknown role submitted with the trunk edit.
    """
    import html

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DhcpScope

    login(client)
    page = client.get("/physical-interfaces")
    rows = json.loads(html.unescape(page.text.split("data-interfaces='", 1)[1].split("'", 1)[0]))
    interface_id = next(row["id"] for row in rows if row["name"] == "eth2")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    with SessionLocal() as db:
        for scope in db.execute(
            select(DhcpScope).where(DhcpScope.interface_name == "eth2")
        ).scalars().all():
            scope.enabled = False
        db.commit()

    response = client.post(
        f"/physical-interfaces/{interface_id}/edit",
        data={
            "role": invalid_role,
            "mode": "trunk",
            "ipv4_method": "static",
            "ip_cidr": "",
            "ipv6_cidr": "",
            "mtu": "1500",
            "admin_state": "up",
            "csrf": csrf,
        },
        follow_redirects=False,
    )

    assert response.status_code == 422
    assert response.text == "Interface role must be one of: management, access, route, unused."


def test_management_to_access_conversion_preserves_ui_and_reverse_conversion_clears_flag(client):
    """Verify role conversion applies the access-only management UI invariant atomically.

    Args:
        client: Application test client fixture.
    """
    import html

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface

    login(client)
    page = client.get("/physical-interfaces")
    rows = json.loads(html.unescape(page.text.split("data-interfaces='", 1)[1].split("'", 1)[0]))
    eth0 = next(row for row in rows if row["name"] == "eth0")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    common = {
        "mode": "access",
        "ipv4_method": "static",
        "ip_cidr": "192.168.167.10/24",
        "ipv6_cidr": "",
        "mtu": "1500",
        "admin_state": "up",
        "csrf": csrf,
    }

    converted = client.post(
        f"/physical-interfaces/{eth0['id']}/edit",
        data={**common, "role": "access"},
        follow_redirects=False,
    )
    assert converted.status_code == 303
    with SessionLocal() as db:
        interface = db.execute(select(PhysicalInterface).where(PhysicalInterface.id == eth0["id"])).scalar_one()
        assert interface.role == "access"
        assert interface.access_management_ui_enabled is True

    reverted = client.post(
        f"/physical-interfaces/{eth0['id']}/edit",
        data={**common, "role": "management", "access_management_ui_enabled": "on"},
        follow_redirects=False,
    )
    assert reverted.status_code == 303
    with SessionLocal() as db:
        interface = db.execute(select(PhysicalInterface).where(PhysicalInterface.id == eth0["id"])).scalar_one()
        assert interface.role == "management"
        assert interface.access_management_ui_enabled is False


def test_physical_interface_link_type_locked_when_vlans_exist(client):
    """Verify that physical interface link type locked when vlans exist.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    import html

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface, VlanInterface

    login(client)
    with SessionLocal() as db:
        eth1 = db.query(PhysicalInterface).filter_by(name="eth1").one()
        eth1.mode = "trunk"
        db.add(
            VlanInterface(
                name="eth1.50",
                parent_interface="eth1",
                vlan_id=50,
                ip_cidr="192.168.50.1/24",
                mtu=1500,
                role="access",
                enabled=True,
            )
        )
        db.commit()

    page = client.get("/physical-interfaces")
    payload = page.text.split("data-interfaces='", 1)[1].split("'", 1)[0]
    rows = json.loads(html.unescape(payload))
    eth1_row = next(row for row in rows if row["name"] == "eth1")
    assert eth1_row["vlan_count"] >= 1
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    response = client.post(
        f"/physical-interfaces/{eth1_row['id']}/edit",
        data={
            "role": "access",
            "mode": "access",
            "ip_cidr": "",
            "mtu": "1500",
            "admin_state": "up",
            "csrf": csrf,
        },
    )
    assert response.status_code == 409
    assert "Move or delete those VLANs before changing the link type" in response.text


def test_physical_interface_grid_menu_actions_are_available(client):
    """Verify that physical interface grid menu actions are available.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    login(client)
    page = client.get("/physical-interfaces")
    assert page.status_code == 200

    js = client.get("/static/app.js?v=public-address-mode-20260708-1")
    assert js.status_code == 200
    assert "Disable interface" in js.text
    assert "Enable interface" in js.text
    assert "Convert DHCP lease to static" in js.text
    assert "requestConfirmation" in js.text
    assert "The management interface must stay enabled." in js.text
    assert 'data.role === "management" && data.admin_up' in js.text
    assert "atlaso_public_address_mode" in js.text
    assert "initializePublicAddressModeToggle" in js.text


def test_management_dhcp_interface_can_be_saved_as_static_from_observed_addresses(client, monkeypatch):
    """Verify that management dhcp interface can be saved as static from observed addresses.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import html

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import ApplianceSettings, DnsSettings, PhysicalInterface

    login(client)
    monkeypatch.setattr("atlaso.app.services.appliance_settings.observed_management_dhcp_dns_servers", lambda interface_name: ["127.0.0.1", "::1", "192.168.167.2", "192.168.167.3"])
    with SessionLocal() as db:
        appliance_settings = db.execute(select(ApplianceSettings)).scalar_one()
        appliance_settings.external_dns_servers = ""
        dns_settings = db.execute(select(DnsSettings)).scalar_one()
        dns_settings.enabled = False
        dns_settings.upstream_servers = ""
        eth0 = db.execute(select(PhysicalInterface).where(PhysicalInterface.name == "eth0")).scalar_one()
        eth0.role = "management"
        eth0.mode = "access"
        eth0.ipv4_method = "dhcp"
        eth0.ip_cidr = None
        eth0.host_ip_cidr = "192.168.167.219/24"
        eth0.host_ipv6_cidr = "fd00:167::219/64"
        db.commit()

    page = client.get("/physical-interfaces")
    payload = page.text.split("data-interfaces='", 1)[1].split("'", 1)[0]
    rows = json.loads(html.unescape(payload))
    eth0_row = next(row for row in rows if row["name"] == "eth0")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    response = client.post(
        f"/physical-interfaces/{eth0_row['id']}/edit",
        data={
            "role": "management",
            "mode": "access",
            "ipv4_method": "static",
            "ip_cidr": eth0_row["host_ip_cidr"],
            "ipv6_enabled": "on",
            "ipv6_cidr": eth0_row["host_ipv6_cidr"],
            "mtu": "1500",
            "admin_state": "up",
            "csrf": csrf,
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    with SessionLocal() as db:
        eth0 = db.execute(select(PhysicalInterface).where(PhysicalInterface.name == "eth0")).scalar_one()
        assert eth0.ipv4_method == "static"
        assert eth0.ip_cidr == "192.168.167.219/24"
        assert eth0.ipv6_cidr == "fd00:167::219/64"
        appliance_settings = db.execute(select(ApplianceSettings)).scalar_one()
        dns_settings = db.execute(select(DnsSettings)).scalar_one()
        assert appliance_settings.external_dns_servers == "192.168.167.2\n192.168.167.3"
        assert dns_settings.upstream_servers == "192.168.167.2\n192.168.167.3"


def test_management_physical_interface_cannot_be_disabled(client):
    """Verify that management physical interface cannot be disabled.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    import html

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface

    login(client)
    with SessionLocal() as db:
        eth0 = db.execute(select(PhysicalInterface).where(PhysicalInterface.name == "eth0")).scalar_one()
        eth0.role = "management"
        eth0.mode = "access"
        eth0.ipv4_method = "dhcp"
        eth0.ip_cidr = None
        eth0.admin_state = "up"
        db.commit()

    page = client.get("/physical-interfaces")
    payload = page.text.split("data-interfaces='", 1)[1].split("'", 1)[0]
    rows = json.loads(html.unescape(payload))
    eth0_row = next(row for row in rows if row["name"] == "eth0")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    response = client.post(
        f"/physical-interfaces/{eth0_row['id']}/edit",
        data={
            "role": "management",
            "mode": "access",
            "ipv4_method": "dhcp",
            "ip_cidr": "",
            "ipv6_cidr": "",
            "mtu": "1500",
            "admin_state": "down",
            "csrf": csrf,
        },
    )

    assert response.status_code == 422
    assert "management interface must stay enabled" in response.text
    with SessionLocal() as db:
        eth0 = db.execute(select(PhysicalInterface).where(PhysicalInterface.name == "eth0")).scalar_one()
        assert eth0.role == "management"
        assert eth0.admin_state == "up"


def test_vlan_interface_create_edit_delete_and_apply(client):
    """Verify that vlan interface create edit delete and apply.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job

    login(client)
    page = client.get("/vlan-interfaces")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    created = client.post(
        "/vlan-interfaces",
        data={
            "parent_interface": "eth1",
            "vlan_id": "50",
            "ip_cidr": "192.168.50.1/24",
            "mtu": "1500",
            "role": "access",
            "enabled": "on",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Grid": "1", "Accept": "application/json"},
    )
    assert created.status_code == 200
    created_row = created.json()["vlan"]
    assert created_row["name"] == "eth1.50"
    assert created_row["enabled"] is True

    updated = client.post(
        f"/vlan-interfaces/{created_row['id']}/edit",
        data={
            "parent_interface": "eth1",
            "vlan_id": "50",
            "ip_cidr": "192.168.50.1/24",
            "ipv6_cidr": "fd00:50::1/64",
            "mtu": "1600",
            "role": "route",
            "enabled": "on",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Grid": "1", "Accept": "application/json"},
    )
    assert updated.status_code == 200
    assert updated.json()["vlan"] == {
        "id": created_row["id"],
        "name": "eth1.50",
        "parent_interface": "eth1",
        "vlan_id": 50,
        "ip_cidr": "192.168.50.1/24",
        "ipv6_cidr": "fd00:50::1/64",
        "mtu": 1600,
        "role": "route",
        "enabled": True,
        "access_management_ui_enabled": False,
        "parent_missing": False,
    }

    page = client.get("/vlan-interfaces")
    assert "eth1.50" in page.text
    assert "192.168.50.1/24" in page.text
    assert "fd00:50::1/64" in page.text
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    apply_response = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": "network"})
    assert_apply_redirect(apply_response)

    with SessionLocal() as db:
        job = db.execute(select(Job).where(Job.type == "appliance-apply")).scalar_one()
        assert "atlaso-helper" in (job.result or "")
        assert "eth1.50" in (job.result or "")

    page = client.get("/vlan-interfaces")
    import html

    payload = page.text.split("data-vlans='", 1)[1].split("'", 1)[0]
    rows = json.loads(html.unescape(payload))
    vlan_id = next(row["id"] for row in rows if row["name"] == "eth1.50")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    deleted = client.post(f"/vlan-interfaces/{vlan_id}/delete", data={"csrf": csrf}, follow_redirects=False)
    assert deleted.status_code == 303
    assert "eth1.50" not in client.get("/vlan-interfaces").text


def test_vlan_ui_rejects_removing_final_management_listener(client):
    """Keep the final flagged management VLAN intact across UI edit and delete.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface, VlanInterface

    login(client)
    with SessionLocal() as db:
        for interface in db.execute(select(PhysicalInterface)).scalars().all():
            interface.role = "unused"
            interface.access_management_ui_enabled = False
        parent = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth1")
        ).scalar_one()
        parent.mode = "trunk"
        parent.admin_state = "up"
        parent.oper_state = "up"
        vlan = VlanInterface(
            name="eth1.469",
            parent_interface="eth1",
            vlan_id=469,
            ip_cidr="192.168.69.1/24",
            role="access",
            enabled=True,
            access_management_ui_enabled=True,
        )
        db.add(vlan)
        db.commit()
        vlan_id = vlan.id

    page = client.get("/vlan-interfaces")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    updated = client.post(
        f"/vlan-interfaces/{vlan_id}/edit",
        data={
            "parent_interface": "eth1",
            "vlan_id": "469",
            "ip_cidr": "192.168.69.1/24",
            "mtu": "1500",
            "role": "access",
            "enabled": "on",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Grid": "1", "Accept": "application/json"},
    )
    deleted = client.post(
        f"/vlan-interfaces/{vlan_id}/delete",
        data={"csrf": csrf},
        follow_redirects=False,
    )

    for response in (updated, deleted):
        assert response.status_code == 422, response.text
        assert "At least one complete management listener must remain" in response.text
    with SessionLocal() as db:
        preserved = db.get(VlanInterface, vlan_id)
        assert preserved is not None
        assert preserved.enabled is True
        assert preserved.access_management_ui_enabled is True


def test_vlan_interface_edit_reports_unrepresentable_dhcp_range(client):
    """Verify VLAN prefix shrink failures use the recoverable grid validation response.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DhcpScope, VlanInterface

    login(client)
    page = client.get("/vlan-interfaces")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    created = client.post(
        "/vlan-interfaces",
        data={
            "parent_interface": "eth1",
            "vlan_id": "84",
            "ip_cidr": "192.168.84.1/24",
            "mtu": "1500",
            "role": "access",
            "enabled": "on",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Grid": "1", "Accept": "application/json"},
    )
    assert created.status_code == 200, created.text
    vlan_id = created.json()["vlan"]["id"]

    scope_name = "vlan-prefix-shrink-dependency"
    with SessionLocal() as db:
        db.add(
            DhcpScope(
                name=scope_name,
                address_family="ipv4",
                interface_name="eth1.84",
                site_address="192.168.84.1",
                prefix_length=24,
                range_expression="192.168.84.100-192.168.84.120",
                dns_server="192.168.84.1",
                ntp_server="192.168.84.1",
            )
        )
        db.commit()

    rejected = client.post(
        f"/vlan-interfaces/{vlan_id}/edit",
        data={
            "parent_interface": "eth1",
            "vlan_id": "84",
            "ip_cidr": "192.168.84.1/28",
            "mtu": "1500",
                "role": "access",
            "enabled": "on",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Grid": "1", "Accept": "application/json"},
    )

    assert rejected.status_code == 422, rejected.text
    assert "cannot fit" in rejected.json()["detail"]
    with SessionLocal() as db:
        vlan = db.get(VlanInterface, vlan_id)
        scope = db.execute(select(DhcpScope).where(DhcpScope.name == scope_name)).scalar_one()
        assert vlan is not None
        assert vlan.ip_cidr == "192.168.84.1/24"
        assert scope.site_address == "192.168.84.1"
        assert scope.prefix_length == 24
        assert scope.range_expression == "192.168.84.100-192.168.84.120"


def test_vlan_interface_delete_reconciles_aliases_after_flush(client, monkeypatch):
    """Verify dependent alias reconcilers cannot still select a deleted VLAN.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace DNS alias reconciliation.
    """
    from sqlalchemy import select

    from atlaso.app import ui
    from atlaso.app.models import VlanInterface

    login(client)
    page = client.get("/vlan-interfaces")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    created = client.post(
        "/vlan-interfaces",
        data={
            "parent_interface": "eth1",
            "vlan_id": "85",
            "ip_cidr": "192.168.85.1/24",
            "mtu": "1500",
            "role": "access",
            "enabled": "on",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Grid": "1", "Accept": "application/json"},
    )
    assert created.status_code == 200, created.text
    vlan_id = created.json()["vlan"]["id"]
    observed_absence: list[bool] = []

    def ensure_esx_alias_after_flush(db, *_args, **_kwargs):
        """Record whether the deleted VLAN is absent during alias reconciliation.

        Args:
            db: Active test database session.
            *_args: Unused positional callback arguments.
            **_kwargs: Unused keyword callback arguments.
        """
        observed_absence.append(
            db.execute(
                select(VlanInterface).where(VlanInterface.name == "eth1.85")
            ).scalar_one_or_none()
            is None
        )
        return "removed-old"

    monkeypatch.setattr(ui, "ensure_dns_for_esx_storage", ensure_esx_alias_after_flush)
    deleted = client.post(
        f"/vlan-interfaces/{vlan_id}/delete",
        data={"csrf": csrf},
        follow_redirects=False,
    )

    assert deleted.status_code == 303, deleted.text
    assert observed_absence == [True]


def test_vlan_interface_delete_rejects_enabled_dhcp_dependency(client):
    """Verify VLAN deletion rolls back while an enabled DHCP scope remains bound.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DhcpScope, DhcpSettings, VlanInterface

    login(client)
    page = client.get("/vlan-interfaces")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    created = client.post(
        "/vlan-interfaces",
        data={
            "parent_interface": "eth1",
            "vlan_id": "86",
            "ip_cidr": "192.168.86.1/24",
            "mtu": "1500",
            "role": "access",
            "enabled": "on",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Grid": "1", "Accept": "application/json"},
    )
    assert created.status_code == 200, created.text
    vlan_id = created.json()["vlan"]["id"]
    scope_name = "vlan-delete-dependency"
    with SessionLocal() as db:
        db.execute(select(DhcpSettings)).scalar_one().enabled = True
        db.add(
            DhcpScope(
                name=scope_name,
                address_family="ipv4",
                interface_name="eth1.86",
                site_address="192.168.86.1",
                prefix_length=24,
                range_expression="192.168.86.100-192.168.86.120",
                dns_server="192.168.86.1",
                ntp_server="192.168.86.1",
                enabled=True,
            )
        )
        db.commit()

    rejected = client.post(
        f"/vlan-interfaces/{vlan_id}/delete",
        data={"csrf": csrf},
        headers={"X-Atlaso-Grid": "1", "Accept": "application/json"},
        follow_redirects=False,
    )

    assert rejected.status_code == 422, rejected.text
    assert "DHCP scope" in rejected.json()["detail"]
    with SessionLocal() as db:
        assert db.get(VlanInterface, vlan_id) is not None
        assert db.execute(
            select(DhcpScope).where(DhcpScope.name == scope_name)
        ).scalar_one().enabled is True


def test_vlan_page_prefers_real_trunk_parent_when_inventory_has_eth2(client):
    """Verify that vlan page prefers real trunk parent when inventory has eth2.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    import html

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface

    login(client)
    with SessionLocal() as db:
        db.query(PhysicalInterface).delete()
        db.add_all(
            [
                PhysicalInterface(
                    name="eth0",
                    mac_address="00:15:5d:01:1d:1a",
                    ip_cidr="192.168.49.1/24",
                    role="management",
                    mode="access",
                    inventory_source="host",
                    desired_state_source="user",
                ),
                PhysicalInterface(
                    name="eth1",
                    mac_address="00:15:5d:01:1d:1b",
                    ip_cidr="192.168.50.1/24",
                    role="access",
                    mode="access",
                    inventory_source="host",
                    desired_state_source="user",
                ),
                PhysicalInterface(
                    name="eth2",
                    mac_address="00:15:5d:01:1d:1c",
                    mtu=9000,
                    role="access",
                    mode="trunk",
                    inventory_source="host",
                    desired_state_source="user",
                ),
                PhysicalInterface(
                    name="eth3",
                    mac_address="00:15:5d:01:1d:1d",
                    role="route",
                    mode="access",
                    inventory_source="host",
                    desired_state_source="user",
                ),
            ]
        )
        db.commit()

    page = client.get("/vlan-interfaces")
    payload = page.text.split("data-parent-options='", 1)[1].split("'", 1)[0]
    options = json.loads(html.unescape(payload))

    assert options == [{"name": "eth2", "label": "eth2 - trunk - host NIC - 00:15:5d:01:1d:1c", "mtu": 9000}]
    assert "eth2 - trunk - host NIC" in page.text
    assert "eth2 - access - trunk" not in page.text


def test_vlan_page_disables_missing_parent_vlan(client):
    """Verify that vlan page disables missing parent vlan.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    import html

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface, VlanInterface

    login(client)
    with SessionLocal() as db:
        db.query(VlanInterface).delete()
        db.query(PhysicalInterface).delete()
        db.add_all(
            [
                PhysicalInterface(
                    name="missing_155d011d1d",
                    mac_address="00:15:5d:01:1d:1d",
                    role="unused",
                    mode="unused",
                    admin_state="down",
                    oper_state="missing",
                    inventory_source="host",
                    desired_state_source="user",
                ),
                PhysicalInterface(
                    name="eth2",
                    mac_address="00:15:5d:01:1d:1c",
                    role="access",
                    mode="trunk",
                    inventory_source="host",
                    desired_state_source="user",
                ),
                VlanInterface(
                    parent_interface="missing_155d011d1d",
                    name="missing_155d011d1d.11",
                    vlan_id=11,
                    ip_cidr="192.168.11.1/24",
                    enabled=True,
                ),
            ]
        )
        db.commit()

    page = client.get("/vlan-interfaces")
    assert page.status_code == 200
    vlan_payload = page.text.split("data-vlans='", 1)[1].split("'", 1)[0]
    rows = json.loads(html.unescape(vlan_payload))
    row = next(item for item in rows if item["name"] == "missing_155d011d1d.11")
    assert row["parent_missing"] is True
    assert row["enabled"] is False

    parent_payload = page.text.split("data-parent-options='", 1)[1].split("'", 1)[0]
    options = json.loads(html.unescape(parent_payload))
    assert options == [{"name": "eth2", "label": "eth2 - trunk - host NIC - 00:15:5d:01:1d:1c", "mtu": 1500}]

    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        f"/vlan-interfaces/{row['id']}/edit",
        data={
            "parent_interface": "missing_155d011d1d",
            "vlan_id": "11",
            "ip_cidr": "192.168.11.1/24",
            "mtu": "1500",
            "role": "access",
            "enabled": "on",
            "csrf": csrf,
        },
    )
    assert response.status_code == 409
    assert "missing from host inventory" in response.text

    disabled = client.post(
        f"/vlan-interfaces/{row['id']}/edit",
        data={
            "parent_interface": "missing_155d011d1d",
            "vlan_id": "11",
            "ip_cidr": "192.168.11.1/24",
            "mtu": "1500",
            "role": "access",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Grid": "1", "Accept": "application/json"},
    )
    assert disabled.status_code == 200
    assert disabled.json()["vlan"]["enabled"] is False
    assert disabled.json()["vlan"]["parent_missing"] is True


def test_vlan_interface_rejects_non_trunk_parent(client):
    """Verify that vlan interface rejects non trunk parent.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    login(client)
    page = client.get("/vlan-interfaces")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/vlan-interfaces",
        data={
            "parent_interface": "eth2",
            "vlan_id": "60",
            "ip_cidr": "192.168.60.1/24",
            "mtu": "1500",
            "role": "access",
            "enabled": "on",
            "csrf": csrf,
        },
    )
    assert response.status_code == 409
    assert "is not a trunk interface" in response.text


def test_vlan_interface_requires_vlan_id_and_ip_cidr(client):
    """Verify that vlan interface requires vlan id and ip cidr.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    login(client)
    page = client.get("/vlan-interfaces")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    missing_ip = client.post(
        "/vlan-interfaces",
        data={
            "parent_interface": "eth1",
            "vlan_id": "70",
            "ip_cidr": "",
            "mtu": "1500",
            "role": "access",
            "enabled": "on",
            "csrf": csrf,
        },
    )
    assert missing_ip.status_code == 409
    assert "VLAN IPv4 CIDR, IPv6 CIDR, or both are required." in missing_ip.text

    missing_vlan = client.post(
        "/vlan-interfaces",
        data={
            "parent_interface": "eth1",
            "vlan_id": "",
            "ip_cidr": "192.168.70.1/24",
            "mtu": "1500",
            "role": "access",
            "enabled": "on",
            "csrf": csrf,
        },
    )
    assert missing_vlan.status_code == 409
    assert "VLAN ID is required" in missing_vlan.text


@pytest.mark.parametrize(
    ("overrides", "expected_message"),
    [
        ({"vlan_id": "0"}, "VLAN ID must be between 1 and 4094."),
        ({"vlan_id": "4095"}, "VLAN ID must be between 1 and 4094."),
        ({"ip_cidr": "192.168.80.1"}, "VLAN IPv4 CIDR must include an address and prefix."),
        ({"ip_cidr": "", "ipv6_cidr": "fd00:80::1"}, "VLAN IPv6 CIDR must include an address and prefix."),
        ({"mtu": "575"}, "VLAN MTU must be between 576 and 9000."),
        ({"mtu": "9001"}, "VLAN MTU must be between 576 and 9000."),
        ({"role": "unsupported"}, "VLAN role must be one of"),
        ({"role": "services"}, "VLAN role must be one of"),
        ({"role": "storage"}, "VLAN role must be one of"),
    ],
)
def test_vlan_interface_wizard_returns_actionable_validation_errors(client, overrides, expected_message):
    """Verify recoverable VLAN wizard validation errors retain actionable detail.

    Args:
        client: Authenticated UI test client fixture.
        overrides: VLAN form values that should fail validation.
        expected_message: Actionable validation detail expected in the response.
    """
    login(client)
    page = client.get("/vlan-interfaces")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    data = {
        "parent_interface": "eth1",
        "vlan_id": "80",
        "ip_cidr": "192.168.80.1/24",
        "ipv6_cidr": "",
        "mtu": "1500",
        "role": "access",
        "enabled": "on",
        "csrf": csrf,
    }
    data.update(overrides)

    response = client.post(
        "/vlan-interfaces",
        data=data,
        headers={"X-Atlaso-Grid": "1", "Accept": "application/json"},
    )

    assert response.status_code == 409
    assert expected_message in response.json()["detail"]


def test_vlan_interface_wizard_supports_ipv6_only_disabled_creation_and_duplicate_errors(client):
    """Verify IPv6-only disabled VLAN creation and recoverable duplicate reporting.

    Args:
        client: Authenticated UI test client fixture.
    """
    login(client)
    page = client.get("/vlan-interfaces")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    data = {
        "parent_interface": "eth1",
        "vlan_id": "81",
        "ip_cidr": "",
        "ipv6_cidr": "fd00:81::1/64",
        "mtu": "1500",
        "role": "access",
        "csrf": csrf,
    }
    created = client.post(
        "/vlan-interfaces",
        data=data,
        headers={"X-Atlaso-Grid": "1", "Accept": "application/json"},
    )
    assert created.status_code == 200
    assert created.json()["vlan"]["ip_cidr"] == ""
    assert created.json()["vlan"]["ipv6_cidr"] == "fd00:81::1/64"
    assert created.json()["vlan"]["enabled"] is False

    duplicate = client.post(
        "/vlan-interfaces",
        data=data,
        headers={"X-Atlaso-Grid": "1", "Accept": "application/json"},
    )
    assert duplicate.status_code == 409
    assert duplicate.json() == {"detail": "VLAN eth1.81 already exists."}


def test_vlan_interface_wizard_saves_management_ui_state_only_for_access_role(client):
    """Verify management UI exposure is reviewed with the complete VLAN record.

    Args:
        client: Authenticated UI test client fixture.
    """
    login(client)
    page = client.get("/vlan-interfaces")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    data = {
        "parent_interface": "eth1",
        "vlan_id": "83",
        "ip_cidr": "192.168.83.1/24",
        "ipv6_cidr": "",
        "mtu": "1500",
        "role": "access",
        "access_management_ui_enabled": "on",
        "enabled": "on",
        "csrf": csrf,
    }
    created = client.post(
        "/vlan-interfaces",
        data=data,
        headers={"X-Atlaso-Grid": "1", "Accept": "application/json"},
    )
    assert created.status_code == 200
    assert created.json()["vlan"]["access_management_ui_enabled"] is True

    rejected = client.post(
        f"/vlan-interfaces/{created.json()['vlan']['id']}/edit",
        data={**data, "role": "route"},
        headers={"X-Atlaso-Grid": "1", "Accept": "application/json"},
    )
    assert rejected.status_code == 422
    assert rejected.json() == {
        "detail": "Management UI exposure is available only for an access-role VLAN."
    }


def test_vlan_role_change_prunes_disallowed_web_terminal_target(client):
    """Verify a VLAN moved to management is removed from Web Terminal selection.

    Args:
        client: Authenticated UI test client fixture.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import ApplianceSettings, PhysicalInterface, VlanInterface
    from atlaso.app.services.appliance_settings import web_terminal_interfaces_from_json

    login(client)
    vlan_name = "eth1.84"
    with SessionLocal() as db:
        parent = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth1")
        ).scalar_one()
        parent.role = "unused"
        parent.mode = "trunk"
        parent.admin_state = "up"
        parent.oper_state = "up"
        vlan = VlanInterface(
            name=vlan_name,
            parent_interface=parent.name,
            vlan_id=84,
            ip_cidr="192.168.84.1/24",
            mtu=1500,
            role="access",
            enabled=True,
        )
        settings = db.execute(select(ApplianceSettings)).scalar_one()
        settings.web_terminal_enabled = True
        settings.web_terminal_interfaces_json = f'["eth0", "{vlan_name}"]'
        db.add(vlan)
        db.commit()
        vlan_id = vlan.id

    page = client.get("/vlan-interfaces")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        f"/vlan-interfaces/{vlan_id}/edit",
        data={
            "parent_interface": "eth1",
            "vlan_id": "84",
            "ip_cidr": "192.168.84.1/24",
            "ipv6_cidr": "",
            "mtu": "1500",
            "role": "management",
            "enabled": "on",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Grid": "1", "Accept": "application/json"},
    )

    assert response.status_code == 200, response.text
    with SessionLocal() as db:
        vlan = db.get(VlanInterface, vlan_id)
        settings = db.execute(select(ApplianceSettings)).scalar_one()
        assert vlan.role == "management"
        assert web_terminal_interfaces_from_json(
            settings.web_terminal_interfaces_json
        ) == ["eth0"]


def test_vlan_interface_wizard_respects_read_only_permissions(client):
    """Verify read-only users keep the VLAN grid without mutation launch paths.

    Args:
        client: Authenticated UI test client fixture.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Role, User
    from atlaso.app.security import roles_to_json

    with SessionLocal() as db:
        admin = db.execute(select(User).where(User.username == "admin")).scalar_one()
        admin.role = Role.VIEWER.value
        admin.roles_json = roles_to_json([Role.VIEWER.value])
        db.commit()

    login(client)
    page = client.get("/vlan-interfaces")
    assert page.status_code == 200
    assert 'data-can-write="false"' in page.text
    assert 'id="vlan-interfaces-table"' in page.text
    assert 'id="vlan-interface-dialog"' not in page.text
    assert "+ Add VLAN interface here" not in page.text

    denied = client.post(
        "/vlan-interfaces",
        data={
            "parent_interface": "eth1",
            "vlan_id": "82",
            "ip_cidr": "192.168.82.1/24",
            "mtu": "1500",
            "role": "access",
            "enabled": "on",
            "csrf": "not-used-before-authorization",
        },
    )
    assert denied.status_code == 403
    assert "Missing required scope: write:vlans" in denied.text
